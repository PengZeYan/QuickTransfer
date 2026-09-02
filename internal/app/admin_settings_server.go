package app

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (server *Server) getTerms(writer http.ResponseWriter, _ *http.Request) {
	settings, _ := server.settings.snapshot()
	writeJSON(writer, http.StatusOK, map[string]any{"terms": settings.Terms})
}

func (server *Server) adminGetSettings(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireAdmin(writer, request, false); !ok {
		return
	}
	settings, secrets := server.settings.snapshot()
	writeJSON(writer, http.StatusOK, map[string]any{
		"settings": settings,
		"runtime": map[string]any{
			"emailActive": server.verificationMode() == "email", "registrationOpen": server.registrationAvailable(),
			"restartRequired": settings.SMTP.Enabled && smtpConfigurationFingerprint(settings.SMTP, secrets.SMTPPassword) != server.activeSMTPFingerprint,
			"scanner":         server.scanner.Name(), "productionScanner": server.scanner.ProductionReady(),
			"publicMode": server.cfg.PublicMode, "buildVersion": buildVersion,
		},
	})
}

func (server *Server) adminUpdateSettings(writer http.ResponseWriter, request *http.Request) {
	user, ok := server.requireAdmin(writer, request, true)
	if !ok {
		return
	}
	if !server.allowPersistent(request, "admin-settings:"+user.ID, 12, time.Hour) {
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "设置修改过于频繁")
		return
	}
	var payload struct {
		Settings ServiceSettings      `json:"settings"`
		Secrets  SecretSettingsUpdate `json:"secrets"`
	}
	if decodeJSON(request, &payload, 160*1024) != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "设置内容无效")
		return
	}
	current, currentSecrets := server.settings.snapshot()
	if payload.Settings.Revision != current.Revision {
		writeAPIError(writer, http.StatusConflict, "settings_revision_conflict", "设置已被更新，请刷新后重试")
		return
	}
	if !sameSMTPIdentity(current.SMTP, payload.Settings.SMTP) && strings.TrimSpace(payload.Secrets.SMTPPassword) == "" {
		if payload.Settings.SMTP.Enabled {
			writeAPIError(writer, http.StatusBadRequest, "smtp_authorization_required", "SMTP 服务商、账号或发件地址变化后必须输入新的授权码")
			return
		}
		payload.Secrets.ClearSMTPPassword = true
	}
	secrets := applySecretUpdate(currentSecrets, payload.Secrets)
	payload.Settings.SMTP.LastTestedAt = current.SMTP.LastTestedAt
	payload.Settings.SMTP.LastTestSucceeded = current.SMTP.LastTestSucceeded
	if !sameSMTPConfiguration(current.SMTP, currentSecrets.SMTPPassword, payload.Settings.SMTP, secrets.SMTPPassword) {
		payload.Settings.SMTP.LastTestedAt = 0
		payload.Settings.SMTP.LastTestSucceeded = false
	}
	next, err := normalizeServiceSettings(payload.Settings, secrets)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "settings_invalid", err.Error())
		return
	}
	if server.cfg.RequireHumanVerification {
		if err := validateCriticalHumanVerification(next, secrets); err != nil {
			writeAPIError(writer, http.StatusConflict, "captcha_activation_required", "当前部署要求完整配置登录、注册、找回密码、游客传输和兑换的人机验证")
			return
		}
	}
	if next.Registration.Open && !server.cfg.ExposeLocalCode {
		if !next.SMTP.Enabled || !next.SMTP.LastTestSucceeded || server.verificationMode() != "email" {
			writeAPIError(writer, http.StatusConflict, "email_activation_required", "请先保存并测试 SMTP，重启服务使邮件配置生效后再开放注册")
			return
		}
	}
	saved, err := server.store.SaveServiceSettings(request.Context(), next, secrets, current.Revision, user.ID, server.cfg.Secret)
	if errors.Is(err, ErrConflict) {
		writeAPIError(writer, http.StatusConflict, "settings_revision_conflict", "设置已被更新，请刷新后重试")
		return
	}
	if err != nil {
		server.logger.Error("save service settings", "error", err)
		writeAPIError(writer, http.StatusInternalServerError, "settings_save_failed", "设置暂时无法保存")
		return
	}
	server.settings.replace(saved, secrets)
	_ = server.store.AddAudit(request.Context(), user.ID, "admin.settings.update", "service_settings", "1",
		"revision="+strconv.FormatInt(saved.Revision, 10), privateRateKey(server.cfg.Secret, server.clientIP(request)))
	writeJSON(writer, http.StatusOK, map[string]any{"settings": saved,
		"restartRequired": saved.SMTP.Enabled && smtpConfigurationFingerprint(saved.SMTP, secrets.SMTPPassword) != server.activeSMTPFingerprint})
}

func (server *Server) adminTestSMTP(writer http.ResponseWriter, request *http.Request) {
	user, ok := server.requireAdmin(writer, request, true)
	if !ok {
		return
	}
	if !server.allowPersistent(request, "smtp-test:"+user.ID, 3, 15*time.Minute) {
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "SMTP 测试过于频繁")
		return
	}
	var payload struct {
		Recipient string `json:"recipient"`
	}
	if decodeJSON(request, &payload, 8192) != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "测试参数无效")
		return
	}
	settings, secrets := server.settings.snapshot()
	recipient, _, err := normalizeEmailAddress(payload.Recipient)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_email", "请输入有效测试邮箱")
		return
	}
	allowed := false
	for _, candidate := range []string{user.Email, settings.SMTP.Username, settings.SMTP.From} {
		if candidate != "" && strings.EqualFold(candidate, recipient) {
			allowed = true
			break
		}
	}
	if !allowed {
		writeAPIError(writer, http.StatusForbidden, "recipient_not_allowed", "测试邮件只能发送到当前管理员或已配置的 SMTP 发件邮箱")
		return
	}
	validated, err := normalizeServiceSettings(settings, secrets)
	if err != nil || !validated.SMTP.Enabled {
		writeAPIError(writer, http.StatusConflict, "smtp_not_configured", "请先保存完整 SMTP 配置")
		return
	}
	cfg := server.cfg
	cfg.LocalVerification = false
	cfg.SMTPHost, cfg.SMTPPort = validated.SMTP.Host, validated.SMTP.Port
	cfg.SMTPUsername, cfg.SMTPPassword = validated.SMTP.Username, secrets.SMTPPassword
	cfg.SMTPFrom, cfg.SMTPFromName = validated.SMTP.From, validated.SMTP.FromName
	cfg.SMTPTLSMode, cfg.SMTPAuthMode = validated.SMTP.TLSMode, validated.SMTP.AuthMode
	sender := verificationSenderForConfig(cfg)
	testID, err := randomToken(10)
	if err != nil {
		server.logger.Error("generate SMTP test id", "error", err)
		writeAPIError(writer, http.StatusServiceUnavailable, "smtp_test_unavailable", "SMTP 测试暂时不可用，请稍后重试")
		return
	}
	if err := sender.Send(request.Context(), recipient, testID, verificationPurposeTest); err != nil {
		server.logger.Error("SMTP test failed", "error", err)
		_ = server.store.AddAudit(request.Context(), user.ID, "admin.smtp.test_failed", "service_settings", "1", "",
			privateRateKey(server.cfg.Secret, server.clientIP(request)))
		writeAPIError(writer, http.StatusServiceUnavailable, "smtp_test_failed", "SMTP 连接或投递测试失败，请检查授权码和服务商设置")
		return
	}
	validated.SMTP.LastTestedAt = time.Now().Unix()
	validated.SMTP.LastTestSucceeded = true
	saved, err := server.store.SaveServiceSettings(request.Context(), validated, secrets, settings.Revision, user.ID, server.cfg.Secret)
	if err != nil {
		writeAPIError(writer, http.StatusConflict, "settings_revision_conflict", "邮件已经发送，但设置状态保存失败，请刷新后重试")
		return
	}
	server.settings.replace(saved, secrets)
	_ = server.store.AddAudit(request.Context(), user.ID, "admin.smtp.test_succeeded", "service_settings", "1", "",
		privateRateKey(server.cfg.Secret, server.clientIP(request)))
	writeJSON(writer, http.StatusOK, map[string]any{"sent": true, "recipient": recipient,
		"testedAt":        saved.SMTP.LastTestedAt,
		"restartRequired": smtpConfigurationFingerprint(saved.SMTP, secrets.SMTPPassword) != server.activeSMTPFingerprint})
}

func sameSMTPIdentity(left, right SMTPSettings) bool {
	return strings.EqualFold(strings.TrimSpace(left.Provider), strings.TrimSpace(right.Provider)) &&
		strings.EqualFold(strings.TrimSpace(left.Username), strings.TrimSpace(right.Username)) &&
		strings.EqualFold(strings.TrimSpace(left.From), strings.TrimSpace(right.From))
}

func smtpConfigurationFingerprint(settings SMTPSettings, password string) string {
	digest := strings.Join([]string{
		strconv.FormatBool(settings.Enabled), strings.ToLower(strings.TrimSpace(settings.Provider)),
		strings.ToLower(strings.TrimSpace(settings.Username)), strings.ToLower(strings.TrimSpace(settings.From)),
		strings.TrimSpace(settings.FromName), password,
	}, "\x00")
	return tokenHash(digest)
}

func sameSMTPConfiguration(left SMTPSettings, leftPassword string, right SMTPSettings, rightPassword string) bool {
	return left.Enabled == right.Enabled &&
		strings.EqualFold(strings.TrimSpace(left.Provider), strings.TrimSpace(right.Provider)) &&
		strings.EqualFold(strings.TrimSpace(left.Username), strings.TrimSpace(right.Username)) &&
		strings.EqualFold(strings.TrimSpace(left.From), strings.TrimSpace(right.From)) &&
		strings.TrimSpace(left.FromName) == strings.TrimSpace(right.FromName) &&
		leftPassword == rightPassword
}
