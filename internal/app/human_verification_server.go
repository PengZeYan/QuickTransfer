package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func humanVerificationConfigFromSettings(settings ServiceSettings, secrets ServiceSecrets) HumanVerificationConfig {
	return HumanVerificationConfig{
		Enabled: settings.Captcha.Enabled, Provider: settings.Captcha.Provider,
		SiteKey: settings.Captcha.SiteKey, Secret: secrets.TurnstileSecret,
		AllowedHostnames: settings.Captcha.AllowedHostnames, TencentCaptchaAppID: settings.Captcha.TencentCaptchaAppID,
		TencentAppSecretKey: secrets.TencentAppSecretKey, TencentSecretID: secrets.TencentSecretID,
		TencentSecretKey: secrets.TencentSecretKey, Actions: settings.Captcha.Actions,
	}
}

func validateCriticalHumanVerification(settings ServiceSettings, secrets ServiceSecrets) error {
	if !settings.Captcha.Enabled {
		return errors.New("human verification is disabled")
	}
	for _, action := range criticalHumanVerificationActions {
		if !settings.Captcha.Actions[action] {
			return fmt.Errorf("critical human verification action %q is disabled", action)
		}
	}
	if _, err := NewHumanVerifier(humanVerificationConfigFromSettings(settings, secrets)); err != nil {
		return err
	}
	return nil
}

func (server *Server) criticalHumanVerificationReady() bool {
	settings, secrets := server.settings.snapshot()
	return validateCriticalHumanVerification(settings, secrets) == nil
}

func (server *Server) issueHumanVerificationChallenge(writer http.ResponseWriter, request *http.Request) {
	settings, _ := server.settings.snapshot()
	action := strings.TrimSpace(request.URL.Query().Get("action"))
	if !settings.Captcha.Enabled || settings.Captcha.Provider != "tencent" || !settings.Captcha.Actions[action] {
		writeAPIError(writer, http.StatusNotFound, "challenge_unavailable", "当前操作不需要腾讯验证码")
		return
	}
	ipHash := privateRateKey(server.cfg.Secret, server.clientIP(request))
	if !server.allowPersistent(request, "captcha-challenge:"+ipHash, 60, time.Hour) {
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "验证码请求过于频繁")
		return
	}
	challenge, err := signTicket(server.cfg.Secret, "human-verification", action+"\x00"+ipHash, 5*time.Minute)
	if err != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "challenge_unavailable", "验证码挑战暂时不可用")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"challenge": challenge, "expiresIn": 300})
}

func (store *Store) RecordHumanVerificationReceipt(ctx context.Context, provider, action, proofHash, ipHash string) error {
	id, err := randomToken(16)
	if err != nil {
		return fmt.Errorf("generate human verification receipt id: %w", err)
	}
	_, err = store.db.ExecContext(ctx, `INSERT INTO human_verification_receipts
		(id,provider,action,proof_hash,result,ip_hash,created_at,expires_at)
		VALUES(?,?,?,?,'accepted',?,?,?)`, id, provider, action, proofHash, ipHash,
		time.Now().Unix(), time.Now().Add(10*time.Minute).Unix())
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "unique") {
		return ErrConflict
	}
	return err
}

func (server *Server) requireHumanVerification(writer http.ResponseWriter, request *http.Request, action string, proof HumanProof) bool {
	if server.settingsDegraded {
		writeAPIError(writer, http.StatusServiceUnavailable, "security_settings_unavailable", "安全配置暂时不可用")
		return false
	}
	settings, secrets := server.settings.snapshot()
	if server.cfg.RequireHumanVerification {
		if err := validateCriticalHumanVerification(settings, secrets); err != nil {
			writeAPIError(writer, http.StatusServiceUnavailable, "human_verification_unavailable", "人机验证尚未完成安全配置")
			return false
		}
	}
	if !settings.Captcha.Enabled || !settings.Captcha.Actions[action] {
		return true
	}
	if settings.Captcha.Provider == "tencent" {
		ipHash := privateRateKey(server.cfg.Secret, server.clientIP(request))
		subject, challengeErr := verifyTicket(server.cfg.Secret, proof.Challenge, "human-verification")
		if challengeErr != nil || !secureEqual(subject, action+"\x00"+ipHash) {
			writeAPIError(writer, http.StatusForbidden, "human_verification_failed", "人机验证与当前操作不匹配，请重新验证")
			return false
		}
	}
	verifierFactory := server.humanVerifierFactory
	if verifierFactory == nil {
		verifierFactory = NewHumanVerifier
	}
	verifier, err := verifierFactory(humanVerificationConfigFromSettings(settings, secrets))
	if err == nil {
		err = verifier.Verify(request.Context(), action, proof, server.clientIP(request))
	}
	ipHash := privateRateKey(server.cfg.Secret, server.clientIP(request))
	if err != nil {
		_ = server.store.AddRiskEvent(request.Context(), action, "rejected", "captcha_failed", "", ipHash, "")
		switch {
		case errors.Is(err, ErrHumanVerificationRequired):
			writeAPIError(writer, http.StatusBadRequest, "human_verification_required", "请先完成人机验证")
		case errors.Is(err, ErrHumanVerificationFailed):
			writeAPIError(writer, http.StatusForbidden, "human_verification_failed", "人机验证失败或已失效，请重新验证")
		default:
			writeAPIError(writer, http.StatusServiceUnavailable, "human_verification_unavailable", "人机验证服务暂时不可用，请稍后重试")
		}
		return false
	}
	proofHash := privateRateKey(server.cfg.Secret, settings.Captcha.Provider+"\x00"+proof.Token+"\x00"+proof.RandStr)
	if err := server.store.RecordHumanVerificationReceipt(request.Context(), settings.Captcha.Provider, action, proofHash, ipHash); err != nil {
		if errors.Is(err, ErrConflict) {
			_ = server.store.AddRiskEvent(request.Context(), action, "rejected", "captcha_replayed", "", ipHash, "")
			writeAPIError(writer, http.StatusForbidden, "human_verification_replayed", "该验证凭据已经使用，请重新验证")
		} else {
			_ = server.store.AddRiskEvent(request.Context(), action, "rejected", "captcha_receipt_failed", "", ipHash, "")
			writeAPIError(writer, http.StatusServiceUnavailable, "human_verification_unavailable", "人机验证状态暂时无法确认")
		}
		return false
	}
	_ = server.store.AddRiskEvent(request.Context(), action, "accepted", "captcha_ok", "", ipHash, "")
	return true
}

func (store *Store) CleanupHumanVerification(ctx context.Context, now int64) error {
	_, err := store.db.ExecContext(ctx, `DELETE FROM human_verification_receipts WHERE expires_at<?`, now)
	return err
}
