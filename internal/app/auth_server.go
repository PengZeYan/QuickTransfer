package app

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	localSessionCookie  = "qt_session"
	secureSessionCookie = "__Host-qt_session"
	guestCookie         = "qt_guest"
)

var authTokenGenerator = randomToken

func (server *Server) register(writer http.ResponseWriter, request *http.Request) {
	settings, _ := server.settings.snapshot()
	if !server.registrationAvailable() {
		writeAPIError(writer, http.StatusForbidden, "registration_closed", "当前暂未开放新用户注册")
		return
	}
	ip := server.clientIP(request)
	if !server.allowPersistent(request, "register:"+ip, 5, time.Hour) {
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "注册尝试过于频繁")
		return
	}
	var payload struct {
		Email         string     `json:"email"`
		TermsAccepted bool       `json:"termsAccepted"`
		TermsVersion  string     `json:"termsVersion"`
		HumanProof    HumanProof `json:"humanProof"`
	}
	if decodeJSON(request, &payload, 16*1024) != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "注册信息无效")
		return
	}
	if !payload.TermsAccepted || payload.TermsVersion != settings.Terms.Version {
		writeAPIError(writer, http.StatusConflict, "terms_version_mismatch", "请阅读并同意当前版本的服务条款、隐私政策与使用规则")
		return
	}
	email, domain, err := normalizeAllowedEmail(payload.Email, settings.Registration.AllowedDomains)
	if errors.Is(err, errEmailDomainNotAllowed) {
		writeAPIError(writer, http.StatusBadRequest, "email_domain_not_allowed", "仅支持 QQ、163、Gmail 等已配置的主流邮箱")
		return
	}
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_credentials", "请输入有效邮箱；不支持 + 别名")
		return
	}
	id, err := authTokenGenerator(16)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "暂时无法注册")
		return
	}
	if !server.requireHumanVerification(writer, request, "register", payload.HumanProof) {
		return
	}
	existing, lookupErr := server.store.UserByEmail(request.Context(), email)
	if lookupErr == nil && existing.Status != "pending" {
		_ = server.store.AddAudit(request.Context(), existing.ID, "user.register_existing", "user", existing.ID, "", ip)
		writeJSON(writer, http.StatusCreated, map[string]any{"requiresVerification": true,
			"expiresIn":         int(server.cfg.VerificationCodeTTL.Seconds()),
			"retryAfterSeconds": settings.Registration.EmailCooldownSeconds})
		return
	}
	if lookupErr != nil && !errors.Is(lookupErr, ErrNotFound) {
		server.logger.Error("lookup registration email", "error", lookupErr)
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "暂时无法注册")
		return
	}
	if !server.reserveVerificationDelivery(writer, request, email, domain) {
		return
	}
	code, err := randomNumericCode(6)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "暂时无法注册")
		return
	}
	codeHash, err := server.hashCredential(request, code)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "暂时无法注册")
		return
	}
	now := time.Now()
	user := User{ID: id, Email: email, Username: defaultUsernameFromEmail(email), PasswordHash: "pending-email-verification", Role: "user", CreatedAt: now.Unix()}
	consent := ConsentEvidence{Version: settings.Terms.Version, DocumentHash: termsDocumentHash(settings.Terms),
		AcceptedAt: now.Unix(), IPHash: privateRateKey(server.cfg.Secret, ip),
		UserAgentHash: privateRateKey(server.cfg.Secret, request.UserAgent())}
	var createErr error
	if lookupErr == nil {
		user.ID, user.Role, user.CreatedAt = existing.ID, existing.Role, existing.CreatedAt
		createErr = server.store.RefreshPendingUser(request.Context(), user.ID, codeHash, now.Unix(),
			now.Add(server.cfg.VerificationCodeTTL).Unix(), consent)
	} else {
		createErr = server.store.CreatePendingUser(request.Context(), user, codeHash,
			now.Add(server.cfg.VerificationCodeTTL).Unix(), consent)
	}
	if createErr != nil {
		if createErr == ErrConflict {
			writeJSON(writer, http.StatusCreated, map[string]any{"requiresVerification": true,
				"expiresIn":         int(server.cfg.VerificationCodeTTL.Seconds()),
				"retryAfterSeconds": settings.Registration.EmailCooldownSeconds})
			return
		}
		server.logger.Error("register user", "error", createErr)
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "暂时无法注册")
		return
	}
	if err := server.sendVerification(request.Context(), email, code, verificationPurposeRegister); err != nil {
		_ = server.store.InvalidateVerificationCodes(request.Context(), user.ID, "verify", time.Now().Unix())
		_ = server.store.AddAudit(request.Context(), user.ID, "email.verify_delivery_failed", "user", user.ID, "", ip)
		server.logger.Error("send registration verification", "userId", user.ID, "error", err)
		writeAPIError(writer, http.StatusServiceUnavailable, "email_delivery_failed", "验证码邮件暂时无法发送，请稍后再试")
		return
	}
	_ = server.store.AddAudit(request.Context(), user.ID, "user.register", "user", user.ID, "", ip)
	response := map[string]any{"requiresVerification": true, "expiresIn": int(server.cfg.VerificationCodeTTL.Seconds()),
		"retryAfterSeconds": settings.Registration.EmailCooldownSeconds}
	if server.cfg.ExposeLocalCode && server.verificationMode() == "local-sandbox" {
		response["verificationCode"] = code
	}
	writeJSON(writer, http.StatusCreated, response)
}

func (server *Server) verifyRegistration(writer http.ResponseWriter, request *http.Request) {
	settings, _ := server.settings.snapshot()
	ip := server.clientIP(request)
	if !server.allowPersistent(request, "verify:"+ip, 10, 15*time.Minute) {
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "验证尝试过于频繁")
		return
	}
	var payload struct {
		Email    string `json:"email"`
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if decodeJSON(request, &payload, 4096) != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "验证信息无效")
		return
	}
	email, _, err := normalizeAllowedEmail(payload.Email, settings.Registration.AllowedDomains)
	if err != nil || len(payload.Code) != 6 || len(payload.Password) < 10 || len(payload.Password) > 128 {
		writeAPIError(writer, http.StatusBadRequest, "invalid_code", "验证码无效")
		return
	}
	if !server.allowPersistent(request, "verify-email:"+privateRateKey(server.cfg.Secret, email), 8, 15*time.Minute) {
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "验证尝试过于频繁")
		return
	}
	passwordHash, err := server.hashCredential(request, payload.Password)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "暂时无法完成注册")
		return
	}
	risk := RegistrationSuccessRisk{
		IPHash:      privateRateKey(server.cfg.Secret, ip),
		SubnetHash:  privateRateKey(server.cfg.Secret, registrationSubnet(ip)),
		IPDaily:     settings.Registration.SuccessfulPerIPDaily,
		SubnetDaily: settings.Registration.SuccessfulPerSubnetDaily,
	}
	user, err := server.store.VerifyUser(request.Context(), email, payload.Code, passwordHash, time.Now().Unix(), risk)
	if err != nil {
		if errors.Is(err, ErrRateLimited) {
			writeAPIError(writer, http.StatusTooManyRequests, "registration_risk_limit", "当前网络的新用户注册次数已达上限，请稍后再试")
			return
		}
		writeAPIError(writer, http.StatusUnauthorized, "invalid_code", "验证码错误或已经失效")
		return
	}
	dailyCheckInReminder := server.shouldPromptDailyCheckIn(request.Context(), user, time.Now())
	if err := server.startSession(writer, request, user); err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "session_failed", "账户已验证，但暂时无法登录")
		return
	}
	_ = server.store.AddAudit(request.Context(), user.ID, "user.verify", "user", user.ID, "", ip)
	writeJSON(writer, http.StatusOK, map[string]any{
		"user": publicUser(user), "dailyCheckInReminder": dailyCheckInReminder,
	})
}

func registrationSubnet(value string) string {
	ip := net.ParseIP(value)
	if ip == nil {
		return value
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		return ipv4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

func (server *Server) login(writer http.ResponseWriter, request *http.Request) {
	ip := server.clientIP(request)
	if !server.allowPersistent(request, "login:"+ip, 10, 15*time.Minute) {
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "登录尝试过于频繁")
		return
	}
	var payload struct {
		Email      string     `json:"email"`
		Password   string     `json:"password"`
		HumanProof HumanProof `json:"humanProof"`
	}
	if decodeJSON(request, &payload, 16*1024) != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "登录信息无效")
		return
	}
	if !server.requireHumanVerification(writer, request, "login", payload.HumanProof) {
		return
	}
	email, _ := normalizeEmail(payload.Email)
	accountKey := privateRateKey(server.cfg.Secret, email)
	if !server.allowPersistent(request, "login-account:"+accountKey, 10, 15*time.Minute) {
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "该账户登录尝试过于频繁")
		return
	}
	user, err := server.store.UserByEmail(request.Context(), email)
	passwordHash := server.dummyPasswordHash
	if err == nil && user.Status != "pending" {
		passwordHash = user.PasswordHash
	}
	passwordOK, verifyErr := server.verifyCredential(request, passwordHash, payload.Password)
	if verifyErr != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "authentication_busy", "登录服务繁忙，请稍后再试")
		return
	}
	if err != nil || !passwordOK {
		_ = server.store.AddRiskEvent(request.Context(), "login", "rejected", "invalid_credentials", accountKey,
			privateRateKey(server.cfg.Secret, ip), "")
		writeAPIError(writer, http.StatusUnauthorized, "invalid_credentials", "邮箱或密码不正确")
		return
	}
	if user.Status == "pending" {
		writeAPIError(writer, http.StatusForbidden, "verification_required", "请先完成邮箱验证")
		return
	}
	if user.Status != "active" {
		writeAPIError(writer, http.StatusForbidden, "account_blocked", "账户当前不可用")
		return
	}
	dailyCheckInReminder := server.shouldPromptDailyCheckIn(request.Context(), user, time.Now())
	membershipGrant, err := server.startLoginSessionWithAudit(writer, request, user, "user.login", "user", user.ID, "", ip)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "session_failed", "暂时无法登录")
		return
	}
	_ = server.store.AddRiskEvent(request.Context(), "login", "accepted", "login_ok", accountKey,
		privateRateKey(server.cfg.Secret, ip), "")
	response := map[string]any{
		"user": publicUser(user), "dailyCheckInReminder": dailyCheckInReminder,
	}
	if membershipGrant.RewardBytes > 0 {
		response["membershipDailyTrafficGrant"] = membershipGrant
	}
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) startSession(writer http.ResponseWriter, request *http.Request, user User) error {
	return server.startSessionWithAudit(writer, request, user, "", "", "", "", "")
}

func (server *Server) startSessionWithAudit(writer http.ResponseWriter, request *http.Request, user User,
	action, targetType, targetID, detail, ip string,
) error {
	session, err := newSessionCredentials()
	if err != nil {
		return err
	}
	now := time.Now()
	createSession := server.store.CreateUserSession
	if action != "" {
		createSession = func(ctx context.Context, userID, tokenHashValue, csrfToken, ipHash, userAgentHash string,
			now, expiresAt int64,
		) error {
			return server.store.CreateUserSessionWithAudit(ctx, userID, tokenHashValue, csrfToken, ipHash, userAgentHash,
				now, expiresAt, action, targetType, targetID, detail, ip)
		}
	}
	if err := createSession(request.Context(), user.ID, tokenHash(session.token), session.csrf,
		tokenHash(server.clientIP(request)), tokenHash(request.UserAgent()), now.Unix(),
		now.Add(server.cfg.SessionLifetime).Unix()); err != nil {
		return err
	}
	server.setSessionCookie(writer, session.token)
	return nil
}

func (server *Server) startLoginSessionWithAudit(writer http.ResponseWriter, request *http.Request, user User,
	action, targetType, targetID, detail, ip string,
) (VIPDailyLoginGrant, error) {
	session, err := newSessionCredentials()
	if err != nil {
		return VIPDailyLoginGrant{}, err
	}
	now := time.Now()
	grant, err := server.store.CreateLoginSessionWithAuditAndVIPDailyGrant(request.Context(), user.ID,
		tokenHash(session.token), session.csrf, tokenHash(server.clientIP(request)), tokenHash(request.UserAgent()),
		now.Unix(), now.Add(server.cfg.SessionLifetime).Unix(), action, targetType, targetID, detail, ip)
	if err != nil {
		return VIPDailyLoginGrant{}, err
	}
	server.setSessionCookie(writer, session.token)
	return grant, nil
}

type sessionCredentials struct {
	token string
	csrf  string
}

func newSessionCredentials() (sessionCredentials, error) {
	return newSessionCredentialsWith(authTokenGenerator)
}

func newSessionCredentialsWith(generate func(int) (string, error)) (sessionCredentials, error) {
	token, err := generate(32)
	if err != nil {
		return sessionCredentials{}, err
	}
	csrf, err := generate(24)
	if err != nil {
		return sessionCredentials{}, err
	}
	return sessionCredentials{token: token, csrf: csrf}, nil
}

func (server *Server) setSessionCookie(writer http.ResponseWriter, token string) {
	name := localSessionCookie
	if server.cfg.PublicMode {
		name = secureSessionCookie
	}
	http.SetCookie(writer, &http.Cookie{Name: name, Value: token, Path: "/", HttpOnly: true,
		Secure: server.cfg.PublicMode, SameSite: http.SameSiteLaxMode, MaxAge: int(server.cfg.SessionLifetime.Seconds())})
}

func (server *Server) logout(writer http.ResponseWriter, request *http.Request) {
	user, _, token, ok := server.requireUser(writer, request, true)
	if !ok {
		return
	}
	_ = server.store.RevokeUserSession(request.Context(), tokenHash(token), time.Now().Unix())
	for _, name := range []string{localSessionCookie, secureSessionCookie} {
		http.SetCookie(writer, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: true,
			Secure: name == secureSessionCookie, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	}
	_ = server.store.AddAudit(request.Context(), user.ID, "user.logout", "user", user.ID, "", server.clientIP(request))
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) requestPasswordReset(writer http.ResponseWriter, request *http.Request) {
	settings, _ := server.settings.snapshot()
	ip := server.clientIP(request)
	if !server.allowPersistent(request, "reset-request:"+ip, 5, time.Hour) {
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "请求过于频繁")
		return
	}
	var payload struct {
		Email      string     `json:"email"`
		HumanProof HumanProof `json:"humanProof"`
	}
	if decodeJSON(request, &payload, 4096) != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "请求无效")
		return
	}
	email, domain, normalizeErr := normalizeAllowedEmail(payload.Email, settings.Registration.AllowedDomains)
	if errors.Is(normalizeErr, errEmailDomainNotAllowed) {
		writeAPIError(writer, http.StatusBadRequest, "email_domain_not_allowed", "该邮箱域名不在允许范围内")
		return
	}
	if normalizeErr != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_email", "邮箱格式无效；不支持 + 别名")
		return
	}
	if !server.requireHumanVerification(writer, request, "password_reset", payload.HumanProof) {
		return
	}
	if !server.reserveVerificationDelivery(writer, request, email, domain) {
		return
	}
	user, err := server.store.UserByEmail(request.Context(), email)
	response := map[string]any{"accepted": true, "expiresIn": int(server.cfg.VerificationCodeTTL.Seconds()),
		"retryAfterSeconds": settings.Registration.EmailCooldownSeconds}
	if err == nil && user.Status == "active" {
		code, codeErr := randomNumericCode(6)
		if codeErr != nil {
			server.logger.Error("generate password reset code", "userId", user.ID, "error", codeErr)
			writeJSON(writer, http.StatusOK, response)
			return
		}
		hash, hashErr := server.hashCredential(request, code)
		if hashErr != nil {
			writeJSON(writer, http.StatusOK, response)
			return
		}
		now := time.Now()
		_ = server.store.InvalidateVerificationCodes(request.Context(), user.ID, "reset", now.Unix())
		if createErr := server.store.CreatePasswordReset(request.Context(), user.ID, hash, now.Unix(), now.Add(server.cfg.VerificationCodeTTL).Unix()); createErr != nil {
			server.logger.Error("create password reset", "userId", user.ID, "error", createErr)
		} else if deliveryErr := server.sendVerification(request.Context(), email, code, verificationPurposeReset); deliveryErr != nil {
			_ = server.store.InvalidateVerificationCodes(request.Context(), user.ID, "reset", time.Now().Unix())
			_ = server.store.AddAudit(request.Context(), user.ID, "email.reset_delivery_failed", "user", user.ID, "", ip)
			server.logger.Error("send password reset verification", "userId", user.ID, "error", deliveryErr)
		} else if server.cfg.ExposeLocalCode && server.verificationMode() == "local-sandbox" {
			response["verificationCode"] = code
		}
	}
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) confirmPasswordReset(writer http.ResponseWriter, request *http.Request) {
	settings, _ := server.settings.snapshot()
	ip := server.clientIP(request)
	if !server.allowPersistent(request, "reset-confirm:"+ip, 10, 15*time.Minute) {
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "验证尝试过于频繁")
		return
	}
	var payload struct {
		Email    string `json:"email"`
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if decodeJSON(request, &payload, 16*1024) != nil || len(payload.Password) < 10 || len(payload.Password) > 128 {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "重置信息无效")
		return
	}
	email, _, normalizeErr := normalizeAllowedEmail(payload.Email, settings.Registration.AllowedDomains)
	if normalizeErr != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "重置信息无效")
		return
	}
	if !server.allowPersistent(request, "reset-confirm-email:"+privateRateKey(server.cfg.Secret, email), 8, 15*time.Minute) {
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "验证尝试过于频繁")
		return
	}
	hash, err := server.hashCredential(request, payload.Password)
	if err != nil || server.store.ResetPassword(request.Context(), email, payload.Code, hash, time.Now().Unix()) != nil {
		writeAPIError(writer, http.StatusUnauthorized, "invalid_code", "验证码错误或已经失效")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"reset": true})
}

func (server *Server) hashCredential(request *http.Request, value string) (string, error) {
	select {
	case server.authSem <- struct{}{}:
		defer func() { <-server.authSem }()
		return hashAccessCode(value)
	case <-request.Context().Done():
		return "", request.Context().Err()
	}
}

func (server *Server) verifyCredential(request *http.Request, encoded, value string) (bool, error) {
	select {
	case server.authSem <- struct{}{}:
		defer func() { <-server.authSem }()
		return verifyAccessCode(encoded, value), nil
	case <-request.Context().Done():
		return false, request.Context().Err()
	}
}

func (server *Server) reserveVerificationDelivery(writer http.ResponseWriter, request *http.Request, email, domain string) bool {
	settings, _ := server.settings.snapshot()
	risk := settings.Registration
	ip := server.clientIP(request)
	now := time.Now().UTC()
	limits := []verificationDeliveryLimit{
		{SubjectKey: "verification-email:" + privateRateKey(server.cfg.Secret, email), Cooldown: time.Duration(risk.EmailCooldownSeconds) * time.Second,
			Hourly: risk.EmailHourly, Daily: risk.EmailDaily},
		{SubjectKey: "verification-ip:" + privateRateKey(server.cfg.Secret, ip), Cooldown: 5 * time.Second,
			Hourly: risk.IPHourly, Daily: risk.IPDaily},
		{SubjectKey: "verification-domain:" + domain, Hourly: risk.DomainHourly,
			Daily: risk.DomainDaily},
	}
	if err := server.store.ReserveVerificationDelivery(request.Context(), limits, now); err != nil {
		if errors.Is(err, ErrRateLimited) {
			writer.Header().Set("Retry-After", strconv.Itoa(max(60, risk.EmailCooldownSeconds)))
			writeAPIError(writer, http.StatusTooManyRequests, "verification_rate_limited", "验证码发送过于频繁，请稍后再试")
			return false
		}
		server.logger.Error("reserve verification delivery", "error", err)
		writeAPIError(writer, http.StatusServiceUnavailable, "verification_unavailable", "验证码服务暂时不可用")
		return false
	}
	return true
}

func (server *Server) getMe(writer http.ResponseWriter, request *http.Request) {
	user, csrf, _, ok := server.requireUser(writer, request, false)
	if !ok {
		return
	}
	settings, _ := server.settings.snapshot()
	account, err := server.store.AccountSummary(request.Context(), user.ID, settings.Defaults.UserStorageBytes,
		settings.Defaults.UserMonthlyTraffic, time.Now())
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法读取账户")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"user": publicUser(user), "account": account, "csrfToken": csrf})
}

func (server *Server) updateProfile(writer http.ResponseWriter, request *http.Request) {
	user, csrf, _, ok := server.requireUser(writer, request, true)
	if !ok {
		return
	}
	var payload struct {
		Username string `json:"username"`
	}
	if decodeJSON(request, &payload, 4096) != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "账户信息无效")
		return
	}
	username, valid := cleanUsername(payload.Username)
	if !valid {
		writeAPIError(writer, http.StatusBadRequest, "invalid_username", "用户名称需为 1–20 个字符")
		return
	}
	if username != user.Username {
		if err := server.store.UpdateUsername(request.Context(), user.ID, username); err != nil {
			if errors.Is(err, ErrNotFound) {
				writeAPIError(writer, http.StatusUnauthorized, "authentication_required", "请先登录")
				return
			}
			server.logger.Error("update username", "userId", user.ID, "error", err)
			writeAPIError(writer, http.StatusInternalServerError, "internal_error", "暂时无法更新用户名称")
			return
		}
		user.Username = username
		_ = server.store.AddAudit(request.Context(), user.ID, "user.profile_update", "user", user.ID, "", server.clientIP(request))
	}
	writeJSON(writer, http.StatusOK, map[string]any{"user": publicUser(user), "csrfToken": csrf})
}

func cleanUsername(value string) (string, bool) {
	var cleaned strings.Builder
	cleaned.Grow(len(value))
	for _, character := range value {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			continue
		}
		cleaned.WriteRune(character)
	}
	username := strings.TrimSpace(cleaned.String())
	length := len([]rune(username))
	return username, length >= 1 && length <= 20
}

func (server *Server) listMyTransfers(writer http.ResponseWriter, request *http.Request) {
	user, _, _, ok := server.requireUser(writer, request, false)
	if !ok {
		return
	}
	transfers, err := server.store.TransfersForOwner(request.Context(), user.ID)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法读取传输记录")
		return
	}
	for index := range transfers {
		if !transferPublished(transfers[index]) {
			transfers[index].PickupCode = ""
		}
	}
	writeJSON(writer, http.StatusOK, map[string]any{"transfers": transfers})
}

func (server *Server) listMyResources(writer http.ResponseWriter, request *http.Request) {
	user, _, _, ok := server.requireUser(writer, request, false)
	if !ok {
		return
	}
	entitlements, err := server.store.EntitlementsForUser(request.Context(), user.ID, time.Now().Unix())
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法读取资源明细")
		return
	}
	trafficEntitlements := make([]ResourceEntitlement, 0, len(entitlements))
	for _, entitlement := range entitlements {
		if entitlement.ResourceType == "traffic" {
			trafficEntitlements = append(trafficEntitlements, entitlement)
		}
	}
	points, err := server.store.PointsForUser(request.Context(), user.ID)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法读取积分明细")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"entitlements": trafficEntitlements, "points": points})
}

func (server *Server) claimTransfer(writer http.ResponseWriter, request *http.Request) {
	user, _, _, ok := server.requireUser(writer, request, true)
	if !ok {
		return
	}
	var payload struct {
		ShareToken  string `json:"shareToken"`
		ManageToken string `json:"manageToken"`
	}
	if decodeJSON(request, &payload, 8192) != nil {
		writeAPIError(writer, http.StatusBadRequest, "claim_failed", "无法认领此传输")
		return
	}
	err := server.store.ClaimTransferWithoutStorageQuota(request.Context(), payload.ShareToken, payload.ManageToken, user.ID)
	if err != nil {
		writeAPIError(writer, http.StatusUnauthorized, "claim_failed", "无法认领此传输")
		return
	}
	_ = server.store.AddAudit(request.Context(), user.ID, "transfer.claim", "transfer", payload.ShareToken, "", server.clientIP(request))
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) requireUser(writer http.ResponseWriter, request *http.Request, requireCSRF bool) (User, string, string, bool) {
	user, csrf, token, ok := server.currentUser(request)
	if !ok {
		writeAPIError(writer, http.StatusUnauthorized, "authentication_required", "请先登录")
		return User{}, "", "", false
	}
	if requireCSRF && !secureEqual(request.Header.Get("X-CSRF-Token"), csrf) {
		writeAPIError(writer, http.StatusForbidden, "csrf_failed", "请求安全校验失败")
		return User{}, "", "", false
	}
	return user, csrf, token, true
}

func (server *Server) currentUser(request *http.Request) (User, string, string, bool) {
	name := localSessionCookie
	if server.cfg.PublicMode {
		name = secureSessionCookie
	}
	cookie, err := request.Cookie(name)
	if err != nil || cookie.Value == "" {
		return User{}, "", "", false
	}
	user, csrf, err := server.store.UserBySession(request.Context(), tokenHash(cookie.Value), time.Now().Unix())
	if err != nil || user.Status != "active" {
		return User{}, "", "", false
	}
	return user, csrf, cookie.Value, true
}

func (server *Server) principal(writer http.ResponseWriter, request *http.Request) Principal {
	name := localSessionCookie
	if server.cfg.PublicMode {
		name = secureSessionCookie
	}
	if cookie, err := request.Cookie(name); err == nil && cookie.Value != "" {
		if user, _, err := server.store.UserBySession(request.Context(), tokenHash(cookie.Value), time.Now().Unix()); err == nil && user.Status == "active" {
			return Principal{Kind: "user", ID: user.ID, User: &user}
		}
	}
	if cookie, err := request.Cookie(guestCookie); err == nil && cookie.Value != "" {
		if id, err := server.store.GuestByToken(request.Context(), tokenHash(cookie.Value), time.Now().Unix()); err == nil {
			return Principal{Kind: "guest", ID: id}
		}
	}
	raw, err := authTokenGenerator(24)
	if err != nil {
		panic(err)
	}
	id, err := authTokenGenerator(16)
	if err != nil {
		panic(err)
	}
	if err := server.store.CreateGuestSession(request.Context(), id, tokenHash(raw), time.Now().Unix()); err != nil {
		panic(err)
	}
	http.SetCookie(writer, &http.Cookie{Name: guestCookie, Value: raw, Path: "/", HttpOnly: true,
		Secure: server.cfg.PublicMode, SameSite: http.SameSiteLaxMode, MaxAge: 30 * 24 * 3600})
	return Principal{Kind: "guest", ID: id}
}

func (server *Server) effectivePolicy(principal Principal) EffectivePolicy {
	settings, _ := server.settings.snapshot()
	const (
		mib = int64(1024 * 1024)
		gib = int64(1024 * 1024 * 1024)
	)
	tier := "guest"
	maxFile := 100 * mib
	maxFiles := 100
	maxDownloads := settings.Defaults.GuestMaxDownloads
	maxExpiryHours := 24
	if maxDownloads <= 0 {
		maxDownloads = 5
	}
	if principal.Authenticated() {
		tier = "normal"
		maxFile = 2 * gib
		maxFiles = 100
		maxDownloads = 100
		maxExpiryHours = 72
		if plan := activeVIPPlan(principal.User.VIPPlan, principal.User.VIPExpiresAt, time.Now().Unix()); plan != "" {
			tier = "vip"
			maxFile = 10 * gib
			maxFiles = 1000
			// The product contract only raises file size and file count. Retention
			// remains capped at three days until a separate retention benefit is
			// explicitly introduced.
			maxExpiryHours = 72
			if plan == "lifetime" {
				maxFile = 50 * gib
				maxFiles = 10000
			}
		}
	}
	if server.cfg.MaxFileBytes > 0 {
		maxFile = min(maxFile, server.cfg.MaxFileBytes)
	}
	if server.cfg.MaxFiles > 0 {
		maxFiles = min(maxFiles, server.cfg.MaxFiles)
	}
	globalExpiryHours := settings.Defaults.MaximumExpiryHours
	if configured := int(server.cfg.MaxExpiry / time.Hour); configured > 0 && (globalExpiryHours <= 0 || configured < globalExpiryHours) {
		globalExpiryHours = configured
	}
	if globalExpiryHours > 0 {
		if maxExpiryHours <= 0 {
			maxExpiryHours = globalExpiryHours
		} else {
			maxExpiryHours = min(maxExpiryHours, globalExpiryHours)
		}
	}
	// The size entitlement is the aggregate cap for one transfer. File count is
	// an independent limit and must never multiply the task byte allowance.
	maxTransfer := maxFile
	if server.cfg.MaxTransferBytes > 0 {
		maxTransfer = min(maxTransfer, server.cfg.MaxTransferBytes)
	}
	if maxTransfer < maxFile {
		maxFile = maxTransfer
	}
	return EffectivePolicy{Tier: tier, MaxFileBytes: maxFile, MaxTransferBytes: maxTransfer,
		MaxFiles: maxFiles, MaxDownloads: maxDownloads, MaxExpiryHours: maxExpiryHours}
}

func (server *Server) allowPersistent(request *http.Request, key string, limit int, window time.Duration) bool {
	if !server.limiter.Allow(key, limit, window) {
		return false
	}
	allowed, err := server.store.AllowPersistent(request.Context(), key, limit, window, 0, 0)
	if err != nil {
		server.logger.Error("persistent rate limit", "key", key, "error", err)
		return false
	}
	return allowed
}

func (server *Server) clientIP(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		host = request.RemoteAddr
	}
	remote := net.ParseIP(host)
	if remote != nil && server.isTrustedProxy(remote) {
		values := strings.Split(request.Header.Get("X-Forwarded-For"), ",")
		for index := len(values) - 1; index >= 0; index-- {
			ip := net.ParseIP(strings.TrimSpace(values[index]))
			if ip != nil && !server.isTrustedProxy(ip) {
				return ip.String()
			}
		}
	}
	if remote != nil {
		return remote.String()
	}
	return host
}

func (server *Server) isTrustedProxy(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, candidate := range server.cfg.TrustedProxyCIDRs {
		candidate = strings.TrimSpace(candidate)
		if trustedIP := net.ParseIP(candidate); trustedIP != nil && trustedIP.Equal(ip) {
			return true
		}
		if _, network, err := net.ParseCIDR(candidate); err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func publicUser(user User) map[string]any {
	username := strings.TrimSpace(user.Username)
	if username == "" {
		username = defaultUsernameFromEmail(user.Email)
	}
	tier := "normal"
	if activeVIPPlan(user.VIPPlan, user.VIPExpiresAt, time.Now().Unix()) != "" {
		tier = "vip"
	}
	return map[string]any{"id": user.ID, "email": user.Email, "username": username, "status": user.Status, "role": user.Role,
		"tier": tier, "vipPlan": canonicalVIPPlan(user.VIPPlan), "vipExpiresAt": user.VIPExpiresAt,
		"mustChangePassword": user.MustChangePassword,
		"createdAt":          user.CreatedAt, "verifiedAt": user.VerifiedAt, "lastLoginAt": user.LastLoginAt}
}

func randomNumericCode(length int) (string, error) {
	result := make([]byte, length)
	for index := range result {
		value, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		result[index] = byte('0' + value.Int64())
	}
	return string(result), nil
}
