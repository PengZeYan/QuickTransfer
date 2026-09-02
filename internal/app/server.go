package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Server struct {
	cfg                   Config
	store                 *Store
	scanner               *Scanner
	logger                *slog.Logger
	limiter               *RateLimiter
	settings              *settingsState
	senderMu              sync.RWMutex
	verificationSender    verificationSender
	activeSMTPFingerprint string
	settingsDegraded      bool
	humanVerifierFactory  func(HumanVerificationConfig) (HumanVerifier, error)
	storage               *StorageInternalClient
	storageReplay         *InternalReplayGuard
	uploadSem             chan struct{}
	authSem               chan struct{}
	dummyPasswordHash     string
	locks                 sync.Map
	handler               http.Handler
}

const buildVersion = "2026.09.01-control.1"
const pendingPickupPrefix = "__pending__"

func NewServer(cfg Config, store *Store, scanner *Scanner, logger *slog.Logger) *Server {
	return newServerWithDependencies(cfg, store, scanner, logger, verificationSenderForConfig(cfg), nil)
}

func NewServerWithRemoteStorage(cfg Config, store *Store, scanner *Scanner, logger *slog.Logger, storage *StorageInternalClient) *Server {
	return newServerWithDependencies(cfg, store, scanner, logger, verificationSenderForConfig(cfg), storage)
}

func newServerWithVerificationSender(cfg Config, store *Store, scanner *Scanner, logger *slog.Logger, sender verificationSender) *Server {
	return newServerWithDependencies(cfg, store, scanner, logger, sender, nil)
}

func newServerWithDependencies(cfg Config, store *Store, scanner *Scanner, logger *slog.Logger, sender verificationSender,
	storage *StorageInternalClient) *Server {
	store.configureRedemptionProtection(cfg.Secret)
	if sender == nil {
		sender = failingVerificationSender{err: errors.New("verification sender is unavailable")}
	}
	settings, secrets, settingsErr := store.LoadServiceSettings(context.Background(), defaultServiceSettings(cfg), cfg.Secret)
	settingsDegraded := settingsErr != nil
	if settingsErr != nil {
		logger.Error("service settings unavailable; safe defaults applied", "error", settingsErr)
		settings = defaultServiceSettings(cfg)
		settings.Registration.Open = false
		secrets = ServiceSecrets{}
	}
	if err := store.EnsureLegalDocument(context.Background(), settings.Terms, "service-startup"); err != nil {
		logger.Error("legal document archive unavailable; registration disabled", "error", err)
		settings.Registration.Open = false
	}
	if settings.SMTP.Enabled {
		smtpConfig := cfg
		smtpConfig.LocalVerification = false
		smtpConfig.SMTPHost, smtpConfig.SMTPPort = settings.SMTP.Host, settings.SMTP.Port
		smtpConfig.SMTPUsername, smtpConfig.SMTPPassword = settings.SMTP.Username, secrets.SMTPPassword
		smtpConfig.SMTPFrom, smtpConfig.SMTPFromName = settings.SMTP.From, settings.SMTP.FromName
		smtpConfig.SMTPTLSMode, smtpConfig.SMTPAuthMode = settings.SMTP.TLSMode, settings.SMTP.AuthMode
		if configured := verificationSenderForConfig(smtpConfig); configured.Mode() == "email" {
			sender = configured
		}
	}
	activeSMTPFingerprint := ""
	if settings.SMTP.Enabled && sender.Mode() == "email" {
		activeSMTPFingerprint = smtpConfigurationFingerprint(settings.SMTP, secrets.SMTPPassword)
	}
	server := &Server{
		cfg: cfg, store: store, scanner: scanner, logger: logger,
		limiter: NewRateLimiter(), settings: &settingsState{settings: settings, secrets: secrets},
		verificationSender: sender, activeSMTPFingerprint: activeSMTPFingerprint, settingsDegraded: settingsDegraded,
		humanVerifierFactory: NewHumanVerifier,
		storage:              storage, storageReplay: NewInternalReplayGuard(),
		uploadSem: make(chan struct{}, cfg.UploadConcurrency), authSem: make(chan struct{}, 4),
		dummyPasswordHash: dummyAccessCodeHash(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health/live", server.healthLive)
	mux.HandleFunc("GET /api/health/ready", server.healthReady)
	mux.HandleFunc("GET /api/health/deep", server.healthDeep)
	mux.HandleFunc("GET /api/v1/config", server.getConfig)
	mux.HandleFunc("GET /api/v1/human-verification/challenge", server.issueHumanVerificationChallenge)
	mux.HandleFunc("POST /api/v1/auth/register", server.register)
	mux.HandleFunc("POST /api/v1/auth/verify", server.verifyRegistration)
	mux.HandleFunc("POST /api/v1/auth/login", server.login)
	mux.HandleFunc("POST /api/v1/auth/logout", server.logout)
	mux.HandleFunc("POST /api/v1/auth/password/request", server.requestPasswordReset)
	mux.HandleFunc("POST /api/v1/auth/password/confirm", server.confirmPasswordReset)
	mux.HandleFunc("GET /api/v1/me", server.getMe)
	mux.HandleFunc("PUT /api/v1/me/profile", server.updateProfile)
	mux.HandleFunc("POST /api/v1/me/password", server.changePassword)
	mux.HandleFunc("GET /api/v1/me/transfers", server.listMyTransfers)
	mux.HandleFunc("GET /api/v1/me/resources", server.listMyResources)
	mux.HandleFunc("GET /api/v1/me/welfare", server.getWelfareStatus)
	mux.HandleFunc("POST /api/v1/me/welfare/check-in", server.claimDailyCheckIn)
	mux.HandleFunc("POST /api/v1/me/transfers/claim", server.claimTransfer)
	mux.HandleFunc("POST /api/v1/me/redemptions", server.redeemCode)
	mux.HandleFunc("GET /api/v1/products", server.listProducts)
	mux.HandleFunc("POST /api/v1/orders", server.createOrder)
	mux.HandleFunc("GET /api/v1/orders", server.listOrders)
	mux.HandleFunc("POST /api/v1/orders/{id}/sandbox-complete", server.completeSandboxOrder)
	mux.HandleFunc("POST /api/v1/reports", server.createReport)
	mux.HandleFunc("GET /api/v1/admin/overview", server.protectedAdminOverview)
	mux.HandleFunc("GET /api/v1/admin/users", server.adminUsers)
	mux.HandleFunc("GET /api/v1/admin/users/{id}", server.adminUserDetail)
	mux.HandleFunc("POST /api/v1/admin/users/{id}/status", server.adminSetUserStatus)
	mux.HandleFunc("GET /api/v1/admin/reports", server.adminReports)
	mux.HandleFunc("POST /api/v1/admin/reports/{id}/status", server.adminSetReportStatus)
	mux.HandleFunc("GET /api/v1/admin/orders", server.adminOrders)
	mux.HandleFunc("POST /api/v1/admin/orders/{id}/refund", server.adminRefundOrder)
	mux.HandleFunc("GET /api/v1/admin/settings", server.adminGetSettings)
	mux.HandleFunc("PUT /api/v1/admin/settings", server.adminUpdateSettings)
	mux.HandleFunc("POST /api/v1/admin/settings/smtp/test", server.adminTestSMTP)
	mux.HandleFunc("GET /api/v1/admin/redemption-batches", server.adminListRedemptionBatches)
	mux.HandleFunc("POST /api/v1/admin/redemption-batches", server.adminCreateRedemptionBatch)
	mux.HandleFunc("POST /api/v1/admin/redemption-batches/{id}/disable", server.adminDisableRedemptionBatch)
	mux.HandleFunc("GET /api/v1/legal/terms", server.getTerms)
	mux.HandleFunc("POST /api/v1/transfers", server.createTransfer)
	mux.HandleFunc("POST /api/v1/transfers/{token}/uploads", server.createUpload)
	if !cfg.ControlPlaneOnly {
		mux.HandleFunc("HEAD /api/v1/uploads/{id}", server.headUpload)
		mux.HandleFunc("PATCH /api/v1/uploads/{id}", server.patchUpload)
		mux.HandleFunc("GET /api/v1/download/{ticket}", server.download)
	}
	mux.HandleFunc("GET /api/v1/shares/{token}", server.getShare)
	mux.HandleFunc("POST /api/v1/shares/{token}/unlock", server.unlockShare)
	mux.HandleFunc("POST /api/v1/shares/{token}/tickets", server.createDownloadTicket)
	mux.HandleFunc("GET /api/v1/pickup/{code}", server.resolvePickup)
	mux.HandleFunc("GET /api/v1/manage/{token}", server.manageTransfer)
	mux.HandleFunc("POST /api/v1/manage/{token}/publish", server.publishTransfer)
	mux.HandleFunc("DELETE /api/v1/manage/{token}", server.revokeTransfer)
	if storage != nil && cfg.UsesRemoteStorage() {
		mux.HandleFunc("POST /internal/v1/storage/uploads/{id}/complete", server.completeStorageUpload)
		mux.HandleFunc("POST /internal/v1/storage/downloads/{id}/begin", server.beginStorageDownload)
		mux.HandleFunc("POST /internal/v1/storage/downloads/{id}/settle", server.settleStorageDownload)
	}
	mux.HandleFunc("/", server.serveFrontend)
	server.handler = server.middleware(mux)
	return server
}

func (server *Server) Handler() http.Handler { return server.handler }

func (server *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		if strings.HasPrefix(request.URL.Path, "/api/") {
			writer.Header().Set("Cache-Control", "no-store")
		}
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		writer.Header().Set("Content-Security-Policy", server.contentSecurityPolicy())
		if server.cfg.PublicMode {
			writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if server.cfg.LocalVerification && !isDirectLoopbackRequest(request) {
			writeAPIError(writer, http.StatusForbidden, "local_only", "本地验证码模式只允许直接从本机访问")
			return
		}
		if request.Method != http.MethodGet && request.Method != http.MethodHead && request.Method != http.MethodOptions {
			if origin := request.Header.Get("Origin"); origin != "" {
				if !server.validRequestOrigin(origin, request.Host) {
					writeAPIError(writer, http.StatusForbidden, "origin_failed", "请求来源校验失败")
					return
				}
			}
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				server.logger.Error("request panic", "error", recovered, "route", safeRequestRoute(request))
				writeAPIError(writer, http.StatusInternalServerError, "internal_error", "服务暂时不可用")
			}
			server.logger.Info("request", "method", request.Method, "route", safeRequestRoute(request), "durationMs", time.Since(started).Milliseconds())
		}()
		next.ServeHTTP(writer, request)
	})
}

func (server *Server) validRequestOrigin(origin, requestHost string) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	if server.cfg.PublicMode {
		expected, expectedErr := url.Parse(server.cfg.BaseURL)
		return expectedErr == nil && strings.EqualFold(parsed.Scheme, expected.Scheme) && strings.EqualFold(parsed.Host, expected.Host)
	}
	return (parsed.Scheme == "http" || parsed.Scheme == "https") && strings.EqualFold(parsed.Host, requestHost)
}

func safeRequestRoute(request *http.Request) string {
	if pattern := strings.TrimSpace(request.Pattern); pattern != "" {
		if _, route, ok := strings.Cut(pattern, " "); ok {
			return route
		}
		return pattern
	}
	if strings.HasPrefix(request.URL.Path, "/api/") || strings.HasPrefix(request.URL.Path, "/s/") ||
		strings.HasPrefix(request.URL.Path, "/c/") {
		return "unmatched-sensitive-route"
	}
	return request.URL.Path
}

func isDirectLoopbackRequest(request *http.Request) bool {
	for _, header := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		if strings.TrimSpace(request.Header.Get(header)) != "" {
			return false
		}
	}
	host := request.Host
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	return isLoopbackHost(host)
}

func (server *Server) healthLive(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{"status": "ok"})
}

func (server *Server) healthReady(writer http.ResponseWriter, request *http.Request) {
	if server.settingsDegraded {
		writeAPIError(writer, http.StatusServiceUnavailable, "security_settings_unavailable", "安全配置不可用")
		return
	}
	if _, err := server.store.Stats(request.Context()); err != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "database_unavailable", "数据库不可用")
		return
	}
	if server.cfg.RequireHumanVerification && !server.criticalHumanVerificationReady() {
		writeAPIError(writer, http.StatusServiceUnavailable, "human_verification_unavailable", "关键操作的人机验证尚未就绪")
		return
	}
	if server.cfg.ControlPlaneOnly {
		var localPlacements int64
		if err := server.store.db.QueryRowContext(request.Context(),
			`SELECT COUNT(*) FROM uploads WHERE storage_kind='local' AND status!='deleted'`).Scan(&localPlacements); err != nil {
			writeAPIError(writer, http.StatusServiceUnavailable, "database_unavailable", "数据库不可用")
			return
		}
		if localPlacements > 0 {
			writeAPIError(writer, http.StatusServiceUnavailable, "local_storage_placements_present", "仍有本地文件等待迁移或清理")
			return
		}
	}
	if _, err := os.Stat(server.cfg.StaticDir); err != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "frontend_unavailable", "前端资源不可用")
		return
	}
	var storageHealth *StorageHealth
	if server.cfg.UsesRemoteStorage() {
		if server.storage == nil {
			writeAPIError(writer, http.StatusServiceUnavailable, "storage_unavailable", "存储节点未配置")
			return
		}
		checkContext, cancel := context.WithTimeout(request.Context(), 3*time.Second)
		health, err := server.storage.Health(checkContext)
		cancel()
		if err != nil || !health.Ready || health.NodeID != server.cfg.StorageNodeID {
			writeAPIError(writer, http.StatusServiceUnavailable, "storage_unavailable", "存储节点未就绪")
			return
		}
		storageHealth = &health
	}
	writeJSON(writer, http.StatusOK, map[string]any{"status": "ready", "scanner": server.scanner.Name(),
		"verification": server.verificationMode(), "buildVersion": buildVersion, "storage": storageHealth})
}

func (server *Server) healthDeep(writer http.ResponseWriter, request *http.Request) {
	if server.cfg.PublicMode || !server.cfg.LoopbackOnly {
		http.NotFound(writer, request)
		return
	}
	if err := server.store.IntegrityCheck(request.Context()); err != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "database_integrity_failed", "数据库完整性检查失败")
		return
	}
	free, err := availableDiskBytes(server.cfg.DataDir)
	if server.cfg.UsesRemoteStorage() {
		if server.storage == nil {
			writeAPIError(writer, http.StatusServiceUnavailable, "storage_unavailable", "存储节点未配置")
			return
		}
		checkContext, cancel := context.WithTimeout(request.Context(), 3*time.Second)
		health, healthErr := server.storage.Health(checkContext)
		cancel()
		if healthErr != nil || !health.Ready || health.NodeID != server.cfg.StorageNodeID {
			writeAPIError(writer, http.StatusServiceUnavailable, "storage_unavailable", "存储节点未就绪")
			return
		}
		free, err = health.FreeBytes, nil
	}
	if err != nil || free < server.cfg.MinFreeBytes {
		writeAPIError(writer, http.StatusInsufficientStorage, "storage_guard", "服务器可用空间不足")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"status": "healthy", "database": "ok", "freeBytes": free,
		"scanner": server.scanner.Name(), "productionScanner": server.scanner.ProductionReady(),
		"verification": server.verificationMode()})
}

func (server *Server) getConfig(writer http.ResponseWriter, request *http.Request) {
	principal := server.principal(writer, request)
	policy := server.effectivePolicy(principal)
	settings, _ := server.settings.snapshot()
	scannerName := server.scanner.Name()
	productionScanner := server.scanner.ProductionReady()
	storageMode := "local"
	storageReady := true
	if server.cfg.UsesRemoteStorage() {
		storageMode = "remote"
		storageReady = false
		scannerName = "远端存储不可用"
		productionScanner = false
		if server.storage != nil {
			checkContext, cancel := context.WithTimeout(request.Context(), 2*time.Second)
			if health, err := server.storage.Health(checkContext); err == nil && health.NodeID == server.cfg.StorageNodeID && health.Ready {
				scannerName, productionScanner = health.Scanner, health.ProductionScanner
				storageReady = true
			}
			cancel()
		}
	}
	captcha := map[string]any{"enabled": settings.Captcha.Enabled, "provider": settings.Captcha.Provider,
		"siteKey": settings.Captcha.SiteKey, "appId": settings.Captcha.TencentCaptchaAppID,
		"actions": settings.Captcha.Actions}
	humanVerificationReady := server.criticalHumanVerificationReady()
	response := map[string]any{
		"maxFileBytes": server.cfg.MaxFileBytes, "maxTransferBytes": server.cfg.MaxTransferBytes,
		"maxFiles": server.cfg.MaxFiles, "defaultExpiryHours": settings.Defaults.DefaultExpiryHours,
		"maxExpiryHours": settings.Defaults.MaximumExpiryHours, "chunkBytes": min(server.cfg.MaxChunkBytes, 4*1024*1024),
		"scanner": scannerName, "productionScanner": productionScanner, "storageMode": storageMode,
		"storageReady":     storageReady,
		"controlPlaneOnly": server.cfg.ControlPlaneOnly, "storageNodeId": server.cfg.StorageNodeID,
		"policy":                         policy,
		"registrationOpen":               server.registrationAvailable(),
		"registrationForceClosed":        server.cfg.RegistrationForceClosed,
		"humanVerificationRequired":      server.cfg.RequireHumanVerification,
		"humanVerificationReady":         humanVerificationReady,
		"emailAllowedDomains":            settings.Registration.AllowedDomains,
		"verificationCodeExpiresSeconds": int(server.cfg.VerificationCodeTTL.Seconds()),
		"verificationCooldownSeconds":    settings.Registration.EmailCooldownSeconds,
		"terms": map[string]any{"version": settings.Terms.Version, "title": settings.Terms.Title,
			"effectiveAt": settings.Terms.EffectiveAt},
		"captcha":        captcha,
		"payments":       map[string]any{"points": settings.Payment.PointsEnabled, "wechat": false, "alipay": false},
		"deploymentMode": map[bool]string{true: "public", false: "local"}[server.cfg.PublicMode],
		"buildVersion":   buildVersion,
	}
	if principal.Authenticated() {
		if account, err := server.store.AccountSummary(request.Context(), principal.ID, settings.Defaults.UserStorageBytes,
			settings.Defaults.UserMonthlyTraffic, time.Now()); err == nil {
			response["account"] = account
		}
	}
	writeJSON(writer, http.StatusOK, response)
}

type createTransferRequest struct {
	Kind         string     `json:"kind"`
	Title        string     `json:"title"`
	AccessCode   string     `json:"accessCode"`
	ExpiresHours int        `json:"expiresHours"`
	MaxDownloads int        `json:"maxDownloads"`
	HumanProof   HumanProof `json:"humanProof"`
}

func (server *Server) createTransfer(writer http.ResponseWriter, request *http.Request) {
	settings, _ := server.settings.snapshot()
	ip := server.clientIP(request)
	if !server.allowPersistent(request, "create:"+ip, 10, time.Hour) {
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "创建任务过于频繁，请稍后再试")
		return
	}
	principal := server.principal(writer, request)
	if principal.Authenticated() {
		_, csrf, _, ok := server.currentUser(request)
		if !ok || !secureEqual(request.Header.Get("X-CSRF-Token"), csrf) {
			writeAPIError(writer, http.StatusForbidden, "csrf_failed", "请求安全校验失败")
			return
		}
	}
	policy := server.effectivePolicy(principal)
	var payload createTransferRequest
	if err := decodeJSON(request, &payload, 16*1024); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "请求参数无效")
		return
	}
	if payload.Kind == "" {
		payload.Kind = "send"
	}
	if payload.Kind != "send" && payload.Kind != "collection" {
		writeAPIError(writer, http.StatusBadRequest, "invalid_kind", "任务类型无效")
		return
	}
	payload.Title = cleanText(payload.Title, 80)
	if payload.Title == "" {
		if payload.Kind == "collection" {
			payload.Title = "文件收集"
		} else {
			payload.Title = "文件分享"
		}
	}
	if strings.TrimSpace(payload.AccessCode) != "" {
		writeAPIError(writer, http.StatusBadRequest, "unsupported_access_code", "新任务不支持访问密码")
		return
	}
	if payload.ExpiresHours == 0 {
		payload.ExpiresHours = settings.Defaults.DefaultExpiryHours
	}
	if payload.ExpiresHours < 1 || payload.ExpiresHours > policy.MaxExpiryHours {
		writeAPIError(writer, http.StatusBadRequest, "invalid_expiry", "有效期超出允许范围")
		return
	}
	if payload.MaxDownloads == 0 {
		payload.MaxDownloads = min(20, policy.MaxDownloads)
	}
	if payload.MaxDownloads < 1 || payload.MaxDownloads > policy.MaxDownloads {
		writeAPIError(writer, http.StatusBadRequest, "invalid_download_limit", "下载次数超出当前账号允许范围")
		return
	}
	if principal.Kind == "guest" {
		if !server.requireHumanVerification(writer, request, "guest_transfer", payload.HumanProof) {
			return
		}
		if settings.Defaults.GuestDailyTasks > 0 {
			allowed, err := server.store.AllowPersistent(request.Context(), "guest-tasks:"+principal.ID,
				settings.Defaults.GuestDailyTasks, 24*time.Hour, 0, 0)
			if err != nil || !allowed {
				writeAPIError(writer, http.StatusTooManyRequests, "guest_daily_limit", "今日游客传输次数已达上限，请登录后继续")
				return
			}
		}
	}
	id, err := randomToken(16)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法创建任务")
		return
	}
	shareToken, err := randomToken(24)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法创建任务")
		return
	}
	manageToken, err := randomToken(24)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法创建任务")
		return
	}
	pickupCode := ""
	if payload.Kind == "collection" {
		pickupCode, err = randomPickupCode(10)
	} else {
		var pendingToken string
		pendingToken, err = randomToken(18)
		pickupCode = pendingPickupPrefix + pendingToken
	}
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法创建任务")
		return
	}
	now := time.Now()
	transfer := Transfer{
		ID: id, Kind: payload.Kind, Title: payload.Title, ShareToken: shareToken,
		ManageHash: tokenHash(manageToken), PickupCode: pickupCode, AccessHash: "",
		Status: "active", ExpiresAt: now.Add(time.Duration(payload.ExpiresHours) * time.Hour).Unix(),
		CreatedAt: now.Unix(), MaxDownloads: payload.MaxDownloads,
		OwnerType: principal.Kind, OwnerID: principal.ID, PolicyMaxFileBytes: policy.MaxFileBytes,
		PolicyMaxTaskBytes: policy.MaxTransferBytes, PolicyMaxFiles: policy.MaxFiles,
	}
	if payload.Kind == "send" {
		transfer.DownloadLimitMode = DownloadLimitModeRetrievalSessionV1
		transfer.DeleteOnExhaustion = true
	} else {
		transfer.DownloadLimitMode = DownloadLimitModeLegacyFile
	}
	if err := server.store.CreateTransfer(request.Context(), transfer); err != nil {
		server.logger.Error("create transfer", "error", err)
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法创建任务")
		return
	}
	sharePath := "/s/" + shareToken
	if payload.Kind == "collection" {
		sharePath = "/c/" + shareToken
	}
	response := map[string]any{
		"kind": payload.Kind, "title": payload.Title, "shareToken": shareToken,
		"manageToken": manageToken, "expiresAt": transfer.ExpiresAt, "policy": policy,
	}
	if payload.Kind == "collection" {
		response["pickupCode"] = pickupCode
		response["shareURL"] = server.cfg.BaseURL + sharePath
		response["downloadURL"] = server.cfg.BaseURL + "/s/" + shareToken
	}
	writeJSON(writer, http.StatusCreated, response)
}

type createUploadRequest struct {
	Name          string     `json:"name"`
	Size          int64      `json:"size"`
	ContentType   string     `json:"contentType"`
	SubmitterName string     `json:"submitterName"`
	HumanProof    HumanProof `json:"humanProof"`
}

func (server *Server) createUpload(writer http.ResponseWriter, request *http.Request) {
	settings, _ := server.settings.snapshot()
	ip := server.clientIP(request)
	if !server.allowPersistent(request, "upload-create:"+ip, 120, time.Hour) {
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "上传任务过于频繁")
		return
	}
	transfer, err := server.activeTransfer(request.Context(), request.PathValue("token"))
	if err != nil {
		writeAPIError(writer, http.StatusGone, "transfer_unavailable", "任务不存在或已失效")
		return
	}
	user, csrf, _, loggedIn := server.currentUser(request)
	if transfer.Kind == "send" {
		accountOwner := loggedIn && transfer.OwnerType == "user" && transfer.OwnerID == user.ID
		if accountOwner && !secureEqual(request.Header.Get("X-CSRF-Token"), csrf) {
			writeAPIError(writer, http.StatusForbidden, "csrf_failed", "请求安全校验失败")
			return
		}
		if !accountOwner && !secureEqual(tokenHash(request.Header.Get("X-Manage-Token")), transfer.ManageHash) {
			writeAPIError(writer, http.StatusUnauthorized, "manage_token_required", "无权向此任务上传")
			return
		}
	} else if transfer.AccessHash != "" && !server.validUnlock(request.Header.Get("X-Unlock-Token"), transfer.ID) {
		writeAPIError(writer, http.StatusUnauthorized, "unlock_required", "请先验证收集密码")
		return
	}
	var payload createUploadRequest
	if err := decodeJSON(request, &payload, 32*1024); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "文件信息无效")
		return
	}
	payload.Name = cleanFilename(payload.Name)
	payload.SubmitterName = cleanText(payload.SubmitterName, 48)
	maxFileBytes := transfer.PolicyMaxFileBytes
	if maxFileBytes <= 0 {
		maxFileBytes = server.cfg.MaxFileBytes
	}
	maxTaskBytes := transfer.PolicyMaxTaskBytes
	if maxTaskBytes <= 0 {
		maxTaskBytes = server.cfg.MaxTransferBytes
	}
	maxFiles := transfer.PolicyMaxFiles
	if maxFiles <= 0 {
		maxFiles = server.cfg.MaxFiles
	}
	anonymousUploader := !loggedIn
	if anonymousUploader && transfer.OwnerType != "guest" {
		const anonymousCap = int64(100 * 1024 * 1024)
		maxFileBytes = min(maxFileBytes, min(settings.Defaults.GuestMaxFileBytes, anonymousCap))
	}
	if payload.Name == "" || payload.Size <= 0 || payload.Size > maxFileBytes {
		writeAPIError(writer, http.StatusRequestEntityTooLarge, "invalid_file", "文件为空或超过本次上传总量上限")
		return
	}
	if anonymousUploader && isGuestBlockedFilename(payload.Name) {
		writeAPIError(writer, http.StatusUnsupportedMediaType, "guest_file_type_blocked", "游客不能上传可执行文件或脚本，请登录后再试")
		return
	}
	if transfer.Kind == "collection" && anonymousUploader {
		if !server.requireHumanVerification(writer, request, "guest_transfer", payload.HumanProof) {
			return
		}
	}
	if anonymousUploader && transfer.OwnerType != "guest" {
		principal := server.principal(writer, request)
		allowed, limitErr := server.store.AllowPersistent(request.Context(), "anonymous-upload-bytes:"+principal.ID,
			0, 24*time.Hour, payload.Size, settings.Defaults.GuestDailyBytes)
		if limitErr != nil || !allowed {
			writeAPIError(writer, http.StatusTooManyRequests, "guest_daily_limit", "今日游客上传额度已用完，请登录后继续")
			return
		}
		ipKey := privateRateKey(server.cfg.Secret, server.clientIP(request))
		allowed, limitErr = server.store.AllowPersistent(request.Context(), "anonymous-upload-ip-bytes:"+ipKey,
			0, 24*time.Hour, payload.Size, settings.Defaults.GuestDailyBytes)
		if limitErr != nil || !allowed {
			writeAPIError(writer, http.StatusTooManyRequests, "guest_daily_limit", "当前网络今日游客上传额度已用完，请登录后继续")
			return
		}
	}
	remoteStorage := server.storage != nil && server.cfg.UsesRemoteStorage()
	if server.cfg.ControlPlaneOnly && !remoteStorage {
		writeAPIError(writer, http.StatusServiceUnavailable, "storage_unavailable", "控制面未连接到远端存储节点")
		return
	}
	if !remoteStorage {
		free, err := availableDiskBytes(server.cfg.DataDir)
		if err != nil || free < server.cfg.MinFreeBytes+uint64(payload.Size) {
			writeAPIError(writer, http.StatusInsufficientStorage, "storage_guard", "服务器可用空间不足")
			return
		}
	}
	payload.ContentType = detectContentType(payload.Name)
	id, err := randomToken(16)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法准备上传")
		return
	}
	uploadToken, err := randomToken(24)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法准备上传")
		return
	}
	tempPath := ""
	if !remoteStorage {
		tempPath = filepath.Join(server.cfg.DataDir, "tmp", id+".part")
		file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			writeAPIError(writer, http.StatusInternalServerError, "storage_error", "无法准备上传空间")
			return
		}
		_ = file.Close()
	}
	upload := Upload{ID: id, TransferID: transfer.ID, UploadHash: tokenHash(uploadToken),
		OriginalName: payload.Name, ContentType: payload.ContentType, Length: payload.Size,
		Status: "uploading", TempPath: tempPath, SubmitterName: payload.SubmitterName, CreatedAt: time.Now().Unix()}
	if remoteStorage {
		upload.StorageKind = StorageKindNode
		upload.StorageNodeID = server.cfg.StorageNodeID
		upload.StorageKey = id
		upload.StorageVersion = StoragePlacementVersionV1
	} else {
		upload.StorageKind = StorageKindLocal
		upload.StorageVersion = StoragePlacementVersionV1
	}
	if err := server.store.CreateUploadWithQuota(request.Context(), upload, transfer, maxFiles, maxTaskBytes,
		settings.Defaults.UserStorageBytes, settings.Defaults.UserMonthlyTraffic, settings.Defaults.GuestDailyBytes); err != nil {
		if !remoteStorage {
			_ = os.Remove(tempPath)
		}
		if errors.Is(err, ErrTrafficExceeded) {
			writeAPIError(writer, http.StatusPaymentRequired, "traffic_insufficient", "剩余上传流量不足，请购买流量或兑换后继续")
			return
		}
		if errors.Is(err, ErrQuotaExceeded) {
			writeAPIError(writer, http.StatusRequestEntityTooLarge, "transfer_limit", "任务大小或文件数量已达当前等级上限")
			return
		}
		if errors.Is(err, ErrRateLimited) {
			writeAPIError(writer, http.StatusTooManyRequests, "guest_daily_limit", "今日游客上传额度已用完，请登录后继续")
			return
		}
		writeAPIError(writer, http.StatusConflict, "transfer_unavailable", "无法加入此任务")
		return
	}
	offset := int64(0)
	if remoteStorage {
		reserved, reserveErr := server.storage.ReserveUpload(request.Context(), StorageReserveUploadRequest{
			ID: id, UploadTokenHash: tokenHash(uploadToken), OriginalName: payload.Name,
			ContentType: payload.ContentType, Length: payload.Size, ExpiresAt: transfer.ExpiresAt,
		})
		if reserveErr != nil || reserved.ID != id || reserved.Length != payload.Size || reserved.Offset < 0 || reserved.Offset > payload.Size {
			deleteContext, cancelDelete := context.WithTimeout(context.Background(), 5*time.Second)
			_ = server.storage.DeleteUpload(deleteContext, id)
			cancelDelete()
			_ = server.store.MarkDeleted(request.Context(), upload)
			server.logger.Error("reserve remote upload", "upload", id, "error", reserveErr)
			writeAPIError(writer, http.StatusServiceUnavailable, "storage_unavailable", "存储节点暂时不可用，请稍后重试")
			return
		}
		offset = reserved.Offset
	}
	uploadURL := "/api/v1/uploads/" + id
	if remoteStorage {
		uploadURL = server.cfg.StoragePublicURL + "/storage/v1/uploads/" + url.PathEscape(id)
	}
	writeJSON(writer, http.StatusCreated, map[string]any{
		"id": id, "uploadToken": uploadToken, "uploadURL": uploadURL,
		"offset": offset, "length": payload.Size, "chunkBytes": min(server.cfg.MaxChunkBytes, 4*1024*1024),
	})
}

func (server *Server) headUpload(writer http.ResponseWriter, request *http.Request) {
	upload, ok := server.authorizedUpload(writer, request)
	if !ok {
		return
	}
	if !upload.IsLocalStorage() {
		http.NotFound(writer, request)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Upload-Offset", strconv.FormatInt(upload.Offset, 10))
	writer.Header().Set("Upload-Length", strconv.FormatInt(upload.Length, 10))
	writer.Header().Set("Upload-Status", upload.Status)
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) patchUpload(writer http.ResponseWriter, request *http.Request) {
	select {
	case server.uploadSem <- struct{}{}:
		defer func() { <-server.uploadSem }()
	default:
		writeAPIError(writer, http.StatusTooManyRequests, "upload_busy", "当前上传较多，请稍后继续")
		return
	}
	value, _ := server.locks.LoadOrStore(request.PathValue("id"), &sync.Mutex{})
	lock := value.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()
	upload, ok := server.authorizedUpload(writer, request)
	if !ok {
		return
	}
	if !upload.IsLocalStorage() {
		http.NotFound(writer, request)
		return
	}
	if upload.Status != "uploading" {
		writer.Header().Set("Upload-Offset", strconv.FormatInt(upload.Offset, 10))
		writer.Header().Set("Upload-Status", upload.Status)
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if request.Header.Get("Content-Type") != "application/offset+octet-stream" {
		writeAPIError(writer, http.StatusUnsupportedMediaType, "invalid_content_type", "上传分片类型无效")
		return
	}
	offset, err := strconv.ParseInt(request.Header.Get("Upload-Offset"), 10, 64)
	if err != nil || offset != upload.Offset {
		writer.Header().Set("Upload-Offset", strconv.FormatInt(upload.Offset, 10))
		writeAPIError(writer, http.StatusConflict, "offset_mismatch", "上传偏移不一致，请重新同步")
		return
	}
	remaining := upload.Length - upload.Offset
	limit := min(server.cfg.MaxChunkBytes, remaining)
	if request.ContentLength < 0 || request.ContentLength > limit {
		writeAPIError(writer, http.StatusRequestEntityTooLarge, "chunk_too_large", "上传分片超过允许大小")
		return
	}
	file, err := os.OpenFile(upload.TempPath, os.O_WRONLY, 0o600)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "storage_error", "上传临时文件不可用")
		return
	}
	if _, err := file.Seek(upload.Offset, io.SeekStart); err != nil {
		_ = file.Close()
		writeAPIError(writer, http.StatusInternalServerError, "storage_error", "无法继续上传")
		return
	}
	reader := http.MaxBytesReader(writer, request.Body, limit)
	written, copyErr := io.Copy(file, reader)
	if copyErr == nil {
		copyErr = file.Sync()
	}
	_ = file.Close()
	if copyErr != nil {
		_ = os.Truncate(upload.TempPath, upload.Offset)
		writeAPIError(writer, http.StatusBadRequest, "chunk_failed", "上传分片失败，可稍后续传")
		return
	}
	next := upload.Offset + written
	if err := server.store.UpdateUploadOffset(request.Context(), upload.ID, upload.Offset, next); err != nil {
		_ = os.Truncate(upload.TempPath, upload.Offset)
		writeAPIError(writer, http.StatusConflict, "offset_conflict", "上传状态已变化，请重新同步")
		return
	}
	status := "uploading"
	if next == upload.Length {
		upload.Offset = next
		if err := finalizeUpload(request.Context(), server.cfg, server.store, upload); err != nil {
			server.logger.Error("finalize upload", "upload", upload.ID, "error", err)
			writeAPIError(writer, http.StatusInternalServerError, "finalize_failed", "文件已上传但暂时无法完成处理")
			return
		}
		status = "uploaded"
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Upload-Offset", strconv.FormatInt(next, 10))
	writer.Header().Set("Upload-Status", status)
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) getShare(writer http.ResponseWriter, request *http.Request) {
	transfer, err := server.store.TransferByShare(request.Context(), request.PathValue("token"))
	if err != nil {
		writeAPIError(writer, http.StatusGone, "transfer_unavailable", "文件不存在或已失效")
		return
	}
	if transfer.DownloadLimitMode == DownloadLimitModeRetrievalSessionV1 && transfer.DeleteOnExhaustion {
		_, retrievalValid := server.validRetrievalSession(request.Context(),
			request.Header.Get(retrievalTokenHeader), transfer.ID)
		if err := activeOrExhaustedTransfer(transfer, retrievalValid, time.Now().Unix()); err != nil {
			if errors.Is(err, ErrDownloadLimit) {
				writeDownloadLimitError(writer)
			} else {
				writeAPIError(writer, http.StatusGone, "transfer_unavailable", "文件不存在或已失效")
			}
			return
		}
	} else if transfer.Status != TransferStatusActive || transfer.ExpiresAt <= time.Now().Unix() {
		writeAPIError(writer, http.StatusGone, "transfer_unavailable", "文件不存在或已失效")
		return
	}
	if !transferPublished(transfer) {
		writeAPIError(writer, http.StatusGone, "transfer_unavailable", "文件尚未完成上传")
		return
	}
	unlocked := transfer.AccessHash == "" || server.validUnlock(request.Header.Get("X-Unlock-Token"), transfer.ID)
	public, err := server.publicTransfer(request.Context(), transfer, unlocked, false)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "暂时无法读取文件")
		return
	}
	// Collection links are submission-only. Existing submissions are visible only
	// through the manager endpoint so one contributor cannot inspect another.
	if transfer.Kind == "collection" {
		public.Files = []Upload{}
		public.FileCount = 0
		public.TotalBytes = 0
		public.Downloads = 0
		public.Scanning = false
		public.BlockedFiles = 0
	}
	writeJSON(writer, http.StatusOK, public)
}

func (server *Server) unlockShare(writer http.ResponseWriter, request *http.Request) {
	ipKey := privateRateKey(server.cfg.Secret, server.clientIP(request))
	shareKey := privateRateKey(server.cfg.Secret, request.PathValue("token"))
	for _, limit := range []struct {
		key   string
		count int
	}{
		{key: "unlock:ip-share:" + ipKey + ":" + shareKey, count: 5},
		{key: "unlock:share:" + shareKey, count: 30},
		{key: "unlock:ip:" + ipKey, count: 50},
	} {
		if !server.allowPersistent(request, limit.key, limit.count, 15*time.Minute) {
			writer.Header().Set("Retry-After", "900")
			writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "密码尝试次数过多，请稍后再试")
			return
		}
	}
	transfer, err := server.activeTransfer(request.Context(), request.PathValue("token"))
	if err != nil {
		writeAPIError(writer, http.StatusGone, "transfer_unavailable", "任务不存在或已失效")
		return
	}
	var payload struct {
		Code string `json:"code"`
	}
	if decodeJSON(request, &payload, 4096) != nil || transfer.AccessHash == "" || !verifyAccessCode(transfer.AccessHash, payload.Code) {
		writeAPIError(writer, http.StatusUnauthorized, "invalid_access_code", "访问密码不正确")
		return
	}
	ticket, err := signTicket(server.cfg.Secret, "unlock", transfer.ID, 30*time.Minute)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "验证失败")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"unlockToken": ticket, "expiresIn": 1800})
}

func (server *Server) createDownloadTicket(writer http.ResponseWriter, request *http.Request) {
	ip := server.clientIP(request)
	if !server.allowPersistent(request, "download-ticket:"+ip, 120, time.Hour) {
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "下载请求过于频繁")
		return
	}
	transfer, err := server.store.TransferByShare(request.Context(), request.PathValue("token"))
	if err != nil {
		writeAPIError(writer, http.StatusGone, "transfer_unavailable", "任务不存在或已失效")
		return
	}
	retrievalMode := transfer.DownloadLimitMode == DownloadLimitModeRetrievalSessionV1 &&
		transfer.DeleteOnExhaustion
	var retrievalSession RetrievalSession
	retrievalValid := false
	if retrievalMode {
		retrievalSession, retrievalValid = server.validRetrievalSession(request.Context(),
			request.Header.Get(retrievalTokenHeader), transfer.ID)
		if err := activeOrExhaustedTransfer(transfer, retrievalValid, time.Now().Unix()); err != nil {
			if errors.Is(err, ErrDownloadLimit) {
				writeDownloadLimitError(writer)
			} else {
				writeAPIError(writer, http.StatusGone, "transfer_unavailable", "任务不存在或已失效")
			}
			return
		}
	} else if transfer.Status != TransferStatusActive || transfer.ExpiresAt <= time.Now().Unix() {
		writeAPIError(writer, http.StatusGone, "transfer_unavailable", "任务不存在或已失效")
		return
	}
	if !transferPublished(transfer) {
		writeAPIError(writer, http.StatusGone, "transfer_unavailable", "文件尚未完成上传")
		return
	}
	user, _, _, loggedIn := server.currentUser(request)
	accountOwner := loggedIn && transfer.OwnerType == "user" && transfer.OwnerID == user.ID
	if accountOwner {
		_, csrf, _, ok := server.currentUser(request)
		if !ok || !secureEqual(request.Header.Get("X-CSRF-Token"), csrf) {
			writeAPIError(writer, http.StatusForbidden, "csrf_failed", "请求安全校验失败")
			return
		}
	}
	if transfer.Kind == "collection" && !accountOwner && !secureEqual(tokenHash(request.Header.Get("X-Manage-Token")), transfer.ManageHash) {
		writeAPIError(writer, http.StatusUnauthorized, "manage_token_required", "收集文件仅创建者可以下载")
		return
	}
	if transfer.Kind != "collection" && transfer.AccessHash != "" && !server.validUnlock(request.Header.Get("X-Unlock-Token"), transfer.ID) {
		writeAPIError(writer, http.StatusUnauthorized, "unlock_required", "请先验证访问密码")
		return
	}
	var payload struct {
		FileID string `json:"fileId"`
	}
	if decodeJSON(request, &payload, 4096) != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "下载参数无效")
		return
	}
	upload, err := server.store.ReadyUploadForTransfer(request.Context(), transfer.ID, payload.FileID)
	if err != nil {
		writeAPIError(writer, http.StatusNotFound, "file_not_found", "文件不可用")
		return
	}
	recipientSubject := "anonymous\x00" + ip + "\x00" + request.UserAgent()
	if loggedIn {
		recipientSubject = "user\x00" + user.ID
	}
	recipientKey := privateRateKey(server.cfg.Secret, "download-recipient\x00"+recipientSubject)
	var reservation DownloadReservation
	createdSession := false
	if retrievalMode {
		retrievalSessionID := ""
		if retrievalValid {
			retrievalSessionID = retrievalSession.ID
		}
		reservation, retrievalSession, createdSession, err = server.store.CreateRetrievalDownloadReservation(
			request.Context(), transfer, upload, recipientKey, retrievalSessionID, 5*time.Minute)
	} else {
		settings, _ := server.settings.snapshot()
		reservation, err = server.store.CreateDownloadReservationForRecipient(request.Context(),
			transfer, upload, recipientKey, settings.Defaults.UserMonthlyTraffic, 5*time.Minute)
	}
	if err != nil {
		if errors.Is(err, ErrDownloadLimit) {
			writeDownloadLimitError(writer)
		} else if errors.Is(err, ErrNotFound) {
			writeAPIError(writer, http.StatusGone, "transfer_unavailable", "任务不存在或已失效")
		} else if errors.Is(err, ErrConflict) {
			writeAPIError(writer, http.StatusConflict, "download_in_progress", "该文件正在当前领取会话中下载")
		} else {
			server.logger.Error("create retrieval session", "transfer", transfer.ID, "error", err)
			writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法创建下载凭据")
		}
		return
	}
	abortReservation := func() {
		_ = server.store.AbortRetrievalDownloadReservation(request.Context(), reservation.ID,
			retrievalMode && createdSession, time.Now().Unix())
	}
	retrievalToken := ""
	retrievalExpiresAt := int64(0)
	if retrievalMode {
		retrievalToken, err = server.signRetrievalSession(retrievalSession)
		if err != nil {
			abortReservation()
			writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法创建领取会话")
			return
		}
		retrievalExpiresAt = retrievalSession.HardExpiresAt
	}
	downloadURL := ""
	if upload.IsNodeStorage() {
		if server.storage == nil || !server.cfg.UsesRemoteStorage() ||
			upload.StorageNodeID != server.cfg.StorageNodeID || upload.StorageKey != upload.ID {
			abortReservation()
			writeAPIError(writer, http.StatusServiceUnavailable, "storage_unavailable", "文件所在存储节点暂时不可用")
			return
		}
		nonce, nonceErr := randomToken(18)
		claims := StorageDownloadClaims{
			Version: StorageDownloadTicketVersion, Purpose: StorageDownloadTicketPurpose,
			KeyID: StorageDownloadTicketKeyID, NodeID: upload.StorageNodeID,
			ReservationID: reservation.ID, UploadID: upload.ID,
			ExpiresAt: time.Now().Add(5 * time.Minute).Unix(), Nonce: nonce,
		}
		ticket, ticketErr := SignStorageDownloadTicket(server.cfg.StorageSharedSecret, claims)
		if nonceErr != nil || ticketErr != nil {
			abortReservation()
			writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法创建下载凭据")
			return
		}
		downloadURL = server.cfg.StoragePublicURL + "/storage/v1/download/" + url.PathEscape(ticket)
	} else {
		if server.cfg.ControlPlaneOnly {
			abortReservation()
			writeAPIError(writer, http.StatusServiceUnavailable, "local_storage_placement", "文件仍在本地存储，需迁移后方可下载")
			return
		}
		ticket, ticketErr := signTicket(server.cfg.Secret, "download", reservation.ID, 5*time.Minute)
		if ticketErr != nil {
			abortReservation()
			writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法创建下载凭据")
			return
		}
		downloadURL = "/api/v1/download/" + ticket
	}
	writeJSON(writer, http.StatusCreated, map[string]any{
		"downloadURL": downloadURL, "expiresIn": 300,
		"retrievalToken": retrievalToken, "retrievalExpiresAt": retrievalExpiresAt,
	})
}

func (server *Server) resolvePickup(writer http.ResponseWriter, request *http.Request) {
	ip := server.clientIP(request)
	if !server.allowPersistent(request, "pickup:"+ip, 10, 15*time.Minute) {
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "取件码尝试次数过多")
		return
	}
	code := strings.ToUpper(strings.TrimSpace(request.PathValue("code")))
	transfer, err := server.store.TransferByPickup(request.Context(), code)
	if err == nil && transfer.DownloadLimitMode == DownloadLimitModeRetrievalSessionV1 &&
		transfer.DeleteOnExhaustion && transfer.Status == TransferStatusExhausted &&
		transfer.ExpiresAt > time.Now().Unix() {
		writeDownloadLimitError(writer)
		return
	}
	if err != nil || transfer.Status != TransferStatusActive || transfer.ExpiresAt <= time.Now().Unix() {
		writeAPIError(writer, http.StatusNotFound, "pickup_not_found", "取件码不存在或已失效")
		return
	}
	sharePath := "/s/" + transfer.ShareToken
	if transfer.Kind == "collection" {
		sharePath = "/c/" + transfer.ShareToken
	}
	writeJSON(writer, http.StatusOK, map[string]any{"kind": transfer.Kind, "shareToken": transfer.ShareToken, "shareURL": server.cfg.BaseURL + sharePath})
}

func (server *Server) download(writer http.ResponseWriter, request *http.Request) {
	settings, _ := server.settings.snapshot()
	if strings.Contains(request.Header.Get("Range"), ",") {
		writer.Header().Set("Content-Range", "bytes */*")
		writeAPIError(writer, http.StatusRequestedRangeNotSatisfiable, "invalid_range", "仅支持单个分段下载")
		return
	}
	reservationID, err := verifyTicket(server.cfg.Secret, request.PathValue("ticket"), "download")
	if err != nil {
		writeAPIError(writer, http.StatusUnauthorized, "invalid_ticket", "下载链接已失效")
		return
	}
	reservation, err := server.store.BeginDownloadReservation(request.Context(), reservationID, time.Now().Unix())
	if err != nil {
		if errors.Is(err, ErrQuotaExceeded) || errors.Is(err, ErrDownloadLimit) {
			writeDownloadLimitError(writer)
		} else {
			writeAPIError(writer, http.StatusUnauthorized, "invalid_ticket", "下载链接已使用或失效")
		}
		return
	}
	upload, _, err := server.store.ReadyUploadForDownload(request.Context(), reservation.UploadID)
	if err != nil || !upload.IsLocalStorage() {
		_ = server.store.SettleDownloadReservation(request.Context(), reservation.ID, 0, settings.Defaults.UserMonthlyTraffic, time.Now().Unix())
		writeAPIError(writer, http.StatusGone, "file_unavailable", "文件不存在或已失效")
		return
	}
	file, err := os.Open(upload.ObjectPath)
	if err != nil {
		_ = server.store.SettleDownloadReservation(request.Context(), reservation.ID, 0, settings.Defaults.UserMonthlyTraffic, time.Now().Unix())
		writeAPIError(writer, http.StatusGone, "file_unavailable", "文件不可用")
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		_ = server.store.SettleDownloadReservation(request.Context(), reservation.ID, 0, settings.Defaults.UserMonthlyTraffic, time.Now().Unix())
		writeAPIError(writer, http.StatusInternalServerError, "storage_error", "无法读取文件")
		return
	}
	writer.Header().Set("Content-Type", upload.ContentType)
	writer.Header().Set("Content-Disposition", contentDisposition(upload.OriginalName))
	writer.Header().Set("Cache-Control", "private, no-store")
	counter := &countingResponseWriter{ResponseWriter: writer}
	http.ServeContent(counter, request, upload.OriginalName, info.ModTime(), file)
	settleContext, settleCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer settleCancel()
	if err := server.store.SettleDownloadReservation(settleContext, reservation.ID, counter.bytes,
		settings.Defaults.UserMonthlyTraffic, time.Now().Unix()); err != nil {
		server.logger.Error("settle download traffic", "reservation", reservation.ID, "bytes", counter.bytes, "error", err)
	}
}

func (server *Server) manageTransfer(writer http.ResponseWriter, request *http.Request) {
	transfer, err := server.store.TransferByShare(request.Context(), request.PathValue("token"))
	user, _, _, loggedIn := server.currentUser(request)
	accountOwner := loggedIn && transfer.OwnerType == "user" && transfer.OwnerID == user.ID
	if err != nil || (!accountOwner && !secureEqual(tokenHash(request.Header.Get("X-Manage-Token")), transfer.ManageHash)) {
		writeAPIError(writer, http.StatusUnauthorized, "invalid_manage_token", "管理凭据无效")
		return
	}
	public, err := server.publicTransfer(request.Context(), transfer, true, true)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法读取任务")
		return
	}
	writeJSON(writer, http.StatusOK, public)
}

func (server *Server) publishTransfer(writer http.ResponseWriter, request *http.Request) {
	transfer, err := server.store.TransferByShare(request.Context(), request.PathValue("token"))
	if err != nil {
		writeAPIError(writer, http.StatusUnauthorized, "invalid_manage_token", "管理凭据无效")
		return
	}
	user, csrf, _, loggedIn := server.currentUser(request)
	accountOwner := loggedIn && transfer.OwnerType == "user" && transfer.OwnerID == user.ID
	if accountOwner && !secureEqual(request.Header.Get("X-CSRF-Token"), csrf) {
		writeAPIError(writer, http.StatusForbidden, "csrf_failed", "请求安全校验失败")
		return
	}
	if !accountOwner && !secureEqual(tokenHash(request.Header.Get("X-Manage-Token")), transfer.ManageHash) {
		writeAPIError(writer, http.StatusUnauthorized, "invalid_manage_token", "管理凭据无效")
		return
	}
	if transfer.Status != "active" || transfer.ExpiresAt <= time.Now().Unix() {
		writeAPIError(writer, http.StatusGone, "transfer_unavailable", "任务不存在或已失效")
		return
	}

	value, _ := server.locks.LoadOrStore("publish:"+transfer.ID, &sync.Mutex{})
	lock := value.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()

	transfer, err = server.store.TransferByID(request.Context(), transfer.ID)
	if err != nil {
		writeAPIError(writer, http.StatusGone, "transfer_unavailable", "任务不存在或已失效")
		return
	}
	if transfer.Kind == "send" && !transferPublished(transfer) {
		managed, readErr := server.publicTransfer(request.Context(), transfer, true, true)
		if readErr != nil {
			writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法读取任务")
			return
		}
		readyFiles := 0
		for _, upload := range managed.Files {
			if upload.Status == "ready" {
				readyFiles++
			}
		}
		if managed.Scanning {
			writeAPIError(writer, http.StatusConflict, "transfer_not_ready", "文件检查尚未完成")
			return
		}
		if readyFiles == 0 {
			writeAPIError(writer, http.StatusConflict, "no_ready_files", "没有可分享的文件")
			return
		}
		pickupCode, randomErr := randomPickupCode(10)
		if randomErr != nil {
			writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法发布任务")
			return
		}
		if updateErr := server.store.PublishTransfer(request.Context(), transfer.ID, transfer.PickupCode, pickupCode); updateErr != nil {
			server.logger.Error("publish transfer", "transfer", transfer.ID, "error", updateErr)
			writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法发布任务")
			return
		}
		transfer.PickupCode = pickupCode
	}
	writeJSON(writer, http.StatusOK, publishedTransferResponse(server.cfg.BaseURL, transfer))
}

func (server *Server) revokeTransfer(writer http.ResponseWriter, request *http.Request) {
	transfer, err := server.store.TransferByShare(request.Context(), request.PathValue("token"))
	user, csrf, _, loggedIn := server.currentUser(request)
	accountOwner := loggedIn && transfer.OwnerType == "user" && transfer.OwnerID == user.ID
	if accountOwner && !secureEqual(request.Header.Get("X-CSRF-Token"), csrf) {
		writeAPIError(writer, http.StatusForbidden, "csrf_failed", "请求安全校验失败")
		return
	}
	if err != nil || (!accountOwner && !secureEqual(tokenHash(request.Header.Get("X-Manage-Token")), transfer.ManageHash)) {
		writeAPIError(writer, http.StatusUnauthorized, "invalid_manage_token", "管理凭据无效")
		return
	}
	if err := server.store.RevokeTransfer(request.Context(), transfer.ID); err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "internal_error", "无法撤销任务")
		return
	}
	if accountOwner {
		_ = server.store.AddAudit(request.Context(), user.ID, "transfer.revoke", "transfer", transfer.ID, "", server.clientIP(request))
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) protectedAdminOverview(writer http.ResponseWriter, request *http.Request) {
	user, ok := server.requireAdmin(writer, request, true)
	if !ok {
		return
	}
	if !server.allowPersistent(request, "admin-overview:"+user.ID, 120, time.Minute) {
		writer.Header().Set("Retry-After", "60")
		writeAPIError(writer, http.StatusTooManyRequests, "rate_limited", "管理统计读取过于频繁")
		return
	}
	server.adminOverview(writer, request)
}

func (server *Server) activeTransfer(ctx context.Context, shareToken string) (Transfer, error) {
	transfer, err := server.store.TransferByShare(ctx, shareToken)
	if err != nil {
		return Transfer{}, err
	}
	if transfer.Status != "active" || transfer.ExpiresAt <= time.Now().Unix() {
		return Transfer{}, ErrNotFound
	}
	return transfer, nil
}

func transferPublished(transfer Transfer) bool {
	return transfer.Kind == "collection" || !strings.HasPrefix(transfer.PickupCode, pendingPickupPrefix)
}

func publishedTransferResponse(baseURL string, transfer Transfer) map[string]any {
	sharePath := "/s/" + transfer.ShareToken
	if transfer.Kind == "collection" {
		sharePath = "/c/" + transfer.ShareToken
	}
	return map[string]any{
		"kind": transfer.Kind, "title": transfer.Title, "shareToken": transfer.ShareToken,
		"pickupCode": transfer.PickupCode, "expiresAt": transfer.ExpiresAt,
		"maxDownloads": transfer.MaxDownloads,
		"shareURL":     baseURL + sharePath, "downloadURL": baseURL + "/s/" + transfer.ShareToken,
	}
}

func (server *Server) publicTransfer(ctx context.Context, transfer Transfer, unlocked, includeAll bool) (PublicTransfer, error) {
	uploads, err := server.store.UploadsForTransfer(ctx, transfer.ID, false)
	if err != nil {
		return PublicTransfer{}, err
	}
	public := PublicTransfer{Kind: transfer.Kind, Title: transfer.Title, ShareToken: transfer.ShareToken,
		PickupCode: transfer.PickupCode, Status: transfer.Status, ExpiresAt: transfer.ExpiresAt,
		CreatedAt: transfer.CreatedAt, MaxDownloads: transfer.MaxDownloads, Downloads: transfer.Downloads, TotalBytes: transfer.TotalBytes,
		FileCount: transfer.FileCount, Locked: transfer.AccessHash != "" && !unlocked, Files: []Upload{}}
	if !transferPublished(transfer) {
		public.PickupCode = ""
	}
	for _, upload := range uploads {
		switch upload.Status {
		case "uploading", "uploaded", "scanning":
			public.Scanning = true
		case "blocked", "quarantined":
			public.BlockedFiles++
		}
		if includeAll || (unlocked && upload.Status == "ready") {
			public.Files = append(public.Files, upload)
		}
	}
	return public, nil
}

func (server *Server) authorizedUpload(writer http.ResponseWriter, request *http.Request) (Upload, bool) {
	upload, err := server.store.UploadByID(request.Context(), request.PathValue("id"))
	if err != nil {
		writeAPIError(writer, http.StatusNotFound, "upload_not_found", "上传会话不存在")
		return Upload{}, false
	}
	authorization := strings.TrimSpace(request.Header.Get("Authorization"))
	token := strings.TrimPrefix(authorization, "Bearer ")
	if token == authorization || !secureEqual(tokenHash(token), upload.UploadHash) {
		writeAPIError(writer, http.StatusUnauthorized, "invalid_upload_token", "上传凭据无效")
		return Upload{}, false
	}
	return upload, true
}

func (server *Server) validUnlock(ticket, transferID string) bool {
	subject, err := verifyTicket(server.cfg.Secret, ticket, "unlock")
	return err == nil && secureEqual(subject, transferID)
}

func (server *Server) serveFrontend(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		http.NotFound(writer, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/api/") || strings.HasPrefix(request.URL.Path, "/internal/") {
		http.NotFound(writer, request)
		return
	}
	cleaned := filepath.Clean(strings.TrimPrefix(request.URL.Path, "/"))
	if cleaned == "." {
		cleaned = "index.html"
	}
	path := filepath.Join(server.cfg.StaticDir, cleaned)
	root, _ := filepath.Abs(server.cfg.StaticDir)
	absolute, _ := filepath.Abs(path)
	if strings.HasPrefix(strings.ToLower(absolute), strings.ToLower(root)+string(os.PathSeparator)) {
		if info, err := os.Stat(absolute); err == nil && !info.IsDir() {
			if strings.Contains(cleaned, "assets"+string(os.PathSeparator)) {
				writer.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			http.ServeFile(writer, request, absolute)
			return
		}
	}
	if strings.Contains(request.Header.Get("Accept"), "text/html") {
		writer.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(writer, request, filepath.Join(server.cfg.StaticDir, "index.html"))
		return
	}
	http.NotFound(writer, request)
}

func cleanText(value string, maxRunes int) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\x00", ""))
	runes := []rune(value)
	if len(runes) > maxRunes {
		value = string(runes[:maxRunes])
	}
	return value
}

func cleanFilename(value string) string {
	value = cleanText(filepath.Base(strings.ReplaceAll(value, "\\", "/")), 255)
	value = strings.TrimRight(value, ". ")
	if value == "." || value == ".." {
		return ""
	}
	return value
}

func contentDisposition(filename string) string {
	fallback := strings.Map(func(r rune) rune {
		if r < 32 || r > 126 || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, filename)
	if fallback == "" {
		fallback = "download"
	}
	return fmt.Sprintf("attachment; filename=\"%s\"; filename*=UTF-8''%s", fallback, url.PathEscape(filename))
}

func decodeJSON(request *http.Request, target any, maxBytes int64) error {
	defer request.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(request.Body, maxBytes))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func writeJSON(writer http.ResponseWriter, status int, payload any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(payload)
}

func writeAPIError(writer http.ResponseWriter, status int, code, message string) {
	writeJSON(writer, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

type countingResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (writer *countingResponseWriter) WriteHeader(status int) {
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *countingResponseWriter) Write(payload []byte) (int, error) {
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	written, err := writer.ResponseWriter.Write(payload)
	if writer.status == http.StatusOK || writer.status == http.StatusPartialContent {
		writer.bytes += int64(written)
	}
	return written, err
}

func detectContentType(name string) string {
	if value := mime.TypeByExtension(filepath.Ext(name)); value != "" {
		return value
	}
	return "application/octet-stream"
}

func isGuestBlockedFilename(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".exe", ".msi", ".msp", ".com", ".scr", ".dll", ".cpl", ".sys", ".drv",
		".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
		".wsh", ".hta", ".lnk", ".url", ".reg", ".jar", ".apk", ".chm", ".scf",
		".msix", ".msixbundle", ".appx", ".appxbundle", ".application", ".sh", ".py",
		".pyw", ".pl", ".php", ".rb":
		return true
	default:
		return false
	}
}
