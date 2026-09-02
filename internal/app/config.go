package app

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr                     string
	BaseURL                  string
	DataDir                  string
	StaticDir                string
	ScanMode                 string
	MaxFileBytes             int64
	MaxTransferBytes         int64
	MaxFiles                 int
	DefaultExpiry            time.Duration
	MaxExpiry                time.Duration
	IncompleteLifetime       time.Duration
	MinFreeBytes             uint64
	MaxChunkBytes            int64
	UploadConcurrency        int
	GuestMaxFileBytes        int64
	GuestMaxTaskBytes        int64
	GuestMaxFiles            int
	GuestMaxDownloads        int
	GuestDailyBytes          int64
	GuestDailyTasks          int
	UserStorageBytes         int64
	UserMonthlyTraffic       int64
	SessionLifetime          time.Duration
	RegistrationOpen         bool
	RegistrationForceClosed  bool
	ExposeLocalCode          bool
	SandboxCommerce          bool
	LocalVerification        bool
	EmailAllowedDomains      []string
	VerificationCodeTTL      time.Duration
	VerificationCooldown     time.Duration
	VerificationEmailHourly  int
	VerificationEmailDaily   int
	VerificationIPHourly     int
	VerificationIPDaily      int
	VerificationDomainHourly int
	VerificationDomainDaily  int
	SMTPHost                 string
	SMTPPort                 int
	SMTPUsername             string
	SMTPPassword             string
	SMTPFrom                 string
	SMTPFromName             string
	SMTPTLSMode              string
	SMTPAuthMode             string
	SMTPConcurrency          int
	TrustedProxyCIDRs        []string
	StoragePublicURL         string
	StorageInternalURL       string
	StorageNodeID            string
	StorageCAFile            string
	StorageSharedSecret      []byte
	ControlPlaneOnly         bool
	RequireHumanVerification bool
	Secret                   []byte
	LoopbackOnly             bool
	PublicMode               bool
}

func LoadConfig() (Config, error) {
	cfg := Config{
		Addr:               envString("QT_ADDR", "127.0.0.1:6655"),
		DataDir:            envString("QT_DATA_DIR", "./data"),
		StaticDir:          envString("QT_STATIC_DIR", "./dist/client"),
		ScanMode:           strings.ToLower(envString("QT_SCAN_MODE", "auto")),
		MaxFileBytes:       envInt64("QT_MAX_FILE_BYTES", 50*1024*1024*1024),
		MaxTransferBytes:   envInt64("QT_MAX_TRANSFER_BYTES", 50*1024*1024*1024),
		MaxFiles:           int(envInt64("QT_MAX_FILES", 10000)),
		DefaultExpiry:      time.Duration(envInt64("QT_DEFAULT_EXPIRY_HOURS", 24)) * time.Hour,
		MaxExpiry:          time.Duration(envInt64("QT_MAX_EXPIRY_HOURS", 72)) * time.Hour,
		IncompleteLifetime: time.Duration(envInt64("QT_INCOMPLETE_HOURS", 6)) * time.Hour,
		MinFreeBytes:       uint64(envInt64("QT_MIN_FREE_BYTES", 1024*1024*1024)),
		MaxChunkBytes:      envInt64("QT_MAX_CHUNK_BYTES", 8*1024*1024),
		UploadConcurrency:  int(envInt64("QT_UPLOAD_CONCURRENCY", 4)),
		GuestMaxFileBytes:  envInt64("QT_GUEST_MAX_FILE_BYTES", 100*1024*1024),
		GuestMaxTaskBytes:  envInt64("QT_GUEST_MAX_TRANSFER_BYTES", 100*1024*1024),
		GuestMaxFiles:      int(envInt64("QT_GUEST_MAX_FILES", 100)),
		GuestMaxDownloads:  int(envInt64("QT_GUEST_MAX_DOWNLOADS", 5)),
		GuestDailyBytes:    envInt64("QT_GUEST_DAILY_BYTES", 300*1024*1024),
		GuestDailyTasks:    int(envInt64("QT_GUEST_DAILY_TASKS", 3)),
		// Retained as an environment compatibility field only. Account storage is
		// unlimited; physical free-space guards remain authoritative.
		UserStorageBytes:         envInt64("QT_USER_STORAGE_BYTES", 0),
		UserMonthlyTraffic:       envInt64("QT_USER_MONTHLY_TRAFFIC_BYTES", 5*1024*1024*1024),
		SessionLifetime:          time.Duration(envInt64("QT_SESSION_HOURS", 7*24)) * time.Hour,
		VerificationCodeTTL:      time.Duration(envInt64("QT_VERIFICATION_CODE_MINUTES", 10)) * time.Minute,
		VerificationCooldown:     time.Duration(envInt64("QT_VERIFICATION_COOLDOWN_SECONDS", 120)) * time.Second,
		VerificationEmailHourly:  int(envInt64("QT_VERIFICATION_EMAIL_HOURLY", 3)),
		VerificationEmailDaily:   int(envInt64("QT_VERIFICATION_EMAIL_DAILY", 5)),
		VerificationIPHourly:     int(envInt64("QT_VERIFICATION_IP_HOURLY", 10)),
		VerificationIPDaily:      int(envInt64("QT_VERIFICATION_IP_DAILY", 20)),
		VerificationDomainHourly: int(envInt64("QT_VERIFICATION_DOMAIN_HOURLY", 100)),
		VerificationDomainDaily:  int(envInt64("QT_VERIFICATION_DOMAIN_DAILY", 500)),
		SMTPHost:                 strings.TrimSpace(os.Getenv("QT_SMTP_HOST")),
		SMTPPort:                 int(envInt64("QT_SMTP_PORT", 465)),
		SMTPUsername:             strings.TrimSpace(os.Getenv("QT_SMTP_USERNAME")),
		SMTPFrom:                 strings.TrimSpace(os.Getenv("QT_SMTP_FROM")),
		SMTPFromName:             envString("QT_SMTP_FROM_NAME", "快传 QuickTransfer"),
		SMTPTLSMode:              strings.ToLower(envString("QT_SMTP_TLS_MODE", "implicit")),
		SMTPAuthMode:             strings.ToLower(envString("QT_SMTP_AUTH_MODE", "login")),
		SMTPConcurrency:          int(envInt64("QT_SMTP_CONCURRENCY", 4)),
		TrustedProxyCIDRs:        envList("QT_TRUSTED_PROXY_CIDRS"),
		StoragePublicURL:         strings.TrimRight(strings.TrimSpace(os.Getenv("QT_STORAGE_PUBLIC_URL")), "/"),
		StorageInternalURL:       strings.TrimRight(strings.TrimSpace(os.Getenv("QT_STORAGE_INTERNAL_URL")), "/"),
		StorageNodeID:            strings.TrimSpace(os.Getenv("QT_STORAGE_NODE_ID")),
		StorageCAFile:            strings.TrimSpace(os.Getenv("QT_STORAGE_CA_FILE")),
	}
	cfg.EmailAllowedDomains = envList("QT_EMAIL_ALLOWED_DOMAINS")
	if len(cfg.EmailAllowedDomains) == 0 {
		cfg.EmailAllowedDomains = []string{"qq.com", "163.com", "gmail.com"}
	}
	var err error
	if cfg.EmailAllowedDomains, err = normalizeEmailDomains(cfg.EmailAllowedDomains); err != nil {
		return Config{}, err
	}
	if cfg.SMTPPassword, err = readSecretEnv("QT_SMTP_PASSWORD", "QT_SMTP_PASSWORD_FILE", "QT_SMTP_PASSWORD_DPAPI_FILE"); err != nil {
		return Config{}, err
	}
	if cfg.SMTPFrom == "" {
		cfg.SMTPFrom = cfg.SMTPUsername
	}
	if cfg.MaxFileBytes <= 0 || cfg.MaxTransferBytes < cfg.MaxFileBytes || cfg.MaxFiles <= 0 || cfg.MaxChunkBytes <= 0 || cfg.UploadConcurrency <= 0 ||
		cfg.GuestMaxFileBytes <= 0 || cfg.GuestMaxTaskBytes < cfg.GuestMaxFileBytes || cfg.GuestMaxFiles <= 0 || cfg.GuestMaxDownloads <= 0 ||
		cfg.GuestDailyBytes < cfg.GuestMaxTaskBytes || cfg.GuestDailyTasks <= 0 || cfg.UserStorageBytes < 0 || cfg.UserMonthlyTraffic <= 0 || cfg.SessionLifetime <= 0 ||
		cfg.VerificationCodeTTL <= 0 || cfg.VerificationCooldown < time.Minute || cfg.VerificationEmailHourly <= 0 ||
		cfg.VerificationEmailDaily < cfg.VerificationEmailHourly || cfg.VerificationIPHourly <= 0 || cfg.VerificationIPDaily < cfg.VerificationIPHourly ||
		cfg.VerificationDomainHourly <= 0 || cfg.VerificationDomainDaily < cfg.VerificationDomainHourly || cfg.SMTPConcurrency <= 0 || cfg.SMTPConcurrency > 32 {
		return Config{}, errors.New("invalid service limit configuration")
	}
	if cfg.GuestMaxFileBytes > cfg.MaxFileBytes || cfg.GuestMaxTaskBytes > cfg.MaxTransferBytes || cfg.GuestMaxFiles > cfg.MaxFiles {
		return Config{}, errors.New("guest limits must not exceed global upload limits")
	}
	if cfg.ScanMode != "auto" && cfg.ScanMode != "required" && cfg.ScanMode != "signature" && cfg.ScanMode != "disabled" {
		return Config{}, fmt.Errorf("unsupported QT_SCAN_MODE %q", cfg.ScanMode)
	}
	for _, candidate := range cfg.TrustedProxyCIDRs {
		if net.ParseIP(candidate) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(candidate); err != nil {
			return Config{}, fmt.Errorf("invalid QT_TRUSTED_PROXY_CIDRS entry %q", candidate)
		}
	}
	host, port, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return Config{}, fmt.Errorf("invalid QT_ADDR: %w", err)
	}
	cfg.LoopbackOnly = isLoopbackHost(host)
	cfg.PublicMode = envBool("QT_PUBLIC_MODE", !cfg.LoopbackOnly)
	cfg.SandboxCommerce = envBool("QT_SANDBOX_COMMERCE", cfg.LoopbackOnly)
	cfg.LocalVerification = envBool("QT_LOCAL_VERIFICATION", false)
	cfg.RegistrationOpen = envBool("QT_REGISTRATION_OPEN", false)
	cfg.RegistrationForceClosed = envBool("QT_REGISTRATION_FORCE_CLOSED", false)
	cfg.ExposeLocalCode = envBool("QT_EXPOSE_LOCAL_VERIFICATION_CODE", false)
	cfg.ControlPlaneOnly = envBool("QT_CONTROL_PLANE_ONLY", false)
	if cfg.RequireHumanVerification, err = envBoolStrict("QT_REQUIRE_HUMAN_VERIFICATION", false); err != nil {
		return Config{}, err
	}
	if !cfg.LoopbackOnly && !cfg.PublicMode {
		return Config{}, errors.New("non-loopback binding requires QT_PUBLIC_MODE=true")
	}
	if cfg.PublicMode && cfg.ScanMode == "disabled" {
		return Config{}, errors.New("QT_SCAN_MODE=disabled is forbidden on a public bind address")
	}
	if cfg.PublicMode && (cfg.SandboxCommerce || cfg.LocalVerification) {
		return Config{}, errors.New("sandbox commerce and local verification are forbidden on a public bind address")
	}
	if cfg.LocalVerification && !cfg.LoopbackOnly {
		return Config{}, errors.New("local verification requires a loopback bind address")
	}
	if cfg.ExposeLocalCode && (!cfg.LocalVerification || !cfg.LoopbackOnly || cfg.PublicMode) {
		return Config{}, errors.New("QT_EXPOSE_LOCAL_VERIFICATION_CODE requires loopback-only local verification")
	}
	if !cfg.LocalVerification {
		smtpConfigured := cfg.SMTPHost != "" || cfg.SMTPUsername != "" || cfg.SMTPPassword != "" || cfg.SMTPFrom != ""
		if smtpConfigured {
			if err := validateSMTPConfig(cfg); err != nil {
				return Config{}, err
			}
		}
	}
	storageConfigured := cfg.StoragePublicURL != "" || cfg.StorageInternalURL != "" || cfg.StorageNodeID != "" || cfg.StorageCAFile != "" ||
		strings.TrimSpace(os.Getenv("QT_STORAGE_SHARED_SECRET_FILE")) != ""
	if storageConfigured {
		if cfg.StoragePublicURL == "" || cfg.StorageInternalURL == "" || cfg.StorageNodeID == "" {
			return Config{}, errors.New("QT_STORAGE_PUBLIC_URL, QT_STORAGE_INTERNAL_URL, and QT_STORAGE_NODE_ID must be configured together")
		}
		if err := validateStorageURL(cfg.StoragePublicURL, cfg.PublicMode, "QT_STORAGE_PUBLIC_URL"); err != nil {
			return Config{}, err
		}
		if err := validateStorageURL(cfg.StorageInternalURL, cfg.PublicMode, "QT_STORAGE_INTERNAL_URL"); err != nil {
			return Config{}, err
		}
		if strings.ContainsAny(cfg.StorageNodeID, "\r\n|/\\") || len(cfg.StorageNodeID) > 64 {
			return Config{}, errors.New("invalid QT_STORAGE_NODE_ID")
		}
		if cfg.StorageCAFile != "" && (!filepath.IsAbs(cfg.StorageCAFile) || strings.ContainsAny(cfg.StorageCAFile, "\r\n\x00")) {
			return Config{}, errors.New("QT_STORAGE_CA_FILE must be a safe absolute path")
		}
		cfg.StorageSharedSecret, err = loadNodeSharedSecret(strings.TrimSpace(os.Getenv("QT_STORAGE_SHARED_SECRET_FILE")))
		if err != nil {
			return Config{}, err
		}
	}
	if cfg.ControlPlaneOnly && !cfg.UsesRemoteStorage() {
		return Config{}, errors.New("QT_CONTROL_PLANE_ONLY=true requires complete remote storage configuration")
	}
	if cfg.BaseURL = strings.TrimRight(strings.TrimSpace(os.Getenv("QT_BASE_URL")), "/"); cfg.BaseURL == "" {
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		cfg.BaseURL = "http://" + net.JoinHostPort(host, port)
	}
	if err := validateBaseURL(cfg.BaseURL, cfg.PublicMode); err != nil {
		return Config{}, err
	}
	for _, dir := range []string{
		cfg.DataDir,
		filepath.Join(cfg.DataDir, "db"),
		filepath.Join(cfg.DataDir, "tmp"),
		filepath.Join(cfg.DataDir, "quarantine"),
		filepath.Join(cfg.DataDir, "objects"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return Config{}, fmt.Errorf("create data directory %s: %w", dir, err)
		}
	}
	secret, err := loadOrCreateSecret(filepath.Join(cfg.DataDir, "app-secret"))
	if err != nil {
		return Config{}, err
	}
	cfg.Secret = secret
	return cfg, nil
}

func validateBaseURL(raw string, publicMode bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return errors.New("invalid QT_BASE_URL")
	}
	if publicMode {
		if !strings.EqualFold(parsed.Scheme, "https") {
			return errors.New("QT_BASE_URL must use https in public mode")
		}
		return nil
	}
	if !strings.EqualFold(parsed.Scheme, "http") ||
		(parsed.Hostname() != "localhost" && !isLoopbackHost(parsed.Hostname())) {
		return errors.New("a non-loopback QT_BASE_URL requires QT_PUBLIC_MODE=true")
	}
	return nil
}

func (cfg Config) UsesRemoteStorage() bool {
	return cfg.StoragePublicURL != "" && cfg.StorageInternalURL != "" && cfg.StorageNodeID != "" && len(cfg.StorageSharedSecret) >= 32
}

func validateStorageURL(raw string, publicMode bool, name string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("invalid %s", name)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return fmt.Errorf("%s must not contain a path", name)
	}
	if strings.EqualFold(parsed.Scheme, "https") {
		return nil
	}
	if !publicMode && strings.EqualFold(parsed.Scheme, "http") {
		host := parsed.Hostname()
		if host == "localhost" || isLoopbackHost(host) {
			return nil
		}
	}
	return fmt.Errorf("%s must use https outside loopback development", name)
}

func loadNodeSharedSecret(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("QT_STORAGE_SHARED_SECRET_FILE is required for remote storage")
	}
	value, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read storage shared secret: %w", err)
	}
	trimmed := strings.TrimSpace(string(value))
	if decoded, decodeErr := base64.RawURLEncoding.DecodeString(trimmed); decodeErr == nil && len(decoded) >= 32 {
		return decoded, nil
	}
	if len(trimmed) >= 32 {
		return []byte(trimmed), nil
	}
	return nil, errors.New("storage shared secret must contain at least 32 bytes")
}

func loadOrCreateSecret(path string) ([]byte, error) {
	if value, err := os.ReadFile(path); err == nil {
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(value)))
		if decodeErr == nil && len(decoded) >= 32 {
			return decoded, nil
		}
		return nil, errors.New("invalid persisted application secret")
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read application secret: %w", err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate application secret: %w", err)
	}
	if err := os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(secret)), 0o600); err != nil {
		return nil, fmt.Errorf("persist application secret: %w", err)
	}
	return secret, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func envString(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envInt64(key string, fallback int64) int64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envBoolStrict(key string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("invalid %s: expected true or false", key)
	}
	return parsed, nil
}

func envList(key string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if item := strings.TrimSpace(part); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func readSecretEnv(valueKey, fileKey, dpapiFileKey string) (string, error) {
	value := strings.TrimSpace(os.Getenv(valueKey))
	path := strings.TrimSpace(os.Getenv(fileKey))
	dpapiPath := strings.TrimSpace(os.Getenv(dpapiFileKey))
	configured := 0
	for _, candidate := range []string{value, path, dpapiPath} {
		if candidate != "" {
			configured++
		}
	}
	if configured > 1 {
		return "", fmt.Errorf("configure only one of %s, %s, or %s", valueKey, fileKey, dpapiFileKey)
	}
	if value != "" {
		return value, nil
	}
	if dpapiPath != "" {
		return readDPAPISecretFile(dpapiPath)
	}
	if path == "" {
		return "", nil
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", fileKey, err)
	}
	if secret := strings.TrimSpace(string(contents)); secret != "" {
		return secret, nil
	}
	return "", fmt.Errorf("%s is empty", fileKey)
}
