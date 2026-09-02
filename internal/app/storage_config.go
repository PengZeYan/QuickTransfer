package app

import (
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

type StorageConfig struct {
	Addr                     string
	PublicURL                string
	ControlURL               string
	DataDir                  string
	NodeID                   string
	SharedSecret             []byte
	AllowedOrigins           []string
	TrustedProxyCIDRs        []string
	ScanMode                 string
	PublicMode               bool
	LoopbackOnly             bool
	TLSCertFile              string
	TLSKeyFile               string
	MaxUploadBytes           int64
	MaxChunkBytes            int64
	UploadConcurrency        int
	UploadConcurrencyPerIP   int
	DownloadConcurrency      int
	DownloadConcurrencyPerIP int
	DataPlaneRatePerSecond   int
	DataPlaneRateBurst       int
	ResourceRatePerSecond    int
	ResourceRateBurst        int
	ResourceFailureLimit     int
	ResourceFailureWindow    time.Duration
	UploadReadIdleTimeout    time.Duration
	UploadReadMaxDuration    time.Duration
	OutboxClaimLease         time.Duration
	OutboxMaxAttempts        int
	ReplayDeadLettersOnStart bool
	MinFreeBytes             uint64
	WorkerInterval           time.Duration
	CleanupInterval          time.Duration
}

const (
	storageControlPlaneMaxUploadBytes      int64 = 50 * 1024 * 1024 * 1024
	storageDefaultMaxUploadBytes           int64 = storageControlPlaneMaxUploadBytes
	storageDefaultUploadConcurrency              = 4
	storageDefaultUploadConcurrencyPerIP         = 2
	storageDefaultDownloadConcurrency            = 32
	storageDefaultDownloadConcurrencyPerIP       = 4
	storageDefaultDataPlaneRatePerSecond         = 256
	storageDefaultDataPlaneRateBurst             = 512
	storageDefaultResourceRatePerSecond          = 64
	storageDefaultResourceRateBurst              = 128
	storageDefaultResourceFailureLimit           = 20
	storageDefaultResourceFailureWindow          = time.Minute
	storageDefaultUploadReadIdleTimeout          = 15 * time.Second
	storageDefaultUploadReadMaxDuration          = 2 * time.Minute
	storageDefaultOutboxClaimLease               = 30 * time.Second
	storageDefaultOutboxMaxAttempts              = 12
)

func LoadStorageConfig() (StorageConfig, error) {
	maxUploadBytes, err := storageEnvPositiveInt64("QT_STORAGE_MAX_UPLOAD_BYTES", storageDefaultMaxUploadBytes)
	if err != nil {
		return StorageConfig{}, err
	}
	if err := validateStorageMaxUploadBytes(maxUploadBytes); err != nil {
		return StorageConfig{}, err
	}
	maxChunkBytes, err := storageEnvPositiveInt64("QT_STORAGE_MAX_CHUNK_BYTES", 8*1024*1024)
	if err != nil {
		return StorageConfig{}, err
	}
	uploadConcurrency, err := storageEnvPositiveInt64("QT_STORAGE_UPLOAD_CONCURRENCY", storageDefaultUploadConcurrency)
	if err != nil {
		return StorageConfig{}, err
	}
	uploadConcurrencyPerIP, err := storageEnvPositiveInt64(
		"QT_STORAGE_UPLOAD_CONCURRENCY_PER_IP", storageDefaultUploadConcurrencyPerIP)
	if err != nil {
		return StorageConfig{}, err
	}
	downloadConcurrency, err := storageEnvPositiveInt64(
		"QT_STORAGE_DOWNLOAD_CONCURRENCY", storageDefaultDownloadConcurrency)
	if err != nil {
		return StorageConfig{}, err
	}
	downloadConcurrencyPerIP, err := storageEnvPositiveInt64(
		"QT_STORAGE_DOWNLOAD_CONCURRENCY_PER_IP", storageDefaultDownloadConcurrencyPerIP)
	if err != nil {
		return StorageConfig{}, err
	}
	dataPlaneRatePerSecond, err := storageEnvPositiveInt64(
		"QT_STORAGE_DATA_PLANE_RATE_PER_SECOND", storageDefaultDataPlaneRatePerSecond)
	if err != nil {
		return StorageConfig{}, err
	}
	dataPlaneRateBurst, err := storageEnvPositiveInt64(
		"QT_STORAGE_DATA_PLANE_RATE_BURST", storageDefaultDataPlaneRateBurst)
	if err != nil {
		return StorageConfig{}, err
	}
	resourceRatePerSecond, err := storageEnvPositiveInt64(
		"QT_STORAGE_RESOURCE_RATE_PER_SECOND", storageDefaultResourceRatePerSecond)
	if err != nil {
		return StorageConfig{}, err
	}
	resourceRateBurst, err := storageEnvPositiveInt64(
		"QT_STORAGE_RESOURCE_RATE_BURST", storageDefaultResourceRateBurst)
	if err != nil {
		return StorageConfig{}, err
	}
	resourceFailureLimit, err := storageEnvPositiveInt64(
		"QT_STORAGE_RESOURCE_FAILURE_LIMIT", storageDefaultResourceFailureLimit)
	if err != nil {
		return StorageConfig{}, err
	}
	resourceFailureWindow, err := storageEnvDuration(
		"QT_STORAGE_RESOURCE_FAILURE_WINDOW", storageDefaultResourceFailureWindow)
	if err != nil {
		return StorageConfig{}, err
	}
	uploadReadIdleTimeout, err := storageEnvDuration(
		"QT_STORAGE_UPLOAD_READ_IDLE_TIMEOUT", storageDefaultUploadReadIdleTimeout)
	if err != nil {
		return StorageConfig{}, err
	}
	uploadReadMaxDuration, err := storageEnvDuration(
		"QT_STORAGE_UPLOAD_READ_MAX_DURATION", storageDefaultUploadReadMaxDuration)
	if err != nil {
		return StorageConfig{}, err
	}
	outboxClaimLease, err := storageEnvDuration(
		"QT_STORAGE_OUTBOX_CLAIM_LEASE", storageDefaultOutboxClaimLease)
	if err != nil {
		return StorageConfig{}, err
	}
	outboxMaxAttempts, err := storageEnvPositiveInt64(
		"QT_STORAGE_OUTBOX_MAX_ATTEMPTS", storageDefaultOutboxMaxAttempts)
	if err != nil {
		return StorageConfig{}, err
	}
	replayDeadLettersOnStart, err := storageEnvBool("QT_STORAGE_REPLAY_DEAD_LETTERS_ON_START", false)
	if err != nil {
		return StorageConfig{}, err
	}
	minFreeBytes, err := storageEnvPositiveInt64("QT_STORAGE_MIN_FREE_BYTES", 1024*1024*1024)
	if err != nil {
		return StorageConfig{}, err
	}
	if uploadConcurrency > 128 || uploadConcurrencyPerIP > 128 {
		return StorageConfig{}, errors.New("QT_STORAGE_UPLOAD_CONCURRENCY must not exceed 128")
	}
	if downloadConcurrency > 2048 || downloadConcurrencyPerIP > 2048 {
		return StorageConfig{}, errors.New("QT_STORAGE_DOWNLOAD_CONCURRENCY limits must not exceed 2048")
	}
	if dataPlaneRatePerSecond > 100_000 || dataPlaneRateBurst > 1_000_000 ||
		resourceRatePerSecond > 100_000 || resourceRateBurst > 1_000_000 ||
		resourceFailureLimit > 100_000 {
		return StorageConfig{}, errors.New("storage data-plane rate limits exceed the supported safety bounds")
	}
	if outboxMaxAttempts > 100 {
		return StorageConfig{}, errors.New("QT_STORAGE_OUTBOX_MAX_ATTEMPTS must not exceed 100")
	}

	addr := storageEnvString("QT_STORAGE_ADDR", "127.0.0.1:7665")
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return StorageConfig{}, fmt.Errorf("invalid QT_STORAGE_ADDR: %w", err)
	}
	loopbackOnly := isLoopbackHost(host)
	publicMode, err := storageEnvBool("QT_STORAGE_PUBLIC_MODE", !loopbackOnly)
	if err != nil {
		return StorageConfig{}, err
	}
	if !loopbackOnly && !publicMode {
		return StorageConfig{}, errors.New("non-loopback QT_STORAGE_ADDR requires QT_STORAGE_PUBLIC_MODE=true")
	}

	cfg := StorageConfig{
		Addr:                     addr,
		PublicURL:                strings.TrimRight(strings.TrimSpace(os.Getenv("QT_STORAGE_PUBLIC_URL")), "/"),
		ControlURL:               strings.TrimRight(strings.TrimSpace(os.Getenv("QT_CONTROL_URL")), "/"),
		DataDir:                  storageEnvString("QT_STORAGE_DATA_DIR", "./data/storage"),
		NodeID:                   strings.TrimSpace(os.Getenv("QT_STORAGE_NODE_ID")),
		AllowedOrigins:           storageEnvList("QT_STORAGE_ALLOWED_ORIGINS"),
		TrustedProxyCIDRs:        storageEnvList("QT_TRUSTED_PROXY_CIDRS"),
		ScanMode:                 strings.ToLower(storageEnvString("QT_STORAGE_SCAN_MODE", "auto")),
		PublicMode:               publicMode,
		LoopbackOnly:             loopbackOnly,
		TLSCertFile:              strings.TrimSpace(os.Getenv("QT_STORAGE_TLS_CERT_FILE")),
		TLSKeyFile:               strings.TrimSpace(os.Getenv("QT_STORAGE_TLS_KEY_FILE")),
		MaxUploadBytes:           maxUploadBytes,
		MaxChunkBytes:            maxChunkBytes,
		UploadConcurrency:        int(uploadConcurrency),
		UploadConcurrencyPerIP:   int(uploadConcurrencyPerIP),
		DownloadConcurrency:      int(downloadConcurrency),
		DownloadConcurrencyPerIP: int(downloadConcurrencyPerIP),
		DataPlaneRatePerSecond:   int(dataPlaneRatePerSecond),
		DataPlaneRateBurst:       int(dataPlaneRateBurst),
		ResourceRatePerSecond:    int(resourceRatePerSecond),
		ResourceRateBurst:        int(resourceRateBurst),
		ResourceFailureLimit:     int(resourceFailureLimit),
		ResourceFailureWindow:    resourceFailureWindow,
		UploadReadIdleTimeout:    uploadReadIdleTimeout,
		UploadReadMaxDuration:    uploadReadMaxDuration,
		OutboxClaimLease:         outboxClaimLease,
		OutboxMaxAttempts:        int(outboxMaxAttempts),
		ReplayDeadLettersOnStart: replayDeadLettersOnStart,
		MinFreeBytes:             uint64(minFreeBytes),
		WorkerInterval:           time.Second,
		CleanupInterval:          time.Minute,
	}
	if cfg.PublicURL == "" && loopbackOnly {
		publicHost := host
		if publicHost == "" {
			publicHost = "127.0.0.1"
		}
		cfg.PublicURL = "http://" + net.JoinHostPort(publicHost, port)
	}
	secretPath := strings.TrimSpace(os.Getenv("QT_STORAGE_SHARED_SECRET_FILE"))
	cfg.SharedSecret, err = loadNodeSharedSecret(secretPath)
	if err != nil {
		return StorageConfig{}, err
	}
	if err := cfg.Validate(); err != nil {
		return StorageConfig{}, err
	}
	if err := prepareStorageDirectories(cfg.DataDir); err != nil {
		return StorageConfig{}, err
	}
	return cfg, nil
}

func validateStorageMaxUploadBytes(maxUploadBytes int64) error {
	if maxUploadBytes < storageControlPlaneMaxUploadBytes {
		return fmt.Errorf(
			"QT_STORAGE_MAX_UPLOAD_BYTES must be at least %d bytes (50 GiB) to satisfy the control-plane upload limit",
			storageControlPlaneMaxUploadBytes,
		)
	}
	return nil
}

func (cfg StorageConfig) Validate() error {
	cfg = cfg.withRuntimeDefaults()
	if _, _, err := net.SplitHostPort(cfg.Addr); err != nil {
		return fmt.Errorf("invalid storage address: %w", err)
	}
	if !validStorageNodeID(cfg.NodeID) {
		return errors.New("QT_STORAGE_NODE_ID is required and must contain only letters, digits, dot, dash, or underscore")
	}
	if len(cfg.SharedSecret) < 32 {
		return errors.New("storage shared secret must contain at least 32 bytes")
	}
	if strings.TrimSpace(cfg.DataDir) == "" {
		return errors.New("QT_STORAGE_DATA_DIR must not be empty")
	}
	if cfg.MaxUploadBytes <= 0 || cfg.MaxChunkBytes <= 0 || cfg.MaxChunkBytes > cfg.MaxUploadBytes ||
		cfg.UploadConcurrency <= 0 || cfg.UploadConcurrency > 128 ||
		cfg.UploadConcurrencyPerIP <= 0 || cfg.UploadConcurrencyPerIP > cfg.UploadConcurrency ||
		cfg.DownloadConcurrency <= 0 || cfg.DownloadConcurrency > 2048 ||
		cfg.DownloadConcurrencyPerIP <= 0 || cfg.DownloadConcurrencyPerIP > cfg.DownloadConcurrency ||
		cfg.DataPlaneRatePerSecond <= 0 || cfg.DataPlaneRatePerSecond > 100_000 ||
		cfg.DataPlaneRateBurst < cfg.DataPlaneRatePerSecond || cfg.DataPlaneRateBurst > 1_000_000 ||
		cfg.ResourceRatePerSecond <= 0 || cfg.ResourceRatePerSecond > cfg.DataPlaneRatePerSecond ||
		cfg.ResourceRateBurst < cfg.ResourceRatePerSecond || cfg.ResourceRateBurst > cfg.DataPlaneRateBurst ||
		cfg.ResourceFailureLimit <= 0 || cfg.ResourceFailureLimit > 100_000 ||
		cfg.MinFreeBytes == 0 {
		return errors.New("invalid storage upload, chunk, concurrency, rate, or reserved-space limit")
	}
	if cfg.ResourceFailureWindow < time.Second || cfg.ResourceFailureWindow > 24*time.Hour {
		return errors.New("invalid storage resource failure window")
	}
	if cfg.UploadReadIdleTimeout < time.Second || cfg.UploadReadIdleTimeout > 5*time.Minute ||
		cfg.UploadReadMaxDuration < cfg.UploadReadIdleTimeout || cfg.UploadReadMaxDuration > 30*time.Minute {
		return errors.New("invalid storage upload read timeout")
	}
	if cfg.OutboxClaimLease < 15*time.Second || cfg.OutboxClaimLease > 10*time.Minute ||
		cfg.OutboxMaxAttempts <= 0 || cfg.OutboxMaxAttempts > 100 {
		return errors.New("invalid storage outbox lease or attempt limit")
	}
	if cfg.WorkerInterval <= 0 || cfg.CleanupInterval <= 0 {
		return errors.New("invalid storage worker interval")
	}
	if cfg.ScanMode != "auto" && cfg.ScanMode != "required" && cfg.ScanMode != "signature" {
		return fmt.Errorf("unsupported QT_STORAGE_SCAN_MODE %q", cfg.ScanMode)
	}
	if cfg.PublicMode && cfg.ScanMode != "required" {
		return errors.New("public storage mode requires QT_STORAGE_SCAN_MODE=required")
	}
	if cfg.PublicURL == "" {
		return errors.New("QT_STORAGE_PUBLIC_URL is required outside loopback development")
	}
	if cfg.ControlURL == "" {
		return errors.New("QT_CONTROL_URL is required")
	}
	if err := validateStorageBaseURL(cfg.PublicURL, cfg.PublicMode, "QT_STORAGE_PUBLIC_URL"); err != nil {
		return err
	}
	if err := validateStorageBaseURL(cfg.ControlURL, cfg.PublicMode, "QT_CONTROL_URL"); err != nil {
		return err
	}
	if cfg.PublicMode && len(cfg.AllowedOrigins) == 0 {
		return errors.New("public storage mode requires at least one QT_STORAGE_ALLOWED_ORIGINS entry")
	}
	for _, origin := range cfg.AllowedOrigins {
		if err := validateStorageOrigin(origin, cfg.PublicMode); err != nil {
			return fmt.Errorf("invalid QT_STORAGE_ALLOWED_ORIGINS entry %q: %w", origin, err)
		}
	}
	for _, candidate := range cfg.TrustedProxyCIDRs {
		if net.ParseIP(candidate) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(candidate); err != nil {
			return fmt.Errorf("invalid QT_TRUSTED_PROXY_CIDRS entry %q", candidate)
		}
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return errors.New("QT_STORAGE_TLS_CERT_FILE and QT_STORAGE_TLS_KEY_FILE must be configured together")
	}
	if cfg.PublicMode && (cfg.TLSCertFile == "" || cfg.TLSKeyFile == "") {
		return errors.New("public storage mode requires a TLS certificate and private key")
	}
	for name, path := range map[string]string{
		"QT_STORAGE_TLS_CERT_FILE": cfg.TLSCertFile,
		"QT_STORAGE_TLS_KEY_FILE":  cfg.TLSKeyFile,
	} {
		if path == "" {
			continue
		}
		info, err := os.Stat(filepath.Clean(path))
		if err != nil || info.IsDir() {
			return fmt.Errorf("%s must name a readable file", name)
		}
	}
	return nil
}

func (cfg StorageConfig) withRuntimeDefaults() StorageConfig {
	if cfg.UploadConcurrency == 0 {
		cfg.UploadConcurrency = storageDefaultUploadConcurrency
	}
	if cfg.UploadConcurrencyPerIP == 0 {
		cfg.UploadConcurrencyPerIP = min(storageDefaultUploadConcurrencyPerIP, cfg.UploadConcurrency)
	}
	if cfg.DownloadConcurrency == 0 {
		cfg.DownloadConcurrency = storageDefaultDownloadConcurrency
	}
	if cfg.DownloadConcurrencyPerIP == 0 {
		cfg.DownloadConcurrencyPerIP = min(storageDefaultDownloadConcurrencyPerIP, cfg.DownloadConcurrency)
	}
	if cfg.DataPlaneRatePerSecond == 0 {
		cfg.DataPlaneRatePerSecond = storageDefaultDataPlaneRatePerSecond
	}
	if cfg.DataPlaneRateBurst == 0 {
		cfg.DataPlaneRateBurst = max(storageDefaultDataPlaneRateBurst, cfg.DataPlaneRatePerSecond)
	}
	if cfg.ResourceRatePerSecond == 0 {
		cfg.ResourceRatePerSecond = min(storageDefaultResourceRatePerSecond, cfg.DataPlaneRatePerSecond)
	}
	if cfg.ResourceRateBurst == 0 {
		cfg.ResourceRateBurst = min(
			max(storageDefaultResourceRateBurst, cfg.ResourceRatePerSecond), cfg.DataPlaneRateBurst)
	}
	if cfg.ResourceFailureLimit == 0 {
		cfg.ResourceFailureLimit = storageDefaultResourceFailureLimit
	}
	if cfg.ResourceFailureWindow == 0 {
		cfg.ResourceFailureWindow = storageDefaultResourceFailureWindow
	}
	if cfg.UploadReadIdleTimeout == 0 {
		cfg.UploadReadIdleTimeout = storageDefaultUploadReadIdleTimeout
	}
	if cfg.UploadReadMaxDuration == 0 {
		cfg.UploadReadMaxDuration = storageDefaultUploadReadMaxDuration
	}
	if cfg.OutboxClaimLease == 0 {
		cfg.OutboxClaimLease = storageDefaultOutboxClaimLease
	}
	if cfg.OutboxMaxAttempts == 0 {
		cfg.OutboxMaxAttempts = storageDefaultOutboxMaxAttempts
	}
	return cfg
}

func prepareStorageDirectories(dataDir string) error {
	for _, path := range []string{
		dataDir,
		filepath.Join(dataDir, "db"),
		filepath.Join(dataDir, "tmp"),
		filepath.Join(dataDir, "quarantine"),
		filepath.Join(dataDir, "objects"),
	} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("create storage data directory %s: %w", path, err)
		}
	}
	return nil
}

func validateStorageBaseURL(raw string, publicMode bool, name string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return fmt.Errorf("invalid %s", name)
	}
	if strings.EqualFold(parsed.Scheme, "https") {
		return nil
	}
	if !publicMode && strings.EqualFold(parsed.Scheme, "http") &&
		(parsed.Hostname() == "localhost" || isLoopbackHost(parsed.Hostname())) {
		return nil
	}
	return fmt.Errorf("%s must use https outside loopback development", name)
}

func validateStorageOrigin(origin string, publicMode bool) error {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("origin must be an exact scheme-and-host value without a trailing slash")
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return errors.New("origin scheme must be http or https")
	}
	if publicMode && !strings.EqualFold(parsed.Scheme, "https") {
		return errors.New("public origin must use https")
	}
	if !publicMode && strings.EqualFold(parsed.Scheme, "http") &&
		parsed.Hostname() != "localhost" && !isLoopbackHost(parsed.Hostname()) {
		return errors.New("non-public http origin must use localhost or a loopback address")
	}
	return nil
}

func storageEnvString(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func storageEnvPositiveInt64(key string, fallback int64) (int64, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", key)
	}
	return parsed, nil
}

func storageEnvDuration(key string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive Go duration such as 15s or 2m", key)
	}
	return parsed, nil
}

func storageEnvBool(key string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", key)
	}
	return parsed, nil
}

func storageEnvList(key string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{})
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}
