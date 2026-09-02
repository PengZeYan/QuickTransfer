package app

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	storageBuildVersion            = "2026.09.01-storage.8"
	storageDownloadCheckpointBytes = int64(1 << 20)
	storageOutboxMaxPendingAge     = 5 * time.Minute
	storageScanLeaseDuration       = 10 * time.Minute
	storageScanLeaseRenewalEvery   = time.Minute
	storageDownloadHeartbeatEvery  = 30 * time.Second
	storageDownloadRecoveryStale   = 2 * time.Minute
	storageDownloadMaxDuration     = downloadReservationMaxDuration - time.Minute
	storageReadinessCanaryEvery    = time.Minute
)

type StorageNode struct {
	cfg           StorageConfig
	store         *StorageStore
	scanner       *Scanner
	logger        *slog.Logger
	control       *StorageInternalClient
	replay        *InternalReplayGuard
	uploadSem     chan struct{}
	downloadSem   chan struct{}
	uploadByIP    *storageSourceConcurrency
	downloadByIP  *storageSourceConcurrency
	dataByIP      *storageTokenBucketLimiter
	dataByKey     *storageTokenBucketLimiter
	failuresByKey *storageFailureWindowLimiter
	origins       map[string]struct{}
	handler       http.Handler
	reserveMu     sync.Mutex
	uploadLock    sync.Map

	downloadHeartbeatInterval  time.Duration
	downloadRecoveryStaleAfter time.Duration
	downloadMaxDuration        time.Duration
	rateLimitNow               func() time.Time
}

const (
	storageRateLimiterMaxEntries      = 16_384
	storageRateLimiterOverflowBuckets = 64
	storageRateLimiterEntryTTL        = 10 * time.Minute
)

type storageRateKey [sha256.Size]byte

type storageTokenBucket struct {
	tokens   float64
	updated  time.Time
	lastSeen time.Time
}

type storageTokenBucketLimiter struct {
	mu         sync.Mutex
	rate       float64
	burst      float64
	entryTTL   time.Duration
	operations uint64
	entries    map[storageRateKey]*storageTokenBucket
	overflow   [storageRateLimiterOverflowBuckets]storageTokenBucket
}

type storageFailureWindow struct {
	started  time.Time
	lastSeen time.Time
	failures int
}

type storageFailureWindowLimiter struct {
	mu         sync.Mutex
	limit      int
	window     time.Duration
	entryTTL   time.Duration
	operations uint64
	entries    map[storageRateKey]*storageFailureWindow
	overflow   [storageRateLimiterOverflowBuckets]storageFailureWindow
}

func newStorageTokenBucketLimiter(rate, burst int) *storageTokenBucketLimiter {
	return &storageTokenBucketLimiter{
		rate: float64(rate), burst: float64(burst), entryTTL: storageRateLimiterEntryTTL,
		entries: make(map[storageRateKey]*storageTokenBucket),
	}
}

func (limiter *storageTokenBucketLimiter) allow(key storageRateKey, now time.Time) (bool, time.Duration) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.operations++
	limiter.pruneLocked(now)
	bucket := limiter.entries[key]
	if bucket == nil {
		if len(limiter.entries) < storageRateLimiterMaxEntries {
			bucket = &storageTokenBucket{tokens: limiter.burst, updated: now, lastSeen: now}
			limiter.entries[key] = bucket
		} else {
			bucket = &limiter.overflow[int(key[0])%len(limiter.overflow)]
		}
	}
	if bucket.updated.IsZero() {
		bucket.tokens, bucket.updated = limiter.burst, now
	} else if elapsed := now.Sub(bucket.updated); elapsed > 0 {
		bucket.tokens = min(limiter.burst, bucket.tokens+elapsed.Seconds()*limiter.rate)
		bucket.updated = now
	}
	bucket.lastSeen = now
	if bucket.tokens >= 1 {
		bucket.tokens--
		return true, 0
	}
	wait := time.Duration((1 - bucket.tokens) / limiter.rate * float64(time.Second))
	if wait < time.Millisecond {
		wait = time.Millisecond
	}
	return false, wait
}

func (limiter *storageTokenBucketLimiter) pruneLocked(now time.Time) {
	if limiter.operations%256 != 0 {
		return
	}
	cutoff := now.Add(-limiter.entryTTL)
	for key, bucket := range limiter.entries {
		if bucket.lastSeen.Before(cutoff) {
			delete(limiter.entries, key)
		}
	}
}

func newStorageFailureWindowLimiter(limit int, window time.Duration) *storageFailureWindowLimiter {
	entryTTL := storageRateLimiterEntryTTL
	if doubled := 2 * window; doubled > entryTTL {
		entryTTL = doubled
	}
	return &storageFailureWindowLimiter{
		limit: limit, window: window, entryTTL: entryTTL,
		entries: make(map[storageRateKey]*storageFailureWindow),
	}
}

func (limiter *storageFailureWindowLimiter) blocked(key storageRateKey, now time.Time) (bool, time.Duration) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.operations++
	limiter.pruneLocked(now)
	entry := limiter.entryLocked(key, now, false)
	if entry == nil {
		return false, 0
	}
	limiter.resetExpiredLocked(entry, now)
	entry.lastSeen = now
	if entry.failures < limiter.limit {
		return false, 0
	}
	retry := entry.started.Add(limiter.window).Sub(now)
	if retry < time.Millisecond {
		retry = time.Millisecond
	}
	return true, retry
}

func (limiter *storageFailureWindowLimiter) record(key storageRateKey, now time.Time) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.operations++
	limiter.pruneLocked(now)
	entry := limiter.entryLocked(key, now, true)
	limiter.resetExpiredLocked(entry, now)
	entry.failures++
	entry.lastSeen = now
}

func (limiter *storageFailureWindowLimiter) entryLocked(key storageRateKey, now time.Time,
	create bool) *storageFailureWindow {
	if entry := limiter.entries[key]; entry != nil {
		return entry
	}
	if len(limiter.entries) >= storageRateLimiterMaxEntries {
		return &limiter.overflow[int(key[0])%len(limiter.overflow)]
	}
	if !create {
		return nil
	}
	entry := &storageFailureWindow{started: now, lastSeen: now}
	limiter.entries[key] = entry
	return entry
}

func (limiter *storageFailureWindowLimiter) resetExpiredLocked(entry *storageFailureWindow, now time.Time) {
	if entry.started.IsZero() || now.Before(entry.started) || !now.Before(entry.started.Add(limiter.window)) {
		entry.started, entry.failures = now, 0
	}
}

func (limiter *storageFailureWindowLimiter) pruneLocked(now time.Time) {
	if limiter.operations%256 != 0 {
		return
	}
	cutoff := now.Add(-limiter.entryTTL)
	for key, entry := range limiter.entries {
		if entry.lastSeen.Before(cutoff) {
			delete(limiter.entries, key)
		}
	}
}

type storageSourceConcurrency struct {
	mu     sync.Mutex
	limit  int
	active map[string]int
}

func newStorageSourceConcurrency(limit int) *storageSourceConcurrency {
	return &storageSourceConcurrency{limit: limit, active: make(map[string]int)}
}

func (limiter *storageSourceConcurrency) tryAcquire(source string) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if limiter.active[source] >= limiter.limit {
		return false
	}
	limiter.active[source]++
	return true
}

func (limiter *storageSourceConcurrency) release(source string) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if limiter.active[source] <= 1 {
		delete(limiter.active, source)
		return
	}
	limiter.active[source]--
}

func NewStorageNode(cfg StorageConfig, store *StorageStore, scanner *Scanner, logger *slog.Logger,
	httpClient *http.Client) (*StorageNode, error) {
	cfg = cfg.withRuntimeDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if store == nil || scanner == nil {
		return nil, errors.New("storage store and scanner are required")
	}
	if store.paths == nil || !store.paths.sameRoot(cfg.DataDir) {
		return nil, errors.New("storage store data directory does not match the node configuration")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	node := &StorageNode{
		cfg: cfg, store: store, scanner: scanner, logger: logger,
		control:                    NewStorageInternalClient(cfg.ControlURL, cfg.NodeID, cfg.SharedSecret, httpClient),
		replay:                     NewInternalReplayGuard(),
		uploadSem:                  make(chan struct{}, cfg.UploadConcurrency),
		downloadSem:                make(chan struct{}, cfg.DownloadConcurrency),
		uploadByIP:                 newStorageSourceConcurrency(cfg.UploadConcurrencyPerIP),
		downloadByIP:               newStorageSourceConcurrency(cfg.DownloadConcurrencyPerIP),
		dataByIP:                   newStorageTokenBucketLimiter(cfg.DataPlaneRatePerSecond, cfg.DataPlaneRateBurst),
		dataByKey:                  newStorageTokenBucketLimiter(cfg.ResourceRatePerSecond, cfg.ResourceRateBurst),
		failuresByKey:              newStorageFailureWindowLimiter(cfg.ResourceFailureLimit, cfg.ResourceFailureWindow),
		origins:                    make(map[string]struct{}, len(cfg.AllowedOrigins)),
		downloadHeartbeatInterval:  storageDownloadHeartbeatEvery,
		downloadRecoveryStaleAfter: storageDownloadRecoveryStale,
		downloadMaxDuration:        storageDownloadMaxDuration,
		rateLimitNow:               time.Now,
	}
	for _, origin := range cfg.AllowedOrigins {
		node.origins[origin] = struct{}{}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /storage/health/live", node.healthLive)
	mux.HandleFunc("GET /storage/health/ready", node.healthReady)
	mux.HandleFunc("OPTIONS /storage/v1/uploads/{id}", node.optionsUpload)
	mux.HandleFunc("HEAD /storage/v1/uploads/{id}", node.headUpload)
	mux.HandleFunc("PATCH /storage/v1/uploads/{id}", node.patchUpload)
	mux.HandleFunc("GET /storage/v1/download/{ticket}", node.download)
	mux.HandleFunc("HEAD /storage/v1/download/{ticket}", node.download)
	mux.HandleFunc("POST /internal/v1/uploads", node.reserveUpload)
	mux.HandleFunc("DELETE /internal/v1/uploads/{id}", node.deleteUpload)
	node.handler = node.middleware(mux)
	return node, nil
}

func (node *StorageNode) Handler() http.Handler {
	return node.handler
}

func RunStorageNode(ctx context.Context, cfg StorageConfig, logger *slog.Logger) error {
	cfg = cfg.withRuntimeDefaults()
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("storage configuration error: %w", err)
	}
	if err := prepareStorageDirectories(cfg.DataDir); err != nil {
		return err
	}
	dataDirectoryLock, err := acquireStorageDataDirectoryLock(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("storage data directory is already in use or cannot be locked: %w", err)
	}
	defer dataDirectoryLock.Close()
	store, err := OpenStorageStore(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("storage database error: %w", err)
	}
	defer store.Close()
	scanner := NewScanner(cfg.ScanMode)
	if err := scanner.Probe(ctx, cfg.DataDir); err != nil {
		if cfg.PublicMode || cfg.ScanMode == "required" {
			return fmt.Errorf("storage antivirus readiness error: %w", err)
		}
		if logger != nil {
			logger.Warn("full antivirus unavailable; storage node is using the development signature scanner", "error", err)
		}
	}
	if cfg.PublicMode && !scanner.ProductionReady() {
		return errors.New("public storage mode requires a verified full antivirus scanner")
	}
	node, err := NewStorageNode(cfg, store, scanner, logger, nil)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	if err := store.ResetOutboxClaims(ctx, now); err != nil {
		return fmt.Errorf("reset storage outbox claims: %w", err)
	}
	if cfg.ReplayDeadLettersOnStart {
		replayed, replayErr := store.ReplayDeadLetters(ctx, now, 0)
		if replayErr != nil {
			return fmt.Errorf("replay storage dead letters: %w", replayErr)
		}
		if logger != nil && replayed > 0 {
			logger.Warn("replayed storage dead letters on startup", "count", replayed)
		}
	}
	if err := node.recoverDownloadSessions(ctx); err != nil {
		return fmt.Errorf("recover storage download settlements: %w", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		node.RunWorkers(runCtx)
	}()

	httpServer := &http.Server{
		Addr: cfg.Addr, Handler: node.Handler(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 10 * time.Minute, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	serveErr := make(chan error, 1)
	go func() {
		if logger != nil {
			logger.Info("storage node started", "address", cfg.Addr, "node", cfg.NodeID,
				"publicURL", cfg.PublicURL, "scanner", scanner.Name())
		}
		var listenErr error
		if cfg.TLSCertFile != "" {
			listenErr = httpServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			listenErr = httpServer.ListenAndServe()
		}
		if errors.Is(listenErr, http.ErrServerClosed) {
			listenErr = nil
		}
		serveErr <- listenErr
	}()

	var unexpectedErr error
	select {
	case <-ctx.Done():
	case listenErr := <-serveErr:
		if listenErr == nil {
			unexpectedErr = errors.New("storage HTTP server stopped unexpectedly")
		} else {
			unexpectedErr = fmt.Errorf("storage HTTP server stopped unexpectedly: %w", listenErr)
		}
	}
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		unexpectedErr = errors.Join(unexpectedErr, fmt.Errorf("storage graceful shutdown failed: %w", err))
	}
	select {
	case <-workerDone:
	case <-shutdownCtx.Done():
		unexpectedErr = errors.Join(unexpectedErr, errors.New("storage worker shutdown timed out"))
	}
	return unexpectedErr
}

func (node *StorageNode) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("Cache-Control", "no-store")
		if node.cfg.PublicMode {
			writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		recorder := &storageResponseRecorder{ResponseWriter: writer}
		resourceKey, dataPlane := storageDataPlaneRateKey(request)
		var failureKey storageRateKey
		if dataPlane {
			now := node.currentRateLimitTime()
			sourceKey := storageHashedRateKey("source", node.storageSourceIP(request))
			failureKey = storageCombinedRateKey("failure", resourceKey, sourceKey)
			if allowed, retry := node.dataByIP.allow(sourceKey, now); !allowed {
				node.writeStorageRateLimit(recorder, request, retry, "data_plane_rate_limited",
					"too many storage data requests from this client")
				node.logStorageRequest(request, recorder, started, "data_plane")
				return
			}
			if allowed, retry := node.dataByKey.allow(resourceKey, now); !allowed {
				node.writeStorageRateLimit(recorder, request, retry, "resource_rate_limited",
					"too many requests for this transfer")
				node.logStorageRequest(request, recorder, started, "data_plane")
				return
			}
			if blocked, retry := node.failuresByKey.blocked(failureKey, now); blocked {
				node.writeStorageRateLimit(recorder, request, retry, "resource_failures_limited",
					"too many failed requests for this transfer")
				node.logStorageRequest(request, recorder, started, "data_plane")
				return
			}
		}
		next.ServeHTTP(recorder, request)
		if dataPlane && recorder.status >= 400 && recorder.status < 500 && recorder.status != http.StatusTooManyRequests {
			node.failuresByKey.record(failureKey, node.currentRateLimitTime())
		}
		node.logStorageRequest(request, recorder, started, "")
	})
}

func (node *StorageNode) logStorageRequest(request *http.Request, recorder *storageResponseRecorder,
	started time.Time, fallbackRoute string) {
	status := recorder.status
	if status == 0 {
		status = http.StatusOK
	}
	route := request.Pattern
	if route == "" {
		route = fallbackRoute
		if route == "" {
			route = "unmatched"
		}
	}
	node.logger.Info("storage request", "route", route, "status", status,
		"durationMs", time.Since(started).Milliseconds())
}

func (node *StorageNode) currentRateLimitTime() time.Time {
	if node.rateLimitNow != nil {
		return node.rateLimitNow()
	}
	return time.Now()
}

func (node *StorageNode) writeStorageRateLimit(writer http.ResponseWriter, request *http.Request,
	retry time.Duration, code, message string) {
	node.applyRateLimitCORSHeaders(writer, request)
	seconds := (retry + time.Second - 1) / time.Second
	if seconds < 1 {
		seconds = 1
	}
	writer.Header().Set("Retry-After", strconv.FormatInt(int64(seconds), 10))
	writeStorageError(writer, http.StatusTooManyRequests, code, message)
}

func (node *StorageNode) applyRateLimitCORSHeaders(writer http.ResponseWriter, request *http.Request) {
	if !storageUploadDataPath(request.URL.Path) {
		return
	}
	origin := request.Header.Get("Origin")
	if origin == "" {
		return
	}
	appendVary(writer.Header(), "Origin")
	if _, allowed := node.origins[origin]; !allowed {
		return
	}
	writer.Header().Set("Access-Control-Allow-Origin", origin)
	writer.Header().Set("Access-Control-Expose-Headers",
		"Upload-Offset, Upload-Length, Upload-Status, Retry-After")
	if request.Method == http.MethodOptions {
		writer.Header().Set("Access-Control-Allow-Methods", "OPTIONS, HEAD, PATCH")
		writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Upload-Offset")
		writer.Header().Set("Access-Control-Max-Age", "600")
	}
}

func storageDataPlaneRateKey(request *http.Request) (storageRateKey, bool) {
	path := request.URL.EscapedPath()
	if storageUploadDataPath(path) {
		return storageHashedRateKey("upload", strings.TrimPrefix(path, "/storage/v1/uploads")), true
	}
	if storageDownloadDataPath(path) {
		return storageHashedRateKey("download", strings.TrimPrefix(path, "/storage/v1/download")), true
	}
	return storageRateKey{}, false
}

func storageUploadDataPath(path string) bool {
	return path == "/storage/v1/uploads" || strings.HasPrefix(path, "/storage/v1/uploads/")
}

func storageDownloadDataPath(path string) bool {
	return path == "/storage/v1/download" || strings.HasPrefix(path, "/storage/v1/download/")
}

func storageHashedRateKey(scope, value string) storageRateKey {
	return sha256.Sum256([]byte(scope + "\x00" + value))
}

func storageCombinedRateKey(scope string, values ...storageRateKey) storageRateKey {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(scope))
	for _, value := range values {
		_, _ = hasher.Write(value[:])
	}
	var result storageRateKey
	copy(result[:], hasher.Sum(nil))
	return result
}

type storageResponseRecorder struct {
	http.ResponseWriter
	status int
}

type storageDownloadCheckpointWriter struct {
	writer         io.Writer
	store          *StorageStore
	reservationID  string
	ctx            context.Context
	progress       *atomic.Int64
	actualBytes    int64
	persistedBytes int64
}

func (writer *storageResponseRecorder) WriteHeader(status int) {
	if writer.status == 0 {
		writer.status = status
	}
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *storageResponseRecorder) Write(payload []byte) (int, error) {
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	return writer.ResponseWriter.Write(payload)
}

func (writer *storageResponseRecorder) Unwrap() http.ResponseWriter {
	return writer.ResponseWriter
}

func (writer *storageDownloadCheckpointWriter) Write(payload []byte) (int, error) {
	if err := writer.ctx.Err(); err != nil {
		return 0, err
	}
	written, writeErr := writer.writer.Write(payload)
	if written <= 0 || written > len(payload) {
		return written, writeErr
	}
	writer.actualBytes += int64(written)
	writer.progress.Store(writer.actualBytes)
	if writer.actualBytes-writer.persistedBytes < storageDownloadCheckpointBytes {
		return written, writeErr
	}
	checkpointCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	checkpointErr := writer.store.UpdateDownloadProgress(checkpointCtx, writer.reservationID,
		writer.actualBytes)
	cancel()
	if checkpointErr != nil {
		checkpointErr = fmt.Errorf("checkpoint storage download progress: %w", checkpointErr)
		if writeErr != nil {
			return written, errors.Join(writeErr, checkpointErr)
		}
		return written, checkpointErr
	}
	writer.persistedBytes = writer.actualBytes
	return written, writeErr
}

func (node *StorageNode) healthLive(writer http.ResponseWriter, _ *http.Request) {
	writeStorageJSON(writer, http.StatusOK, StorageHealth{
		Status: "live", Ready: true, NodeID: node.cfg.NodeID, Scanner: node.scanner.Name(),
		ProductionScanner: node.scanner.ProductionReady(), Version: storageBuildVersion,
	})
}

func (node *StorageNode) healthReady(writer http.ResponseWriter, request *http.Request) {
	health := node.storageHealth(request.Context(), time.Now())
	if !health.Ready {
		writeStorageJSON(writer, http.StatusServiceUnavailable, health)
		return
	}
	writeStorageJSON(writer, http.StatusOK, health)
}

func (node *StorageNode) storageHealth(ctx context.Context, now time.Time) StorageHealth {
	health := StorageHealth{
		Status: "ready", Ready: true, NodeID: node.cfg.NodeID, Scanner: node.scanner.Name(),
		ProductionScanner: node.scanner.ProductionReady(), Version: storageBuildVersion,
	}
	markUnavailable := func(detail string) {
		health.Status, health.Ready = "not_ready", false
		if health.OutboxLastError == "" && detail != "" {
			health.OutboxLastError = truncateText(detail, 512)
		}
	}
	if err := node.store.Ping(ctx); err != nil {
		markUnavailable("storage database ping failed")
		return health
	}
	if err := node.store.WriteReadinessCanary(ctx, now.Unix()); err != nil {
		markUnavailable("storage database is not writable")
		return health
	}
	pending, oldestDueAt, err := node.store.OutboxHealth(ctx)
	if err != nil {
		markUnavailable("storage outbox could not be inspected")
		return health
	}
	health.OutboxPending, health.OutboxOldestDueAt = pending, oldestDueAt
	oldestPendingAt, lastOutboxError, err := node.store.OutboxReadiness(ctx)
	if err != nil {
		markUnavailable("storage outbox readiness could not be inspected")
		return health
	}
	health.OutboxOldestPendingAt, health.OutboxLastError = oldestPendingAt, lastOutboxError
	blockingReplays, err := node.store.BlockingReplayCount(ctx)
	if err != nil {
		markUnavailable("storage replay state could not be inspected")
		return health
	}
	if blockingReplays > 0 {
		health.OutboxLastError = fmt.Sprintf(
			"%d dead-letter replay event(s) await a successful control callback", blockingReplays)
		markUnavailable(health.OutboxLastError)
	}
	deadLetters, oldestFailedAt, deadLetterError, err := node.store.DeadLetterHealth(ctx)
	if err != nil {
		markUnavailable("storage dead-letter queue could not be inspected")
		return health
	}
	if deadLetters > 0 {
		detail := fmt.Sprintf("storage outbox has %d dead-letter event(s); oldest failed at %d",
			deadLetters, oldestFailedAt)
		if deadLetterError != "" {
			detail += ": " + deadLetterError
		}
		health.OutboxLastError = truncateText(detail, 512)
		markUnavailable(health.OutboxLastError)
	}
	freeBytes, err := availableDiskBytes(node.cfg.DataDir)
	health.FreeBytes = freeBytes
	if err != nil || freeBytes <= node.cfg.MinFreeBytes ||
		((node.cfg.PublicMode || node.cfg.ScanMode == "required") && !health.ProductionScanner) ||
		(pending > 0 && oldestPendingAt > 0 &&
			oldestPendingAt <= now.Add(-storageOutboxMaxPendingAge).Unix()) {
		markUnavailable(health.OutboxLastError)
	}
	return health
}

func (node *StorageNode) requireStorageAcceptance(writer http.ResponseWriter, request *http.Request) bool {
	if node.storageHealth(request.Context(), time.Now()).Ready {
		return true
	}
	writer.Header().Set("Retry-After", "5")
	writeStorageError(writer, http.StatusServiceUnavailable, "storage_not_ready",
		"storage is temporarily not accepting new transfers")
	return false
}

func (node *StorageNode) optionsUpload(writer http.ResponseWriter, request *http.Request) {
	if !node.applyUploadCORS(writer, request, true) {
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (node *StorageNode) headUpload(writer http.ResponseWriter, request *http.Request) {
	if !node.applyUploadCORS(writer, request, false) {
		return
	}
	upload, ok := node.authorizedStorageUpload(writer, request)
	if !ok {
		return
	}
	node.setUploadHeaders(writer, upload)
	writer.WriteHeader(http.StatusOK)
}

func (node *StorageNode) patchUpload(writer http.ResponseWriter, request *http.Request) {
	if !node.applyUploadCORS(writer, request, false) {
		return
	}
	upload, ok := node.authorizedStorageUpload(writer, request)
	if !ok {
		return
	}
	node.setUploadHeaders(writer, upload)
	if upload.Status != StorageUploadStatusUploading {
		writeStorageError(writer, http.StatusConflict, "upload_not_writable", "upload is no longer writable")
		return
	}
	if !strings.EqualFold(strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]),
		"application/offset+octet-stream") {
		writeStorageError(writer, http.StatusUnsupportedMediaType, "invalid_content_type",
			"Content-Type must be application/offset+octet-stream")
		return
	}
	offset, err := strconv.ParseInt(strings.TrimSpace(request.Header.Get("Upload-Offset")), 10, 64)
	if err != nil || offset < 0 {
		writeStorageError(writer, http.StatusBadRequest, "invalid_offset", "Upload-Offset must be a non-negative integer")
		return
	}
	if offset != upload.Offset {
		writeStorageError(writer, http.StatusConflict, "offset_mismatch", "Upload-Offset does not match the stored offset")
		return
	}
	if request.ContentLength <= 0 {
		writeStorageError(writer, http.StatusLengthRequired, "content_length_required", "a positive Content-Length is required")
		return
	}
	if request.ContentLength > node.cfg.MaxChunkBytes || offset > upload.Length-request.ContentLength {
		writeStorageError(writer, http.StatusRequestEntityTooLarge, "chunk_too_large", "chunk exceeds the configured or remaining length")
		return
	}
	lock := node.lockForUpload(upload.ID)
	if !lock.TryLock() {
		writeStorageError(writer, http.StatusConflict, "upload_busy",
			"another chunk is already being processed for this upload")
		return
	}
	defer lock.Unlock()
	if !node.requireStorageAcceptance(writer, request) {
		return
	}
	releaseSlot, limitKind := node.acquireTransferSlot(request, node.uploadSem, node.uploadByIP)
	if releaseSlot == nil {
		writer.Header().Set("Retry-After", "1")
		code := "upload_concurrency"
		if limitKind == "source" {
			code = "upload_source_concurrency"
		}
		writeStorageError(writer, http.StatusTooManyRequests, code, "too many concurrent upload chunks")
		return
	}
	defer releaseSlot()
	upload, err = node.store.UploadByID(request.Context(), upload.ID)
	if err != nil {
		writeStorageError(writer, http.StatusNotFound, "upload_not_found", "upload does not exist")
		return
	}
	node.setUploadHeaders(writer, upload)
	if upload.Status != StorageUploadStatusUploading || upload.Offset != offset || upload.ExpiresAt <= time.Now().Unix() {
		writeStorageError(writer, http.StatusConflict, "upload_changed", "upload state or offset changed")
		return
	}
	freeBytes, err := availableDiskBytes(node.cfg.DataDir)
	if err != nil || freeBytes <= node.cfg.MinFreeBytes || uint64(request.ContentLength) > freeBytes-node.cfg.MinFreeBytes {
		writeStorageError(writer, http.StatusInsufficientStorage, "insufficient_storage", "reserved free-space limit would be crossed")
		return
	}
	payload, err := readStorageUploadBody(writer, request, request.ContentLength,
		node.cfg.UploadReadIdleTimeout, node.cfg.UploadReadMaxDuration)
	if err != nil || int64(len(payload)) != request.ContentLength {
		if errors.Is(err, errStorageUploadReadTimeout) {
			writeStorageError(writer, http.StatusRequestTimeout, "upload_read_timeout",
				"upload chunk was not delivered within the configured time limit")
			return
		}
		writeStorageError(writer, http.StatusBadRequest, "invalid_chunk_length", "request body does not match Content-Length")
		return
	}
	if err := node.writeUploadChunk(upload, payload); err != nil {
		node.logger.Error("write storage upload chunk", "route", "PATCH /storage/v1/uploads/{id}", "error", err)
		writeStorageError(writer, http.StatusInternalServerError, "storage_error", "unable to persist upload chunk")
		return
	}
	nextOffset := offset + int64(len(payload))
	if err := node.store.UpdateUploadOffset(request.Context(), upload.ID, offset, nextOffset); err != nil {
		_ = os.Truncate(upload.Path, offset)
		if current, loadErr := node.store.UploadByID(request.Context(), upload.ID); loadErr == nil {
			node.setUploadHeaders(writer, current)
		}
		writeStorageError(writer, http.StatusConflict, "offset_changed", "upload offset changed concurrently")
		return
	}
	upload.Offset = nextOffset
	if nextOffset == upload.Length {
		if err := node.finalizeCompletedUpload(request.Context(), upload); err != nil {
			node.logger.Error("isolate completed upload", "route", "PATCH /storage/v1/uploads/{id}", "error", err)
			writeStorageError(writer, http.StatusInternalServerError, "isolation_failed", "upload was saved but could not enter quarantine")
			return
		}
		upload.Status = StorageUploadStatusPendingScan
	}
	node.setUploadHeaders(writer, upload)
	writer.WriteHeader(http.StatusNoContent)
}

func (node *StorageNode) reserveUpload(writer http.ResponseWriter, request *http.Request) {
	body, ok := node.verifiedInternalBody(writer, request, storageProtocolBodyMax)
	if !ok {
		return
	}
	var payload StorageReserveUploadRequest
	if err := decodeStorageProtocolJSON(body, &payload); err != nil {
		writeStorageError(writer, http.StatusBadRequest, "invalid_request", "invalid reserve request")
		return
	}
	if err := node.validateReserveRequest(payload); err != nil {
		writeStorageError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !node.requireStorageAcceptance(writer, request) {
		return
	}
	now := time.Now().Unix()
	requested := storageUploadRecord{
		ID: payload.ID, UploadTokenHash: payload.UploadTokenHash, OriginalName: payload.OriginalName,
		ContentType: payload.ContentType, Length: payload.Length, Status: StorageUploadStatusUploading,
		Path: node.storagePath("tmp", payload.ID, ".part"), ExpiresAt: payload.ExpiresAt,
	}
	node.reserveMu.Lock()
	defer node.reserveMu.Unlock()
	if existing, err := node.store.UploadByID(request.Context(), payload.ID); err == nil {
		stored, _, reserveErr := node.store.ReserveUpload(request.Context(), requested)
		if reserveErr != nil {
			writeStorageError(writer, http.StatusConflict, "reservation_conflict", "upload id is reserved with different metadata")
			return
		}
		if existing.ExpiresAt <= now {
			writeStorageError(writer, http.StatusGone, "reservation_expired", "upload reservation has expired")
			return
		}
		if err := node.ensureUploadingFile(stored, false); err != nil {
			writeStorageError(writer, http.StatusInternalServerError, "storage_error", "reserved upload file is unavailable")
			return
		}
		node.writeReserveResponse(writer, http.StatusOK, stored)
		return
	} else if !errors.Is(err, ErrNotFound) {
		writeStorageError(writer, http.StatusInternalServerError, "storage_error", "unable to inspect storage reservation")
		return
	}
	reservedBytes, err := node.store.ReservedUploadBytes(request.Context(), now)
	if err != nil {
		writeStorageError(writer, http.StatusInternalServerError, "storage_error", "unable to calculate storage reservations")
		return
	}
	freeBytes, err := availableDiskBytes(node.cfg.DataDir)
	if err != nil || !storageReservationFits(freeBytes, node.cfg.MinFreeBytes, reservedBytes, payload.Length) {
		writeStorageError(writer, http.StatusInsufficientStorage, "insufficient_storage", "storage reservation would cross the free-space limit")
		return
	}
	stored, created, err := node.store.ReserveUpload(request.Context(), requested)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, ErrConflict) {
			status = http.StatusConflict
		}
		writeStorageError(writer, status, "reservation_failed", "unable to reserve upload")
		return
	}
	if err := node.ensureUploadingFile(stored, created); err != nil {
		if created {
			_ = node.store.DeleteUpload(request.Context(), stored.ID)
		}
		writeStorageError(writer, http.StatusInternalServerError, "storage_error", "unable to create reserved upload file")
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	node.writeReserveResponse(writer, status, stored)
}

func (node *StorageNode) deleteUpload(writer http.ResponseWriter, request *http.Request) {
	if _, ok := node.verifiedInternalBody(writer, request, storageProtocolBodyMax); !ok {
		return
	}
	id := request.PathValue("id")
	if !validStorageObjectID(id) {
		writeStorageError(writer, http.StatusBadRequest, "invalid_upload_id", "invalid upload id")
		return
	}
	lock := node.lockForUpload(id)
	lock.Lock()
	defer lock.Unlock()
	upload, err := node.store.UploadByID(request.Context(), id)
	if errors.Is(err, ErrNotFound) {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeStorageError(writer, http.StatusInternalServerError, "storage_error", "unable to load upload")
		return
	}
	activeDownloads, err := node.store.HasActiveDownloadSessions(request.Context(), id)
	if err != nil {
		writeStorageError(writer, http.StatusInternalServerError, "storage_error", "unable to inspect active downloads")
		return
	}
	if activeDownloads {
		writeStorageError(writer, http.StatusConflict, "download_in_progress", "download is still in progress")
		return
	}
	if err := node.removeUploadFiles(upload); err != nil {
		writeStorageError(writer, http.StatusInternalServerError, "storage_error", "unable to remove upload data")
		return
	}
	if err := node.store.DeleteUpload(request.Context(), id); err != nil {
		writeStorageError(writer, http.StatusInternalServerError, "storage_error", "unable to delete upload record")
		return
	}
	node.uploadLock.Delete(id)
	writer.WriteHeader(http.StatusNoContent)
}

func (node *StorageNode) download(writer http.ResponseWriter, request *http.Request) {
	claims, err := VerifyStorageDownloadTicket(node.cfg.SharedSecret, request.PathValue("ticket"))
	if err != nil || claims.NodeID != node.cfg.NodeID {
		writeStorageError(writer, http.StatusUnauthorized, "invalid_ticket", "download ticket is invalid or expired")
		return
	}
	if !node.requireStorageAcceptance(writer, request) {
		return
	}
	if request.Method == http.MethodGet {
		releaseSlot, limitKind := node.acquireTransferSlot(request, node.downloadSem, node.downloadByIP)
		if releaseSlot == nil {
			writer.Header().Set("Retry-After", "1")
			code := "download_concurrency"
			if limitKind == "source" {
				code = "download_source_concurrency"
			}
			writeStorageError(writer, http.StatusTooManyRequests, code,
				"too many concurrent download connections")
			return
		}
		defer releaseSlot()
	}
	objectLock := node.lockForUpload(claims.UploadID)
	objectLock.Lock()
	objectLocked := true
	defer func() {
		if objectLocked {
			objectLock.Unlock()
		}
	}()
	upload, err := node.store.CleanUpload(request.Context(), claims.UploadID, time.Now().Unix())
	if err != nil || filepath.Clean(upload.Path) != filepath.Clean(node.storagePath("objects", upload.ID, ".blob")) {
		writeStorageError(writer, http.StatusGone, "file_unavailable", "download object is unavailable")
		return
	}
	file, err := os.Open(upload.Path)
	if err != nil {
		writeStorageError(writer, http.StatusGone, "file_unavailable", "download object is unavailable")
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.IsDir() || info.Size() != upload.Length {
		writeStorageError(writer, http.StatusGone, "file_unavailable", "download object is incomplete")
		return
	}
	selected, err := parseStorageRange(request.Header.Get("Range"), upload.Length)
	if err != nil {
		writer.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", upload.Length))
		writeStorageError(writer, http.StatusRequestedRangeNotSatisfiable, "invalid_range",
			"only an absent Range or one valid byte range is supported")
		return
	}
	if request.Method == http.MethodHead {
		setStorageDownloadHeaders(writer, upload, selected)
		if selected.Partial {
			writer.WriteHeader(http.StatusPartialContent)
		} else {
			writer.WriteHeader(http.StatusOK)
		}
		return
	}
	if _, err := file.Seek(selected.Start, io.SeekStart); err != nil {
		writeStorageError(writer, http.StatusInternalServerError, "storage_error", "unable to read download object")
		return
	}
	settlePath := "/internal/v1/storage/downloads/" + url.PathEscape(claims.ReservationID) + "/settle"
	streamStarted := time.Now()
	if err := node.store.PrepareDownloadSession(request.Context(), storageDownloadSession{
		ReservationID: claims.ReservationID, UploadID: upload.ID, ExpectedBytes: upload.Length,
		StreamBytes: selected.Length, SettlePath: settlePath, StartedAt: streamStarted.Unix(),
	}); err != nil {
		status := http.StatusServiceUnavailable
		code := "download_session_unavailable"
		if errors.Is(err, ErrConflict) {
			status, code = http.StatusForbidden, "download_already_started"
		}
		writeStorageError(writer, status, code, "download session could not be prepared")
		return
	}
	beginBody, _ := json.Marshal(StorageDownloadBeginRequest{NodeID: node.cfg.NodeID, UploadID: upload.ID})
	beginPath := "/internal/v1/storage/downloads/" + url.PathEscape(claims.ReservationID) + "/begin"
	if beginErr := node.sendControl(request.Context(), http.MethodPost, beginPath, beginBody); beginErr != nil {
		status := http.StatusServiceUnavailable
		var httpErr *StorageHTTPError
		if errors.As(beginErr, &httpErr) && httpErr.StatusCode >= 400 && httpErr.StatusCode < 500 {
			status = http.StatusForbidden
		}
		if storageBeginDefinitelyRejected(beginErr) {
			if cancelErr := node.store.CancelDownloadSession(context.Background(), claims.ReservationID); cancelErr != nil {
				node.logger.Error("cancel rejected storage download session", "route",
					"POST /internal/v1/storage/downloads/{reservation}/begin", "error", cancelErr)
			}
		} else if settleErr := node.store.FinishPendingDownloadSession(
			context.Background(), claims.ReservationID, time.Now().Unix()); settleErr != nil {
			node.logger.Error("persist ambiguous storage download settlement", "route",
				"POST /internal/v1/storage/downloads/{reservation}/settle", "error", settleErr)
		}
		writeStorageError(writer, status, "download_not_authorized", "control plane did not authorize this download")
		return
	}
	if err := node.store.ActivateDownloadSession(request.Context(), claims.ReservationID); err != nil {
		if settleErr := node.store.FinishPendingDownloadSession(
			context.Background(), claims.ReservationID, time.Now().Unix()); settleErr != nil {
			node.logger.Error("persist unactivated storage download settlement", "route",
				"POST /internal/v1/storage/downloads/{reservation}/settle", "error", settleErr)
		}
		writeStorageError(writer, http.StatusServiceUnavailable, "download_session_unavailable",
			"download session could not be activated")
		return
	}
	objectLock.Unlock()
	objectLocked = false
	setStorageDownloadHeaders(writer, upload, selected)
	if selected.Partial {
		writer.WriteHeader(http.StatusPartialContent)
	}
	streamDeadline := streamStarted.Add(node.downloadMaxDuration)
	streamCtx, streamCancel := context.WithDeadline(request.Context(), streamDeadline)
	defer streamCancel()
	responseController := http.NewResponseController(writer)
	if err := responseController.SetWriteDeadline(streamDeadline); err != nil &&
		!errors.Is(err, http.ErrNotSupported) {
		node.logger.Warn("set storage download deadline", "route", "GET /storage/v1/download/{ticket}",
			"error", err)
	}
	var progress atomic.Int64
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		node.runDownloadHeartbeats(streamCtx, streamCancel, claims.ReservationID, settlePath, &progress)
	}()
	checkpointWriter := &storageDownloadCheckpointWriter{
		writer: writer, store: node.store, reservationID: claims.ReservationID,
		ctx: streamCtx, progress: &progress,
	}
	actualBytes, copyErr := io.CopyN(checkpointWriter, file, selected.Length)
	streamCancel()
	<-heartbeatDone
	if copyErr != nil {
		node.logger.Warn("storage download interrupted", "route", "GET /storage/v1/download/{ticket}", "error", copyErr)
	}
	settleCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	settleErr := node.store.FinishDownloadSession(settleCtx, claims.ReservationID, actualBytes, time.Now().Unix())
	if settleErr != nil {
		settleErr = node.store.ConservativelyFinishDownloadSession(
			settleCtx, claims.ReservationID, time.Now().Unix())
	}
	if settleErr != nil {
		node.logger.Error("persist storage download settlement", "route",
			"POST /internal/v1/storage/downloads/{reservation}/settle", "error", settleErr)
		cancel()
		return
	}
	node.retryOutbox(settleCtx)
	cancel()
}

func (node *StorageNode) runDownloadHeartbeats(ctx context.Context, cancelStream context.CancelFunc,
	reservationID, settlePath string, progress *atomic.Int64) {
	interval := node.downloadHeartbeatInterval
	if interval <= 0 {
		interval = storageDownloadHeartbeatEvery
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			actualBytes := progress.Load()
			heartbeatCtx, heartbeatCancel := context.WithTimeout(ctx, 10*time.Second)
			now := time.Now().Unix()
			reliableBytes, err := node.store.HeartbeatDownloadSession(heartbeatCtx, reservationID, actualBytes, now)
			if err != nil {
				heartbeatCancel()
				node.logger.Error("persist storage download heartbeat", "route",
					"POST /internal/v1/storage/downloads/{reservation}/settle", "error", err)
				cancelStream()
				return
			}
			if reliableBytes == 0 {
				heartbeatCancel()
				continue
			}
			body, err := json.Marshal(StorageDownloadSettleRequest{ActualBytes: reliableBytes})
			if err == nil {
				err = node.sendControl(heartbeatCtx, http.MethodPost, settlePath, body)
			}
			heartbeatCancel()
			if err == nil {
				continue
			}
			var httpErr *StorageHTTPError
			if errors.As(err, &httpErr) && httpErr.StatusCode >= 400 && httpErr.StatusCode < 500 {
				node.logger.Warn("control rejected storage download heartbeat", "route",
					"POST /internal/v1/storage/downloads/{reservation}/settle", "error", err)
				cancelStream()
				return
			}
			node.logger.Warn("retryable storage download heartbeat failed", "route",
				"POST /internal/v1/storage/downloads/{reservation}/settle", "error", err)
		}
	}
}

func setStorageDownloadHeaders(writer http.ResponseWriter, upload storageUploadRecord, selected storageRange) {
	writer.Header().Set("Accept-Ranges", "bytes")
	writer.Header().Set("Content-Type", upload.ContentType)
	writer.Header().Set("Content-Disposition", contentDisposition(upload.OriginalName))
	writer.Header().Set("Content-Length", strconv.FormatInt(selected.Length, 10))
	if selected.Partial {
		writer.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d",
			selected.Start, selected.Start+selected.Length-1, upload.Length))
	}
}

func (node *StorageNode) recoverDownloadSessions(ctx context.Context) error {
	for {
		recovered, err := node.store.RecoverDownloadSessions(ctx, time.Now().Unix(), 100)
		if err != nil {
			return err
		}
		if recovered < 100 {
			return nil
		}
	}
}

func (node *StorageNode) RunWorkers(ctx context.Context) {
	var workers sync.WaitGroup
	start := func(interval time.Duration, work func(context.Context)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			runStorageWorker(ctx, interval, work)
		}()
	}
	start(node.cfg.WorkerInterval, node.recoverCompletedUploads)
	start(node.cfg.WorkerInterval, node.scanPendingUploads)
	start(node.cfg.WorkerInterval, node.retryOutbox)
	start(node.cfg.WorkerInterval, node.recoverStaleDownloadSessions)
	start(storageReadinessCanaryEvery, node.probeStorageWritable)
	start(node.cfg.CleanupInterval, node.cleanupExpiredUploads)
	workers.Wait()
}

func runStorageWorker(ctx context.Context, interval time.Duration, work func(context.Context)) {
	if ctx.Err() != nil {
		return
	}
	work(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			work(ctx)
		}
	}
}

func (node *StorageNode) recoverCompletedUploads(ctx context.Context) {
	uploads, err := node.store.RecoverableCompletedUploads(ctx, 32)
	if err != nil {
		node.logger.Error("recover completed storage uploads", "route", "worker/recover", "error", err)
		return
	}
	for _, upload := range uploads {
		lock := node.lockForUpload(upload.ID)
		lock.Lock()
		err := node.finalizeCompletedUpload(ctx, upload)
		lock.Unlock()
		if err != nil && !errors.Is(err, ErrConflict) {
			node.logger.Error("recover completed storage upload", "route", "worker/recover", "error", err)
		}
	}
}

func (node *StorageNode) recoverStaleDownloadSessions(ctx context.Context) {
	now := time.Now()
	staleAfter := node.downloadRecoveryStaleAfter
	if staleAfter <= 0 {
		staleAfter = storageDownloadRecoveryStale
	}
	maxDuration := node.downloadMaxDuration
	if maxDuration <= 0 {
		maxDuration = storageDownloadMaxDuration
	}
	recovered, err := node.store.RecoverStaleDownloadSessions(ctx, now.Unix(),
		now.Add(-staleAfter).Unix(), now.Add(-maxDuration).Unix(), 100)
	if err != nil {
		node.logger.Error("recover stale storage downloads", "route", "worker/download-recovery", "error", err)
		return
	}
	if recovered > 0 {
		node.retryOutbox(ctx)
	}
}

func (node *StorageNode) scanPendingUploads(ctx context.Context) {
	for scanned := 0; scanned < 4; scanned++ {
		now := time.Now()
		uploads, err := node.store.ClaimPendingScans(ctx, now.Unix(),
			now.Add(storageScanLeaseDuration).Unix(), 1)
		if err != nil {
			node.logger.Error("claim storage scans", "route", "worker/scan", "error", err)
			return
		}
		if len(uploads) == 0 {
			break
		}
		upload := uploads[0]
		if ctx.Err() != nil {
			_ = node.store.ReleaseScanClaim(context.Background(), upload.ID, upload.ScanLeaseID)
			return
		}
		lock := node.lockForUpload(upload.ID)
		lock.Lock()
		node.scanOneUpload(ctx, upload)
		lock.Unlock()
	}
	node.retryOutbox(ctx)
}

func (node *StorageNode) scanOneUpload(ctx context.Context, upload storageUploadRecord) {
	stopLeaseRenewal := node.startScanLeaseRenewal(ctx, upload)
	scanPath, err := node.resolveScanPath(upload)
	if err != nil {
		leaseErr := stopLeaseRenewal()
		if ctx.Err() != nil {
			_ = node.store.ReleaseScanClaim(context.Background(), upload.ID, upload.ScanLeaseID)
			return
		}
		if leaseErr != nil {
			_ = node.store.ReleaseScanClaim(context.Background(), upload.ID, upload.ScanLeaseID)
			node.logger.Error("renew storage scan lease", "route", "worker/scan", "error", leaseErr)
			return
		}
		node.finishScannerError(ctx, upload, upload.Path, "quarantined file is unavailable", "")
		return
	}
	result, scanErr := node.scanner.Scan(ctx, scanPath)
	leaseErr := stopLeaseRenewal()
	if ctx.Err() != nil {
		_ = node.store.ReleaseScanClaim(context.Background(), upload.ID, upload.ScanLeaseID)
		return
	}
	if leaseErr != nil {
		_ = node.store.ReleaseScanClaim(context.Background(), upload.ID, upload.ScanLeaseID)
		node.logger.Error("renew storage scan lease", "route", "worker/scan", "error", leaseErr)
		return
	}
	if scanErr != nil || strings.Contains(result.Detail, "could not scan") {
		detail := result.Detail
		if scanErr != nil {
			detail = truncateText(scanErr.Error(), 512)
		}
		node.finishScannerError(ctx, upload, scanPath, detail, result.SHA256)
		return
	}
	if !result.Clean {
		event, eventErr := node.scanCompletionEvent(upload.ID, StorageCompletionStatusBlocked,
			result.SHA256, result.Detail)
		if eventErr != nil {
			_ = node.store.ReleaseScanClaim(ctx, upload.ID, upload.ScanLeaseID)
			return
		}
		if err := node.store.CompleteScan(ctx, upload.ID, upload.ScanLeaseID, time.Now().Unix(),
			StorageUploadStatusBlocked, "", result.SHA256, result.Detail, event); err != nil {
			_ = node.store.ReleaseScanClaim(ctx, upload.ID, upload.ScanLeaseID)
			node.logger.Error("record blocked storage upload", "route", "worker/scan", "error", err)
			return
		}
		_ = node.removeGeneratedPath(scanPath)
		return
	}
	objectPath := node.storagePath("objects", upload.ID, ".blob")
	if filepath.Clean(scanPath) != filepath.Clean(objectPath) {
		if err := os.Rename(scanPath, objectPath); err != nil {
			_ = node.store.ReleaseScanClaim(ctx, upload.ID, upload.ScanLeaseID)
			node.logger.Error("promote clean storage upload", "route", "worker/scan", "error", err)
			return
		}
	}
	event, eventErr := node.scanCompletionEvent(upload.ID, StorageCompletionStatusReady,
		result.SHA256, result.Detail)
	if eventErr != nil {
		_ = node.store.ReleaseScanClaim(ctx, upload.ID, upload.ScanLeaseID)
		return
	}
	if err := node.store.CompleteScan(ctx, upload.ID, upload.ScanLeaseID, time.Now().Unix(),
		StorageUploadStatusClean, objectPath, result.SHA256, result.Detail, event); err != nil {
		_ = node.store.ReleaseScanClaim(ctx, upload.ID, upload.ScanLeaseID)
		node.logger.Error("record clean storage upload", "route", "worker/scan", "error", err)
	}
}

func (node *StorageNode) finishScannerError(ctx context.Context, upload storageUploadRecord, currentPath,
	detail, sha256Value string) {
	quarantinePath := node.storagePath("quarantine", upload.ID, ".blob")
	if currentPath != "" && filepath.Clean(currentPath) != filepath.Clean(quarantinePath) {
		if _, err := os.Stat(currentPath); err == nil {
			if renameErr := os.Rename(currentPath, quarantinePath); renameErr != nil {
				quarantinePath = currentPath
			}
		}
	}
	event, err := node.scanCompletionEvent(upload.ID, StorageCompletionStatusQuarantined,
		sha256Value, detail)
	if err != nil {
		_ = node.store.ReleaseScanClaim(ctx, upload.ID, upload.ScanLeaseID)
		return
	}
	if err := node.store.CompleteScan(ctx, upload.ID, upload.ScanLeaseID, time.Now().Unix(),
		StorageUploadStatusScannerError, quarantinePath, sha256Value, detail, event); err != nil {
		_ = node.store.ReleaseScanClaim(ctx, upload.ID, upload.ScanLeaseID)
		node.logger.Error("record quarantined storage upload", "route", "worker/scan", "error", err)
	}
}

func (node *StorageNode) startScanLeaseRenewal(ctx context.Context,
	upload storageUploadRecord) func() error {
	renewalCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(storageScanLeaseRenewalEvery)
		defer ticker.Stop()
		for {
			select {
			case <-renewalCtx.Done():
				done <- nil
				return
			case <-ticker.C:
				now := time.Now()
				renewCtx, renewCancel := context.WithTimeout(context.Background(), 10*time.Second)
				err := node.store.RenewScanLease(renewCtx, upload.ID, upload.ScanLeaseID,
					now.Unix(), now.Add(storageScanLeaseDuration).Unix())
				renewCancel()
				if err != nil {
					done <- err
					return
				}
			}
		}
	}()
	return func() error {
		cancel()
		if err := <-done; err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		now := time.Now()
		renewCtx, renewCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer renewCancel()
		return node.store.RenewScanLease(renewCtx, upload.ID, upload.ScanLeaseID,
			now.Unix(), now.Add(storageScanLeaseDuration).Unix())
	}
}

func (node *StorageNode) scanCompletionEvent(uploadID, status, sha256Value,
	detail string) (storageOutboxRecord, error) {
	body, err := json.Marshal(StorageUploadCompleteRequest{
		NodeID: node.cfg.NodeID, Status: status, SHA256: sha256Value, ScanDetail: detail,
	})
	if err != nil {
		return storageOutboxRecord{}, err
	}
	return storageOutboxRecord{
		EventKey: "upload-complete:" + uploadID, Method: http.MethodPost,
		Path:          "/internal/v1/storage/uploads/" + url.PathEscape(uploadID) + "/complete",
		Body:          body,
		NextAttemptAt: time.Now().Unix(),
	}, nil
}

func (node *StorageNode) retryOutbox(ctx context.Context) {
	for processed := 0; processed < 32; processed++ {
		if ctx.Err() != nil {
			return
		}
		now := time.Now()
		events, err := node.store.ClaimOutbox(ctx, now.Unix(), now.Add(node.cfg.OutboxClaimLease).Unix(), 1)
		if err != nil {
			node.logger.Error("claim storage outbox", "route", "worker/outbox", "error", err)
			return
		}
		if len(events) == 0 {
			return
		}
		event := events[0]
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = node.sendControl(requestCtx, event.Method, event.Path, event.Body)
		cancel()
		if err == nil {
			if ackErr := node.store.AckClaimedOutbox(ctx, event, time.Now().Unix()); ackErr != nil {
				node.logger.Error("acknowledge storage outbox", "route", storageControlRouteTemplate(event.Path), "error", ackErr)
			}
			continue
		}
		var httpErr *StorageHTTPError
		status := 0
		if errors.As(err, &httpErr) {
			status = httpErr.StatusCode
		}
		if storageOutboxSemanticTerminal(event, status) {
			if ackErr := node.store.AckClaimedOutbox(ctx, event, time.Now().Unix()); ackErr != nil {
				node.logger.Error("acknowledge terminal storage outbox response", "route",
					storageControlRouteTemplate(event.Path), "status", status, "error", ackErr)
			} else {
				node.logger.Warn("storage outbox callback reached terminal response", "route",
					storageControlRouteTemplate(event.Path), "status", status, "action", "ack")
			}
			continue
		}
		detail := storageOutboxErrorDetail(err)
		attemptsAfterFailure := event.Attempts + 1
		if storageOutboxPermanentFailure(status) || attemptsAfterFailure >= node.cfg.OutboxMaxAttempts {
			if deadLetterErr := node.store.DeadLetterClaimedOutbox(ctx, event, time.Now().Unix(),
				status, detail); deadLetterErr != nil {
				node.logger.Error("move storage outbox event to dead letter", "route",
					storageControlRouteTemplate(event.Path), "status", status, "error", deadLetterErr)
			} else {
				node.logger.Error("storage outbox event moved to dead letter", "route",
					storageControlRouteTemplate(event.Path), "status", status,
					"attempts", attemptsAfterFailure)
			}
			continue
		}
		retryNow := time.Now()
		next := retryNow.Add(storageOutboxBackoff(event.Attempts)).Unix()
		if retryErr := node.store.RetryClaimedOutbox(ctx, event, retryNow.Unix(), next, detail); retryErr != nil {
			node.logger.Error("reschedule storage outbox", "route", storageControlRouteTemplate(event.Path), "error", retryErr)
		}
	}
}

func (node *StorageNode) probeStorageWritable(ctx context.Context) {
	if err := node.store.WriteReadinessCanary(ctx, time.Now().Unix()); err != nil {
		node.logger.Error("storage readiness write canary failed", "route", "worker/readiness-canary", "error", err)
	}
}

func (node *StorageNode) cleanupExpiredUploads(ctx context.Context) {
	uploads, err := node.store.ExpiredUploads(ctx, time.Now().Unix(), 100)
	if err != nil {
		node.logger.Error("load expired storage uploads", "route", "worker/cleanup", "error", err)
		return
	}
	for _, upload := range uploads {
		lock := node.lockForUpload(upload.ID)
		lock.Lock()
		activeDownloads, activeErr := node.store.HasActiveDownloadSessions(ctx, upload.ID)
		removeErr := activeErr
		if removeErr == nil && activeDownloads {
			lock.Unlock()
			continue
		}
		if removeErr == nil {
			removeErr = node.removeUploadFiles(upload)
		}
		if removeErr == nil {
			removeErr = node.store.DeleteUpload(ctx, upload.ID)
		}
		lock.Unlock()
		if removeErr != nil {
			node.logger.Error("remove expired storage upload", "route", "worker/cleanup", "error", removeErr)
			continue
		}
		node.uploadLock.Delete(upload.ID)
	}
}

func (node *StorageNode) sendControl(ctx context.Context, method, path string, body []byte) error {
	responseBody, status, err := node.control.sendSigned(ctx, method, path, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return newStorageHTTPError(status, responseBody)
	}
	return nil
}

func (node *StorageNode) verifiedInternalBody(writer http.ResponseWriter, request *http.Request,
	maxBytes int64) ([]byte, bool) {
	body, err := readStorageBody(request, maxBytes)
	if err != nil {
		writeStorageError(writer, http.StatusBadRequest, "invalid_body", "request body is too large or unreadable")
		return nil, false
	}
	if err := VerifyInternalRequest(request, body, node.cfg.SharedSecret, node.cfg.NodeID,
		node.replay, time.Now()); err != nil {
		writeStorageError(writer, http.StatusUnauthorized, "internal_auth_failed", "internal authentication failed")
		return nil, false
	}
	return body, true
}

func (node *StorageNode) validateReserveRequest(payload StorageReserveUploadRequest) error {
	if !validStorageObjectID(payload.ID) {
		return errors.New("invalid upload id")
	}
	hash, err := base64.RawURLEncoding.DecodeString(payload.UploadTokenHash)
	if err != nil || len(hash) != 32 {
		return errors.New("uploadTokenHash must be a base64url SHA-256 value")
	}
	if payload.OriginalName == "" || cleanFilename(payload.OriginalName) != payload.OriginalName {
		return errors.New("originalName must be a safe base filename of at most 255 characters")
	}
	if payload.ContentType == "" || len(payload.ContentType) > 255 || strings.ContainsAny(payload.ContentType, "\r\n\x00") {
		return errors.New("invalid contentType")
	}
	if payload.Length <= 0 || payload.Length > node.cfg.MaxUploadBytes {
		return errors.New("length exceeds the storage-node limit")
	}
	if payload.ExpiresAt <= time.Now().Unix() {
		return errors.New("expiresAt must be in the future")
	}
	return nil
}

func (node *StorageNode) authorizedStorageUpload(writer http.ResponseWriter,
	request *http.Request) (storageUploadRecord, bool) {
	id := request.PathValue("id")
	if !validStorageObjectID(id) {
		writeStorageError(writer, http.StatusNotFound, "upload_not_found", "upload does not exist")
		return storageUploadRecord{}, false
	}
	upload, err := node.store.UploadByID(request.Context(), id)
	if err != nil {
		writeStorageError(writer, http.StatusNotFound, "upload_not_found", "upload does not exist")
		return storageUploadRecord{}, false
	}
	fields := strings.Fields(request.Header.Get("Authorization"))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") ||
		!secureEqual(tokenHash(fields[1]), upload.UploadTokenHash) {
		writeStorageError(writer, http.StatusUnauthorized, "invalid_upload_token", "upload token is invalid")
		return storageUploadRecord{}, false
	}
	if upload.ExpiresAt <= time.Now().Unix() {
		writeStorageError(writer, http.StatusGone, "upload_expired", "upload reservation has expired")
		return storageUploadRecord{}, false
	}
	return upload, true
}

func (node *StorageNode) applyUploadCORS(writer http.ResponseWriter, request *http.Request,
	preflight bool) bool {
	origin := request.Header.Get("Origin")
	if origin == "" {
		if preflight {
			writeStorageError(writer, http.StatusBadRequest, "origin_required", "Origin is required for preflight")
			return false
		}
		return true
	}
	appendVary(writer.Header(), "Origin")
	if _, allowed := node.origins[origin]; !allowed {
		writeStorageError(writer, http.StatusForbidden, "origin_not_allowed", "origin is not allowed")
		return false
	}
	writer.Header().Set("Access-Control-Allow-Origin", origin)
	writer.Header().Set("Access-Control-Expose-Headers", "Upload-Offset, Upload-Length, Upload-Status")
	if !preflight {
		return true
	}
	method := strings.ToUpper(strings.TrimSpace(request.Header.Get("Access-Control-Request-Method")))
	if method != http.MethodPatch && method != http.MethodHead {
		writeStorageError(writer, http.StatusForbidden, "method_not_allowed", "preflight method is not allowed")
		return false
	}
	allowedHeaders := map[string]struct{}{
		"authorization": {}, "content-type": {}, "upload-offset": {},
	}
	for _, header := range strings.Split(request.Header.Get("Access-Control-Request-Headers"), ",") {
		header = strings.ToLower(strings.TrimSpace(header))
		if header == "" {
			continue
		}
		if _, allowed := allowedHeaders[header]; !allowed {
			writeStorageError(writer, http.StatusForbidden, "header_not_allowed", "preflight header is not allowed")
			return false
		}
	}
	writer.Header().Set("Access-Control-Allow-Methods", "OPTIONS, HEAD, PATCH")
	writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Upload-Offset")
	writer.Header().Set("Access-Control-Max-Age", "600")
	return true
}

func (node *StorageNode) setUploadHeaders(writer http.ResponseWriter, upload storageUploadRecord) {
	writer.Header().Set("Upload-Offset", strconv.FormatInt(upload.Offset, 10))
	writer.Header().Set("Upload-Length", strconv.FormatInt(upload.Length, 10))
	writer.Header().Set("Upload-Status", externalStorageUploadStatus(upload.Status))
}

func externalStorageUploadStatus(status string) string {
	switch status {
	case StorageUploadStatusPendingScan, StorageUploadStatusScanning:
		return "scanning"
	case StorageUploadStatusClean:
		return StorageCompletionStatusReady
	case StorageUploadStatusScannerError:
		return StorageCompletionStatusQuarantined
	default:
		return status
	}
}

func (node *StorageNode) writeReserveResponse(writer http.ResponseWriter, status int, upload storageUploadRecord) {
	writeStorageJSON(writer, status, StorageReserveUploadResponse{
		ID: upload.ID, Length: upload.Length, Offset: upload.Offset,
		Status: externalStorageUploadStatus(upload.Status), ExpiresAt: upload.ExpiresAt,
	})
}

func (node *StorageNode) ensureUploadingFile(upload storageUploadRecord, created bool) error {
	if upload.Status != StorageUploadStatusUploading {
		return nil
	}
	expectedPath := node.storagePath("tmp", upload.ID, ".part")
	if filepath.Clean(upload.Path) != filepath.Clean(expectedPath) {
		return errors.New("upload path is not server-generated")
	}
	flags := os.O_WRONLY | os.O_CREATE
	if created {
		flags |= os.O_EXCL
	}
	file, err := os.OpenFile(expectedPath, flags, 0o600)
	if err != nil && created && errors.Is(err, os.ErrExist) {
		info, statErr := os.Stat(expectedPath)
		if statErr == nil && info.Size() == 0 {
			return nil
		}
	}
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() != upload.Offset {
		return fmt.Errorf("upload file size %d does not match offset %d", info.Size(), upload.Offset)
	}
	return nil
}

func (node *StorageNode) writeUploadChunk(upload storageUploadRecord, payload []byte) error {
	if filepath.Clean(upload.Path) != filepath.Clean(node.storagePath("tmp", upload.ID, ".part")) {
		return errors.New("upload path is not server-generated")
	}
	file, err := os.OpenFile(upload.Path, os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() < upload.Offset {
		return errors.New("upload file is shorter than the persisted offset")
	}
	if info.Size() > upload.Offset {
		if err := file.Truncate(upload.Offset); err != nil {
			return err
		}
	}
	if _, err := file.Seek(upload.Offset, io.SeekStart); err != nil {
		return err
	}
	written, err := file.Write(payload)
	if err != nil {
		return err
	}
	if written != len(payload) {
		return io.ErrShortWrite
	}
	return file.Sync()
}

func (node *StorageNode) finalizeCompletedUpload(ctx context.Context, upload storageUploadRecord) error {
	quarantinePath := node.storagePath("quarantine", upload.ID, ".blob")
	tempPath := node.storagePath("tmp", upload.ID, ".part")
	quarantineInfo, quarantineErr := os.Stat(quarantinePath)
	if quarantineErr == nil {
		if quarantineInfo.IsDir() || quarantineInfo.Size() != upload.Length {
			return errors.New("quarantine destination conflicts with completed upload")
		}
		if _, tempErr := os.Stat(tempPath); tempErr == nil {
			if err := os.Remove(tempPath); err != nil {
				return err
			}
		} else if !os.IsNotExist(tempErr) {
			return tempErr
		}
	} else if os.IsNotExist(quarantineErr) {
		if err := os.Rename(tempPath, quarantinePath); err != nil {
			return err
		}
	} else {
		return quarantineErr
	}
	return node.store.MarkPendingScan(ctx, upload.ID, quarantinePath)
}

func (node *StorageNode) resolveScanPath(upload storageUploadRecord) (string, error) {
	for _, candidate := range []string{
		upload.Path,
		node.storagePath("quarantine", upload.ID, ".blob"),
		node.storagePath("objects", upload.ID, ".blob"),
	} {
		if candidate == "" || !node.isGeneratedUploadPath(upload.ID, candidate) {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Size() == upload.Length {
			return candidate, nil
		}
	}
	return "", errors.New("no complete server-generated upload file exists")
}

func (node *StorageNode) removeUploadFiles(upload storageUploadRecord) error {
	paths := []string{
		node.storagePath("tmp", upload.ID, ".part"),
		node.storagePath("quarantine", upload.ID, ".blob"),
		node.storagePath("objects", upload.ID, ".blob"),
	}
	if upload.Path != "" {
		if !node.isGeneratedUploadPath(upload.ID, upload.Path) {
			return errors.New("refusing to remove a non-generated upload path")
		}
		paths = append(paths, upload.Path)
	}
	seen := make(map[string]struct{})
	for _, path := range paths {
		path = filepath.Clean(path)
		if _, exists := seen[path]; exists {
			continue
		}
		seen[path] = struct{}{}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (node *StorageNode) removeGeneratedPath(path string) error {
	cleaned := filepath.Clean(path)
	root, err := filepath.Abs(node.cfg.DataDir)
	if err != nil {
		return err
	}
	absolute, err := filepath.Abs(cleaned)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(root, absolute)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return errors.New("refusing to remove path outside storage data directory")
	}
	if err := os.Remove(absolute); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (node *StorageNode) storagePath(directory, id, extension string) string {
	path, err := node.store.paths.resolveUploadKey(id, storageUploadPathKey(directory, id, extension))
	if err != nil {
		return ""
	}
	return path
}

func (node *StorageNode) isGeneratedUploadPath(id, path string) bool {
	cleaned := filepath.Clean(path)
	for _, expected := range []string{
		node.storagePath("tmp", id, ".part"),
		node.storagePath("quarantine", id, ".blob"),
		node.storagePath("objects", id, ".blob"),
	} {
		if cleaned == filepath.Clean(expected) {
			return true
		}
	}
	return false
}

func (node *StorageNode) lockForUpload(id string) *sync.Mutex {
	value, _ := node.uploadLock.LoadOrStore(id, &sync.Mutex{})
	return value.(*sync.Mutex)
}

func storageReservationFits(freeBytes, minimumFree uint64, reservedBytes, requestedBytes int64) bool {
	if reservedBytes < 0 || requestedBytes <= 0 || freeBytes <= minimumFree {
		return false
	}
	available := freeBytes - minimumFree
	if uint64(reservedBytes) > available {
		return false
	}
	return uint64(requestedBytes) <= available-uint64(reservedBytes)
}

func (node *StorageNode) acquireTransferSlot(request *http.Request, global chan struct{},
	perSource *storageSourceConcurrency) (func(), string) {
	source := node.storageSourceIP(request)
	if !perSource.tryAcquire(source) {
		return nil, "source"
	}
	select {
	case global <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() {
				<-global
				perSource.release(source)
			})
		}, ""
	default:
		perSource.release(source)
		return nil, "global"
	}
}

func (node *StorageNode) storageSourceIP(request *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(request.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(request.RemoteAddr)
	}
	host = strings.Trim(host, "[]")
	remote := net.ParseIP(host)
	if remote != nil && node.isTrustedStorageProxy(remote) {
		values := strings.Split(request.Header.Get("X-Forwarded-For"), ",")
		for index := len(values) - 1; index >= 0; index-- {
			candidate := net.ParseIP(strings.TrimSpace(values[index]))
			if candidate != nil && !node.isTrustedStorageProxy(candidate) {
				return candidate.String()
			}
		}
	}
	if remote != nil {
		return remote.String()
	}
	if host == "" {
		return "unknown"
	}
	return strings.ToLower(host)
}

func (node *StorageNode) isTrustedStorageProxy(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, candidate := range node.cfg.TrustedProxyCIDRs {
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

func appendVary(header http.Header, value string) {
	for _, current := range header.Values("Vary") {
		for _, item := range strings.Split(current, ",") {
			if strings.EqualFold(strings.TrimSpace(item), value) {
				return
			}
		}
	}
	header.Add("Vary", value)
}

func readStorageBody(request *http.Request, maxBytes int64) ([]byte, error) {
	defer request.Body.Close()
	if request.ContentLength > maxBytes {
		return nil, errors.New("request body is too large")
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, errors.New("request body is too large")
	}
	return body, nil
}

var errStorageUploadReadTimeout = errors.New("storage upload read timeout")

type storageUploadDeadlineReader struct {
	source       io.Reader
	controller   *http.ResponseController
	idleTimeout  time.Duration
	hardDeadline time.Time
}

func (reader *storageUploadDeadlineReader) Read(buffer []byte) (int, error) {
	now := time.Now()
	if !now.Before(reader.hardDeadline) {
		return 0, errStorageUploadReadTimeout
	}
	deadline := now.Add(reader.idleTimeout)
	if deadline.After(reader.hardDeadline) {
		deadline = reader.hardDeadline
	}
	if err := reader.controller.SetReadDeadline(deadline); err != nil &&
		!errors.Is(err, http.ErrNotSupported) {
		return 0, err
	}
	written, err := reader.source.Read(buffer)
	if err != nil {
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			return written, errStorageUploadReadTimeout
		}
	}
	return written, err
}

func readStorageUploadBody(writer http.ResponseWriter, request *http.Request, maxBytes int64,
	idleTimeout, maxDuration time.Duration) ([]byte, error) {
	defer request.Body.Close()
	if request.ContentLength > maxBytes {
		return nil, errors.New("request body is too large")
	}
	controller := http.NewResponseController(writer)
	defer func() { _ = controller.SetReadDeadline(time.Time{}) }()
	var hardExpired atomic.Bool
	hardTimer := time.AfterFunc(maxDuration, func() {
		hardExpired.Store(true)
		_ = request.Body.Close()
	})
	defer hardTimer.Stop()
	reader := &storageUploadDeadlineReader{
		source: request.Body, controller: controller, idleTimeout: idleTimeout,
		hardDeadline: time.Now().Add(maxDuration),
	}
	body, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if hardExpired.Load() {
		return nil, errStorageUploadReadTimeout
	}
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, errors.New("request body is too large")
	}
	return body, nil
}

func writeStorageJSON(writer http.ResponseWriter, status int, payload any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(payload)
}

func writeStorageError(writer http.ResponseWriter, status int, code, message string) {
	writeStorageJSON(writer, status, map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

type storageRange struct {
	Start   int64
	Length  int64
	Partial bool
}

func parseStorageRange(value string, size int64) (storageRange, error) {
	if value == "" {
		return storageRange{Start: 0, Length: size}, nil
	}
	if size <= 0 || !strings.HasPrefix(value, "bytes=") || strings.Contains(value, ",") {
		return storageRange{}, errors.New("invalid or multipart range")
	}
	spec := strings.TrimSpace(strings.TrimPrefix(value, "bytes="))
	parts := strings.Split(spec, "-")
	if len(parts) != 2 {
		return storageRange{}, errors.New("invalid range")
	}
	if parts[0] == "" {
		suffix, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || suffix <= 0 {
			return storageRange{}, errors.New("invalid suffix range")
		}
		if suffix > size {
			suffix = size
		}
		return storageRange{Start: size - suffix, Length: suffix, Partial: true}, nil
	}
	start, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || start < 0 || start >= size {
		return storageRange{}, errors.New("invalid range start")
	}
	end := size - 1
	if parts[1] != "" {
		end, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil || end < start {
			return storageRange{}, errors.New("invalid range end")
		}
		if end >= size {
			end = size - 1
		}
	}
	return storageRange{Start: start, Length: end - start + 1, Partial: true}, nil
}

func storageOutboxBackoff(attempts int) time.Duration {
	if attempts < 0 {
		attempts = 0
	}
	if attempts > 8 {
		attempts = 8
	}
	return time.Duration(1<<attempts) * time.Second
}

func storageOutboxErrorDetail(err error) string {
	var httpErr *StorageHTTPError
	if errors.As(err, &httpErr) {
		return fmt.Sprintf("control callback returned HTTP %d", httpErr.StatusCode)
	}
	return truncateText(err.Error(), 512)
}

func storageOutboxSemanticTerminal(event storageOutboxRecord, status int) bool {
	if status != http.StatusGone {
		return false
	}
	switch {
	case strings.HasPrefix(event.EventKey, "upload-complete:"):
		id := strings.TrimPrefix(event.EventKey, "upload-complete:")
		return id != "" && event.Method == http.MethodPost &&
			event.Path == "/internal/v1/storage/uploads/"+url.PathEscape(id)+"/complete"
	case strings.HasPrefix(event.EventKey, "download-settle:"):
		id := strings.TrimPrefix(event.EventKey, "download-settle:")
		return id != "" && event.Method == http.MethodPost &&
			event.Path == "/internal/v1/storage/downloads/"+url.PathEscape(id)+"/settle"
	default:
		return false
	}
}

func storageOutboxPermanentFailure(status int) bool {
	if status < 400 || status >= 500 {
		return false
	}
	switch status {
	case http.StatusRequestTimeout, http.StatusConflict, http.StatusTooEarly, http.StatusTooManyRequests:
		return false
	default:
		return true
	}
}

func storageBeginDefinitelyRejected(err error) bool {
	var httpErr *StorageHTTPError
	return errors.As(err, &httpErr) && httpErr.StatusCode >= 400 && httpErr.StatusCode < 500 &&
		httpErr.StatusCode != http.StatusRequestTimeout && httpErr.StatusCode != http.StatusTooManyRequests
}

func storageControlRouteTemplate(path string) string {
	switch {
	case strings.HasPrefix(path, "/internal/v1/storage/uploads/") && strings.HasSuffix(path, "/complete"):
		return "POST /internal/v1/storage/uploads/{id}/complete"
	case strings.HasPrefix(path, "/internal/v1/storage/downloads/") && strings.HasSuffix(path, "/begin"):
		return "POST /internal/v1/storage/downloads/{reservation}/begin"
	case strings.HasPrefix(path, "/internal/v1/storage/downloads/") && strings.HasSuffix(path, "/settle"):
		return "POST /internal/v1/storage/downloads/{reservation}/settle"
	default:
		return "internal-control"
	}
}
