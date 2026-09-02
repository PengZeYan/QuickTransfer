package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type StorageStore struct {
	db    *sql.DB
	paths *storageDataPaths
}

type storageUploadRecord struct {
	ID              string
	UploadTokenHash string
	OriginalName    string
	ContentType     string
	Length          int64
	Offset          int64
	Status          string
	Path            string
	SHA256          string
	ScanDetail      string
	ExpiresAt       int64
	ScanLeaseUntil  int64
	ScanLeaseID     string
}

type storageOutboxRecord struct {
	ID             int64
	EventKey       string
	Method         string
	Path           string
	Body           []byte
	Attempts       int
	NextAttemptAt  int64
	CreatedAt      int64
	LastError      string
	Version        int64
	ClaimToken     string
	ClaimUntil     int64
	ReplayBlocking int
}

type storageDownloadSession struct {
	ReservationID string
	UploadID      string
	ExpectedBytes int64
	StreamBytes   int64
	ActualBytes   int64
	Status        string
	SettlePath    string
	StartedAt     int64
	HeartbeatAt   int64
}

type storageDownloadSettlementMode uint8

const (
	storageSettleStreamingExact storageDownloadSettlementMode = iota
	storageSettlePendingZero
	storageSettleStreamingCheckpoint
)

const storageUploadColumns = `id,token_hash,original_name,content_type,length,offset,status,path,sha256,scan_detail,expires_at,scan_lease_until,scan_lease_id`

const storageDownloadSessionColumns = `reservation_id,upload_id,expected_bytes,stream_bytes,actual_bytes,status,settle_path,started_at,heartbeat_at`

func OpenStorageStore(dataDir string) (*StorageStore, error) {
	if err := prepareStorageDirectories(dataDir); err != nil {
		return nil, err
	}
	paths, err := newStorageDataPaths(dataDir)
	if err != nil {
		return nil, err
	}
	dbPath := filepath.Join(paths.root, "db", "storage-node.db")
	dsn := dbPath + "?_pragma=busy_timeout%3d5000&_pragma=journal_mode%3dWAL&_pragma=synchronous%3dFULL"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	statements := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=FULL",
		`CREATE TABLE IF NOT EXISTS storage_uploads (
			id TEXT PRIMARY KEY,
			token_hash TEXT NOT NULL,
			original_name TEXT NOT NULL,
			content_type TEXT NOT NULL,
			length INTEGER NOT NULL,
			offset INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL,
			path TEXT NOT NULL,
			sha256 TEXT NOT NULL DEFAULT '',
			scan_detail TEXT NOT NULL DEFAULT '',
			expires_at INTEGER NOT NULL,
			scan_lease_until INTEGER NOT NULL DEFAULT 0,
			scan_lease_id TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS storage_outbox (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event_key TEXT NOT NULL UNIQUE,
			method TEXT NOT NULL,
			path TEXT NOT NULL,
			body BLOB NOT NULL,
			attempts INTEGER NOT NULL DEFAULT 0,
			next_attempt_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL DEFAULT 0,
			last_error TEXT NOT NULL DEFAULT '',
			version INTEGER NOT NULL DEFAULT 1,
			claim_token TEXT NOT NULL DEFAULT '',
			claim_until INTEGER NOT NULL DEFAULT 0,
			replay_blocking INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS storage_outbox_dead_letter (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			original_id INTEGER NOT NULL,
			event_key TEXT NOT NULL UNIQUE,
			method TEXT NOT NULL,
			path TEXT NOT NULL,
			body BLOB NOT NULL,
			attempts INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			failed_at INTEGER NOT NULL,
			last_status INTEGER NOT NULL DEFAULT 0,
			last_error TEXT NOT NULL,
			version INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS storage_readiness_canary (
			id INTEGER PRIMARY KEY CHECK(id=1),
			touched_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS storage_download_sessions (
			reservation_id TEXT PRIMARY KEY,
			upload_id TEXT NOT NULL,
			expected_bytes INTEGER NOT NULL,
			stream_bytes INTEGER NOT NULL,
			actual_bytes INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL,
			settle_path TEXT NOT NULL,
			started_at INTEGER NOT NULL,
			heartbeat_at INTEGER NOT NULL
		)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("storage database migration: %w", err)
		}
	}
	if err := ensureSQLiteColumn(db, "storage_uploads", "scan_lease_until", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage database migration: %w", err)
	}
	if err := ensureSQLiteColumn(db, "storage_uploads", "scan_lease_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage database migration: %w", err)
	}
	if err := ensureSQLiteColumn(db, "storage_outbox", "created_at", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage database migration: %w", err)
	}
	if err := ensureSQLiteColumn(db, "storage_outbox", "last_error", "TEXT NOT NULL DEFAULT ''"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage database migration: %w", err)
	}
	if err := ensureSQLiteColumn(db, "storage_outbox", "version", "INTEGER NOT NULL DEFAULT 1"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage database migration: %w", err)
	}
	if err := ensureSQLiteColumn(db, "storage_outbox", "claim_token", "TEXT NOT NULL DEFAULT ''"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage database migration: %w", err)
	}
	if err := ensureSQLiteColumn(db, "storage_outbox", "claim_until", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage database migration: %w", err)
	}
	if err := ensureSQLiteColumn(db, "storage_outbox", "replay_blocking", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage database migration: %w", err)
	}
	if err := ensureSQLiteColumn(db, "storage_download_sessions", "stream_bytes", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage database migration: %w", err)
	}
	if err := ensureSQLiteColumn(db, "storage_download_sessions", "heartbeat_at", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage database migration: %w", err)
	}
	if _, err := db.Exec(`UPDATE storage_download_sessions SET
		stream_bytes=CASE WHEN stream_bytes<=0 THEN expected_bytes ELSE stream_bytes END,
		heartbeat_at=CASE WHEN heartbeat_at<=0 THEN started_at ELSE heartbeat_at END
		WHERE stream_bytes<=0 OR heartbeat_at<=0`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage database migration: %w", err)
	}
	if _, err := db.Exec(`UPDATE storage_outbox SET created_at=MIN(next_attempt_at,unixepoch())
		WHERE created_at<=0`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage database migration: %w", err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO storage_readiness_canary(id,touched_at) VALUES(1,unixepoch())`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage database migration: %w", err)
	}
	for _, statement := range []string{
		"DROP INDEX IF EXISTS idx_storage_uploads_claim",
		`CREATE INDEX IF NOT EXISTS idx_storage_uploads_claim
			ON storage_uploads(status,scan_lease_until,expires_at,id)`,
		`CREATE INDEX IF NOT EXISTS idx_storage_uploads_expiry
			ON storage_uploads(expires_at,id)`,
		"DROP INDEX IF EXISTS idx_storage_outbox_due",
		`CREATE INDEX IF NOT EXISTS idx_storage_outbox_due
			ON storage_outbox(next_attempt_at,claim_until,id)`,
		`CREATE INDEX IF NOT EXISTS idx_storage_outbox_age
			ON storage_outbox(created_at,id)`,
		`CREATE INDEX IF NOT EXISTS idx_storage_outbox_dead_letter_age
			ON storage_outbox_dead_letter(failed_at,id)`,
		`CREATE INDEX IF NOT EXISTS idx_storage_download_sessions_recovery
			ON storage_download_sessions(status,reservation_id)`,
		`CREATE INDEX IF NOT EXISTS idx_storage_download_sessions_upload_status
			ON storage_download_sessions(upload_id,status)`,
		"PRAGMA optimize",
	} {
		if _, err := db.Exec(statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("storage database index migration: %w", err)
		}
	}
	if err := migrateStorageUploadPaths(context.Background(), db, paths); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage upload path migration: %w", err)
	}
	return &StorageStore{db: db, paths: paths}, nil
}

func (store *StorageStore) Close() error {
	return store.db.Close()
}

func (store *StorageStore) Ping(ctx context.Context) error {
	return store.db.PingContext(ctx)
}

func (store *StorageStore) WriteReadinessCanary(ctx context.Context, now int64) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE storage_readiness_canary SET touched_at=? WHERE id=1`, now)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("storage readiness canary row is unavailable")
	}
	return tx.Rollback()
}

func (store *StorageStore) scanUpload(row interface{ Scan(...any) error }) (storageUploadRecord, error) {
	upload, err := scanStorageUpload(row)
	if err != nil {
		return storageUploadRecord{}, err
	}
	if store.paths == nil {
		return storageUploadRecord{}, errors.New("storage data path resolver is unavailable")
	}
	_, absolute, err := store.paths.normalizeUploadPath(upload.ID, upload.Path)
	if err != nil {
		return storageUploadRecord{}, fmt.Errorf("resolve stored path for upload %s: %w", upload.ID, err)
	}
	upload.Path = absolute
	return upload, nil
}

func (store *StorageStore) persistentUploadPath(id, value string) (string, string, error) {
	if store.paths == nil {
		return "", "", errors.New("storage data path resolver is unavailable")
	}
	return store.paths.normalizeUploadPath(id, value)
}

func (store *StorageStore) OutboxHealth(ctx context.Context) (pending, oldestDueAt int64, err error) {
	err = store.db.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(MIN(next_attempt_at),0)
		FROM storage_outbox`).Scan(&pending, &oldestDueAt)
	return pending, oldestDueAt, err
}

func (store *StorageStore) OutboxReadiness(ctx context.Context) (oldestPendingAt int64,
	lastError string, err error) {
	err = store.db.QueryRowContext(ctx, `SELECT COALESCE(MIN(created_at),0),COALESCE((
		SELECT last_error FROM storage_outbox ORDER BY created_at,id LIMIT 1
	),'') FROM storage_outbox`).Scan(&oldestPendingAt, &lastError)
	return oldestPendingAt, lastError, err
}

func (store *StorageStore) DeadLetterHealth(ctx context.Context) (count, oldestFailedAt int64,
	lastError string, err error) {
	err = store.db.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(MIN(failed_at),0),COALESCE((
		SELECT last_error FROM storage_outbox_dead_letter ORDER BY failed_at,id LIMIT 1
	),'') FROM storage_outbox_dead_letter`).Scan(&count, &oldestFailedAt, &lastError)
	return count, oldestFailedAt, lastError, err
}

func (store *StorageStore) BlockingReplayCount(ctx context.Context) (int64, error) {
	var count int64
	err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM storage_outbox WHERE replay_blocking<>0`).Scan(&count)
	return count, err
}

func scanStorageDownloadSession(row interface{ Scan(...any) error }) (storageDownloadSession, error) {
	var session storageDownloadSession
	err := row.Scan(&session.ReservationID, &session.UploadID, &session.ExpectedBytes,
		&session.StreamBytes, &session.ActualBytes, &session.Status, &session.SettlePath,
		&session.StartedAt, &session.HeartbeatAt)
	return session, err
}

func (store *StorageStore) DownloadSessionByID(ctx context.Context,
	reservationID string) (storageDownloadSession, error) {
	session, err := scanStorageDownloadSession(store.db.QueryRowContext(ctx,
		`SELECT `+storageDownloadSessionColumns+` FROM storage_download_sessions WHERE reservation_id=?`,
		reservationID))
	if errors.Is(err, sql.ErrNoRows) {
		return storageDownloadSession{}, ErrNotFound
	}
	return session, err
}

func (store *StorageStore) HasActiveDownloadSessions(ctx context.Context, uploadID string) (bool, error) {
	var count int
	err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM storage_download_sessions
		WHERE upload_id=? AND status IN ('begin_pending','streaming','settle_pending')`, uploadID).Scan(&count)
	return count > 0, err
}

func (store *StorageStore) PrepareDownloadSession(ctx context.Context, session storageDownloadSession) error {
	if session.StreamBytes <= 0 {
		session.StreamBytes = session.ExpectedBytes
	}
	if session.HeartbeatAt <= 0 {
		session.HeartbeatAt = session.StartedAt
	}
	if session.ReservationID == "" || session.UploadID == "" || session.ExpectedBytes <= 0 ||
		session.StreamBytes <= 0 || session.StreamBytes > session.ExpectedBytes || session.SettlePath == "" ||
		session.StartedAt <= 0 || session.HeartbeatAt <= 0 {
		return errors.New("invalid storage download session")
	}
	result, err := store.db.ExecContext(ctx, `INSERT INTO storage_download_sessions
		(reservation_id,upload_id,expected_bytes,stream_bytes,actual_bytes,status,settle_path,started_at,heartbeat_at)
		VALUES(?,?,?,?,0,'begin_pending',?,?,?) ON CONFLICT(reservation_id) DO NOTHING`,
		session.ReservationID, session.UploadID, session.ExpectedBytes, session.StreamBytes,
		session.SettlePath, session.StartedAt, session.HeartbeatAt)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrConflict
	}
	return nil
}

func (store *StorageStore) ActivateDownloadSession(ctx context.Context, reservationID string) error {
	result, err := store.db.ExecContext(ctx, `UPDATE storage_download_sessions SET status='streaming'
		WHERE reservation_id=? AND status='begin_pending'`, reservationID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrConflict
	}
	return nil
}

func (store *StorageStore) UpdateDownloadProgress(ctx context.Context, reservationID string,
	actualBytes int64) error {
	if actualBytes <= 0 {
		return errors.New("invalid storage download progress")
	}
	result, err := store.db.ExecContext(ctx, `UPDATE storage_download_sessions SET actual_bytes=?
		WHERE reservation_id=? AND status='streaming' AND actual_bytes<? AND ?<=stream_bytes`,
		actualBytes, reservationID, actualBytes, actualBytes)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrConflict
	}
	return nil
}

func (store *StorageStore) HeartbeatDownloadSession(ctx context.Context, reservationID string,
	actualBytes, now int64) (int64, error) {
	if actualBytes < 0 || now <= 0 {
		return 0, errors.New("invalid storage download heartbeat")
	}
	var reliableBytes int64
	err := store.db.QueryRowContext(ctx, `UPDATE storage_download_sessions SET
		actual_bytes=MAX(actual_bytes,?),heartbeat_at=MAX(heartbeat_at,?)
		WHERE reservation_id=? AND status='streaming' AND ?<=stream_bytes
		RETURNING actual_bytes`, actualBytes, now, reservationID, actualBytes).Scan(&reliableBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrConflict
	}
	if err != nil {
		return 0, err
	}
	return reliableBytes, nil
}

func (store *StorageStore) CancelDownloadSession(ctx context.Context, reservationID string) error {
	result, err := store.db.ExecContext(ctx, `DELETE FROM storage_download_sessions
		WHERE reservation_id=? AND status='begin_pending'`, reservationID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrConflict
	}
	return nil
}

func (store *StorageStore) FinishDownloadSession(ctx context.Context, reservationID string,
	actualBytes, now int64) error {
	return store.queueDownloadSettlement(ctx, reservationID, actualBytes, now,
		storageSettleStreamingExact)
}

func (store *StorageStore) FinishPendingDownloadSession(ctx context.Context,
	reservationID string, now int64) error {
	return store.queueDownloadSettlement(ctx, reservationID, 0, now, storageSettlePendingZero)
}

func (store *StorageStore) ConservativelyFinishDownloadSession(ctx context.Context,
	reservationID string, now int64) error {
	return store.queueDownloadSettlement(ctx, reservationID, 0, now,
		storageSettleStreamingCheckpoint)
}

func (store *StorageStore) queueDownloadSettlement(ctx context.Context, reservationID string,
	actualBytes, now int64, mode storageDownloadSettlementMode) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	session, err := scanStorageDownloadSession(tx.QueryRowContext(ctx,
		`SELECT `+storageDownloadSessionColumns+` FROM storage_download_sessions WHERE reservation_id=?`,
		reservationID))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	switch mode {
	case storageSettlePendingZero:
		actualBytes = 0
	case storageSettleStreamingCheckpoint:
		actualBytes = session.ActualBytes
	case storageSettleStreamingExact:
	default:
		return errors.New("invalid storage download settlement mode")
	}
	if actualBytes < 0 || actualBytes > session.StreamBytes {
		return errors.New("invalid storage download settlement byte count")
	}
	if mode == storageSettleStreamingExact && actualBytes < session.ActualBytes {
		return ErrConflict
	}
	if session.Status == "settle_pending" {
		if session.ActualBytes != actualBytes {
			return ErrConflict
		}
	} else {
		expectedStatus := "streaming"
		if mode == storageSettlePendingZero {
			expectedStatus = "begin_pending"
		}
		if session.Status != expectedStatus {
			return ErrConflict
		}
	}
	reportedBytes := actualBytes
	if actualBytes > 0 && actualBytes < session.ExpectedBytes {
		reportedBytes, err = encodeFinalNodeDownloadBytes(session.ExpectedBytes, actualBytes)
		if err != nil {
			return err
		}
	}
	body, err := json.Marshal(StorageDownloadSettleRequest{ActualBytes: reportedBytes})
	if err != nil {
		return err
	}
	event := storageOutboxRecord{
		EventKey: "download-settle:" + reservationID, Method: http.MethodPost,
		Path: session.SettlePath, Body: body, NextAttemptAt: now,
	}
	if session.Status != "settle_pending" {
		result, err := tx.ExecContext(ctx, `UPDATE storage_download_sessions
			SET status='settle_pending',actual_bytes=? WHERE reservation_id=? AND status=?`,
			actualBytes, reservationID, session.Status)
		if err != nil {
			return err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if rows != 1 {
			return ErrConflict
		}
	}
	if err := enqueueStorageOutboxTx(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *StorageStore) RecoverDownloadSessions(ctx context.Context, now int64, limit int) (int, error) {
	return store.recoverDownloadSessions(ctx, now, limit, "status IN ('begin_pending','streaming')", nil)
}

func (store *StorageStore) RecoverStaleDownloadSessions(ctx context.Context, now, staleBefore,
	hardBefore int64, limit int) (int, error) {
	return store.recoverDownloadSessions(ctx, now, limit,
		`(status='begin_pending' AND started_at<=?) OR
		 (status='streaming' AND (heartbeat_at<=? OR started_at<=?))`,
		[]any{staleBefore, staleBefore, hardBefore})
}

func (store *StorageStore) recoverDownloadSessions(ctx context.Context, now int64, limit int,
	where string, arguments []any) (int, error) {
	if limit <= 0 || strings.TrimSpace(where) == "" {
		return 0, errors.New("invalid storage download recovery query")
	}
	queryArguments := append(append([]any(nil), arguments...), limit)
	rows, err := store.db.QueryContext(ctx, `SELECT reservation_id,status FROM storage_download_sessions
		WHERE `+where+` ORDER BY started_at,reservation_id LIMIT ?`, queryArguments...)
	if err != nil {
		return 0, err
	}
	type recoverableSession struct {
		reservationID string
		status        string
	}
	var sessions []recoverableSession
	for rows.Next() {
		var session recoverableSession
		if err := rows.Scan(&session.reservationID, &session.status); err != nil {
			_ = rows.Close()
			return 0, err
		}
		sessions = append(sessions, session)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	recovered := 0
	for _, session := range sessions {
		var recoverErr error
		if session.status == "begin_pending" {
			recoverErr = store.FinishPendingDownloadSession(ctx, session.reservationID, now)
		} else {
			recoverErr = store.ConservativelyFinishDownloadSession(ctx, session.reservationID, now)
		}
		if recoverErr != nil {
			return recovered, recoverErr
		}
		recovered++
	}
	return recovered, nil
}

func scanStorageUpload(row interface{ Scan(...any) error }) (storageUploadRecord, error) {
	var upload storageUploadRecord
	err := row.Scan(&upload.ID, &upload.UploadTokenHash, &upload.OriginalName, &upload.ContentType,
		&upload.Length, &upload.Offset, &upload.Status, &upload.Path, &upload.SHA256,
		&upload.ScanDetail, &upload.ExpiresAt, &upload.ScanLeaseUntil, &upload.ScanLeaseID)
	return upload, err
}

func (store *StorageStore) UploadByID(ctx context.Context, id string) (storageUploadRecord, error) {
	upload, err := store.scanUpload(store.db.QueryRowContext(ctx,
		`SELECT `+storageUploadColumns+` FROM storage_uploads WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return storageUploadRecord{}, ErrNotFound
	}
	return upload, err
}

func (store *StorageStore) ReserveUpload(ctx context.Context, requested storageUploadRecord) (storageUploadRecord, bool, error) {
	persistentPath, absolutePath, err := store.persistentUploadPath(requested.ID, requested.Path)
	if err != nil || persistentPath == "" {
		if err == nil {
			err = errors.New("uploading storage path must not be empty")
		}
		return storageUploadRecord{}, false, err
	}
	if persistentPath != storageUploadPathKey("tmp", requested.ID, ".part") {
		return storageUploadRecord{}, false, errors.New("upload reservation path must use its generated temporary key")
	}
	requested.Path = absolutePath
	result, err := store.db.ExecContext(ctx, `INSERT INTO storage_uploads
		(id,token_hash,original_name,content_type,length,offset,status,path,sha256,scan_detail,expires_at)
		VALUES(?,?,?,?,?,0,'uploading',?,'','',?) ON CONFLICT(id) DO NOTHING`,
		requested.ID, requested.UploadTokenHash, requested.OriginalName, requested.ContentType,
		requested.Length, persistentPath, requested.ExpiresAt)
	if err != nil {
		return storageUploadRecord{}, false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return storageUploadRecord{}, false, err
	}
	stored, err := store.UploadByID(ctx, requested.ID)
	if err != nil {
		return storageUploadRecord{}, false, err
	}
	if stored.UploadTokenHash != requested.UploadTokenHash || stored.OriginalName != requested.OriginalName ||
		stored.ContentType != requested.ContentType || stored.Length != requested.Length ||
		stored.ExpiresAt != requested.ExpiresAt {
		return storageUploadRecord{}, false, ErrConflict
	}
	return stored, rows == 1, nil
}

func (store *StorageStore) ReservedUploadBytes(ctx context.Context, now int64) (int64, error) {
	var reserved int64
	err := store.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(length-offset),0)
		FROM storage_uploads WHERE status='uploading' AND expires_at>?`, now).Scan(&reserved)
	return reserved, err
}

func (store *StorageStore) UpdateUploadOffset(ctx context.Context, id string, expected, next int64) error {
	result, err := store.db.ExecContext(ctx, `UPDATE storage_uploads SET offset=?
		WHERE id=? AND offset=? AND status='uploading' AND ?<=length`, next, id, expected, next)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrConflict
	}
	return nil
}

func (store *StorageStore) MarkPendingScan(ctx context.Context, id, quarantinePath string) error {
	persistentPath, absolutePath, err := store.persistentUploadPath(id, quarantinePath)
	if err != nil {
		return err
	}
	if persistentPath != storageUploadPathKey("quarantine", id, ".blob") {
		return errors.New("pending scan path must use its generated quarantine key")
	}
	result, err := store.db.ExecContext(ctx, `UPDATE storage_uploads
		SET status='pending_scan',path=?,scan_lease_until=0,scan_lease_id=''
		WHERE id=? AND offset=length AND status='uploading'`, persistentPath, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 1 {
		return nil
	}
	upload, loadErr := store.UploadByID(ctx, id)
	if loadErr == nil && upload.Status == StorageUploadStatusPendingScan && upload.Path == absolutePath {
		return nil
	}
	return ErrConflict
}

func (store *StorageStore) RecoverableCompletedUploads(ctx context.Context, limit int) ([]storageUploadRecord, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT `+storageUploadColumns+`
		FROM storage_uploads WHERE status='uploading' AND offset=length ORDER BY expires_at,id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return store.collectUploads(rows)
}

func (store *StorageStore) ClaimPendingScans(ctx context.Context, now, leaseUntil int64,
	limit int) ([]storageUploadRecord, error) {
	if limit <= 0 || leaseUntil <= now {
		return nil, errors.New("invalid storage scan lease")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT `+storageUploadColumns+`
		FROM storage_uploads
		WHERE (status='pending_scan' OR (status='scanning' AND scan_lease_until<=?)) AND expires_at>?
		ORDER BY expires_at,id LIMIT ?`, now, now, limit)
	if err != nil {
		return nil, err
	}
	candidates, err := store.collectUploads(rows)
	if closeErr := rows.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	claimed := make([]storageUploadRecord, 0, len(candidates))
	for _, candidate := range candidates {
		leaseID, tokenErr := randomToken(12)
		if tokenErr != nil {
			return nil, tokenErr
		}
		result, updateErr := tx.ExecContext(ctx, `UPDATE storage_uploads
			SET status='scanning',scan_lease_until=?,scan_lease_id=?
			WHERE id=? AND expires_at>? AND
			(status='pending_scan' OR (status='scanning' AND scan_lease_until<=?))`,
			leaseUntil, leaseID, candidate.ID, now, now)
		if updateErr != nil {
			return nil, updateErr
		}
		count, updateErr := result.RowsAffected()
		if updateErr != nil {
			return nil, updateErr
		}
		if count == 1 {
			candidate.Status = StorageUploadStatusScanning
			candidate.ScanLeaseUntil = leaseUntil
			candidate.ScanLeaseID = leaseID
			claimed = append(claimed, candidate)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return claimed, nil
}

func (store *StorageStore) collectUploads(rows *sql.Rows) ([]storageUploadRecord, error) {
	var uploads []storageUploadRecord
	for rows.Next() {
		upload, err := store.scanUpload(rows)
		if err != nil {
			return nil, err
		}
		uploads = append(uploads, upload)
	}
	return uploads, rows.Err()
}

func (store *StorageStore) ReleaseScanClaim(ctx context.Context, id, leaseID string) error {
	_, err := store.db.ExecContext(ctx, `UPDATE storage_uploads
		SET status='pending_scan',scan_lease_until=0,scan_lease_id=''
		WHERE id=? AND status='scanning' AND scan_lease_id=?`, id, leaseID)
	return err
}

func (store *StorageStore) RenewScanLease(ctx context.Context, id, leaseID string,
	now, leaseUntil int64) error {
	if id == "" || leaseID == "" || leaseUntil <= now {
		return errors.New("invalid storage scan lease renewal")
	}
	result, err := store.db.ExecContext(ctx, `UPDATE storage_uploads SET scan_lease_until=?
		WHERE id=? AND status='scanning' AND scan_lease_id=? AND scan_lease_until>?`,
		leaseUntil, id, leaseID, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrConflict
	}
	return nil
}

func (store *StorageStore) CompleteScan(ctx context.Context, id, leaseID string, now int64,
	internalStatus, finalPath, sha256Value, scanDetail string, event storageOutboxRecord) error {
	if id == "" || leaseID == "" {
		return errors.New("invalid storage scan lease owner")
	}
	if internalStatus != StorageUploadStatusClean && internalStatus != StorageUploadStatusBlocked &&
		internalStatus != StorageUploadStatusScannerError {
		return errors.New("invalid final storage scan status")
	}
	persistentPath, absolutePath, err := store.persistentUploadPath(id, finalPath)
	if err != nil {
		return err
	}
	switch internalStatus {
	case StorageUploadStatusClean:
		if persistentPath != storageUploadPathKey("objects", id, ".blob") {
			return errors.New("clean storage path must use its generated object key")
		}
	case StorageUploadStatusBlocked:
		if persistentPath != "" {
			return errors.New("blocked storage upload must not retain a file path")
		}
	case StorageUploadStatusScannerError:
		if persistentPath == "" {
			return errors.New("scanner-error storage upload must retain a generated path")
		}
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE storage_uploads
		SET status=?,path=?,sha256=?,scan_detail=?,scan_lease_until=0,scan_lease_id=''
		WHERE id=? AND status='scanning' AND scan_lease_id=? AND scan_lease_until>?`, internalStatus,
		persistentPath, sha256Value, scanDetail, id, leaseID, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		stored, loadErr := store.scanUpload(tx.QueryRowContext(ctx,
			`SELECT `+storageUploadColumns+` FROM storage_uploads WHERE id=?`, id))
		if loadErr != nil || stored.Status != internalStatus || stored.Path != absolutePath ||
			stored.SHA256 != sha256Value || stored.ScanDetail != scanDetail {
			if errors.Is(loadErr, sql.ErrNoRows) {
				return ErrNotFound
			}
			if loadErr != nil {
				return loadErr
			}
			return ErrConflict
		}
	}
	if err := enqueueStorageOutboxTx(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *StorageStore) EnqueueOutbox(ctx context.Context, event storageOutboxRecord) error {
	event, err := normalizeStorageOutboxRecord(event)
	if err != nil {
		return err
	}
	_, err = store.db.ExecContext(ctx, `INSERT INTO storage_outbox
		(event_key,method,path,body,attempts,next_attempt_at,created_at,last_error,version,claim_token,claim_until,replay_blocking)
		VALUES(?,?,?,?,0,?,?,?,1,'',0,0)
		ON CONFLICT(event_key) DO UPDATE SET method=excluded.method,path=excluded.path,body=excluded.body,
		next_attempt_at=MIN(storage_outbox.next_attempt_at,excluded.next_attempt_at),
		version=storage_outbox.version+1`,
		event.EventKey, event.Method, event.Path, event.Body, event.NextAttemptAt,
		event.CreatedAt, event.LastError)
	return err
}

func enqueueStorageOutboxTx(ctx context.Context, tx *sql.Tx, event storageOutboxRecord) error {
	event, err := normalizeStorageOutboxRecord(event)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO storage_outbox
		(event_key,method,path,body,attempts,next_attempt_at,created_at,last_error,version,claim_token,claim_until,replay_blocking)
		VALUES(?,?,?,?,0,?,?,?,1,'',0,0)
		ON CONFLICT(event_key) DO UPDATE SET method=excluded.method,path=excluded.path,body=excluded.body,
		next_attempt_at=MIN(storage_outbox.next_attempt_at,excluded.next_attempt_at),
		version=storage_outbox.version+1`,
		event.EventKey, event.Method, event.Path, event.Body, event.NextAttemptAt,
		event.CreatedAt, event.LastError)
	return err
}

func normalizeStorageOutboxRecord(event storageOutboxRecord) (storageOutboxRecord, error) {
	if event.EventKey == "" || event.Method == "" || event.Path == "" || event.NextAttemptAt <= 0 {
		return storageOutboxRecord{}, errors.New("invalid storage outbox event")
	}
	if event.CreatedAt <= 0 {
		event.CreatedAt = time.Now().Unix()
	}
	if len(event.LastError) > 512 {
		event.LastError = event.LastError[:512]
	}
	return event, nil
}

func (store *StorageStore) DueOutbox(ctx context.Context, now int64, limit int) ([]storageOutboxRecord, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT id,event_key,method,path,body,attempts,next_attempt_at,
		created_at,last_error,version,claim_token,claim_until,replay_blocking
		FROM storage_outbox WHERE next_attempt_at<=? ORDER BY next_attempt_at,id LIMIT ?`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectStorageOutbox(rows)
}

func (store *StorageStore) ClaimOutbox(ctx context.Context, now, leaseUntil int64,
	limit int) ([]storageOutboxRecord, error) {
	if leaseUntil <= now || limit <= 0 {
		return nil, errors.New("invalid storage outbox claim")
	}
	claimToken, err := randomToken(18)
	if err != nil {
		return nil, fmt.Errorf("generate storage outbox claim token: %w", err)
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE storage_outbox SET claim_token=?,claim_until=? WHERE id IN (
		SELECT id FROM storage_outbox
		WHERE next_attempt_at<=? AND (claim_token='' OR claim_until<=?)
		ORDER BY next_attempt_at,id LIMIT ?
	)`, claimToken, leaseUntil, now, now, limit); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,event_key,method,path,body,attempts,next_attempt_at,
		created_at,last_error,version,claim_token,claim_until,replay_blocking
		FROM storage_outbox WHERE claim_token=? ORDER BY next_attempt_at,id`, claimToken)
	if err != nil {
		return nil, err
	}
	events, err := collectStorageOutbox(rows)
	closeErr := rows.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}

func collectStorageOutbox(rows *sql.Rows) ([]storageOutboxRecord, error) {
	var events []storageOutboxRecord
	for rows.Next() {
		var event storageOutboxRecord
		if err := rows.Scan(&event.ID, &event.EventKey, &event.Method, &event.Path, &event.Body,
			&event.Attempts, &event.NextAttemptAt, &event.CreatedAt, &event.LastError,
			&event.Version, &event.ClaimToken, &event.ClaimUntil, &event.ReplayBlocking); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (store *StorageStore) AckClaimedOutbox(ctx context.Context, event storageOutboxRecord,
	now int64) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var eventKey, claimToken string
	var version int64
	err = tx.QueryRowContext(ctx, `SELECT event_key,version,claim_token FROM storage_outbox WHERE id=?`,
		event.ID).Scan(&eventKey, &version, &claimToken)
	if errors.Is(err, sql.ErrNoRows) {
		return tx.Commit()
	}
	if err != nil {
		return err
	}
	if claimToken == "" || claimToken != event.ClaimToken {
		return ErrConflict
	}
	if version != event.Version {
		_, err = tx.ExecContext(ctx, `UPDATE storage_outbox SET claim_token='',claim_until=0,
			next_attempt_at=MIN(next_attempt_at,?) WHERE id=? AND claim_token=?`,
			now, event.ID, event.ClaimToken)
		if err != nil {
			return err
		}
		return tx.Commit()
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM storage_outbox WHERE id=? AND claim_token=? AND version=?`,
		event.ID, event.ClaimToken, event.Version)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrConflict
	}
	if strings.HasPrefix(eventKey, "download-settle:") {
		reservationID := strings.TrimPrefix(eventKey, "download-settle:")
		if _, err := tx.ExecContext(ctx, `DELETE FROM storage_download_sessions
			WHERE reservation_id=? AND status='settle_pending'`, reservationID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (store *StorageStore) RetryClaimedOutbox(ctx context.Context, event storageOutboxRecord,
	now, nextAttemptAt int64, lastError string) error {
	if len(lastError) > 512 {
		lastError = lastError[:512]
	}
	result, err := store.db.ExecContext(ctx, `UPDATE storage_outbox SET attempts=attempts+1,
		next_attempt_at=?,last_error=?,claim_token='',claim_until=0
		WHERE id=? AND claim_token=? AND version=?`, nextAttemptAt, lastError,
		event.ID, event.ClaimToken, event.Version)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 1 {
		return nil
	}
	_, err = store.db.ExecContext(ctx, `UPDATE storage_outbox SET claim_token='',claim_until=0,
		next_attempt_at=MIN(next_attempt_at,?) WHERE id=? AND claim_token=?`,
		now, event.ID, event.ClaimToken)
	return err
}

func (store *StorageStore) DeadLetterClaimedOutbox(ctx context.Context, event storageOutboxRecord,
	failedAt int64, status int, lastError string) error {
	if len(lastError) > 512 {
		lastError = lastError[:512]
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var currentVersion int64
	var currentClaim string
	if err := tx.QueryRowContext(ctx, `SELECT version,claim_token FROM storage_outbox WHERE id=?`,
		event.ID).Scan(&currentVersion, &currentClaim); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return tx.Commit()
		}
		return err
	}
	if currentClaim != event.ClaimToken || currentClaim == "" {
		return ErrConflict
	}
	if currentVersion != event.Version {
		if _, err := tx.ExecContext(ctx, `UPDATE storage_outbox SET claim_token='',claim_until=0,
			next_attempt_at=MIN(next_attempt_at,?) WHERE id=? AND claim_token=?`,
			failedAt, event.ID, event.ClaimToken); err != nil {
			return err
		}
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO storage_outbox_dead_letter
		(original_id,event_key,method,path,body,attempts,created_at,failed_at,last_status,last_error,version)
		SELECT id,event_key,method,path,body,attempts+1,created_at,?,?,?,version
		FROM storage_outbox WHERE id=? AND claim_token=? AND version=?
		ON CONFLICT(event_key) DO UPDATE SET original_id=excluded.original_id,method=excluded.method,
		path=excluded.path,body=excluded.body,attempts=excluded.attempts,created_at=excluded.created_at,
		failed_at=excluded.failed_at,last_status=excluded.last_status,last_error=excluded.last_error,
		version=excluded.version`, failedAt, status, lastError, event.ID, event.ClaimToken, event.Version); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM storage_outbox WHERE id=? AND claim_token=? AND version=?`,
		event.ID, event.ClaimToken, event.Version)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrConflict
	}
	return tx.Commit()
}

func (store *StorageStore) ResetOutboxClaims(ctx context.Context, now int64) error {
	_, err := store.db.ExecContext(ctx, `UPDATE storage_outbox SET claim_token='',claim_until=0,
		next_attempt_at=MIN(next_attempt_at,?) WHERE claim_token<>'' OR claim_until<>0`, now)
	return err
}

func (store *StorageStore) ReplayDeadLetters(ctx context.Context, now int64, limit int) (int, error) {
	if limit <= 0 {
		limit = 1000
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,event_key,method,path,body,version
		FROM storage_outbox_dead_letter ORDER BY failed_at,id LIMIT ?`, limit)
	if err != nil {
		return 0, err
	}
	type replayRecord struct {
		id      int64
		key     string
		method  string
		path    string
		body    []byte
		version int64
	}
	var records []replayRecord
	for rows.Next() {
		var record replayRecord
		if err := rows.Scan(&record.id, &record.key, &record.method, &record.path,
			&record.body, &record.version); err != nil {
			_ = rows.Close()
			return 0, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	for _, record := range records {
		if _, err := tx.ExecContext(ctx, `INSERT INTO storage_outbox
			(event_key,method,path,body,attempts,next_attempt_at,created_at,last_error,version,claim_token,claim_until,replay_blocking)
			VALUES(?,?,?,?,0,?,?,'replayed from dead letter',?,'',0,1)
			ON CONFLICT(event_key) DO UPDATE SET method=excluded.method,path=excluded.path,body=excluded.body,
			attempts=0,next_attempt_at=excluded.next_attempt_at,created_at=excluded.created_at,
			last_error=excluded.last_error,version=MAX(storage_outbox.version,excluded.version)+1,
			claim_token='',claim_until=0,replay_blocking=1`, record.key, record.method, record.path, record.body,
			now, now, record.version+1); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM storage_outbox_dead_letter WHERE id=?`, record.id); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(records), nil
}

func (store *StorageStore) ExpiredUploads(ctx context.Context, now int64, limit int) ([]storageUploadRecord, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT `+storageUploadColumns+`
		FROM storage_uploads u WHERE expires_at<=?
		AND NOT EXISTS(SELECT 1 FROM storage_download_sessions d WHERE d.upload_id=u.id
			AND d.status IN ('begin_pending','streaming','settle_pending'))
		ORDER BY expires_at,id LIMIT ?`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return store.collectUploads(rows)
}

func (store *StorageStore) DeleteUpload(ctx context.Context, id string) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var activeDownloads int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM storage_download_sessions
		WHERE upload_id=? AND status IN ('begin_pending','streaming','settle_pending')`, id).
		Scan(&activeDownloads); err != nil {
		return err
	}
	if activeDownloads > 0 {
		return ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM storage_uploads WHERE id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM storage_outbox WHERE event_key=?`, "upload-complete:"+id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM storage_outbox_dead_letter WHERE event_key=?`,
		"upload-complete:"+id); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *StorageStore) CleanUpload(ctx context.Context, id string, now int64) (storageUploadRecord, error) {
	upload, err := store.scanUpload(store.db.QueryRowContext(ctx, `SELECT `+storageUploadColumns+`
		FROM storage_uploads WHERE id=? AND status='clean' AND expires_at>?`, id, now))
	if errors.Is(err, sql.ErrNoRows) {
		return storageUploadRecord{}, ErrNotFound
	}
	return upload, err
}
