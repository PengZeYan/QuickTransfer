package app

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	modernsqlite "modernc.org/sqlite"
)

var (
	ErrNotFound        = errors.New("not found")
	ErrQuotaExceeded   = errors.New("quota exceeded")
	ErrDownloadLimit   = errors.New("download limit reached")
	ErrConflict        = errors.New("conflict")
	ErrUnauthorized    = errors.New("unauthorized")
	ErrRateLimited     = errors.New("rate limited")
	ErrTrafficExceeded = errors.New("traffic exceeded")
)

const (
	sqliteMaxOpenConnections      = 4
	sqliteBusyTimeoutMilliseconds = 5000
	sqliteSynchronousFull         = 2
	sqliteReadinessReserveBytes   = 1 << 20
	sqliteCanaryRollbackTimeout   = 2 * time.Second
)

type Store struct {
	db                      *sql.DB
	dbDir                   string
	diskFree                func(string) (uint64, error)
	redemptionProtectionKey []byte
}

func (store *Store) configureRedemptionProtection(key []byte) {
	clear(store.redemptionProtectionKey)
	store.redemptionProtectionKey = append(store.redemptionProtectionKey[:0], key...)
}

type verifiedSQLiteConnector struct {
	driver.Connector
}

func (connector verifiedSQLiteConnector) Connect(ctx context.Context) (driver.Conn, error) {
	connection, err := connector.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	if err := verifySQLiteConnection(ctx, connection); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return connection, nil
}

func verifySQLiteConnection(ctx context.Context, connection driver.Conn) error {
	execQuerier, ok := connection.(modernsqlite.ExecQuerierContext)
	if !ok {
		return errors.New("sqlite driver connection cannot verify PRAGMAs")
	}

	journalMode, err := sqlitePragmaString(ctx, execQuerier, "journal_mode")
	if err != nil {
		return fmt.Errorf("verify sqlite journal_mode: %w", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		return fmt.Errorf("verify sqlite journal_mode: got %q, want WAL", journalMode)
	}

	synchronous, err := sqlitePragmaInt(ctx, execQuerier, "synchronous")
	if err != nil {
		return fmt.Errorf("verify sqlite synchronous: %w", err)
	}
	if synchronous != sqliteSynchronousFull {
		return fmt.Errorf("verify sqlite synchronous: got %d, want FULL (%d)", synchronous, sqliteSynchronousFull)
	}

	foreignKeys, err := sqlitePragmaInt(ctx, execQuerier, "foreign_keys")
	if err != nil {
		return fmt.Errorf("verify sqlite foreign_keys: %w", err)
	}
	if foreignKeys != 1 {
		return fmt.Errorf("verify sqlite foreign_keys: got %d, want ON", foreignKeys)
	}

	busyTimeout, err := sqlitePragmaInt(ctx, execQuerier, "busy_timeout")
	if err != nil {
		return fmt.Errorf("verify sqlite busy_timeout: %w", err)
	}
	if busyTimeout != sqliteBusyTimeoutMilliseconds {
		return fmt.Errorf("verify sqlite busy_timeout: got %d, want %d", busyTimeout, sqliteBusyTimeoutMilliseconds)
	}
	return nil
}

func sqlitePragmaString(ctx context.Context, connection modernsqlite.ExecQuerierContext, name string) (string, error) {
	value, err := sqlitePragmaValue(ctx, connection, name)
	if err != nil {
		return "", err
	}
	switch typed := value.(type) {
	case string:
		return typed, nil
	case []byte:
		return string(typed), nil
	default:
		return fmt.Sprint(typed), nil
	}
}

func sqlitePragmaInt(ctx context.Context, connection modernsqlite.ExecQuerierContext, name string) (int, error) {
	value, err := sqlitePragmaValue(ctx, connection, name)
	if err != nil {
		return 0, err
	}
	switch typed := value.(type) {
	case int64:
		return int(typed), nil
	case string:
		return strconv.Atoi(typed)
	case []byte:
		return strconv.Atoi(string(typed))
	default:
		return 0, fmt.Errorf("unexpected %s value type %T", name, value)
	}
}

func sqlitePragmaValue(ctx context.Context, connection modernsqlite.ExecQuerierContext, name string) (driver.Value, error) {
	rows, err := connection.QueryContext(ctx, "PRAGMA "+name, nil)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if columns := rows.Columns(); len(columns) != 1 {
		return nil, fmt.Errorf("unexpected %s column count %d", name, len(columns))
	}
	values := make([]driver.Value, 1)
	if err := rows.Next(values); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s returned no value", name)
		}
		return nil, err
	}
	return values[0], nil
}

const uploadColumns = `id,transfer_id,upload_hash,original_name,content_type,length,offset,status,temp_path,object_path,sha256,scan_detail,submitter_name,created_at,completed_at,storage_released,storage_kind,storage_node_id,storage_key,storage_version`
const uploadColumnsJoined = `u.id,u.transfer_id,u.upload_hash,u.original_name,u.content_type,u.length,u.offset,u.status,u.temp_path,u.object_path,u.sha256,u.scan_detail,u.submitter_name,u.created_at,u.completed_at,u.storage_released,u.storage_kind,u.storage_node_id,u.storage_key,u.storage_version`

func OpenStore(dataDir string) (*Store, error) {
	dbDir := filepath.Join(dataDir, "db")
	dbPath := filepath.Join(dbDir, "quicktransfer.db")
	// DSN PRAGMAs run for every physical connection. The connector then reads
	// each value back before database/sql may add that connection to the pool.
	dsn := dbPath + "?_pragma=busy_timeout%3d5000&_pragma=journal_mode%3dWAL" +
		"&_pragma=synchronous%3dFULL&_pragma=foreign_keys%3dON"
	baseConnector, err := modernsqlite.NewConnector(dsn)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(verifiedSQLiteConnector{Connector: baseConnector})
	db.SetMaxOpenConns(sqliteMaxOpenConnections)
	db.SetMaxIdleConns(sqliteMaxOpenConnections)
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS transfers (
			id TEXT PRIMARY KEY,
			kind TEXT NOT NULL CHECK(kind IN ('send','collection')),
			title TEXT NOT NULL,
			share_token TEXT NOT NULL UNIQUE,
			manage_hash TEXT NOT NULL,
			pickup_code TEXT NOT NULL UNIQUE,
			access_hash TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'active',
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			max_downloads INTEGER NOT NULL DEFAULT 20,
			downloads INTEGER NOT NULL DEFAULT 0,
			total_bytes INTEGER NOT NULL DEFAULT 0,
			file_count INTEGER NOT NULL DEFAULT 0,
			download_limit_mode TEXT NOT NULL DEFAULT 'legacy_file',
			delete_on_exhaustion INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS uploads (
			id TEXT PRIMARY KEY,
			transfer_id TEXT NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
			upload_hash TEXT NOT NULL,
			original_name TEXT NOT NULL,
			content_type TEXT NOT NULL,
			length INTEGER NOT NULL,
			offset INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'uploading',
			temp_path TEXT NOT NULL,
			object_path TEXT NOT NULL DEFAULT '',
			sha256 TEXT NOT NULL DEFAULT '',
			scan_detail TEXT NOT NULL DEFAULT '',
			submitter_name TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			completed_at INTEGER NOT NULL DEFAULT 0,
			storage_released INTEGER NOT NULL DEFAULT 0,
			storage_kind TEXT NOT NULL DEFAULT 'local' CHECK(storage_kind IN ('local','node')),
			storage_node_id TEXT NOT NULL DEFAULT '',
			storage_key TEXT NOT NULL DEFAULT '',
			storage_version INTEGER NOT NULL DEFAULT 1 CHECK(storage_version>0)
		)`,
		"CREATE INDEX IF NOT EXISTS idx_uploads_transfer ON uploads(transfer_id)",
		"CREATE INDEX IF NOT EXISTS idx_uploads_status ON uploads(status, created_at)",
		"CREATE INDEX IF NOT EXISTS idx_transfers_expiry ON transfers(status, expires_at)",
		`CREATE TABLE IF NOT EXISTS qt_sqlite_readiness_canary (
			id INTEGER PRIMARY KEY CHECK(id=1),
			probe INTEGER NOT NULL
		)`,
		"INSERT OR IGNORE INTO qt_sqlite_readiness_canary(id,probe) VALUES(1,0)",
	} {
		if _, err := db.Exec(statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("database migration: %w", err)
		}
	}
	if err := migrateStore(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db, dbDir: dbDir, diskFree: availableDiskBytes}, nil
}

func (store *Store) Close() error {
	clear(store.redemptionProtectionKey)
	return store.db.Close()
}

func (store *Store) CreateTransfer(ctx context.Context, transfer Transfer) error {
	if transfer.DownloadLimitMode == "" {
		transfer.DownloadLimitMode = DownloadLimitModeLegacyFile
	}
	_, err := store.db.ExecContext(ctx, `INSERT INTO transfers
		(id,kind,title,share_token,manage_hash,pickup_code,access_hash,status,expires_at,created_at,max_downloads,
		 owner_type,owner_id,policy_max_file_bytes,policy_max_task_bytes,policy_max_files,
		 download_limit_mode,delete_on_exhaustion)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, transfer.ID, transfer.Kind, transfer.Title, transfer.ShareToken,
		transfer.ManageHash, transfer.PickupCode, transfer.AccessHash, transfer.Status, transfer.ExpiresAt,
		transfer.CreatedAt, transfer.MaxDownloads, transfer.OwnerType, transfer.OwnerID, transfer.PolicyMaxFileBytes,
		transfer.PolicyMaxTaskBytes, transfer.PolicyMaxFiles, transfer.DownloadLimitMode, transfer.DeleteOnExhaustion)
	return err
}

func (store *Store) transferBy(ctx context.Context, field, value string) (Transfer, error) {
	query := `SELECT id,kind,title,share_token,manage_hash,pickup_code,access_hash,status,
		expires_at,created_at,max_downloads,downloads,total_bytes,file_count,owner_type,owner_id,
		policy_max_file_bytes,policy_max_task_bytes,policy_max_files,
		download_limit_mode,delete_on_exhaustion FROM transfers WHERE ` + field + `=?`
	var transfer Transfer
	err := store.db.QueryRowContext(ctx, query, value).Scan(&transfer.ID, &transfer.Kind, &transfer.Title,
		&transfer.ShareToken, &transfer.ManageHash, &transfer.PickupCode, &transfer.AccessHash,
		&transfer.Status, &transfer.ExpiresAt, &transfer.CreatedAt, &transfer.MaxDownloads,
		&transfer.Downloads, &transfer.TotalBytes, &transfer.FileCount, &transfer.OwnerType, &transfer.OwnerID,
		&transfer.PolicyMaxFileBytes, &transfer.PolicyMaxTaskBytes, &transfer.PolicyMaxFiles,
		&transfer.DownloadLimitMode, &transfer.DeleteOnExhaustion)
	if errors.Is(err, sql.ErrNoRows) {
		return Transfer{}, ErrNotFound
	}
	transfer.RequiresCode = transfer.AccessHash != ""
	return transfer, err
}

func (store *Store) TransferByID(ctx context.Context, id string) (Transfer, error) {
	return store.transferBy(ctx, "id", id)
}
func (store *Store) TransferByShare(ctx context.Context, token string) (Transfer, error) {
	return store.transferBy(ctx, "share_token", token)
}
func (store *Store) TransferByPickup(ctx context.Context, code string) (Transfer, error) {
	return store.transferBy(ctx, "pickup_code", code)
}

func (store *Store) PublishTransfer(ctx context.Context, id, pendingCode, pickupCode string) error {
	result, err := store.db.ExecContext(ctx,
		`UPDATE transfers SET pickup_code=? WHERE id=? AND pickup_code=? AND status='active'`,
		pickupCode, id, pendingCode)
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

func (store *Store) CreateUpload(ctx context.Context, upload Upload, maxFiles int, maxBytes int64) error {
	var err error
	upload, err = normalizeUploadPlacement(upload)
	if err != nil {
		return err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var files int
	var bytes int64
	var status string
	var expiresAt int64
	if err := tx.QueryRowContext(ctx, `SELECT file_count,total_bytes,status,expires_at FROM transfers WHERE id=?`, upload.TransferID).Scan(&files, &bytes, &status, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if status != "active" || expiresAt <= time.Now().Unix() {
		return ErrConflict
	}
	if files+1 > maxFiles || bytes+upload.Length > maxBytes {
		return ErrQuotaExceeded
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO uploads
		(id,transfer_id,upload_hash,original_name,content_type,length,offset,status,temp_path,submitter_name,created_at,
		 storage_kind,storage_node_id,storage_key,storage_version)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, upload.ID, upload.TransferID, upload.UploadHash,
		upload.OriginalName, upload.ContentType, upload.Length, 0, "uploading", upload.TempPath,
		upload.SubmitterName, upload.CreatedAt, upload.StorageKind, upload.StorageNodeID, upload.StorageKey,
		upload.StorageVersion); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE transfers SET file_count=file_count+1,total_bytes=total_bytes+? WHERE id=?`, upload.Length, upload.TransferID); err != nil {
		return err
	}
	return tx.Commit()
}

func scanUpload(row interface{ Scan(...any) error }) (Upload, error) {
	var upload Upload
	err := row.Scan(&upload.ID, &upload.TransferID, &upload.UploadHash, &upload.OriginalName,
		&upload.ContentType, &upload.Length, &upload.Offset, &upload.Status, &upload.TempPath,
		&upload.ObjectPath, &upload.SHA256, &upload.ScanDetail, &upload.SubmitterName,
		&upload.CreatedAt, &upload.CompletedAt, &upload.StorageReleased, &upload.StorageKind,
		&upload.StorageNodeID, &upload.StorageKey, &upload.StorageVersion)
	return upload, err
}

func normalizeUploadPlacement(upload Upload) (Upload, error) {
	if upload.StorageKind == "" {
		upload.StorageKind = StorageKindLocal
	}
	if upload.StorageVersion == 0 {
		upload.StorageVersion = StoragePlacementVersionV1
	}
	if upload.StorageVersion < StoragePlacementVersionV1 {
		return Upload{}, ErrConflict
	}
	switch upload.StorageKind {
	case StorageKindLocal:
		if upload.StorageNodeID != "" || upload.StorageKey != "" {
			return Upload{}, ErrConflict
		}
	case StorageKindNode:
		if upload.StorageNodeID == "" || upload.StorageKey == "" || upload.TempPath != "" || upload.ObjectPath != "" {
			return Upload{}, ErrConflict
		}
	default:
		return Upload{}, ErrConflict
	}
	return upload, nil
}

func (store *Store) UploadByID(ctx context.Context, id string) (Upload, error) {
	upload, err := scanUpload(store.db.QueryRowContext(ctx, `SELECT `+uploadColumns+` FROM uploads WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Upload{}, ErrNotFound
	}
	return upload, err
}

func (store *Store) UpdateUploadOffset(ctx context.Context, id string, expected, next int64) error {
	result, err := store.db.ExecContext(ctx, `UPDATE uploads SET offset=? WHERE id=? AND offset=? AND status='uploading' AND storage_kind='local'`, next, id, expected)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return ErrConflict
	}
	return nil
}

func (store *Store) MarkUploaded(ctx context.Context, id, quarantinePath string) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE uploads SET status='uploaded',temp_path=?
		WHERE id=? AND status='uploading' AND offset=length AND storage_kind='local'`, quarantinePath, id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return ErrConflict
	}
	if err := settleUploadTrafficTx(ctx, tx, id, time.Now().Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) ClaimUploads(ctx context.Context, limit int) ([]Upload, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT `+uploadColumns+` FROM uploads WHERE status='uploaded' AND storage_kind='local' ORDER BY created_at LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	var candidates []Upload
	for rows.Next() {
		upload, scanErr := scanUpload(rows)
		if scanErr != nil {
			_ = rows.Close()
			return nil, scanErr
		}
		candidates = append(candidates, upload)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	var claimed []Upload
	for _, upload := range candidates {
		result, updateErr := store.db.ExecContext(ctx, `UPDATE uploads SET status='scanning' WHERE id=? AND status='uploaded' AND storage_kind='local'`, upload.ID)
		if updateErr != nil {
			return nil, updateErr
		}
		count, _ := result.RowsAffected()
		if count == 1 {
			upload.Status = "scanning"
			claimed = append(claimed, upload)
		}
	}
	return claimed, nil
}

func (store *Store) MarkReady(ctx context.Context, id, objectPath, sha256, detail string) error {
	_, err := store.db.ExecContext(ctx, `UPDATE uploads SET status='ready',object_path=?,sha256=?,scan_detail=?,completed_at=? WHERE id=? AND status='scanning' AND storage_kind='local'`, objectPath, sha256, detail, time.Now().Unix(), id)
	return err
}

func (store *Store) MarkBlocked(ctx context.Context, id, sha256, detail string) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE uploads SET status='blocked',sha256=?,scan_detail=?,temp_path='',completed_at=? WHERE id=? AND storage_kind='local'`,
		sha256, detail, time.Now().Unix(), id); err != nil {
		return err
	}
	if err := releaseUploadStorageTx(ctx, tx, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) MarkQuarantined(ctx context.Context, id, sha256, detail string) error {
	_, err := store.db.ExecContext(ctx, `UPDATE uploads SET status='quarantined',sha256=?,scan_detail=?,completed_at=? WHERE id=? AND storage_kind='local'`, sha256, detail, time.Now().Unix(), id)
	return err
}

func (store *Store) UploadsForTransfer(ctx context.Context, transferID string, readyOnly bool) ([]Upload, error) {
	query := `SELECT ` + uploadColumns + ` FROM uploads WHERE transfer_id=?`
	if readyOnly {
		query += ` AND status='ready'`
	}
	query += ` ORDER BY created_at,id`
	rows, err := store.db.QueryContext(ctx, query, transferID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var uploads []Upload
	for rows.Next() {
		upload, scanErr := scanUpload(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		uploads = append(uploads, upload)
	}
	return uploads, rows.Err()
}

func (store *Store) ReadyUploadForTransfer(ctx context.Context, transferID, uploadID string) (Upload, error) {
	upload, err := scanUpload(store.db.QueryRowContext(ctx, `SELECT `+uploadColumns+` FROM uploads WHERE id=? AND transfer_id=? AND status='ready'`, uploadID, transferID))
	if errors.Is(err, sql.ErrNoRows) {
		return Upload{}, ErrNotFound
	}
	return upload, err
}

func (store *Store) ReadyUploadForDownload(ctx context.Context, uploadID string) (Upload, Transfer, error) {
	upload, err := store.UploadByID(ctx, uploadID)
	if err != nil || upload.Status != "ready" {
		return Upload{}, Transfer{}, ErrNotFound
	}
	transfer, err := store.TransferByID(ctx, upload.TransferID)
	if err != nil || (transfer.Status != TransferStatusActive && transfer.Status != TransferStatusExhausted) ||
		transfer.ExpiresAt <= time.Now().Unix() {
		return Upload{}, Transfer{}, ErrNotFound
	}
	return upload, transfer, nil
}

func (store *Store) IncrementDownload(ctx context.Context, transferID string) error {
	result, err := store.db.ExecContext(ctx, `UPDATE transfers SET downloads=downloads+1 WHERE id=? AND status='active' AND downloads<max_downloads`, transferID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return ErrQuotaExceeded
	}
	return nil
}

func (store *Store) RevokeTransfer(ctx context.Context, id string) error {
	_, err := store.db.ExecContext(ctx, `UPDATE transfers SET status='revoked' WHERE id=? AND status='active'`, id)
	return err
}

func (store *Store) MaintenanceCandidates(ctx context.Context, incompleteBefore, now int64) ([]Upload, error) {
	_, _ = store.db.ExecContext(ctx, `UPDATE transfers SET status='expired' WHERE status='active' AND expires_at<=?`, now)
	rows, err := store.db.QueryContext(ctx, `SELECT `+uploadColumnsJoined+` FROM uploads u JOIN transfers t ON t.id=u.transfer_id
		WHERE (t.status IN ('expired','revoked') AND u.status!='deleted')
		OR (t.status='exhausted' AND t.delete_on_exhaustion=1 AND u.status!='deleted'
			AND NOT EXISTS(SELECT 1 FROM retrieval_sessions s WHERE s.transfer_id=t.id
				AND s.status IN ('provisional','active'))
			AND NOT EXISTS(SELECT 1 FROM download_reservations r WHERE r.transfer_id=t.id
				AND r.status='consuming'))
		OR (u.status='uploading' AND u.created_at<?)`, incompleteBefore)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var uploads []Upload
	for rows.Next() {
		upload, scanErr := scanUpload(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		uploads = append(uploads, upload)
	}
	return uploads, rows.Err()
}

func (store *Store) MarkDeleted(ctx context.Context, upload Upload) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := releaseUploadStorageTx(ctx, tx, upload.ID); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE uploads SET status='deleted',temp_path='',object_path='' WHERE id=?`, upload.ID); err != nil {
		return err
	}
	if upload.Status == "uploading" {
		if _, err := tx.ExecContext(ctx, `UPDATE transfers SET file_count=MAX(file_count-1,0),total_bytes=MAX(total_bytes-?,0) WHERE id=?`, upload.Length, upload.TransferID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (store *Store) CompletableUploads(ctx context.Context) ([]Upload, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT `+uploadColumns+` FROM uploads WHERE status='uploading' AND offset=length AND storage_kind='local' LIMIT 20`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var uploads []Upload
	for rows.Next() {
		upload, scanErr := scanUpload(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		uploads = append(uploads, upload)
	}
	return uploads, rows.Err()
}

func (store *Store) Stats(ctx context.Context) (map[string]any, error) {
	if err := store.ReadinessCheck(ctx); err != nil {
		return nil, err
	}
	stats := map[string]any{}
	queries := []struct {
		key   string
		query string
		args  []any
	}{
		{"activeTransfers", `SELECT COUNT(*) FROM transfers WHERE status='active' AND expires_at>?`, []any{time.Now().Unix()}},
		{"readyFiles", `SELECT COUNT(*) FROM uploads WHERE status='ready'`, nil},
		{"pendingScans", `SELECT COUNT(*) FROM uploads WHERE status IN ('uploaded','scanning')`, nil},
		{"storedBytes", `SELECT COALESCE(SUM(length),0) FROM uploads WHERE status='ready'`, nil},
	}
	for _, item := range queries {
		var value int64
		if err := store.db.QueryRowContext(ctx, item.query, item.args...).Scan(&value); err != nil {
			return nil, err
		}
		stats[item.key] = value
	}
	return stats, nil
}

// ReadinessCheck proves that the database volume has emergency headroom and
// that SQLite can acquire and use a write transaction. The canary update is
// always rolled back, so health polling never persists business or probe data.
func (store *Store) ReadinessCheck(ctx context.Context) error {
	if store.db == nil {
		return errors.New("sqlite readiness: database is not open")
	}
	if store.dbDir == "" {
		return errors.New("sqlite readiness: database directory is unavailable")
	}
	diskFree := store.diskFree
	if diskFree == nil {
		diskFree = availableDiskBytes
	}
	freeBytes, err := diskFree(store.dbDir)
	if err != nil {
		return fmt.Errorf("sqlite readiness: inspect database volume: %w", err)
	}
	if freeBytes < sqliteReadinessReserveBytes {
		return fmt.Errorf("sqlite readiness: database volume has %d free bytes, need at least %d",
			freeBytes, sqliteReadinessReserveBytes)
	}

	connection, err := store.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("sqlite readiness: acquire connection: %w", err)
	}
	defer connection.Close()
	if _, err := connection.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("sqlite readiness: begin write canary: %w", err)
	}

	rollback := func() error {
		rollbackContext, cancel := context.WithTimeout(context.Background(), sqliteCanaryRollbackTimeout)
		defer cancel()
		_, rollbackErr := connection.ExecContext(rollbackContext, "ROLLBACK")
		return rollbackErr
	}
	needsRollback := true
	defer func() {
		if needsRollback {
			_ = rollback()
		}
	}()

	result, err := connection.ExecContext(ctx,
		"UPDATE qt_sqlite_readiness_canary SET probe=probe+1 WHERE id=1")
	if err != nil {
		return fmt.Errorf("sqlite readiness: execute write canary: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite readiness: inspect write canary: %w", err)
	}
	if rowsAffected != 1 {
		return fmt.Errorf("sqlite readiness: write canary affected %d rows", rowsAffected)
	}
	if err := rollback(); err != nil {
		return fmt.Errorf("sqlite readiness: rollback write canary: %w", err)
	}
	needsRollback = false
	return nil
}

func (store *Store) IntegrityCheck(ctx context.Context) error {
	var result string
	if err := store.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return fmt.Errorf("sqlite quick_check: %s", result)
	}
	return nil
}
