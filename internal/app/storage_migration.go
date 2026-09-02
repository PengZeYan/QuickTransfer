package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// StorageMigrationOptions describes an offline migration from the monolithic
// control-plane object store into one storage node. The control database and
// storage database must already exist; Apply=false never creates or changes
// either database or any object file. CopyOnly disables hard-link reuse for
// local placements and requires source and destination to have different file
// identities.
type StorageMigrationOptions struct {
	ControlDataDir   string
	SourceObjectsDir string
	StorageDataDir   string
	NodeID           string
	Apply            bool
	CopyOnly         bool

	linkFile func(string, string) error
}

// StorageMigrationReport contains non-sensitive migration totals. Candidate
// and Bytes include ready rows already migrated to the requested node. Reused
// counts candidates whose destination object was already usable. Imported
// counts control rows switched to explicit node placement during this run.
type StorageMigrationReport struct {
	Candidate         int
	Imported          int
	Reused            int
	Bytes             int64
	Skipped           int
	Quarantined       int
	Blocked           int
	Deleted           int
	ControlQuickCheck bool
	StorageQuickCheck bool
}

type storageMigrationConfig struct {
	controlDBPath string
	storageDBPath string
	sourceRoot    storageMigrationDirectory
	targetRoot    storageMigrationDirectory
	storagePaths  *storageDataPaths
	nodeID        string
	apply         bool
	copyOnly      bool
	linkFile      func(string, string) error
}

type storageMigrationDirectory struct {
	absolute string
	resolved string
}

type storageMigrationUpload struct {
	id              string
	transferID      string
	uploadTokenHash string
	originalName    string
	contentType     string
	length          int64
	offset          int64
	status          string
	tempPath        string
	objectPath      string
	sha256          string
	scanDetail      string
	expiresAt       int64
	storageKind     string
	storageNodeID   string
	storageKey      string
	storageVersion  int64
}

type storageMigrationCandidate struct {
	upload         storageMigrationUpload
	sourcePath     string
	targetPath     string
	nodeID         string
	alreadyPlaced  bool
	targetReusable bool
	expected       storageUploadRecord
}

// RunStorageMigration audits or applies an offline storage migration. It first
// validates every ready source object before performing any apply operation.
// Each applied object is made ready on the storage node before the control row
// is switched to explicit node placement.
func RunStorageMigration(ctx context.Context, options StorageMigrationOptions) (StorageMigrationReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	config, err := validateStorageMigrationOptions(options)
	if err != nil {
		return StorageMigrationReport{}, err
	}

	control, storage, err := openStorageMigrationStores(ctx, config, true)
	if err != nil {
		return StorageMigrationReport{}, err
	}
	report, candidates, auditErr := auditStorageMigration(ctx, control, storage, config)
	if auditErr != nil || !config.apply {
		if auditErr == nil {
			for _, candidate := range candidates {
				if candidate.targetReusable {
					report.Reused++
				}
			}
		}
		report, auditErr = finishStorageMigration(ctx, control, storage, report, auditErr)
		closeErr := closeStorageMigrationStores(control, storage)
		return report, errors.Join(auditErr, closeErr)
	}
	if err := closeStorageMigrationStores(control, storage); err != nil {
		return report, fmt.Errorf("close read-only migration databases: %w", err)
	}

	control, storage, err = openStorageMigrationStores(ctx, config, false)
	if err != nil {
		return report, err
	}
	defer closeStorageMigrationStores(control, storage)

	// Re-audit using the writable connections so a changed stop-copy or target
	// cannot invalidate the read-only preflight before the first write.
	report, candidates, err = auditStorageMigration(ctx, control, storage, config)
	if err == nil {
		if err = migrateStorageUploadPaths(ctx, storage.db, config.storagePaths); err != nil {
			err = fmt.Errorf("migrate storage database paths: %w", err)
		}
	}
	if err == nil {
		for _, candidate := range candidates {
			if candidate.alreadyPlaced {
				report.Reused++
				continue
			}
			reused, readyErr := ensureStorageMigrationObject(ctx, candidate, config.linkFile, config.copyOnly)
			if readyErr != nil {
				err = fmt.Errorf("prepare storage object %s: %w", candidate.upload.id, readyErr)
				break
			}
			if reused {
				report.Reused++
			}
			if _, recordErr := ensureStorageMigrationRecord(ctx, storage, candidate.expected); recordErr != nil {
				err = fmt.Errorf("import storage record %s: %w", candidate.upload.id, recordErr)
				break
			}
			changed, switchErr := switchStorageMigrationControl(ctx, control, candidate)
			if switchErr != nil {
				err = fmt.Errorf("switch control record %s: %w", candidate.upload.id, switchErr)
				break
			}
			if changed {
				report.Imported++
			}
		}
	}
	return finishStorageMigration(ctx, control, storage, report, err)
}

func validateStorageMigrationOptions(options StorageMigrationOptions) (storageMigrationConfig, error) {
	controlDataDir := strings.TrimSpace(options.ControlDataDir)
	sourceObjectsDir := strings.TrimSpace(options.SourceObjectsDir)
	storageDataDir := strings.TrimSpace(options.StorageDataDir)
	nodeID := strings.TrimSpace(options.NodeID)
	for name, value := range map[string]string{
		"control data directory":   controlDataDir,
		"source objects directory": sourceObjectsDir,
		"storage data directory":   storageDataDir,
		"node id":                  nodeID,
	} {
		if value == "" {
			return storageMigrationConfig{}, fmt.Errorf("%s must not be empty", name)
		}
	}
	if !validStorageNodeID(nodeID) {
		return storageMigrationConfig{}, errors.New("invalid storage node id")
	}

	controlRoot, err := filepath.Abs(filepath.Clean(controlDataDir))
	if err != nil {
		return storageMigrationConfig{}, fmt.Errorf("resolve control data directory: %w", err)
	}
	storageRoot, err := filepath.Abs(filepath.Clean(storageDataDir))
	if err != nil {
		return storageMigrationConfig{}, fmt.Errorf("resolve storage data directory: %w", err)
	}
	sourceRoot, err := inspectStorageMigrationDirectory("source objects directory", sourceObjectsDir)
	if err != nil {
		return storageMigrationConfig{}, err
	}
	targetRoot, err := inspectStorageMigrationDirectory("storage objects directory", filepath.Join(storageRoot, "objects"))
	if err != nil {
		return storageMigrationConfig{}, err
	}
	storagePaths, err := newStorageDataPaths(storageRoot)
	if err != nil {
		return storageMigrationConfig{}, fmt.Errorf("initialize storage path resolver: %w", err)
	}
	controlDBPath := filepath.Join(controlRoot, "db", "quicktransfer.db")
	storageDBPath := filepath.Join(storageRoot, "db", "storage-node.db")
	if err := inspectStorageMigrationDatabase("control database", controlDBPath); err != nil {
		return storageMigrationConfig{}, err
	}
	if err := inspectStorageMigrationDatabase("storage database", storageDBPath); err != nil {
		return storageMigrationConfig{}, err
	}
	linkFile := options.linkFile
	if linkFile == nil {
		linkFile = os.Link
	}
	return storageMigrationConfig{
		controlDBPath: controlDBPath,
		storageDBPath: storageDBPath,
		sourceRoot:    sourceRoot,
		targetRoot:    targetRoot,
		storagePaths:  storagePaths,
		nodeID:        nodeID,
		apply:         options.Apply,
		copyOnly:      options.CopyOnly,
		linkFile:      linkFile,
	}, nil
}

func inspectStorageMigrationDirectory(name, path string) (storageMigrationDirectory, error) {
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return storageMigrationDirectory{}, fmt.Errorf("resolve %s: %w", name, err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return storageMigrationDirectory{}, fmt.Errorf("inspect %s: %w", name, err)
	}
	if !info.IsDir() {
		return storageMigrationDirectory{}, fmt.Errorf("%s is not a directory", name)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return storageMigrationDirectory{}, fmt.Errorf("resolve %s links: %w", name, err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return storageMigrationDirectory{}, fmt.Errorf("resolve %s absolute path: %w", name, err)
	}
	return storageMigrationDirectory{absolute: absolute, resolved: resolved}, nil
}

func inspectStorageMigrationDatabase(name, path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", name)
	}
	for _, suffix := range []string{"-wal", "-journal"} {
		journal, statErr := os.Stat(path + suffix)
		if statErr == nil && journal.Size() > 0 {
			return fmt.Errorf("%s has an uncheckpointed SQLite journal; checkpoint the stopped copy first", name)
		}
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("inspect %s journal: %w", name, statErr)
		}
	}
	return nil
}

func openStorageMigrationStores(ctx context.Context, config storageMigrationConfig, readOnly bool) (*Store, *StorageStore, error) {
	controlDB, err := openStorageMigrationDatabase(ctx, config.controlDBPath, readOnly)
	if err != nil {
		return nil, nil, fmt.Errorf("open control database: %w", err)
	}
	storageDB, err := openStorageMigrationDatabase(ctx, config.storageDBPath, readOnly)
	if err != nil {
		_ = controlDB.Close()
		return nil, nil, fmt.Errorf("open storage database: %w", err)
	}
	return &Store{db: controlDB}, &StorageStore{db: storageDB, paths: config.storagePaths}, nil
}

func openStorageMigrationDatabase(ctx context.Context, path string, readOnly bool) (*sql.DB, error) {
	slashPath := filepath.ToSlash(path)
	if volume := filepath.VolumeName(path); volume != "" && !strings.HasPrefix(slashPath, "/") {
		slashPath = "/" + slashPath
	}
	uri := &url.URL{Scheme: "file", Path: slashPath}
	query := uri.Query()
	if readOnly {
		query.Set("mode", "ro")
		query.Set("immutable", "1")
		query.Add("_pragma", "query_only=ON")
	} else {
		query.Set("mode", "rw")
		query.Add("_pragma", "foreign_keys=ON")
	}
	query.Add("_pragma", "busy_timeout=5000")
	uri.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func closeStorageMigrationStores(control *Store, storage *StorageStore) error {
	var errs []error
	if storage != nil && storage.db != nil {
		if err := storage.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close storage database: %w", err))
		}
	}
	if control != nil && control.db != nil {
		if err := control.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close control database: %w", err))
		}
	}
	return errors.Join(errs...)
}

func auditStorageMigration(ctx context.Context, control *Store, storage *StorageStore,
	config storageMigrationConfig) (StorageMigrationReport, []storageMigrationCandidate, error) {
	if err := auditStorageMigrationControlSchema(ctx, control); err != nil {
		return StorageMigrationReport{}, nil, err
	}
	report, err := auditStorageMigrationStatuses(ctx, control)
	if err != nil {
		return report, nil, err
	}
	rows, err := control.db.QueryContext(ctx, `SELECT u.id,u.transfer_id,u.upload_hash,u.original_name,
		u.content_type,u.length,u.offset,u.status,u.temp_path,u.object_path,u.sha256,u.scan_detail,t.expires_at,
		u.storage_kind,u.storage_node_id,u.storage_key,u.storage_version
		FROM uploads u LEFT JOIN transfers t ON t.id=u.transfer_id
		WHERE u.status='ready' ORDER BY u.created_at,u.id`)
	if err != nil {
		return report, nil, fmt.Errorf("query ready uploads: %w", err)
	}
	defer rows.Close()

	var candidates []storageMigrationCandidate
	var auditErrors []error
	for rows.Next() {
		upload, scanErr := scanStorageMigrationUpload(rows)
		if scanErr != nil {
			auditErrors = append(auditErrors, scanErr)
			continue
		}
		report.Candidate++
		if upload.length > 0 && report.Bytes <= int64(^uint64(0)>>1)-upload.length {
			report.Bytes += upload.length
		} else if upload.length < 0 {
			auditErrors = append(auditErrors, fmt.Errorf("upload %s has a negative length", upload.id))
			continue
		} else if upload.length > 0 {
			auditErrors = append(auditErrors, errors.New("candidate byte total overflows int64"))
			continue
		}
		candidate, candidateErr := auditStorageMigrationCandidate(ctx, storage, config, upload)
		if candidateErr != nil {
			auditErrors = append(auditErrors, candidateErr)
			continue
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		auditErrors = append(auditErrors, fmt.Errorf("iterate ready uploads: %w", err))
	}
	if len(auditErrors) > 0 {
		return report, nil, fmt.Errorf("storage migration audit failed: %w", errors.Join(auditErrors...))
	}
	return report, candidates, nil
}

func auditStorageMigrationControlSchema(ctx context.Context, control *Store) error {
	var version int
	if err := control.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("inspect control database schema version: %w", err)
	}
	if version < 4 {
		return fmt.Errorf("control database schema version %d is older than required placement schema v4", version)
	}
	rows, err := control.db.QueryContext(ctx, "PRAGMA table_info(uploads)")
	if err != nil {
		return fmt.Errorf("inspect uploads placement columns: %w", err)
	}
	defer rows.Close()
	required := []string{"storage_kind", "storage_node_id", "storage_key", "storage_version"}
	found := make(map[string]bool, len(required))
	for rows.Next() {
		var columnID, notNull, primaryKey int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&columnID, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			return fmt.Errorf("scan uploads placement columns: %w", err)
		}
		for _, requiredName := range required {
			if name == requiredName {
				found[name] = true
				break
			}
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate uploads placement columns: %w", err)
	}
	var missing []string
	for _, name := range required {
		if !found[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("control database is missing placement columns: %s", strings.Join(missing, ","))
	}
	return nil
}

func auditStorageMigrationStatuses(ctx context.Context, control *Store) (StorageMigrationReport, error) {
	rows, err := control.db.QueryContext(ctx, `SELECT status,COUNT(*) FROM uploads GROUP BY status ORDER BY status`)
	if err != nil {
		return StorageMigrationReport{}, fmt.Errorf("audit upload statuses: %w", err)
	}
	defer rows.Close()
	var report StorageMigrationReport
	var uploading, uploaded, scanning int
	var unsupported []string
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return report, err
		}
		switch status {
		case "ready":
		case "uploading":
			uploading = count
		case "uploaded":
			uploaded = count
		case "scanning":
			scanning = count
		case "quarantined":
			report.Quarantined = count
			report.Skipped += count
		case "blocked":
			report.Blocked = count
			report.Skipped += count
		case "deleted":
			report.Deleted = count
			report.Skipped += count
		default:
			unsupported = append(unsupported, fmt.Sprintf("%s=%d", status, count))
		}
	}
	if err := rows.Err(); err != nil {
		return report, err
	}
	if uploading+uploaded+scanning > 0 {
		return report, fmt.Errorf("refusing migration with unfinished uploads: uploading=%d uploaded=%d scanning=%d",
			uploading, uploaded, scanning)
	}
	if len(unsupported) > 0 {
		return report, fmt.Errorf("refusing migration with unsupported upload statuses: %s", strings.Join(unsupported, ","))
	}
	return report, nil
}

func scanStorageMigrationUpload(row interface{ Scan(...any) error }) (storageMigrationUpload, error) {
	var upload storageMigrationUpload
	var expiresAt sql.NullInt64
	err := row.Scan(&upload.id, &upload.transferID, &upload.uploadTokenHash, &upload.originalName,
		&upload.contentType, &upload.length, &upload.offset, &upload.status, &upload.tempPath,
		&upload.objectPath, &upload.sha256, &upload.scanDetail, &expiresAt, &upload.storageKind,
		&upload.storageNodeID, &upload.storageKey, &upload.storageVersion)
	if err != nil {
		return storageMigrationUpload{}, fmt.Errorf("scan ready upload metadata: %w", err)
	}
	if !expiresAt.Valid {
		return storageMigrationUpload{}, fmt.Errorf("upload %s has no transfer expiry", upload.id)
	}
	upload.expiresAt = expiresAt.Int64
	return upload, nil
}

func auditStorageMigrationCandidate(ctx context.Context, storage *StorageStore, config storageMigrationConfig,
	upload storageMigrationUpload) (storageMigrationCandidate, error) {
	if !validStorageObjectID(upload.id) {
		return storageMigrationCandidate{}, fmt.Errorf("upload %q has an invalid storage object id", upload.id)
	}
	if upload.offset != upload.length {
		return storageMigrationCandidate{}, fmt.Errorf("upload %s ready offset does not equal its length", upload.id)
	}
	if !validStorageMigrationSHA256(upload.sha256) {
		return storageMigrationCandidate{}, fmt.Errorf("upload %s has an invalid SHA256 value", upload.id)
	}
	targetPath := filepath.Join(config.targetRoot.absolute, upload.id+".blob")
	expected := storageUploadRecord{
		ID:              upload.id,
		UploadTokenHash: upload.uploadTokenHash,
		OriginalName:    upload.originalName,
		ContentType:     upload.contentType,
		Length:          upload.length,
		Offset:          upload.length,
		Status:          StorageUploadStatusClean,
		Path:            targetPath,
		SHA256:          upload.sha256,
		ScanDetail:      upload.scanDetail,
		ExpiresAt:       upload.expiresAt,
	}
	candidate := storageMigrationCandidate{
		upload: upload, targetPath: targetPath, nodeID: config.nodeID, expected: expected,
	}

	switch upload.storageKind {
	case StorageKindNode:
		if upload.storageNodeID != config.nodeID || upload.storageKey != upload.id ||
			upload.storageVersion != StoragePlacementVersionV1 || upload.tempPath != "" || upload.objectPath != "" {
			return storageMigrationCandidate{}, fmt.Errorf("upload %s has a conflicting node placement", upload.id)
		}
		candidate.alreadyPlaced = true
		candidate.targetReusable = true
		if err := verifyStorageMigrationObject(ctx, targetPath, upload.length, upload.sha256); err != nil {
			return storageMigrationCandidate{}, fmt.Errorf("upload %s placed object is invalid: %w", upload.id, err)
		}
		stored, found, err := loadStorageMigrationRecord(ctx, storage, upload.id)
		if err != nil {
			return storageMigrationCandidate{}, fmt.Errorf("load storage record %s: %w", upload.id, err)
		}
		if !found {
			return storageMigrationCandidate{}, fmt.Errorf("upload %s has node placement but no storage record", upload.id)
		}
		if mismatch := storageMigrationRecordMismatch(expected, stored); mismatch != "" {
			return storageMigrationCandidate{}, fmt.Errorf("upload %s storage record conflicts in %s", upload.id, mismatch)
		}
		return candidate, nil
	case StorageKindLocal:
		if upload.storageNodeID != "" || upload.storageKey != "" ||
			upload.storageVersion != StoragePlacementVersionV1 {
			return storageMigrationCandidate{}, fmt.Errorf("upload %s has an invalid local placement", upload.id)
		}
	default:
		return storageMigrationCandidate{}, fmt.Errorf("upload %s has unsupported storage kind %q", upload.id,
			upload.storageKind)
	}

	sourcePath, err := inspectStorageMigrationSourcePath(config.sourceRoot, upload.id, upload.objectPath)
	if err != nil {
		return storageMigrationCandidate{}, fmt.Errorf("upload %s source path is invalid: %w", upload.id, err)
	}
	if err := verifyStorageMigrationObject(ctx, sourcePath, upload.length, upload.sha256); err != nil {
		return storageMigrationCandidate{}, fmt.Errorf("upload %s source object is invalid: %w", upload.id, err)
	}
	candidate.sourcePath = sourcePath

	if exists, err := storageMigrationObjectExists(targetPath); err != nil {
		return storageMigrationCandidate{}, fmt.Errorf("inspect target object for upload %s: %w", upload.id, err)
	} else if exists {
		if err := verifyStorageMigrationObject(ctx, targetPath, upload.length, upload.sha256); err != nil {
			return storageMigrationCandidate{}, fmt.Errorf("upload %s target object conflicts: %w", upload.id, err)
		}
		if config.copyOnly {
			if err := requireIndependentStorageMigrationFiles(sourcePath, targetPath); err != nil {
				return storageMigrationCandidate{}, fmt.Errorf("upload %s copy-only preflight failed: %w", upload.id, err)
			}
		}
		candidate.targetReusable = true
	}
	stored, found, err := loadStorageMigrationRecord(ctx, storage, upload.id)
	if err != nil {
		return storageMigrationCandidate{}, fmt.Errorf("load storage record %s: %w", upload.id, err)
	}
	if found {
		if mismatch := storageMigrationRecordMismatch(expected, stored); mismatch != "" {
			return storageMigrationCandidate{}, fmt.Errorf("upload %s storage record conflicts in %s", upload.id, mismatch)
		}
	}
	return candidate, nil
}

func inspectStorageMigrationSourcePath(root storageMigrationDirectory, id, storedPath string) (string, error) {
	if storedPath == "" {
		return "", errors.New("object path is empty")
	}
	if storageMigrationHasParentTraversal(storedPath) {
		return "", errors.New("object path contains directory traversal")
	}
	cleaned := filepath.Clean(storedPath)
	if filepath.Base(cleaned) != id+".blob" {
		return "", errors.New("basename is not the expected id.blob")
	}
	var absolute string
	var err error
	if filepath.IsAbs(cleaned) {
		absolute, err = filepath.Abs(cleaned)
		if err != nil {
			return "", fmt.Errorf("resolve absolute object path: %w", err)
		}
		if !storageMigrationPathWithin(root.absolute, absolute) {
			return "", errors.New("object path is outside the explicit source objects directory")
		}
	} else {
		if filepath.VolumeName(cleaned) != "" || !filepath.IsLocal(cleaned) {
			return "", errors.New("relative object path is not local")
		}
		// Legacy relative paths were persisted relative to the old process
		// working directory. The explicit source root replaces that ambient
		// dependency; only the already-validated id.blob basename is mapped.
		absolute = filepath.Join(root.absolute, id+".blob")
	}
	if !storageMigrationPathWithin(root.absolute, absolute) {
		return "", errors.New("object path is outside the explicit source objects directory")
	}
	if err := rejectStorageMigrationReparsePath(root.absolute, absolute); err != nil {
		return "", err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", fmt.Errorf("inspect source object: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("source object is not a regular file")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve source object links: %w", err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve source object absolute path: %w", err)
	}
	if !storageMigrationPathWithin(root.resolved, resolved) {
		return "", errors.New("source object resolves outside the explicit source objects directory")
	}
	return absolute, nil
}

func storageMigrationHasParentTraversal(path string) bool {
	for _, part := range strings.FieldsFunc(path, func(character rune) bool {
		return character == '/' || character == '\\'
	}) {
		if part == ".." {
			return true
		}
	}
	return false
}

func rejectStorageMigrationReparsePath(root, candidate string) error {
	relative, err := filepath.Rel(root, candidate)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return errors.New("object path is outside the explicit source objects directory")
	}
	current := root
	parts := []string{"."}
	if relative != "." {
		parts = append(parts, strings.Split(relative, string(os.PathSeparator))...)
	}
	for _, part := range parts {
		if part != "." {
			current = filepath.Join(current, part)
		}
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect source path component: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("source object path contains a symbolic link or reparse point")
		}
	}
	return nil
}

func storageMigrationPathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	if err != nil || relative == ".." {
		return false
	}
	return !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

func validStorageMigrationSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func storageMigrationObjectExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return true, errors.New("object is not a regular file")
	}
	return true, nil
}

func verifyStorageMigrationObject(ctx context.Context, path string, expectedSize int64, expectedSHA256 string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("object is not a regular file")
	}
	if info.Size() != expectedSize {
		return fmt.Errorf("object length %d does not match database length %d", info.Size(), expectedSize)
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return errors.New("object changed while it was opened")
	}
	hash := sha256.New()
	written, err := copyStorageMigrationStream(ctx, hash, file)
	if err != nil {
		return err
	}
	if written != expectedSize {
		return fmt.Errorf("hashed length %d does not match database length %d", written, expectedSize)
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(actual, expectedSHA256) {
		return errors.New("SHA256 does not match the database value")
	}
	return nil
}

func copyStorageMigrationStream(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, 1024*1024)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			written, writeErr := destination.Write(buffer[:read])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != read {
				return total, io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			return total, nil
		}
		if readErr != nil {
			return total, readErr
		}
	}
}

func loadStorageMigrationRecord(ctx context.Context, storage *StorageStore, id string) (storageUploadRecord, bool, error) {
	stored, err := storage.scanUpload(storage.db.QueryRowContext(ctx,
		`SELECT `+storageUploadColumns+` FROM storage_uploads WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return storageUploadRecord{}, false, nil
	}
	return stored, err == nil, err
}

func storageMigrationRecordMismatch(expected, actual storageUploadRecord) string {
	var fields []string
	if actual.ID != expected.ID {
		fields = append(fields, "id")
	}
	if actual.UploadTokenHash != expected.UploadTokenHash {
		fields = append(fields, "token_hash")
	}
	if actual.OriginalName != expected.OriginalName {
		fields = append(fields, "original_name")
	}
	if actual.ContentType != expected.ContentType {
		fields = append(fields, "content_type")
	}
	if actual.Length != expected.Length {
		fields = append(fields, "length")
	}
	if actual.Offset != expected.Offset {
		fields = append(fields, "offset")
	}
	if actual.Status != expected.Status {
		fields = append(fields, "status")
	}
	if actual.Path != expected.Path {
		fields = append(fields, "path")
	}
	if actual.SHA256 != expected.SHA256 {
		fields = append(fields, "sha256")
	}
	if actual.ScanDetail != expected.ScanDetail {
		fields = append(fields, "scan_detail")
	}
	if actual.ExpiresAt != expected.ExpiresAt {
		fields = append(fields, "expires_at")
	}
	if actual.ScanLeaseUntil != expected.ScanLeaseUntil {
		fields = append(fields, "scan_lease_until")
	}
	if actual.ScanLeaseID != expected.ScanLeaseID {
		fields = append(fields, "scan_lease_id")
	}
	return strings.Join(fields, ",")
}

func ensureStorageMigrationObject(ctx context.Context, candidate storageMigrationCandidate,
	linkFile func(string, string) error, copyOnly bool) (bool, error) {
	if err := verifyStorageMigrationObject(ctx, candidate.sourcePath, candidate.upload.length,
		candidate.upload.sha256); err != nil {
		return false, fmt.Errorf("source revalidation failed: %w", err)
	}
	if same, err := sameStorageMigrationFile(candidate.sourcePath, candidate.targetPath); err != nil {
		return false, err
	} else if same {
		if copyOnly {
			return false, errors.New("copy-only requires source and target to have different file identities")
		}
		return true, nil
	}
	if exists, err := storageMigrationObjectExists(candidate.targetPath); err != nil {
		return false, err
	} else if exists {
		if err := verifyStorageMigrationObject(ctx, candidate.targetPath, candidate.upload.length,
			candidate.upload.sha256); err != nil {
			return false, fmt.Errorf("refusing to overwrite an existing target: %w", err)
		}
		if copyOnly {
			if err := requireIndependentStorageMigrationFiles(candidate.sourcePath, candidate.targetPath); err != nil {
				return false, err
			}
		}
		return true, nil
	}

	if !copyOnly {
		if err := linkFile(candidate.sourcePath, candidate.targetPath); err == nil {
			if verifyErr := verifyStorageMigrationObject(ctx, candidate.targetPath, candidate.upload.length,
				candidate.upload.sha256); verifyErr != nil {
				_ = os.Remove(candidate.targetPath)
				return false, fmt.Errorf("hard-linked target verification failed: %w", verifyErr)
			}
			return false, nil
		}
	}
	if exists, err := storageMigrationObjectExists(candidate.targetPath); err != nil {
		return false, err
	} else if exists {
		if err := verifyStorageMigrationObject(ctx, candidate.targetPath, candidate.upload.length,
			candidate.upload.sha256); err != nil {
			return false, fmt.Errorf("refusing to overwrite an existing target: %w", err)
		}
		if copyOnly {
			if err := requireIndependentStorageMigrationFiles(candidate.sourcePath, candidate.targetPath); err != nil {
				return false, err
			}
		}
		return true, nil
	}
	return copyStorageMigrationObject(ctx, candidate, copyOnly)
}

func sameStorageMigrationFile(sourcePath, targetPath string) (bool, error) {
	if filepath.Clean(sourcePath) == filepath.Clean(targetPath) {
		return true, nil
	}
	sourceInfo, err := os.Stat(sourcePath)
	if err != nil {
		return false, err
	}
	targetInfo, err := os.Stat(targetPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return os.SameFile(sourceInfo, targetInfo), nil
}

func requireIndependentStorageMigrationFiles(sourcePath, targetPath string) error {
	same, err := sameStorageMigrationFile(sourcePath, targetPath)
	if err != nil {
		return fmt.Errorf("compare source and target file identities: %w", err)
	}
	if same {
		return errors.New("copy-only target shares the source file identity (hard link or same file)")
	}
	return nil
}

func copyStorageMigrationObject(ctx context.Context, candidate storageMigrationCandidate, copyOnly bool) (bool, error) {
	source, err := os.Open(candidate.sourcePath)
	if err != nil {
		return false, err
	}
	defer source.Close()
	temporary, err := os.CreateTemp(filepath.Dir(candidate.targetPath), "."+candidate.upload.id+".migration-*")
	if err != nil {
		return false, err
	}
	temporaryPath := temporary.Name()
	temporaryOpen := true
	defer func() {
		if temporaryOpen {
			_ = temporary.Close()
		}
		if temporaryPath != "" {
			_ = os.Remove(temporaryPath)
		}
	}()

	hash := sha256.New()
	written, err := copyStorageMigrationStream(ctx, io.MultiWriter(temporary, hash), source)
	if err != nil {
		return false, err
	}
	if written != candidate.upload.length || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), candidate.upload.sha256) {
		return false, errors.New("copied object does not match the database length and SHA256")
	}
	if err := temporary.Sync(); err != nil {
		return false, fmt.Errorf("fsync copied object: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	temporaryOpen = false
	if err := verifyStorageMigrationObject(ctx, temporaryPath, candidate.upload.length, candidate.upload.sha256); err != nil {
		return false, fmt.Errorf("temporary object verification failed: %w", err)
	}

	if exists, err := storageMigrationObjectExists(candidate.targetPath); err != nil {
		return false, err
	} else if exists {
		if err := verifyStorageMigrationObject(ctx, candidate.targetPath, candidate.upload.length,
			candidate.upload.sha256); err != nil {
			return false, fmt.Errorf("refusing to overwrite an existing target: %w", err)
		}
		if copyOnly {
			if err := requireIndependentStorageMigrationFiles(candidate.sourcePath, candidate.targetPath); err != nil {
				return false, err
			}
		}
		return true, nil
	}
	if err := os.Rename(temporaryPath, candidate.targetPath); err != nil {
		if exists, inspectErr := storageMigrationObjectExists(candidate.targetPath); inspectErr == nil && exists {
			if verifyErr := verifyStorageMigrationObject(ctx, candidate.targetPath, candidate.upload.length,
				candidate.upload.sha256); verifyErr == nil {
				if copyOnly {
					if independentErr := requireIndependentStorageMigrationFiles(candidate.sourcePath,
						candidate.targetPath); independentErr != nil {
						return false, independentErr
					}
				}
				return true, nil
			}
		}
		return false, fmt.Errorf("atomically publish copied object: %w", err)
	}
	temporaryPath = ""
	if err := verifyStorageMigrationObject(ctx, candidate.targetPath, candidate.upload.length,
		candidate.upload.sha256); err != nil {
		return false, fmt.Errorf("published object verification failed: %w", err)
	}
	if err := requireIndependentStorageMigrationFiles(candidate.sourcePath, candidate.targetPath); err != nil {
		_ = os.Remove(candidate.targetPath)
		return false, fmt.Errorf("published object independence verification failed: %w", err)
	}
	return false, nil
}

func ensureStorageMigrationRecord(ctx context.Context, storage *StorageStore,
	expected storageUploadRecord) (bool, error) {
	persistentPath, absolutePath, err := storage.persistentUploadPath(expected.ID, expected.Path)
	if err != nil {
		return false, err
	}
	if persistentPath != storageUploadPathKey("objects", expected.ID, ".blob") {
		return false, errors.New("migrated storage record must use its generated object key")
	}
	expected.Path = absolutePath
	tx, err := storage.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO storage_uploads
		(id,token_hash,original_name,content_type,length,offset,status,path,sha256,scan_detail,expires_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`, expected.ID, expected.UploadTokenHash,
		expected.OriginalName, expected.ContentType, expected.Length, expected.Offset, expected.Status,
		persistentPath, expected.SHA256, expected.ScanDetail, expected.ExpiresAt)
	if err != nil {
		return false, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	stored, err := storage.scanUpload(tx.QueryRowContext(ctx,
		`SELECT `+storageUploadColumns+` FROM storage_uploads WHERE id=?`, expected.ID))
	if err != nil {
		return false, err
	}
	if mismatch := storageMigrationRecordMismatch(expected, stored); mismatch != "" {
		return false, fmt.Errorf("existing storage record conflicts in %s", mismatch)
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return rowsAffected == 1, nil
}

func switchStorageMigrationControl(ctx context.Context, control *Store,
	candidate storageMigrationCandidate) (bool, error) {
	tx, err := control.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	upload, err := scanStorageMigrationUpload(tx.QueryRowContext(ctx, `SELECT u.id,u.transfer_id,u.upload_hash,
		u.original_name,u.content_type,u.length,u.offset,u.status,u.temp_path,u.object_path,u.sha256,
		u.scan_detail,t.expires_at,u.storage_kind,u.storage_node_id,u.storage_key,u.storage_version
		FROM uploads u LEFT JOIN transfers t ON t.id=u.transfer_id WHERE u.id=?`,
		candidate.upload.id))
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, err
	}
	if upload.status != "ready" || !sameStorageMigrationMetadata(upload, candidate.upload) {
		return false, ErrConflict
	}
	if upload.storageKind == StorageKindNode {
		if upload.storageNodeID != candidate.nodeID || upload.storageKey != upload.id ||
			upload.storageVersion != StoragePlacementVersionV1 || upload.tempPath != "" || upload.objectPath != "" {
			return false, ErrConflict
		}
		if err := tx.Commit(); err != nil {
			return false, err
		}
		return false, nil
	}
	if upload.storageKind != StorageKindLocal || upload.storageNodeID != "" || upload.storageKey != "" ||
		upload.storageVersion != StoragePlacementVersionV1 || upload.tempPath != candidate.upload.tempPath ||
		upload.objectPath != candidate.upload.objectPath {
		return false, ErrConflict
	}
	result, err := tx.ExecContext(ctx, `UPDATE uploads SET temp_path='',object_path='',storage_kind=?,
		storage_node_id=?,storage_key=?,storage_version=?
		WHERE id=? AND status='ready' AND transfer_id=? AND upload_hash=? AND original_name=? AND content_type=?
		AND length=? AND offset=? AND temp_path=? AND object_path=? AND sha256=? AND scan_detail=?
		AND storage_kind='local' AND storage_node_id='' AND storage_key='' AND storage_version=?`,
		StorageKindNode, candidate.nodeID, candidate.upload.id, StoragePlacementVersionV1,
		upload.id, upload.transferID, upload.uploadTokenHash,
		upload.originalName, upload.contentType, upload.length, upload.offset, upload.tempPath,
		upload.objectPath, upload.sha256, upload.scanDetail, StoragePlacementVersionV1)
	if err != nil {
		return false, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if rowsAffected != 1 {
		return false, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func sameStorageMigrationMetadata(left, right storageMigrationUpload) bool {
	return left.id == right.id && left.transferID == right.transferID &&
		left.uploadTokenHash == right.uploadTokenHash && left.originalName == right.originalName &&
		left.contentType == right.contentType && left.length == right.length && left.offset == right.offset &&
		left.sha256 == right.sha256 && left.scanDetail == right.scanDetail && left.expiresAt == right.expiresAt
}

func finishStorageMigration(ctx context.Context, control *Store, storage *StorageStore,
	report StorageMigrationReport, migrationErr error) (StorageMigrationReport, error) {
	controlErr := storageMigrationQuickCheck(ctx, control.db)
	if controlErr == nil {
		report.ControlQuickCheck = true
	} else {
		controlErr = fmt.Errorf("control database quick_check: %w", controlErr)
	}
	storageErr := storageMigrationQuickCheck(ctx, storage.db)
	if storageErr == nil {
		report.StorageQuickCheck = true
	} else {
		storageErr = fmt.Errorf("storage database quick_check: %w", storageErr)
	}
	return report, errors.Join(migrationErr, controlErr, storageErr)
}

func storageMigrationQuickCheck(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, "PRAGMA quick_check")
	if err != nil {
		return err
	}
	defer rows.Close()
	ok := false
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			return err
		}
		if result != "ok" {
			return fmt.Errorf("SQLite reported an integrity problem")
		}
		ok = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !ok {
		return errors.New("SQLite returned no quick_check result")
	}
	return nil
}
