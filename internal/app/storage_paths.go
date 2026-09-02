package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
)

type storageDataPaths struct {
	root         string
	resolvedRoot string
}

func newStorageDataPaths(dataDir string) (*storageDataPaths, error) {
	root, err := filepath.Abs(filepath.Clean(dataDir))
	if err != nil {
		return nil, fmt.Errorf("resolve storage data directory: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("inspect storage data directory: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("storage data path is not a directory")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve storage data directory links: %w", err)
	}
	resolvedRoot, err = filepath.Abs(resolvedRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve storage data directory absolute path: %w", err)
	}
	paths := &storageDataPaths{root: root, resolvedRoot: resolvedRoot}
	for _, directory := range []string{"db", "tmp", "quarantine", "objects"} {
		if err := paths.validateDirectory(directory); err != nil {
			return nil, err
		}
	}
	return paths, nil
}

func (paths *storageDataPaths) validateDirectory(directory string) error {
	lexical := filepath.Join(paths.root, directory)
	info, err := os.Lstat(lexical)
	if err != nil {
		return fmt.Errorf("inspect storage %s directory: %w", directory, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("storage %s path must be a real directory, not a link or reparse point", directory)
	}
	resolved, err := filepath.EvalSymlinks(lexical)
	if err != nil {
		return fmt.Errorf("resolve storage %s directory: %w", directory, err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return fmt.Errorf("resolve storage %s directory absolute path: %w", directory, err)
	}
	relative, err := filepath.Rel(paths.resolvedRoot, resolved)
	if err != nil || relative != directory {
		return fmt.Errorf("storage %s directory resolves outside the storage data directory", directory)
	}
	return nil
}

func storageUploadPathKey(directory, id, extension string) string {
	return directory + "/" + id + extension
}

func validateStorageUploadPathKey(id, key string) error {
	if key == "" || strings.ContainsAny(key, "\\\x00") || pathpkg.IsAbs(key) || pathpkg.Clean(key) != key {
		return errors.New("storage upload path is not a canonical relative key")
	}
	parts := strings.Split(key, "/")
	if len(parts) != 2 || !validStorageObjectID(id) {
		return errors.New("storage upload path is not server-generated")
	}
	var expected string
	switch parts[0] {
	case "tmp":
		expected = id + ".part"
	case "quarantine", "objects":
		expected = id + ".blob"
	default:
		return errors.New("storage upload path uses an unsupported directory")
	}
	if parts[1] != expected {
		return errors.New("storage upload path does not match its upload id")
	}
	return nil
}

func (paths *storageDataPaths) resolveUploadKey(id, key string) (string, error) {
	if err := validateStorageUploadPathKey(id, key); err != nil {
		return "", err
	}
	absolute := filepath.Join(paths.root, filepath.FromSlash(key))
	relative, err := filepath.Rel(paths.root, absolute)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return "", errors.New("storage upload path escapes the storage data directory")
	}
	parent := filepath.Dir(absolute)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return "", fmt.Errorf("inspect storage upload parent directory: %w", err)
	}
	if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("storage upload parent is a link, reparse point, or non-directory")
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", fmt.Errorf("resolve storage upload parent directory: %w", err)
	}
	resolvedParent, err = filepath.Abs(resolvedParent)
	if err != nil {
		return "", fmt.Errorf("resolve storage upload parent absolute path: %w", err)
	}
	resolvedRelative, err := filepath.Rel(paths.resolvedRoot, resolvedParent)
	if err != nil || resolvedRelative != filepath.Dir(filepath.FromSlash(key)) {
		return "", errors.New("storage upload parent resolves outside its generated directory")
	}
	if info, lstatErr := os.Lstat(absolute); lstatErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("storage upload path is a link or reparse point")
		}
	} else if !errors.Is(lstatErr, os.ErrNotExist) {
		return "", fmt.Errorf("inspect storage upload path: %w", lstatErr)
	}
	return absolute, nil
}

func (paths *storageDataPaths) normalizeUploadPath(id, storedPath string) (string, string, error) {
	if storedPath == "" {
		return "", "", nil
	}
	if !storagePathHasParentTraversal(storedPath) {
		if err := validateStorageUploadPathKey(id, storedPath); err == nil {
			absolute, resolveErr := paths.resolveUploadKey(id, storedPath)
			return storedPath, absolute, resolveErr
		}
	}
	if storagePathHasParentTraversal(storedPath) || !filepath.IsAbs(storedPath) {
		return "", "", errors.New("storage upload path is neither a canonical key nor a safe legacy absolute path")
	}
	absolute, err := filepath.Abs(filepath.Clean(storedPath))
	if err != nil {
		return "", "", fmt.Errorf("resolve legacy storage upload path: %w", err)
	}
	relative, err := filepath.Rel(paths.root, absolute)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return "", "", errors.New("legacy storage upload path is outside the current storage data directory")
	}
	key := filepath.ToSlash(relative)
	if err := validateStorageUploadPathKey(id, key); err != nil {
		return "", "", fmt.Errorf("legacy storage upload path is not server-generated: %w", err)
	}
	resolved, err := paths.resolveUploadKey(id, key)
	if err != nil {
		return "", "", err
	}
	same, err := filepath.Rel(resolved, absolute)
	if err != nil || same != "." {
		return "", "", errors.New("legacy storage upload path does not resolve to its generated location")
	}
	return key, resolved, nil
}

func (paths *storageDataPaths) sameRoot(dataDir string) bool {
	other, err := newStorageDataPaths(dataDir)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(paths.resolvedRoot, other.resolvedRoot)
	return err == nil && relative == "."
}

func storagePathHasParentTraversal(value string) bool {
	for _, part := range strings.FieldsFunc(value, func(character rune) bool {
		return character == '/' || character == '\\'
	}) {
		if part == ".." {
			return true
		}
	}
	return false
}

func migrateStorageUploadPaths(ctx context.Context, db *sql.DB, paths *storageDataPaths) error {
	if paths == nil {
		return errors.New("storage data path resolver is required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,path FROM storage_uploads ORDER BY id`)
	if err != nil {
		return err
	}
	type pathUpdate struct {
		id       string
		previous string
		key      string
	}
	var updates []pathUpdate
	for rows.Next() {
		var id, storedPath string
		if err := rows.Scan(&id, &storedPath); err != nil {
			_ = rows.Close()
			return err
		}
		key, _, err := paths.normalizeUploadPath(id, storedPath)
		if err != nil {
			_ = rows.Close()
			return fmt.Errorf("validate stored path for upload %s: %w", id, err)
		}
		if key != storedPath {
			updates = append(updates, pathUpdate{id: id, previous: storedPath, key: key})
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, update := range updates {
		result, err := tx.ExecContext(ctx, `UPDATE storage_uploads SET path=? WHERE id=? AND path=?`,
			update.key, update.id, update.previous)
		if err != nil {
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if changed != 1 {
			return errors.New("storage upload path changed during migration")
		}
	}
	return tx.Commit()
}
