package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	storageLogFileEnvironment = "QT_STORAGE_LOG_FILE"
	storageLogMaximumBytes    = int64(50 * 1024 * 1024)
	storageLogBackupCount     = 5
)

var safeStorageLogName = regexp.MustCompile(`(?i)^[a-z0-9][a-z0-9._-]*\.jsonl$`)

type storageLogOutput struct {
	logger      *slog.Logger
	destination string
	closer      io.Closer
}

func newStorageLogOutputFromEnvironment() (*storageLogOutput, error) {
	configuredPath, configured := os.LookupEnv(storageLogFileEnvironment)
	if !configured || strings.TrimSpace(configuredPath) == "" {
		return &storageLogOutput{
			logger:      slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})),
			destination: "stdout",
			closer:      io.NopCloser(strings.NewReader("")),
		}, nil
	}
	if configuredPath != strings.TrimSpace(configuredPath) {
		return nil, fmt.Errorf("%s must not contain leading or trailing whitespace", storageLogFileEnvironment)
	}
	writer, err := newRotatingJSONLWriter(configuredPath, storageLogMaximumBytes, storageLogBackupCount)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", storageLogFileEnvironment, err)
	}
	return &storageLogOutput{
		logger:      slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: slog.LevelInfo})),
		destination: writer.path,
		closer:      writer,
	}, nil
}

func (output *storageLogOutput) close() error {
	if output == nil || output.closer == nil {
		return nil
	}
	return output.closer.Close()
}

type rotatingJSONLWriter struct {
	mu         sync.Mutex
	path       string
	directory  string
	maxBytes   int64
	maxBackups int
	file       *os.File
	size       int64
	closed     bool
}

func newRotatingJSONLWriter(path string, maxBytes int64, maxBackups int) (*rotatingJSONLWriter, error) {
	if maxBytes <= 0 {
		return nil, errors.New("maximum log size must be positive")
	}
	if maxBackups < 1 || maxBackups > 100 {
		return nil, errors.New("log backup count must be between 1 and 100")
	}
	cleanPath, err := validateStorageLogPath(path)
	if err != nil {
		return nil, err
	}
	writer := &rotatingJSONLWriter{
		path: cleanPath, directory: filepath.Dir(cleanPath), maxBytes: maxBytes, maxBackups: maxBackups,
	}
	if err := writer.openBaseLocked(); err != nil {
		return nil, err
	}
	return writer, nil
}

func (writer *rotatingJSONLWriter) Write(payload []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.closed {
		return 0, os.ErrClosed
	}
	if writer.file == nil {
		if err := writer.openBaseLocked(); err != nil {
			return 0, err
		}
	}
	var rotationErr error
	if writer.size > 0 && writer.size+int64(len(payload)) > writer.maxBytes {
		rotationErr = writer.rotateLocked()
	}
	if rotationErr != nil {
		writer.writeRotationFailureLocked(rotationErr)
	}
	if writer.file == nil {
		return 0, fmt.Errorf("persistent log is unavailable after rotation: %w", rotationErr)
	}
	written, err := writer.file.Write(payload)
	writer.size += int64(written)
	return written, err
}

func (writer *rotatingJSONLWriter) Close() error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.closed {
		return nil
	}
	writer.closed = true
	if writer.file == nil {
		return nil
	}
	syncErr := writer.file.Sync()
	closeErr := writer.file.Close()
	writer.file = nil
	return errors.Join(syncErr, closeErr)
}

func (writer *rotatingJSONLWriter) openBaseLocked() error {
	cleanPath, err := validateStorageLogPath(writer.path)
	if err != nil {
		return err
	}
	if cleanPath != writer.path {
		return errors.New("persistent log path changed after validation")
	}
	file, err := os.OpenFile(writer.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create or append persistent log: %w", err)
	}
	if err := hardenStorageLogFile(file); err != nil {
		_ = file.Close()
		return fmt.Errorf("restrict persistent log permissions: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("stat persistent log: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return errors.New("persistent log target is not a regular file")
	}
	writer.file = file
	writer.size = info.Size()
	return nil
}

func (writer *rotatingJSONLWriter) rotateLocked() error {
	if writer.file != nil {
		if err := writer.file.Sync(); err != nil {
			return fmt.Errorf("sync current log before rotation: %w", err)
		}
		closeErr := writer.file.Close()
		writer.file = nil
		if closeErr != nil {
			reopenErr := writer.openBaseLocked()
			return errors.Join(fmt.Errorf("close current log before rotation: %w", closeErr), reopenErr)
		}
	}

	rotationErr := writer.shiftBackupsLocked()
	reopenErr := writer.openBaseLocked()
	if rotationErr != nil || reopenErr != nil {
		return errors.Join(rotationErr, reopenErr)
	}
	return nil
}

func (writer *rotatingJSONLWriter) shiftBackupsLocked() error {
	for index := writer.maxBackups; index >= 1; index-- {
		source := writer.path
		if index > 1 {
			source = writer.backupPath(index - 1)
		}
		target := writer.backupPath(index)
		if err := writer.validateRotationTarget(source); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		if err := writer.removeExistingRotationTarget(target); err != nil {
			return err
		}
		if err := os.Rename(source, target); err != nil {
			return fmt.Errorf("rotate %q to %q: %w", source, target, err)
		}
	}
	return nil
}

func (writer *rotatingJSONLWriter) backupPath(index int) string {
	return fmt.Sprintf("%s.%d", writer.path, index)
}

func (writer *rotatingJSONLWriter) validateRotationTarget(path string) error {
	cleanPath := filepath.Clean(path)
	baseName := filepath.Base(writer.path)
	rotationName := filepath.Base(cleanPath)
	if filepath.Dir(cleanPath) != writer.directory ||
		(cleanPath != writer.path && !strings.HasPrefix(rotationName, baseName+".")) {
		return fmt.Errorf("rotation path escaped the persistent log directory: %q", path)
	}
	info, err := os.Lstat(cleanPath)
	if err != nil {
		return err
	}
	if isStorageLogReparsePoint(info) || !info.Mode().IsRegular() {
		return fmt.Errorf("rotation target is not a regular non-reparse file: %q", cleanPath)
	}
	return nil
}

func (writer *rotatingJSONLWriter) removeExistingRotationTarget(path string) error {
	if err := writer.validateRotationTarget(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove oldest persistent log backup %q: %w", path, err)
	}
	return nil
}

func (writer *rotatingJSONLWriter) writeRotationFailureLocked(rotationErr error) {
	if writer.file == nil {
		return
	}
	record, err := json.Marshal(map[string]any{
		"time":  time.Now().UTC().Format(time.RFC3339Nano),
		"level": "ERROR",
		"msg":   "persistent log rotation failed; continuing on current file",
		"event": "log_rotation_failed",
		"error": rotationErr.Error(),
	})
	if err != nil {
		return
	}
	record = append(record, '\n')
	written, _ := writer.file.Write(record)
	writer.size += int64(written)
}

func validateStorageLogPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("persistent log path is empty")
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("persistent log path must be absolute")
	}
	cleanPath := filepath.Clean(path)
	if cleanPath != path {
		return "", errors.New("persistent log path must already be clean and cannot contain traversal segments")
	}
	if !safeStorageLogName.MatchString(filepath.Base(cleanPath)) {
		return "", errors.New("persistent log filename must be a safe .jsonl name")
	}
	directory := filepath.Dir(cleanPath)
	volumeRoot := filepath.Clean(filepath.VolumeName(cleanPath) + string(os.PathSeparator))
	if directory == volumeRoot {
		return "", errors.New("persistent log must be below an explicit log directory, not a filesystem root")
	}
	if err := validateStorageLogDirectory(directory); err != nil {
		return "", err
	}
	if info, err := os.Lstat(cleanPath); err == nil {
		if isStorageLogReparsePoint(info) || !info.Mode().IsRegular() {
			return "", errors.New("persistent log target must be a regular non-reparse file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect persistent log target: %w", err)
	}
	return cleanPath, nil
}

func validateStorageLogDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("persistent log directory must already exist: %w", err)
	}
	if !info.IsDir() || isStorageLogReparsePoint(info) {
		return errors.New("persistent log directory must be a real directory, not a reparse point")
	}
	for cursor := directory; ; cursor = filepath.Dir(cursor) {
		info, err := os.Lstat(cursor)
		if err != nil {
			return fmt.Errorf("inspect persistent log directory ancestor: %w", err)
		}
		if isStorageLogReparsePoint(info) {
			return fmt.Errorf("persistent log path traverses a reparse point: %q", cursor)
		}
		parent := filepath.Dir(cursor)
		if parent == cursor {
			break
		}
	}
	return nil
}

func filepathAbs(path string) (string, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(absolutePath), nil
}
