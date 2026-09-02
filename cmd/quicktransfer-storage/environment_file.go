package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	storageEnvironmentFileArgument = "--env-file"
	maximumStorageEnvironmentBytes = 64 * 1024
)

var allowedStorageEnvironmentNames = map[string]struct{}{
	"QT_CONTROL_URL":                          {},
	"QT_STORAGE_ADDR":                         {},
	"QT_STORAGE_ALLOWED_ORIGINS":              {},
	"QT_STORAGE_DATA_DIR":                     {},
	"QT_STORAGE_DATA_PLANE_RATE_BURST":        {},
	"QT_STORAGE_DATA_PLANE_RATE_PER_SECOND":   {},
	"QT_STORAGE_DOWNLOAD_CONCURRENCY":         {},
	"QT_STORAGE_DOWNLOAD_CONCURRENCY_PER_IP":  {},
	"QT_STORAGE_LOG_FILE":                     {},
	"QT_STORAGE_MAX_CHUNK_BYTES":              {},
	"QT_STORAGE_MAX_UPLOAD_BYTES":             {},
	"QT_STORAGE_MIN_FREE_BYTES":               {},
	"QT_STORAGE_NODE_ID":                      {},
	"QT_STORAGE_OUTBOX_CLAIM_LEASE":           {},
	"QT_STORAGE_OUTBOX_MAX_ATTEMPTS":          {},
	"QT_STORAGE_PUBLIC_MODE":                  {},
	"QT_STORAGE_PUBLIC_URL":                   {},
	"QT_STORAGE_REPLAY_DEAD_LETTERS_ON_START": {},
	"QT_STORAGE_RESOURCE_FAILURE_LIMIT":       {},
	"QT_STORAGE_RESOURCE_FAILURE_WINDOW":      {},
	"QT_STORAGE_RESOURCE_RATE_BURST":          {},
	"QT_STORAGE_RESOURCE_RATE_PER_SECOND":     {},
	"QT_STORAGE_SCAN_MODE":                    {},
	"QT_STORAGE_SHARED_SECRET_FILE":           {},
	"QT_STORAGE_TLS_CERT_FILE":                {},
	"QT_STORAGE_TLS_KEY_FILE":                 {},
	"QT_STORAGE_UPLOAD_CONCURRENCY":           {},
	"QT_STORAGE_UPLOAD_CONCURRENCY_PER_IP":    {},
	"QT_STORAGE_UPLOAD_READ_IDLE_TIMEOUT":     {},
	"QT_STORAGE_UPLOAD_READ_MAX_DURATION":     {},
	"QT_TRUSTED_PROXY_CIDRS":                  {},
}

func loadStorageEnvironmentFromArguments(arguments []string) error {
	path, configured, err := storageEnvironmentFileFromArguments(arguments)
	if err != nil {
		return err
	}
	if !configured {
		return nil
	}
	values, err := readStorageEnvironmentFile(path)
	if err != nil {
		return fmt.Errorf("load storage environment file: %w", err)
	}
	for name, value := range values {
		if err := os.Setenv(name, value); err != nil {
			return fmt.Errorf("set storage environment %s: %w", name, err)
		}
	}
	return nil
}

func storageEnvironmentFileFromArguments(arguments []string) (string, bool, error) {
	var path string
	for index := 0; index < len(arguments); index++ {
		if arguments[index] != storageEnvironmentFileArgument {
			return "", false, fmt.Errorf("unsupported argument %q", arguments[index])
		}
		if path != "" {
			return "", false, errors.New("--env-file may be specified only once")
		}
		index++
		if index >= len(arguments) || strings.TrimSpace(arguments[index]) == "" {
			return "", false, errors.New("--env-file requires a non-empty path")
		}
		path = arguments[index]
	}
	return path, path != "", nil
}

func readStorageEnvironmentFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := bufio.NewReader(io.LimitReader(file, maximumStorageEnvironmentBytes+1))
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if len(content) > maximumStorageEnvironmentBytes {
		return nil, fmt.Errorf("environment file exceeds %d bytes", maximumStorageEnvironmentBytes)
	}
	text := strings.TrimPrefix(string(content), "\ufeff")
	values := make(map[string]string)
	for lineNumber, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, found := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if !found || name == "" {
			return nil, fmt.Errorf("invalid environment entry at line %d", lineNumber+1)
		}
		if _, allowed := allowedStorageEnvironmentNames[name]; !allowed {
			return nil, fmt.Errorf("unsupported storage environment name %q at line %d", name, lineNumber+1)
		}
		if _, duplicate := values[name]; duplicate {
			return nil, fmt.Errorf("duplicate storage environment name %q at line %d", name, lineNumber+1)
		}
		if strings.ContainsRune(value, '\x00') {
			return nil, fmt.Errorf("storage environment value %q contains a NUL character", name)
		}
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		values[name] = value
	}
	if len(values) == 0 {
		return nil, errors.New("environment file contains no storage settings")
	}
	return values, nil
}
