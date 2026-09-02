package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"quicktransfer/internal/app"
)

const serviceName = "QuickTransferStorage"

type storageConfigLoader func() (app.StorageConfig, error)
type storageNodeRunner func(context.Context, app.StorageConfig, *slog.Logger) error

func main() {
	os.Exit(runStorageProcess())
}

func runStorageProcess() (exitCode int) {
	if err := loadStorageEnvironmentFromArguments(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "quicktransfer-storage: environment initialization failed: %v\n", err)
		return 1
	}
	logOutput, err := newStorageLogOutputFromEnvironment()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "quicktransfer-storage: persistent log initialization failed: %v\n", err)
		return 1
	}
	logger := logOutput.logger
	identity, err := currentStorageProcessIdentity()
	if err != nil {
		logger.Error("storage process identity failed", "event", "process_identity_failed", "error", err)
		_ = logOutput.close()
		return 1
	}
	startedAt := time.Now()
	logger.Info("storage process started",
		"event", "process_start",
		"serviceName", serviceName,
		"pid", os.Getpid(),
		"goos", runtime.GOOS,
		"binaryPath", identity.path,
		"binarySha256", identity.sha256,
		"logDestination", logOutput.destination,
	)
	defer func() {
		logger.Info("storage process exiting",
			"event", "process_exit",
			"serviceName", serviceName,
			"pid", os.Getpid(),
			"binarySha256", identity.sha256,
			"exitCode", exitCode,
			"uptimeMs", time.Since(startedAt).Milliseconds(),
		)
		if closeErr := logOutput.close(); closeErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "quicktransfer-storage: persistent log close failed: %v\n", closeErr)
			if exitCode == 0 {
				exitCode = 1
			}
		}
	}()

	handled, err := runAsServiceIfNeeded(logger)
	if err != nil {
		logger.Error("storage service failed", "service", serviceName, "error", err)
		return 1
	}
	if handled {
		return 0
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := runConfiguredStorage(ctx, logger, app.LoadStorageConfig, app.RunStorageNode); err != nil {
		logger.Error("storage node stopped", "error", err)
		return 1
	}
	return 0
}

type storageProcessIdentity struct {
	path   string
	sha256 string
}

func currentStorageProcessIdentity() (storageProcessIdentity, error) {
	executablePath, err := os.Executable()
	if err != nil {
		return storageProcessIdentity{}, fmt.Errorf("resolve executable path: %w", err)
	}
	executablePath, err = filepathAbs(executablePath)
	if err != nil {
		return storageProcessIdentity{}, fmt.Errorf("normalize executable path: %w", err)
	}
	file, err := os.Open(executablePath)
	if err != nil {
		return storageProcessIdentity{}, fmt.Errorf("open executable for build identity: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return storageProcessIdentity{}, fmt.Errorf("hash executable for build identity: %w", err)
	}
	return storageProcessIdentity{path: executablePath, sha256: hex.EncodeToString(hash.Sum(nil))}, nil
}

func runConfiguredStorage(
	ctx context.Context,
	logger *slog.Logger,
	loadConfig storageConfigLoader,
	runNode storageNodeRunner,
) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("storage node configuration failed: %w", err)
	}
	err = runNode(ctx, cfg, logger)
	if ctx.Err() != nil && errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
