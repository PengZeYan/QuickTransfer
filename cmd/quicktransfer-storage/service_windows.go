//go:build windows

package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"quicktransfer/internal/app"
)

const (
	serviceStartWaitHint = 30 * time.Second
	serviceStopWaitHint  = 25 * time.Second
)

type windowsStorageService struct {
	logger     *slog.Logger
	loadConfig storageConfigLoader
	runNode    storageNodeRunner
}

var _ svc.Handler = (*windowsStorageService)(nil)

func runAsServiceIfNeeded(logger *slog.Logger) (bool, error) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false, err
	}
	if !isService {
		return false, nil
	}
	if err := validateWindowsServiceLogConfiguration(os.Getenv(storageLogFileEnvironment)); err != nil {
		return true, err
	}
	handler := &windowsStorageService{
		logger:     logger,
		loadConfig: app.LoadStorageConfig,
		runNode:    app.RunStorageNode,
	}
	return true, svc.Run(serviceName, handler)
}

func validateWindowsServiceLogConfiguration(logPath string) error {
	if strings.TrimSpace(logPath) == "" {
		return errors.New("Windows service requires QT_STORAGE_LOG_FILE; SCM stdout is not a persistent log")
	}
	return nil
}

func (service *windowsStorageService) Execute(
	_ []string,
	requests <-chan svc.ChangeRequest,
	changes chan<- svc.Status,
) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{
		State:    svc.StartPending,
		WaitHint: uint32(serviceStartWaitHint / time.Millisecond),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		finished <- runConfiguredStorage(ctx, service.logger, service.loadConfig, service.runNode)
	}()

	running := svc.Status{State: svc.Running, Accepts: accepted}
	changes <- running
	for {
		select {
		case err := <-finished:
			changes <- svc.Status{State: svc.StopPending, WaitHint: 1}
			if err != nil {
				service.logger.Error("storage Windows service stopped unexpectedly", "error", err)
				return true, 1
			}
			return false, 0
		case request, ok := <-requests:
			if !ok {
				cancel()
				return service.waitForShutdown(finished, changes)
			}
			switch request.Cmd {
			case svc.Interrogate:
				changes <- running
			case svc.Stop, svc.Shutdown:
				service.logger.Info("storage Windows service shutdown requested", "command", request.Cmd)
				cancel()
				return service.waitForShutdown(finished, changes)
			default:
				service.logger.Warn("unsupported Windows service control request", "command", request.Cmd)
			}
		}
	}
}

func (service *windowsStorageService) waitForShutdown(
	finished <-chan error,
	changes chan<- svc.Status,
) (bool, uint32) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	checkpoint := uint32(1)
	reportPending := func() {
		changes <- svc.Status{
			State:      svc.StopPending,
			CheckPoint: checkpoint,
			WaitHint:   uint32(serviceStopWaitHint / time.Millisecond),
		}
		checkpoint++
	}
	reportPending()
	for {
		select {
		case err := <-finished:
			if err != nil {
				service.logger.Error("storage Windows service graceful shutdown failed", "error", err)
				return true, 1
			}
			return false, 0
		case <-ticker.C:
			reportPending()
		}
	}
}
