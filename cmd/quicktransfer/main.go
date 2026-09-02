package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"quicktransfer/internal/app"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("quicktransfer stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := app.LoadConfig()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}
	store, err := app.OpenStore(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	defer store.Close()
	scannerMode := cfg.ScanMode
	if cfg.UsesRemoteStorage() {
		scannerMode = "signature"
	}
	scanner := app.NewScanner(scannerMode)
	if !cfg.UsesRemoteStorage() {
		if err := scanner.Probe(context.Background(), cfg.DataDir); err != nil {
			if cfg.ScanMode == "required" || cfg.PublicMode {
				return fmt.Errorf("antivirus readiness error: %w", err)
			}
			logger.Warn("full antivirus unavailable; local service will use the built-in signature guard", "error", err)
		}
		if cfg.PublicMode && !scanner.ProductionReady() {
			return errors.New("public binding requires a verified full antivirus scanner")
		}
	}
	var server *app.Server
	var worker *app.Worker
	if cfg.UsesRemoteStorage() {
		storageHTTPClient, err := app.NewStorageHTTPClient(cfg.StorageCAFile)
		if err != nil {
			return fmt.Errorf("storage TLS configuration error: %w", err)
		}
		storage := app.NewStorageInternalClient(cfg.StorageInternalURL, cfg.StorageNodeID, cfg.StorageSharedSecret, storageHTTPClient)
		server = app.NewServerWithRemoteStorage(cfg, store, scanner, logger, storage)
		worker = app.NewWorkerWithRemoteStorage(cfg, store, scanner, logger, storage)
	} else {
		server = app.NewServer(cfg, store, scanner, logger)
		worker = app.NewWorker(cfg, store, scanner, logger)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go worker.Run(ctx)

	httpServer := &http.Server{
		Addr: cfg.Addr, Handler: server.Handler(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 2 * time.Minute, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20,
	}
	serveErr := make(chan error, 1)
	go func() {
		logger.Info("quicktransfer started", "address", cfg.Addr, "baseURL", cfg.BaseURL, "scanner", scanner.Name())
		err := httpServer.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	var unexpectedErr error
	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if err == nil {
			unexpectedErr = errors.New("HTTP server stopped unexpectedly")
		} else {
			unexpectedErr = fmt.Errorf("HTTP server stopped unexpectedly: %w", err)
		}
		cancel()
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		if unexpectedErr != nil {
			return errors.Join(unexpectedErr, fmt.Errorf("graceful shutdown failed: %w", err))
		}
		return fmt.Errorf("graceful shutdown failed: %w", err)
	}
	return unexpectedErr
}
