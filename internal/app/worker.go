package app

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

type Worker struct {
	cfg     Config
	store   *Store
	scanner *Scanner
	logger  *slog.Logger
	remote  remoteStorageDeleter
}

type remoteStorageDeleter interface {
	DeleteUpload(context.Context, string) error
}

func NewWorker(cfg Config, store *Store, scanner *Scanner, logger *slog.Logger) *Worker {
	return &Worker{cfg: cfg, store: store, scanner: scanner, logger: logger}
}

func NewWorkerWithRemoteStorage(cfg Config, store *Store, scanner *Scanner, logger *slog.Logger, remote remoteStorageDeleter) *Worker {
	return &Worker{cfg: cfg, store: store, scanner: scanner, logger: logger, remote: remote}
}

func (worker *Worker) Run(ctx context.Context) {
	fast := time.NewTicker(time.Second)
	maintenance := time.NewTicker(time.Minute)
	defer fast.Stop()
	defer maintenance.Stop()
	worker.recoverCompleted(ctx)
	worker.scanPending(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-fast.C:
			worker.recoverCompleted(ctx)
			worker.scanPending(ctx)
		case <-maintenance.C:
			worker.cleanup(ctx)
		}
	}
}

func (worker *Worker) recoverCompleted(ctx context.Context) {
	uploads, err := worker.store.CompletableUploads(ctx)
	if err != nil {
		worker.logger.Error("recover completed uploads", "error", err)
		return
	}
	for _, upload := range uploads {
		if err := finalizeUpload(ctx, worker.cfg, worker.store, upload); err != nil && !errors.Is(err, ErrConflict) {
			worker.logger.Error("finalize recovered upload", "upload", upload.ID, "error", err)
		}
	}
}

func finalizeUpload(ctx context.Context, cfg Config, store *Store, upload Upload) error {
	quarantinePath := filepath.Join(cfg.DataDir, "quarantine", upload.ID+".blob")
	if _, err := os.Stat(quarantinePath); os.IsNotExist(err) {
		if err := os.Rename(upload.TempPath, quarantinePath); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return store.MarkUploaded(ctx, upload.ID, quarantinePath)
}

func (worker *Worker) scanPending(ctx context.Context) {
	uploads, err := worker.store.ClaimUploads(ctx, 4)
	if err != nil {
		worker.logger.Error("claim scans", "error", err)
		return
	}
	for _, upload := range uploads {
		result, scanErr := worker.scanner.Scan(ctx, upload.TempPath)
		if scanErr != nil {
			_ = worker.store.MarkQuarantined(ctx, upload.ID, result.SHA256, scanErr.Error())
			worker.logger.Warn("file scan unavailable; kept quarantined", "upload", upload.ID, "error", scanErr)
			continue
		}
		if !result.Clean {
			_ = os.Remove(upload.TempPath)
			_ = worker.store.MarkBlocked(ctx, upload.ID, result.SHA256, result.Detail)
			worker.logger.Warn("file blocked", "upload", upload.ID, "engine", result.Engine)
			continue
		}
		objectPath := filepath.Join(worker.cfg.DataDir, "objects", upload.ID+".blob")
		if err := os.Rename(upload.TempPath, objectPath); err != nil {
			_ = worker.store.MarkQuarantined(ctx, upload.ID, result.SHA256, "storage promotion failed")
			worker.logger.Error("promote clean file", "upload", upload.ID, "error", err)
			continue
		}
		if err := worker.store.MarkReady(ctx, upload.ID, objectPath, result.SHA256, result.Detail); err != nil {
			worker.logger.Error("mark file ready", "upload", upload.ID, "error", err)
		}
	}
}

func (worker *Worker) cleanup(ctx context.Context) {
	now := time.Now()
	if err := worker.store.CleanupIdentity(ctx, now.Unix()); err != nil {
		worker.logger.Error("cleanup identity records", "error", err)
	}
	if err := worker.store.CleanupHumanVerification(ctx, now.Unix()); err != nil {
		worker.logger.Error("cleanup human verification receipts", "error", err)
	}
	initialTraffic := worker.cfg.UserMonthlyTraffic
	if settings, _, err := worker.store.LoadServiceSettings(ctx, defaultServiceSettings(worker.cfg), worker.cfg.Secret); err == nil {
		initialTraffic = settings.Defaults.UserMonthlyTraffic
	} else {
		worker.logger.Error("load cleanup settings", "error", err)
	}
	if err := worker.store.ReleaseExpiredDownloadReservations(ctx, initialTraffic, now.Unix()); err != nil {
		worker.logger.Error("release expired download reservations", "error", err)
	}
	if err := worker.store.ReleaseExpiredRetrievalSessions(ctx, now.Unix()); err != nil {
		worker.logger.Error("release expired retrieval sessions", "error", err)
	}
	uploads, err := worker.store.MaintenanceCandidates(ctx, now.Add(-worker.cfg.IncompleteLifetime).Unix(), now.Unix())
	if err != nil {
		worker.logger.Error("load cleanup candidates", "error", err)
		return
	}
	for _, upload := range uploads {
		if upload.IsNodeStorage() {
			if worker.remote == nil || upload.StorageNodeID != worker.cfg.StorageNodeID || upload.StorageKey != upload.ID {
				worker.logger.Error("remote upload cleanup unavailable", "upload", upload.ID)
				continue
			}
			if err := worker.remote.DeleteUpload(ctx, upload.ID); err != nil {
				worker.logger.Error("delete remote upload", "upload", upload.ID, "error", err)
				continue
			}
		} else {
			removeFailed := false
			for _, path := range []string{upload.TempPath, upload.ObjectPath} {
				if path != "" {
					if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
						worker.logger.Error("delete local upload", "upload", upload.ID, "error", removeErr)
						removeFailed = true
					}
				}
			}
			if removeFailed {
				continue
			}
		}
		if err := worker.store.MarkDeleted(ctx, upload); err != nil {
			worker.logger.Error("mark upload deleted", "upload", upload.ID, "error", err)
		}
	}
}
