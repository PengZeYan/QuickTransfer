//go:build windows

package app

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/windows"
)

type storageDataDirectoryLock struct {
	mu         sync.Mutex
	file       *os.File
	overlapped windows.Overlapped
}

func acquireStorageDataDirectoryLock(dataDir string) (*storageDataDirectoryLock, error) {
	lockPath := storageDataDirectoryLockPath(dataDir)
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open storage data directory lock: %w", err)
	}
	lock := &storageDataDirectoryLock{file: file}
	if err := windows.LockFileEx(windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &lock.overlapped); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock storage data directory %s: %w", dataDir, err)
	}
	return lock, nil
}

func (lock *storageDataDirectoryLock) Close() error {
	if lock == nil {
		return nil
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	if lock.file == nil {
		return nil
	}
	file := lock.file
	lock.file = nil
	unlockErr := windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &lock.overlapped)
	return errors.Join(unlockErr, file.Close())
}
