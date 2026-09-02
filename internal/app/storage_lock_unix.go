//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package app

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

type storageDataDirectoryLock struct {
	mu   sync.Mutex
	file *os.File
}

func acquireStorageDataDirectoryLock(dataDir string) (*storageDataDirectoryLock, error) {
	lockPath := storageDataDirectoryLockPath(dataDir)
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open storage data directory lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock storage data directory %s: %w", dataDir, err)
	}
	return &storageDataDirectoryLock{file: file}, nil
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
	return errors.Join(unix.Flock(int(file.Fd()), unix.LOCK_UN), file.Close())
}
