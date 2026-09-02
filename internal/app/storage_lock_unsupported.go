//go:build !windows && !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package app

import "errors"

type storageDataDirectoryLock struct{}

func acquireStorageDataDirectoryLock(string) (*storageDataDirectoryLock, error) {
	return nil, errors.New("storage data directory locking is unsupported on this operating system")
}

func (*storageDataDirectoryLock) Close() error {
	return nil
}
