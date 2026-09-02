package app

import "path/filepath"

const storageDataDirectoryLockName = ".quicktransfer-storage.lock"

func storageDataDirectoryLockPath(dataDir string) string {
	return filepath.Join(dataDir, storageDataDirectoryLockName)
}
