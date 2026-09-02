//go:build !windows

package main

import "os"

func isStorageLogReparsePoint(info os.FileInfo) bool {
	return info.Mode()&os.ModeSymlink != 0
}

func hardenStorageLogFile(file *os.File) error {
	return file.Chmod(0o600)
}
