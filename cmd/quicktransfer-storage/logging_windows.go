//go:build windows

package main

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

func isStorageLogReparsePoint(info os.FileInfo) bool {
	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	attributes, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && attributes.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

func hardenStorageLogFile(_ *os.File) error {
	// Windows deployment creates an inheritance-protected log root whose only
	// writable principals are SYSTEM, Administrators, and LocalService. New log
	// files inherit that DACL; chmod does not model Windows ACLs.
	return nil
}
