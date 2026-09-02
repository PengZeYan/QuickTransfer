//go:build !windows

package main

import "log/slog"

func runAsServiceIfNeeded(_ *slog.Logger) (bool, error) {
	return false, nil
}
