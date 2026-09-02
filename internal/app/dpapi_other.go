//go:build !windows

package app

import "errors"

func readDPAPISecretFile(_ string) (string, error) {
	return "", errors.New("QT_SMTP_PASSWORD_DPAPI_FILE is supported only on Windows")
}
