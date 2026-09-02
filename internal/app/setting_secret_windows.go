//go:build windows

package app

import (
	"encoding/base64"
	"errors"
	"strings"
)

func sealSettingSecret(value string, _ []byte) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("cannot protect an empty setting secret")
	}
	plaintext := []byte(value)
	protected, err := protectLocalMachine(plaintext)
	clear(plaintext)
	if err != nil {
		return "", err
	}
	defer clear(protected)
	return "dpapi:" + base64.RawStdEncoding.EncodeToString(protected), nil
}

func openSettingSecret(value string, _ []byte) (string, error) {
	encoded, ok := strings.CutPrefix(strings.TrimSpace(value), "dpapi:")
	if !ok {
		return "", errors.New("unsupported protected setting format")
	}
	protected, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(protected) == 0 {
		return "", errors.New("invalid protected setting")
	}
	defer clear(protected)
	plaintext, err := unprotectLocalMachine(protected)
	if err != nil {
		return "", err
	}
	defer clear(plaintext)
	secret := strings.TrimSpace(string(plaintext))
	if secret == "" {
		return "", errors.New("protected setting decrypted to an empty value")
	}
	return secret, nil
}
