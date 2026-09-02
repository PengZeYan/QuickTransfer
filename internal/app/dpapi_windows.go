//go:build windows

package app

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type dpapiSecretEnvelope struct {
	ProtectedPassword string `json:"protectedPassword"`
}

func readDPAPISecretFile(path string) (string, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read QT_SMTP_PASSWORD_DPAPI_FILE: %w", err)
	}
	var envelope dpapiSecretEnvelope
	if err := json.Unmarshal(contents, &envelope); err != nil {
		return "", fmt.Errorf("parse QT_SMTP_PASSWORD_DPAPI_FILE: %w", err)
	}
	protected, err := base64.StdEncoding.DecodeString(strings.TrimSpace(envelope.ProtectedPassword))
	if err != nil || len(protected) == 0 {
		return "", errors.New("QT_SMTP_PASSWORD_DPAPI_FILE contains an invalid protectedPassword")
	}
	decrypted, err := unprotectLocalMachine(protected)
	clear(protected)
	if err != nil {
		return "", fmt.Errorf("decrypt QT_SMTP_PASSWORD_DPAPI_FILE: %w", err)
	}
	secret := strings.TrimSpace(string(decrypted))
	clear(decrypted)
	if secret == "" {
		return "", errors.New("QT_SMTP_PASSWORD_DPAPI_FILE decrypted to an empty secret")
	}
	return secret, nil
}

func unprotectLocalMachine(protected []byte) ([]byte, error) {
	input := windows.DataBlob{Size: uint32(len(protected)), Data: &protected[0]}
	var output windows.DataBlob
	if err := windows.CryptUnprotectData(&input, nil, nil, 0, nil, 0, &output); err != nil {
		return nil, err
	}
	if output.Data == nil || output.Size == 0 {
		return nil, errors.New("DPAPI returned no data")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	result := make([]byte, int(output.Size))
	copy(result, unsafe.Slice(output.Data, int(output.Size)))
	return result, nil
}

func protectLocalMachine(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("cannot protect an empty secret")
	}
	input := windows.DataBlob{Size: uint32(len(plaintext)), Data: &plaintext[0]}
	var output windows.DataBlob
	if err := windows.CryptProtectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE, &output); err != nil {
		return nil, err
	}
	if output.Data == nil || output.Size == 0 {
		return nil, errors.New("DPAPI returned no protected data")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	result := make([]byte, int(output.Size))
	copy(result, unsafe.Slice(output.Data, int(output.Size)))
	return result, nil
}
