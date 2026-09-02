//go:build !windows

package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

func sealSettingSecret(value string, key []byte) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(key) < 32 {
		return "", errors.New("setting secret and application key are required")
	}
	digest := sha256.Sum256(key)
	block, err := aes.NewCipher(digest[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(value), []byte("quicktransfer-setting-v1"))
	return "aesgcm:" + base64.RawStdEncoding.EncodeToString(sealed), nil
}

func openSettingSecret(value string, key []byte) (string, error) {
	encoded, ok := strings.CutPrefix(strings.TrimSpace(value), "aesgcm:")
	if !ok || len(key) < 32 {
		return "", errors.New("unsupported protected setting format")
	}
	sealed, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(key)
	block, err := aes.NewCipher(digest[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(sealed) < gcm.NonceSize() {
		return "", errors.New("invalid protected setting")
	}
	plaintext, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], []byte("quicktransfer-setting-v1"))
	if err != nil {
		return "", err
	}
	defer clear(plaintext)
	return strings.TrimSpace(string(plaintext)), nil
}
