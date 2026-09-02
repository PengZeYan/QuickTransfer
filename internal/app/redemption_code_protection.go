package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

const redemptionCodeProtectionAAD = "quicktransfer-redemption-code-v1"

// Redemption codes remain recoverable for authenticated administrators, but
// are never stored as plaintext. This portable envelope deliberately uses the
// application secret on every OS so control-plane database restores do not
// become tied to a Windows DPAPI machine.
func sealRedemptionCode(value string, key []byte) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(key) < 32 {
		return "", errors.New("redemption code and application key are required")
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
	if err := readCryptographicRandom(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(value), []byte(redemptionCodeProtectionAAD))
	return "aesgcm:" + base64.RawStdEncoding.EncodeToString(sealed), nil
}

func openRedemptionCode(value string, key []byte) (string, error) {
	encoded, ok := strings.CutPrefix(strings.TrimSpace(value), "aesgcm:")
	if !ok || len(key) < 32 {
		return "", errors.New("unsupported protected redemption code")
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
		return "", errors.New("invalid protected redemption code")
	}
	plaintext, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], []byte(redemptionCodeProtectionAAD))
	if err != nil {
		return "", err
	}
	defer clear(plaintext)
	code := strings.TrimSpace(string(plaintext))
	if code == "" {
		return "", errors.New("protected redemption code decrypted to an empty value")
	}
	return code, nil
}
