package app

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const pickupAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

var (
	cryptographicRandomReader io.Reader = rand.Reader
	dummyHashOnce             sync.Once
	dummyHash                 string
)

func readCryptographicRandom(buffer []byte) error {
	if len(buffer) == 0 {
		return errors.New("cryptographic random request must not be empty")
	}
	if _, err := io.ReadFull(cryptographicRandomReader, buffer); err != nil {
		return fmt.Errorf("read cryptographic random data: %w", err)
	}
	return nil
}

func randomToken(size int) (string, error) {
	if size <= 0 {
		return "", errors.New("random token size must be positive")
	}
	buffer := make([]byte, size)
	if err := readCryptographicRandom(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func randomPickupCode(length int) (string, error) {
	if length <= 0 {
		return "", errors.New("pickup code length must be positive")
	}
	random := make([]byte, length)
	if err := readCryptographicRandom(random); err != nil {
		return "", err
	}
	result := make([]byte, length)
	for index, value := range random {
		result[index] = pickupAlphabet[int(value)%len(pickupAlphabet)]
	}
	return string(result), nil
}

func tokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func secureEqual(left, right string) bool {
	leftHash := sha256.Sum256([]byte(left))
	rightHash := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftHash[:], rightHash[:]) == 1
}

func hashAccessCode(code string) (string, error) {
	if code == "" {
		return "", nil
	}
	salt := make([]byte, 16)
	if err := readCryptographicRandom(salt); err != nil {
		return "", err
	}
	return encodeAccessCodeHash(code, salt), nil
}

func encodeAccessCodeHash(code string, salt []byte) string {
	key := argon2.IDKey([]byte(code), salt, 2, 32*1024, 1, 32)
	return fmt.Sprintf("$argon2id$v=19$m=32768,t=2,p=1$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

func verifyAccessCode(encoded, code string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var memory uint32
	var iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	actual := argon2.IDKey([]byte(code), salt, iterations, memory, parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func dummyAccessCodeHash() string {
	dummyHashOnce.Do(func() {
		// The dummy value is deliberately deterministic and non-secret. It keeps
		// unknown-account verification on the same Argon2id path without making
		// authentication availability depend on fresh entropy.
		saltDigest := sha256.Sum256([]byte("quicktransfer-dummy-access-code-salt-v1"))
		dummyHash = encodeAccessCodeHash("quicktransfer-dummy-access-code-v1", saltDigest[:16])
	})
	return dummyHash
}

func signTicket(secret []byte, purpose, subject string, lifetime time.Duration) (string, error) {
	nonce, err := randomToken(8)
	if err != nil {
		return "", err
	}
	payload := strings.Join([]string{purpose, subject, strconv.FormatInt(time.Now().Add(lifetime).Unix(), 10), nonce}, "|")
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func verifyTicket(secret []byte, ticket, purpose string) (string, error) {
	parts := strings.Split(ticket, ".")
	if len(parts) != 2 {
		return "", errors.New("invalid ticket")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(parts[0]))
	actual, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(mac.Sum(nil), actual) {
		return "", errors.New("invalid ticket")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("invalid ticket")
	}
	fields := strings.Split(string(decoded), "|")
	if len(fields) != 4 || fields[0] != purpose {
		return "", errors.New("invalid ticket")
	}
	expiresAt, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || time.Now().Unix() >= expiresAt {
		return "", errors.New("expired ticket")
	}
	return fields[1], nil
}

type rateEntry struct {
	started time.Time
	count   int
}

type RateLimiter struct {
	mu      sync.Mutex
	entries map[string]rateEntry
}

func NewRateLimiter() *RateLimiter { return &RateLimiter{entries: make(map[string]rateEntry)} }

func (limiter *RateLimiter) Allow(key string, limit int, window time.Duration) bool {
	now := time.Now()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	entry, exists := limiter.entries[key]
	if !exists || now.Sub(entry.started) >= window {
		limiter.entries[key] = rateEntry{started: now, count: 1}
		return true
	}
	if entry.count >= limit {
		return false
	}
	entry.count++
	limiter.entries[key] = entry
	if len(limiter.entries) > 10000 {
		for candidate, stored := range limiter.entries {
			if now.Sub(stored.started) > time.Hour {
				delete(limiter.entries, candidate)
			}
		}
	}
	return true
}
