package app

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	humanVerificationTimeout     = 6 * time.Second
	turnstileSiteverifyEndpoint  = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	tencentCaptchaEndpoint       = "https://captcha.tencentcloudapi.com"
	turnstileMaximumTokenLength  = 2048
	tencentMaximumTicketLength   = 4096
	tencentMaximumRandStrLength  = 1024
	humanVerificationResponseMax = 1 << 20
)

var (
	ErrHumanVerificationRequired    = errors.New("human verification proof is required")
	ErrHumanVerificationFailed      = errors.New("human verification failed")
	ErrHumanVerificationUnavailable = errors.New("human verification is unavailable")
)

var criticalHumanVerificationActions = [...]string{
	"login",
	"register",
	"password_reset",
	"guest_transfer",
	"redeem",
}

type HumanProof struct {
	Token     string `json:"token"`
	RandStr   string `json:"randStr,omitempty"`
	Challenge string `json:"challenge,omitempty"`
}

type HumanVerificationConfig struct {
	Enabled             bool
	Provider            string
	SiteKey             string
	Secret              string
	AllowedHostnames    []string
	TencentCaptchaAppID int64
	TencentAppSecretKey string
	TencentSecretID     string
	TencentSecretKey    string
	Actions             map[string]bool
}

// HumanVerifier validates a proof for one named critical action. An action that
// is not enabled in HumanVerificationConfig.Actions is intentionally bypassed.
type HumanVerifier interface {
	Verify(ctx context.Context, action string, proof HumanProof, remoteIP string) error
}

type humanVerificationProvider interface {
	verify(ctx context.Context, action string, proof HumanProof, remoteIP string) error
}

type humanVerificationService struct {
	enabled  bool
	actions  map[string]bool
	provider humanVerificationProvider
}

type humanVerifierOptions struct {
	client   *http.Client
	endpoint string
	now      func() time.Time
	random   io.Reader
}

type turnstileVerifier struct {
	secret           string
	allowedHostnames map[string]struct{}
	client           *http.Client
	endpoint         string
	random           io.Reader
}

type tencentCaptchaVerifier struct {
	captchaAppID int64
	appSecretKey string
	secretID     string
	secretKey    string
	client       *http.Client
	endpoint     string
	now          func() time.Time
}

func NewHumanVerifier(cfg HumanVerificationConfig) (HumanVerifier, error) {
	return newHumanVerifier(cfg, humanVerifierOptions{})
}

func newHumanVerifier(cfg HumanVerificationConfig, options humanVerifierOptions) (HumanVerifier, error) {
	service := &humanVerificationService{
		enabled: cfg.Enabled,
		actions: cloneHumanVerificationActions(cfg.Actions),
	}
	if !cfg.Enabled || !hasEnabledHumanVerificationAction(service.actions) {
		return service, nil
	}

	client := options.client
	if client == nil {
		client = &http.Client{
			Timeout: humanVerificationTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	switch normalizeHumanVerificationProvider(cfg.Provider) {
	case "turnstile":
		if strings.TrimSpace(cfg.SiteKey) == "" || strings.TrimSpace(cfg.Secret) == "" {
			return nil, fmt.Errorf("%w: Turnstile site key and secret are required", ErrHumanVerificationUnavailable)
		}
		allowedHostnames, err := normalizeHumanVerificationHostnames(cfg.AllowedHostnames)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrHumanVerificationUnavailable, err)
		}
		endpoint := options.endpoint
		if endpoint == "" {
			endpoint = turnstileSiteverifyEndpoint
		}
		randomSource := options.random
		if randomSource == nil {
			randomSource = rand.Reader
		}
		service.provider = &turnstileVerifier{
			secret: cfg.Secret, allowedHostnames: allowedHostnames,
			client: client, endpoint: endpoint, random: randomSource,
		}
	case "tencent":
		if cfg.TencentCaptchaAppID <= 0 || strings.TrimSpace(cfg.TencentAppSecretKey) == "" ||
			strings.TrimSpace(cfg.TencentSecretID) == "" || strings.TrimSpace(cfg.TencentSecretKey) == "" {
			return nil, fmt.Errorf("%w: Tencent CAPTCHA credentials are incomplete", ErrHumanVerificationUnavailable)
		}
		endpoint := options.endpoint
		if endpoint == "" {
			endpoint = tencentCaptchaEndpoint
		}
		now := options.now
		if now == nil {
			now = time.Now
		}
		service.provider = &tencentCaptchaVerifier{
			captchaAppID: cfg.TencentCaptchaAppID, appSecretKey: cfg.TencentAppSecretKey,
			secretID: cfg.TencentSecretID, secretKey: cfg.TencentSecretKey,
			client: client, endpoint: endpoint, now: now,
		}
	default:
		return nil, fmt.Errorf("%w: unsupported provider", ErrHumanVerificationUnavailable)
	}
	return service, nil
}

func (service *humanVerificationService) Verify(ctx context.Context, action string, proof HumanProof, remoteIP string) error {
	if !service.enabled || !service.actions[action] {
		return nil
	}
	if service.provider == nil {
		return ErrHumanVerificationUnavailable
	}
	if ctx == nil {
		return ErrHumanVerificationUnavailable
	}
	return service.provider.verify(ctx, action, proof, remoteIP)
}

func (verifier *turnstileVerifier) verify(ctx context.Context, action string, proof HumanProof, remoteIP string) error {
	token := strings.TrimSpace(proof.Token)
	if token == "" {
		return ErrHumanVerificationRequired
	}
	if len(token) > turnstileMaximumTokenLength {
		return ErrHumanVerificationFailed
	}
	ip, err := normalizeHumanVerificationIP(remoteIP)
	if err != nil {
		return ErrHumanVerificationFailed
	}
	idempotencyKey, err := randomUUID(verifier.random)
	if err != nil {
		return fmt.Errorf("%w: could not create request identifier", ErrHumanVerificationUnavailable)
	}

	form := url.Values{
		"secret":          {verifier.secret},
		"response":        {token},
		"remoteip":        {ip},
		"idempotency_key": {idempotencyKey},
	}
	requestContext, cancel := context.WithTimeout(ctx, humanVerificationTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, verifier.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("%w: invalid Turnstile endpoint", ErrHumanVerificationUnavailable)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := verifier.client.Do(request)
	if err != nil {
		return fmt.Errorf("%w: Turnstile request failed", ErrHumanVerificationUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: Turnstile returned an unsuccessful status", ErrHumanVerificationUnavailable)
	}

	var result struct {
		Success  bool     `json:"success"`
		Hostname string   `json:"hostname"`
		Action   string   `json:"action"`
		Errors   []string `json:"error-codes"`
	}
	if err := decodeHumanVerificationJSON(response.Body, &result); err != nil {
		return fmt.Errorf("%w: invalid Turnstile response", ErrHumanVerificationUnavailable)
	}
	if !result.Success || result.Action != action {
		return ErrHumanVerificationFailed
	}
	hostname, hostnameErr := normalizeHumanVerificationHostname(result.Hostname)
	if hostnameErr != nil {
		return ErrHumanVerificationFailed
	}
	if _, allowed := verifier.allowedHostnames[hostname]; !allowed {
		return ErrHumanVerificationFailed
	}
	return nil
}

func (verifier *tencentCaptchaVerifier) verify(ctx context.Context, _ string, proof HumanProof, remoteIP string) error {
	ticket := strings.TrimSpace(proof.Token)
	randStr := strings.TrimSpace(proof.RandStr)
	if ticket == "" || randStr == "" {
		return ErrHumanVerificationRequired
	}
	if strings.HasPrefix(ticket, "trerror_") || len(ticket) > tencentMaximumTicketLength || len(randStr) > tencentMaximumRandStrLength {
		return ErrHumanVerificationFailed
	}
	ip, err := normalizeHumanVerificationIP(remoteIP)
	if err != nil {
		return ErrHumanVerificationFailed
	}

	payload, err := json.Marshal(struct {
		CaptchaType  int    `json:"CaptchaType"`
		Ticket       string `json:"Ticket"`
		UserIP       string `json:"UserIp"`
		RandStr      string `json:"Randstr"`
		CaptchaAppID int64  `json:"CaptchaAppId"`
		AppSecretKey string `json:"AppSecretKey"`
	}{
		CaptchaType: 9, Ticket: ticket, UserIP: ip, RandStr: randStr,
		CaptchaAppID: verifier.captchaAppID, AppSecretKey: verifier.appSecretKey,
	})
	if err != nil {
		return fmt.Errorf("%w: could not encode Tencent request", ErrHumanVerificationUnavailable)
	}

	requestContext, cancel := context.WithTimeout(ctx, humanVerificationTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, verifier.endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return fmt.Errorf("%w: invalid Tencent endpoint", ErrHumanVerificationUnavailable)
	}
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Header.Set("X-TC-Action", "DescribeCaptchaResult")
	request.Header.Set("X-TC-Version", "2019-07-22")
	timestamp := verifier.now().UTC()
	request.Header.Set("X-TC-Timestamp", fmt.Sprintf("%d", timestamp.Unix()))
	request.Header.Set("Authorization", tencentTC3Authorization(
		verifier.secretID, verifier.secretKey, request.URL.Host, request.URL.EscapedPath(), request.URL.RawQuery, payload, timestamp,
	))

	response, err := verifier.client.Do(request)
	if err != nil {
		return fmt.Errorf("%w: Tencent request failed", ErrHumanVerificationUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: Tencent returned an unsuccessful status", ErrHumanVerificationUnavailable)
	}

	var result struct {
		Response struct {
			CaptchaCode int `json:"CaptchaCode"`
			EvilLevel   int `json:"EvilLevel"`
			Error       *struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
		} `json:"Response"`
	}
	if err := decodeHumanVerificationJSON(response.Body, &result); err != nil {
		return fmt.Errorf("%w: invalid Tencent response", ErrHumanVerificationUnavailable)
	}
	if result.Response.Error != nil {
		return ErrHumanVerificationUnavailable
	}
	if result.Response.CaptchaCode != 1 || result.Response.EvilLevel == 100 {
		return ErrHumanVerificationFailed
	}
	return nil
}

func tencentTC3Authorization(secretID, secretKey, host, escapedPath, rawQuery string, payload []byte, timestamp time.Time) string {
	const (
		algorithm     = "TC3-HMAC-SHA256"
		service       = "captcha"
		signedHeaders = "content-type;host"
		contentType   = "application/json; charset=utf-8"
	)
	if escapedPath == "" {
		escapedPath = "/"
	}
	host = strings.ToLower(host)
	canonicalHeaders := "content-type:" + contentType + "\n" + "host:" + host + "\n"
	payloadHash := sha256.Sum256(payload)
	canonicalRequest := strings.Join([]string{
		http.MethodPost,
		escapedPath,
		rawQuery,
		canonicalHeaders,
		signedHeaders,
		hex.EncodeToString(payloadHash[:]),
	}, "\n")
	canonicalRequestHash := sha256.Sum256([]byte(canonicalRequest))
	date := timestamp.UTC().Format("2006-01-02")
	credentialScope := date + "/" + service + "/tc3_request"
	stringToSign := algorithm + "\n" + fmt.Sprintf("%d", timestamp.Unix()) + "\n" + credentialScope + "\n" + hex.EncodeToString(canonicalRequestHash[:])

	secretDate := humanVerificationHMAC([]byte("TC3"+secretKey), date)
	secretService := humanVerificationHMAC(secretDate, service)
	secretSigning := humanVerificationHMAC(secretService, "tc3_request")
	signature := hex.EncodeToString(humanVerificationHMAC(secretSigning, stringToSign))
	return algorithm + " Credential=" + secretID + "/" + credentialScope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature
}

func humanVerificationHMAC(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func decodeHumanVerificationJSON(reader io.Reader, target any) error {
	limited := io.LimitReader(reader, humanVerificationResponseMax+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(payload) == 0 || len(payload) > humanVerificationResponseMax {
		return errors.New("invalid response size")
	}
	if err := json.Unmarshal(payload, target); err != nil {
		return err
	}
	return nil
}

func randomUUID(reader io.Reader) (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(reader, value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func normalizeHumanVerificationIP(value string) (string, error) {
	value = strings.TrimSpace(value)
	if net.ParseIP(value) == nil {
		return "", errors.New("invalid remote IP")
	}
	return value, nil
}

func normalizeHumanVerificationProvider(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "cloudflare", "cloudflare-turnstile", "turnstile":
		return "turnstile"
	case "tencent", "tencent-captcha", "tencentcloud":
		return "tencent"
	default:
		return ""
	}
}

func normalizeHumanVerificationHostnames(values []string) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		hostname, err := normalizeHumanVerificationHostname(value)
		if err != nil {
			return nil, errors.New("Turnstile allowed hostnames must contain exact hostnames")
		}
		result[hostname] = struct{}{}
	}
	if len(result) == 0 {
		return nil, errors.New("at least one Turnstile allowed hostname is required")
	}
	return result, nil
}

func normalizeHumanVerificationHostname(value string) (string, error) {
	hostname := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if hostname == "" || len(hostname) > 253 || strings.Contains(hostname, "*") ||
		strings.ContainsAny(hostname, "/\\ :\t\r\n") {
		return "", errors.New("invalid exact hostname")
	}
	if parsed := net.ParseIP(hostname); parsed != nil {
		if strings.Contains(hostname, ":") {
			return "", errors.New("IPv6 literals are not valid Turnstile hostnames")
		}
		return hostname, nil
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid DNS hostname label")
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", errors.New("invalid DNS hostname character")
			}
		}
	}
	return hostname, nil
}

func cloneHumanVerificationActions(values map[string]bool) map[string]bool {
	result := make(map[string]bool, len(values))
	for action, enabled := range values {
		result[action] = enabled
	}
	return result
}

func hasEnabledHumanVerificationAction(actions map[string]bool) bool {
	for _, enabled := range actions {
		if enabled {
			return true
		}
	}
	return false
}
