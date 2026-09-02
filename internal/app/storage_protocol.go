package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	StorageHeaderNode      = "X-QT-Node"
	StorageHeaderTimestamp = "X-QT-Timestamp"
	StorageHeaderNonce     = "X-QT-Nonce"
	StorageHeaderSignature = "X-QT-Signature"
	StorageHeaderAudience  = "X-QT-Audience"
	StorageHeaderDirection = "X-QT-Direction"

	StorageUploadStatusUploading    = "uploading"
	StorageUploadStatusPendingScan  = "pending_scan"
	StorageUploadStatusScanning     = "scanning"
	StorageUploadStatusClean        = "clean"
	StorageUploadStatusBlocked      = "blocked"
	StorageUploadStatusScannerError = "scanner_error"

	StorageCompletionStatusReady       = "ready"
	StorageCompletionStatusBlocked     = "blocked"
	StorageCompletionStatusQuarantined = "quarantined"

	StorageDownloadTicketVersion = 1
	StorageDownloadTicketPurpose = "download"
	StorageDownloadTicketKeyID   = "v1"
)

const (
	storageSignatureVersion                  = "v2"
	storageInternalAudienceControl           = "quicktransfer-control"
	storageInternalAudienceStorage           = "quicktransfer-storage"
	storageInternalDirectionControlToStorage = "control-to-storage"
	storageInternalDirectionStorageToControl = "storage-to-control"
	storageInternalMaxSkew                   = 60 * time.Second
	storageProtocolBodyMax                   = 1 << 20
)

var (
	ErrStorageInternalAuth     = errors.New("storage internal authentication failed")
	ErrStorageInternalReplay   = errors.New("storage internal request replayed")
	ErrStorageInternalRedirect = errors.New("storage internal redirects are forbidden")
	ErrStorageTicketInvalid    = errors.New("invalid storage download ticket")
	ErrStorageTicketExpired    = errors.New("expired storage download ticket")
)

// StorageReserveUploadRequest is sent by the control plane. UploadTokenHash is
// the base64url-encoded SHA-256 hash of the bearer token; the raw token is never
// persisted by a storage node.
type StorageReserveUploadRequest struct {
	ID              string `json:"id"`
	UploadTokenHash string `json:"uploadTokenHash"`
	OriginalName    string `json:"originalName"`
	ContentType     string `json:"contentType"`
	Length          int64  `json:"length"`
	ExpiresAt       int64  `json:"expiresAt"`
}

type StorageReserveUploadResponse struct {
	ID        string `json:"id"`
	Length    int64  `json:"length"`
	Offset    int64  `json:"offset"`
	Status    string `json:"status"`
	ExpiresAt int64  `json:"expiresAt"`
}

type StorageHealth struct {
	Status                string `json:"status"`
	Ready                 bool   `json:"ready"`
	NodeID                string `json:"nodeId"`
	Scanner               string `json:"scanner"`
	ProductionScanner     bool   `json:"productionScanner"`
	FreeBytes             uint64 `json:"freeBytes,omitempty"`
	OutboxPending         int64  `json:"outboxPending"`
	OutboxOldestDueAt     int64  `json:"outboxOldestDueAt,omitempty"`
	OutboxOldestPendingAt int64  `json:"outboxOldestPendingAt,omitempty"`
	OutboxLastError       string `json:"outboxLastError,omitempty"`
	Version               string `json:"version"`
}

type StorageDownloadClaims struct {
	Version       int    `json:"version"`
	Purpose       string `json:"purpose"`
	KeyID         string `json:"keyId"`
	NodeID        string `json:"nodeId"`
	ReservationID string `json:"reservationId"`
	UploadID      string `json:"uploadId"`
	ExpiresAt     int64  `json:"expiresAt"`
	Nonce         string `json:"nonce"`
}

type StorageUploadCompleteRequest struct {
	NodeID     string `json:"nodeId"`
	Status     string `json:"status"`
	SHA256     string `json:"sha256"`
	ScanDetail string `json:"scanDetail"`
}

type StorageDownloadBeginRequest struct {
	NodeID   string `json:"nodeId"`
	UploadID string `json:"uploadId"`
}

type StorageDownloadSettleRequest struct {
	ActualBytes int64 `json:"actualBytes"`
}

type StorageHTTPError struct {
	StatusCode int
	Body       string
}

func (err *StorageHTTPError) Error() string {
	if err.Body == "" {
		return fmt.Sprintf("storage request returned HTTP %d", err.StatusCode)
	}
	return fmt.Sprintf("storage request returned HTTP %d: %s", err.StatusCode, err.Body)
}

// InternalReplayGuard stores recently accepted node/nonce pairs in memory.
// Its scope should match the lifetime of the HTTP server or middleware.
type InternalReplayGuard struct {
	mu   sync.Mutex
	seen map[string]int64
}

func NewInternalReplayGuard() *InternalReplayGuard {
	return &InternalReplayGuard{seen: make(map[string]int64)}
}

func (guard *InternalReplayGuard) accept(nodeID, nonce string, signedAt, now time.Time) bool {
	if guard == nil {
		return false
	}
	key := nodeID + "\x00" + nonce
	nowUnix := now.Unix()
	expiresAt := signedAt.Add(storageInternalMaxSkew).Unix()
	guard.mu.Lock()
	defer guard.mu.Unlock()
	for candidate, expiry := range guard.seen {
		if expiry < nowUnix {
			delete(guard.seen, candidate)
		}
	}
	if expiry, exists := guard.seen[key]; exists && expiry >= nowUnix {
		return false
	}
	guard.seen[key] = expiresAt
	return true
}

// SignInternalRequest adds the X-QT-* authentication and domain-binding headers. body must be
// exactly the byte sequence that will be sent in request.Body.
func SignInternalRequest(request *http.Request, nodeID string, secret, body []byte) error {
	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		return fmt.Errorf("generate internal request nonce: %w", err)
	}
	return SignInternalRequestAt(request, nodeID, secret, body, time.Now(),
		base64.RawURLEncoding.EncodeToString(nonceBytes))
}

// SignInternalRequestAt is the deterministic variant used by middleware tests
// and callers that already own a timestamp and nonce.
func SignInternalRequestAt(request *http.Request, nodeID string, secret, body []byte, at time.Time, nonce string) error {
	if request == nil || request.URL == nil || len(secret) < 32 || !validStorageNodeID(nodeID) || !validInternalNonce(nonce) {
		return ErrStorageInternalAuth
	}
	escapedPath := request.URL.EscapedPath()
	audience, direction, ok := storageInternalRequestDomain(escapedPath)
	if !ok {
		return ErrStorageInternalAuth
	}
	timestamp := strconv.FormatInt(at.Unix(), 10)
	signature := storageInternalSignature(secret, nodeID, audience, direction, request.Method, escapedPath,
		request.URL.RawQuery, timestamp, nonce, body)
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	request.Header.Set(StorageHeaderNode, nodeID)
	request.Header.Set(StorageHeaderTimestamp, timestamp)
	request.Header.Set(StorageHeaderNonce, nonce)
	request.Header.Set(StorageHeaderAudience, audience)
	request.Header.Set(StorageHeaderDirection, direction)
	request.Header.Set(StorageHeaderSignature, signature)
	return nil
}

// VerifyInternalRequest verifies an already-buffered request body and consumes
// the nonce only after all cryptographic checks pass.
func VerifyInternalRequest(request *http.Request, body, secret []byte, expectedNodeID string,
	guard *InternalReplayGuard, now time.Time) error {
	if request == nil || request.URL == nil || len(secret) < 32 || guard == nil {
		return ErrStorageInternalAuth
	}
	nodeID, ok := singleHeader(request.Header, StorageHeaderNode)
	if !ok || nodeID != expectedNodeID || !validStorageNodeID(nodeID) {
		return ErrStorageInternalAuth
	}
	timestamp, ok := singleHeader(request.Header, StorageHeaderTimestamp)
	if !ok || timestamp == "" || strings.TrimSpace(timestamp) != timestamp {
		return ErrStorageInternalAuth
	}
	timestampUnix, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return ErrStorageInternalAuth
	}
	signedAt := time.Unix(timestampUnix, 0)
	if signedAt.Before(now.Add(-storageInternalMaxSkew)) || signedAt.After(now.Add(storageInternalMaxSkew)) {
		return ErrStorageInternalAuth
	}
	nonce, ok := singleHeader(request.Header, StorageHeaderNonce)
	if !ok || !validInternalNonce(nonce) {
		return ErrStorageInternalAuth
	}
	escapedPath := request.URL.EscapedPath()
	expectedAudience, expectedDirection, ok := storageInternalRequestDomain(escapedPath)
	if !ok {
		return ErrStorageInternalAuth
	}
	audience, ok := singleHeader(request.Header, StorageHeaderAudience)
	if !ok || audience != expectedAudience {
		return ErrStorageInternalAuth
	}
	direction, ok := singleHeader(request.Header, StorageHeaderDirection)
	if !ok || direction != expectedDirection {
		return ErrStorageInternalAuth
	}
	encodedSignature, ok := singleHeader(request.Header, StorageHeaderSignature)
	if !ok {
		return ErrStorageInternalAuth
	}
	actualSignature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil || len(actualSignature) != sha256.Size ||
		base64.RawURLEncoding.EncodeToString(actualSignature) != encodedSignature {
		return ErrStorageInternalAuth
	}
	expectedEncoded := storageInternalSignature(secret, nodeID, audience, direction, request.Method, escapedPath,
		request.URL.RawQuery, timestamp, nonce, body)
	expectedSignature, _ := base64.RawURLEncoding.DecodeString(expectedEncoded)
	if !hmac.Equal(expectedSignature, actualSignature) {
		return ErrStorageInternalAuth
	}
	if !guard.accept(nodeID, nonce, signedAt, now) {
		return ErrStorageInternalReplay
	}
	return nil
}

func storageInternalSignature(secret []byte, nodeID, audience, direction, method, escapedPath, rawQuery,
	timestamp, nonce string, body []byte) string {
	if escapedPath == "" {
		escapedPath = "/"
	}
	bodyHash := sha256.Sum256(body)
	canonical := strings.Join([]string{
		storageSignatureVersion,
		nodeID,
		audience,
		direction,
		strings.ToUpper(method),
		escapedPath,
		rawQuery,
		timestamp,
		nonce,
		hex.EncodeToString(bodyHash[:]),
	}, "\n")
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func storageInternalRequestDomain(escapedPath string) (audience, direction string, ok bool) {
	if escapedPath == "/internal/v1/uploads" || strings.HasPrefix(escapedPath, "/internal/v1/uploads/") {
		return storageInternalAudienceStorage, storageInternalDirectionControlToStorage, true
	}
	if strings.HasPrefix(escapedPath, "/internal/v1/storage/") {
		return storageInternalAudienceControl, storageInternalDirectionStorageToControl, true
	}
	return "", "", false
}

func singleHeader(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1 && returnValue != ""
}

func validInternalNonce(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validStorageNodeID(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func validStorageObjectID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func SignStorageDownloadTicket(secret []byte, claims StorageDownloadClaims) (string, error) {
	if len(secret) < 32 || !validStorageDownloadClaims(claims) {
		return "", ErrStorageTicketInvalid
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encode storage download claims: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func VerifyStorageDownloadTicket(secret []byte, ticket string) (StorageDownloadClaims, error) {
	return VerifyStorageDownloadTicketAt(secret, ticket, time.Now())
}

func VerifyStorageDownloadTicketAt(secret []byte, ticket string, now time.Time) (StorageDownloadClaims, error) {
	if len(secret) < 32 || len(ticket) > 4096 {
		return StorageDownloadClaims{}, ErrStorageTicketInvalid
	}
	parts := strings.Split(ticket, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return StorageDownloadClaims{}, ErrStorageTicketInvalid
	}
	actualSignature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(actualSignature) != sha256.Size ||
		base64.RawURLEncoding.EncodeToString(actualSignature) != parts[1] {
		return StorageDownloadClaims{}, ErrStorageTicketInvalid
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(mac.Sum(nil), actualSignature) {
		return StorageDownloadClaims{}, ErrStorageTicketInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) > storageProtocolBodyMax ||
		base64.RawURLEncoding.EncodeToString(payload) != parts[0] {
		return StorageDownloadClaims{}, ErrStorageTicketInvalid
	}
	var claims StorageDownloadClaims
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil {
		return StorageDownloadClaims{}, ErrStorageTicketInvalid
	}
	if err := ensureJSONEOF(decoder); err != nil || !validStorageDownloadClaims(claims) {
		return StorageDownloadClaims{}, ErrStorageTicketInvalid
	}
	if claims.ExpiresAt <= now.Unix() {
		return StorageDownloadClaims{}, ErrStorageTicketExpired
	}
	return claims, nil
}

func validStorageDownloadClaims(claims StorageDownloadClaims) bool {
	return claims.Version == StorageDownloadTicketVersion && claims.Purpose == StorageDownloadTicketPurpose &&
		claims.KeyID == StorageDownloadTicketKeyID && validStorageNodeID(claims.NodeID) && validStorageObjectID(claims.UploadID) &&
		validStorageObjectID(claims.ReservationID) && claims.ExpiresAt > 0 && validInternalNonce(claims.Nonce)
}

type StorageInternalClient struct {
	baseURL    string
	nodeID     string
	secret     []byte
	httpClient *http.Client
}

func NewStorageInternalClient(baseURL, nodeID string, secret []byte, httpClient *http.Client) *StorageInternalClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	internalHTTPClient := *httpClient
	internalHTTPClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return ErrStorageInternalRedirect
	}
	return &StorageInternalClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"), nodeID: nodeID,
		secret: append([]byte(nil), secret...), httpClient: &internalHTTPClient,
	}
}

func (client *StorageInternalClient) ReserveUpload(ctx context.Context,
	payload StorageReserveUploadRequest) (StorageReserveUploadResponse, error) {
	var response StorageReserveUploadResponse
	body, err := json.Marshal(payload)
	if err != nil {
		return response, err
	}
	responseBody, status, err := client.sendSigned(ctx, http.MethodPost, "/internal/v1/uploads", body)
	if err != nil {
		return response, err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return response, newStorageHTTPError(status, responseBody)
	}
	if err := decodeStorageProtocolJSON(responseBody, &response); err != nil {
		return StorageReserveUploadResponse{}, fmt.Errorf("decode storage reserve response: %w", err)
	}
	return response, nil
}

func (client *StorageInternalClient) DeleteUpload(ctx context.Context, id string) error {
	if !validStorageObjectID(id) {
		return errors.New("invalid storage upload id")
	}
	responseBody, status, err := client.sendSigned(ctx, http.MethodDelete,
		"/internal/v1/uploads/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return newStorageHTTPError(status, responseBody)
	}
	return nil
}

func (client *StorageInternalClient) Health(ctx context.Context) (StorageHealth, error) {
	var health StorageHealth
	request, err := client.newRequest(ctx, http.MethodGet, "/storage/health/ready", nil)
	if err != nil {
		return health, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return health, err
	}
	responseBody, readErr := readStorageResponse(response)
	if readErr != nil {
		return health, readErr
	}
	if response.StatusCode != http.StatusOK {
		return health, newStorageHTTPError(response.StatusCode, responseBody)
	}
	if err := decodeStorageProtocolJSON(responseBody, &health); err != nil {
		return StorageHealth{}, fmt.Errorf("decode storage health: %w", err)
	}
	return health, nil
}

func (client *StorageInternalClient) sendSigned(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	request, err := client.newRequest(ctx, method, path, body)
	if err != nil {
		return nil, 0, err
	}
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	if err := SignInternalRequest(request, client.nodeID, client.secret, body); err != nil {
		return nil, 0, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, 0, err
	}
	responseBody, readErr := readStorageResponse(response)
	return responseBody, response.StatusCode, readErr
}

func (client *StorageInternalClient) newRequest(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	if client == nil || client.baseURL == "" || !validStorageNodeID(client.nodeID) || len(client.secret) < 32 {
		return nil, errors.New("invalid storage internal client configuration")
	}
	parsedBase, err := url.Parse(client.baseURL)
	if err != nil || parsedBase.Scheme == "" || parsedBase.Host == "" || parsedBase.RawQuery != "" || parsedBase.Fragment != "" {
		return nil, errors.New("invalid storage internal base URL")
	}
	parsedPath, err := url.Parse(path)
	if err != nil || !strings.HasPrefix(path, "/") {
		return nil, errors.New("invalid storage internal request path")
	}
	parsedBase.Path, parsedBase.RawPath = "", ""
	target := parsedBase.ResolveReference(parsedPath).String()
	return http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
}

func readStorageResponse(response *http.Response) ([]byte, error) {
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, storageProtocolBodyMax+1))
	if err != nil {
		return nil, err
	}
	if len(body) > storageProtocolBodyMax {
		return nil, errors.New("storage response is too large")
	}
	return body, nil
}

func newStorageHTTPError(status int, body []byte) error {
	return &StorageHTTPError{StatusCode: status, Body: truncateText(strings.TrimSpace(string(body)), 512)}
}

func decodeStorageProtocolJSON(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
