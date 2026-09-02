package app

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

const maxStorageCABytes = 1024 * 1024

// NewStorageHTTPClient creates an HTTP client whose additional trust anchor is
// scoped to storage traffic. It does not modify the process-wide or operating
// system trust store, and it intentionally keeps normal hostname verification.
func NewStorageHTTPClient(caFile string) (*http.Client, error) {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("default HTTP transport has an unsupported type")
	}
	storageTransport := transport.Clone()
	if strings.TrimSpace(caFile) == "" {
		return &http.Client{Transport: storageTransport, Timeout: 15 * time.Second}, nil
	}

	info, err := os.Lstat(caFile)
	if err != nil {
		return nil, fmt.Errorf("inspect storage CA certificate: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("storage CA certificate must not be a symbolic link")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("storage CA certificate must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > maxStorageCABytes {
		return nil, fmt.Errorf("storage CA certificate size must be between 1 and %d bytes", maxStorageCABytes)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read storage CA certificate: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("storage CA certificate file contains no valid PEM certificate")
	}

	tlsConfig := storageTransport.TLSClientConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	tlsConfig.RootCAs = roots
	if tlsConfig.MinVersion < tls.VersionTLS12 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	storageTransport.TLSClientConfig = tlsConfig
	return &http.Client{Transport: storageTransport, Timeout: 15 * time.Second}, nil
}
