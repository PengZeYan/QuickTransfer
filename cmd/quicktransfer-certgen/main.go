package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	rootCertificateName = "root-ca.pem"
	rootDERName         = "root-ca.cer"
	rootPrivateKeyName  = "root-ca-private-key.pem"
	leafCertificateName = "fullchain.pem"
	leafPrivateKeyName  = "private-key.pem"
)

type issueResult struct {
	Status               string   `json:"status"`
	IPAddress            string   `json:"ipAddress"`
	RootCreated          bool     `json:"rootCreated"`
	RootCertificate      string   `json:"rootCertificate"`
	RootDERCertificate   string   `json:"rootDerCertificate"`
	RootSHA256           string   `json:"rootSha256"`
	Certificate          string   `json:"certificate"`
	PrivateKey           string   `json:"privateKey"`
	CertificateSHA256    string   `json:"certificateSha256"`
	CertificateNotBefore string   `json:"certificateNotBefore"`
	CertificateNotAfter  string   `json:"certificateNotAfter"`
	SubjectAltNames      []string `json:"subjectAltNames"`
}

type verifyResult struct {
	Status              string   `json:"status"`
	IPAddress           string   `json:"ipAddress"`
	RootSHA256          string   `json:"rootSha256"`
	CertificateSHA256   string   `json:"certificateSha256"`
	CertificateNotAfter string   `json:"certificateNotAfter"`
	SubjectAltNames     []string `json:"subjectAltNames"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "quicktransfer-certgen:", err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("expected one of: issue, verify-files, verify-url")
	}
	var result any
	var err error
	switch args[0] {
	case "issue":
		result, err = runIssue(args[1:])
	case "verify-files":
		result, err = runVerifyFiles(args[1:])
	case "verify-url":
		result, err = runVerifyURL(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func runIssue(args []string) (issueResult, error) {
	set := flag.NewFlagSet("issue", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	ipText := set.String("ip", "", "public IPv4 or IPv6 address")
	pkiDir := set.String("pki-dir", "", "directory for the private CA")
	tlsDir := set.String("tls-dir", "", "directory for the node certificate")
	rootYears := set.Int("root-years", 10, "private root lifetime in years")
	leafDays := set.Int("leaf-days", 397, "node certificate lifetime in days")
	renew := set.Bool("renew", false, "replace an existing node certificate")
	if err := set.Parse(args); err != nil {
		return issueResult{}, err
	}
	ip := net.ParseIP(strings.TrimSpace(*ipText))
	if ip == nil {
		return issueResult{}, errors.New("-ip must be a valid IPv4 or IPv6 address")
	}
	if *pkiDir == "" || *tlsDir == "" {
		return issueResult{}, errors.New("-pki-dir and -tls-dir are required")
	}
	if *rootYears < 1 || *rootYears > 20 || *leafDays < 1 || *leafDays > 397 {
		return issueResult{}, errors.New("root-years must be 1-20 and leaf-days must be 1-397")
	}
	pkiRoot, err := cleanAbsoluteDirectory(*pkiDir)
	if err != nil {
		return issueResult{}, fmt.Errorf("pki directory: %w", err)
	}
	tlsRoot, err := cleanAbsoluteDirectory(*tlsDir)
	if err != nil {
		return issueResult{}, fmt.Errorf("tls directory: %w", err)
	}
	if sameOrNested(pkiRoot, tlsRoot) {
		return issueResult{}, errors.New("pki-dir and tls-dir must be independent, non-nested directories")
	}
	if err := os.MkdirAll(pkiRoot, 0o700); err != nil {
		return issueResult{}, err
	}
	if err := os.MkdirAll(tlsRoot, 0o700); err != nil {
		return issueResult{}, err
	}

	rootCertPath := filepath.Join(pkiRoot, rootCertificateName)
	rootDERPath := filepath.Join(pkiRoot, rootDERName)
	rootKeyPath := filepath.Join(pkiRoot, rootPrivateKeyName)
	rootCert, rootKey, rootCreated, err := loadOrCreateRoot(rootCertPath, rootDERPath, rootKeyPath, *rootYears)
	if err != nil {
		return issueResult{}, err
	}

	leafCertPath := filepath.Join(tlsRoot, leafCertificateName)
	leafKeyPath := filepath.Join(tlsRoot, leafPrivateKeyName)
	if !*renew {
		leafCertificateExists := pathExists(leafCertPath)
		leafKeyExists := pathExists(leafKeyPath)
		if leafCertificateExists != leafKeyExists {
			return issueResult{}, errors.New("node certificate is incomplete; use -renew only after reviewing the existing files")
		}
		if leafCertificateExists {
			verified, err := verifyCertificateFiles(ip, rootCertPath, leafCertPath, leafKeyPath)
			if err != nil {
				return issueResult{}, fmt.Errorf("existing node certificate is not reusable; use -renew only after review: %w", err)
			}
			return issueResult{
				Status:              "reused",
				IPAddress:           verified.IPAddress,
				RootCreated:         rootCreated,
				RootCertificate:     rootCertPath,
				RootDERCertificate:  rootDERPath,
				RootSHA256:          verified.RootSHA256,
				Certificate:         leafCertPath,
				PrivateKey:          leafKeyPath,
				CertificateSHA256:   verified.CertificateSHA256,
				CertificateNotAfter: verified.CertificateNotAfter,
				SubjectAltNames:     verified.SubjectAltNames,
			}, nil
		}
	}
	leafCert, leafKeyPEM, fullChain, err := createLeaf(rootCert, rootKey, ip, *leafDays)
	if err != nil {
		return issueResult{}, err
	}
	if err := writeAtomic(leafKeyPath, leafKeyPEM, 0o600, *renew); err != nil {
		return issueResult{}, fmt.Errorf("write node private key: %w", err)
	}
	if err := writeAtomic(leafCertPath, fullChain, 0o644, *renew); err != nil {
		return issueResult{}, fmt.Errorf("write node certificate: %w", err)
	}
	if _, err := verifyCertificateFiles(ip, rootCertPath, leafCertPath, leafKeyPath); err != nil {
		return issueResult{}, fmt.Errorf("verify generated certificate: %w", err)
	}
	return issueResult{
		Status:               "issued",
		IPAddress:            ip.String(),
		RootCreated:          rootCreated,
		RootCertificate:      rootCertPath,
		RootDERCertificate:   rootDERPath,
		RootSHA256:           certificateSHA256(rootCert),
		Certificate:          leafCertPath,
		PrivateKey:           leafKeyPath,
		CertificateSHA256:    certificateSHA256(leafCert),
		CertificateNotBefore: leafCert.NotBefore.UTC().Format(time.RFC3339),
		CertificateNotAfter:  leafCert.NotAfter.UTC().Format(time.RFC3339),
		SubjectAltNames:      []string{"IP:" + ip.String()},
	}, nil
}

func runVerifyFiles(args []string) (verifyResult, error) {
	set := flag.NewFlagSet("verify-files", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	ipText := set.String("ip", "", "expected IP address")
	caPath := set.String("ca", "", "root CA PEM file")
	certPath := set.String("cert", "", "node certificate/full-chain PEM file")
	keyPath := set.String("key", "", "node PKCS#8 private-key PEM file")
	if err := set.Parse(args); err != nil {
		return verifyResult{}, err
	}
	ip := net.ParseIP(strings.TrimSpace(*ipText))
	if ip == nil || *caPath == "" || *certPath == "" || *keyPath == "" {
		return verifyResult{}, errors.New("-ip, -ca, -cert, and -key are required")
	}
	return verifyCertificateFiles(ip, *caPath, *certPath, *keyPath)
}

func runVerifyURL(args []string) (verifyResult, error) {
	set := flag.NewFlagSet("verify-url", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	urlText := set.String("url", "", "HTTPS origin to verify")
	caPath := set.String("ca", "", "root CA PEM file")
	timeout := set.Duration("timeout", 10*time.Second, "connection timeout")
	if err := set.Parse(args); err != nil {
		return verifyResult{}, err
	}
	uri, err := url.Parse(*urlText)
	if err != nil || uri.Scheme != "https" || uri.Hostname() == "" || uri.User != nil || uri.Path != "" || uri.RawQuery != "" || uri.Fragment != "" {
		return verifyResult{}, errors.New("-url must be an exact HTTPS origin")
	}
	ip := net.ParseIP(uri.Hostname())
	if ip == nil {
		return verifyResult{}, errors.New("private-IP verification requires an IP-literal HTTPS origin")
	}
	rootCert, roots, err := loadRootPool(*caPath)
	if err != nil {
		return verifyResult{}, err
	}
	port := uri.Port()
	if port == "" {
		port = "443"
	}
	dialer := &net.Dialer{Timeout: *timeout}
	connection, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(uri.Hostname(), port), &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		ServerName: uri.Hostname(),
	})
	if err != nil {
		return verifyResult{}, err
	}
	defer connection.Close()
	state := connection.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return verifyResult{}, errors.New("TLS endpoint returned no peer certificate")
	}
	leaf := state.PeerCertificates[0]
	return verifyResult{
		Status:              "verified",
		IPAddress:           ip.String(),
		RootSHA256:          certificateSHA256(rootCert),
		CertificateSHA256:   certificateSHA256(leaf),
		CertificateNotAfter: leaf.NotAfter.UTC().Format(time.RFC3339),
		SubjectAltNames:     []string{"IP:" + ip.String()},
	}, nil
}

func loadOrCreateRoot(certPath, derPath, keyPath string, years int) (*x509.Certificate, *ecdsa.PrivateKey, bool, error) {
	exists := []bool{pathExists(certPath), pathExists(derPath), pathExists(keyPath)}
	if exists[0] || exists[1] || exists[2] {
		if !exists[0] || !exists[1] || !exists[2] {
			return nil, nil, false, errors.New("private CA is incomplete; refusing to replace or guess missing files")
		}
		cert, err := readFirstCertificate(certPath)
		if err != nil {
			return nil, nil, false, err
		}
		key, err := readECDSAPrivateKey(keyPath)
		if err != nil {
			return nil, nil, false, err
		}
		if !cert.IsCA || !publicKeysEqual(cert.PublicKey, &key.PublicKey) {
			return nil, nil, false, errors.New("private CA certificate and key do not form a valid CA pair")
		}
		return cert, key, false, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, false, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "QuickTransferStorage Private Root CA", Organization: []string{"QuickTransfer"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(years, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, false, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, false, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, false, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := writeAtomic(keyPath, keyPEM, 0o600, false); err != nil {
		return nil, nil, false, err
	}
	if err := writeAtomic(certPath, certPEM, 0o644, false); err != nil {
		return nil, nil, false, err
	}
	if err := writeAtomic(derPath, der, 0o644, false); err != nil {
		return nil, nil, false, err
	}
	return cert, key, true, nil
}

func createLeaf(root *x509.Certificate, rootKey *ecdsa.PrivateKey, ip net.IP, days int) (*x509.Certificate, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now().UTC()
	notAfter := now.Add(time.Duration(days) * 24 * time.Hour)
	if limit := root.NotAfter.Add(-24 * time.Hour); notAfter.After(limit) {
		notAfter = limit
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject: pkix.Name{
			CommonName:   "QuickTransferStorage " + ip.String(),
			Organization: []string{"QuickTransfer"},
		},
		NotBefore:   now.Add(-5 * time.Minute),
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{ip},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})...)
	return cert, keyPEM, chain, nil
}

func verifyCertificateFiles(ip net.IP, caPath, certPath, keyPath string) (verifyResult, error) {
	root, roots, err := loadRootPool(caPath)
	if err != nil {
		return verifyResult{}, err
	}
	leaf, err := readFirstCertificate(certPath)
	if err != nil {
		return verifyResult{}, err
	}
	key, err := readECDSAPrivateKey(keyPath)
	if err != nil {
		return verifyResult{}, err
	}
	if !publicKeysEqual(leaf.PublicKey, &key.PublicKey) {
		return verifyResult{}, errors.New("node certificate and private key do not match")
	}
	if err := leaf.VerifyHostname(ip.String()); err != nil {
		return verifyResult{}, fmt.Errorf("IP SAN verification failed: %w", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: ip.String(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return verifyResult{}, fmt.Errorf("certificate chain verification failed: %w", err)
	}
	return verifyResult{
		Status:              "verified",
		IPAddress:           ip.String(),
		RootSHA256:          certificateSHA256(root),
		CertificateSHA256:   certificateSHA256(leaf),
		CertificateNotAfter: leaf.NotAfter.UTC().Format(time.RFC3339),
		SubjectAltNames:     []string{"IP:" + ip.String()},
	}, nil
}

func loadRootPool(path string) (*x509.Certificate, *x509.CertPool, error) {
	root, err := readFirstCertificate(path)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return root, pool, nil
}

func readFirstCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("certificate PEM is invalid")
	}
	return x509.ParseCertificate(block.Bytes)
}

func readECDSAPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("private key must be PKCS#8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not ECDSA")
	}
	return key, nil
}

func publicKeysEqual(left any, right *ecdsa.PublicKey) bool {
	key, ok := left.(*ecdsa.PublicKey)
	return ok && key.Curve == right.Curve && key.X.Cmp(right.X) == 0 && key.Y.Cmp(right.Y) == 0
}

func certificateSHA256(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", digest[:])
}

func randomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil || serial.Sign() == 0 {
		panic("cryptographic random serial generation failed")
	}
	return serial
}

func cleanAbsoluteDirectory(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(absolute), nil
}

func sameOrNested(left, right string) bool {
	left = strings.TrimRight(strings.ToLower(left), string(os.PathSeparator))
	right = strings.TrimRight(strings.ToLower(right), string(os.PathSeparator))
	return left == right || strings.HasPrefix(left, right+string(os.PathSeparator)) || strings.HasPrefix(right, left+string(os.PathSeparator))
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func writeAtomic(path string, data []byte, mode os.FileMode, overwrite bool) error {
	if !overwrite && pathExists(path) {
		return fmt.Errorf("refusing to overwrite existing file %s", path)
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".qt-next-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	backup := ""
	if overwrite && pathExists(path) {
		backup = path + ".previous"
		_ = os.Remove(backup)
		if err := os.Rename(path, backup); err != nil {
			return err
		}
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		if backup != "" {
			_ = os.Rename(backup, path)
		}
		return err
	}
	if backup != "" {
		_ = os.Remove(backup)
	}
	return nil
}
