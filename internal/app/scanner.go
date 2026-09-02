package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

var eicarSignature = []byte("EICAR-STANDARD-ANTIVIRUS-TEST-FILE")

type ScanResult struct {
	Clean  bool
	SHA256 string
	Engine string
	Detail string
}

type Scanner struct {
	mode          string
	defenderPath  string
	mu            sync.RWMutex
	defenderReady bool
}

func NewScanner(mode string) *Scanner {
	if mode == "signature" {
		return &Scanner{mode: mode}
	}
	return &Scanner{mode: mode, defenderPath: findDefender()}
}

func (scanner *Scanner) Name() string {
	if scanner.mode == "disabled" {
		return "disabled"
	}
	scanner.mu.RLock()
	ready := scanner.defenderReady
	scanner.mu.RUnlock()
	if ready {
		return "Microsoft Defender + signature guard"
	}
	return "built-in signature guard"
}

func (scanner *Scanner) ProductionReady() bool {
	scanner.mu.RLock()
	defer scanner.mu.RUnlock()
	return scanner.defenderReady && scanner.mode != "disabled"
}

func (scanner *Scanner) Probe(ctx context.Context, dataDir string) error {
	if scanner.mode == "disabled" || scanner.mode == "signature" {
		return nil
	}
	if scanner.defenderPath == "" {
		return fmt.Errorf("Microsoft Defender command line scanner is unavailable")
	}
	probe, err := os.CreateTemp(filepath.Join(dataDir, "quarantine"), "scanner-probe-*.txt")
	if err != nil {
		return fmt.Errorf("create scanner probe: %w", err)
	}
	path := probe.Name()
	defer os.Remove(path)
	if _, err := probe.WriteString("QuickTransfer antivirus readiness probe\n"); err != nil {
		_ = probe.Close()
		return fmt.Errorf("write scanner probe: %w", err)
	}
	if err := probe.Close(); err != nil {
		return fmt.Errorf("close scanner probe: %w", err)
	}
	if _, err := scanner.runDefender(ctx, path); err != nil {
		return fmt.Errorf("Microsoft Defender readiness probe failed: %w", err)
	}
	scanner.mu.Lock()
	scanner.defenderReady = true
	scanner.mu.Unlock()
	return nil
}

func (scanner *Scanner) Scan(ctx context.Context, path string) (ScanResult, error) {
	file, err := os.Open(path)
	if err != nil {
		return ScanResult{}, err
	}
	hasher := sha256.New()
	buffer := make([]byte, 1024*1024)
	carry := make([]byte, 0, len(eicarSignature))
	malicious := false
	for {
		read, readErr := file.Read(buffer)
		if read > 0 {
			chunk := buffer[:read]
			_, _ = hasher.Write(chunk)
			combined := append(append([]byte{}, carry...), chunk...)
			if bytes.Contains(combined, eicarSignature) {
				malicious = true
			}
			keep := len(eicarSignature) - 1
			if len(combined) < keep {
				keep = len(combined)
			}
			carry = append(carry[:0], combined[len(combined)-keep:]...)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = file.Close()
			return ScanResult{}, readErr
		}
	}
	_ = file.Close()
	result := ScanResult{SHA256: hex.EncodeToString(hasher.Sum(nil)), Engine: scanner.Name()}
	if malicious {
		result.Detail = "known antivirus test signature detected"
		return result, nil
	}
	if scanner.mode == "disabled" {
		result.Clean = true
		result.Detail = "scan disabled for local development"
		return result, nil
	}
	if !scanner.ProductionReady() {
		if scanner.mode == "required" {
			return result, fmt.Errorf("Microsoft Defender scanner is required but unavailable")
		}
		result.Clean = true
		result.Detail = "signature guard passed; full antivirus unavailable"
		return result, nil
	}
	output, commandErr := scanner.runDefender(ctx, path)
	if commandErr != nil {
		result.Detail = "Microsoft Defender rejected or could not scan the file"
		if trimmed := strings.TrimSpace(string(output)); trimmed != "" {
			result.Detail += ": " + truncateText(trimmed, 240)
		}
		return result, nil
	}
	result.Clean = true
	result.Detail = "Microsoft Defender scan passed"
	return result, nil
}

func (scanner *Scanner) runDefender(ctx context.Context, path string) ([]byte, error) {
	scanCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(scanCtx, scanner.defenderPath, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation")
	return command.CombinedOutput()
}

func findDefender() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	var candidates []string
	if root := os.Getenv("ProgramData"); root != "" {
		platform := filepath.Join(root, "Microsoft", "Windows Defender", "Platform")
		entries, _ := os.ReadDir(platform)
		for _, entry := range entries {
			if entry.IsDir() {
				candidates = append(candidates, filepath.Join(platform, entry.Name(), "MpCmdRun.exe"))
			}
		}
	}
	if root := os.Getenv("ProgramFiles"); root != "" {
		candidates = append(candidates, filepath.Join(root, "Windows Defender", "MpCmdRun.exe"))
	}
	sort.Sort(sort.Reverse(sort.StringSlice(candidates)))
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

func truncateText(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "…"
}
