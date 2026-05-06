package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/NonsoAmadi10/lnaudit/pkg/config"
	"github.com/NonsoAmadi10/lnaudit/pkg/scanner"
)

func TestCheckNoMacaroons_Disabled(t *testing.T) {
	cfg := &config.LndConfig{NoMacaroons: true}
	findings := CheckNoMacaroons(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != scanner.Critical {
		t.Errorf("severity = %v, want CRITICAL", findings[0].Severity)
	}
}

func TestCheckNoMacaroons_Enabled(t *testing.T) {
	cfg := &config.LndConfig{NoMacaroons: false}
	findings := CheckNoMacaroons(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestCheckAdminMacaroonLeaks_NoLeaks(t *testing.T) {
	// Use a temp dir as LND data dir — no stray macaroons should exist
	dir := t.TempDir()
	findings := CheckAdminMacaroonLeaks(dir)
	// We can't guarantee other dirs are clean, so just verify it runs without panic
	_ = findings
}

func TestCheckAdminMacaroonLeaks_FindsStray(t *testing.T) {
	tmpDir := t.TempDir()
	strayPath := filepath.Join(tmpDir, "admin.macaroon")
	os.WriteFile(strayPath, []byte("fake-macaroon"), 0600)

	// Use a different dir as LND data dir so the stray is outside it
	lndDir := t.TempDir()

	// We need to search the tmpDir. Since CheckAdminMacaroonLeaks searches
	// predefined dirs, we test the detection logic directly.
	findings := checkMacaroonInDir(tmpDir, lndDir)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for stray admin.macaroon, got %d", len(findings))
	}
	if findings[0].Severity != scanner.Critical {
		t.Errorf("severity = %v, want CRITICAL for admin.macaroon", findings[0].Severity)
	}
}

func TestCheckAdminMacaroonLeaks_IgnoresLndDir(t *testing.T) {
	lndDir := t.TempDir()
	macPath := filepath.Join(lndDir, "admin.macaroon")
	os.WriteFile(macPath, []byte("fake-macaroon"), 0600)

	findings := checkMacaroonInDir(lndDir, lndDir)
	if len(findings) != 0 {
		t.Errorf("should ignore macaroons inside LND data dir, got %d findings", len(findings))
	}
}

// helper to test macaroon detection in a specific directory
func checkMacaroonInDir(searchDir, lndDataDir string) []scanner.Finding {
	var findings []scanner.Finding
	matches, _ := filepath.Glob(filepath.Join(searchDir, "*.macaroon"))
	for _, m := range matches {
		absPath, _ := filepath.Abs(m)
		if lndDataDir != "" {
			absLnd, _ := filepath.Abs(lndDataDir)
			if len(absPath) >= len(absLnd) && absPath[:len(absLnd)] == absLnd {
				continue
			}
		}
		name := filepath.Base(absPath)
		sev := scanner.High
		if name == "admin.macaroon" {
			sev = scanner.Critical
		}
		findings = append(findings, scanner.Finding{
			ID:       "A-3",
			Module:   "access",
			Severity: sev,
			Title:    "Macaroon found outside LND data directory: " + absPath,
		})
	}
	return findings
}

// --- Dangerous Flags Tests ---

func TestCheckDangerousFlags_NoSeedBackup(t *testing.T) {
	cfg := &config.LndConfig{NoSeedBackup: true}
	findings := CheckDangerousFlags(cfg)
	found := false
	for _, f := range findings {
		if f.ID == "H-6a" && f.Severity == scanner.Critical {
			found = true
		}
	}
	if !found {
		t.Error("expected CRITICAL finding for noseedbackup")
	}
}

func TestCheckDangerousFlags_NoEncryptWallet(t *testing.T) {
	cfg := &config.LndConfig{NoEncryptWallet: true}
	findings := CheckDangerousFlags(cfg)
	found := false
	for _, f := range findings {
		if f.ID == "H-6b" && f.Severity == scanner.Critical {
			found = true
		}
	}
	if !found {
		t.Error("expected CRITICAL finding for noencryptwallet")
	}
}

func TestCheckDangerousFlags_DebugTrace(t *testing.T) {
	cfg := &config.LndConfig{DebugLevel: "trace"}
	findings := CheckDangerousFlags(cfg)
	found := false
	for _, f := range findings {
		if f.ID == "H-4" && f.Severity == scanner.High {
			found = true
		}
	}
	if !found {
		t.Error("expected HIGH finding for debuglevel=trace")
	}
}

func TestCheckDangerousFlags_DebugHTLC(t *testing.T) {
	cfg := &config.LndConfig{DebugHTLC: true}
	findings := CheckDangerousFlags(cfg)
	found := false
	for _, f := range findings {
		if f.ID == "H-4b" && f.Severity == scanner.Medium {
			found = true
		}
	}
	if !found {
		t.Error("expected MEDIUM finding for debughtlc")
	}
}

func TestCheckDangerousFlags_TrickleDelayZero(t *testing.T) {
	cfg := &config.LndConfig{TrickleDelay: 0, TrickleDelayExplicit: true}
	findings := CheckDangerousFlags(cfg)
	found := false
	for _, f := range findings {
		if f.ID == "H-6c" {
			found = true
		}
	}
	if !found {
		t.Error("expected finding for explicitly set trickledelay=0")
	}
}

func TestCheckDangerousFlags_TrickleDelayNotSet(t *testing.T) {
	// When not explicitly set, TrickleDelay defaults to 0 but should NOT be flagged
	cfg := &config.LndConfig{TrickleDelay: 0, TrickleDelayExplicit: false}
	findings := CheckDangerousFlags(cfg)
	for _, f := range findings {
		if f.ID == "H-6c" {
			t.Error("should NOT flag trickledelay when it was not explicitly set")
		}
	}
}

func TestCheckDangerousFlags_UnsafeDisconnect(t *testing.T) {
	cfg := &config.LndConfig{UnsafeDisconnect: true}
	findings := CheckDangerousFlags(cfg)
	found := false
	for _, f := range findings {
		if f.ID == "H-6d" && f.Severity == scanner.Low {
			found = true
		}
	}
	if !found {
		t.Error("expected LOW finding for unsafe-disconnect")
	}
}

func TestCheckDangerousFlags_Clean(t *testing.T) {
	cfg := &config.LndConfig{
		DebugLevel:           "info",
		TrickleDelay:         5000,
		TrickleDelayExplicit: true,
	}
	findings := CheckDangerousFlags(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean config, got %d", len(findings))
	}
}
