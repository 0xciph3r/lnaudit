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
	// Point HOME at an empty temp dir -- no macaroons should be found.
	home := t.TempDir()
	t.Setenv("HOME", home)

	findings := CheckAdminMacaroonLeaks(home)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in empty dir, got %d", len(findings))
	}
}

func TestCheckAdminMacaroonLeaks_FindsStray(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Place a stray admin.macaroon one level inside home.
	strayDir := filepath.Join(home, "projects")
	if err := os.Mkdir(strayDir, 0o700); err != nil {
		t.Fatal(err)
	}
	strayPath := filepath.Join(strayDir, "admin.macaroon")
	if err := os.WriteFile(strayPath, []byte("fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	lndDir := filepath.Join(home, ".lnd")
	findings := CheckAdminMacaroonLeaks(lndDir)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for stray admin.macaroon, got %d", len(findings))
	}
	if findings[0].Severity != scanner.Critical {
		t.Errorf("severity = %v, want CRITICAL for admin.macaroon", findings[0].Severity)
	}
}

func TestCheckAdminMacaroonLeaks_IgnoresLndDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	lndDir := filepath.Join(home, ".lnd", "data", "chain", "bitcoin", "mainnet")
	if err := os.MkdirAll(lndDir, 0o700); err != nil {
		t.Fatal(err)
	}
	macPath := filepath.Join(lndDir, "admin.macaroon")
	if err := os.WriteFile(macPath, []byte("fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := CheckAdminMacaroonLeaks(lndDir)
	if len(findings) != 0 {
		t.Errorf("should ignore macaroons inside LND data dir, got %d findings", len(findings))
	}
}

func TestCheckAdminMacaroonLeaks_SiblingDirNotIgnored(t *testing.T) {
	// /home/lnddata and /home/lnddata2 are siblings -- a file in lnddata2
	// must NOT be excluded when lndDataDir is lnddata.
	home := t.TempDir()
	t.Setenv("HOME", home)

	lndDir := filepath.Join(home, "lnddata")
	siblingDir := filepath.Join(home, "lnddata2")
	if err := os.MkdirAll(lndDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(siblingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	siblingMac := filepath.Join(siblingDir, "admin.macaroon")
	if err := os.WriteFile(siblingMac, []byte("fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := CheckAdminMacaroonLeaks(lndDir)
	if len(findings) != 1 {
		t.Fatalf("sibling path should produce 1 finding, got %d", len(findings))
	}
}

func TestCheckAdminMacaroonLeaks_DepthLimit(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Build a chain: home/a/b/c/d/admin.macaroon (depth 4 from home -- included)
	deepDir := filepath.Join(home, "a", "b", "c", "d")
	if err := os.MkdirAll(deepDir, 0o700); err != nil {
		t.Fatal(err)
	}
	deepMac := filepath.Join(deepDir, "admin.macaroon")
	if err := os.WriteFile(deepMac, []byte("fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Build a chain: home/a/b/c/d/e/admin.macaroon (depth 5 -- excluded)
	tooDeepDir := filepath.Join(home, "a", "b", "c", "d", "e")
	if err := os.MkdirAll(tooDeepDir, 0o700); err != nil {
		t.Fatal(err)
	}
	tooDeepMac := filepath.Join(tooDeepDir, "admin.macaroon")
	if err := os.WriteFile(tooDeepMac, []byte("fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := CheckAdminMacaroonLeaks("")
	if len(findings) != 1 {
		t.Errorf("expected exactly 1 finding (depth 4 included, depth 5 excluded), got %d", len(findings))
	}
	if len(findings) == 1 && findings[0].Severity != scanner.Critical {
		t.Errorf("finding should be CRITICAL, got %v", findings[0].Severity)
	}
}

func TestCheckAdminMacaroonLeaks_SkipDirsNotTraversed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Place a macaroon inside a skipDir -- it must NOT be reported.
	gitDir := filepath.Join(home, ".git")
	if err := os.Mkdir(gitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	gitMac := filepath.Join(gitDir, "admin.macaroon")
	if err := os.WriteFile(gitMac, []byte("fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Place a macaroon in a normal dir -- it MUST be reported.
	normalDir := filepath.Join(home, "backup")
	if err := os.Mkdir(normalDir, 0o700); err != nil {
		t.Fatal(err)
	}
	normalMac := filepath.Join(normalDir, "admin.macaroon")
	if err := os.WriteFile(normalMac, []byte("fake"), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := CheckAdminMacaroonLeaks("")
	if len(findings) != 1 {
		t.Errorf("expected 1 finding (skip dir excluded), got %d", len(findings))
	}
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
