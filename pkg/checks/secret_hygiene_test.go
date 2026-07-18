package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0xciph3r/lnaudit/pkg/scanner"
)

func TestCheckSecretHygieneLeaks_FindsStrayTLSKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	outside := filepath.Join(home, "backup")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "tls.key"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}

	lndDir := filepath.Join(home, ".lnd")
	dataDir := filepath.Join(lndDir, "data")
	findings := CheckSecretHygieneLeaks(lndDir, dataDir)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "H-7a" || findings[0].Severity != scanner.High {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestCheckSecretHygieneLeaks_IgnoresTLSKeyInsideLndDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	lndDir := filepath.Join(home, ".lnd")
	if err := os.MkdirAll(lndDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lndDir, "tls.key"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := CheckSecretHygieneLeaks(lndDir, filepath.Join(lndDir, "data"))
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestCheckSecretHygieneLeaks_FindsSeedMaterial(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	seedDir := filepath.Join(home, "notes")
	if err := os.MkdirAll(seedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(seedDir, "wallet.seed"), []byte("seed words"), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := CheckSecretHygieneLeaks(filepath.Join(home, ".lnd"), filepath.Join(home, ".lnd", "data"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "H-7b" || findings[0].Severity != scanner.Critical {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestCheckSecretHygieneLeaks_SensitiveEnvWithUnsafePerms(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	envDir := filepath.Join(home, "deploy")
	if err := os.MkdirAll(envDir, 0o700); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(envDir, ".env.production")
	content := []byte("API_KEY=abc123\nNODE_ENV=production\n")
	if err := os.WriteFile(envPath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	findings := CheckSecretHygieneLeaks(filepath.Join(home, ".lnd"), filepath.Join(home, ".lnd", "data"))
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	ids := map[string]bool{}
	for _, f := range findings {
		ids[f.ID] = true
	}
	if !ids["H-7c"] || !ids["H-7d"] {
		t.Fatalf("expected H-7c and H-7d, got %#v", findings)
	}
}

func TestCheckSecretHygieneLeaks_EnvWithoutSensitiveKeys(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	envDir := filepath.Join(home, "project")
	if err := os.MkdirAll(envDir, 0o700); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(envDir, ".env")
	if err := os.WriteFile(envPath, []byte("LOG_LEVEL=info\nPORT=8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := CheckSecretHygieneLeaks(filepath.Join(home, ".lnd"), filepath.Join(home, ".lnd", "data"))
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}
