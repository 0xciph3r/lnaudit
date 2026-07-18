package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0xciph3r/lnaudit/pkg/scanner"
)

func TestCheckMacaroonLeastPrivilege_ReadonlyIntegration(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfgPath := filepath.Join(home, "services", "api.yaml")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("macaroon_path=/secrets/admin.macaroon\nrpc=getinfo,listchannels\n")
	if err := os.WriteFile(cfgPath, content, 0o600); err != nil {
		t.Fatal(err)
	}

	findings := CheckMacaroonLeastPrivilege(filepath.Join(home, ".lnd"), filepath.Join(home, ".lnd", "data"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "A-4" || findings[0].Severity != scanner.High {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestCheckMacaroonLeastPrivilege_InvoiceIntegration(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfgPath := filepath.Join(home, "deploy", ".env.production")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("LND_MACAROON=/run/secrets/admin.macaroon\nLND_MODE=addinvoice\n")
	if err := os.WriteFile(cfgPath, content, 0o600); err != nil {
		t.Fatal(err)
	}

	findings := CheckMacaroonLeastPrivilege(filepath.Join(home, ".lnd"), filepath.Join(home, ".lnd", "data"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "A-5" || findings[0].Severity != scanner.High {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestCheckMacaroonLeastPrivilege_CustomScopeReview(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfgPath := filepath.Join(home, "infra", "lnd-client.conf")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("macaroon=admin.macaroon\nendpoint=localhost:10009\n")
	if err := os.WriteFile(cfgPath, content, 0o600); err != nil {
		t.Fatal(err)
	}

	findings := CheckMacaroonLeastPrivilege(filepath.Join(home, ".lnd"), filepath.Join(home, ".lnd", "data"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "A-6" || findings[0].Severity != scanner.Medium {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestCheckMacaroonLeastPrivilege_IgnoresAdminWorkloads(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfgPath := filepath.Join(home, "ops", "channel-manager.yaml")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("macaroon=admin.macaroon\nactions=openchannel,closechannel\n")
	if err := os.WriteFile(cfgPath, content, 0o600); err != nil {
		t.Fatal(err)
	}

	findings := CheckMacaroonLeastPrivilege(filepath.Join(home, ".lnd"), filepath.Join(home, ".lnd", "data"))
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for admin workload, got %d", len(findings))
	}
}

func TestCheckMacaroonLeastPrivilege_IgnoresLndDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	lndDir := filepath.Join(home, ".lnd")
	cfgPath := filepath.Join(lndDir, "integration.conf")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("macaroon=admin.macaroon\nrpc=getinfo\n")
	if err := os.WriteFile(cfgPath, content, 0o600); err != nil {
		t.Fatal(err)
	}

	findings := CheckMacaroonLeastPrivilege(lndDir, filepath.Join(lndDir, "data"))
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings inside lnd dir, got %d", len(findings))
	}
}
