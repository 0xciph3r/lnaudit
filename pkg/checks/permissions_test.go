package checks

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/NonsoAmadi10/lnaudit/pkg/scanner"
)

func skipOnWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission tests not applicable on Windows")
	}
}

func TestCheckFilePermissions_TooPermissive(t *testing.T) {
	skipOnWindows(t)

	dir := t.TempDir()
	walletPath := filepath.Join(dir, "wallet.db")
	os.WriteFile(walletPath, []byte("fake-wallet"), 0644) // too permissive

	paths := FilePaths{WalletDB: walletPath}
	findings := CheckFilePermissions(paths)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != scanner.Critical {
		t.Errorf("severity = %v, want CRITICAL", findings[0].Severity)
	}
	if findings[0].Module != "keys" {
		t.Errorf("module = %q, want keys", findings[0].Module)
	}
}

func TestCheckFilePermissions_Correct(t *testing.T) {
	skipOnWindows(t)

	dir := t.TempDir()
	walletPath := filepath.Join(dir, "wallet.db")
	os.WriteFile(walletPath, []byte("fake-wallet"), 0600) // correct

	paths := FilePaths{WalletDB: walletPath}
	findings := CheckFilePermissions(paths)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for correct permissions, got %d", len(findings))
	}
}

func TestCheckFilePermissions_MissingFile(t *testing.T) {
	paths := FilePaths{WalletDB: "/nonexistent/path/wallet.db"}
	findings := CheckFilePermissions(paths)

	// Missing file should not produce a permission finding
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for missing file, got %d", len(findings))
	}
}

func TestCheckFilePermissions_EmptyPath(t *testing.T) {
	paths := FilePaths{} // all paths empty
	findings := CheckFilePermissions(paths)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty paths, got %d", len(findings))
	}
}

func TestCheckFilePermissions_MultipleFiles(t *testing.T) {
	skipOnWindows(t)

	dir := t.TempDir()

	// wallet.db: too permissive
	walletPath := filepath.Join(dir, "wallet.db")
	os.WriteFile(walletPath, []byte("w"), 0666)

	// tls.key: correct
	tlsPath := filepath.Join(dir, "tls.key")
	os.WriteFile(tlsPath, []byte("k"), 0600)

	// admin.macaroon: group-readable
	macPath := filepath.Join(dir, "admin.macaroon")
	os.WriteFile(macPath, []byte("m"), 0640)

	paths := FilePaths{
		WalletDB:      walletPath,
		TLSKey:        tlsPath,
		AdminMacaroon: macPath,
	}
	findings := CheckFilePermissions(paths)

	// wallet.db (0666) and admin.macaroon (0640) should be flagged
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

func TestCheckFilePermissions_ConfigFile640(t *testing.T) {
	skipOnWindows(t)

	dir := t.TempDir()
	confPath := filepath.Join(dir, "lnd.conf")
	os.WriteFile(confPath, []byte("[Application Options]\n"), 0640) // acceptable

	paths := FilePaths{ConfigFile: confPath}
	findings := CheckFilePermissions(paths)

	if len(findings) != 0 {
		t.Errorf("0640 should be acceptable for lnd.conf, got %d findings", len(findings))
	}
}

func TestCheckFilePermissions_ConfigFile644(t *testing.T) {
	skipOnWindows(t)

	dir := t.TempDir()
	confPath := filepath.Join(dir, "lnd.conf")
	os.WriteFile(confPath, []byte("[Application Options]\n"), 0644) // world-readable

	paths := FilePaths{ConfigFile: confPath}
	findings := CheckFilePermissions(paths)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for world-readable lnd.conf, got %d", len(findings))
	}
	if findings[0].Severity != scanner.High {
		t.Errorf("severity = %v, want HIGH", findings[0].Severity)
	}
}

func TestCheckFilePermissions_TorOnionKey(t *testing.T) {
	skipOnWindows(t)

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "v3_onion_private_key")
	os.WriteFile(keyPath, []byte("onion-key"), 0644)

	paths := FilePaths{TorOnionKey: keyPath}
	findings := CheckFilePermissions(paths)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for permissive onion key, got %d", len(findings))
	}
	if findings[0].Severity != scanner.Critical {
		t.Errorf("severity = %v, want CRITICAL", findings[0].Severity)
	}
}

func TestCheckFilePermissions_SymlinkDetection(t *testing.T) {
	skipOnWindows(t)

	dir := t.TempDir()
	realFile := filepath.Join(dir, "real_wallet.db")
	os.WriteFile(realFile, []byte("real"), 0600)

	symlinkPath := filepath.Join(dir, "wallet.db")
	os.Symlink(realFile, symlinkPath)

	paths := FilePaths{WalletDB: symlinkPath}
	findings := CheckFilePermissions(paths)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for symlinked wallet.db, got %d", len(findings))
	}
	if findings[0].Severity != scanner.High {
		t.Errorf("severity = %v, want HIGH for symlink", findings[0].Severity)
	}
}

func TestIsOverlyPermissive(t *testing.T) {
	tests := []struct {
		actual, max os.FileMode
		overly      bool
	}{
		{0600, 0600, false},
		{0644, 0600, true},
		{0640, 0640, false},
		{0640, 0600, true},
		{0600, 0640, false},
		{0666, 0600, true},
		{0400, 0600, false},
		{0700, 0600, true}, // execute bit on owner exceeds 0600
	}
	for _, tt := range tests {
		got := isOverlyPermissive(tt.actual, tt.max)
		if got != tt.overly {
			t.Errorf("isOverlyPermissive(%04o, %04o) = %v, want %v",
				tt.actual, tt.max, got, tt.overly)
		}
	}
}
