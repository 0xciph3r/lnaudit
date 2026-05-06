package lndpath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetect_ExplicitPaths(t *testing.T) {
	dir := t.TempDir()
	confFile := filepath.Join(dir, "lnd.conf")
	if err := os.WriteFile(confFile, []byte("[Application Options]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := Detect(dir, confFile)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if p.LndDir != dir {
		t.Errorf("LndDir = %q, want %q", p.LndDir, dir)
	}
	if p.ConfigFile != confFile {
		t.Errorf("ConfigFile = %q, want %q", p.ConfigFile, confFile)
	}
}

func TestDetect_AutoFindConfig(t *testing.T) {
	dir := t.TempDir()
	confFile := filepath.Join(dir, DefaultConfigName)
	if err := os.WriteFile(confFile, []byte("[Application Options]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := Detect(dir, "")
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if p.ConfigFile != confFile {
		t.Errorf("ConfigFile = %q, want %q", p.ConfigFile, confFile)
	}
}

func TestDetect_NoConfigFile(t *testing.T) {
	dir := t.TempDir()

	p, err := Detect(dir, "")
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if p.ConfigFile != "" {
		t.Errorf("ConfigFile = %q, want empty (no config found)", p.ConfigFile)
	}
}

func TestDetect_DataDirFromConfig(t *testing.T) {
	dir := t.TempDir()
	customData := filepath.Join(dir, "custom-data")
	confContent := "[Application Options]\ndatadir=" + customData + "\n"
	confFile := filepath.Join(dir, DefaultConfigName)
	if err := os.WriteFile(confFile, []byte(confContent), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := Detect(dir, "")
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if p.DataDir != customData {
		t.Errorf("DataDir = %q, want %q (should be read from config)", p.DataDir, customData)
	}
}

func TestDetect_DataDirFallback(t *testing.T) {
	dir := t.TempDir()
	// Config exists but has no datadir key
	confFile := filepath.Join(dir, DefaultConfigName)
	if err := os.WriteFile(confFile, []byte("[Application Options]\nalias=mynode\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := Detect(dir, "")
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	want := filepath.Join(dir, "data")
	if p.DataDir != want {
		t.Errorf("DataDir = %q, want %q (should fallback to <lnddir>/data)", p.DataDir, want)
	}
}

func TestPaths_ChainDir(t *testing.T) {
	dataDir := "/home/user/.lnd/data"
	p := Paths{
		DataDir: dataDir,
		Chain:   "bitcoin",
		Network: "mainnet",
	}

	want := filepath.Join(dataDir, "chain", "bitcoin", "mainnet")
	if got := p.ChainDir(); got != want {
		t.Errorf("ChainDir() = %q, want %q", got, want)
	}
}

func TestPaths_FileLocations(t *testing.T) {
	dataDir := "/home/user/.lnd/data"
	p := Paths{
		DataDir: dataDir,
		Chain:   "bitcoin",
		Network: "mainnet",
	}
	chainDir := p.ChainDir()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"WalletDB", p.WalletDB(), filepath.Join(chainDir, "wallet.db")},
		{"ChannelBackup", p.ChannelBackup(), filepath.Join(chainDir, "channel.backup")},
		{"AdminMacaroon", p.AdminMacaroon(), filepath.Join(chainDir, "admin.macaroon")},
		{"ReadonlyMacaroon", p.ReadonlyMacaroon(), filepath.Join(chainDir, "readonly.macaroon")},
		{"InvoiceMacaroon", p.InvoiceMacaroon(), filepath.Join(chainDir, "invoice.macaroon")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s() = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestDefaultLndDir(t *testing.T) {
	dir := defaultLndDir()
	if dir == "" {
		t.Error("defaultLndDir() returned empty string")
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home dir")
	}

	got := expandHome("~/some/path")
	want := filepath.Join(home, "some", "path")
	if got != want {
		t.Errorf("expandHome(~/some/path) = %q, want %q", got, want)
	}
}

func TestExpandHome_NoTilde(t *testing.T) {
	got := expandHome("/absolute/path")
	if got != "/absolute/path" {
		t.Errorf("expandHome(/absolute/path) = %q, want /absolute/path", got)
	}
}
