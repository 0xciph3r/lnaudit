package lndpath

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Defaults for LND installations across platforms.
const (
	DefaultConfigName = "lnd.conf"
	DefaultTLSCert    = "tls.cert"
	DefaultTLSKey     = "tls.key"
	DefaultWalletDB   = "wallet.db"
	DefaultChannelBak = "channel.backup"
	DefaultAdminMac   = "admin.macaroon"
	DefaultReadMac    = "readonly.macaroon"
	DefaultInvoiceMac = "invoice.macaroon"
)

// Paths holds resolved paths to LND's data directory and key files.
type Paths struct {
	LndDir     string
	ConfigFile string
	TLSCert    string
	TLSKey     string
	DataDir    string
	Network    string
	Chain      string
}

// ChainDir returns the chain-specific data directory, e.g. ~/.lnd/data/chain/bitcoin/mainnet
func (p Paths) ChainDir() string {
	return filepath.Join(p.DataDir, "chain", p.Chain, p.Network)
}

// WalletDB returns the expected path to wallet.db.
func (p Paths) WalletDB() string {
	return filepath.Join(p.ChainDir(), DefaultWalletDB)
}

// ChannelBackup returns the expected path to channel.backup.
func (p Paths) ChannelBackup() string {
	return filepath.Join(p.ChainDir(), DefaultChannelBak)
}

// AdminMacaroon returns the expected path to admin.macaroon.
func (p Paths) AdminMacaroon() string {
	return filepath.Join(p.ChainDir(), DefaultAdminMac)
}

// ReadonlyMacaroon returns the expected path to readonly.macaroon.
func (p Paths) ReadonlyMacaroon() string {
	return filepath.Join(p.ChainDir(), DefaultReadMac)
}

// InvoiceMacaroon returns the expected path to invoice.macaroon.
func (p Paths) InvoiceMacaroon() string {
	return filepath.Join(p.ChainDir(), DefaultInvoiceMac)
}

// defaultLndDir returns the platform-specific default LND directory.
func defaultLndDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}

	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Lnd")
	case "windows":
		appData := os.Getenv("LOCALAPPDATA")
		if appData == "" {
			appData = filepath.Join(home, "AppData", "Local")
		}
		return filepath.Join(appData, "Lnd")
	default: // linux, freebsd, etc.
		return filepath.Join(home, ".lnd")
	}
}

// candidateDirs returns all directories to search for an LND installation,
// ordered by likelihood.
func candidateDirs() []string {
	home, _ := os.UserHomeDir()
	candidates := []string{
		defaultLndDir(),
	}

	// Also check the common ~/.lnd path on all platforms (many macOS users
	// install LND via CLI and use ~/.lnd instead of Application Support).
	unixStyle := filepath.Join(home, ".lnd")
	if unixStyle != candidates[0] {
		candidates = append(candidates, unixStyle)
	}

	return candidates
}

// Detect finds the LND data directory and configuration file.
// If lndDir is provided, it is used directly. Otherwise, the function
// searches common installation paths for the current OS user.
// If configFile is provided, it is used directly. Otherwise, lnd.conf
// is looked up inside the resolved LND directory.
// The DataDir is populated from lnd.conf (datadir=) if available,
// falling back to <lnddir>/data.
func Detect(lndDir, configFile string) (Paths, error) {
	p := Paths{
		Network: "mainnet",
		Chain:   "bitcoin",
	}

	// Resolve LND directory
	if lndDir != "" {
		p.LndDir = lndDir
	} else {
		p.LndDir = findExistingDir(candidateDirs())
		if p.LndDir == "" {
			p.LndDir = defaultLndDir()
		}
	}

	// Resolve config file
	if configFile != "" {
		p.ConfigFile = configFile
	} else {
		candidate := filepath.Join(p.LndDir, DefaultConfigName)
		if fileExists(candidate) {
			p.ConfigFile = candidate
		}
	}

	// Attempt to read datadir from lnd.conf if it exists.
	// This is a lightweight parse — full config parsing comes later.
	p.DataDir = filepath.Join(p.LndDir, "data")
	if p.ConfigFile != "" {
		if dd := readKeyFromConfig(p.ConfigFile, "datadir"); dd != "" {
			p.DataDir = expandHome(dd)
		}
	}

	p.TLSCert = filepath.Join(p.LndDir, DefaultTLSCert)
	p.TLSKey = filepath.Join(p.LndDir, DefaultTLSKey)

	return p, nil
}

// readKeyFromConfig does a simple line-scan of an INI-style config file
// and returns the value of the first matching key. This avoids a full
// config parse dependency at the path-detection layer.
func readKeyFromConfig(path, key string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	prefix := key + "="
	for _, line := range splitLines(string(data)) {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), prefix) {
			return strings.TrimSpace(trimmed[len(prefix):])
		}
	}
	return ""
}

func splitLines(s string) []string {
	return strings.Split(s, "\n")
}

// expandHome replaces a leading ~ with the current user's home directory.
func expandHome(path string) string {
	if !strings.HasPrefix(path, "~") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[1:])
}

func findExistingDir(dirs []string) string {
	for _, d := range dirs {
		if info, err := os.Stat(d); err == nil && info.IsDir() {
			return d
		}
	}
	return ""
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
