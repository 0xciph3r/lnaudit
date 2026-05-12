package checks

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/NonsoAmadi10/lnaudit/pkg/scanner"
)

// sensitiveFile defines a file to check and its expected permissions.
type sensitiveFile struct {
	path     string
	name     string
	maxPerm  fs.FileMode
	severity scanner.Severity
	module   string
}

// CheckFilePermissions audits permissions on sensitive LND files.
// It checks wallet.db, tls.key, macaroons, channel.backup, lnd.conf,
// and the Tor onion private key.
func CheckFilePermissions(paths FilePaths) []scanner.Finding {
	targets := []sensitiveFile{
		{paths.WalletDB, "wallet.db", 0o600, scanner.Critical, "keys"},
		{paths.TLSKey, "tls.key", 0o600, scanner.Critical, "keys"},
		{paths.AdminMacaroon, "admin.macaroon", 0o600, scanner.Critical, "access"},
		{paths.ReadonlyMacaroon, "readonly.macaroon", 0o600, scanner.High, "access"},
		{paths.InvoiceMacaroon, "invoice.macaroon", 0o600, scanner.High, "access"},
		{paths.ChannelBackup, "channel.backup", 0o600, scanner.Critical, "keys"},
		{paths.ConfigFile, "lnd.conf", 0o640, scanner.High, "access"},
	}

	// Tor onion key if provided
	if paths.TorOnionKey != "" {
		targets = append(targets, sensitiveFile{
			path:     paths.TorOnionKey,
			name:     "tor onion private key",
			maxPerm:  0o600,
			severity: scanner.Critical,
			module:   "keys",
		})
	}

	var findings []scanner.Finding

	for _, t := range targets {
		if t.path == "" {
			continue
		}

		f := checkSingleFile(t)
		if f != nil {
			findings = append(findings, *f)
		}
	}

	return findings
}

func checkSingleFile(sf sensitiveFile) *scanner.Finding {
	// Use Lstat to check the file itself, not what a symlink points to.
	// This prevents an attacker from planting symlinks to mislead permission reports
	// and protects against remediation commands (chmod) being applied to symlink targets.
	info, err := os.Lstat(sf.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist — not a permission issue
		}
		return &scanner.Finding{
			ID:          fmt.Sprintf("PERM-%s", sf.name),
			Module:      sf.module,
			Severity:    scanner.Low,
			Title:       fmt.Sprintf("Cannot stat %s", sf.name),
			Description: fmt.Sprintf("Unable to check permissions on %s: %v", sf.path, err),
		}
	}

	// Warn if the file is a symlink — sensitive files should not be symlinks
	if info.Mode()&os.ModeSymlink != 0 {
		return &scanner.Finding{
			ID:       fmt.Sprintf("PERM-%s", sf.name),
			Module:   sf.module,
			Severity: scanner.High,
			Title:    fmt.Sprintf("%s is a symlink (unexpected)", sf.name),
			Description: fmt.Sprintf(
				"%s at %s is a symbolic link. Sensitive files should be regular files, "+
					"not symlinks, to prevent symlink-following attacks.",
				sf.name, sf.path,
			),
			Remediation: fmt.Sprintf("Investigate why %s is a symlink and replace with a regular file.", sf.path),
		}
	}

	perm := info.Mode().Perm()

	// Check if actual permissions exceed the maximum allowed
	if isOverlyPermissive(perm, sf.maxPerm) {
		return &scanner.Finding{
			ID:       fmt.Sprintf("PERM-%s", sf.name),
			Module:   sf.module,
			Severity: sf.severity,
			Title:    fmt.Sprintf("%s has permissions %04o (too permissive)", sf.name, perm),
			Description: fmt.Sprintf(
				"%s at %s has permissions %04o. Maximum recommended: %04o.",
				sf.name, sf.path, perm, sf.maxPerm,
			),
			Remediation: fmt.Sprintf("chmod %04o %s", sf.maxPerm, sf.path),
		}
	}

	return nil
}

// isOverlyPermissive returns true if the actual permission grants access
// beyond what maxPerm allows. We check group and other bits.
func isOverlyPermissive(actual, maxPerm fs.FileMode) bool {
	// If the file allows any bits that maxPerm doesn't, it's too permissive.
	// For example, if maxPerm is 0o600 and actual is 0o644, the group-read (040)
	// and other-read (004) bits exceed the maximum.
	excess := actual & ^maxPerm
	return excess != 0
}

// FilePaths holds the resolved paths to files that need permission checking.
type FilePaths struct {
	WalletDB         string
	TLSKey           string
	AdminMacaroon    string
	ReadonlyMacaroon string
	InvoiceMacaroon  string
	ChannelBackup    string
	ConfigFile       string
	TorOnionKey      string
}
