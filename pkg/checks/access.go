package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/NonsoAmadi10/lnaudit/pkg/config"
	"github.com/NonsoAmadi10/lnaudit/pkg/scanner"
)

// macaroonScanDepth is the maximum directory depth walked during the macaroon
// leak scan. Deep enough to catch common backup and project directories without
// traversing the entire filesystem.
const macaroonScanDepth = 4

// skipDirs are directories that are safe to skip during the home directory walk:
// they are either too large, never contain stray credentials, or are system dirs.
var skipDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
	"vendor":       true,
	".cache":       true,
	".npm":         true,
	".gradle":      true,
	"Library":      true, // macOS system libraries
	"go":           true, // Go SDK
}

// CheckNoMacaroons verifies that macaroon authentication is not disabled.
func CheckNoMacaroons(cfg *config.LndConfig) []scanner.Finding {
	if cfg.NoMacaroons {
		return []scanner.Finding{{
			ID:       "A-1",
			Module:   "access",
			Severity: scanner.Critical,
			Title:    "Macaroon authentication is DISABLED",
			Description: "The --no-macaroons flag is set, meaning anyone who can reach " +
				"your gRPC/REST interface has full admin access with no authentication.",
			Remediation: "Remove no-macaroons=true from lnd.conf and restart LND.",
			Reference:   "POST-MORTEM.md#6-nicehash-2017",
		}}
	}
	return nil
}

// isInsideDir reports whether path is inside (or equal to) dir.
// Both paths should be cleaned and absolute before calling.
// Uses filepath.Rel to avoid the HasPrefix sibling-path pitfall
// (e.g., /data/lnd2 falsely matching /data/lnd).
func isInsideDir(path, dir string) bool {
	if dir == "" {
		return false
	}
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	// Rel returns ".." or "../..." when path is outside dir.
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// CheckAdminMacaroonLeaks scans the full home directory up to
// macaroonScanDepth levels deep for admin.macaroon copies outside the LND
// data directory. Walking the full home tree catches stray copies in
// project dirs, backup dirs, and sync folders that a shallow scan misses.
func CheckAdminMacaroonLeaks(lndDataDir string) []scanner.Finding {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	cleanDataDir := ""
	if lndDataDir != "" {
		cleanDataDir, _ = filepath.Abs(filepath.Clean(lndDataDir))
	}

	var findings []scanner.Finding
	seen := make(map[string]bool)

	baseDepth := strings.Count(filepath.Clean(home), string(filepath.Separator))

	_ = filepath.WalkDir(home, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// For a single unreadable file, skip the file but continue the walk.
			// For an unreadable directory, skip the whole subtree.
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			currentDepth := strings.Count(filepath.Clean(path), string(filepath.Separator))
			// Use > so that depth exactly equal to macaroonScanDepth is still
			// entered -- files inside it are at depth macaroonScanDepth and
			// are included in the scan.
			if currentDepth-baseDepth > macaroonScanDepth {
				return filepath.SkipDir
			}
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(d.Name(), ".macaroon") {
			return nil
		}

		absPath, _ := filepath.Abs(path)
		if seen[absPath] {
			return nil
		}
		seen[absPath] = true

		// Skip symlinks to avoid false positives.
		info, statErr := os.Lstat(absPath)
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		// Skip if the file is inside the LND data directory.
		if isInsideDir(absPath, cleanDataDir) {
			return nil
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
			Title:    fmt.Sprintf("Macaroon found outside LND data directory: %s", name),
			Description: fmt.Sprintf(
				"A copy of %s was found in %s. Macaroons should only exist in the LND data directory. "+
					"Stray copies increase the risk of credential theft.",
				name, filepath.Dir(absPath),
			),
			Remediation: "Securely delete the stray macaroon file. Verify it is not needed before removal.",
			Reference:   "POST-MORTEM.md#9-binance-2019",
		})
		return nil
	})

	return findings
}

// CheckDangerousFlags audits lnd.conf for flags that weaken security.
func CheckDangerousFlags(cfg *config.LndConfig) []scanner.Finding {
	var findings []scanner.Finding

	if cfg.NoSeedBackup {
		findings = append(findings, scanner.Finding{
			ID:          "H-6a",
			Module:      "hygiene",
			Severity:    scanner.Critical,
			Title:       "Seed backup is DISABLED (--noseedbackup)",
			Description: "The wallet was created without a seed phrase. If you lose access to the wallet file, all funds are permanently lost.",
			Remediation: "Create a new wallet with a seed backup. Migrate funds from the unseeded wallet.",
		})
	}

	if cfg.NoEncryptWallet {
		findings = append(findings, scanner.Finding{
			ID:          "H-6b",
			Module:      "hygiene",
			Severity:    scanner.Critical,
			Title:       "Wallet encryption is DISABLED (--noencryptwallet)",
			Description: "The wallet is stored unencrypted on disk. Anyone with file access can steal all funds.",
			Remediation: "Remove noencryptwallet from lnd.conf. Create a new encrypted wallet and migrate funds.",
			Reference:   "POST-MORTEM.md#2-bitcoinica--linode-2012",
		})
	}

	if cfg.DebugLevel == "trace" || cfg.DebugLevel == "debug" {
		findings = append(findings, scanner.Finding{
			ID:       "H-4",
			Module:   "hygiene",
			Severity: scanner.High,
			Title:    fmt.Sprintf("Debug logging enabled in production (debuglevel=%s)", cfg.DebugLevel),
			Description: "Verbose logging may write sensitive data to log files, including " +
				"payment preimages, macaroon data, and peer connection details.",
			Remediation: "Set debuglevel=info in lnd.conf for production nodes.",
		})
	}

	if cfg.DebugHTLC {
		findings = append(findings, scanner.Finding{
			ID:          "H-4b",
			Module:      "hygiene",
			Severity:    scanner.Medium,
			Title:       "HTLC debug mode is enabled (--debughtlc)",
			Description: "HTLC debugging logs detailed payment routing information that could be used to analyze payment flows.",
			Remediation: "Remove debughtlc=true from lnd.conf.",
		})
	}

	if cfg.TrickleDelayExplicit && cfg.TrickleDelay == 0 {
		findings = append(findings, scanner.Finding{
			ID:          "H-6c",
			Module:      "hygiene",
			Severity:    scanner.Medium,
			Title:       "Trickle delay is disabled (trickledelay=0)",
			Description: "With no trickle delay, gossip announcements are sent immediately, making it easier to perform timing analysis on your node's activity.",
			Remediation: "Remove the trickledelay override or set it to the default (5000ms).",
		})
	}

	if cfg.UnsafeDisconnect {
		findings = append(findings, scanner.Finding{
			ID:          "H-6d",
			Module:      "hygiene",
			Severity:    scanner.Low,
			Title:       "Unsafe disconnect is enabled (--unsafe-disconnect)",
			Description: "Allows disconnecting from peers with active channels, which could lead to missed updates and force closures.",
			Remediation: "Remove unsafe-disconnect=true from lnd.conf unless you have a specific need.",
		})
	}

	return findings
}
