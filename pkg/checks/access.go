package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/NonsoAmadi10/lnaudit/pkg/config"
	"github.com/NonsoAmadi10/lnaudit/pkg/scanner"
)

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

// CheckAdminMacaroonLeaks scans common directories for admin.macaroon copies
// outside the LND data directory.
func CheckAdminMacaroonLeaks(lndDataDir string) []scanner.Finding {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	searchDirs := []string{
		filepath.Join(home, "Downloads"),
		filepath.Join(home, "Desktop"),
		filepath.Join(home, "Documents"),
		os.TempDir(),
		"/tmp",
	}

	var findings []scanner.Finding
	seen := make(map[string]bool)

	for _, dir := range searchDirs {
		matches, _ := filepath.Glob(filepath.Join(dir, "*.macaroon"))
		for _, m := range matches {
			absPath, _ := filepath.Abs(m)
			if seen[absPath] {
				continue
			}
			seen[absPath] = true

			// Skip symlinks to avoid false positives and dangerous remediation
			if info, err := os.Lstat(absPath); err != nil || info.Mode()&os.ModeSymlink != 0 {
				continue
			}

			// Skip if it's inside the LND data directory
			if lndDataDir != "" && strings.HasPrefix(absPath, lndDataDir) {
				continue
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
		}
	}

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
