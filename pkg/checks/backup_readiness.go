package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xciph3r/lnaudit/pkg/scanner"
)

// CheckChannelBackupReadiness validates channel.backup presence for local node data.
// It intentionally avoids unverifiable heuristics (for example inferring off-node
// posture from local filename scans).
func CheckChannelBackupReadiness(channelBackupPath, scanRoot, lndDir, lndDataDir string) []scanner.Finding {
	_ = scanRoot
	_ = lndDir

	if strings.TrimSpace(channelBackupPath) == "" {
		return nil
	}
	if !dirExists(lndDataDir) {
		// In config-only CI contexts the scanner host usually does not have LND data.
		// Skip backup posture checks instead of producing host-environment false positives.
		return nil
	}

	var findings []scanner.Finding

	_, err := os.Stat(channelBackupPath)
	if err != nil {
		if os.IsNotExist(err) {
			if hasChannelStateEvidence(channelBackupPath) {
				findings = append(findings, scanner.Finding{
					ID:       "C-10",
					Module:   "channels",
					Severity: scanner.High,
					Title:    "Static channel backup file is missing",
					Description: fmt.Sprintf(
						"Expected channel backup file was not found at %s.",
						redactHomePath(channelBackupPath),
					),
					Remediation: "Create and export a static channel backup, then store a copy off-node in secure storage.",
				})
			}
		}
		return findings
	}

	return findings
}

func dirExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func hasChannelStateEvidence(channelBackupPath string) bool {
	chainDir := filepath.Dir(channelBackupPath)
	// wallet.db in chain/<coin>/<network> is strong evidence of initialized node state.
	if _, err := os.Stat(filepath.Join(chainDir, "wallet.db")); err == nil {
		return true
	}

	// channel.db usually lives at data/graph/<network>/channel.db.
	networkDir := filepath.Base(chainDir)
	dataDir := filepath.Clean(filepath.Join(chainDir, "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(dataDir, "graph", networkDir, "channel.db")); err == nil {
		return true
	}

	return false
}
