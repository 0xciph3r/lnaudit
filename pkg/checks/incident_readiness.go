package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xciph3r/lnaudit/pkg/scanner"
)

const minRunbookChars = 200

// CheckIncidentReadiness verifies that operational incident-response runbooks
// are present and cover critical recovery actions.
func CheckIncidentReadiness(runbookDir, scanRoot, lndDir, lndDataDir string) []scanner.Finding {
	_ = scanRoot

	root := strings.TrimSpace(runbookDir)
	if root == "" {
		return nil
	}

	cleanLndDir := ""
	if lndDir != "" {
		cleanLndDir, _ = filepath.Abs(filepath.Clean(lndDir))
	}
	cleanDataDir := ""
	if lndDataDir != "" {
		cleanDataDir, _ = filepath.Abs(filepath.Clean(lndDataDir))
	}

	type topic struct {
		id          string
		title       string
		needles     []string
		missingSev  scanner.Severity
		remediation string
	}

	topics := []topic{
		{
			id:          "H-8a",
			title:       "No key-rotation runbook evidence found",
			needles:     []string{"key rotation", "rotate key", "rotate tls", "macaroon rotation"},
			missingSev:  scanner.High,
			remediation: "Document an actionable key-rotation runbook covering TLS key/cert rotation and macaroon revocation/reissue.",
		},
		{
			id:          "H-8b",
			title:       "No fund-sweep runbook evidence found",
			needles:     []string{"fund sweep", "sweep funds", "emergency sweep"},
			missingSev:  scanner.High,
			remediation: "Document an emergency fund-sweep procedure with destination controls and operator roles.",
		},
		{
			id:          "H-8c",
			title:       "No channel-close response runbook evidence found",
			needles:     []string{"force close", "channel close", "cooperative close"},
			missingSev:  scanner.Medium,
			remediation: "Document channel close handling, including force-close monitoring and on-chain settlement steps.",
		},
		{
			id:          "H-8d",
			title:       "No restore/recovery runbook evidence found",
			needles:     []string{"restore", "disaster recovery", "recover node", "recovery procedure"},
			missingSev:  scanner.Medium,
			remediation: "Document restore steps from static channel backups and wallet seed material in sequence.",
		},
	}

	coverage := map[string]int{}
	baseDepth := strings.Count(filepath.Clean(root), string(filepath.Separator))

	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			currentDepth := strings.Count(filepath.Clean(path), string(filepath.Separator))
			if currentDepth-baseDepth > macaroonScanDepth {
				return filepath.SkipDir
			}
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".md" && ext != ".txt" && ext != ".adoc" {
			return nil
		}

		absPath, err := filepath.Abs(path)
		if err != nil || isInsideDir(absPath, cleanLndDir) || isInsideDir(absPath, cleanDataDir) {
			return nil
		}
		info, err := os.Lstat(absPath)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if info.Size() > 512*1024 {
			return nil
		}

		data, err := readRunbookFile(absPath)
		if err != nil {
			return nil
		}
		content := strings.ToLower(string(data))
		for _, tp := range topics {
			if containsAny(content, tp.needles) {
				coverage[tp.id] = max(coverage[tp.id], len([]rune(strings.TrimSpace(content))))
			}
		}
		return nil
	})

	var findings []scanner.Finding
	for _, tp := range topics {
		docLen := coverage[tp.id]
		if docLen == 0 {
			findings = append(findings, scanner.Finding{
				ID:          tp.id,
				Module:      "hygiene",
				Severity:    tp.missingSev,
				Title:       tp.title,
				Description: fmt.Sprintf("No runbook content matching this incident category was detected under %s.", redactHomePath(root)),
				Remediation: tp.remediation,
			})
			continue
		}
		if docLen < minRunbookChars {
			findings = append(findings, scanner.Finding{
				ID:          tp.id + "-q",
				Module:      "hygiene",
				Severity:    scanner.Low,
				Title:       "Incident runbook appears too brief for reliable execution",
				Description: fmt.Sprintf("%s content exists but appears very short (%d chars), which may be insufficient during incident response.", tp.title, docLen),
				Remediation: "Expand the runbook with explicit commands, verification steps, and rollback criteria.",
			})
		}
	}

	return findings
}

func readRunbookFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
