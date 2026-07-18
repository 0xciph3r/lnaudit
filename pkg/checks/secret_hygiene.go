package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/0xciph3r/lnaudit/pkg/scanner"
)

var sensitiveEnvKeyPattern = regexp.MustCompile(`(?im)^\s*(LND_(MACAROON|TLSKEY|TLS_KEY|SEED)|ADMIN_MACAROON|READONLY_MACAROON|INVOICE_MACAROON|API_KEY|API_SECRET|SECRET_KEY|AUTH_TOKEN|ACCESS_TOKEN|BEARER_TOKEN|PRIVATE_KEY)\s*=`)

var seedFileNames = map[string]bool{
	"seed.txt":        true,
	"wallet.seed":     true,
	"seed.backup":     true,
	"mnemonic.txt":    true,
	"recovery.seed":   true,
	"seed-phrase.txt": true,
}

const maxEnvFileSize = 64 * 1024 // 64KiB

// CheckSecretHygieneLeaks scans for high-risk secret files placed outside
// expected LND directories.
func CheckSecretHygieneLeaks(lndDir, lndDataDir string) []scanner.Finding {
	home, err := os.UserHomeDir()
	if err != nil {
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

	var findings []scanner.Finding
	seen := make(map[string]bool)
	baseDepth := strings.Count(filepath.Clean(home), string(filepath.Separator))

	_ = filepath.WalkDir(home, func(path string, d os.DirEntry, walkErr error) error {
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

		absPath, err := filepath.Abs(path)
		if err != nil || seen[absPath] {
			return nil
		}
		seen[absPath] = true

		info, statErr := os.Lstat(absPath)
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		if isInsideDir(absPath, cleanLndDir) || isInsideDir(absPath, cleanDataDir) {
			return nil
		}

		name := strings.ToLower(filepath.Base(absPath))
		switch {
		case name == "tls.key":
			findings = append(findings, scanner.Finding{
				ID:       "H-7a",
				Module:   "hygiene",
				Severity: scanner.High,
				Title:    "TLS private key found outside LND directory",
				Description: fmt.Sprintf(
					"tls.key was found at %s. A stray TLS private key can allow TLS impersonation of your node.",
					absPath,
				),
				Remediation: "Securely delete or move this key into the intended LND directory and rotate certificates if exposure is suspected.",
			})
		case seedFileNames[name] || strings.HasSuffix(name, ".seed"):
			findings = append(findings, scanner.Finding{
				ID:       "H-7b",
				Module:   "hygiene",
				Severity: scanner.Critical,
				Title:    "Potential wallet seed material found outside secure storage",
				Description: fmt.Sprintf(
					"Potential seed material file found at %s. Seed material outside hardened storage is a direct fund-loss risk.",
					absPath,
				),
				Remediation: "Move or securely remove plaintext seed files from general-purpose directories and keep backups in an offline secure medium.",
			})
		case strings.HasPrefix(name, ".env"):
			envFindings := checkSensitiveEnvFile(absPath, info.Mode().Perm())
			findings = append(findings, envFindings...)
		}

		return nil
	})

	return findings
}

func checkSensitiveEnvFile(path string, mode os.FileMode) []scanner.Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if len(data) > maxEnvFileSize {
		return nil
	}
	if !sensitiveEnvKeyPattern.Match(data) {
		return nil
	}

	findings := []scanner.Finding{{
		ID:       "H-7c",
		Module:   "hygiene",
		Severity: scanner.High,
		Title:    "Sensitive credentials found in .env file",
		Description: fmt.Sprintf(
			"%s contains sensitive credential variables. Environment files are frequently copied, logged, or committed by accident.",
			path,
		),
		Remediation: "Move sensitive values to a secret manager and keep only non-sensitive defaults in .env files.",
	}}

	if mode&0o077 != 0 {
		findings = append(findings, scanner.Finding{
			ID:       "H-7d",
			Module:   "hygiene",
			Severity: scanner.High,
			Title:    "Sensitive .env file has overly broad permissions",
			Description: fmt.Sprintf(
				"%s contains sensitive variables and has permissions %04o. Group/other access increases credential theft risk.",
				path,
				mode,
			),
			Remediation: "Restrict the file to owner-only access (chmod 600) and rotate credentials if the file was exposed.",
		})
	}

	return findings
}
