package checks

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xciph3r/lnaudit/pkg/scanner"
)

const integrationScanMaxFileSize = 256 * 1024 // 256 KiB
const integrationScanMaxFiles = 2000

var integrationFileExtensions = map[string]bool{
	".env":     true,
	".yaml":    true,
	".yml":     true,
	".json":    true,
	".toml":    true,
	".conf":    true,
	".ini":     true,
	".sh":      true,
	".service": true,
	".txt":     true,
}

var readOnlyOperationHints = []string{
	"getinfo",
	"listchannels",
	"listpeers",
	"feereport",
	"forwardinghistory",
	"walletbalance",
	"channelbalance",
	"pendingchannels",
	"listpayments",
}

var invoiceOperationHints = []string{
	"addinvoice",
	"lookupinvoice",
	"listinvoices",
	"subscribeinvoices",
	"invoicesrpc",
}

var adminOperationHints = []string{
	"openchannel",
	"closechannel",
	"closeallchannels",
	"sendcoins",
	"sendmany",
	"bumpfee",
	"importprivkey",
	"walletunlocker",
	"newaddress",
	"sendtoroute",
	"updatenodeannouncement",
}

// CheckMacaroonLeastPrivilege scans integration/deployment files for
// over-privileged admin.macaroon usage where readonly, invoice, or custom
// baked macaroons are likely sufficient.
func CheckMacaroonLeastPrivilege(lndDir, lndDataDir string) []scanner.Finding {
	return CheckMacaroonLeastPrivilegeInRoot("", lndDir, lndDataDir)
}

// CheckMacaroonLeastPrivilegeInRoot is the same as CheckMacaroonLeastPrivilege
// but allows overriding scan root for performance and privacy control.
func CheckMacaroonLeastPrivilegeInRoot(scanRoot, lndDir, lndDataDir string) []scanner.Finding {
	root := resolveScanRoot(scanRoot)
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

	var findings []scanner.Finding
	seen := make(map[string]bool)
	baseDepth := strings.Count(filepath.Clean(root), string(filepath.Separator))
	scannedFiles := 0

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

		if !isIntegrationConfigFile(d.Name()) {
			return nil
		}

		absPath, err := filepath.Abs(path)
		if err != nil || seen[absPath] {
			return nil
		}
		seen[absPath] = true

		if isInsideDir(absPath, cleanLndDir) || isInsideDir(absPath, cleanDataDir) {
			return nil
		}

		info, statErr := os.Lstat(absPath)
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if info.Size() <= 0 || info.Size() > integrationScanMaxFileSize {
			return nil
		}
		scannedFiles++
		if scannedFiles > integrationScanMaxFiles {
			return fs.SkipAll
		}

		data, readErr := os.ReadFile(absPath)
		if readErr != nil {
			return nil
		}

		content := strings.ToLower(string(data))
		if !strings.Contains(content, "admin.macaroon") {
			return nil
		}
		if containsAny(content, adminOperationHints) {
			// The integration appears to require mutating/admin operations.
			return nil
		}

		switch {
		case containsAny(content, readOnlyOperationHints) && !containsAny(content, invoiceOperationHints):
			findings = append(findings, scanner.Finding{
				ID:       "A-4",
				Module:   "access",
				Severity: scanner.High,
				Title:    "Integration likely over-privileged with admin.macaroon (read-only workload)",
				Description: fmt.Sprintf(
					"%s references admin.macaroon and appears to use read-only RPC operations. "+
						"Using admin credentials for read-only workloads increases blast radius if the integration host is compromised.",
					redactHomePath(absPath),
				),
				Remediation: "Use readonly.macaroon for this integration or bake a custom macaroon limited to the required read-only permissions.",
			})
		case containsAny(content, invoiceOperationHints) && !containsAny(content, readOnlyOperationHints):
			findings = append(findings, scanner.Finding{
				ID:       "A-5",
				Module:   "access",
				Severity: scanner.High,
				Title:    "Integration likely over-privileged with admin.macaroon (invoice workload)",
				Description: fmt.Sprintf(
					"%s references admin.macaroon and appears invoice-focused. "+
						"Admin credentials are broader than needed for invoice-only integrations.",
					redactHomePath(absPath),
				),
				Remediation: "Use invoice.macaroon for this integration or bake a custom macaroon with only invoice permissions.",
			})
		default:
			findings = append(findings, scanner.Finding{
				ID:       "A-6",
				Module:   "access",
				Severity: scanner.Medium,
				Title:    "Integration uses admin.macaroon where least-privilege may be possible",
				Description: fmt.Sprintf(
					"%s references admin.macaroon outside the LND data directory. "+
						"Even when exact RPC scope is unclear, integrations should avoid full admin credentials by default.",
					redactHomePath(absPath),
				),
				Remediation: "Replace admin.macaroon with readonly.macaroon, invoice.macaroon, or a custom-baked macaroon scoped to only required RPC methods.",
			})
		}

		return nil
	})

	return findings
}

func isIntegrationConfigFile(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, ".env") {
		return true
	}
	if strings.HasPrefix(lower, "docker-compose") || strings.HasPrefix(lower, "compose.") {
		return true
	}
	return integrationFileExtensions[filepath.Ext(lower)]
}

func containsAny(content string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(content, n) {
			return true
		}
	}
	return false
}
