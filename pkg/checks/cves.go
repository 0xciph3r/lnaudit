package checks

import (
	"fmt"

	"github.com/NonsoAmadi10/lnaudit/pkg/scanner"
)

// knownCVE describes a vulnerability affecting specific LND versions.
type knownCVE struct {
	ID          string
	Severity    scanner.Severity
	Title       string
	Description string
	Reference   string
	FixedIn     string // first version that contains the fix
}

// cveDatabase lists publicly disclosed LND vulnerabilities.
// Versions older than FixedIn are considered affected.
var cveDatabase = []knownCVE{
	{
		ID:          "CVE-2019-12999",
		Severity:    scanner.Critical,
		Title:       "Channel state desync leading to fund theft",
		Description: "LND versions before 0.7.1-beta contain a vulnerability where a malicious peer can desynchronize channel state and steal funds.",
		Reference:   "https://lists.linuxfoundation.org/pipermail/lightning-dev/2019-September/002174.html",
		FixedIn:     "0.7.1",
	},
	{
		ID:          "CVE-2020-26895",
		Severity:    scanner.Critical,
		Title:       "Invoice preimage extraction via forwarded HTLCs",
		Description: "LND versions before 0.11.0-beta allow a routing node to steal payment preimages by exploiting HTLC handling logic.",
		Reference:   "https://lists.linuxfoundation.org/pipermail/lightning-dev/2020-October/002857.html",
		FixedIn:     "0.11.0",
	},
	{
		ID:          "CVE-2020-26896",
		Severity:    scanner.High,
		Title:       "Channel acceptance criteria bypass",
		Description: "LND versions before 0.10.0-beta allow peers to open channels that bypass local acceptance criteria under certain conditions.",
		Reference:   "https://lists.linuxfoundation.org/pipermail/lightning-dev/2020-October/002858.html",
		FixedIn:     "0.10.0",
	},
	{
		ID:          "CVE-2021-41593",
		Severity:    scanner.Critical,
		Title:       "Premature channel funding spend",
		Description: "LND versions before 0.13.3-beta allow a malicious peer to trigger early spend of funding transactions, potentially stealing funds.",
		Reference:   "https://github.com/lightningnetwork/lnd/security/advisories/GHSA-5x4f-35xg-5q7j",
		FixedIn:     "0.13.3",
	},
	{
		ID:          "CVE-2023-40231",
		Severity:    scanner.High,
		Title:       "Replacement cycling attack on HTLCs",
		Description: "LND versions before 0.17.0-beta are vulnerable to replacement cycling attacks that can steal HTLC funds by manipulating transaction replacement in the mempool.",
		Reference:   "https://github.com/lightningnetwork/lnd/security/advisories",
		FixedIn:     "0.17.0",
	},
}

// parseVersion extracts major, minor, patch integers from an LND version string.
// Handles formats like "0.19.1-beta", "0.17.0-beta commit=...", "0.7.1".
func parseVersion(v string) (major, minor, patch int, ok bool) {
	// Strip everything after space (e.g., "commit=...")
	for i, c := range v {
		if c == ' ' {
			v = v[:i]
			break
		}
	}

	// Strip known suffixes
	for _, suffix := range []string{"-beta.rc1", "-beta.rc2", "-beta.rc3", "-beta.rc4", "-beta", "-alpha"} {
		if len(v) > len(suffix) && v[len(v)-len(suffix):] == suffix {
			v = v[:len(v)-len(suffix)]
			break
		}
	}

	// Parse M.m.p
	n, _ := fmt.Sscanf(v, "%d.%d.%d", &major, &minor, &patch)
	return major, minor, patch, n == 3
}

// versionBefore returns true if version a is strictly older than version b.
func versionBefore(a, b string) bool {
	aMaj, aMin, aPat, aOK := parseVersion(a)
	bMaj, bMin, bPat, bOK := parseVersion(b)
	if !aOK || !bOK {
		return false
	}
	if aMaj != bMaj {
		return aMaj < bMaj
	}
	if aMin != bMin {
		return aMin < bMin
	}
	return aPat < bPat
}
