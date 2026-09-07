package checks

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/0xciph3r/lnaudit/pkg/config"
	"github.com/0xciph3r/lnaudit/pkg/scanner"
)

const watchtowerDialTimeout = 2 * time.Second

// dialTowerAddr is swappable in tests.
var dialTowerAddr = net.DialTimeout

// CheckWatchtowerConnectivity validates watchtower URI posture and optionally
// probes endpoint reachability from the current scanning host.
func CheckWatchtowerConnectivity(cfg *config.LndConfig, probe bool) []scanner.Finding {
	if cfg == nil || !cfg.WatchtowerClient.Active {
		return nil
	}

	towers := cfg.WatchtowerClient.Towers
	if len(towers) == 0 {
		return []scanner.Finding{{
			ID:       "C-6",
			Module:   "channels",
			Severity: scanner.High,
			Title:    "Watchtower client is enabled but no tower URIs are configured",
			Description: "wtclient.active=true is set, but wtclient.private-tower-uris is empty. " +
				"Without at least one configured tower, watchtower protection is non-functional.",
			Remediation: "Set wtclient.private-tower-uris=<pubkey>@<host>:<port> for one or more reachable towers.",
		}}
	}

	reachable := 0
	unreachable := 0
	onionOnly := 0
	malformed := 0

	for _, raw := range towers {
		addr, onion, ok := parseTowerAddress(raw)
		if !ok {
			malformed++
			continue
		}
		if onion {
			onionOnly++
			continue
		}
		if !probe {
			continue
		}
		conn, err := dialTowerAddr("tcp", addr, watchtowerDialTimeout)
		if err != nil {
			unreachable++
			continue
		}
		_ = conn.Close()
		reachable++
	}

	var findings []scanner.Finding

	if malformed > 0 {
		findings = append(findings, scanner.Finding{
			ID:       "C-9",
			Module:   "channels",
			Severity: scanner.Low,
			Title:    "Some watchtower URIs are malformed",
			Description: fmt.Sprintf(
				"%d malformed watchtower URI(s) were found in wtclient.private-tower-uris.",
				malformed,
			),
			Remediation: "Fix malformed tower URIs to avoid silent watchtower coverage gaps.",
		})
	}

	if !probe {
		return findings
	}

	if reachable == 0 && onionOnly > 0 && onionOnly+malformed == len(towers) {
		findings = append(findings, scanner.Finding{
			ID:       "C-7",
			Module:   "channels",
			Severity: scanner.Info,
			Title:    "Watchtower endpoints are onion-only and were not actively verified",
			Description: "All configured watchtower URIs are .onion endpoints. " +
				"Direct TCP probing from this scan host does not validate Tor-routed node connectivity.",
			Remediation: "Verify watchtower reachability from the same Tor-routed runtime environment as LND.",
		})
		return findings
	}

	if reachable == 0 {
		findings = append(findings, scanner.Finding{
			ID:       "C-8",
			Module:   "channels",
			Severity: scanner.Medium,
			Title:    "No configured watchtower endpoint appears reachable",
			Description: fmt.Sprintf(
				"Probed %d tower URI(s) from the scanning host; %d reachable, %d unreachable, %d malformed, %d onion-only.",
				len(towers), reachable, unreachable, malformed, onionOnly,
			),
			Remediation: "Validate tower reachability from the LND host/network context, then fix URIs, DNS, routing, or firewall rules.",
		})
	} else if unreachable > 0 {
		findings = append(findings, scanner.Finding{
			ID:       "C-13",
			Module:   "channels",
			Severity: scanner.Low,
			Title:    "Some configured watchtower endpoints are unreachable",
			Description: fmt.Sprintf(
				"Probed %d tower URI(s) from the scanning host; %d reachable, %d unreachable.",
				len(towers), reachable, unreachable,
			),
			Remediation: "Remove stale watchtower URIs and keep only currently reachable endpoints.",
		})
	}

	return findings
}

func parseTowerAddress(raw string) (addr string, onion, ok bool) {
	uri := strings.TrimSpace(raw)
	if uri == "" {
		return "", false, false
	}

	parts := strings.SplitN(uri, "@", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || parts[1] == "" {
		return "", false, false
	}
	hostPort := parts[1]
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
		port = "9911"
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", false, false
	}
	onion = strings.HasSuffix(strings.ToLower(host), ".onion")
	return net.JoinHostPort(host, port), onion, true
}
