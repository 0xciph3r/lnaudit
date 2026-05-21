package checks

import (
	"fmt"
	"net"
	"strings"

	"github.com/NonsoAmadi10/lnaudit/pkg/config"
	"github.com/NonsoAmadi10/lnaudit/pkg/scanner"
)

// CheckNetworkExposure audits listener bindings, external IP declarations,
// and NAT/UPnP settings for unnecessary network exposure.
func CheckNetworkExposure(cfg *config.LndConfig) []scanner.Finding {
	var findings []scanner.Finding

	// P2P listener bound to all interfaces without Tor
	for _, addr := range cfg.Listeners {
		if isBoundToAllInterfaces(addr) && !cfg.Tor.Active {
			findings = append(findings, scanner.Finding{
				ID:       "N-1",
				Module:   "transport",
				Severity: scanner.Medium,
				Title:    fmt.Sprintf("P2P listener bound to all interfaces: %s", addr),
				Description: "The P2P listener accepts connections on all network interfaces. " +
					"Without Tor, your node's IP address is directly visible to all peers.",
				Remediation: "Bind listen to a specific interface (e.g., listen=127.0.0.1:9735) or enable Tor.",
			})
		}
	}

	// NAT/UPnP auto port-forwarding
	if cfg.NAT {
		findings = append(findings, scanner.Finding{
			ID:       "N-2",
			Module:   "transport",
			Severity: scanner.Medium,
			Title:    "NAT traversal (UPnP) is enabled",
			Description: "nat=true instructs LND to use UPnP to automatically open ports on your router. " +
				"This bypasses firewall rules and exposes your node without explicit operator action.",
			Remediation: "Remove nat=true from lnd.conf and configure port forwarding manually if needed.",
		})
	}

	// Multiple external IPs declared
	if len(cfg.ExternalIPs) > 1 {
		var clearnetCount int
		for _, ip := range cfg.ExternalIPs {
			if !isOnionAddress(ip) {
				clearnetCount++
			}
		}
		if clearnetCount > 1 {
			findings = append(findings, scanner.Finding{
				ID:       "N-3",
				Module:   "transport",
				Severity: scanner.Medium,
				Title:    fmt.Sprintf("Multiple clearnet IPs advertised (%d)", clearnetCount),
				Description: fmt.Sprintf(
					"Your node advertises %d clearnet IP addresses: %s. "+
						"Each additional address increases your network footprint and attack surface.",
					clearnetCount, strings.Join(cfg.ExternalIPs, ", "),
				),
				Remediation: "Remove unnecessary externalip entries from lnd.conf. One address is sufficient.",
			})
		}
	}

	// RPC on non-loopback without Tor
	for _, addr := range cfg.RPCListeners {
		if !isLoopback(addr) && !isBoundToAllInterfaces(addr) && !cfg.Tor.Active {
			findings = append(findings, scanner.Finding{
				ID:       "N-4",
				Module:   "transport",
				Severity: scanner.High,
				Title:    fmt.Sprintf("gRPC listener on non-loopback address: %s", addr),
				Description: "The gRPC control plane is bound to a non-loopback address, making it " +
					"reachable from other machines on the network.",
				Remediation: "Change rpclisten to 127.0.0.1:<port> in lnd.conf unless remote access is intentional.",
			})
		}
	}

	for _, addr := range cfg.RESTListeners {
		if !isLoopback(addr) && !isBoundToAllInterfaces(addr) && !cfg.Tor.Active {
			findings = append(findings, scanner.Finding{
				ID:       "N-5",
				Module:   "transport",
				Severity: scanner.High,
				Title:    fmt.Sprintf("REST listener on non-loopback address: %s", addr),
				Description: "The REST API is bound to a non-loopback address, making it " +
					"reachable from other machines on the network.",
				Remediation: "Change restlisten to 127.0.0.1:<port> in lnd.conf unless remote access is intentional.",
			})
		}
	}

	return findings
}

// isLoopback returns true if the address resolves to a loopback interface.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.IsLoopback()
	}
	return strings.EqualFold(host, "localhost")
}
