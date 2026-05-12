package checks

import (
	"fmt"
	"net"
	"time"

	"github.com/NonsoAmadi10/lnaudit/pkg/scanner"
)

// portCheck defines a port to probe and how to classify it.
type portCheck struct {
	Port        int
	Service     string
	Severity    scanner.Severity
	Description string
	Remediation string
}

// lndPorts lists known ports associated with LND and Bitcoin infrastructure.
var lndPorts = []portCheck{
	{
		Port:     10009,
		Service:  "LND gRPC",
		Severity: scanner.High,
		Description: "The LND gRPC control plane is reachable on this host. " +
			"If exposed to the network, an attacker with a stolen macaroon can drain the wallet.",
		Remediation: "Bind rpclisten to 127.0.0.1 or restrict access with a firewall.",
	},
	{
		Port:     8080,
		Service:  "LND REST",
		Severity: scanner.High,
		Description: "The LND REST API is reachable on this host. " +
			"REST exposes the same wallet controls as gRPC.",
		Remediation: "Bind restlisten to 127.0.0.1 or disable REST if unused.",
	},
	{
		Port:     9735,
		Service:  "Lightning P2P",
		Severity: scanner.Info,
		Description: "The Lightning P2P port is open. This is expected for a routing node " +
			"but reveals the node's presence on the network.",
		Remediation: "No action needed unless running a private node behind Tor.",
	},
	{
		Port:     9911,
		Service:  "Watchtower Server",
		Severity: scanner.Low,
		Description: "A watchtower server port is open. If intentional, ensure only " +
			"authorized clients can connect.",
		Remediation: "Restrict watchtower access via firewall rules if not offering public tower service.",
	},
	{
		Port:     8332,
		Service:  "Bitcoin Core RPC (mainnet)",
		Severity: scanner.High,
		Description: "The Bitcoin Core RPC port is open. This provides wallet and blockchain " +
			"access that should not be exposed beyond localhost.",
		Remediation: "Set rpcbind=127.0.0.1 in bitcoin.conf and restrict with rpcallowip.",
	},
	{
		Port:        8333,
		Service:     "Bitcoin Core P2P (mainnet)",
		Severity:    scanner.Info,
		Description: "The Bitcoin Core P2P port is open. This is normal for a full node.",
		Remediation: "No action needed for a standard full node.",
	},
	{
		Port:     18332,
		Service:  "Bitcoin Core RPC (testnet)",
		Severity: scanner.Medium,
		Description: "The Bitcoin Core testnet RPC port is open. While testnet funds are not valuable, " +
			"an open RPC can leak configuration details.",
		Remediation: "Bind testnet RPC to 127.0.0.1 or close the port if not in use.",
	},
	{
		Port:     18443,
		Service:  "Bitcoin Core RPC (regtest)",
		Severity: scanner.Medium,
		Description: "The Bitcoin Core regtest RPC port is open. Regtest instances " +
			"are typically development-only and should not be exposed.",
		Remediation: "Bind regtest RPC to 127.0.0.1 or stop the regtest daemon if not needed.",
	},
}

const portDialTimeout = 800 * time.Millisecond

// CheckOpenPorts probes known LND and Bitcoin ports on the given host.
// Pass "localhost" or "" to scan the local machine.
func CheckOpenPorts(host string) []scanner.Finding {
	if host == "" {
		host = "127.0.0.1"
	}

	// Strip any existing port from the host (e.g., "localhost:10009" -> "localhost")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	findings := make([]scanner.Finding, 0, len(lndPorts))

	for _, pc := range lndPorts {
		addr := net.JoinHostPort(host, fmt.Sprintf("%d", pc.Port))
		conn, err := net.DialTimeout("tcp", addr, portDialTimeout)
		if err != nil {
			continue
		}
		conn.Close()

		findings = append(findings, scanner.Finding{
			ID:          fmt.Sprintf("P-%d", pc.Port),
			Module:      "ports",
			Severity:    pc.Severity,
			Title:       fmt.Sprintf("Port %d open: %s", pc.Port, pc.Service),
			Description: pc.Description,
			Remediation: pc.Remediation,
		})
	}

	return findings
}
