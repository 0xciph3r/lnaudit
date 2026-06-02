package checks

import (
	"github.com/NonsoAmadi10/lnaudit/pkg/config"
	"github.com/NonsoAmadi10/lnaudit/pkg/scanner"
)

// CheckProtocolSecurity audits protocol-level settings for dangerous configurations.
func CheckProtocolSecurity(cfg *config.LndConfig) []scanner.Finding {
	var findings []scanner.Finding

	if cfg.Protocol.ZeroConf {
		findings = append(findings, scanner.Finding{
			ID:          "R-1",
			Module:      "protocol",
			Severity:    scanner.Critical,
			Title:       "Zero-conf channels are enabled (protocol.zero-conf=true)",
			Description: "Channels are treated as active before they have any on-chain confirmations. The channel opener can double-spend the funding transaction and steal all channel funds. Only safe with explicitly trusted counterparties.",
			Remediation: "Remove protocol.zero-conf=true from lnd.conf unless all channel partners are fully trusted.",
		})
	}

	if cfg.Protocol.NoAnchors {
		findings = append(findings, scanner.Finding{
			ID:          "R-2",
			Module:      "protocol",
			Severity:    scanner.High,
			Title:       "Anchor channels are disabled (protocol.no-anchors=true)",
			Description: "Anchor channels enable fee-bumping of commitment transactions during fee spikes. Disabling them means your node relies on pre-committed fee rates, increasing the risk of unconfirmed force-close transactions and potential fund loss.",
			Remediation: "Remove protocol.no-anchors=true from lnd.conf to re-enable anchor channel support.",
		})
	}

	if cfg.Protocol.WumboChannels {
		findings = append(findings, scanner.Finding{
			ID:          "R-3",
			Module:      "protocol",
			Severity:    scanner.Medium,
			Title:       "Wumbo channels are enabled (protocol.wumbo-channels=true)",
			Description: "Channels larger than 0.16 BTC (~16.7M sats) are allowed. Large channels significantly increase the blast radius of a breach or force-close event.",
			Remediation: "Disable protocol.wumbo-channels unless you need large channels and have watchtowers active.",
		})
	}

	return findings
}

// CheckAutopilotSecurity audits autopilot configuration.
func CheckAutopilotSecurity(cfg *config.LndConfig) []scanner.Finding {
	var findings []scanner.Finding

	if cfg.Autopilot.Active {
		sev := scanner.High
		desc := "Autopilot autonomously opens channels without operator intervention. " +
			"The node trusts graph data from peers to pick targets. A Sybil attacker " +
			"flooding the graph with fake nodes can attract autopilot to open channels " +
			"with adversarial nodes."

		if cfg.Autopilot.Allocation > 0.5 {
			sev = scanner.Critical
			desc += " Autopilot allocation is set above 50%, meaning the majority of " +
				"your wallet funds will be deployed automatically based on heuristics, not manual judgment."
		}

		findings = append(findings, scanner.Finding{
			ID:          "R-4",
			Module:      "policy",
			Severity:    sev,
			Title:       "Autopilot is enabled (autopilot.active=true)",
			Description: desc,
			Remediation: "Disable autopilot.active in lnd.conf for production nodes. Open channels manually with vetted peers.",
		})
	}

	return findings
}

// CheckGossipSecurity audits gossip rate limiting configuration.
func CheckGossipSecurity(cfg *config.LndConfig) []scanner.Finding {
	var findings []scanner.Finding

	if cfg.Gossip.BanThresholdExplicit && cfg.Gossip.BanThreshold == 0 {
		findings = append(findings, scanner.Finding{
			ID:          "R-5",
			Module:      "policy",
			Severity:    scanner.High,
			Title:       "Gossip peer banning is disabled (gossip.ban-threshold=0)",
			Description: "Setting ban-threshold to 0 disables banning entirely. A single peer can flood the node with unlimited malicious gossip messages, consuming CPU and memory without consequence.",
			Remediation: "Remove gossip.ban-threshold=0 from lnd.conf or set it to the default (100).",
		})
	}

	return findings
}

// CheckTLSHardening audits TLS-related security settings.
func CheckTLSHardening(cfg *config.LndConfig) []scanner.Finding {
	var findings []scanner.Finding

	if cfg.NoRestTLS {
		findings = append(findings, scanner.Finding{
			ID:          "R-6",
			Module:      "transport",
			Severity:    scanner.Critical,
			Title:       "REST API TLS is disabled (no-rest-tls=true)",
			Description: "REST API traffic is sent in plaintext. Any network observer can intercept RPC credentials, macaroons, payment data, and channel information.",
			Remediation: "Remove no-rest-tls=true from lnd.conf immediately.",
		})
	}

	if cfg.TLSEncryptKeyExplicit && !cfg.TLSEncryptKey {
		findings = append(findings, scanner.Finding{
			ID:          "R-7",
			Module:      "transport",
			Severity:    scanner.Medium,
			Title:       "TLS private key encryption is explicitly disabled",
			Description: "The TLS private key is stored unencrypted on disk. An attacker with filesystem read access can impersonate your node's gRPC/REST endpoint.",
			Remediation: "Set tlsencryptkey=true in lnd.conf to encrypt the TLS key with the wallet passphrase.",
		})
	}

	return findings
}

// CheckDangerousFlagsExtended audits additional dangerous flags not covered
// by the original CheckDangerousFlags.
func CheckDangerousFlagsExtended(cfg *config.LndConfig) []scanner.Finding {
	var findings []scanner.Finding

	if cfg.WalletUnlockAllowCreate {
		findings = append(findings, scanner.Finding{
			ID:          "R-8",
			Module:      "access",
			Severity:    scanner.Critical,
			Title:       "Wallet auto-creation is enabled (wallet-unlock-allow-create=true)",
			Description: "LND will create a new wallet via the unauthenticated WalletUnlocker RPC if none exists at startup. An attacker who connects to the gRPC port first can inject an adversarial seed and control the wallet.",
			Remediation: "Remove wallet-unlock-allow-create=true from lnd.conf. Create wallets manually.",
			Reference:   "https://github.com/lightningnetwork/lnd/blob/master/sample-lnd.conf",
		})
	}

	return findings
}
