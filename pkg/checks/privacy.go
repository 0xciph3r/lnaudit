package checks

import (
	"github.com/NonsoAmadi10/lnaudit/pkg/config"
	"github.com/NonsoAmadi10/lnaudit/pkg/scanner"
)

// CheckTorConfig audits the Tor-related settings in lnd.conf.
func CheckTorConfig(cfg *config.LndConfig) []scanner.Finding {
	if !cfg.Tor.Active {
		return nil
	}

	var findings []scanner.Finding

	// Skip proxy for clearnet targets — leaks real IP
	if cfg.Tor.SkipProxyForClearnetTargets {
		findings = append(findings, scanner.Finding{
			ID:       "N-1",
			Module:   "privacy",
			Severity: scanner.Critical,
			Title:    "Tor skip-proxy-for-clearnet-targets is ENABLED (IP leak!)",
			Description: "When this flag is set, connections to non-.onion peers bypass " +
				"the Tor proxy entirely, revealing your real IP address to those peers.",
			Remediation: "Set tor.skip-proxy-for-clearnet-targets=false in lnd.conf",
			Reference:   "POST-MORTEM.md#6-nicehash-2017",
		})
	}

	// Stream isolation
	if !cfg.Tor.StreamIsolation {
		findings = append(findings, scanner.Finding{
			ID:       "N-2",
			Module:   "privacy",
			Severity: scanner.Medium,
			Title:    "Tor stream isolation is disabled",
			Description: "Without stream isolation, all peer connections may share the same " +
				"Tor circuit. An adversary controlling a Tor exit/relay could correlate " +
				"your connections to different peers.",
			Remediation: "Set tor.streamisolation=true in lnd.conf",
		})
	}

	// V3 onion
	if !cfg.Tor.V3 {
		findings = append(findings, scanner.Finding{
			ID:       "N-1b",
			Module:   "privacy",
			Severity: scanner.High,
			Title:    "Tor V3 onion services not enabled",
			Description: "V2 onion addresses use RSA-1024 keys, which are deprecated and " +
				"considered cryptographically weak. V3 uses Ed25519.",
			Remediation: "Set tor.v3=true in lnd.conf (V2 is being phased out by the Tor project).",
		})
	}

	// Onion key encryption
	if !cfg.Tor.EncryptKey {
		findings = append(findings, scanner.Finding{
			ID:       "K-2",
			Module:   "keys",
			Severity: scanner.Critical,
			Title:    "Tor onion private key is NOT encrypted on disk",
			Description: "The onion service private key is stored in plaintext. A server " +
				"compromise would expose your hidden service identity.",
			Remediation: "Set tor.encryptkey=true in lnd.conf and restart LND.",
			Reference:   "POST-MORTEM.md#2-bitcoinica--linode-2012",
		})
	}

	return findings
}

// CheckPrivacySettings audits protocol-level privacy features.
func CheckPrivacySettings(cfg *config.LndConfig) []scanner.Finding {
	var findings []scanner.Finding

	// SCID alias
	if !cfg.Protocol.ScidAlias {
		findings = append(findings, scanner.Finding{
			ID:       "N-3",
			Module:   "privacy",
			Severity: scanner.Medium,
			Title:    "SCID alias (option-scid-alias) is not enabled",
			Description: "Without SCID aliases, your channel UTXOs are publicly linked to " +
				"your node identity through gossip. Enabling this provides short channel " +
				"ID aliases that don't reveal the funding transaction.",
			Remediation: "Set protocol.option-scid-alias=true in lnd.conf",
		})
	}

	return findings
}

// CheckChannelSafety audits channel-related safety settings.
func CheckChannelSafety(cfg *config.LndConfig) []scanner.Finding {
	var findings []scanner.Finding

	// Watchtower client
	if !cfg.WatchtowerClient.Active {
		findings = append(findings, scanner.Finding{
			ID:       "C-1",
			Module:   "channels",
			Severity: scanner.High,
			Title:    "No watchtower client configured",
			Description: "Without a watchtower, if your node goes offline, a malicious channel " +
				"partner could broadcast a revoked commitment transaction and steal your funds.",
			Remediation: "Add [wtclient] section with wtclient.active=true and at least one tower URI.",
			Reference:   "POST-MORTEM.md#5-bitfinex-2016",
		})
	}

	// Channel confirmation depth
	if cfg.Bitcoin.DefaultChanConfs > 0 && cfg.Bitcoin.DefaultChanConfs < 3 {
		findings = append(findings, scanner.Finding{
			ID:       "C-2",
			Module:   "channels",
			Severity: scanner.High,
			Title:    "Channel confirmation depth is dangerously low",
			Description: "bitcoin.defaultchanconfs is set below 3. This makes channels " +
				"vulnerable to double-spend attacks on the funding transaction.",
			Remediation: "Set bitcoin.defaultchanconfs=3 or higher (6 recommended for high-value channels).",
			Reference:   "POST-MORTEM.md#7-bitcoin-gold-51-attack-2018",
		})
	}

	// Max channel size
	if cfg.MaxChanSize == 0 {
		findings = append(findings, scanner.Finding{
			ID:       "C-4",
			Module:   "channels",
			Severity: scanner.Medium,
			Title:    "No maximum channel size configured",
			Description: "Without maxchansize, the node uses the protocol default (~0.17 BTC). " +
				"Setting an explicit limit prevents a single channel from locking up too much capital.",
			Remediation: "Set maxchansize in lnd.conf to a value appropriate for your risk tolerance.",
			Reference:   "POST-MORTEM.md#5-bitfinex-2016",
		})
	}

	// Max pending channels
	if cfg.MaxPendingChannels == 0 {
		findings = append(findings, scanner.Finding{
			ID:       "C-5",
			Module:   "channels",
			Severity: scanner.Low,
			Title:    "MaxPendingChannels not explicitly configured",
			Description: "The default of 1 pending channel is conservative but may not suit all operators. " +
				"Consider setting this explicitly based on your operational needs.",
		})
	}

	return findings
}
