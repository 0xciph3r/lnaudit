package checks

import (
	"fmt"

	"github.com/NonsoAmadi10/lnaudit/pkg/config"
	"github.com/NonsoAmadi10/lnaudit/pkg/scanner"
)

// CheckChannelPolicy audits channel policy settings for security misconfigurations.
func CheckChannelPolicy(cfg *config.LndConfig) []scanner.Finding {
	var findings []scanner.Finding

	// allow-circular-route=true enables balance probing
	if cfg.AllowCircularRoute {
		findings = append(findings, scanner.Finding{
			ID:          "P-1",
			Module:      "policy",
			Severity:    scanner.Medium,
			Title:       "Circular routing is enabled (allow-circular-route=true)",
			Description: "HTLCs are allowed to arrive and depart on the same channel. This enables balance-probing and fee-extraction attacks by adversaries who can infer your channel balances.",
			Remediation: "Remove allow-circular-route=true from lnd.conf unless you have a specific operational need.",
		})
	}

	// rejectpush=false (default) allows push-amount channels
	if !cfg.RejectPush && !cfg.RejectPushExplicit {
		findings = append(findings, scanner.Finding{
			ID:          "P-2",
			Module:      "policy",
			Severity:    scanner.Low,
			Title:       "Push-amount channels are accepted (rejectpush not set)",
			Description: "Channels with a non-zero push amount are accepted. Push-amount channels enable pinning and griefing attacks and are considered suspicious on production nodes.",
			Remediation: "Set rejectpush=true in lnd.conf to reject channels that push funds at open time.",
		})
	}

	// default-remote-max-htlcs too high or at protocol max (483)
	if cfg.DefaultRemoteMaxHTLCsExplicit && cfg.DefaultRemoteMaxHTLCs > 100 {
		findings = append(findings, scanner.Finding{
			ID:       "P-3",
			Module:   "policy",
			Severity: scanner.High,
			Title:    fmt.Sprintf("Remote HTLC limit is high (default-remote-max-htlcs=%d)", cfg.DefaultRemoteMaxHTLCs),
			Description: "A high HTLC limit allows an adversary to pin many dust HTLCs on every channel, " +
				"exhausting commitment space and blocking legitimate payments (channel jamming attack).",
			Remediation: "Set default-remote-max-htlcs to 30 or lower in lnd.conf. The protocol maximum (483) is almost never needed.",
		})
	}

	// enable-upfront-shutdown not set
	if !cfg.EnableUpfrontShutdown {
		findings = append(findings, scanner.Finding{
			ID:          "P-4",
			Module:      "policy",
			Severity:    scanner.Low,
			Title:       "Upfront shutdown script is not enabled",
			Description: "Without enable-upfront-shutdown, the cooperative-close payout address is not negotiated at channel open time. A peer could socially engineer a close to an unexpected address.",
			Remediation: "Set enable-upfront-shutdown=true in lnd.conf to lock in the close address at channel open.",
		})
	}

	// max-cltv-expiry set very high
	if cfg.MaxCLTVExpiryExplicit && cfg.MaxCLTVExpiry > 2016 {
		findings = append(findings, scanner.Finding{
			ID:       "P-5",
			Module:   "policy",
			Severity: scanner.Medium,
			Title:    fmt.Sprintf("CLTV expiry limit is very high (max-cltv-expiry=%d blocks)", cfg.MaxCLTVExpiry),
			Description: fmt.Sprintf("Forwarded HTLCs can lock funds for up to %d blocks (~%d days). "+
				"This enables routing attacks where adversaries lock your channel liquidity for extended periods.",
				cfg.MaxCLTVExpiry, cfg.MaxCLTVExpiry/144),
			Remediation: "Set max-cltv-expiry=2016 in lnd.conf (the default, ~2 weeks) unless you have a specific reason for a higher value.",
		})
	}

	// minchansize too low or not set
	if cfg.MinChanSizeExplicit && cfg.MinChanSize < 20000 {
		findings = append(findings, scanner.Finding{
			ID:       "P-6",
			Module:   "policy",
			Severity: scanner.Medium,
			Title:    fmt.Sprintf("Minimum channel size is very low (minchansize=%d sats)", cfg.MinChanSize),
			Description: "Channels smaller than 20,000 sats cost very little to open but have negligible economic value. " +
				"They can be used as a channel-flooding DoS attack, consuming your node's resources.",
			Remediation: "Set minchansize=20000 or higher in lnd.conf.",
		})
	}

	return findings
}

// CheckBitcoinPolicy audits Bitcoin-section policy settings.
func CheckBitcoinPolicy(cfg *config.LndConfig) []scanner.Finding {
	var findings []scanner.Finding

	// bitcoin.timelockdelta too low
	if cfg.Bitcoin.TimelockDeltaExplicit && cfg.Bitcoin.TimelockDelta < 40 {
		findings = append(findings, scanner.Finding{
			ID:       "P-7",
			Module:   "policy",
			Severity: scanner.High,
			Title:    fmt.Sprintf("CLTV delta is dangerously low (bitcoin.timelockdelta=%d)", cfg.Bitcoin.TimelockDelta),
			Description: fmt.Sprintf("A CLTV delta of %d blocks gives your node very little time to go to chain "+
				"if an upstream HTLC times out. BOLTs recommend a minimum of 40. "+
				"A value below 40 risks fund loss during chain congestion.", cfg.Bitcoin.TimelockDelta),
			Remediation: "Set bitcoin.timelockdelta=80 in lnd.conf (recommended for production).",
		})
	}

	// bitcoin.minhtlc at the protocol minimum (1 msat)
	if cfg.Bitcoin.MinHTLCExplicit && cfg.Bitcoin.MinHTLC <= 1 {
		findings = append(findings, scanner.Finding{
			ID:          "P-8",
			Module:      "policy",
			Severity:    scanner.Low,
			Title:       fmt.Sprintf("Minimum HTLC is at protocol minimum (bitcoin.minhtlc=%d msat)", cfg.Bitcoin.MinHTLC),
			Description: "Accepting 1 msat HTLCs allows virtually free spam routing attempts that consume CPU for signature verification and database writes.",
			Remediation: "Set bitcoin.minhtlc=1000 (1 sat) or higher in lnd.conf to raise the cost of spam.",
		})
	}

	// bitcoin.estimatemode set to ECONOMICAL
	if cfg.Bitcoin.EstimateMode == "ECONOMICAL" {
		findings = append(findings, scanner.Finding{
			ID:          "P-9",
			Module:      "policy",
			Severity:    scanner.Medium,
			Title:       "Fee estimation uses ECONOMICAL mode",
			Description: "ECONOMICAL fee estimation produces lower fees but increases the risk of unconfirmed transactions during fee spikes. For channels with real funds, CONSERVATIVE is safer.",
			Remediation: "Set bitcoin.estimatemode=CONSERVATIVE in lnd.conf.",
		})
	}

	return findings
}

// CheckPaymentSecurity audits payment and invoice security settings.
func CheckPaymentSecurity(cfg *config.LndConfig) []scanner.Finding {
	var findings []scanner.Finding

	if cfg.AcceptKeysend {
		findings = append(findings, scanner.Finding{
			ID:          "P-10",
			Module:      "policy",
			Severity:    scanner.Info,
			Title:       "Keysend payments are accepted (accept-keysend=true)",
			Description: "Any node on the network can push spontaneous payments and attached data to this node without prior invoice exchange. This can be used for spam or to probe channel balances via repeated small payments.",
			Remediation: "Disable accept-keysend in lnd.conf if spontaneous payments are not required by your use case.",
		})
	}

	if cfg.AcceptAMP {
		findings = append(findings, scanner.Finding{
			ID:          "P-11",
			Module:      "policy",
			Severity:    scanner.Info,
			Title:       "AMP payments are accepted (accept-amp=true)",
			Description: "Atomic Multi-Path spontaneous payments are accepted. Same risk profile as keysend but for multi-part payments — allows unsolicited payment spam and balance probing.",
			Remediation: "Disable accept-amp in lnd.conf if AMP payments are not required.",
		})
	}

	if cfg.RequireInterceptor {
		findings = append(findings, scanner.Finding{
			ID:          "P-12",
			Module:      "policy",
			Severity:    scanner.High,
			Title:       "HTLC interceptor is required (requireinterceptor=true)",
			Description: "ALL HTLCs are held pending interceptor registration. If the interceptor process crashes or is never attached, the node stops processing ALL incoming and forwarded payments — a total payment DoS.",
			Remediation: "Remove requireinterceptor=true from lnd.conf unless you have a reliable, always-on interceptor process.",
		})
	}

	if cfg.RESTCors == "*" {
		findings = append(findings, scanner.Finding{
			ID:          "P-13",
			Module:      "access",
			Severity:    scanner.High,
			Title:       "REST CORS accepts all origins (restcors=*)",
			Description: "Any website visited by the operator can make credentialed REST requests using the browser's stored macaroons. A malicious website can silently invoke LND APIs.",
			Remediation: "Remove restcors=* from lnd.conf or restrict to specific trusted origins.",
		})
	}

	return findings
}
