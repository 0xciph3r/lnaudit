package checks

import (
	"fmt"

	lngrpc "github.com/NonsoAmadi10/lnaudit/pkg/grpc"
	"github.com/NonsoAmadi10/lnaudit/pkg/scanner"
)

// CheckLndVersion compares the running LND version against known CVEs.
func CheckLndVersion(client lngrpc.LndClient) ([]scanner.Finding, error) {
	info, err := client.GetInfo()
	if err != nil {
		return nil, fmt.Errorf("version check: %w", err)
	}

	var findings []scanner.Finding
	for _, cve := range cveDatabase {
		if versionBefore(info.Version, cve.FixedIn) {
			findings = append(findings, scanner.Finding{
				ID:       fmt.Sprintf("L-CVE-%s", cve.ID),
				Module:   "live",
				Severity: cve.Severity,
				Title:    fmt.Sprintf("%s: %s", cve.ID, cve.Title),
				Description: fmt.Sprintf(
					"Running LND %s which is affected by %s. %s",
					info.Version, cve.ID, cve.Description,
				),
				Remediation: fmt.Sprintf("Upgrade LND to %s-beta or later.", cve.FixedIn),
				Reference:   cve.Reference,
			})
		}
	}

	return findings, nil
}

// CheckChainSync verifies the node is fully synced to the blockchain.
func CheckChainSync(client lngrpc.LndClient) ([]scanner.Finding, error) {
	info, err := client.GetInfo()
	if err != nil {
		return nil, fmt.Errorf("chain sync check: %w", err)
	}

	var findings []scanner.Finding

	if !info.SyncedToChain {
		findings = append(findings, scanner.Finding{
			ID:       "L-1",
			Module:   "live",
			Severity: scanner.Critical,
			Title:    "Node is NOT synced to the blockchain",
			Description: fmt.Sprintf(
				"The node is at block height %d but has not finished syncing. "+
					"An unsynced node cannot verify channel states or detect on-chain fraud.",
				info.BlockHeight,
			),
			Remediation: "Wait for the node to fully sync before routing payments or opening channels.",
		})
	}

	if !info.SyncedToGraph {
		findings = append(findings, scanner.Finding{
			ID:       "L-2",
			Module:   "live",
			Severity: scanner.Medium,
			Title:    "Node is not synced to the channel graph",
			Description: "The node has not finished syncing the network graph. " +
				"Pathfinding and fee estimation may be unreliable.",
			Remediation: "Wait for graph sync to complete. This usually resolves on its own.",
		})
	}

	return findings, nil
}

// CheckPeerCount warns if the node has too few connected peers.
func CheckPeerCount(client lngrpc.LndClient) ([]scanner.Finding, error) {
	info, err := client.GetInfo()
	if err != nil {
		return nil, fmt.Errorf("peer count check: %w", err)
	}

	var findings []scanner.Finding

	if info.NumPeers == 0 {
		findings = append(findings, scanner.Finding{
			ID:       "L-3",
			Module:   "live",
			Severity: scanner.High,
			Title:    "Node has ZERO connected peers",
			Description: "The node is completely isolated with no peer connections. " +
				"It cannot route payments, monitor channels, or detect fraud.",
			Remediation: "Check network connectivity and firewall rules. Ensure LND can reach the internet.",
		})
	} else if info.NumPeers < 3 {
		findings = append(findings, scanner.Finding{
			ID:       "L-3",
			Module:   "live",
			Severity: scanner.Medium,
			Title:    fmt.Sprintf("Node has only %d peer(s)", info.NumPeers),
			Description: "Having fewer than 3 peers reduces redundancy for payment routing " +
				"and makes the node more susceptible to eclipse attacks.",
			Remediation: "Connect to additional well-known peers to improve resilience.",
		})
	}

	return findings, nil
}

// CheckPendingForceClose detects any channels being force-closed.
func CheckPendingForceClose(client lngrpc.LndClient) ([]scanner.Finding, error) {
	pending, err := client.PendingChannels()
	if err != nil {
		return nil, fmt.Errorf("force-close check: %w", err)
	}

	var findings []scanner.Finding

	if len(pending) > 0 {
		totalLimbo := int64(0)
		for _, fc := range pending {
			totalLimbo += fc.LimboBalance
		}

		findings = append(findings, scanner.Finding{
			ID:       "L-4",
			Module:   "live",
			Severity: scanner.High,
			Title:    fmt.Sprintf("%d channel(s) being force-closed (%d sats in limbo)", len(pending), totalLimbo),
			Description: "One or more channels are in a force-close state. " +
				"Funds are locked in time-locked transactions and may be at risk if the node goes offline before they mature.",
			Remediation: "Keep the node online until all force-close transactions are resolved. " +
				"Monitor the pending channels and ensure your watchtower is active.",
		})
	}

	return findings, nil
}

// CheckLargeLocalBalance flags channels where local balance exceeds a high
// percentage of the total capacity, indicating concentrated exposure.
func CheckLargeLocalBalance(client lngrpc.LndClient) ([]scanner.Finding, error) {
	channels, err := client.ListChannels()
	if err != nil {
		return nil, fmt.Errorf("balance check: %w", err)
	}

	bal, err := client.WalletBalance()
	if err != nil {
		return nil, fmt.Errorf("wallet balance check: %w", err)
	}

	var findings []scanner.Finding

	// Sum total local balance across all channels
	totalLocal := int64(0)
	for _, ch := range channels {
		totalLocal += ch.LocalBalance
	}

	totalExposure := totalLocal + bal.ConfirmedBalance

	// Flag individual channels with > 80% local balance and significant sats
	const highBalanceThreshold = 0.80
	const minSignificantSats = 500_000

	for _, ch := range channels {
		if ch.Capacity == 0 {
			continue
		}
		ratio := float64(ch.LocalBalance) / float64(ch.Capacity)
		if ratio > highBalanceThreshold && ch.LocalBalance > minSignificantSats {
			findings = append(findings, scanner.Finding{
				ID:       "L-5",
				Module:   "live",
				Severity: scanner.Medium,
				Title: fmt.Sprintf(
					"Channel %d has %.0f%% local balance (%d sats)",
					ch.ChanID, ratio*100, ch.LocalBalance,
				),
				Description: "A large portion of this channel's capacity is on your side. " +
					"This concentrates risk: if the remote peer force-closes, these funds are locked in a timelock.",
				Remediation: "Consider rebalancing the channel or splitting liquidity across multiple channels.",
			})
		}
	}

	// Flag if total node exposure is very high
	if totalExposure > 10_000_000 {
		findings = append(findings, scanner.Finding{
			ID:       "L-6",
			Module:   "live",
			Severity: scanner.Info,
			Title:    fmt.Sprintf("Total node exposure: %d sats (%.4f BTC)", totalExposure, float64(totalExposure)/1e8),
			Description: "This is the total value held by the node across on-chain wallet and Lightning channels. " +
				"Higher exposure warrants stricter security controls.",
			Remediation: "Ensure watchtowers are active, backups are current, and access controls are tight.",
		})
	}

	return findings, nil
}
