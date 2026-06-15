package checks

import (
	"fmt"

	lngrpc "github.com/0xciph3r/lnaudit/pkg/grpc"
	"github.com/0xciph3r/lnaudit/pkg/scanner"
)

// CheckChannelJamming detects channels with a high number of pending HTLCs,
// which may indicate an active channel jamming attack.
func CheckChannelJamming(client lngrpc.LndClient) ([]scanner.Finding, error) {
	channels, err := client.ListChannels()
	if err != nil {
		return nil, fmt.Errorf("channel jamming check: %w", err)
	}

	var findings []scanner.Finding

	const jammingThreshold = 20

	totalPending := 0
	jammedCount := 0

	for _, ch := range channels {
		totalPending += ch.NumPendingHTLCs

		if ch.NumPendingHTLCs >= jammingThreshold {
			jammedCount++
			findings = append(findings, scanner.Finding{
				ID:       "L-7",
				Module:   "live",
				Severity: scanner.High,
				Title: fmt.Sprintf(
					"Channel %d has %d pending HTLCs (possible jamming)",
					ch.ChanID, ch.NumPendingHTLCs,
				),
				Description: fmt.Sprintf(
					"This channel with peer %s has %d pending HTLCs, which is unusually high. "+
						"This may indicate an active channel jamming attack where an adversary "+
						"holds many HTLCs open to exhaust your channel capacity.",
					ch.RemotePubkey[:16]+"...", ch.NumPendingHTLCs,
				),
				Remediation: "Consider disconnecting from this peer or closing the channel. " +
					"Lower default-remote-max-htlcs in lnd.conf to limit HTLC slots.",
			})
		}
	}

	if totalPending > 50 && jammedCount == 0 {
		findings = append(findings, scanner.Finding{
			ID:       "L-8",
			Module:   "live",
			Severity: scanner.Medium,
			Title:    fmt.Sprintf("High total pending HTLCs across all channels (%d)", totalPending),
			Description: "The node has a large number of pending HTLCs spread across multiple channels. " +
				"While no single channel is critically jammed, the aggregate exposure is elevated.",
			Remediation: "Monitor pending HTLC counts. Consider lowering default-remote-max-htlcs to reduce total exposure.",
		})
	}

	return findings, nil
}

// CheckZeroConfChannels detects active zero-confirmation channels.
func CheckZeroConfChannels(client lngrpc.LndClient) ([]scanner.Finding, error) {
	channels, err := client.ListChannels()
	if err != nil {
		return nil, fmt.Errorf("zero-conf check: %w", err)
	}

	var findings []scanner.Finding

	zeroConfCount := 0
	totalZeroConfCapacity := int64(0)

	for _, ch := range channels {
		if ch.ZeroConf {
			zeroConfCount++
			totalZeroConfCapacity += ch.Capacity
		}
	}

	if zeroConfCount > 0 {
		findings = append(findings, scanner.Finding{
			ID:       "L-9",
			Module:   "live",
			Severity: scanner.High,
			Title: fmt.Sprintf(
				"%d zero-conf channel(s) active (%d sats total capacity)",
				zeroConfCount, totalZeroConfCapacity,
			),
			Description: "Zero-confirmation channels are active on this node. These channels were " +
				"treated as open before the funding transaction had any on-chain confirmations. " +
				"The channel opener could have double-spent the funding transaction.",
			Remediation: "Only use zero-conf channels with explicitly trusted counterparties. " +
				"Disable protocol.zero-conf in lnd.conf to prevent new zero-conf channels.",
		})
	}

	return findings, nil
}

// CheckHighHTLCLimits detects channels where the remote party has negotiated
// excessively high HTLC limits, increasing jamming exposure.
func CheckHighHTLCLimits(client lngrpc.LndClient) ([]scanner.Finding, error) {
	channels, err := client.ListChannels()
	if err != nil {
		return nil, fmt.Errorf("HTLC limit check: %w", err)
	}

	var findings []scanner.Finding

	const dangerousHTLCLimit uint32 = 200
	highLimitCount := 0

	for _, ch := range channels {
		if ch.RemoteMaxHTLCs >= dangerousHTLCLimit {
			highLimitCount++
		}
	}

	if highLimitCount > 0 {
		findings = append(findings, scanner.Finding{
			ID:       "L-10",
			Module:   "live",
			Severity: scanner.Medium,
			Title: fmt.Sprintf(
				"%d channel(s) allow %d+ remote HTLCs",
				highLimitCount, dangerousHTLCLimit,
			),
			Description: fmt.Sprintf(
				"%d channels allow the remote party to add %d or more concurrent HTLCs. "+
					"High HTLC limits increase exposure to channel jamming attacks where "+
					"an adversary pins many dust HTLCs to exhaust commitment space.",
				highLimitCount, dangerousHTLCLimit,
			),
			Remediation: "Set default-remote-max-htlcs=30 in lnd.conf for new channels. " +
				"Existing channels retain their negotiated limits until closed and reopened.",
		})
	}

	return findings, nil
}
