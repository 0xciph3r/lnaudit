package checks

import (
	"fmt"
	"math"

	lngrpc "github.com/0xciph3r/lnaudit/pkg/grpc"
	"github.com/0xciph3r/lnaudit/pkg/scanner"
)

const (
	// DefaultMaxHotWalletSats is a recommended threshold for confirmed on-chain funds.
	DefaultMaxHotWalletSats int64 = 5_000_000
	// DefaultMaxNodeExposureSats is a recommended threshold for wallet + local channel balance.
	DefaultMaxNodeExposureSats int64 = 10_000_000
	// DefaultMaxChannelCapacitySats is a recommended per-channel capacity threshold.
	DefaultMaxChannelCapacitySats int64 = 8_000_000
)

// ExposureLimits controls live alert thresholds for node fund exposure.
type ExposureLimits struct {
	MaxHotWalletSats    int64
	MaxNodeExposureSats int64
	MaxChannelCapSats   int64
}

// CheckExposureLimits validates live node balances against configurable thresholds.
func CheckExposureLimits(client lngrpc.LndClient, limits ExposureLimits) ([]scanner.Finding, error) {
	if limits.MaxHotWalletSats <= 0 && limits.MaxNodeExposureSats <= 0 && limits.MaxChannelCapSats <= 0 {
		return nil, nil
	}

	var channels []lngrpc.Channel
	var err error
	needChannels := limits.MaxChannelCapSats > 0 || limits.MaxNodeExposureSats > 0
	if needChannels {
		channels, err = client.ListChannels()
		if err != nil {
			return nil, fmt.Errorf("exposure limits check: %w", err)
		}
	}

	var wallet *lngrpc.WalletBalance
	if limits.MaxHotWalletSats > 0 || limits.MaxNodeExposureSats > 0 {
		wallet, err = client.WalletBalance()
		if err != nil {
			return nil, fmt.Errorf("exposure limits check: %w", err)
		}
	}

	var findings []scanner.Finding

	if limits.MaxHotWalletSats > 0 && wallet.ConfirmedBalance > limits.MaxHotWalletSats {
		sev := scanner.Medium
		if atLeastDouble(wallet.ConfirmedBalance, limits.MaxHotWalletSats) {
			sev = scanner.High
		}
		findings = append(findings, scanner.Finding{
			ID:       "L-11",
			Module:   "live",
			Severity: sev,
			Title:    "Hot wallet balance exceeds configured threshold",
			Description: fmt.Sprintf(
				"Confirmed wallet balance is %d sats, above the configured threshold of %d sats.",
				wallet.ConfirmedBalance, limits.MaxHotWalletSats,
			),
			Remediation: "Reduce hot-wallet allocation or raise --max-hot-wallet-sats if this posture is intentional.",
		})
	}

	totalLocal := int64(0)
	for _, ch := range channels {
		totalLocal += ch.LocalBalance
		if limits.MaxChannelCapSats > 0 && ch.Capacity > limits.MaxChannelCapSats {
			sev := scanner.Medium
			if atLeastDouble(ch.Capacity, limits.MaxChannelCapSats) {
				sev = scanner.High
			}
			findings = append(findings, scanner.Finding{
				ID:       "L-12",
				Module:   "live",
				Severity: sev,
				Title:    fmt.Sprintf("Channel %d capacity exceeds configured threshold", ch.ChanID),
				Description: fmt.Sprintf(
					"Channel capacity is %d sats, above the configured threshold of %d sats.",
					ch.Capacity, limits.MaxChannelCapSats,
				),
				Remediation: "Split large channels across multiple peers or raise --max-channel-capacity-sats if this is deliberate.",
			})
		}
	}

	totalExposure := totalLocal
	if wallet != nil {
		totalExposure += wallet.ConfirmedBalance
	}
	if limits.MaxNodeExposureSats > 0 && totalExposure > limits.MaxNodeExposureSats {
		sev := scanner.Medium
		if atLeastDouble(totalExposure, limits.MaxNodeExposureSats) {
			sev = scanner.High
		}
		findings = append(findings, scanner.Finding{
			ID:       "L-13",
			Module:   "live",
			Severity: sev,
			Title:    "Total node exposure exceeds configured threshold",
			Description: fmt.Sprintf(
				"Total exposure is %d sats (wallet + local channel balances), above the configured threshold of %d sats.",
				totalExposure, limits.MaxNodeExposureSats,
			),
			Remediation: "Lower node balances, distribute liquidity across separate nodes, or raise --max-node-exposure-sats if acceptable for your risk model.",
		})
	}

	return findings, nil
}

func atLeastDouble(value, threshold int64) bool {
	if threshold <= 0 {
		return false
	}
	if threshold > math.MaxInt64/2 {
		return false
	}
	return value >= threshold*2
}
