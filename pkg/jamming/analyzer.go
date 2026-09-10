package jamming

import (
	"fmt"
	"sort"

	"github.com/0xciph3r/lnaudit/pkg/scanner"
)

type metricPoint struct {
	snapshotIndex       int
	slotSaturation      float64
	liquiditySaturation float64
	hasLiquidity        bool
}

type streakInfo struct {
	length   int
	maxValue float64
}

const defaultRemoteMaxHTLCs = 483

// Analyze evaluates a channel timeline deterministically and returns findings.
func Analyze(t Timeline, opts Options) []Finding {
	normalized := normalizeOptions(opts)
	if len(t.Snapshots) == 0 {
		return []Finding{}
	}

	seriesByChannel, sampleCount := buildSeries(t)
	if sampleCount == 0 {
		return []Finding{}
	}

	channelIDs := make([]uint64, 0, len(seriesByChannel))
	for chanID := range seriesByChannel {
		channelIDs = append(channelIDs, chanID)
	}
	sort.Slice(channelIDs, func(i, j int) bool { return channelIDs[i] < channelIDs[j] })

	findings := make([]Finding, 0)
	for _, chanID := range channelIDs {
		points := seriesByChannel[chanID]

		slotStreak := evaluateStreak(
			points,
			func(point metricPoint) (bool, float64) {
				return point.slotSaturation >= normalized.SlotSaturationThreshold, point.slotSaturation
			},
		)
		liqStreak := evaluateStreak(
			points,
			func(point metricPoint) (bool, float64) {
				if !point.hasLiquidity {
					return false, 0
				}
				return point.liquiditySaturation >= normalized.LiquiditySaturationThreshold, point.liquiditySaturation
			},
		)
		corroboratedStreak := evaluateStreak(
			points,
			func(point metricPoint) (bool, float64) {
				if !point.hasLiquidity {
					return false, 0
				}
				slotOK := point.slotSaturation >= normalized.SlotSaturationThreshold
				liquidityOK := point.liquiditySaturation >= normalized.LiquiditySaturationThreshold
				if !slotOK || !liquidityOK {
					return false, 0
				}
				return true, max(point.slotSaturation, point.liquiditySaturation)
			},
		)

		slotSustained := slotStreak.length >= normalized.MinSustainedSamples
		liquiditySustained := liqStreak.length >= normalized.MinSustainedSamples
		corroborated := corroboratedStreak.length >= normalized.MinSustainedSamples

		if corroborated {
			findings = append(findings, Finding{
				ID:         "J-16-3",
				Class:      ClassCorroboratedJam,
				Severity:   scanner.High,
				Confidence: ConfidenceCorroborated,
				ChannelID:  chanID,
				Title:      fmt.Sprintf("Channel %d shows corroborated sustained jamming pressure", chanID),
				Description: "Slot and liquidity saturation remained elevated across the sampling window, " +
					"which is consistent with sustained jamming pressure.",
				Evidence: baseEvidence(
					"corroborated_saturation",
					corroboratedStreak.maxValue,
					max(normalized.SlotSaturationThreshold, normalized.LiquiditySaturationThreshold),
					sampleCount,
					corroboratedStreak.length,
					ConfidenceCorroborated,
				),
			})
			continue
		}

		if slotSustained {
			findings = append(findings, Finding{
				ID:         "J-16-1",
				Class:      ClassSlotPressure,
				Severity:   scanner.High,
				Confidence: ConfidenceSustained,
				ChannelID:  chanID,
				Title:      fmt.Sprintf("Channel %d has sustained slot saturation pressure", chanID),
				Description: "Pending HTLC slot occupancy stayed above the configured saturation threshold " +
					"for multiple consecutive samples.",
				Evidence: baseEvidence(
					"slot_saturation_ratio",
					slotStreak.maxValue,
					normalized.SlotSaturationThreshold,
					sampleCount,
					slotStreak.length,
					ConfidenceSustained,
				),
			})
		} else if slotStreak.length > 0 && normalized.EmitObserved {
			findings = append(findings, Finding{
				ID:         "J-16-1",
				Class:      ClassSlotPressure,
				Severity:   scanner.Medium,
				Confidence: ConfidenceObserved,
				ChannelID:  chanID,
				Title:      fmt.Sprintf("Channel %d shows observed slot saturation spike", chanID),
				Description: "A slot saturation anomaly was observed but did not persist long enough " +
					"to classify as sustained pressure.",
				Evidence: baseEvidence(
					"slot_saturation_ratio",
					slotStreak.maxValue,
					normalized.SlotSaturationThreshold,
					sampleCount,
					slotStreak.length,
					ConfidenceObserved,
				),
			})
		}

		if liquiditySustained {
			findings = append(findings, Finding{
				ID:         "J-16-2",
				Class:      ClassLiquidityPressure,
				Severity:   scanner.High,
				Confidence: ConfidenceSustained,
				ChannelID:  chanID,
				Title:      fmt.Sprintf("Channel %d has sustained liquidity saturation pressure", chanID),
				Description: "Pending HTLC value remained elevated relative to channel capacity across " +
					"multiple consecutive samples.",
				Evidence: baseEvidence(
					"liquidity_saturation_ratio",
					liqStreak.maxValue,
					normalized.LiquiditySaturationThreshold,
					sampleCount,
					liqStreak.length,
					ConfidenceSustained,
				),
			})
		} else if liqStreak.length > 0 && normalized.EmitObserved {
			findings = append(findings, Finding{
				ID:         "J-16-2",
				Class:      ClassLiquidityPressure,
				Severity:   scanner.Medium,
				Confidence: ConfidenceObserved,
				ChannelID:  chanID,
				Title:      fmt.Sprintf("Channel %d shows observed liquidity saturation spike", chanID),
				Description: "A liquidity saturation anomaly was observed but did not persist long enough " +
					"to classify as sustained pressure.",
				Evidence: baseEvidence(
					"liquidity_saturation_ratio",
					liqStreak.maxValue,
					normalized.LiquiditySaturationThreshold,
					sampleCount,
					liqStreak.length,
					ConfidenceObserved,
				),
			})
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		if findings[i].Class != findings[j].Class {
			return findings[i].Class < findings[j].Class
		}
		if findings[i].ChannelID != findings[j].ChannelID {
			return findings[i].ChannelID < findings[j].ChannelID
		}
		return findings[i].Title < findings[j].Title
	})

	return findings
}

func buildSeries(t Timeline) (seriesByChannel map[uint64][]metricPoint, sampleCount int) {
	snapshots := append([]Snapshot(nil), t.Snapshots...)
	sort.SliceStable(snapshots, func(i, j int) bool {
		return snapshots[i].Timestamp.Before(snapshots[j].Timestamp)
	})

	deduped := make([]Snapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if len(deduped) > 0 && snapshot.Timestamp.Equal(deduped[len(deduped)-1].Timestamp) {
			continue
		}
		deduped = append(deduped, snapshot)
	}

	seriesByChannel = make(map[uint64][]metricPoint)
	sampleCount = 0
	for snapshotIndex, snapshot := range deduped {
		channels := append([]ChannelSample(nil), snapshot.Channels...)
		sort.Slice(channels, func(i, j int) bool {
			return channels[i].ChanID < channels[j].ChanID
		})

		if len(channels) == 0 {
			continue
		}
		sampleCount++
		seen := make(map[uint64]struct{}, len(channels))
		for _, channel := range channels {
			if _, exists := seen[channel.ChanID]; exists {
				continue
			}
			seen[channel.ChanID] = struct{}{}

			slotDenominator := float64(channel.RemoteMaxHTLCs)
			if slotDenominator < 1 {
				slotDenominator = defaultRemoteMaxHTLCs
			}
			slotCount := channel.PendingHTLCCount
			if slotCount < 0 {
				slotCount = 0
			}

			liquiditySaturation := 0.0
			hasLiquidity := channel.CapacitySat > 0
			if hasLiquidity {
				liquidityValue := channel.PendingHTLCValueSat
				if liquidityValue < 0 {
					liquidityValue = 0
				}
				liquiditySaturation = float64(liquidityValue) / float64(channel.CapacitySat)
			}

			seriesByChannel[channel.ChanID] = append(seriesByChannel[channel.ChanID], metricPoint{
				snapshotIndex:       snapshotIndex,
				slotSaturation:      float64(slotCount) / slotDenominator,
				liquiditySaturation: liquiditySaturation,
				hasLiquidity:        hasLiquidity,
			})
		}
	}
	return
}

func evaluateStreak(points []metricPoint, predicate func(metricPoint) (bool, float64)) streakInfo {
	best := streakInfo{}
	currentLength := 0
	currentMax := 0.0
	prevIndex := -1

	for _, point := range points {
		matched, value := predicate(point)
		if !matched {
			currentLength = 0
			currentMax = 0
			prevIndex = -1
			continue
		}

		if currentLength == 0 || point.snapshotIndex != prevIndex+1 {
			currentLength = 1
			currentMax = value
		} else {
			currentLength++
			if value > currentMax {
				currentMax = value
			}
		}
		prevIndex = point.snapshotIndex

		if currentLength > best.length {
			best = streakInfo{
				length:   currentLength,
				maxValue: currentMax,
			}
		}
	}
	return best
}

func baseEvidence(metric string, measured, threshold float64, sampleCount, sustainedSamples int, confidence Confidence) map[string]interface{} {
	return map[string]interface{}{
		"metric":         metric,
		"measured_value": measured,
		"threshold":      threshold,
		"sample_count":   sampleCount,
		"window_samples": sustainedSamples,
		"confidence":     confidence,
	}
}
