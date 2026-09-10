package jamming

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/0xciph3r/lnaudit/pkg/scanner"
)

func TestAnalyze_FixtureCoverage(t *testing.T) {
	tests := []struct {
		name         string
		fixture      string
		wantClass    AttackClass
		wantSeverity scanner.Severity
		wantMinCount int
	}{
		{
			name:         "sustained slot jam emits high slot pressure finding",
			fixture:      "sustained_slot_jam.json",
			wantClass:    ClassSlotPressure,
			wantSeverity: scanner.High,
			wantMinCount: 1,
		},
		{
			name:         "sustained liquidity jam emits high liquidity finding",
			fixture:      "sustained_liquidity_jam.json",
			wantClass:    ClassLiquidityPressure,
			wantSeverity: scanner.High,
			wantMinCount: 1,
		},
		{
			name:         "threshold squatting is detected by saturation ratio",
			fixture:      "threshold_squatting.json",
			wantClass:    ClassSlotPressure,
			wantSeverity: scanner.High,
			wantMinCount: 1,
		},
		{
			name:         "concurrent slot and liquidity pressure emit corroborated finding",
			fixture:      "sustained_corroborated_jam.json",
			wantClass:    ClassCorroboratedJam,
			wantSeverity: scanner.High,
			wantMinCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timeline := loadFixtureTimeline(t, tt.fixture)
			findings := Analyze(timeline, DefaultOptions())
			if countFindings(findings, tt.wantClass, tt.wantSeverity) < tt.wantMinCount {
				t.Fatalf(
					"Analyze(%s) did not emit expected findings class=%s severity=%s; findings=%+v",
					tt.fixture,
					tt.wantClass,
					tt.wantSeverity,
					findings,
				)
			}
		})
	}
}

func TestAnalyze_BenignAndPoisoningDoNotEscalateHigh(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
	}{
		{
			name:    "benign burst is not escalated to high",
			fixture: "benign_burst.json",
		},
		{
			name:    "scan-window poisoning pattern is not escalated to high",
			fixture: "scan_window_poisoning.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timeline := loadFixtureTimeline(t, tt.fixture)
			findings := Analyze(timeline, DefaultOptions())
			for _, finding := range findings {
				if finding.Severity >= scanner.High {
					t.Fatalf("unexpected high-or-above finding for %s: %+v", tt.fixture, finding)
				}
			}
		})
	}
}

func TestAnalyze_DeterministicOutput(t *testing.T) {
	timeline := loadFixtureTimeline(t, "sustained_slot_jam.json")
	opts := DefaultOptions()

	first := Analyze(timeline, opts)
	second := Analyze(timeline, opts)

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("determinism failure: findings differ between identical runs\nfirst=%+v\nsecond=%+v", first, second)
	}

	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first run: %v", err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal second run: %v", err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("byte determinism failure: json mismatch\nfirst=%s\nsecond=%s", firstJSON, secondJSON)
	}
}

func TestAnalyze_NonOverlappingSignalsDoNotCorroborate(t *testing.T) {
	timeline := Timeline{
		Snapshots: []Snapshot{
			{
				Timestamp: mustTime(t, "2026-02-01T00:00:00Z"),
				Channels:  []ChannelSample{{ChanID: 9001, CapacitySat: 1_000_000, PendingHTLCCount: 21, PendingHTLCValueSat: 20_000, RemoteMaxHTLCs: 30}},
			},
			{
				Timestamp: mustTime(t, "2026-02-01T00:01:00Z"),
				Channels:  []ChannelSample{{ChanID: 9001, CapacitySat: 1_000_000, PendingHTLCCount: 22, PendingHTLCValueSat: 20_000, RemoteMaxHTLCs: 30}},
			},
			{
				Timestamp: mustTime(t, "2026-02-01T00:02:00Z"),
				Channels:  []ChannelSample{{ChanID: 9001, CapacitySat: 1_000_000, PendingHTLCCount: 23, PendingHTLCValueSat: 20_000, RemoteMaxHTLCs: 30}},
			},
			{
				Timestamp: mustTime(t, "2026-02-01T00:03:00Z"),
				Channels:  []ChannelSample{{ChanID: 9001, CapacitySat: 1_000_000, PendingHTLCCount: 1, PendingHTLCValueSat: 700_000, RemoteMaxHTLCs: 30}},
			},
			{
				Timestamp: mustTime(t, "2026-02-01T00:04:00Z"),
				Channels:  []ChannelSample{{ChanID: 9001, CapacitySat: 1_000_000, PendingHTLCCount: 1, PendingHTLCValueSat: 710_000, RemoteMaxHTLCs: 30}},
			},
			{
				Timestamp: mustTime(t, "2026-02-01T00:05:00Z"),
				Channels:  []ChannelSample{{ChanID: 9001, CapacitySat: 1_000_000, PendingHTLCCount: 1, PendingHTLCValueSat: 720_000, RemoteMaxHTLCs: 30}},
			},
		},
	}

	findings := Analyze(timeline, DefaultOptions())
	if hasClassHighOrAbove(findings, ClassCorroboratedJam) {
		t.Fatalf("unexpected corroborated finding for non-overlapping signals: %+v", findings)
	}
	if !hasClassHighOrAbove(findings, ClassSlotPressure) {
		t.Fatalf("expected slot pressure finding, got: %+v", findings)
	}
	if !hasClassHighOrAbove(findings, ClassLiquidityPressure) {
		t.Fatalf("expected liquidity pressure finding, got: %+v", findings)
	}
}

func TestAnalyze_DuplicateChannelRowsDoNotCreateSustainedFinding(t *testing.T) {
	timeline := Timeline{
		Snapshots: []Snapshot{
			{
				Timestamp: mustTime(t, "2026-02-02T00:00:00Z"),
				Channels: []ChannelSample{
					{ChanID: 9101, CapacitySat: 1_000_000, PendingHTLCCount: 24, PendingHTLCValueSat: 20_000, RemoteMaxHTLCs: 30},
					{ChanID: 9101, CapacitySat: 1_000_000, PendingHTLCCount: 24, PendingHTLCValueSat: 20_000, RemoteMaxHTLCs: 30},
					{ChanID: 9101, CapacitySat: 1_000_000, PendingHTLCCount: 24, PendingHTLCValueSat: 20_000, RemoteMaxHTLCs: 30},
				},
			},
		},
	}

	findings := Analyze(timeline, Options{MinSustainedSamples: 3, EmitObserved: true})
	if hasHighOrAbove(findings) {
		t.Fatalf("single snapshot duplicates should not create high findings: %+v", findings)
	}
}

func TestAnalyze_ChannelAbsenceBreaksStreak(t *testing.T) {
	timeline := Timeline{
		Snapshots: []Snapshot{
			{Timestamp: mustTime(t, "2026-02-03T00:00:00Z"), Channels: []ChannelSample{{ChanID: 9201, CapacitySat: 1_000_000, PendingHTLCCount: 24, PendingHTLCValueSat: 20_000, RemoteMaxHTLCs: 30}}},
			{Timestamp: mustTime(t, "2026-02-03T00:01:00Z"), Channels: []ChannelSample{}},
			{Timestamp: mustTime(t, "2026-02-03T00:02:00Z"), Channels: []ChannelSample{{ChanID: 9201, CapacitySat: 1_000_000, PendingHTLCCount: 24, PendingHTLCValueSat: 20_000, RemoteMaxHTLCs: 30}}},
			{Timestamp: mustTime(t, "2026-02-03T00:03:00Z"), Channels: []ChannelSample{{ChanID: 9201, CapacitySat: 1_000_000, PendingHTLCCount: 24, PendingHTLCValueSat: 20_000, RemoteMaxHTLCs: 30}}},
		},
	}

	findings := Analyze(timeline, Options{MinSustainedSamples: 3})
	if hasHighOrAbove(findings) {
		t.Fatalf("gap-separated samples should not count as one sustained streak: %+v", findings)
	}
}

func TestAnalyze_UnknownRemoteMaxDoesNotEscalateToHigh(t *testing.T) {
	timeline := Timeline{
		Snapshots: []Snapshot{
			{Timestamp: mustTime(t, "2026-02-04T00:00:00Z"), Channels: []ChannelSample{{ChanID: 9301, CapacitySat: 1_000_000, PendingHTLCCount: 1, PendingHTLCValueSat: 10_000, RemoteMaxHTLCs: 0}}},
			{Timestamp: mustTime(t, "2026-02-04T00:01:00Z"), Channels: []ChannelSample{{ChanID: 9301, CapacitySat: 1_000_000, PendingHTLCCount: 1, PendingHTLCValueSat: 10_000, RemoteMaxHTLCs: 0}}},
			{Timestamp: mustTime(t, "2026-02-04T00:02:00Z"), Channels: []ChannelSample{{ChanID: 9301, CapacitySat: 1_000_000, PendingHTLCCount: 1, PendingHTLCValueSat: 10_000, RemoteMaxHTLCs: 0}}},
		},
	}

	findings := Analyze(timeline, DefaultOptions())
	if hasHighOrAbove(findings) {
		t.Fatalf("unknown remote max should not trigger high slot saturation: %+v", findings)
	}
}

func TestAnalyze_SingleSnapshotGuardrail(t *testing.T) {
	timeline := Timeline{
		Snapshots: []Snapshot{
			{Timestamp: mustTime(t, "2026-02-05T00:00:00Z"), Channels: []ChannelSample{{ChanID: 9401, CapacitySat: 1_000_000, PendingHTLCCount: 25, PendingHTLCValueSat: 10_000, RemoteMaxHTLCs: 30}}},
		},
	}

	findings := Analyze(timeline, Options{MinSustainedSamples: 1, EmitObserved: true})
	if hasHighOrAbove(findings) {
		t.Fatalf("single snapshot must not produce high severity: %+v", findings)
	}
}

func TestAnalyze_EvidenceFieldsCompleteness(t *testing.T) {
	timeline := loadFixtureTimeline(t, "sustained_slot_jam.json")
	findings := Analyze(timeline, DefaultOptions())
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	requiredKeys := []string{
		"metric",
		"measured_value",
		"threshold",
		"sample_count",
		"window_samples",
		"confidence",
	}

	for _, finding := range findings {
		for _, key := range requiredKeys {
			if _, ok := finding.Evidence[key]; !ok {
				t.Fatalf("missing evidence key %q on finding %+v", key, finding)
			}
		}
	}
}

func TestAnalyze_STRIDEThreatScenarios(t *testing.T) {
	tests := []struct {
		name           string
		strideCategory string
		fixture        string
		expectHigh     bool
	}{
		{
			name:           "DoS sustained slot pressure",
			strideCategory: "Denial of Service",
			fixture:        "sustained_slot_jam.json",
			expectHigh:     true,
		},
		{
			name:           "DoS sustained liquidity lockup",
			strideCategory: "Denial of Service",
			fixture:        "sustained_liquidity_jam.json",
			expectHigh:     true,
		},
		{
			name:           "Tampering-like scan poisoning should not escalate",
			strideCategory: "Tampering",
			fixture:        "scan_window_poisoning.json",
			expectHigh:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+" ["+tt.strideCategory+"]", func(t *testing.T) {
			findings := Analyze(loadFixtureTimeline(t, tt.fixture), DefaultOptions())
			hasHigh := hasHighOrAbove(findings)
			if hasHigh != tt.expectHigh {
				t.Fatalf("STRIDE scenario %q expected high=%v got high=%v", tt.fixture, tt.expectHigh, hasHigh)
			}
		})
	}
}

func TestAnalyze_PASTAAttackProgressionScenarios(t *testing.T) {
	tests := []struct {
		name          string
		pastaPhase    int
		fixture       string
		expectClasses []AttackClass
	}{
		{
			name:          "Phase 4 attack simulation catches threshold squatting",
			pastaPhase:    4,
			fixture:       "threshold_squatting.json",
			expectClasses: []AttackClass{ClassSlotPressure},
		},
		{
			name:          "Phase 5 weakness analysis keeps benign burst below sustained classes",
			pastaPhase:    5,
			fixture:       "benign_burst.json",
			expectClasses: nil,
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s [phase %d]", tt.name, tt.pastaPhase), func(t *testing.T) {
			findings := Analyze(loadFixtureTimeline(t, tt.fixture), DefaultOptions())

			if len(tt.expectClasses) == 0 {
				if hasHighOrAbove(findings) {
					t.Fatalf("PASTA benign scenario escalated unexpectedly: %+v", findings)
				}
				return
			}

			for _, class := range tt.expectClasses {
				if !hasClassHighOrAbove(findings, class) {
					t.Fatalf("PASTA scenario missing class %q at HIGH severity; findings=%+v", class, findings)
				}
			}
		})
	}
}

func loadFixtureTimeline(t *testing.T, name string) Timeline {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "timelines", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var timeline Timeline
	if err := json.Unmarshal(raw, &timeline); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", name, err)
	}
	return timeline
}

func countFindings(findings []Finding, class AttackClass, severity scanner.Severity) int {
	count := 0
	for _, finding := range findings {
		if finding.Class == class && finding.Severity == severity {
			count++
		}
	}
	return count
}

func hasHighOrAbove(findings []Finding) bool {
	for _, finding := range findings {
		if finding.Severity >= scanner.High {
			return true
		}
	}
	return false
}

func hasClassHighOrAbove(findings []Finding, class AttackClass) bool {
	for _, finding := range findings {
		if finding.Class == class && finding.Severity >= scanner.High {
			return true
		}
	}
	return false
}

func mustTime(t *testing.T, raw string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t.Fatalf("parse time %q: %v", raw, err)
	}
	return parsed
}
