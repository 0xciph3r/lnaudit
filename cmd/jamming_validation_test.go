package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func resetJammingFlagsForTest() {
	jammingFromFile = ""
	jammingLndDir = ""
	jammingConnectAddr = ""
	jammingMacaroonPath = ""
	jammingTLSCertPath = ""
	jammingRecordPath = ""
	jammingOutputFormat = "table"
	jammingMinSeverity = "low"
	jammingFailOn = "critical"
	jammingNoColor = false
	jammingQuiet = false
	jammingEmitObserved = false
	jammingSlotThreshold = 0.60
	jammingLiquidityThreshold = 0.60
	jammingMinSustained = 3
}

func TestValidateJammingAnalyzeFlags_AcceptsValidFromFile(t *testing.T) {
	resetJammingFlagsForTest()
	jammingFromFile = "testdata/timelines/sustained_slot_jam.json"
	if err := validateJammingAnalyzeFlags(); err != nil {
		t.Fatalf("expected valid flags, got error: %v", err)
	}
}

func TestValidateJammingAnalyzeFlags_RejectsMissingSource(t *testing.T) {
	resetJammingFlagsForTest()
	if err := validateJammingAnalyzeFlags(); err == nil {
		t.Fatal("expected missing source to error")
	}
}

func TestValidateJammingAnalyzeFlags_RejectsCombinedSources(t *testing.T) {
	resetJammingFlagsForTest()
	jammingFromFile = "timeline.json"
	jammingConnectAddr = "localhost:10009"
	if err := validateJammingAnalyzeFlags(); err == nil {
		t.Fatal("expected combined source flags to error")
	}
}

func TestValidateJammingAnalyzeFlags_RejectsRecordWithoutConnect(t *testing.T) {
	resetJammingFlagsForTest()
	jammingFromFile = "timeline.json"
	jammingRecordPath = "record.json"
	if err := validateJammingAnalyzeFlags(); err == nil {
		t.Fatal("expected --record without --connect to error")
	}
}

func TestValidateJammingAnalyzeFlags_RejectsInvalidThresholds(t *testing.T) {
	resetJammingFlagsForTest()
	jammingFromFile = "timeline.json"
	jammingSlotThreshold = 0
	if err := validateJammingAnalyzeFlags(); err == nil {
		t.Fatal("expected invalid slot threshold to error")
	}

	resetJammingFlagsForTest()
	jammingFromFile = "timeline.json"
	jammingLiquidityThreshold = 1.5
	if err := validateJammingAnalyzeFlags(); err == nil {
		t.Fatal("expected invalid liquidity threshold to error")
	}
}

func TestValidateJammingAnalyzeFlags_RejectsInvalidMinSustained(t *testing.T) {
	resetJammingFlagsForTest()
	jammingFromFile = "timeline.json"
	jammingMinSustained = 1
	if err := validateJammingAnalyzeFlags(); err == nil {
		t.Fatal("expected invalid min sustained to error")
	}
}

func TestResolveJammingTimeline_RejectsEmptyTimelineFile(t *testing.T) {
	resetJammingFlagsForTest()
	dir := t.TempDir()
	path := filepath.Join(dir, "empty-timeline.json")
	if err := os.WriteFile(path, []byte(`{"snapshots":[]}`), 0o600); err != nil {
		t.Fatalf("write empty timeline: %v", err)
	}

	jammingFromFile = path
	_, err := resolveJammingTimeline()
	if err == nil {
		t.Fatal("expected empty timeline file to error")
	}
}
