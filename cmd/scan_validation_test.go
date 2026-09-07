package cmd

import "testing"

func TestValidateScanFlagValues_AcceptsValidValues(t *testing.T) {
	if err := validateScanFlagValues("table", "high", "low"); err != nil {
		t.Fatalf("expected valid flags, got error: %v", err)
	}
	if err := validateScanFlagValues("json", "critical", "info"); err != nil {
		t.Fatalf("expected valid flags, got error: %v", err)
	}
	if err := validateScanFlagValues("sarif", "med", "HIGH"); err != nil {
		t.Fatalf("expected valid flags, got error: %v", err)
	}
}

func TestValidateScanFlagValues_RejectsInvalidFormat(t *testing.T) {
	if err := validateScanFlagValues("sariff", "high", "low"); err == nil {
		t.Fatal("expected invalid format to return error")
	}
}

func TestValidateScanFlagValues_RejectsInvalidFailOn(t *testing.T) {
	if err := validateScanFlagValues("table", "severe", "low"); err == nil {
		t.Fatal("expected invalid fail-on to return error")
	}
}

func TestValidateScanFlagValues_RejectsInvalidMinSeverity(t *testing.T) {
	if err := validateScanFlagValues("table", "high", "minor"); err == nil {
		t.Fatal("expected invalid min-severity to return error")
	}
}
