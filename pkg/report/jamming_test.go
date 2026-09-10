package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/0xciph3r/lnaudit/pkg/jamming"
	"github.com/0xciph3r/lnaudit/pkg/scanner"
)

func sampleJammingFindings() []jamming.Finding {
	return []jamming.Finding{
		{
			ID:          "J-16-1",
			Class:       jamming.ClassSlotPressure,
			Severity:    scanner.High,
			Confidence:  jamming.ConfidenceSustained,
			ChannelID:   1234,
			Title:       "Channel 1234 has sustained slot saturation pressure",
			Description: "Pending HTLC slot occupancy remained elevated.",
			Evidence: map[string]interface{}{
				"metric":         "slot_saturation_ratio",
				"measured_value": 0.8,
			},
		},
	}
}

func TestJammingJSONWriter_ValidJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := JammingJSONWriter(&buf, sampleJammingFindings()); err != nil {
		t.Fatalf("JammingJSONWriter error: %v", err)
	}

	var out JammingJSONOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(out.Findings))
	}
	if out.Findings[0].Confidence != string(jamming.ConfidenceSustained) {
		t.Fatalf("confidence = %q, want sustained", out.Findings[0].Confidence)
	}
}

func TestJammingJSONWriterWithScore_UsesProvidedScore(t *testing.T) {
	var buf bytes.Buffer
	filtered := []jamming.Finding{}
	if err := JammingJSONWriterWithScore(
		&buf,
		filtered,
		80,
		scanner.RatingAcceptable,
		map[string]int{"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
	); err != nil {
		t.Fatalf("JammingJSONWriterWithScore error: %v", err)
	}

	var out JammingJSONOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if out.Score != 80 {
		t.Fatalf("score = %d, want 80", out.Score)
	}
	if out.Summary["high"] != 1 {
		t.Fatalf("summary high = %d, want 1", out.Summary["high"])
	}
}

func TestJammingSARIFWriter_ContainsConfidenceAndEvidence(t *testing.T) {
	var buf bytes.Buffer
	if err := JammingSARIFWriter(&buf, sampleJammingFindings()); err != nil {
		t.Fatalf("JammingSARIFWriter error: %v", err)
	}

	var out sarifLog
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if len(out.Runs) != 1 || len(out.Runs[0].Results) != 1 {
		t.Fatalf("unexpected SARIF shape: %+v", out)
	}
	props := out.Runs[0].Results[0].Properties
	if props == nil {
		t.Fatal("result properties missing")
	}
	if props.Confidence != string(jamming.ConfidenceSustained) {
		t.Fatalf("confidence = %q, want sustained", props.Confidence)
	}
	if props.Evidence == nil {
		t.Fatal("expected evidence in SARIF properties")
	}
}

func TestSARIFWriter_DoesNotEmitJammingFieldsForScannerFindings(t *testing.T) {
	var buf bytes.Buffer
	r := sampleReport()
	if err := SARIFWriter(&buf, r); err != nil {
		t.Fatalf("SARIFWriter error: %v", err)
	}

	var out sarifLog
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	for _, result := range out.Runs[0].Results {
		if result.Properties != nil && result.Properties.Confidence != "" {
			t.Fatalf("unexpected confidence field on scanner finding: %+v", result)
		}
		if result.Properties != nil && len(result.Properties.Evidence) > 0 {
			t.Fatalf("unexpected evidence field on scanner finding: %+v", result)
		}
	}
}
