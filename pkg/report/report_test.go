package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xciph3r/lnaudit/pkg/scanner"
)

func sampleReport() *scanner.Report {
	r := &scanner.Report{}
	r.Add(scanner.Finding{
		ID:          "T-3",
		Module:      "transport",
		Severity:    scanner.Critical,
		Title:       "RPC bound to 0.0.0.0:10009",
		Description: "gRPC control plane is exposed to all network interfaces.",
		Remediation: "Change rpclisten to 127.0.0.1:10009 in lnd.conf",
	})
	r.Add(scanner.Finding{
		ID:          "K-2",
		Module:      "keys",
		Severity:    scanner.Critical,
		Title:       "Tor onion key is NOT encrypted on disk",
		Remediation: "Set tor.encryptkey=true and restart LND",
	})
	r.Add(scanner.Finding{
		ID:          "N-2",
		Module:      "privacy",
		Severity:    scanner.Medium,
		Title:       "Stream isolation is disabled",
		Remediation: "Set tor.streamisolation=true",
	})
	r.Add(scanner.Finding{
		ID:       "T-1",
		Module:   "transport",
		Severity: scanner.Info,
		Title:    "TLS certificate valid (expires 2025-11-15)",
	})
	return r
}

func TestTableWriter_ContainsScore(t *testing.T) {
	var buf bytes.Buffer
	r := sampleReport()
	TableWriter(&buf, r, false)
	output := buf.String()

	if !strings.Contains(output, "Score:") {
		t.Error("table output should contain a score line")
	}
	if !strings.Contains(output, "/100") {
		t.Error("table output should show score out of 100")
	}
}

func TestTableWriter_ContainsFindings(t *testing.T) {
	var buf bytes.Buffer
	r := sampleReport()
	TableWriter(&buf, r, false)
	output := buf.String()

	if !strings.Contains(output, "RPC bound to 0.0.0.0:10009") {
		t.Error("table output should contain finding title")
	}
	if !strings.Contains(output, "Transport Security") {
		t.Error("table output should contain module header")
	}
}

func TestTableWriter_EmptyReport(t *testing.T) {
	var buf bytes.Buffer
	r := &scanner.Report{}
	TableWriter(&buf, r, false)
	output := buf.String()

	if !strings.Contains(output, "No findings") {
		t.Error("empty report should say no findings")
	}
}

func TestTableWriter_ShowsRemediation(t *testing.T) {
	var buf bytes.Buffer
	r := sampleReport()
	TableWriter(&buf, r, false)
	output := buf.String()

	if !strings.Contains(output, "Recommendation:") {
		t.Error("table output should show recommendation label")
	}
	if !strings.Contains(output, "rpclisten") {
		t.Error("table output should show remediation content")
	}
}

func TestJSONWriter_ValidJSON(t *testing.T) {
	var buf bytes.Buffer
	r := sampleReport()
	if err := JSONWriter(&buf, r); err != nil {
		t.Fatalf("JSONWriter error: %v", err)
	}

	var out JSONOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

func TestJSONWriter_ScoreAndRating(t *testing.T) {
	var buf bytes.Buffer
	r := sampleReport()
	if err := JSONWriter(&buf, r); err != nil {
		t.Fatalf("JSONWriter error: %v", err)
	}

	var out JSONOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}

	if out.Score != r.Score() {
		t.Errorf("JSON score = %d, want %d", out.Score, r.Score())
	}
	if out.Rating != string(r.Rating()) {
		t.Errorf("JSON rating = %q, want %q", out.Rating, r.Rating())
	}
}

func TestJSONWriter_FindingsCount(t *testing.T) {
	var buf bytes.Buffer
	r := sampleReport()
	if err := JSONWriter(&buf, r); err != nil {
		t.Fatalf("JSONWriter error: %v", err)
	}

	var out JSONOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}

	if len(out.Findings) != len(r.Findings) {
		t.Errorf("JSON findings count = %d, want %d", len(out.Findings), len(r.Findings))
	}
}

func TestJSONWriter_SummaryTotals(t *testing.T) {
	var buf bytes.Buffer
	r := sampleReport()
	if err := JSONWriter(&buf, r); err != nil {
		t.Fatalf("JSONWriter error: %v", err)
	}

	var out JSONOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}

	if out.Summary["critical"] != 2 {
		t.Errorf("JSON summary critical = %d, want 2", out.Summary["critical"])
	}
	if out.Summary["medium"] != 1 {
		t.Errorf("JSON summary medium = %d, want 1", out.Summary["medium"])
	}
}

func TestModuleOrder(t *testing.T) {
	groups := map[string][]scanner.Finding{
		"hygiene":   {{ID: "H-1"}},
		"transport": {{ID: "T-1"}},
		"keys":      {{ID: "K-1"}},
	}

	order := moduleOrder(groups)
	if order[0] != "transport" {
		t.Errorf("first module should be transport, got %q", order[0])
	}
	if order[1] != "keys" {
		t.Errorf("second module should be keys, got %q", order[1])
	}
	if order[2] != "hygiene" {
		t.Errorf("third module should be hygiene, got %q", order[2])
	}
}

func TestSARIFWriter_ValidJSON(t *testing.T) {
	var buf bytes.Buffer
	r := sampleReport()
	if err := SARIFWriter(&buf, r); err != nil {
		t.Fatalf("SARIFWriter error: %v", err)
	}

	var out sarifLog
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid SARIF JSON: %v", err)
	}

	if out.Version != "2.1.0" {
		t.Fatalf("SARIF version = %q, want 2.1.0", out.Version)
	}
	if len(out.Runs) != 1 {
		t.Fatalf("SARIF runs = %d, want 1", len(out.Runs))
	}
}

func TestSARIFWriter_PreservesFindingMetadata(t *testing.T) {
	var buf bytes.Buffer
	r := sampleReport()
	if err := SARIFWriter(&buf, r); err != nil {
		t.Fatalf("SARIFWriter error: %v", err)
	}

	var out sarifLog
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}

	results := out.Runs[0].Results
	if len(results) != len(r.Findings) {
		t.Fatalf("SARIF results = %d, want %d", len(results), len(r.Findings))
	}

	first := results[0]
	if first.RuleID == "" {
		t.Fatal("SARIF result should include ruleId")
	}
	if first.Properties == nil || first.Properties.Severity == "" || first.Properties.Module == "" {
		t.Fatal("SARIF result should include severity and module properties")
	}
}

func TestSARIFWriter_EmptyReport(t *testing.T) {
	var buf bytes.Buffer
	r := &scanner.Report{}
	if err := SARIFWriter(&buf, r); err != nil {
		t.Fatalf("SARIFWriter error: %v", err)
	}

	var out sarifLog
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}

	if len(out.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(out.Runs))
	}
	if len(out.Runs[0].Results) != 0 {
		t.Fatalf("results = %d, want 0", len(out.Runs[0].Results))
	}
	if len(out.Runs[0].Tool.Driver.Rules) != 0 {
		t.Fatalf("rules = %d, want 0", len(out.Runs[0].Tool.Driver.Rules))
	}
}

func TestSarifLevelForSeverity(t *testing.T) {
	if got := sarifLevelForSeverity(scanner.Critical); got != "error" {
		t.Fatalf("critical level = %q, want error", got)
	}
	if got := sarifLevelForSeverity(scanner.High); got != "error" {
		t.Fatalf("high level = %q, want error", got)
	}
	if got := sarifLevelForSeverity(scanner.Medium); got != "warning" {
		t.Fatalf("medium level = %q, want warning", got)
	}
	if got := sarifLevelForSeverity(scanner.Low); got != "note" {
		t.Fatalf("low level = %q, want note", got)
	}
	if got := sarifLevelForSeverity(scanner.Info); got != "note" {
		t.Fatalf("info level = %q, want note", got)
	}
}

func TestSarifRulesFromFindings_FallbackText(t *testing.T) {
	findings := []scanner.Finding{{
		ID:       "X-1",
		Module:   "custom",
		Severity: scanner.Low,
		Title:    "Only title available",
	}}

	rules := sarifRulesFromFindings(findings)
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if rules[0].FullDescription.Text != "Only title available" {
		t.Fatalf("full description = %q, want title fallback", rules[0].FullDescription.Text)
	}
	if rules[0].Help.Text == "" {
		t.Fatal("help text should be populated with a fallback when remediation is missing")
	}
}

func TestSARIFWriter_ResultsIncludeFingerprints(t *testing.T) {
	var buf bytes.Buffer
	r := sampleReport()
	if err := SARIFWriter(&buf, r); err != nil {
		t.Fatalf("SARIFWriter error: %v", err)
	}

	var out sarifLog
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}

	for _, result := range out.Runs[0].Results {
		if result.PartialFingerprints == nil || result.PartialFingerprints["lnaudit/finding-key"] == "" {
			t.Fatalf("result %s should include stable fingerprint", result.RuleID)
		}
	}
}

func TestSarifLevelForSeverity_LowIsNote(t *testing.T) {
	if got := sarifLevelForSeverity(scanner.Low); got != "note" {
		t.Fatalf("low level = %q, want note", got)
	}
}

func TestSarifStableFingerprint_ChannelInstancesAreDistinct(t *testing.T) {
	f1 := scanner.Finding{
		ID:          "L-12",
		Module:      "live",
		Title:       "Channel 123 capacity exceeds configured threshold",
		Remediation: "Split channels",
	}
	f2 := scanner.Finding{
		ID:          "L-12",
		Module:      "live",
		Title:       "Channel 456 capacity exceeds configured threshold",
		Remediation: "Split channels",
	}

	fp1 := sarifStableFingerprint(f1)
	fp2 := sarifStableFingerprint(f2)
	if fp1 == fp2 {
		t.Fatalf("fingerprints should differ for different channel instances: %s", fp1)
	}
}

func TestSarifStableFingerprint_IgnoresRemediationText(t *testing.T) {
	base := scanner.Finding{
		ID:     "T-3",
		Module: "transport",
		Title:  "RPC bound to 0.0.0.0:10009",
	}
	f1 := base
	f1.Remediation = "Set rpclisten to loopback"
	f2 := base
	f2.Remediation = "Use localhost binding for RPC"

	fp1 := sarifStableFingerprint(f1)
	fp2 := sarifStableFingerprint(f2)
	if fp1 != fp2 {
		t.Fatalf("fingerprint should be stable across remediation text edits")
	}
}

func TestSarifRuleTitle_GeneralizesChannelIDs(t *testing.T) {
	title := "Channel 999 capacity exceeds configured threshold"
	got := sarifRuleTitle(title)
	if got != "Channel <id> capacity exceeds configured threshold" {
		t.Fatalf("rule title = %q", got)
	}
}
