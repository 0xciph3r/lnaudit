package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/NonsoAmadi10/lnd-hardening-toolkit/pkg/scanner"
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

	if !strings.Contains(output, "→") {
		t.Error("table output should show remediation arrows")
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
	json.Unmarshal(buf.Bytes(), &out)

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
	json.Unmarshal(buf.Bytes(), &out)

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
	json.Unmarshal(buf.Bytes(), &out)

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
