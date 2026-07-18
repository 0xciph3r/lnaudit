package confgen

import (
	"bytes"
	"strings"
	"testing"

	"github.com/0xciph3r/lnaudit/pkg/scanner"
)

func TestSuggestFromFindings_MapsCommonIDs(t *testing.T) {
	findings := []scanner.Finding{
		{ID: "A-1"},
		{ID: "P-2"},
		{ID: "R-6"},
		{ID: "T-3"},
		{ID: "A-4"},
	}

	got := SuggestFromFindings(findings)
	if len(got.Suggestions) == 0 {
		t.Fatal("expected suggestions, got none")
	}

	wantKeys := map[string]bool{
		"no-macaroons": false,
		"rejectpush":   false,
		"no-rest-tls":  false,
		"rpclisten":    false,
	}
	for _, s := range got.Suggestions {
		if _, ok := wantKeys[s.Key]; ok {
			wantKeys[s.Key] = true
		}
	}
	for k, found := range wantKeys {
		if !found {
			t.Fatalf("missing expected suggestion key %q", k)
		}
	}

	hasManual := false
	for _, m := range got.ManualActions {
		if strings.Contains(m, "readonly.macaroon") {
			hasManual = true
			break
		}
	}
	if !hasManual {
		t.Fatal("expected manual action for readonly macaroon")
	}
}

func TestWriteSuggestedConfigPatch_OutputsSections(t *testing.T) {
	findings := []scanner.Finding{
		{ID: "P-7"},
		{ID: "R-8"},
		{ID: "C-1"},
	}

	var buf bytes.Buffer
	if err := WriteSuggestedConfigPatch(&buf, findings); err != nil {
		t.Fatalf("WriteSuggestedConfigPatch error: %v", err)
	}

	out := buf.String()
	for _, token := range []string{
		"[Application Options]",
		"[Bitcoin]",
		"[wtclient]",
		"bitcoin.timelockdelta=80",
		"wallet-unlock-allow-create=false",
		"wtclient.active=true",
		"Manual actions",
	} {
		if !strings.Contains(out, token) {
			t.Fatalf("expected output to contain %q, got:\n%s", token, out)
		}
	}
}

func TestWriteSuggestedConfigPatch_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSuggestedConfigPatch(&buf, nil); err != nil {
		t.Fatalf("WriteSuggestedConfigPatch error: %v", err)
	}
	if !strings.Contains(buf.String(), "No config suggestions") {
		t.Fatalf("unexpected output: %s", buf.String())
	}
}
