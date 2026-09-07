package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckIncidentReadiness_MissingRunbooks(t *testing.T) {
	root := t.TempDir()
	findings := CheckIncidentReadiness(root, "", "", "")
	if len(findings) < 4 {
		t.Fatalf("expected missing-runbook findings, got %d", len(findings))
	}
}

func TestCheckIncidentReadiness_SkipsWhenRunbookDirUnset(t *testing.T) {
	findings := CheckIncidentReadiness("", "", "", "")
	if len(findings) != 0 {
		t.Fatalf("expected no findings when --runbook-dir is unset, got %#v", findings)
	}
}

func TestCheckIncidentReadiness_BriefRunbooksFlaggedLow(t *testing.T) {
	root := t.TempDir()
	body := "# runbook\nkey rotation and fund sweep and channel close and restore"
	if err := os.WriteFile(filepath.Join(root, "incident.md"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := CheckIncidentReadiness(root, "", "", "")
	hasLow := false
	for _, f := range findings {
		if strings.HasSuffix(f.ID, "-q") {
			hasLow = true
		}
	}
	if !hasLow {
		t.Fatalf("expected low-severity quality findings for brief runbook, got %#v", findings)
	}
}

func TestCheckIncidentReadiness_CoveredTopicsNoFindings(t *testing.T) {
	root := t.TempDir()
	longText := strings.Repeat("step ", 80) // > 200 chars
	content := `
# key rotation
Procedure for key rotation and rotate tls and macaroon rotation.
` + longText + `
# fund sweep
Emergency fund sweep procedure and sweep funds instructions.
` + longText + `
# channel close
Force close and cooperative close execution details.
` + longText + `
# restore
Restore and disaster recovery procedure.
` + longText
	if err := os.WriteFile(filepath.Join(root, "runbook.md"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := CheckIncidentReadiness(root, "", "", "")
	if len(findings) != 0 {
		t.Fatalf("expected no findings for complete runbook coverage, got %#v", findings)
	}
}
