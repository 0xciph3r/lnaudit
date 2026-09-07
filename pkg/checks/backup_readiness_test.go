package checks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckChannelBackupReadiness_SkipsWhenDataDirMissing(t *testing.T) {
	root := t.TempDir()
	backupPath := filepath.Join(root, "channel.backup")
	findings := CheckChannelBackupReadiness(backupPath, root, filepath.Join(root, ".lnd"), filepath.Join(root, ".lnd", "data"))
	if len(findings) != 0 {
		t.Fatalf("expected no findings when data dir is absent, got %#v", findings)
	}
}

func TestCheckChannelBackupReadiness_MissingBackupWithChannelState(t *testing.T) {
	root := t.TempDir()
	lndDir := filepath.Join(root, ".lnd")
	dataDir := filepath.Join(lndDir, "data")
	chainDir := filepath.Join(dataDir, "chain", "bitcoin", "mainnet")
	if err := os.MkdirAll(chainDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Evidence that the node has initialized chain data.
	if err := os.WriteFile(filepath.Join(chainDir, "wallet.db"), []byte("db"), 0o600); err != nil {
		t.Fatal(err)
	}

	backupPath := filepath.Join(chainDir, "channel.backup")
	findings := CheckChannelBackupReadiness(backupPath, root, lndDir, dataDir)
	hasMissing := false
	for _, f := range findings {
		if f.ID == "C-10" {
			hasMissing = true
		}
	}
	if !hasMissing {
		t.Fatalf("expected C-10 missing backup finding with channel state evidence, got %#v", findings)
	}
}

func TestCheckChannelBackupReadiness_MissingBackupWithoutChannelState(t *testing.T) {
	root := t.TempDir()
	lndDir := filepath.Join(root, ".lnd")
	dataDir := filepath.Join(lndDir, "data")
	chainDir := filepath.Join(dataDir, "chain", "bitcoin", "mainnet")
	if err := os.MkdirAll(chainDir, 0o700); err != nil {
		t.Fatal(err)
	}

	backupPath := filepath.Join(chainDir, "channel.backup")
	findings := CheckChannelBackupReadiness(backupPath, root, lndDir, dataDir)
	for _, f := range findings {
		if f.ID == "C-10" {
			t.Fatalf("did not expect C-10 without channel state evidence: %#v", findings)
		}
	}
}

func TestCheckChannelBackupReadiness_ExistingBackupNoFindings(t *testing.T) {
	root := t.TempDir()
	lndDir := filepath.Join(root, ".lnd")
	dataDir := filepath.Join(lndDir, "data")
	chainDir := filepath.Join(dataDir, "chain", "bitcoin", "mainnet")
	if err := os.MkdirAll(chainDir, 0o700); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(chainDir, "channel.backup")
	if err := os.WriteFile(backupPath, []byte("backup"), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := CheckChannelBackupReadiness(backupPath, root, lndDir, dataDir)
	if len(findings) != 0 {
		t.Fatalf("expected no findings when backup exists, got %#v", findings)
	}
}

func TestHasChannelStateEvidence_FindsGraphDB(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, ".lnd", "data")
	chainDir := filepath.Join(dataDir, "chain", "bitcoin", "mainnet")
	graphDir := filepath.Join(dataDir, "graph", "mainnet")
	if err := os.MkdirAll(chainDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(graphDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(graphDir, "channel.db"), []byte("db"), 0o600); err != nil {
		t.Fatal(err)
	}

	backupPath := filepath.Join(chainDir, "channel.backup")
	if !hasChannelStateEvidence(backupPath) {
		t.Fatal("expected graph channel.db to count as channel state evidence")
	}
}
