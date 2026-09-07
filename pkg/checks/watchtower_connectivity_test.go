package checks

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/0xciph3r/lnaudit/pkg/config"
)

func TestCheckWatchtowerConnectivity_NotActive(t *testing.T) {
	cfg := &config.LndConfig{}
	if findings := CheckWatchtowerConnectivity(cfg, false); len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

func TestCheckWatchtowerConnectivity_ActiveNoTowers(t *testing.T) {
	cfg := &config.LndConfig{}
	cfg.WatchtowerClient.Active = true
	findings := CheckWatchtowerConnectivity(cfg, false)
	if len(findings) != 1 || findings[0].ID != "C-6" {
		t.Fatalf("expected C-6 finding, got %#v", findings)
	}
}

func TestCheckWatchtowerConnectivity_AllUnreachable(t *testing.T) {
	cfg := &config.LndConfig{}
	cfg.WatchtowerClient.Active = true
	cfg.WatchtowerClient.Towers = []string{"02abc@tower.example.com:9911"}

	orig := dialTowerAddr
	dialTowerAddr = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, errors.New("dial failed")
	}
	defer func() { dialTowerAddr = orig }()

	findings := CheckWatchtowerConnectivity(cfg, true)
	if len(findings) != 1 || findings[0].ID != "C-8" {
		t.Fatalf("expected C-8 finding, got %#v", findings)
	}
}

func TestCheckWatchtowerConnectivity_OnionOnly(t *testing.T) {
	cfg := &config.LndConfig{}
	cfg.WatchtowerClient.Active = true
	cfg.WatchtowerClient.Towers = []string{"02abc@towerhiddenservice.onion:9911"}

	findings := CheckWatchtowerConnectivity(cfg, true)
	if len(findings) != 1 || findings[0].ID != "C-7" {
		t.Fatalf("expected C-7 finding, got %#v", findings)
	}
}

func TestCheckWatchtowerConnectivity_ProbeDisabledSkipsReachability(t *testing.T) {
	cfg := &config.LndConfig{}
	cfg.WatchtowerClient.Active = true
	cfg.WatchtowerClient.Towers = []string{"02abc@tower.example.com:9911"}
	findings := CheckWatchtowerConnectivity(cfg, false)
	if len(findings) != 0 {
		t.Fatalf("expected no reachability findings when probe is disabled, got %#v", findings)
	}
}

func TestParseTowerAddress_DefaultPort(t *testing.T) {
	addr, onion, ok := parseTowerAddress("02abc@tower.example.com")
	if !ok {
		t.Fatal("expected valid parsed address")
	}
	if addr != "tower.example.com:9911" {
		t.Fatalf("address = %q, want tower.example.com:9911", addr)
	}
	if onion {
		t.Fatal("expected non-onion host")
	}
}
