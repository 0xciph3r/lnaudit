package checks

import (
	"testing"

	"github.com/NonsoAmadi10/lnaudit/pkg/config"
	"github.com/NonsoAmadi10/lnaudit/pkg/scanner"
)

// --- Tor Config Tests ---

func TestCheckTorConfig_SkipProxy(t *testing.T) {
	cfg := &config.LndConfig{
		Tor: config.TorConfig{
			Active:                      true,
			V3:                          true,
			EncryptKey:                  true,
			StreamIsolation:             true,
			SkipProxyForClearnetTargets: true,
		},
	}
	findings := CheckTorConfig(cfg)
	found := false
	for _, f := range findings {
		if f.ID == "N-1" && f.Severity == scanner.Critical {
			found = true
		}
	}
	if !found {
		t.Error("expected CRITICAL finding for skip-proxy-for-clearnet-targets")
	}
}

func TestCheckTorConfig_NoStreamIsolation(t *testing.T) {
	cfg := &config.LndConfig{
		Tor: config.TorConfig{
			Active:          true,
			V3:              true,
			EncryptKey:      true,
			StreamIsolation: false,
		},
	}
	findings := CheckTorConfig(cfg)
	found := false
	for _, f := range findings {
		if f.ID == "N-2" && f.Severity == scanner.Medium {
			found = true
		}
	}
	if !found {
		t.Error("expected MEDIUM finding for missing stream isolation")
	}
}

func TestCheckTorConfig_NoV3(t *testing.T) {
	cfg := &config.LndConfig{
		Tor: config.TorConfig{
			Active:          true,
			V3:              false,
			EncryptKey:      true,
			StreamIsolation: true,
		},
	}
	findings := CheckTorConfig(cfg)
	found := false
	for _, f := range findings {
		if f.ID == "N-1b" && f.Severity == scanner.High {
			found = true
		}
	}
	if !found {
		t.Error("expected HIGH finding for Tor V2 (no V3)")
	}
}

func TestCheckTorConfig_UnencryptedKey(t *testing.T) {
	cfg := &config.LndConfig{
		Tor: config.TorConfig{
			Active:          true,
			V3:              true,
			EncryptKey:      false,
			StreamIsolation: true,
		},
	}
	findings := CheckTorConfig(cfg)
	found := false
	for _, f := range findings {
		if f.ID == "K-2" && f.Severity == scanner.Critical {
			found = true
		}
	}
	if !found {
		t.Error("expected CRITICAL finding for unencrypted onion key")
	}
}

func TestCheckTorConfig_FullySecure(t *testing.T) {
	cfg := &config.LndConfig{
		Tor: config.TorConfig{
			Active:          true,
			V3:              true,
			EncryptKey:      true,
			StreamIsolation: true,
		},
	}
	findings := CheckTorConfig(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for fully secure Tor config, got %d", len(findings))
	}
}

func TestCheckTorConfig_Inactive(t *testing.T) {
	cfg := &config.LndConfig{
		Tor: config.TorConfig{Active: false},
	}
	findings := CheckTorConfig(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when Tor is not active, got %d", len(findings))
	}
}

// --- Privacy Settings Tests ---

func TestCheckPrivacySettings_NoScidAlias(t *testing.T) {
	cfg := &config.LndConfig{
		Protocol: config.ProtocolConfig{ScidAlias: false},
	}
	findings := CheckPrivacySettings(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != scanner.Medium {
		t.Errorf("severity = %v, want MEDIUM", findings[0].Severity)
	}
}

func TestCheckPrivacySettings_ScidEnabled(t *testing.T) {
	cfg := &config.LndConfig{
		Protocol: config.ProtocolConfig{ScidAlias: true},
	}
	findings := CheckPrivacySettings(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings with SCID alias enabled, got %d", len(findings))
	}
}

// --- Channel Safety Tests ---

func TestCheckChannelSafety_NoWatchtower(t *testing.T) {
	cfg := &config.LndConfig{
		WatchtowerClient:   config.WatchtowerClientConfig{Active: false},
		MaxChanSize:        16777215,
		MaxPendingChannels: 2,
		Bitcoin:            config.BitcoinConfig{DefaultChanConfs: 6},
	}
	findings := CheckChannelSafety(cfg)
	found := false
	for _, f := range findings {
		if f.ID == "C-1" && f.Severity == scanner.High {
			found = true
		}
	}
	if !found {
		t.Error("expected HIGH finding for missing watchtower")
	}
}

func TestCheckChannelSafety_LowConfirmations(t *testing.T) {
	cfg := &config.LndConfig{
		WatchtowerClient:   config.WatchtowerClientConfig{Active: true},
		Bitcoin:            config.BitcoinConfig{DefaultChanConfs: 1},
		MaxChanSize:        16777215,
		MaxPendingChannels: 1,
	}
	findings := CheckChannelSafety(cfg)
	found := false
	for _, f := range findings {
		if f.ID == "C-2" && f.Severity == scanner.High {
			found = true
		}
	}
	if !found {
		t.Error("expected HIGH finding for 1 confirmation depth")
	}
}

func TestCheckChannelSafety_NoMaxChanSize(t *testing.T) {
	cfg := &config.LndConfig{
		WatchtowerClient:   config.WatchtowerClientConfig{Active: true},
		Bitcoin:            config.BitcoinConfig{DefaultChanConfs: 6},
		MaxPendingChannels: 2,
	}
	findings := CheckChannelSafety(cfg)
	found := false
	for _, f := range findings {
		if f.ID == "C-4" && f.Severity == scanner.Medium {
			found = true
		}
	}
	if !found {
		t.Error("expected MEDIUM finding for no maxchansize")
	}
}

func TestCheckChannelSafety_FullyConfigured(t *testing.T) {
	cfg := &config.LndConfig{
		WatchtowerClient:   config.WatchtowerClientConfig{Active: true},
		Bitcoin:            config.BitcoinConfig{DefaultChanConfs: 6},
		MaxChanSize:        16777215,
		MaxPendingChannels: 2,
	}
	findings := CheckChannelSafety(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for fully configured channels, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  %s: %s", f.ID, f.Title)
		}
	}
}
