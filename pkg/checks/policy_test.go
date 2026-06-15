package checks

import (
	"testing"

	"github.com/0xciph3r/lnaudit/pkg/config"
	lngrpc "github.com/0xciph3r/lnaudit/pkg/grpc"
	"github.com/0xciph3r/lnaudit/pkg/scanner"
)

func TestCheckChannelPolicy(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *config.LndConfig
		wantIDs    []string
		wantMinLen int
	}{
		{
			name: "AllowCircularRoute",
			cfg: &config.LndConfig{
				AllowCircularRoute: true,
			},
			wantIDs: []string{"P-1"},
		},
		{
			name: "RejectPushNotSet",
			cfg: &config.LndConfig{
				RejectPush:         false,
				RejectPushExplicit: false,
			},
			wantIDs: []string{"P-2"},
		},
		{
			name: "RejectPushExplicitlyFalse",
			cfg: &config.LndConfig{
				RejectPush:         false,
				RejectPushExplicit: true,
			},
			wantMinLen: 0, // should not trigger since explicitly set
		},
		{
			name: "HighRemoteMaxHTLCs",
			cfg: &config.LndConfig{
				DefaultRemoteMaxHTLCs:         483,
				DefaultRemoteMaxHTLCsExplicit: true,
			},
			wantIDs: []string{"P-3"},
		},
		{
			name: "UpfrontShutdownNotEnabled",
			cfg: &config.LndConfig{
				EnableUpfrontShutdown: false,
			},
			wantIDs: []string{"P-4"},
		},
		{
			name: "HighMaxCLTVExpiry",
			cfg: &config.LndConfig{
				MaxCLTVExpiry:         5000,
				MaxCLTVExpiryExplicit: true,
				EnableUpfrontShutdown: true,
				RejectPushExplicit:    true,
			},
			wantIDs: []string{"P-5"},
		},
		{
			name: "LowMinChanSize",
			cfg: &config.LndConfig{
				MinChanSize:           5000,
				MinChanSizeExplicit:   true,
				EnableUpfrontShutdown: true,
				RejectPushExplicit:    true,
			},
			wantIDs: []string{"P-6"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := CheckChannelPolicy(tt.cfg)
			if tt.wantIDs != nil {
				for _, wantID := range tt.wantIDs {
					found := false
					for _, f := range findings {
						if f.ID == wantID {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected finding %s but did not find it (got %d findings)", wantID, len(findings))
					}
				}
			}
		})
	}
}

func TestCheckBitcoinPolicy(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.LndConfig
		wantIDs []string
	}{
		{
			name: "LowTimelockDelta",
			cfg: &config.LndConfig{
				Bitcoin: config.BitcoinConfig{
					TimelockDelta:         20,
					TimelockDeltaExplicit: true,
				},
			},
			wantIDs: []string{"P-7"},
		},
		{
			name: "MinHTLCAtMinimum",
			cfg: &config.LndConfig{
				Bitcoin: config.BitcoinConfig{
					MinHTLC:         1,
					MinHTLCExplicit: true,
				},
			},
			wantIDs: []string{"P-8"},
		},
		{
			name: "EconomicalFeeMode",
			cfg: &config.LndConfig{
				Bitcoin: config.BitcoinConfig{
					EstimateMode: "ECONOMICAL",
				},
			},
			wantIDs: []string{"P-9"},
		},
		{
			name:    "SafeDefaults",
			cfg:     &config.LndConfig{},
			wantIDs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := CheckBitcoinPolicy(tt.cfg)
			if tt.wantIDs == nil {
				if len(findings) != 0 {
					t.Errorf("expected no findings but got %d", len(findings))
				}
				return
			}
			for _, wantID := range tt.wantIDs {
				found := false
				for _, f := range findings {
					if f.ID == wantID {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected finding %s", wantID)
				}
			}
		})
	}
}

func TestCheckPaymentSecurity(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.LndConfig
		wantIDs []string
	}{
		{
			name: "RequireInterceptor",
			cfg: &config.LndConfig{
				RequireInterceptor: true,
			},
			wantIDs: []string{"P-12"},
		},
		{
			name: "WildcardCORS",
			cfg: &config.LndConfig{
				RESTCors: "*",
			},
			wantIDs: []string{"P-13"},
		},
		{
			name: "KeysendAndAMP",
			cfg: &config.LndConfig{
				AcceptKeysend: true,
				AcceptAMP:     true,
			},
			wantIDs: []string{"P-10", "P-11"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := CheckPaymentSecurity(tt.cfg)
			for _, wantID := range tt.wantIDs {
				found := false
				for _, f := range findings {
					if f.ID == wantID {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected finding %s", wantID)
				}
			}
		})
	}
}

func TestCheckProtocolSecurity(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.LndConfig
		wantIDs []string
	}{
		{
			name: "ZeroConf",
			cfg: &config.LndConfig{
				Protocol: config.ProtocolConfig{ZeroConf: true},
			},
			wantIDs: []string{"R-1"},
		},
		{
			name: "NoAnchors",
			cfg: &config.LndConfig{
				Protocol: config.ProtocolConfig{NoAnchors: true},
			},
			wantIDs: []string{"R-2"},
		},
		{
			name: "WumboChannels",
			cfg: &config.LndConfig{
				Protocol: config.ProtocolConfig{WumboChannels: true},
			},
			wantIDs: []string{"R-3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := CheckProtocolSecurity(tt.cfg)
			for _, wantID := range tt.wantIDs {
				found := false
				for _, f := range findings {
					if f.ID == wantID {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected finding %s", wantID)
				}
			}
		})
	}
}

func TestCheckAutopilotSecurity(t *testing.T) {
	t.Run("AutopilotActive", func(t *testing.T) {
		cfg := &config.LndConfig{
			Autopilot: config.AutopilotConfig{Active: true, Allocation: 0.6},
		}
		findings := CheckAutopilotSecurity(cfg)
		if len(findings) == 0 {
			t.Fatal("expected finding for active autopilot")
		}
		if findings[0].Severity != scanner.Critical {
			t.Errorf("expected Critical for >50%% allocation, got %s", findings[0].Severity)
		}
	})

	t.Run("AutopilotLowAllocation", func(t *testing.T) {
		cfg := &config.LndConfig{
			Autopilot: config.AutopilotConfig{Active: true, Allocation: 0.3},
		}
		findings := CheckAutopilotSecurity(cfg)
		if len(findings) == 0 {
			t.Fatal("expected finding for active autopilot")
		}
		if findings[0].Severity != scanner.High {
			t.Errorf("expected High for <=50%% allocation, got %s", findings[0].Severity)
		}
	})

	t.Run("AutopilotInactive", func(t *testing.T) {
		cfg := &config.LndConfig{}
		findings := CheckAutopilotSecurity(cfg)
		if len(findings) != 0 {
			t.Errorf("expected no findings for inactive autopilot, got %d", len(findings))
		}
	})
}

func TestCheckTLSHardening(t *testing.T) {
	t.Run("NoRestTLS", func(t *testing.T) {
		cfg := &config.LndConfig{NoRestTLS: true}
		findings := CheckTLSHardening(cfg)
		if len(findings) == 0 || findings[0].ID != "R-6" {
			t.Error("expected R-6 finding for no-rest-tls")
		}
		if findings[0].Severity != scanner.Critical {
			t.Errorf("expected Critical, got %s", findings[0].Severity)
		}
	})

	t.Run("TLSKeyNotEncrypted", func(t *testing.T) {
		cfg := &config.LndConfig{
			TLSEncryptKey:         false,
			TLSEncryptKeyExplicit: true,
		}
		findings := CheckTLSHardening(cfg)
		found := false
		for _, f := range findings {
			if f.ID == "R-7" {
				found = true
			}
		}
		if !found {
			t.Error("expected R-7 finding for explicitly disabled TLS key encryption")
		}
	})
}

func TestCheckDangerousFlagsExtended(t *testing.T) {
	t.Run("WalletUnlockAllowCreate", func(t *testing.T) {
		cfg := &config.LndConfig{WalletUnlockAllowCreate: true}
		findings := CheckDangerousFlagsExtended(cfg)
		if len(findings) == 0 || findings[0].ID != "R-8" {
			t.Error("expected R-8 finding for wallet-unlock-allow-create")
		}
		if findings[0].Severity != scanner.Critical {
			t.Errorf("expected Critical, got %s", findings[0].Severity)
		}
	})
}

func TestCheckGossipSecurity(t *testing.T) {
	t.Run("BanThresholdZero", func(t *testing.T) {
		cfg := &config.LndConfig{
			Gossip: config.GossipConfig{
				BanThreshold:         0,
				BanThresholdExplicit: true,
			},
		}
		findings := CheckGossipSecurity(cfg)
		if len(findings) == 0 || findings[0].ID != "R-5" {
			t.Error("expected R-5 finding for disabled gossip banning")
		}
	})
}

// Live check tests using MockClient

func TestCheckChannelJamming(t *testing.T) {
	t.Run("JammedChannel", func(t *testing.T) {
		client := &lngrpc.MockClient{
			ChannelsResp: []lngrpc.Channel{
				{ChanID: 1, RemotePubkey: "0123456789abcdef0123456789abcdef0123456789abcdef01234567", NumPendingHTLCs: 25, Capacity: 1000000},
				{ChanID: 2, RemotePubkey: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01", NumPendingHTLCs: 2, Capacity: 500000},
			},
		}
		findings, err := CheckChannelJamming(client)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) == 0 {
			t.Error("expected finding for jammed channel")
		}
		found := false
		for _, f := range findings {
			if f.ID == "L-7" {
				found = true
			}
		}
		if !found {
			t.Error("expected L-7 finding")
		}
	})

	t.Run("NoJamming", func(t *testing.T) {
		client := &lngrpc.MockClient{
			ChannelsResp: []lngrpc.Channel{
				{ChanID: 1, RemotePubkey: "0123456789abcdef01234567", NumPendingHTLCs: 3, Capacity: 1000000},
			},
		}
		findings, err := CheckChannelJamming(client)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("expected no findings, got %d", len(findings))
		}
	})
}

func TestCheckZeroConfChannels(t *testing.T) {
	t.Run("HasZeroConf", func(t *testing.T) {
		client := &lngrpc.MockClient{
			ChannelsResp: []lngrpc.Channel{
				{ChanID: 1, ZeroConf: true, Capacity: 500000},
				{ChanID: 2, ZeroConf: false, Capacity: 1000000},
			},
		}
		findings, err := CheckZeroConfChannels(client)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) == 0 {
			t.Error("expected finding for zero-conf channel")
		}
	})

	t.Run("NoZeroConf", func(t *testing.T) {
		client := &lngrpc.MockClient{
			ChannelsResp: []lngrpc.Channel{
				{ChanID: 1, ZeroConf: false, Capacity: 1000000},
			},
		}
		findings, err := CheckZeroConfChannels(client)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("expected no findings, got %d", len(findings))
		}
	})
}

func TestCheckHighHTLCLimits(t *testing.T) {
	t.Run("HighLimits", func(t *testing.T) {
		client := &lngrpc.MockClient{
			ChannelsResp: []lngrpc.Channel{
				{ChanID: 1, RemoteMaxHTLCs: 483, Capacity: 1000000},
				{ChanID: 2, RemoteMaxHTLCs: 250, Capacity: 500000},
				{ChanID: 3, RemoteMaxHTLCs: 30, Capacity: 500000},
			},
		}
		findings, err := CheckHighHTLCLimits(client)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(findings) == 0 {
			t.Error("expected finding for high HTLC limits")
		}
	})
}
