package checks

import (
	"fmt"
	"testing"

	lngrpc "github.com/0xciph3r/lnaudit/pkg/grpc"
	"github.com/0xciph3r/lnaudit/pkg/scanner"
)

func TestCheckExposureLimits_NoFindingsUnderThresholds(t *testing.T) {
	mock := &lngrpc.MockClient{
		ChannelsResp: []lngrpc.Channel{
			{ChanID: 1, Capacity: 1_000_000, LocalBalance: 500_000},
		},
		WalletResp: &lngrpc.WalletBalance{ConfirmedBalance: 300_000},
	}

	findings, err := CheckExposureLimits(mock, ExposureLimits{
		MaxHotWalletSats:    1_000_000,
		MaxNodeExposureSats: 2_000_000,
		MaxChannelCapSats:   2_000_000,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

func TestCheckExposureLimits_FindsAllThresholdBreaches(t *testing.T) {
	mock := &lngrpc.MockClient{
		ChannelsResp: []lngrpc.Channel{
			{ChanID: 99, Capacity: 9_000_000, LocalBalance: 3_000_000},
		},
		WalletResp: &lngrpc.WalletBalance{ConfirmedBalance: 6_000_000},
	}

	findings, err := CheckExposureLimits(mock, ExposureLimits{
		MaxHotWalletSats:    5_000_000,
		MaxNodeExposureSats: 8_000_000,
		MaxChannelCapSats:   8_000_000,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	ids := map[string]bool{}
	for _, f := range findings {
		ids[f.ID] = true
	}
	for _, id := range []string{"L-11", "L-12", "L-13"} {
		if !ids[id] {
			t.Fatalf("missing finding %s", id)
		}
	}
}

func TestCheckExposureLimits_DisabledWhenAllThresholdsUnset(t *testing.T) {
	mock := &lngrpc.MockClient{
		ChannelsResp: []lngrpc.Channel{
			{ChanID: 1, Capacity: DefaultMaxChannelCapacitySats + 1, LocalBalance: 100_000},
		},
		WalletResp: &lngrpc.WalletBalance{ConfirmedBalance: DefaultMaxHotWalletSats + 1},
	}

	findings, err := CheckExposureLimits(mock, ExposureLimits{
		MaxHotWalletSats:    0,
		MaxNodeExposureSats: 0,
		MaxChannelCapSats:   0,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings when thresholds are unset, got %d", len(findings))
	}
}

func TestCheckExposureLimits_ErrorPropagation(t *testing.T) {
	mock := &lngrpc.MockClient{
		ChannelsErr: fmt.Errorf("rpc unavailable"),
	}
	_, err := CheckExposureLimits(mock, ExposureLimits{MaxChannelCapSats: 1})
	if err == nil {
		t.Fatal("expected error when channel listing fails")
	}
}

func TestCheckExposureLimits_WalletErrorPropagation(t *testing.T) {
	mock := &lngrpc.MockClient{
		ChannelsResp: []lngrpc.Channel{{ChanID: 1, Capacity: 10_000}},
		WalletErr:    fmt.Errorf("wallet rpc unavailable"),
	}
	_, err := CheckExposureLimits(mock, ExposureLimits{MaxHotWalletSats: 1})
	if err == nil {
		t.Fatal("expected error when wallet balance lookup fails")
	}
}

func TestCheckExposureLimits_SeverityEscalatesAtTwoX(t *testing.T) {
	mock := &lngrpc.MockClient{
		ChannelsResp: []lngrpc.Channel{
			{ChanID: 1, Capacity: 16_000_000, LocalBalance: 4_000_000},
		},
		WalletResp: &lngrpc.WalletBalance{ConfirmedBalance: 10_000_000},
	}

	findings, err := CheckExposureLimits(mock, ExposureLimits{
		MaxHotWalletSats:    5_000_000,
		MaxNodeExposureSats: 7_000_000,
		MaxChannelCapSats:   8_000_000,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if (f.ID == "L-11" || f.ID == "L-12" || f.ID == "L-13") && f.Severity != scanner.High {
			t.Fatalf("expected HIGH severity for %s at >=2x threshold, got %s", f.ID, f.Severity)
		}
	}
}
