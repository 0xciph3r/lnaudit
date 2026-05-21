package checks

import (
	"fmt"
	"testing"

	lngrpc "github.com/NonsoAmadi10/lnaudit/pkg/grpc"
	"github.com/NonsoAmadi10/lnaudit/pkg/scanner"
)

// --- Version / CVE tests ---

func TestCheckLndVersion_Current(t *testing.T) {
	mock := &lngrpc.MockClient{
		NodeInfoResp: &lngrpc.NodeInfo{Version: "0.19.1-beta commit=v0.19.1-beta"},
	}
	findings, err := CheckLndVersion(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for current version, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  %s: %s", f.ID, f.Title)
		}
	}
}

func TestCheckLndVersion_OldVersion(t *testing.T) {
	mock := &lngrpc.MockClient{
		NodeInfoResp: &lngrpc.NodeInfo{Version: "0.12.0-beta"},
	}
	findings, err := CheckLndVersion(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected CVE findings for v0.12.0, got none")
	}

	hasCritical := false
	for _, f := range findings {
		if f.Severity == scanner.Critical {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Error("expected at least one CRITICAL finding for v0.12.0")
	}
}

func TestCheckLndVersion_VeryOld(t *testing.T) {
	mock := &lngrpc.MockClient{
		NodeInfoResp: &lngrpc.NodeInfo{Version: "0.6.0-beta"},
	}
	findings, err := CheckLndVersion(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// v0.6.0 is before all CVE fixes
	if len(findings) != len(cveDatabase) {
		t.Errorf("expected %d CVE findings for v0.6.0, got %d", len(cveDatabase), len(findings))
	}
}

func TestCheckLndVersion_Error(t *testing.T) {
	mock := &lngrpc.MockClient{
		NodeInfoErr: fmt.Errorf("connection refused"),
	}
	_, err := CheckLndVersion(mock)
	if err == nil {
		t.Fatal("expected error when GetInfo fails")
	}
}

// --- Chain sync tests ---

func TestCheckChainSync_FullySynced(t *testing.T) {
	mock := &lngrpc.MockClient{
		NodeInfoResp: &lngrpc.NodeInfo{
			SyncedToChain: true,
			SyncedToGraph: true,
			BlockHeight:   850000,
		},
	}
	findings, err := CheckChainSync(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for fully synced node, got %d", len(findings))
	}
}

func TestCheckChainSync_NotSyncedToChain(t *testing.T) {
	mock := &lngrpc.MockClient{
		NodeInfoResp: &lngrpc.NodeInfo{
			SyncedToChain: false,
			SyncedToGraph: true,
			BlockHeight:   100,
		},
	}
	findings, err := CheckChainSync(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != scanner.Critical {
		t.Errorf("expected CRITICAL, got %s", findings[0].Severity)
	}
	if findings[0].ID != "L-1" {
		t.Errorf("expected ID L-1, got %s", findings[0].ID)
	}
}

func TestCheckChainSync_NotSyncedToGraph(t *testing.T) {
	mock := &lngrpc.MockClient{
		NodeInfoResp: &lngrpc.NodeInfo{
			SyncedToChain: true,
			SyncedToGraph: false,
			BlockHeight:   850000,
		},
	}
	findings, err := CheckChainSync(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != scanner.Medium {
		t.Errorf("expected MEDIUM, got %s", findings[0].Severity)
	}
}

func TestCheckChainSync_BothUnsynced(t *testing.T) {
	mock := &lngrpc.MockClient{
		NodeInfoResp: &lngrpc.NodeInfo{
			SyncedToChain: false,
			SyncedToGraph: false,
			BlockHeight:   0,
		},
	}
	findings, err := CheckChainSync(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(findings))
	}
}

// --- Peer count tests ---

func TestCheckPeerCount_Healthy(t *testing.T) {
	mock := &lngrpc.MockClient{
		NodeInfoResp: &lngrpc.NodeInfo{NumPeers: 5},
	}
	findings, err := CheckPeerCount(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for 5 peers, got %d", len(findings))
	}
}

func TestCheckPeerCount_ZeroPeers(t *testing.T) {
	mock := &lngrpc.MockClient{
		NodeInfoResp: &lngrpc.NodeInfo{NumPeers: 0},
	}
	findings, err := CheckPeerCount(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != scanner.High {
		t.Errorf("expected HIGH for 0 peers, got %s", findings[0].Severity)
	}
}

func TestCheckPeerCount_FewPeers(t *testing.T) {
	mock := &lngrpc.MockClient{
		NodeInfoResp: &lngrpc.NodeInfo{NumPeers: 2},
	}
	findings, err := CheckPeerCount(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for 2 peers, got %d", len(findings))
	}
	if findings[0].Severity != scanner.Medium {
		t.Errorf("expected MEDIUM for 2 peers, got %s", findings[0].Severity)
	}
}

func TestCheckPeerCount_ExactlyThree(t *testing.T) {
	mock := &lngrpc.MockClient{
		NodeInfoResp: &lngrpc.NodeInfo{NumPeers: 3},
	}
	findings, err := CheckPeerCount(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for exactly 3 peers, got %d", len(findings))
	}
}

// --- Force-close tests ---

func TestCheckPendingForceClose_None(t *testing.T) {
	mock := &lngrpc.MockClient{
		PendingResp: nil,
	}
	findings, err := CheckPendingForceClose(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestCheckPendingForceClose_Active(t *testing.T) {
	mock := &lngrpc.MockClient{
		PendingResp: []lngrpc.PendingForceClose{
			{ChannelPoint: "abc:0", LimboBalance: 500000},
			{ChannelPoint: "def:1", LimboBalance: 250000},
		},
	}
	findings, err := CheckPendingForceClose(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != scanner.High {
		t.Errorf("expected HIGH, got %s", findings[0].Severity)
	}
}

// --- Large local balance tests ---

func TestCheckLargeLocalBalance_Balanced(t *testing.T) {
	mock := &lngrpc.MockClient{
		ChannelsResp: []lngrpc.Channel{
			{ChanID: 1, Capacity: 1000000, LocalBalance: 400000, RemoteBalance: 600000},
		},
		WalletResp: &lngrpc.WalletBalance{ConfirmedBalance: 100000},
	}
	findings, err := CheckLargeLocalBalance(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 40% local, under threshold and under minimum sats
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for balanced channel, got %d", len(findings))
	}
}

func TestCheckLargeLocalBalance_HeavyLocal(t *testing.T) {
	mock := &lngrpc.MockClient{
		ChannelsResp: []lngrpc.Channel{
			{ChanID: 1, Capacity: 1000000, LocalBalance: 900000, RemoteBalance: 100000},
		},
		WalletResp: &lngrpc.WalletBalance{ConfirmedBalance: 100000},
	}
	findings, err := CheckLargeLocalBalance(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for 90%% local balance, got %d", len(findings))
	}
	if findings[0].Severity != scanner.Medium {
		t.Errorf("expected MEDIUM, got %s", findings[0].Severity)
	}
}

func TestCheckLargeLocalBalance_SmallChannel(t *testing.T) {
	// High ratio but below minSignificantSats
	mock := &lngrpc.MockClient{
		ChannelsResp: []lngrpc.Channel{
			{ChanID: 1, Capacity: 100000, LocalBalance: 95000, RemoteBalance: 5000},
		},
		WalletResp: &lngrpc.WalletBalance{ConfirmedBalance: 50000},
	}
	findings, err := CheckLargeLocalBalance(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for small channel, got %d", len(findings))
	}
}

func TestCheckLargeLocalBalance_HighExposure(t *testing.T) {
	mock := &lngrpc.MockClient{
		ChannelsResp: []lngrpc.Channel{
			{ChanID: 1, Capacity: 5000000, LocalBalance: 2000000, RemoteBalance: 3000000},
		},
		WalletResp: &lngrpc.WalletBalance{ConfirmedBalance: 9000000},
	}
	findings, err := CheckLargeLocalBalance(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Total exposure = 2M + 9M = 11M > 10M threshold
	hasInfo := false
	for _, f := range findings {
		if f.ID == "L-6" {
			hasInfo = true
		}
	}
	if !hasInfo {
		t.Error("expected L-6 (total exposure) INFO finding for >10M sats")
	}
}

// --- Version parsing tests ---

func TestParseVersion(t *testing.T) {
	tests := []struct {
		input               string
		major, minor, patch int
		ok                  bool
	}{
		{"0.19.1-beta commit=v0.19.1-beta", 0, 19, 1, true},
		{"0.17.0-beta", 0, 17, 0, true},
		{"0.7.1", 0, 7, 1, true},
		{"0.13.3-beta.rc1", 0, 13, 3, true},
		{"0.21.0-alpha", 0, 21, 0, true},
		{"garbage", 0, 0, 0, false},
		{"", 0, 0, 0, false},
	}

	for _, tt := range tests {
		maj, mnr, pat, ok := parseVersion(tt.input)
		if ok != tt.ok {
			t.Errorf("parseVersion(%q): ok=%v, want %v", tt.input, ok, tt.ok)
			continue
		}
		if ok && (maj != tt.major || mnr != tt.minor || pat != tt.patch) {
			t.Errorf("parseVersion(%q) = %d.%d.%d, want %d.%d.%d",
				tt.input, maj, mnr, pat, tt.major, tt.minor, tt.patch)
		}
	}
}

func TestVersionBefore(t *testing.T) {
	tests := []struct {
		a, b   string
		before bool
	}{
		{"0.12.0-beta", "0.13.3", true},
		{"0.13.3-beta", "0.13.3", false},
		{"0.13.4-beta", "0.13.3", false},
		{"0.7.0-beta", "0.7.1", true},
		{"0.19.1-beta", "0.17.0", false},
		{"0.16.99-beta", "0.17.0", true},
	}

	for _, tt := range tests {
		got := versionBefore(tt.a, tt.b)
		if got != tt.before {
			t.Errorf("versionBefore(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.before)
		}
	}
}
