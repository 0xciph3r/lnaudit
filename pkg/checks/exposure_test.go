package checks

import (
	"testing"

	"github.com/NonsoAmadi10/lnaudit/pkg/config"
	"github.com/NonsoAmadi10/lnaudit/pkg/scanner"
)

func TestCheckNetworkExposure_P2PAllInterfaces_NoTor(t *testing.T) {
	cfg := &config.LndConfig{
		Listeners: []string{"0.0.0.0:9735"},
		Tor:       config.TorConfig{Active: false},
	}
	findings := CheckNetworkExposure(cfg)

	found := findByID(findings, "N-1")
	if found == nil {
		t.Fatal("expected finding N-1 for P2P on all interfaces without Tor")
	}
	if found.Severity != scanner.Medium {
		t.Errorf("severity = %v, want MEDIUM", found.Severity)
	}
}

func TestCheckNetworkExposure_P2PAllInterfaces_WithTor(t *testing.T) {
	cfg := &config.LndConfig{
		Listeners: []string{"0.0.0.0:9735"},
		Tor:       config.TorConfig{Active: true},
	}
	findings := CheckNetworkExposure(cfg)

	if findByID(findings, "N-1") != nil {
		t.Error("should not flag P2P on all interfaces when Tor is active")
	}
}

func TestCheckNetworkExposure_P2PLoopback(t *testing.T) {
	cfg := &config.LndConfig{
		Listeners: []string{"127.0.0.1:9735"},
	}
	findings := CheckNetworkExposure(cfg)

	if findByID(findings, "N-1") != nil {
		t.Error("should not flag P2P on loopback")
	}
}

func TestCheckNetworkExposure_NATEnabled(t *testing.T) {
	cfg := &config.LndConfig{NAT: true}
	findings := CheckNetworkExposure(cfg)

	found := findByID(findings, "N-2")
	if found == nil {
		t.Fatal("expected finding N-2 for NAT enabled")
	}
	if found.Severity != scanner.Medium {
		t.Errorf("severity = %v, want MEDIUM", found.Severity)
	}
}

func TestCheckNetworkExposure_NATDisabled(t *testing.T) {
	cfg := &config.LndConfig{NAT: false}
	findings := CheckNetworkExposure(cfg)

	if findByID(findings, "N-2") != nil {
		t.Error("should not flag NAT when disabled")
	}
}

func TestCheckNetworkExposure_MultipleExternalIPs(t *testing.T) {
	cfg := &config.LndConfig{
		ExternalIPs: []string{"1.2.3.4:9735", "5.6.7.8:9735"},
	}
	findings := CheckNetworkExposure(cfg)

	found := findByID(findings, "N-3")
	if found == nil {
		t.Fatal("expected finding N-3 for multiple clearnet IPs")
	}
	if found.Severity != scanner.Medium {
		t.Errorf("severity = %v, want MEDIUM", found.Severity)
	}
}

func TestCheckNetworkExposure_SingleExternalIP(t *testing.T) {
	cfg := &config.LndConfig{
		ExternalIPs: []string{"1.2.3.4:9735"},
	}
	findings := CheckNetworkExposure(cfg)

	if findByID(findings, "N-3") != nil {
		t.Error("should not flag a single external IP")
	}
}

func TestCheckNetworkExposure_MixedOnionAndClearnet(t *testing.T) {
	cfg := &config.LndConfig{
		ExternalIPs: []string{"1.2.3.4:9735", "abc123.onion:9735"},
	}
	findings := CheckNetworkExposure(cfg)

	// Only 1 clearnet IP, so N-3 should not fire
	if findByID(findings, "N-3") != nil {
		t.Error("should not flag when only 1 clearnet IP (plus onion)")
	}
}

func TestCheckNetworkExposure_RPCNonLoopback(t *testing.T) {
	cfg := &config.LndConfig{
		RPCListeners: []string{"192.168.1.10:10009"},
	}
	findings := CheckNetworkExposure(cfg)

	found := findByID(findings, "N-4")
	if found == nil {
		t.Fatal("expected finding N-4 for RPC on non-loopback")
	}
	if found.Severity != scanner.High {
		t.Errorf("severity = %v, want HIGH", found.Severity)
	}
}

func TestCheckNetworkExposure_RPCLoopback(t *testing.T) {
	cfg := &config.LndConfig{
		RPCListeners: []string{"127.0.0.1:10009"},
	}
	findings := CheckNetworkExposure(cfg)

	if findByID(findings, "N-4") != nil {
		t.Error("should not flag RPC on loopback")
	}
}

func TestCheckNetworkExposure_RPCLocalhost(t *testing.T) {
	cfg := &config.LndConfig{
		RPCListeners: []string{"localhost:10009"},
	}
	findings := CheckNetworkExposure(cfg)

	if findByID(findings, "N-4") != nil {
		t.Error("should not flag RPC on localhost")
	}
}

func TestCheckNetworkExposure_RESTNonLoopback(t *testing.T) {
	cfg := &config.LndConfig{
		RESTListeners: []string{"10.0.0.5:8080"},
	}
	findings := CheckNetworkExposure(cfg)

	found := findByID(findings, "N-5")
	if found == nil {
		t.Fatal("expected finding N-5 for REST on non-loopback")
	}
}

func TestCheckNetworkExposure_CleanConfig(t *testing.T) {
	cfg := &config.LndConfig{
		Listeners:    []string{"127.0.0.1:9735"},
		RPCListeners: []string{"127.0.0.1:10009"},
		ExternalIPs:  []string{"1.2.3.4:9735"},
		NAT:          false,
	}
	findings := CheckNetworkExposure(cfg)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean config, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  %s: %s", f.ID, f.Title)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	tests := []struct {
		addr     string
		loopback bool
	}{
		{"127.0.0.1:10009", true},
		{"localhost:10009", true},
		{"[::1]:10009", true},
		{"0.0.0.0:10009", false},
		{"192.168.1.1:10009", false},
		{"10.0.0.5:8080", false},
		{":10009", false},
	}
	for _, tt := range tests {
		got := isLoopback(tt.addr)
		if got != tt.loopback {
			t.Errorf("isLoopback(%q) = %v, want %v", tt.addr, got, tt.loopback)
		}
	}
}

// findByID returns the first finding with the given ID, or nil.
func findByID(findings []scanner.Finding, id string) *scanner.Finding {
	for i := range findings {
		if findings[i].ID == id {
			return &findings[i]
		}
	}
	return nil
}
