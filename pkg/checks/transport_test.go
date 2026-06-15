package checks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xciph3r/lnaudit/pkg/config"
	"github.com/0xciph3r/lnaudit/pkg/scanner"
)

func generateTestCert(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-lnd-node"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func writeCertFile(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tls.cert")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckTLSCert_Valid(t *testing.T) {
	certPEM := generateTestCert(t,
		time.Now().Add(-24*time.Hour),
		time.Now().Add(365*24*time.Hour),
	)
	path := writeCertFile(t, certPEM)

	findings := CheckTLSCert(path)
	for _, f := range findings {
		if f.Severity >= scanner.High {
			t.Errorf("unexpected high+ finding for valid cert: %s", f.Title)
		}
	}
}

func TestCheckTLSCert_Expired(t *testing.T) {
	certPEM := generateTestCert(t,
		time.Now().Add(-365*24*time.Hour),
		time.Now().Add(-1*time.Hour), // expired
	)
	path := writeCertFile(t, certPEM)

	findings := CheckTLSCert(path)
	found := false
	for _, f := range findings {
		if f.ID == "T-1a" && f.Severity == scanner.Critical {
			found = true
		}
	}
	if !found {
		t.Error("expected CRITICAL finding for expired certificate")
	}
}

func TestCheckTLSCert_ExpiringSoon(t *testing.T) {
	certPEM := generateTestCert(t,
		time.Now().Add(-300*24*time.Hour),
		time.Now().Add(15*24*time.Hour), // 15 days left
	)
	path := writeCertFile(t, certPEM)

	findings := CheckTLSCert(path)
	found := false
	for _, f := range findings {
		if f.ID == "T-1a" && f.Severity == scanner.High {
			found = true
		}
	}
	if !found {
		t.Error("expected HIGH finding for certificate expiring within 30 days")
	}
}

func TestCheckTLSCert_NotFound(t *testing.T) {
	findings := CheckTLSCert("/nonexistent/tls.cert")
	if len(findings) != 1 || findings[0].Severity != scanner.Critical {
		t.Error("expected CRITICAL finding for missing TLS cert")
	}
}

func TestCheckTLSCert_InvalidPEM(t *testing.T) {
	path := writeCertFile(t, []byte("not a pem file"))
	findings := CheckTLSCert(path)
	if len(findings) != 1 || findings[0].Severity != scanner.High {
		t.Error("expected HIGH finding for invalid PEM")
	}
}

func TestCheckTLSCert_EmptyPath(t *testing.T) {
	findings := CheckTLSCert("")
	if len(findings) != 0 {
		t.Error("expected no findings for empty path")
	}
}

// --- RPC Bind Address Tests ---

func TestCheckRPCBindAddress_Localhost(t *testing.T) {
	cfg := &config.LndConfig{
		RPCListeners:  []string{"127.0.0.1:10009"},
		RESTListeners: []string{"127.0.0.1:8080"},
	}
	findings := CheckRPCBindAddress(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for localhost, got %d", len(findings))
	}
}

func TestCheckRPCBindAddress_AllInterfaces(t *testing.T) {
	cfg := &config.LndConfig{
		RPCListeners: []string{"0.0.0.0:10009"},
	}
	findings := CheckRPCBindAddress(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != scanner.Critical {
		t.Errorf("severity = %v, want CRITICAL", findings[0].Severity)
	}
}

func TestCheckRPCBindAddress_BarePort(t *testing.T) {
	cfg := &config.LndConfig{
		RPCListeners: []string{":10009"},
	}
	findings := CheckRPCBindAddress(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for bare port, got %d", len(findings))
	}
}

func TestCheckRPCBindAddress_IPv6AllInterfaces(t *testing.T) {
	cfg := &config.LndConfig{
		RESTListeners: []string{"[::]:8080"},
	}
	findings := CheckRPCBindAddress(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for [::], got %d", len(findings))
	}
}

func TestCheckRPCBindAddress_Both(t *testing.T) {
	cfg := &config.LndConfig{
		RPCListeners:  []string{"0.0.0.0:10009"},
		RESTListeners: []string{"0.0.0.0:8080"},
	}
	findings := CheckRPCBindAddress(cfg)
	if len(findings) != 2 {
		t.Errorf("expected 2 findings (RPC + REST), got %d", len(findings))
	}
}

// --- External IP Leak Tests ---

func TestCheckExternalIPLeak_TorOnly(t *testing.T) {
	cfg := &config.LndConfig{
		Tor: config.TorConfig{Active: true},
	}
	findings := CheckExternalIPLeak(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for Tor-only with no external IPs, got %d", len(findings))
	}
}

func TestCheckExternalIPLeak_TorWithClearnet(t *testing.T) {
	cfg := &config.LndConfig{
		Tor:         config.TorConfig{Active: true},
		ExternalIPs: []string{"203.0.113.50"},
	}
	findings := CheckExternalIPLeak(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for clearnet IP with Tor, got %d", len(findings))
	}
	if findings[0].Severity != scanner.High {
		t.Errorf("severity = %v, want HIGH", findings[0].Severity)
	}
}

func TestCheckExternalIPLeak_TorWithOnion(t *testing.T) {
	cfg := &config.LndConfig{
		Tor:         config.TorConfig{Active: true},
		ExternalIPs: []string{"abc123.onion:9735"},
	}
	findings := CheckExternalIPLeak(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for .onion address with Tor, got %d", len(findings))
	}
}

func TestCheckExternalIPLeak_NoTor(t *testing.T) {
	cfg := &config.LndConfig{
		Tor:         config.TorConfig{Active: false},
		ExternalIPs: []string{"203.0.113.50"},
	}
	findings := CheckExternalIPLeak(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when Tor is not active, got %d", len(findings))
	}
}

func TestIsBoundToAllInterfaces(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:10009", false},
		{"0.0.0.0:10009", true},
		{":10009", true},
		{"[::]:8080", true},
		{"192.168.1.5:10009", false},
		{"localhost:10009", false},
	}
	for _, tt := range tests {
		if got := isBoundToAllInterfaces(tt.addr); got != tt.want {
			t.Errorf("isBoundToAllInterfaces(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestIsOnionAddress(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"abc123.onion", true},
		{"abc123.onion:9735", true},
		{"203.0.113.50", false},
		{"mynode.example.com:9735", false},
		{"ABC.ONION:9735", true},
	}
	for _, tt := range tests {
		if got := isOnionAddress(tt.addr); got != tt.want {
			t.Errorf("isOnionAddress(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}
