package checks

import (
	"net"
	"strconv"
	"testing"
)

func TestCheckOpenPorts_DetectsOpenPort(t *testing.T) {
	// Start a temporary listener on a random port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	// Temporarily inject our test port into the scan list
	original := lndPorts
	lndPorts = []portCheck{{
		Port:        port,
		Service:     "test-service",
		Severity:    5, // scanner.High
		Description: "test",
		Remediation: "test",
	}}
	defer func() { lndPorts = original }()

	findings := CheckOpenPorts("127.0.0.1")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for open port, got %d", len(findings))
	}
	if findings[0].Module != "ports" {
		t.Errorf("expected module 'ports', got %q", findings[0].Module)
	}
}

func TestCheckOpenPorts_ClosedPort(t *testing.T) {
	original := lndPorts
	lndPorts = []portCheck{{
		Port:        59999, // unlikely to be open
		Service:     "test-closed",
		Severity:    5,
		Description: "test",
		Remediation: "test",
	}}
	defer func() { lndPorts = original }()

	findings := CheckOpenPorts("127.0.0.1")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for closed port, got %d", len(findings))
	}
}

func TestCheckOpenPorts_EmptyHost(t *testing.T) {
	original := lndPorts
	lndPorts = []portCheck{{
		Port:        59998,
		Service:     "test",
		Severity:    5,
		Description: "test",
		Remediation: "test",
	}}
	defer func() { lndPorts = original }()

	// Should not panic with empty host
	findings := CheckOpenPorts("")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestCheckOpenPorts_StripsPort(t *testing.T) {
	original := lndPorts
	lndPorts = []portCheck{{
		Port:        59997,
		Service:     "test",
		Severity:    5,
		Description: "test",
		Remediation: "test",
	}}
	defer func() { lndPorts = original }()

	// Pass host with port, should strip it
	findings := CheckOpenPorts("localhost:10009")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}
