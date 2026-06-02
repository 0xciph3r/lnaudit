package confgen

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenerate_DefaultOptions(t *testing.T) {
	var buf bytes.Buffer
	err := Generate(&buf, DefaultOptions())
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	output := buf.String()

	// Must contain key sections
	for _, section := range []string{
		"[Application Options]",
		"[Bitcoin]",
		"[protocol]",
		"[wtclient]",
	} {
		if !strings.Contains(output, section) {
			t.Errorf("output should contain section %q", section)
		}
	}

	// Must contain critical security settings
	for _, setting := range []string{
		"rpclisten=127.0.0.1:10009",
		"restlisten=127.0.0.1:8080",
		"debuglevel=info",
		"bitcoin.mainnet=true",
		"bitcoin.defaultchanconfs=3",
		"protocol.option-scid-alias=true",
		"wtclient.active=true",
	} {
		if !strings.Contains(output, setting) {
			t.Errorf("output should contain setting %q", setting)
		}
	}

	// Must NOT contain Tor section by default
	if strings.Contains(output, "[tor]") {
		t.Error("default options should not include [tor] section")
	}

	// Must contain checklist
	if !strings.Contains(output, "POST-GENERATION CHECKLIST") {
		t.Error("output should contain post-generation checklist")
	}

	// Must contain warning about being a template
	if !strings.Contains(output, "WARNING") {
		t.Error("output should contain template warning")
	}
}

func TestGenerate_WithTor(t *testing.T) {
	var buf bytes.Buffer
	opts := DefaultOptions()
	opts.Tor = true

	err := Generate(&buf, opts)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	output := buf.String()

	for _, setting := range []string{
		"[tor]",
		"tor.active=true",
		"tor.v3=true",
		"tor.streamisolation=true",
		"tor.encryptkey=true",
		"listen=127.0.0.1:9735",
	} {
		if !strings.Contains(output, setting) {
			t.Errorf("Tor config should contain %q", setting)
		}
	}
}

func TestGenerate_TestnetNetwork(t *testing.T) {
	var buf bytes.Buffer
	opts := DefaultOptions()
	opts.Network = "testnet"

	err := Generate(&buf, opts)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "bitcoin.testnet=true") {
		t.Error("should contain bitcoin.testnet=true")
	}
	if strings.Contains(output, "bitcoin.mainnet=true") {
		t.Error("should not contain bitcoin.mainnet=true for testnet")
	}
}

func TestGenerate_WithWatchtower(t *testing.T) {
	var buf bytes.Buffer
	opts := DefaultOptions()
	opts.Watchtower = "03abc@tower.example.com:9911"

	err := Generate(&buf, opts)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "wtclient.private-tower-uris=03abc@tower.example.com:9911") {
		t.Error("should contain watchtower URI")
	}
}

func TestGenerate_WithAlias(t *testing.T) {
	var buf bytes.Buffer
	opts := DefaultOptions()
	opts.Alias = "my-node"

	err := Generate(&buf, opts)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "alias=my-node") {
		t.Error("should contain alias setting")
	}
}

func TestGenerate_NoEmptySections(t *testing.T) {
	var buf bytes.Buffer
	err := Generate(&buf, DefaultOptions())
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	// Check there are no consecutive blank lines (indicating empty sections)
	output := buf.String()
	if strings.Contains(output, "\n\n\n\n") {
		t.Error("output should not have excessive blank lines")
	}
}
