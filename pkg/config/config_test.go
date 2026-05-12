package config

import (
	"testing"
)

const sampleConfig = `
[Application Options]
debuglevel=info
alias=my-routing-node
maxpendingchannels=2
maxchansize=16777215
rpclisten=127.0.0.1:10009
restlisten=127.0.0.1:8080
externalip=203.0.113.50
externalip=mynode.example.com

[Bitcoin]
bitcoin.active=true
bitcoin.mainnet=true
bitcoin.node=bitcoind
bitcoin.defaultchanconfs=6

[tor]
tor.active=true
tor.v3=true
tor.encryptkey=true
tor.streamisolation=true
tor.skip-proxy-for-clearnet-targets=false
tor.socks=127.0.0.1:9050
tor.control=127.0.0.1:9051

[wtclient]
wtclient.active=true

[protocol]
protocol.option-scid-alias=true
`

func TestParse_BasicFields(t *testing.T) {
	c, err := ParseBytes([]byte(sampleConfig))
	if err != nil {
		t.Fatalf("ParseBytes() error: %v", err)
	}

	if c.Alias != "my-routing-node" {
		t.Errorf("Alias = %q, want %q", c.Alias, "my-routing-node")
	}
	if c.DebugLevel != "info" {
		t.Errorf("DebugLevel = %q, want %q", c.DebugLevel, "info")
	}
	if c.MaxPendingChannels != 2 {
		t.Errorf("MaxPendingChannels = %d, want 2", c.MaxPendingChannels)
	}
	if c.MaxChanSize != 16777215 {
		t.Errorf("MaxChanSize = %d, want 16777215", c.MaxChanSize)
	}
}

func TestParse_MultiValueKeys(t *testing.T) {
	c, err := ParseBytes([]byte(sampleConfig))
	if err != nil {
		t.Fatalf("ParseBytes() error: %v", err)
	}

	if len(c.RPCListeners) != 1 || c.RPCListeners[0] != "127.0.0.1:10009" {
		t.Errorf("RPCListeners = %v, want [127.0.0.1:10009]", c.RPCListeners)
	}
	if len(c.ExternalIPs) != 2 {
		t.Errorf("ExternalIPs = %v, want 2 entries", c.ExternalIPs)
	}
}

func TestParse_Bitcoin(t *testing.T) {
	c, err := ParseBytes([]byte(sampleConfig))
	if err != nil {
		t.Fatalf("ParseBytes() error: %v", err)
	}

	if !c.Bitcoin.Active {
		t.Error("Bitcoin.Active should be true")
	}
	if c.Bitcoin.Network != "mainnet" {
		t.Errorf("Bitcoin.Network = %q, want mainnet", c.Bitcoin.Network)
	}
	if c.Bitcoin.Node != "bitcoind" {
		t.Errorf("Bitcoin.Node = %q, want bitcoind", c.Bitcoin.Node)
	}
	if c.Bitcoin.DefaultChanConfs != 6 {
		t.Errorf("Bitcoin.DefaultChanConfs = %d, want 6", c.Bitcoin.DefaultChanConfs)
	}
}

func TestParse_Tor(t *testing.T) {
	c, err := ParseBytes([]byte(sampleConfig))
	if err != nil {
		t.Fatalf("ParseBytes() error: %v", err)
	}

	if !c.Tor.Active {
		t.Error("Tor.Active should be true")
	}
	if !c.Tor.V3 {
		t.Error("Tor.V3 should be true")
	}
	if !c.Tor.EncryptKey {
		t.Error("Tor.EncryptKey should be true")
	}
	if !c.Tor.StreamIsolation {
		t.Error("Tor.StreamIsolation should be true")
	}
	if c.Tor.SkipProxyForClearnetTargets {
		t.Error("Tor.SkipProxyForClearnetTargets should be false")
	}
}

func TestParse_WatchtowerClient(t *testing.T) {
	c, err := ParseBytes([]byte(sampleConfig))
	if err != nil {
		t.Fatalf("ParseBytes() error: %v", err)
	}

	if !c.WatchtowerClient.Active {
		t.Error("WatchtowerClient.Active should be true")
	}
}

func TestParse_Protocol(t *testing.T) {
	c, err := ParseBytes([]byte(sampleConfig))
	if err != nil {
		t.Fatalf("ParseBytes() error: %v", err)
	}

	if !c.Protocol.ScidAlias {
		t.Error("Protocol.ScidAlias should be true")
	}
}

func TestParse_DangerousFlags(t *testing.T) {
	dangerous := `
[Application Options]
noseedbackup=true
no-macaroons=true
noencryptwallet=true
debuglevel=trace
debughtlc=true
unsafe-disconnect=true
trickledelay=0
`
	c, err := ParseBytes([]byte(dangerous))
	if err != nil {
		t.Fatalf("ParseBytes() error: %v", err)
	}

	if !c.NoSeedBackup {
		t.Error("NoSeedBackup should be true")
	}
	if !c.NoMacaroons {
		t.Error("NoMacaroons should be true")
	}
	if !c.NoEncryptWallet {
		t.Error("NoEncryptWallet should be true")
	}
	if c.DebugLevel != "trace" {
		t.Errorf("DebugLevel = %q, want trace", c.DebugLevel)
	}
	if !c.DebugHTLC {
		t.Error("DebugHTLC should be true")
	}
	if !c.UnsafeDisconnect {
		t.Error("UnsafeDisconnect should be true")
	}
	if c.TrickleDelay != 0 {
		t.Errorf("TrickleDelay = %d, want 0", c.TrickleDelay)
	}
}

func TestParse_EmptyConfig(t *testing.T) {
	c, err := ParseBytes([]byte(""))
	if err != nil {
		t.Fatalf("ParseBytes() error: %v", err)
	}

	if c.NoMacaroons {
		t.Error("NoMacaroons should default to false")
	}
	if c.Bitcoin.Network != "mainnet" {
		t.Errorf("Bitcoin.Network = %q, want mainnet (default)", c.Bitcoin.Network)
	}
}

func TestParse_TorSkipProxy(t *testing.T) {
	leaky := `
[tor]
tor.active=true
tor.skip-proxy-for-clearnet-targets=true
`
	c, err := ParseBytes([]byte(leaky))
	if err != nil {
		t.Fatalf("ParseBytes() error: %v", err)
	}

	if !c.Tor.SkipProxyForClearnetTargets {
		t.Error("Tor.SkipProxyForClearnetTargets should be true")
	}
}

func TestParse_TestnetNetwork(t *testing.T) {
	conf := `
[Bitcoin]
bitcoin.active=true
bitcoin.testnet=true
bitcoin.node=bitcoind
`
	c, err := ParseBytes([]byte(conf))
	if err != nil {
		t.Fatalf("ParseBytes() error: %v", err)
	}

	if c.Bitcoin.Network != "testnet" {
		t.Errorf("Bitcoin.Network = %q, want testnet", c.Bitcoin.Network)
	}
}

func TestParse_RegtestNetwork(t *testing.T) {
	conf := `
[Bitcoin]
bitcoin.active=true
bitcoin.regtest=true
`
	c, err := ParseBytes([]byte(conf))
	if err != nil {
		t.Fatalf("ParseBytes() error: %v", err)
	}

	if c.Bitcoin.Network != "regtest" {
		t.Errorf("Bitcoin.Network = %q, want regtest", c.Bitcoin.Network)
	}
}
