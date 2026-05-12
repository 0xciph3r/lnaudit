package config

import (
	"fmt"
	"os"

	"gopkg.in/ini.v1"
)

// LndConfig represents parsed settings from lnd.conf relevant to security scanning.
type LndConfig struct {
	// [Application Options]
	DataDir              string `ini:"datadir"`
	NoMacaroons          bool   `ini:"no-macaroons"`
	DebugLevel           string `ini:"debuglevel"`
	DebugHTLC            bool   `ini:"debughtlc"`
	NoSeedBackup         bool   `ini:"noseedbackup"`
	NoEncryptWallet      bool   `ini:"noencryptwallet"`
	UnsafeDisconnect     bool   `ini:"unsafe-disconnect"`
	TrickleDelay         int    `ini:"trickledelay"`
	TrickleDelayExplicit bool   // true if trickledelay was explicitly set in config
	MaxPendingChannels   int    `ini:"maxpendingchannels"`
	MaxChanSize          int64  `ini:"maxchansize"`
	Alias                string `ini:"alias"`
	NAT                  bool   `ini:"nat"`

	// Listener configuration (multi-value keys)
	RPCListeners  []string
	RESTListeners []string
	Listeners     []string
	ExternalIPs   []string
	ExternalHosts []string

	// [Bitcoin]
	Bitcoin BitcoinConfig

	// [tor]
	Tor TorConfig

	// [wtclient]
	WatchtowerClient WatchtowerClientConfig

	// [protocol]
	Protocol ProtocolConfig

	// [gossip]
	Gossip GossipConfig

	// Raw provides access to any key not explicitly modeled above.
	Raw *ini.File
}

// BitcoinConfig holds [Bitcoin] section values.
type BitcoinConfig struct {
	Active           bool   `ini:"bitcoin.active"`
	Node             string `ini:"bitcoin.node"`
	DefaultChanConfs int    `ini:"bitcoin.defaultchanconfs"`
	Network          string // derived from bitcoin.mainnet, bitcoin.testnet, etc.
}

// TorConfig holds [tor] section values.
type TorConfig struct {
	Active                      bool   `ini:"tor.active"`
	V3                          bool   `ini:"tor.v3"`
	EncryptKey                  bool   `ini:"tor.encryptkey"`
	StreamIsolation             bool   `ini:"tor.streamisolation"`
	SkipProxyForClearnetTargets bool   `ini:"tor.skip-proxy-for-clearnet-targets"`
	SOCKS                       string `ini:"tor.socks"`
	Control                     string `ini:"tor.control"`
}

// WatchtowerClientConfig holds [wtclient] section values.
type WatchtowerClientConfig struct {
	Active bool     `ini:"wtclient.active"`
	Towers []string // private-tower-uris
}

// ProtocolConfig holds [protocol] section values.
type ProtocolConfig struct {
	Anchors   bool `ini:"protocol.anchors"`
	ScidAlias bool `ini:"protocol.option-scid-alias"`
}

// GossipConfig holds [gossip] section values.
type GossipConfig struct {
	SubBatchDelay string `ini:"gossip.sub-batch-delay"`
}

// maxConfigSize is the largest config file we'll read (1 MB).
const maxConfigSize = 1 << 20

// Parse reads an lnd.conf file and returns a structured LndConfig.
func Parse(path string) (*LndConfig, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	if info.Size() > maxConfigSize {
		return nil, fmt.Errorf("config file too large (%d bytes, max %d)", info.Size(), maxConfigSize)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	return ParseBytes(data)
}

// ParseBytes parses lnd.conf content from raw bytes.
func ParseBytes(data []byte) (*LndConfig, error) {
	cfg, err := ini.LoadSources(ini.LoadOptions{
		AllowBooleanKeys:        true,
		InsensitiveSections:     true,
		InsensitiveKeys:         true,
		SkipUnrecognizableLines: true,
	}, data)
	if err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Re-load with ShadowLoad to support repeated keys (rpclisten, externalip, etc.)
	shadow, err := ini.ShadowLoad(data)
	if err == nil {
		cfg = shadow
	}

	c := &LndConfig{Raw: cfg}

	// [Application Options] — the default section in lnd.conf
	appSec := cfg.Section("Application Options")
	if appSec != nil {
		c.DataDir = appSec.Key("datadir").String()
		c.NoMacaroons, _ = appSec.Key("no-macaroons").Bool()
		c.DebugLevel = appSec.Key("debuglevel").String()
		c.DebugHTLC, _ = appSec.Key("debughtlc").Bool()
		c.NoSeedBackup, _ = appSec.Key("noseedbackup").Bool()
		c.NoEncryptWallet, _ = appSec.Key("noencryptwallet").Bool()
		c.UnsafeDisconnect, _ = appSec.Key("unsafe-disconnect").Bool()
		c.TrickleDelay, _ = appSec.Key("trickledelay").Int()
		c.TrickleDelayExplicit = appSec.Key("trickledelay").String() != ""
		c.MaxPendingChannels, _ = appSec.Key("maxpendingchannels").Int()
		c.MaxChanSize, _ = appSec.Key("maxchansize").Int64()
		c.Alias = appSec.Key("alias").String()
		c.NAT, _ = appSec.Key("nat").Bool()

		c.RPCListeners = readMulti(appSec, "rpclisten")
		c.RESTListeners = readMulti(appSec, "restlisten")
		c.Listeners = readMulti(appSec, "listen")
		c.ExternalIPs = readMulti(appSec, "externalip")
		c.ExternalHosts = readMulti(appSec, "externalhosts")
	}

	// [Bitcoin]
	btcSec := cfg.Section("Bitcoin")
	if btcSec != nil {
		c.Bitcoin.Active, _ = btcSec.Key("bitcoin.active").Bool()
		c.Bitcoin.Node = btcSec.Key("bitcoin.node").String()
		c.Bitcoin.DefaultChanConfs, _ = btcSec.Key("bitcoin.defaultchanconfs").Int()

		// Derive network from the explicit boolean flags.
		// LND only allows one to be set; we check in priority order.
		switch {
		case keyIsTrue(btcSec, "bitcoin.mainnet"):
			c.Bitcoin.Network = "mainnet"
		case keyIsTrue(btcSec, "bitcoin.testnet"):
			c.Bitcoin.Network = "testnet"
		case keyIsTrue(btcSec, "bitcoin.regtest"):
			c.Bitcoin.Network = "regtest"
		case keyIsTrue(btcSec, "bitcoin.simnet"):
			c.Bitcoin.Network = "simnet"
		case keyIsTrue(btcSec, "bitcoin.signet"):
			c.Bitcoin.Network = "signet"
		default:
			c.Bitcoin.Network = "mainnet"
		}
	}

	// [tor]
	torSec := cfg.Section("tor")
	if torSec != nil {
		c.Tor.Active, _ = torSec.Key("tor.active").Bool()
		c.Tor.V3, _ = torSec.Key("tor.v3").Bool()
		c.Tor.EncryptKey, _ = torSec.Key("tor.encryptkey").Bool()
		c.Tor.StreamIsolation, _ = torSec.Key("tor.streamisolation").Bool()
		c.Tor.SkipProxyForClearnetTargets, _ = torSec.Key("tor.skip-proxy-for-clearnet-targets").Bool()
		c.Tor.SOCKS = torSec.Key("tor.socks").String()
		c.Tor.Control = torSec.Key("tor.control").String()
	}

	// [wtclient]
	wtSec := cfg.Section("wtclient")
	if wtSec != nil {
		c.WatchtowerClient.Active, _ = wtSec.Key("wtclient.active").Bool()
		c.WatchtowerClient.Towers = readMulti(wtSec, "wtclient.private-tower-uris")
	}

	// [protocol]
	protoSec := cfg.Section("protocol")
	if protoSec != nil {
		c.Protocol.Anchors, _ = protoSec.Key("protocol.anchors").Bool()
		c.Protocol.ScidAlias, _ = protoSec.Key("protocol.option-scid-alias").Bool()
	}

	// [gossip]
	gossSec := cfg.Section("gossip")
	if gossSec != nil {
		c.Gossip.SubBatchDelay = gossSec.Key("gossip.sub-batch-delay").String()
	}

	return c, nil
}

// readMulti collects all values for a key that may appear multiple times
// (LND uses repeated keys like rpclisten= for multiple listeners).
func readMulti(sec *ini.Section, key string) []string {
	k := sec.Key(key)
	vals := k.ValueWithShadows()
	var result []string
	for _, v := range vals {
		if v != "" {
			result = append(result, v)
		}
	}
	return result
}

func keyIsTrue(sec *ini.Section, key string) bool {
	v, err := sec.Key(key).Bool()
	return err == nil && v
}
