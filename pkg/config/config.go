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

	// New security-relevant flags
	NoRestTLS               bool `ini:"no-rest-tls"`
	TLSEncryptKey           bool `ini:"tlsencryptkey"`
	TLSEncryptKeyExplicit   bool // true if tlsencryptkey was explicitly set
	WalletUnlockAllowCreate bool `ini:"wallet-unlock-allow-create"`
	AllowCircularRoute      bool `ini:"allow-circular-route"`
	RejectPush              bool `ini:"rejectpush"`
	RejectPushExplicit      bool // true if rejectpush was explicitly set
	RejectHTLC              bool `ini:"rejecthtlc"`
	EnableUpfrontShutdown   bool `ini:"enable-upfront-shutdown"`
	DefaultRemoteMaxHTLCs   int  `ini:"default-remote-max-htlcs"`
	DefaultRemoteMaxHTLCsExplicit bool
	MaxCLTVExpiry           int  `ini:"max-cltv-expiry"`
	MaxCLTVExpiryExplicit   bool
	ChannelMaxFeeExposure   int64 `ini:"channel-max-fee-exposure"`
	MinChanSize             int64 `ini:"minchansize"`
	MinChanSizeExplicit     bool
	AcceptKeysend           bool `ini:"accept-keysend"`
	AcceptAMP               bool `ini:"accept-amp"`
	RequireInterceptor      bool `ini:"requireinterceptor"`
	NoListen                bool `ini:"nolisten"`
	RESTCors                string `ini:"restcors"`
	GCCanceledInvoicesStartup bool `ini:"gc-canceled-invoices-on-startup"`
	GCCanceledInvoicesFly     bool `ini:"gc-canceled-invoices-on-the-fly"`
	HTTPHeaderTimeout       string `ini:"http-header-timeout"`

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

	// [autopilot]
	Autopilot AutopilotConfig

	// Raw provides access to any key not explicitly modeled above.
	Raw *ini.File
}

// BitcoinConfig holds [Bitcoin] section values.
type BitcoinConfig struct {
	Active           bool   `ini:"bitcoin.active"`
	Node             string `ini:"bitcoin.node"`
	DefaultChanConfs int    `ini:"bitcoin.defaultchanconfs"`
	Network          string // derived from bitcoin.mainnet, bitcoin.testnet, etc.
	MinHTLC          int64  `ini:"bitcoin.minhtlc"`
	MinHTLCExplicit  bool
	TimelockDelta    int    `ini:"bitcoin.timelockdelta"`
	TimelockDeltaExplicit bool
	EstimateMode     string `ini:"bitcoin.estimatemode"`
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
	Anchors        bool `ini:"protocol.anchors"`
	ScidAlias      bool `ini:"protocol.option-scid-alias"`
	ZeroConf       bool `ini:"protocol.zero-conf"`
	WumboChannels  bool `ini:"protocol.wumbo-channels"`
	NoAnchors      bool `ini:"protocol.no-anchors"`
}

// GossipConfig holds [gossip] section values.
type GossipConfig struct {
	SubBatchDelay string `ini:"gossip.sub-batch-delay"`
	BanThreshold  int    `ini:"gossip.ban-threshold"`
	BanThresholdExplicit bool
}

// AutopilotConfig holds [autopilot] section values.
type AutopilotConfig struct {
	Active     bool    `ini:"autopilot.active"`
	Allocation float64 `ini:"autopilot.allocation"`
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

		// New security-relevant flags
		c.NoRestTLS, _ = appSec.Key("no-rest-tls").Bool()
		c.TLSEncryptKey, _ = appSec.Key("tlsencryptkey").Bool()
		c.TLSEncryptKeyExplicit = appSec.Key("tlsencryptkey").String() != ""
		c.WalletUnlockAllowCreate, _ = appSec.Key("wallet-unlock-allow-create").Bool()
		c.AllowCircularRoute, _ = appSec.Key("allow-circular-route").Bool()
		c.RejectPush, _ = appSec.Key("rejectpush").Bool()
		c.RejectPushExplicit = appSec.Key("rejectpush").String() != ""
		c.RejectHTLC, _ = appSec.Key("rejecthtlc").Bool()
		c.EnableUpfrontShutdown, _ = appSec.Key("enable-upfront-shutdown").Bool()
		c.DefaultRemoteMaxHTLCs, _ = appSec.Key("default-remote-max-htlcs").Int()
		c.DefaultRemoteMaxHTLCsExplicit = appSec.Key("default-remote-max-htlcs").String() != ""
		c.MaxCLTVExpiry, _ = appSec.Key("max-cltv-expiry").Int()
		c.MaxCLTVExpiryExplicit = appSec.Key("max-cltv-expiry").String() != ""
		c.ChannelMaxFeeExposure, _ = appSec.Key("channel-max-fee-exposure").Int64()
		c.MinChanSize, _ = appSec.Key("minchansize").Int64()
		c.MinChanSizeExplicit = appSec.Key("minchansize").String() != ""
		c.AcceptKeysend, _ = appSec.Key("accept-keysend").Bool()
		c.AcceptAMP, _ = appSec.Key("accept-amp").Bool()
		c.RequireInterceptor, _ = appSec.Key("requireinterceptor").Bool()
		c.NoListen, _ = appSec.Key("nolisten").Bool()
		c.RESTCors = appSec.Key("restcors").String()
		c.GCCanceledInvoicesStartup, _ = appSec.Key("gc-canceled-invoices-on-startup").Bool()
		c.GCCanceledInvoicesFly, _ = appSec.Key("gc-canceled-invoices-on-the-fly").Bool()
		c.HTTPHeaderTimeout = appSec.Key("http-header-timeout").String()

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
		c.Bitcoin.MinHTLC, _ = btcSec.Key("bitcoin.minhtlc").Int64()
		c.Bitcoin.MinHTLCExplicit = btcSec.Key("bitcoin.minhtlc").String() != ""
		c.Bitcoin.TimelockDelta, _ = btcSec.Key("bitcoin.timelockdelta").Int()
		c.Bitcoin.TimelockDeltaExplicit = btcSec.Key("bitcoin.timelockdelta").String() != ""
		c.Bitcoin.EstimateMode = btcSec.Key("bitcoin.estimatemode").String()

		// Derive network from the explicit boolean flags.
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
		c.Protocol.ZeroConf, _ = protoSec.Key("protocol.zero-conf").Bool()
		c.Protocol.WumboChannels, _ = protoSec.Key("protocol.wumbo-channels").Bool()
		c.Protocol.NoAnchors, _ = protoSec.Key("protocol.no-anchors").Bool()
	}

	// [gossip]
	gossSec := cfg.Section("gossip")
	if gossSec != nil {
		c.Gossip.SubBatchDelay = gossSec.Key("gossip.sub-batch-delay").String()
		c.Gossip.BanThreshold, _ = gossSec.Key("gossip.ban-threshold").Int()
		c.Gossip.BanThresholdExplicit = gossSec.Key("gossip.ban-threshold").String() != ""
	}

	// [autopilot]
	autoSec := cfg.Section("autopilot")
	if autoSec != nil {
		c.Autopilot.Active, _ = autoSec.Key("autopilot.active").Bool()
		c.Autopilot.Allocation, _ = autoSec.Key("autopilot.allocation").Float64()
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
