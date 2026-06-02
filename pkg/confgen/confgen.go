package confgen

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// Options controls what sections are included in the generated config.
type Options struct {
	Network    string // mainnet, testnet, regtest, signet (default: mainnet)
	Tor        bool   // include Tor configuration
	Watchtower string // watchtower URI (empty = include section with placeholder)
	Alias      string // node alias
}

// DefaultOptions returns production-safe defaults.
func DefaultOptions() Options {
	return Options{
		Network: "mainnet",
	}
}

// Generate writes a hardened lnd.conf to the given writer.
func Generate(w io.Writer, opts Options) error {
	if opts.Network == "" {
		opts.Network = "mainnet"
	}

	sections := []section{
		headerSection(opts),
		applicationSection(opts),
		bitcoinSection(opts),
		protocolSection(),
		channelSection(),
	}

	if opts.Tor {
		sections = append(sections, torSection())
	}

	sections = append(sections, watchtowerSection(opts))
	sections = append(sections, checklistSection(opts))

	for i, s := range sections {
		if _, err := fmt.Fprint(w, s.render()); err != nil {
			return err
		}
		if i < len(sections)-1 {
			fmt.Fprintln(w)
		}
	}

	return nil
}

// section represents a block of config output.
type section struct {
	lines []string
}

func (s section) render() string {
	return strings.Join(s.lines, "\n") + "\n"
}

func line(s string) string  { return s }
func comment(s string) string { return "# " + s }
func blank() string          { return "" }

func headerSection(opts Options) section {
	return section{lines: []string{
		comment("============================================================"),
		comment("lnaudit — Hardened LND Configuration"),
		comment(fmt.Sprintf("Generated: %s", time.Now().Format("2006-01-02"))),
		comment(fmt.Sprintf("Network:   %s", opts.Network)),
		comment(""),
		comment("This configuration applies security best practices based on"),
		comment("analysis of real-world Bitcoin infrastructure incidents."),
		comment(""),
		comment("WARNING: This is a starter template. Review and merge with"),
		comment("your existing configuration before use. Node-specific settings"),
		comment("(wallet paths, chain backend, fees) are NOT included."),
		comment(""),
		comment("See: https://github.com/NonsoAmadi10/lnaudit"),
		comment("============================================================"),
	}}
}

func applicationSection(opts Options) section {
	lines := []string{
		blank(),
		line("[Application Options]"),
		blank(),
		comment("--- RPC/REST Binding ---"),
		comment("Bind control interfaces to localhost ONLY."),
		comment("Exposing gRPC/REST to 0.0.0.0 gives any network peer full"),
		comment("admin access to your node and wallet."),
		comment("Ref: NiceHash breach — exposed management interface led to $64M loss."),
		line("rpclisten=127.0.0.1:10009"),
		line("restlisten=127.0.0.1:8080"),
		blank(),
		comment("--- Authentication ---"),
		comment("NEVER disable macaroon authentication. The --no-macaroons flag"),
		comment("removes all auth from gRPC/REST, turning your node into an"),
		comment("open wallet accessible to anyone on the network."),
		comment("no-macaroons is false by default — do not set it to true."),
		blank(),
		comment("--- Seed Backup ---"),
		comment("NEVER set noseedbackup=true. Without a seed phrase, losing"),
		comment("access to the wallet file means permanent, irrecoverable fund loss."),
		comment("noseedbackup is false by default — do not set it to true."),
		blank(),
		comment("--- Wallet Encryption ---"),
		comment("NEVER set noencryptwallet=true. An unencrypted wallet file"),
		comment("on disk means anyone with file access can steal all funds."),
		comment("Ref: Bitcoinica/Linode breach — server compromise exposed unencrypted keys."),
		comment("noencryptwallet is false by default — do not set it to true."),
		blank(),
		comment("--- Logging ---"),
		comment("Use 'info' level in production. Debug/trace logging can write"),
		comment("payment preimages, macaroon data, and peer details to log files."),
		line("debuglevel=info"),
		blank(),
		comment("--- Gossip Timing ---"),
		comment("Keep the default trickle delay. Setting trickledelay=0 sends"),
		comment("gossip immediately, enabling timing analysis of node activity."),
		comment("Default: 5000ms (do not override unless you understand the risk)."),
		blank(),
		comment("--- Disconnect Safety ---"),
		comment("Do not enable unsafe-disconnect in production. It allows"),
		comment("disconnecting from peers with active channels, risking missed"),
		comment("updates and force closures."),
	}

	if opts.Alias != "" {
		lines = append(lines, blank())
		lines = append(lines, line(fmt.Sprintf("alias=%s", opts.Alias)))
	}

	// P2P listener — bind to localhost if Tor, otherwise default
	if opts.Tor {
		lines = append(lines,
			blank(),
			comment("--- P2P Listener ---"),
			comment("With Tor active, bind the P2P listener to localhost."),
			comment("Tor creates a hidden service that routes traffic to this address."),
			line("listen=127.0.0.1:9735"),
		)
	}

	return section{lines: lines}
}

func bitcoinSection(opts Options) section {
	networkFlag := fmt.Sprintf("bitcoin.%s=true", opts.Network)

	return section{lines: []string{
		blank(),
		line("[Bitcoin]"),
		blank(),
		line("bitcoin.active=true"),
		line(networkFlag),
		blank(),
		comment("--- Channel Confirmation Depth ---"),
		comment("Require at least 3 confirmations before a channel is considered open."),
		comment("Low confirmation targets make channels vulnerable to double-spend"),
		comment("attacks on the funding transaction."),
		comment("Ref: Bitcoin Gold 51% attack (2018) — low confirmation depth exploited."),
		comment("Use 6 for high-value channels."),
		line("bitcoin.defaultchanconfs=3"),
	}}
}

func protocolSection() section {
	return section{lines: []string{
		blank(),
		line("[protocol]"),
		blank(),
		comment("--- SCID Alias ---"),
		comment("Enable Short Channel ID aliases so that channel UTXOs are not"),
		comment("publicly linked to your node identity through gossip."),
		comment("Without this, anyone can see your on-chain funding transactions."),
		line("protocol.option-scid-alias=true"),
		blank(),
		comment("--- Anchors ---"),
		comment("Enable anchor outputs for more reliable fee bumping on"),
		comment("force-close transactions. Recommended for all nodes."),
		line("protocol.anchors=true"),
	}}
}

func channelSection() section {
	return section{lines: []string{
		blank(),
		comment("--- Channel Limits ---"),
		comment("Set an explicit maximum channel size to prevent a single channel"),
		comment("from locking up too much capital. Adjust based on your risk tolerance."),
		comment("Value in satoshis. 16777215 = ~0.17 BTC (protocol default)."),
		comment("Ref: Bitfinex breach — concentrated channel exposure amplified losses."),
		comment("maxchansize=16777215"),
		blank(),
		comment("--- Pending Channel Limit ---"),
		comment("Limit the number of channels that can be in a pending state."),
		comment("Default is 1, which is conservative."),
		comment("maxpendingchannels=1"),
	}}
}

func torSection() section {
	return section{lines: []string{
		blank(),
		line("[tor]"),
		blank(),
		comment("--- Tor Activation ---"),
		comment("Route all LND traffic through Tor to hide your node's IP address."),
		line("tor.active=true"),
		blank(),
		comment("--- V3 Onion ---"),
		comment("Use V3 onion services (Ed25519). V2 uses RSA-1024, which is"),
		comment("deprecated and cryptographically weak."),
		line("tor.v3=true"),
		blank(),
		comment("--- Stream Isolation ---"),
		comment("Use a separate Tor circuit for each peer connection."),
		comment("Without this, an adversary controlling a Tor relay could"),
		comment("correlate your connections to different peers."),
		line("tor.streamisolation=true"),
		blank(),
		comment("--- Onion Key Encryption ---"),
		comment("Encrypt the onion service private key on disk."),
		comment("A server compromise without this flag exposes your hidden"),
		comment("service identity permanently."),
		comment("Ref: Bitcoinica/Linode breach — plaintext keys on compromised servers."),
		line("tor.encryptkey=true"),
		blank(),
		comment("--- Clearnet Proxy Bypass ---"),
		comment("NEVER enable skip-proxy-for-clearnet-targets with Tor active."),
		comment("It routes non-.onion traffic outside Tor, revealing your real"),
		comment("IP address to every clearnet peer."),
		comment("tor.skip-proxy-for-clearnet-targets is false by default."),
	}}
}

func watchtowerSection(opts Options) section {
	lines := []string{
		blank(),
		line("[wtclient]"),
		blank(),
		comment("--- Watchtower Client ---"),
		comment("A watchtower monitors your channels while your node is offline."),
		comment("Without one, a malicious channel partner can broadcast a revoked"),
		comment("commitment transaction and steal your funds while you are down."),
		comment("Ref: Bitfinex breach — unmonitored channels exploited."),
		line("wtclient.active=true"),
	}

	if opts.Watchtower != "" {
		lines = append(lines,
			blank(),
			comment("Watchtower server URI:"),
			line(fmt.Sprintf("wtclient.private-tower-uris=%s", opts.Watchtower)),
		)
	} else {
		lines = append(lines,
			blank(),
			comment("Add your watchtower URI below:"),
			comment("wtclient.private-tower-uris=<pubkey>@<host>:<port>"),
		)
	}

	return section{lines: lines}
}

func checklistSection(opts Options) section {
	lines := []string{
		blank(),
		comment("============================================================"),
		comment("POST-GENERATION CHECKLIST"),
		comment(""),
		comment("The following security measures cannot be set in lnd.conf."),
		comment("Complete these steps manually after deploying this config:"),
		comment(""),
		comment("  1. File permissions"),
		comment("     chmod 0600 wallet.db tls.key admin.macaroon channel.backup"),
		comment("     chmod 0640 lnd.conf"),
		comment("     Ensure files are owned by the LND service user."),
		comment(""),
		comment("  2. TLS certificate"),
		comment("     Verify tls.cert is not expired."),
		comment("     Rotate periodically: delete tls.cert + tls.key, restart LND."),
		comment(""),
		comment("  3. Macaroon hygiene"),
		comment("     Do NOT copy admin.macaroon to ~/Downloads or shared folders."),
		comment("     Use readonly.macaroon or invoice.macaroon for integrations."),
		comment(""),
		comment("  4. Firewall"),
		comment("     Block external access to ports 10009 (gRPC) and 8080 (REST)."),
		comment("     Only allow 9735 (P2P) if running a public routing node."),
		comment(""),
		comment("  5. Chain backend"),
		comment("     Configure your bitcoin/bitcoind/neutrino backend separately."),
		comment("     This template does not include chain backend settings."),
		comment(""),
		comment("  6. Validate with lnaudit"),
		comment("     Run: lnaudit scan --config /path/to/lnd.conf"),
		comment("     Then: lnaudit scan --connect localhost:10009"),
		comment(""),
		comment("============================================================"),
	}

	return section{lines: lines}
}
