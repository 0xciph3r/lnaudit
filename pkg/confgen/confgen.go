package confgen

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// Profile controls the overall security posture of the generated config.
type Profile string

const (
	// ProfilePrivate generates a config for wallet/private nodes that do not
	// route payments for others. This is the most restrictive profile.
	ProfilePrivate Profile = "private"

	// ProfileRouting generates a config for public routing nodes. It relaxes
	// some restrictions that would impair routing (e.g. rejecthtlc is not set)
	// while still applying all non-disruptive hardening.
	ProfileRouting Profile = "routing"
)

// Options controls what sections are included in the generated config.
type Options struct {
	Network    string  // mainnet, testnet, regtest, signet (default: mainnet)
	Profile    Profile // private or routing (default: routing)
	Tor        bool    // include Tor configuration
	Watchtower string  // watchtower URI (empty = include section with placeholder)
	Alias      string  // node alias
}

// DefaultOptions returns production-safe defaults.
func DefaultOptions() Options {
	return Options{
		Network: "mainnet",
		Profile: ProfileRouting,
	}
}

// Generate writes a hardened lnd.conf to the given writer.
func Generate(w io.Writer, opts Options) error {
	if opts.Network == "" {
		opts.Network = "mainnet"
	}
	if opts.Profile == "" {
		opts.Profile = ProfileRouting
	}

	sections := []section{
		headerSection(opts),
		applicationSection(opts),
		tlsSection(),
		rateLimitSection(),
		bitcoinSection(opts),
		channelSection(opts),
		protocolSection(opts),
		gossipSection(),
		paymentSection(opts),
		healthCheckSection(opts),
	}

	if opts.Tor {
		sections = append(sections, torSection())
	}

	sections = append(sections,
		watchtowerSection(opts),
		autopilotSection(),
		debugSection(),
		checklistSection(),
	)

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

func line(s string) string    { return s }
func comment(s string) string { return "# " + s }
func blank() string           { return "" }

func headerSection(opts Options) section {
	profileDesc := "routing node"
	if opts.Profile == ProfilePrivate {
		profileDesc = "private / wallet node"
	}

	return section{lines: []string{
		comment("============================================================"),
		comment("lnaudit — Hardened LND Configuration"),
		comment(fmt.Sprintf("Generated: %s", time.Now().Format("2006-01-02"))),
		comment(fmt.Sprintf("Network:   %s", opts.Network)),
		comment(fmt.Sprintf("Profile:   %s", profileDesc)),
		comment(""),
		comment("This configuration applies security best practices based on"),
		comment("analysis of real-world Bitcoin infrastructure incidents."),
		comment(""),
		comment("Settings are categorized as:"),
		comment("  [Active]  — Recommended hardening, emitted as key=value"),
		comment("  [Policy]  — Operational choice, commented for review"),
		comment("  [Warning] — Dangerous flag, never enable in production"),
		comment(""),
		comment("WARNING: This is a starter template. Review and merge with"),
		comment("your existing configuration before use. Node-specific settings"),
		comment("(wallet paths, chain backend, fees) are NOT included."),
		comment(""),
		comment("Sections:"),
		comment("  1.  Application Options    7.  Gossip Rate Limiting"),
		comment("  2.  TLS Hardening          8.  Payment & Invoice"),
		comment("  3.  Rate Limiting & DoS    9.  Health Checks"),
		comment("  4.  Bitcoin                10. Tor (if enabled)"),
		comment("  5.  Channel Policy         11. Watchtower"),
		comment("  6.  Protocol               12. Autopilot / Debug"),
		comment(""),
		comment("See: https://github.com/0xciph3r/lnaudit"),
		comment("============================================================"),
	}}
}

func applicationSection(opts Options) section {
	lines := []string{
		blank(),
		line("[Application Options]"),
		blank(),
		comment("=== 1. Application Security ==="),
		blank(),
		comment("[Active] Bind control interfaces to localhost ONLY."),
		comment("Exposing gRPC/REST to 0.0.0.0 gives any network peer full"),
		comment("admin access to your node and wallet."),
		comment("Ref: NiceHash breach — exposed management interface led to $64M loss."),
		line("rpclisten=127.0.0.1:10009"),
		line("restlisten=127.0.0.1:8080"),
		blank(),
		comment("[Warning] NEVER disable macaroon authentication."),
		comment("The --no-macaroons flag removes all auth from gRPC/REST, turning"),
		comment("your node into an open wallet accessible to anyone on the network."),
		comment("no-macaroons is false by default — do not set it to true."),
		blank(),
		comment("[Warning] NEVER set noseedbackup=true. Without a seed phrase,"),
		comment("losing access to the wallet file means permanent fund loss."),
		blank(),
		comment("[Warning] NEVER set noencryptwallet=true. An unencrypted wallet"),
		comment("on disk means anyone with file access can steal all funds."),
		comment("Ref: Bitcoinica/Linode breach — server compromise exposed unencrypted keys."),
		blank(),
		comment("[Active] Use 'info' level in production. Debug/trace logging can"),
		comment("write payment preimages, macaroon data, and peer details to logs."),
		line("debuglevel=info"),
		blank(),
		comment("[Warning] Do not set trickledelay=0. It sends gossip immediately,"),
		comment("enabling timing analysis of your node's activity."),
		comment("Default: 5000ms — do not override unless you understand the risk."),
		blank(),
		comment("[Warning] Do not enable unsafe-disconnect in production. It allows"),
		comment("disconnecting from peers with active channels, risking missed"),
		comment("updates and force closures."),
		blank(),
		comment("[Warning] Do not set wallet-unlock-allow-create=true."),
		comment("It allows wallet creation via the unauthenticated WalletUnlocker"),
		comment("RPC at startup. An attacker who connects first can inject an"),
		comment("adversarial seed and control the wallet."),
		blank(),
		comment("[Active] Do not accept CORS from all origins on the REST API."),
		comment("Setting restcors=* allows any website visited by the operator to"),
		comment("make credentialed REST requests using the browser's stored macaroons."),
		comment("Leave unset (default: no CORS) or restrict to specific origins."),
	}

	if opts.Alias != "" {
		lines = append(lines,
			blank(),
			line(fmt.Sprintf("alias=%s", opts.Alias)),
		)
	}

	if opts.Tor {
		lines = append(lines,
			blank(),
			comment("[Active] With Tor active, bind the P2P listener to localhost."),
			comment("Tor creates a hidden service that routes traffic to this address."),
			line("listen=127.0.0.1:9735"),
		)
	}

	if opts.Profile == ProfilePrivate {
		lines = append(lines,
			blank(),
			comment("[Active] Private node — disable inbound P2P connections."),
			comment("Reduces attack surface for nodes that only initiate outbound channels."),
			line("nolisten=true"),
		)
	}

	return section{lines: lines}
}

func tlsSection() section {
	return section{lines: []string{
		blank(),
		comment("=== 2. TLS Hardening ==="),
		blank(),
		comment("[Active] Encrypt the TLS private key on disk."),
		comment("Without this, an attacker with filesystem read access can"),
		comment("impersonate your node's gRPC/REST endpoint."),
		comment("The key is tied to the wallet unlock passphrase."),
		line("tlsencryptkey=true"),
		blank(),
		comment("[Active] Disable automatic SAN population."),
		comment("By default, LND embeds all interface IPs and the system hostname"),
		comment("into the TLS certificate SAN field. This leaks network topology"),
		comment("(private IPs, hostnames) to any client that reads the cert."),
		line("tlsdisableautofill=true"),
		blank(),
		comment("[Active] Enable automatic TLS certificate refresh."),
		comment("If the cert expires or IPs change, LND regenerates the cert"),
		comment("instead of continuing with an expired/invalid certificate."),
		line("tlsautorefresh=true"),
		blank(),
		comment("[Policy] Reduce TLS cert duration from the default 14 months."),
		comment("Shorter durations reduce the window for a compromised key to be"),
		comment("abused. 2160h = 90 days. Requires tlsautorefresh=true."),
		comment("tlscertduration=2160h"),
		blank(),
		comment("[Warning] NEVER set no-rest-tls=true. It sends REST API traffic"),
		comment("in plaintext — any network observer can intercept macaroons,"),
		comment("payment data, and RPC credentials."),
	}}
}

func rateLimitSection() section {
	return section{lines: []string{
		blank(),
		comment("=== 3. Rate Limiting & DoS Protection ==="),
		blank(),
		comment("[Policy] Maximum incoming P2P connection slots."),
		comment("Too high and a single IP can exhaust file descriptors and memory."),
		comment("Default: 100. Adjust based on your node's capacity."),
		comment("num-restricted-slots=100"),
		blank(),
		comment("[Active] HTTP header read timeout for the REST interface."),
		comment("Prevents Slowloris-style attacks that hold REST connections open"),
		comment("by sending headers very slowly."),
		line("http-header-timeout=5s"),
		blank(),
		comment("[Active] Connection timeout for outbound TCP connections."),
		comment("Very long values fill the connection pool with hanging sockets"),
		comment("during network partitions. Default: 2m."),
		line("connectiontimeout=120s"),
	}}
}

func bitcoinSection(opts Options) section {
	networkFlag := fmt.Sprintf("bitcoin.%s=true", opts.Network)

	return section{lines: []string{
		blank(),
		line("[Bitcoin]"),
		blank(),
		comment("=== 4. Bitcoin Backend ==="),
		blank(),
		line("bitcoin.active=true"),
		line(networkFlag),
		blank(),
		comment("[Active] Require at least 3 confirmations before a channel is open."),
		comment("Low confirmation targets make channels vulnerable to double-spend"),
		comment("attacks on the funding transaction."),
		comment("Ref: Bitcoin Gold 51%% attack (2018) — low confirmation depth exploited."),
		comment("Use 6 for high-value channels."),
		line("bitcoin.defaultchanconfs=3"),
		blank(),
		comment("[Active] Use conservative fee estimation."),
		comment("ECONOMICAL produces lower fees but increases the risk of"),
		comment("unconfirmed transactions during fee spikes."),
		line("bitcoin.estimatemode=CONSERVATIVE"),
		blank(),
		comment("[Active] CLTV expiry delta for forwarded payments."),
		comment("Very small values shrink the window for the node to safely"),
		comment("go to chain if an upstream HTLC times out. BOLTs recommend"),
		comment("minimum 40; real-world recommendation is 80+."),
		line("bitcoin.timelockdelta=80"),
		blank(),
		comment("[Active] Minimum inbound HTLC size (millisatoshis)."),
		comment("Accepting 1 msat HTLCs allows virtually free spam routing"),
		comment("attempts that consume CPU for signature verification and DB writes."),
		line("bitcoin.minhtlc=1000"),
		blank(),
		comment("[Policy] CSV delay required from the remote party."),
		comment("Lower values give an attacker less time to be penalized before"),
		comment("sweeping funds. Higher values lock up counterparty capital longer."),
		comment("Default: scaled 144-2016 based on channel size."),
		comment("bitcoin.defaultremotedelay=144"),
		blank(),
		comment("[Policy] Maximum CSV delay we accept on our own funds."),
		comment("A malicious peer proposing an enormous delay can lock up your"),
		comment("funds for months after a force close. Default: 2016."),
		comment("bitcoin.maxlocaldelay=2016"),
	}}
}

func channelSection(opts Options) section {
	lines := []string{
		blank(),
		comment("=== 5. Channel Policy ==="),
		blank(),
		comment("[Active] Minimum channel size (satoshis)."),
		comment("Dust-sized channels cost very little to open but have negligible"),
		comment("economic value — they can be used as a channel-flooding DoS."),
		line("minchansize=20000"),
		blank(),
		comment("[Policy] Maximum channel size (satoshis)."),
		comment("Limits exposure from any single channel. 16777215 = ~0.17 BTC"),
		comment("(protocol default). Adjust based on your risk tolerance."),
		comment("Ref: Bitfinex breach — concentrated channel exposure amplified losses."),
		comment("maxchansize=16777215"),
		blank(),
		comment("[Policy] Limit pending (unconfirmed) channels. Default: 1."),
		comment("maxpendingchannels=1"),
		blank(),
		comment("[Active] Maximum concurrent HTLCs the remote party can add."),
		comment("The protocol maximum (483) means an adversary can pin 483 dust"),
		comment("HTLCs on every channel, exhausting commitment space and blocking"),
		comment("legitimate payments. 30 is a reasonable balance."),
		line("default-remote-max-htlcs=30"),
		blank(),
		comment("[Active] Maximum CLTV expiry for forwarded payments (blocks)."),
		comment("A large value allows routing attacks where HTLCs lock funds for"),
		comment("weeks. Default: 2016 blocks (~2 weeks)."),
		line("max-cltv-expiry=2016"),
		blank(),
		comment("[Active] Fee exposure limit from dust HTLCs (satoshis)."),
		comment("Limits how much fee exposure dust HTLC storms can dump onto a"),
		comment("channel. Too low may cause force-closes on busy channels."),
		line("channel-max-fee-exposure=500000"),
		blank(),
		comment("[Active] Do not allow HTLCs that arrive and depart on the same"),
		comment("channel. Enabling this allows balance-probing and fee-extraction"),
		comment("attacks."),
		comment("allow-circular-route is false by default — do not set it to true."),
		blank(),
		comment("[Active] Negotiate cooperative-close payout script at open time."),
		comment("Prevents a peer from redirecting cooperative-close funds to an"),
		comment("unexpected address via social engineering."),
		line("enable-upfront-shutdown=true"),
	}

	if opts.Profile == ProfilePrivate {
		lines = append(lines,
			blank(),
			comment("[Active] Private node — reject all forwarded HTLCs."),
			comment("This node only sends/receives, it does not route for others."),
			comment("Reduces information leakage and forwarding-related attack surface."),
			line("rejecthtlc=true"),
		)
	}

	lines = append(lines,
		blank(),
		comment("[Active] Reject channels with a non-zero push amount."),
		comment("Push-amount channels enable pinning/griefing attacks and are"),
		comment("considered suspicious on production nodes."),
		line("rejectpush=true"),
	)

	return section{lines: lines}
}

func protocolSection(opts Options) section {
	lines := []string{
		blank(),
		line("[protocol]"),
		blank(),
		comment("=== 6. Protocol Security ==="),
		blank(),
		comment("[Active] Enable SCID aliases so that channel UTXOs are not"),
		comment("publicly linked to your node identity through gossip."),
		comment("Without this, anyone can see your on-chain funding transactions."),
		line("protocol.option-scid-alias=true"),
		blank(),
		comment("[Active] Enable anchor outputs for more reliable fee bumping"),
		comment("on force-close transactions."),
		line("protocol.anchors=true"),
		blank(),
		comment("[Warning] Do not enable protocol.zero-conf unless you explicitly"),
		comment("trust the channel counterparty. Zero-conf channels are active"),
		comment("before they have any on-chain confirmations — the opener can"),
		comment("double-spend the funding transaction and steal all channel funds."),
		blank(),
		comment("[Warning] Do not set protocol.no-anchors=true. Anchor channels"),
		comment("enable fee-bumping of commitment transactions. Disabling them"),
		comment("means your node relies on pre-committed fee rates, increasing"),
		comment("force-close risk during fee spikes."),
	}

	if opts.Profile == ProfilePrivate {
		lines = append(lines,
			blank(),
			comment("[Policy] Consider disabling onion message relay for private nodes."),
			comment("Reduces the DoS attack surface from onion message spam."),
			comment("protocol.no-onion-messages=true"),
		)
	}

	lines = append(lines,
		blank(),
		comment("[Warning] Do not enable protocol.wumbo-channels unless you"),
		comment("understand the risk. Wumbo channels (>0.16 BTC) increase the"),
		comment("blast radius of a breach or force-close."),
	)

	return section{lines: lines}
}

func gossipSection() section {
	return section{lines: []string{
		blank(),
		comment("=== 7. Gossip Rate Limiting ==="),
		blank(),
		comment("[Active] Ban score threshold for misbehaving gossip peers."),
		comment("Setting to 0 disables banning entirely, allowing unlimited"),
		comment("malicious gossip from any peer. Default: 100."),
		line("gossip.ban-threshold=100"),
		blank(),
		comment("[Active] Maximum channel update messages per peer per interval."),
		comment("Without this, a single peer can flood the node with fake channel"),
		comment("updates, consuming CPU and memory."),
		line("gossip.max-channel-update-burst=10"),
		line("gossip.channel-update-interval=1m0s"),
		blank(),
		comment("[Active] Global and per-peer outbound gossip bandwidth caps."),
		comment("Prevent a gossip flood from exhausting the node's uplink."),
		line("gossip.msg-rate-bytes=1024000"),
		line("gossip.msg-burst-bytes=2048000"),
		line("gossip.peer-msg-rate-bytes=51200"),
		blank(),
		comment("[Active] Confirmations required before processing channel"),
		comment("announcements. Lowering this increases the risk of processing"),
		comment("announcements for reorged-away channels. Minimum enforced: 3."),
		line("gossip.announcement-conf=6"),
		blank(),
		comment("[Policy] Number of peers to sync the graph from."),
		comment("Too low (1) = eclipse attack risk. Too high = bandwidth-intensive."),
		comment("Default: 3."),
		comment("numgraphsyncpeers=3"),
	}}
}

func paymentSection(opts Options) section {
	lines := []string{
		blank(),
		comment("=== 8. Payment & Invoice Security ==="),
		blank(),
		comment("[Active] Garbage-collect canceled invoices to prevent database"),
		comment("bloat and reduce the data exposed to anyone with DB access."),
		line("gc-canceled-invoices-on-startup=true"),
		line("gc-canceled-invoices-on-the-fly=true"),
	}

	if opts.Profile == ProfilePrivate {
		lines = append(lines,
			blank(),
			comment("[Policy] Private nodes may want to disable keysend and AMP."),
			comment("These allow any node on the network to push unsolicited payments"),
			comment("(and attached data) to this node without prior invoice exchange."),
			comment("accept-keysend=false"),
			comment("accept-amp=false"),
		)
	} else {
		lines = append(lines,
			blank(),
			comment("[Policy] Keysend and AMP accept spontaneous payments."),
			comment("Useful for routing nodes and tipping, but allows any node to"),
			comment("push payments and probe your balance via repeated small amounts."),
			comment("Enable only if your use case requires it."),
			comment("accept-keysend=false"),
			comment("accept-amp=false"),
		)
	}

	lines = append(lines,
		blank(),
		comment("[Warning] Do not set requireinterceptor=true unless you have a"),
		comment("reliable, always-on interceptor process. If the interceptor crashes"),
		comment("or fails to register, ALL HTLCs (incoming and forwarded) are held"),
		comment("indefinitely — total payment DoS."),
	)

	return section{lines: lines}
}

func healthCheckSection(opts Options) section {
	lines := []string{
		blank(),
		comment("=== 9. Health Checks ==="),
		comment("Most health checks are DISABLED by default (0 attempts)."),
		comment("A disabled health check means LND silently continues running in"),
		comment("a degraded state (disk full, expired cert, Tor down) rather than"),
		comment("shutting down gracefully."),
		blank(),
		comment("[Active] Disk space monitoring."),
		comment("If disk fills up, LND cannot write channel backups, commit DB"),
		comment("transactions, or persist HTLC states. Data loss results."),
		line("healthcheck.diskspace.attempts=2"),
		line("healthcheck.diskspace.timeout=5s"),
		line("healthcheck.diskspace.backoff=1m0s"),
		line("healthcheck.diskspace.interval=6h0m0s"),
		line("healthcheck.diskspace.diskrequired=0.1"),
		blank(),
		comment("[Active] TLS certificate monitoring."),
		comment("If the TLS cert expires, all gRPC/REST connections fail and"),
		comment("the node becomes unmanageable."),
		line("healthcheck.tls.attempts=2"),
		line("healthcheck.tls.timeout=5s"),
		line("healthcheck.tls.backoff=1m0s"),
		line("healthcheck.tls.interval=1m0s"),
		blank(),
		comment("[Active] Chain backend monitoring."),
		comment("If the chain backend fails, the node operates with stale chain"),
		comment("data, missing force-close events and HTLC expirations."),
		line("healthcheck.chainbackend.attempts=3"),
		line("healthcheck.chainbackend.timeout=5s"),
		line("healthcheck.chainbackend.backoff=30s"),
		line("healthcheck.chainbackend.interval=1m0s"),
	}

	if opts.Tor {
		lines = append(lines,
			blank(),
			comment("[Active] Tor connection monitoring."),
			comment("If Tor goes down while tor.active=true, the node continues"),
			comment("thinking it is connected but cannot receive inbound connections"),
			comment("or relay through Tor — silently deanonymized or unreachable."),
			line("healthcheck.torconnection.attempts=2"),
			line("healthcheck.torconnection.timeout=5s"),
			line("healthcheck.torconnection.backoff=1m0s"),
			line("healthcheck.torconnection.interval=1m0s"),
		)
	}

	return section{lines: lines}
}

func autopilotSection() section {
	return section{lines: []string{
		blank(),
		comment("=== 12a. Autopilot ==="),
		blank(),
		comment("[Warning] Do NOT enable autopilot on production routing nodes."),
		comment("Autopilot autonomously opens channels without operator intervention,"),
		comment("trusting graph data from peers to pick targets. A Sybil attacker"),
		comment("flooding the graph with fake nodes can attract autopilot to open"),
		comment("channels with adversarial nodes."),
		comment(""),
		comment("If you must use autopilot, limit allocation and set a minimum"),
		comment("channel size to reduce dust channel flooding:"),
		comment("autopilot.active=false"),
		comment("autopilot.allocation=0.3"),
		comment("autopilot.minchansize=100000"),
		comment("autopilot.maxchannels=3"),
		comment("autopilot.minconfs=3"),
	}}
}

func debugSection() section {
	return section{lines: []string{
		blank(),
		comment("=== 12b. Debug / Profiling ==="),
		blank(),
		comment("[Warning] NEVER enable pprof on production nodes."),
		comment("If set, it exposes a Go profiling HTTP endpoint. If bound to"),
		comment("0.0.0.0, any internet host can dump goroutine stacks, heap"),
		comment("profiles, and memory maps — leaking sensitive channel state,"),
		comment("payment in-flight data, and private key usage patterns."),
		comment("pprof.profile is disabled by default — do not set it."),
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

func checklistSection() section {
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
