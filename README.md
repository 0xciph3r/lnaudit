# ⚡ lnaudit

[![CI](https://github.com/NonsoAmadi10/lnaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/NonsoAmadi10/lnaudit/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/NonsoAmadi10/lnaudit)](https://goreportcard.com/report/github.com/NonsoAmadi10/lnaudit)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/NonsoAmadi10/lnaudit)](https://github.com/NonsoAmadi10/lnaudit/releases)

A security scanner for Lightning Network Daemon (LND) nodes. Audits your node's configuration, file permissions, network exposure, and live runtime state, then tells you exactly what to fix.

Built for anyone running LND in production: solo operators, routing nodes, exchanges, and custodians.

📖 **[Documentation](https://nonsoamadi10.github.io/lnaudit/)** · 🐛 [Report Bug](https://github.com/NonsoAmadi10/lnaudit/issues/new?template=bug_report.md) · 💡 [Request Feature](https://github.com/NonsoAmadi10/lnaudit/issues/new?template=feature_request.md)

## Why

Running LND with default settings leaves security gaps: overly permissive file permissions, weak TLS certificates, disabled macaroon authentication, missing watchtower configurations, and gossip settings that leak your IP address.

Most operators don't know these gaps exist until it's too late. This tool was built after studying [10 real-world Bitcoin infrastructure hacks](docs/POST-MORTEM.md) that collectively lost billions. Every check traces back to a real incident.

## Installation

### Prerequisites

- **Go 1.23+** ([install Go](https://go.dev/doc/install))
- **LND node** with access to its configuration directory (a running node is not required for config scanning)

### From source (recommended)

```bash
go install github.com/NonsoAmadi10/lnaudit@latest
```

### From release binaries

Download the latest binary for your platform from [Releases](https://github.com/NonsoAmadi10/lnaudit/releases):

```bash
# Linux (amd64)
curl -LO https://github.com/NonsoAmadi10/lnaudit/releases/latest/download/lnaudit-linux-amd64
chmod +x lnaudit-linux-amd64
sudo mv lnaudit-linux-amd64 /usr/local/bin/lnaudit

# macOS (Apple Silicon)
curl -LO https://github.com/NonsoAmadi10/lnaudit/releases/latest/download/lnaudit-darwin-arm64
chmod +x lnaudit-darwin-arm64
sudo mv lnaudit-darwin-arm64 /usr/local/bin/lnaudit
```

### Build from source

```bash
git clone https://github.com/NonsoAmadi10/lnaudit.git
cd lnaudit
make build
./bin/lnaudit version
```

## Quick Start

```bash
# Config-only scan (no running node needed)
lnaudit scan

# Specify config path explicitly
lnaudit scan --config ~/.lnd/lnd.conf

# Live scan against a running LND node via gRPC
lnaudit scan --connect localhost:10009

# Live scan with explicit credential paths
lnaudit scan --connect localhost:10009 \
  --tlscert ~/.lnd/tls.cert \
  --macaroon ~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon

# JSON output for scripting / CI
lnaudit scan --format json

# Only show HIGH and CRITICAL findings
lnaudit scan --min-severity high

# Exit with code 1 if any HIGH+ finding exists (for CI/CD)
lnaudit scan --fail-on high
```

## What It Checks

| Module | Checks | Examples |
|--------|--------|----------|
| **Transport** | TLS certificate audit, RPC bind exposure, IP leak detection | Expired/weak TLS certs, RPC bound to 0.0.0.0, clearnet IP leaked with Tor |
| **Key Management** | File permissions on wallet.db, tls.key, macaroons, channel.backup | World-readable wallet, symlinked sensitive files |
| **Access Control** | Macaroon authentication, stray macaroon detection, dangerous flags | `--noseedbackup`, `--noencryptwallet`, `debuglevel=trace` |
| **Network Privacy** | Tor configuration, SCID alias, proxy settings | Missing stream isolation, V2 onion (deprecated), unencrypted onion key |
| **Channel Safety** | Watchtower config, confirmation depth, channel limits | No watchtower, low confirmation targets, excessive max channel size |
| **Network Exposure** | P2P listener binding, NAT/UPnP, gRPC/REST non-loopback | Listen on all interfaces, UPnP auto port-forwarding |
| **Port Scanning** | Probes known LND and Bitcoin ports for unexpected exposure | gRPC/REST open, Bitcoin Core RPC reachable |
| **Live Checks** | Version vs known CVEs, chain sync, peer count, force-close, balance | Running a CVE-affected version, unsynced node, zero peers |

## Example Output

```
⚡ lnaudit v0.1.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  🔴 CRITICAL  wallet.db has permissions 0644 (too permissive)
               → chmod 0600 /home/user/.lnd/data/chain/bitcoin/mainnet/wallet.db

  🔴 CRITICAL  noseedbackup is enabled, seed is never persisted
               → Remove noseedbackup from lnd.conf

  🟡 HIGH      No watchtower client configured
               → Add [wtclient] section with at least one tower URI

  🟡 HIGH      RPC listener bound to all interfaces
               → Bind rpclisten to 127.0.0.1:10009

  🟡 MEDIUM    Tor onion key is not encrypted on disk
               → Set tor.encryptkey=true in lnd.conf

  🔵 LOW       unsafe-disconnect is enabled
               → Remove unsafe-disconnect from lnd.conf

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Score: 38/100  Critical Risk
  2 critical · 2 high · 1 medium · 1 low
```

## CLI Reference

```
Usage:
  lnaudit scan [flags]

Flags:
      --config string         path to lnd.conf (auto-detected if not set)
      --lnddir string         LND data directory (auto-detected if not set)
      --connect string        gRPC address of running LND node (e.g., localhost:10009)
      --macaroon string       path to admin.macaroon (auto-detected from lnddir)
      --tlscert string        path to tls.cert for gRPC (auto-detected from lnddir)
      --format string         output format: table, json (default "table")
      --min-severity string   minimum severity to display (default "low")
      --fail-on string        exit 1 if findings at or above this severity (default "critical")
      --verbose               show INFO-level findings
      --no-color              disable colored output
      --quiet                 only output the score
```

When `--connect` is provided, the scanner runs both config checks (if `lnd.conf` is available) and live checks via gRPC. Config is optional in live-only mode.

## Architecture

```
lnaudit/
├── cmd/                    # CLI commands (scan, version)
├── pkg/
│   ├── scanner/            # Core engine: Finding, Severity, Report, scoring
│   ├── checks/             # Security check implementations
│   │   ├── permissions.go  # File permission auditing, symlink detection
│   │   ├── transport.go    # TLS, RPC bind, IP exposure
│   │   ├── exposure.go     # P2P listener, NAT/UPnP, network exposure
│   │   ├── access.go       # Macaroons, dangerous flags
│   │   ├── privacy.go      # Tor, SCID alias, channel safety
│   │   ├── live.go         # Live checks: version, sync, peers, balance
│   │   ├── cves.go         # Known CVE database for LND versions
│   │   └── ports.go        # Open port scanning
│   ├── grpc/               # gRPC client interface and connection
│   │   ├── client.go       # LndClient interface and response types
│   │   ├── connect.go      # TLS + macaroon auth, real implementation
│   │   └── mock.go         # MockClient for unit testing
│   ├── config/             # lnd.conf parser (INI format)
│   ├── lndpath/            # Auto-detection of LND paths
│   └── report/             # Output formatters (table, JSON)
├── docs/                   # Documentation and post-mortem research
├── Makefile                # Build, test, lint, release targets
└── .github/                # CI workflows, issue/PR templates
```

## Scoring

Each finding deducts points from a starting score of 100:

| Severity | Deduction | Meaning |
|----------|-----------|---------|
| CRITICAL | -15 | Direct fund loss risk or key exposure |
| HIGH | -10 | Significant security weakness |
| MEDIUM | -5 | Suboptimal configuration |
| LOW | -2 | Minor hardening opportunity |
| INFO | 0 | Informational |

| Score | Rating |
|-------|--------|
| 90–100 | ✅ Hardened |
| 70–89 | 🟢 Acceptable |
| 40–69 | 🟡 Needs Hardening |
| 0–39 | 🔴 Critical Risk |

## Roadmap

- [x] Config-based scanning (no running node needed)
- [x] File permission auditing with symlink detection
- [x] TLS certificate analysis
- [x] Dangerous flag detection
- [x] Tor and privacy configuration audit
- [x] Scoring engine with severity-based ratings
- [x] Network exposure and open port scanning
- [x] Live node scanning via gRPC (version/CVE, sync, peers, balance, force-close)
- [ ] Confidence levels on findings (Certain, Firm, Tentative)
- [ ] SARIF output for GitHub Code Scanning and CI/CD pipelines
- [ ] Severity threshold gating (`--fail-on high`)
- [ ] Baseline diffing (compare scans, report only new findings)
- [ ] Standalone HTML report generation
- [ ] Macaroon permission auditing (detect overly permissive credentials)
- [ ] TLS cipher and protocol version probing
- [ ] Backup safety validation (freshness, existence, encryption status)
- [ ] Scan profiles (`--profile quick|full|compliance`)
- [ ] Custom check definitions via YAML policy files
- [ ] Docker security checks (root user, privileged mode, secret handling, volume permissions)
- [ ] Kubernetes security checks (NetworkPolicy, RBAC, secret mounts, pod security context)
- [ ] Homebrew / Docker distribution
- [ ] Fleet scanning (multiple nodes)
- [ ] Plugin system for community-contributed checks

## Related

- [LND Deep Dive](https://nonsoamadi10.github.io/lnd-deep-dive/) - The security research behind this tool
- [Post-Mortem Analysis](docs/POST-MORTEM.md) - 10 Bitcoin infrastructure hacks that motivated this project
- [LND](https://github.com/lightningnetwork/lnd) - The Lightning Network Daemon

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before getting started.

- 🐛 [Report a bug](https://github.com/NonsoAmadi10/lnaudit/issues/new?template=bug_report.md)
- 💡 [Request a feature](https://github.com/NonsoAmadi10/lnaudit/issues/new?template=feature_request.md)
- 🔒 [Report a security vulnerability](SECURITY.md)

## License

[MIT](LICENSE)
