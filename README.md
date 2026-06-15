# lnaudit

[![CI](https://github.com/0xciph3r/lnaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/0xciph3r/lnaudit/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/0xciph3r/lnaudit)](https://goreportcard.com/report/github.com/0xciph3r/lnaudit)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/0xciph3r/lnaudit)](https://github.com/0xciph3r/lnaudit/releases)

**A security auditing framework for Lightning Network infrastructure**

lnaudit is an open-source security scanner for Lightning Network Daemon (LND) nodes. It provides comprehensive auditing of node configuration, file permissions, TLS certificates, macaroon credentials, network exposure, and live runtime state to identify misconfigurations before they lead to fund loss.

Built for production Lightning infrastructure: routing nodes, exchanges, payment processors, and custodians.

**[Documentation](https://0xciph3r.github.io/lnaudit/)** · [Report Bug](https://github.com/0xciph3r/lnaudit/issues/new?template=bug_report.md) · [Request Feature](https://github.com/0xciph3r/lnaudit/issues/new?template=feature_request.md)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Example Output](#example-output)
- [Hardened Config Generator](#hardened-config-generator)
- [Security Modules](#security-modules)
- [Scoring Methodology](#scoring-methodology)
- [CI/CD Integration](#cicd-integration)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

---

## Overview

Lightning Network nodes represent hot financial infrastructure that must remain online, networked, and capable of signing transactions in real-time. This operational model introduces a unique threat landscape distinct from cold storage Bitcoin custody.

Most catastrophic losses in Bitcoin infrastructure have resulted not from cryptographic breaks, but from operational failures: weak file permissions, credential leaks, exposed APIs, and configuration drift. lnaudit addresses this gap by encoding operational security best practices into automated, repeatable checks.

### Why lnaudit?

- **Evidence-based security**: Every check traces back to real-world incidents. Our [post-mortem analysis](docs/POST-MORTEM.md) of 10 major Bitcoin infrastructure breaches ($3.6B+ in losses) informed the design of every module.
- **Pre-deployment validation**: Scan configuration files before deployment. Catch misconfigurations in CI/CD pipelines before nodes ever start.
- **Zero runtime dependency**: Config scanning requires no running node. Live checks use read-only gRPC APIs with standard TLS and macaroon authentication.
- **Quantified risk**: Severity-weighted scoring provides a single metric to track security posture over time.
- **Actionable output**: Each finding includes specific remediation guidance.

---

## Features

- **Static configuration analysis**: Parse and audit `lnd.conf` without a running node, including TLS, RPC/REST, macaroons, Tor, channel policy, autopilot, gossip, payment, and protocol hardening
- **Live runtime checks**: Connect via gRPC to audit version, sync state, peer count, force-close state, balance exposure, pending HTLC pressure, zero-conf channels, and negotiated HTLC limits
- **Actionable remediation**: Every finding includes a description, a specific recommendation, and a reference to the real-world incident that motivated the check
- **Hardened config generator**: Generate a security-hardened `lnd.conf` template with comments explaining every setting and its threat model context
- **Interactive scan experience**: Bubble Tea-powered spinner and progress tracking during scans with TTY detection for CI compatibility
- **File permission auditing**: Detect world-readable wallets, credentials, and TLS private keys
- **Symlink attack detection**: Identify symbolic links to sensitive files that bypass permission checks
- **TLS certificate validation**: Check expiration, key strength, and self-signed status
- **Network exposure analysis**: Detect binds to `0.0.0.0`, UPnP, and non-loopback listeners
- **Privacy leak detection**: Audit Tor configuration, SCID aliases, and clearnet IP disclosure
- **Channel-jamming awareness**: Detect risky HTLC limits in configuration and live channels with abnormal pending HTLC counts
- **Protocol risk detection**: Flag zero-conf, no-anchor, wumbo, circular routing, weak timelocks, and unsafe fee-estimation choices
- **CVE mapping**: Cross-reference running LND version against known vulnerabilities
- **Port scanning**: Probe common Bitcoin and LND ports for unexpected exposure
- **Multiple output formats**: Human-readable reports for operators and JSON for automation
- **CI/CD gates**: Exit with non-zero status on high-severity findings

---

## Installation

### From Source (Recommended)

Due to Go module replace directives required by LND dependencies, installation from source is the recommended method:

```bash
git clone https://github.com/0xciph3r/lnaudit.git
cd lnaudit
make build
sudo mv bin/lnaudit /usr/local/bin/
lnaudit version
```

### From Release Binaries

Download the latest release for your platform:

```bash
# Linux (amd64)
curl -LO https://github.com/0xciph3r/lnaudit/releases/latest/download/lnaudit-linux-amd64
chmod +x lnaudit-linux-amd64
sudo mv lnaudit-linux-amd64 /usr/local/bin/lnaudit

# macOS (Apple Silicon)
curl -LO https://github.com/0xciph3r/lnaudit/releases/latest/download/lnaudit-darwin-arm64
chmod +x lnaudit-darwin-arm64
sudo mv lnaudit-darwin-arm64 /usr/local/bin/lnaudit

# macOS (Intel)
curl -LO https://github.com/0xciph3r/lnaudit/releases/latest/download/lnaudit-darwin-amd64
chmod +x lnaudit-darwin-amd64
sudo mv lnaudit-darwin-amd64 /usr/local/bin/lnaudit
```

### Prerequisites

- **Go 1.23+** (for building from source)
- **LND node** with access to configuration directory (running node optional for config-only scans)

---

## Quick Start

### Configuration-Only Scan

Scan your `lnd.conf` before deployment (no running node required):

```bash
# Auto-detect config location
lnaudit scan

# Explicit config path
lnaudit scan --config ~/.lnd/lnd.conf

# Specify LND data directory
lnaudit scan --lnddir /mnt/lnd
```

### Live Node Scan

Connect to a running node via gRPC for runtime checks:

```bash
# Auto-detect credentials
lnaudit scan --connect localhost:10009

# Explicit credential paths
lnaudit scan --connect localhost:10009 \
  --tlscert ~/.lnd/tls.cert \
  --macaroon ~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon
```

### Combined Scan

Run both config and live checks:

```bash
lnaudit scan --config ~/.lnd/lnd.conf --connect localhost:10009
```

### What Each Scan Mode Covers

| Mode | Source | Checks |
|------|--------|--------|
| Static | `lnd.conf`, data directory, local filesystem | RPC/REST binding, TLS hardening, macaroon auth, wallet creation safety, Tor privacy, watchtower config, channel policy, Bitcoin policy, payment settings, protocol flags, autopilot, gossip banning, file permissions |
| Live | gRPC read-only APIs | LND version vs CVEs, chain and graph sync, peer count, force-close state, balance exposure, active zero-conf channels, high pending HTLC counts, negotiated remote HTLC limits |
| Active network | Local port probing | Unexpected exposure on common LND and Bitcoin service ports |

### CI/CD Integration

Fail builds on high-severity findings:

```bash
# Exit code 1 if HIGH or CRITICAL findings exist
lnaudit scan --fail-on high --format json > audit.json

# Filter output by severity
lnaudit scan --min-severity high

# Quiet mode (only show score)
lnaudit scan --quiet
```

### Generate Hardened Config

```bash
# Generate a security-hardened lnd.conf to stdout
lnaudit generate

# Generate for a private wallet node
lnaudit generate --profile private

# Generate for a public routing node
lnaudit generate --profile routing

# Write to file with Tor enabled
lnaudit generate --tor --output lnd.conf
```

---

## Example Output

Each finding includes a severity rating, description explaining the risk, a specific recommendation, and a reference to the real-world incident that motivated the check:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 lnaudit — Security Audit Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 ■ Transport Security
 ────────────────────────────────────────────────────────────

  CRITICAL  gRPC bound to all interfaces: 0.0.0.0:10009
      The gRPC control plane is exposed to all network
      interfaces, including the public internet.

      Recommendation:
        Change rpclisten to 127.0.0.1:10009 in lnd.conf
      Ref: POST-MORTEM.md#6-nicehash-2017

  CRITICAL  REST API bound to all interfaces: 0.0.0.0:8080
      The REST API is exposed to all network interfaces.

      Recommendation:
        Change restlisten to 127.0.0.1:8080 in lnd.conf

 ■ Key Management
 ────────────────────────────────────────────────────────────

  CRITICAL  Tor onion private key is NOT encrypted on disk
      The onion service private key is stored in plaintext.
      A server compromise would expose your hidden service
      identity.

      Recommendation:
        Set tor.encryptkey=true in lnd.conf and restart LND.
      Ref: POST-MORTEM.md#2-bitcoinica--linode-2012

 ■ Access Control
 ────────────────────────────────────────────────────────────

  CRITICAL  Macaroon authentication is DISABLED
      The --no-macaroons flag is set, meaning anyone who can
      reach your gRPC/REST interface has full admin access
      with no authentication.

      Recommendation:
        Remove no-macaroons=true from lnd.conf and restart
        LND.
      Ref: POST-MORTEM.md#6-nicehash-2017

 ■ Network Privacy
 ────────────────────────────────────────────────────────────

  MEDIUM    Tor stream isolation is disabled
      Without stream isolation, all peer connections may
      share the same Tor circuit. An adversary controlling a
      Tor exit/relay could correlate your connections.

      Recommendation:
        Set tor.streamisolation=true in lnd.conf

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Score: 0/100  Critical Risk
 7 critical · 5 high · 3 medium · 2 low · 0 info
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Hardened Config Generator

Generate a security-hardened `lnd.conf` template with `lnaudit generate`. Every setting includes comments explaining **why** it matters, with references to the real-world incidents that motivated it.

```bash
# Print to stdout
lnaudit generate

# Generate profile-specific templates
lnaudit generate --profile routing
lnaudit generate --profile private

# Write to file (created with 0600 permissions)
lnaudit generate --output hardened.conf

# Include Tor configuration
lnaudit generate --tor

# Target a specific network
lnaudit generate --network testnet

# Include watchtower URI
lnaudit generate --watchtower "03abc...@tower.example.com:9911"

# Set node alias
lnaudit generate --alias "my-routing-node"

# Combine flags
lnaudit generate --profile routing --tor --watchtower "03abc...@host:9911" --output lnd.conf
```

Profiles control whether the template is optimized for a public routing node or a private wallet node:

| Profile | Use case | Behavior |
|---------|----------|----------|
| `routing` | Public Lightning routing node | Keeps routing functionality enabled while hardening RPC, TLS, Tor, gossip, channel policy, watchtower, and fee-safety settings |
| `private` | Wallet/private node that primarily sends and receives | Adds more restrictive defaults such as disabling inbound P2P and rejecting forwarded HTLCs |

### Example Output

```ini
# ============================================================
# lnaudit — Hardened LND Configuration
# Generated: 2026-06-02
# Network:   mainnet
# Profile:   routing node
#
# Settings are categorized as:
#   [Active]  — Recommended hardening, emitted as key=value
#   [Policy]  — Operational choice, commented for review
#   [Warning] — Dangerous flag, never enable in production
# ============================================================

[Application Options]

# Bind control interfaces to localhost ONLY.
# Ref: NiceHash breach — exposed management interface led to $64M loss.
rpclisten=127.0.0.1:10009
restlisten=127.0.0.1:8080

# Use 'info' level in production. Debug/trace logging can write
# payment preimages, macaroon data, and peer details to log files.
debuglevel=info

# Encrypt the TLS private key on disk.
tlsencryptkey=true

# Prevent Slowloris-style REST header attacks.
http-header-timeout=5s

[Bitcoin]

bitcoin.active=true
bitcoin.mainnet=true
bitcoin.defaultchanconfs=3
bitcoin.estimatemode=CONSERVATIVE
bitcoin.timelockdelta=80
bitcoin.minhtlc=1000

[protocol]

protocol.option-scid-alias=true
protocol.anchors=true

# Do not enable protocol.zero-conf unless all counterparties are trusted.

[tor]

# Route all LND traffic through Tor to hide your node's IP address.
tor.active=true
tor.v3=true
tor.streamisolation=true
tor.encryptkey=true

[wtclient]

# A watchtower monitors your channels while your node is offline.
# Ref: Bitfinex breach — unmonitored channels exploited.
wtclient.active=true
```

The generated config also includes a **post-generation checklist** for security measures that cannot be set in `lnd.conf`: file permissions, TLS rotation, macaroon hygiene, firewall rules, and chain backend configuration.

---

## Security Modules

lnaudit performs 60+ security checks across static configuration, filesystem, network exposure, and live gRPC runtime state:

| Module | Checks | Key Threats Mitigated |
|--------|--------|----------------------|
| **Transport Security** | TLS certificate validation, encrypted TLS key checks, REST TLS checks, RPC/REST binding audit, HTTP header timeout review | Expired certificates, weak crypto, plaintext REST, API exposure, Slowloris-style REST attacks |
| **Key Management** | File permission auditing on wallet.db, TLS keys, macaroons, channel backups | World-readable credentials, key leaks |
| **Access Control** | Macaroon authentication status, stray macaroon detection, wallet unlock safety, REST CORS, dangerous flags | Disabled auth (`--no-macaroons`), seed injection, browser-origin RPC attacks, debug logging with secrets |
| **Network Privacy** | Tor configuration, stream isolation, SCID aliases, onion key encryption | IP address leaks, V2 onion deprecation, clearnet fallback |
| **Channel Safety** | Watchtower configuration, confirmation depth, channel limits, force-close detection, pending HTLC pressure | Unmonitored channels, low confirmation targets, channel jamming, stuck HTLCs |
| **Policy** | Circular routing, push-amount channels, HTLC limits, CLTV expiry, timelock delta, minimum HTLC size, fee estimation, autopilot | Balance probing, griefing, channel jamming, liquidity lockup, under-fee'd transactions, autonomous fund deployment |
| **Protocol** | Zero-conf, anchor channels, wumbo channels, SCID aliases | Double-spend risk, weak force-close fee bumping, large-channel blast radius, channel UTXO linkage |
| **Payment Security** | Keysend, AMP, HTLC interceptor, canceled invoice garbage collection | Unsolicited payment spam, balance probing, interceptor-induced payment DoS, invoice database bloat |
| **Gossip Security** | Gossip ban threshold, graph sync settings, gossip rate limiting guidance | Gossip flooding, CPU/memory exhaustion, eclipse risk |
| **Network Exposure** | P2P and RPC listener binding, UPnP, NAT configuration | Bind to 0.0.0.0, automatic port forwarding |
| **Port Scanning** | Active probing of common LND and Bitcoin Core ports | Unexpected service exposure, open gRPC/REST APIs |
| **Live Checks** | Version vs CVE database, chain sync, peer connectivity, force-close state, balance thresholds, zero-conf channels, high pending HTLCs, negotiated HTLC limits | Running vulnerable versions, offline nodes, fund exposure, active channel jamming, unsafe live channel state |

The scanner is intentionally split between static checks that can run before deployment and live checks that require read-only gRPC access to a running node.

---

## Scoring Methodology

Each finding deducts points from a baseline score of 100:

| Severity | Deduction | Definition |
|----------|-----------|------------|
| **CRITICAL** | -15 | Direct fund loss risk or private key exposure |
| **HIGH** | -10 | Significant security weakness enabling attack escalation |
| **MEDIUM** | -5 | Suboptimal configuration increasing attack surface |
| **LOW** | -2 | Minor hardening opportunity |
| **INFO** | 0 | Informational notice |

### Score Interpretation

| Score Range | Rating | Recommendation |
|-------------|--------|----------------|
| 90–100 | Hardened | Production-ready with strong operational security |
| 70–89 | Acceptable | Suitable for production with minor improvements |
| 40–69 | Needs Hardening | Address findings before production deployment |
| 0–39 | Critical Risk | Immediate remediation required |

Severity levels are calibrated against real-world incidents documented in [docs/POST-MORTEM.md](docs/POST-MORTEM.md).

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  lnaudit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install lnaudit
        run: |
          curl -LO https://github.com/0xciph3r/lnaudit/releases/latest/download/lnaudit-linux-amd64
          chmod +x lnaudit-linux-amd64
          sudo mv lnaudit-linux-amd64 /usr/local/bin/lnaudit
      
      - name: Audit LND Configuration
        run: lnaudit scan --config config/lnd.conf --fail-on high --format json
```

### GitLab CI

```yaml
lnaudit:
  stage: security
  script:
    - curl -LO https://github.com/0xciph3r/lnaudit/releases/latest/download/lnaudit-linux-amd64
    - chmod +x lnaudit-linux-amd64
    - ./lnaudit-linux-amd64 scan --config lnd.conf --fail-on high
  only:
    - merge_requests
    - main
```

### Pre-Commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

if git diff --cached --name-only | grep -q "lnd.conf"; then
    echo "Auditing LND configuration..."
    lnaudit scan --config lnd.conf --min-severity high
    if [ $? -ne 0 ]; then
        echo "Security audit failed. Fix findings or use --no-verify to skip."
        exit 1
    fi
fi
```

---

## Architecture

```
lnaudit/
├── cmd/                        # CLI entry points
│   ├── scan.go                 # scan command orchestration
│   ├── generate.go             # hardened lnd.conf generator
│   └── spinner.go              # Bubble Tea scan progress UI
├── pkg/
│   ├── scanner/               # Core scanning engine
│   │   └── scanner.go         # Finding type, aggregation, and scoring
│   ├── checks/                # Security check implementations
│   │   ├── permissions.go     # File permission auditing
│   │   ├── transport.go       # TLS and RPC security
│   │   ├── exposure.go        # Network exposure analysis
│   │   ├── access.go          # Access control and auth checks
│   │   ├── privacy.go         # Tor and privacy auditing
│   │   ├── policy.go          # Channel, Bitcoin, payment policy checks
│   │   ├── resilience.go      # Protocol, autopilot, gossip, TLS hardening checks
│   │   ├── live.go            # Live node checks via gRPC
│   │   ├── live_extended.go   # Live channel jamming and zero-conf checks
│   │   ├── cves.go            # CVE database and version mapping
│   │   └── ports.go           # Port scanning
│   ├── confgen/               # Hardened lnd.conf generation
│   ├── grpc/                  # gRPC client interface
│   │   ├── client.go          # LndClient interface
│   │   ├── connect.go         # Real gRPC client implementation
│   │   └── mock.go            # Mock client for testing
│   ├── config/                # LND configuration parser
│   ├── lndpath/               # Path detection utilities
│   └── report/                # Output formatters (table, JSON)
├── docs/
│   └── POST-MORTEM.md         # Analysis of real-world incidents
├── .github/
│   ├── workflows/             # CI/CD pipelines
│   ├── ISSUE_TEMPLATE/        # Issue templates
│   └── PULL_REQUEST_TEMPLATE.md
└── Makefile                   # Build automation
```

---

## Contributing

lnaudit is open-source software released under the MIT License. Contributions are welcome and encouraged.

### How to Contribute

1. **Report Issues**: [Open an issue](https://github.com/0xciph3r/lnaudit/issues/new) for bugs or feature requests
2. **Submit Pull Requests**: See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines
3. **Improve Documentation**: Help refine docs, add examples, or clarify usage
4. **Add Security Checks**: Propose new checks based on real-world incidents or CVEs

### Development Setup

```bash
# Clone repository
git clone https://github.com/0xciph3r/lnaudit.git
cd lnaudit

# Install dependencies
go mod download

# Run tests
make test

# Run linter
make lint

# Build binary
make build
```

### Testing

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run specific test
go test -v ./pkg/checks -run TestPermissions
```

---

## Security

### Reporting Vulnerabilities

If you discover a security vulnerability in lnaudit, please report it privately via [SECURITY.md](SECURITY.md).

**Do not open public issues for security vulnerabilities.**

### Security Considerations

- lnaudit performs **read-only** operations. It never modifies configuration files, credentials, or node state.
- Live scans require `admin.macaroon` to access gRPC APIs. Store credentials securely and restrict access.
- Port scanning modules perform active network probing. Ensure firewall rules permit localhost connections.
- Audit logs may contain sensitive information (file paths, network topology). Store reports securely.

---

## License

lnaudit is released under the [MIT License](LICENSE).

```
Copyright (c) 2024 lnaudit contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Acknowledgments

This project was informed by analysis of real-world Bitcoin infrastructure incidents including Mt. Gox, Bitfloor, Bitstamp, NiceHash, and others. We are grateful to the operators and researchers who documented these incidents for the benefit of the broader ecosystem.

Built with:
- [Lightning Network Daemon (LND)](https://github.com/lightningnetwork/lnd)
- [btcsuite](https://github.com/btcsuite)
- [Cobra CLI](https://github.com/spf13/cobra)

---

## Links

- **Website**: [0xciph3r.github.io/lnaudit](https://0xciph3r.github.io/lnaudit/)
- **GitHub**: [github.com/0xciph3r/lnaudit](https://github.com/0xciph3r/lnaudit)
- **Issue Tracker**: [github.com/0xciph3r/lnaudit/issues](https://github.com/0xciph3r/lnaudit/issues)
- **Releases**: [github.com/0xciph3r/lnaudit/releases](https://github.com/0xciph3r/lnaudit/releases)

---

For questions, feedback, or support, please [open an issue](https://github.com/0xciph3r/lnaudit/issues/new) or start a [discussion](https://github.com/0xciph3r/lnaudit/discussions).
