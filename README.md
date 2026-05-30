# lnaudit

[![CI](https://github.com/NonsoAmadi10/lnaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/NonsoAmadi10/lnaudit/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/NonsoAmadi10/lnaudit)](https://goreportcard.com/report/github.com/NonsoAmadi10/lnaudit)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/NonsoAmadi10/lnaudit)](https://github.com/NonsoAmadi10/lnaudit/releases)

**A security auditing framework for Lightning Network infrastructure**

lnaudit is an open-source security scanner for Lightning Network Daemon (LND) nodes. It provides comprehensive auditing of node configuration, file permissions, TLS certificates, macaroon credentials, network exposure, and live runtime state to identify misconfigurations before they lead to fund loss.

Built for production Lightning infrastructure: routing nodes, exchanges, payment processors, and custodians.

**[Documentation](https://nonsoamadi10.github.io/lnaudit/)** · [Report Bug](https://github.com/NonsoAmadi10/lnaudit/issues/new?template=bug_report.md) · [Request Feature](https://github.com/NonsoAmadi10/lnaudit/issues/new?template=feature_request.md)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
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

- **Static configuration analysis**: Parse and audit `lnd.conf` without a running node
- **Live runtime checks**: Connect via gRPC to audit version, sync state, peer count, channel health, and balance exposure
- **File permission auditing**: Detect world-readable wallets, credentials, and TLS private keys
- **Symlink attack detection**: Identify symbolic links to sensitive files that bypass permission checks
- **TLS certificate validation**: Check expiration, key strength, and self-signed status
- **Network exposure analysis**: Detect binds to `0.0.0.0`, UPnP, and non-loopback listeners
- **Privacy leak detection**: Audit Tor configuration, SCID aliases, and clearnet IP disclosure
- **CVE mapping**: Cross-reference running LND version against known vulnerabilities
- **Port scanning**: Probe common Bitcoin and LND ports for unexpected exposure
- **Multiple output formats**: Human-readable tables, JSON for automation, SARIF for GitHub Code Scanning
- **CI/CD gates**: Exit with non-zero status on high-severity findings

---

## Installation

### From Source (Recommended)

Due to Go module replace directives required by LND dependencies, installation from source is the recommended method:

```bash
git clone https://github.com/NonsoAmadi10/lnaudit.git
cd lnaudit
make build
sudo mv bin/lnaudit /usr/local/bin/
lnaudit version
```

### From Release Binaries

Download the latest release for your platform:

```bash
# Linux (amd64)
curl -LO https://github.com/NonsoAmadi10/lnaudit/releases/latest/download/lnaudit-linux-amd64
chmod +x lnaudit-linux-amd64
sudo mv lnaudit-linux-amd64 /usr/local/bin/lnaudit

# macOS (Apple Silicon)
curl -LO https://github.com/NonsoAmadi10/lnaudit/releases/latest/download/lnaudit-darwin-arm64
chmod +x lnaudit-darwin-arm64
sudo mv lnaudit-darwin-arm64 /usr/local/bin/lnaudit

# macOS (Intel)
curl -LO https://github.com/NonsoAmadi10/lnaudit/releases/latest/download/lnaudit-darwin-amd64
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

---

## Security Modules

lnaudit performs 40+ security checks across seven modules:

| Module | Checks | Key Threats Mitigated |
|--------|--------|----------------------|
| **Transport Security** | TLS certificate validation, cipher suite analysis, RPC binding audit | Expired certificates, weak crypto, API exposure |
| **Key Management** | File permission auditing on wallet.db, TLS keys, macaroons, channel backups | World-readable credentials, key leaks |
| **Access Control** | Macaroon authentication status, stray macaroon detection, dangerous flags | Disabled auth (`--no-macaroons`), debug logging with secrets |
| **Network Privacy** | Tor configuration, stream isolation, SCID aliases, onion key encryption | IP address leaks, V2 onion deprecation, clearnet fallback |
| **Channel Safety** | Watchtower configuration, confirmation depth, channel limits, force-close detection | Unmonitored channels, low confirmation targets |
| **Network Exposure** | P2P and RPC listener binding, UPnP, NAT configuration | Bind to 0.0.0.0, automatic port forwarding |
| **Port Scanning** | Active probing of common LND and Bitcoin Core ports | Unexpected service exposure, open gRPC/REST APIs |
| **Live Checks** | Version vs CVE database, chain sync, peer connectivity, balance thresholds | Running vulnerable versions, offline nodes, fund exposure |

For detailed technical specifications, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).

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
          curl -LO https://github.com/NonsoAmadi10/lnaudit/releases/latest/download/lnaudit-linux-amd64
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
    - curl -LO https://github.com/NonsoAmadi10/lnaudit/releases/latest/download/lnaudit-linux-amd64
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
│   └── lnaudit/
│       └── main.go            # Command dispatch (scan, version)
├── pkg/
│   ├── scanner/               # Core scanning engine
│   │   ├── scanner.go         # Finding aggregation and scoring
│   │   ├── finding.go         # Finding type and severity
│   │   └── report.go          # Report generation
│   ├── checks/                # Security check implementations
│   │   ├── permissions.go     # File permission auditing
│   │   ├── transport.go       # TLS and RPC security
│   │   ├── exposure.go        # Network exposure analysis
│   │   ├── access.go          # Access control and auth checks
│   │   ├── privacy.go         # Tor and privacy auditing
│   │   ├── live.go            # Live node checks via gRPC
│   │   ├── cves.go            # CVE database and version mapping
│   │   └── ports.go           # Port scanning
│   ├── grpc/                  # gRPC client interface
│   │   ├── client.go          # LndClient interface
│   │   ├── connect.go         # Real gRPC client implementation
│   │   └── mock.go            # Mock client for testing
│   ├── config/                # LND configuration parser
│   ├── lndpath/               # Path detection utilities
│   └── report/                # Output formatters (table, JSON, SARIF)
├── docs/
│   ├── POST-MORTEM.md         # Analysis of real-world incidents
│   ├── ARCHITECTURE.md        # Technical design documentation
│   └── SECURITY.md            # Security policy and vulnerability reporting
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

1. **Report Issues**: [Open an issue](https://github.com/NonsoAmadi10/lnaudit/issues/new) for bugs or feature requests
2. **Submit Pull Requests**: See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines
3. **Improve Documentation**: Help refine docs, add examples, or clarify usage
4. **Add Security Checks**: Propose new checks based on real-world incidents or CVEs

### Development Setup

```bash
# Clone repository
git clone https://github.com/NonsoAmadi10/lnaudit.git
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

- **Website**: [nonsoamadi10.github.io/lnaudit](https://nonsoamadi10.github.io/lnaudit/)
- **GitHub**: [github.com/NonsoAmadi10/lnaudit](https://github.com/NonsoAmadi10/lnaudit)
- **Issue Tracker**: [github.com/NonsoAmadi10/lnaudit/issues](https://github.com/NonsoAmadi10/lnaudit/issues)
- **Releases**: [github.com/NonsoAmadi10/lnaudit/releases](https://github.com/NonsoAmadi10/lnaudit/releases)

---

For questions, feedback, or support, please [open an issue](https://github.com/NonsoAmadi10/lnaudit/issues/new) or start a [discussion](https://github.com/NonsoAmadi10/lnaudit/discussions).
