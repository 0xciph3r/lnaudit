# ⚡ lnaudit

A security scanner for LND node operators. Audits your Lightning node configuration, identifies misconfigurations, and provides actionable hardening recommendations.

Built for anyone running LND in production — solo operators, routing nodes, exchanges, and custodians.

## Why

Running LND with default settings leaves security gaps: unencrypted keys on disk, weak Tor configurations, missing watchtower setups, overly permissive macaroons, and gossip settings that leak privacy. Most operators don't know these gaps exist until it's too late.

This tool scans your node and tells you exactly what to fix.

## What it checks

| Module | What it scans |
|--------|--------------|
| **Transport** | Brontide TLS config, listener exposure, connection limits |
| **Key Management** | Wallet encryption, seed backup posture, key file permissions |
| **Channel Safety** | Watchtower connectivity, backup freshness, breach protection |
| **Access Control** | Macaroon permissions, RPC exposure, middleware config |
| **Network Privacy** | Tor configuration, IP leak detection, gossip privacy settings |
| **Node Hygiene** | Disk usage, log levels, debug flags in production |

## Quick start

```bash
# Install
go install github.com/NonsoAmadi10/lnaudit@latest

# Scan your node (reads lnd.conf + connects via gRPC)
lnaudit scan --config ~/.lnd/lnd.conf

# Output formats
lnaudit scan --format json    # Machine-readable
lnaudit scan --format table   # Terminal (default)
lnaudit scan --format sarif   # CI/CD integration
```

## Example output

```
⚡ LND Hardening Toolkit v0.1.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Scanning node: 03a1b2c3...@localhost:10009

  CRITICAL  Tor onion key is not encrypted on disk
            → Set --tor.encryptkey=true in lnd.conf

  HIGH      No watchtower client configured
            → Add [wtclient] section with at least one tower

  HIGH      Node announces clearnet IP alongside .onion
            → Remove externalip= if running Tor-only

  MEDIUM    Default macaroon admin.macaroon has no timeout caveat
            → Bake time-limited macaroons for applications

  LOW       Channel backup is 48 hours old
            → Verify backup automation is running

  INFO      AssumeChannelValid is disabled (good)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Score: 62/100 — Needs hardening
  3 critical/high · 1 medium · 1 low · 1 info
```

## Architecture

```
lnaudit/
├── cmd/                    # CLI entrypoint
│   └── lnaudit/
├── pkg/
│   ├── scanner/            # Core scanning engine
│   ├── checks/             # Individual check implementations
│   │   ├── transport.go
│   │   ├── keys.go
│   │   ├── channels.go
│   │   ├── access.go
│   │   ├── privacy.go
│   │   └── hygiene.go
│   ├── config/             # LND config parser
│   ├── grpc/               # LND gRPC client
│   └── report/             # Output formatters (table, JSON, SARIF)
├── go.mod
├── go.sum
├── LICENSE
└── README.md
```

## Requirements

- Go 1.21+
- Access to the target node's `lnd.conf` and/or gRPC endpoint
- Read-only macaroon (`readonly.macaroon`) for live checks

## Roadmap

- [ ] Config-based scanning (no node connection needed)
- [ ] Live node scanning via gRPC
- [ ] CI/CD integration (GitHub Actions, SARIF output)
- [ ] Homebrew / Docker distribution
- [ ] Benchmarking against CIS-style hardening baselines

## Related

- [LND Deep Dive](https://nonsoamadi10.github.io/lnd-deep-dive/) — the security research behind this tool
- [LND](https://github.com/lightningnetwork/lnd) — the Lightning Network Daemon

## License

MIT
