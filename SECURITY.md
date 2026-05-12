# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in lnaudit, **please report it responsibly**. Do not open a public GitHub issue.

### How to Report

Email: **nonsoamadi@aol.com**

Include as much detail as possible:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to Expect

- **Acknowledgment** within 48 hours
- **Assessment** within 1 week
- **Fix timeline** communicated after assessment
- **Credit** in the release notes (unless you prefer anonymity)

### Scope

The following are in scope:

- Bugs in lnaudit that could cause it to report **false negatives** (missing a real vulnerability)
- Bugs that could **leak sensitive information** from the scanned node (config paths, macaroon contents, etc.)
- Path traversal or symlink attacks via user-supplied input
- Dependencies with known CVEs

The following are out of scope:

- Vulnerabilities in LND itself (report to [Lightning Labs](https://github.com/lightningnetwork/lnd/security))
- Social engineering attacks
- Issues in third-party dependencies that don't affect lnaudit's functionality

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | ✅        |
| < latest | ❌       |

We only support the latest release. Please upgrade before reporting.
