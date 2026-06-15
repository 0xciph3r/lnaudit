# Contributing to lnaudit

Thank you for your interest in contributing to lnaudit! This project aims to make Lightning Network nodes more secure, and every contribution helps.

## Getting Started

1. **Fork the repository** and clone your fork:

   ```bash
   git clone https://github.com/<your-username>/lnaudit.git
   cd lnaudit
   ```

2. **Install development dependencies:**

   ```bash
   make dev-deps
   ```

3. **Verify everything works:**

   ```bash
   make check
   ```

   This runs formatting, vetting, linting, and all tests.

## Development Workflow

### Branch Naming

Use descriptive branch names:

- `feat/watchtower-live-check` — new feature
- `fix/symlink-permission-bypass` — bug fix
- `docs/update-readme` — documentation
- `chore/ci-go-1.25` — maintenance

### Making Changes

1. Create a feature branch from `main`
2. Write your code and tests
3. Run `make check` to ensure everything passes
4. Commit with a clear message (see below)
5. Push and open a pull request

### Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add watchtower connectivity check via gRPC
fix: prevent false positive on default trickle delay
docs: add example output for JSON format
chore: bump golangci-lint to v1.62
test: add coverage for signet network detection
```

### Running Tests

```bash
make test              # Run all tests
make test-verbose      # With verbose output
make test-race         # With Go race detector
make coverage          # Generate coverage report
```

### Code Style

- Code is formatted with `gofmt -s` and `goimports`
- Run `make fmt` to auto-format
- Run `make lint` to check for issues
- Follow existing patterns in the codebase
- Add tests for new functionality

## Adding a New Security Check

Security checks live in `pkg/checks/`. lnaudit supports two check families:

- **Static checks** inspect `lnd.conf`, file permissions, certificates, and local path state. They work before a node is running.
- **Live checks** use read-only gRPC APIs against a running LND node. They inspect runtime state such as sync status, channels, pending HTLCs, force-closes, and negotiated channel limits.

### Static checks

1. **Choose the right file** based on the module:
   - `transport.go` — TLS, RPC/REST, bind address hardening
   - `access.go` — macaroons, wallet/auth flags, credential hygiene
   - `privacy.go` — Tor, SCID aliases, network privacy
   - `exposure.go` — listener and NAT exposure
   - `policy.go` — channel, Bitcoin, payment, and routing policy
   - `resilience.go` — protocol, autopilot, gossip, and additional hardening
   - `permissions.go` — filesystem permission checks

2. **Define your check function** returning `[]scanner.Finding`:

   ```go
   func CheckSomething(cfg *config.LndConfig) []scanner.Finding {
       var findings []scanner.Finding
       // your logic here
       return findings
   }
   ```

3. **Add parser support** in `pkg/config/config.go` if the check needs a new `lnd.conf` flag. Prefer explicit marker fields such as `FooExplicit bool` when the difference between "unset" and "set to zero/false" matters.

### Live checks

1. Extend `pkg/grpc/client.go` if the check needs additional runtime fields from LND.
2. Populate those fields in `pkg/grpc/connect.go`.
3. Update `pkg/grpc/mock.go` when needed for tests.
4. Define a live check with the gRPC signature:

   ```go
   func CheckSomethingLive(client lngrpc.LndClient) ([]scanner.Finding, error) {
       channels, err := client.ListChannels()
       if err != nil {
           return nil, fmt.Errorf("something check: %w", err)
       }

       var findings []scanner.Finding
       // your logic here
       return findings, nil
   }
   ```

### Severity and output rules

Use appropriate severity levels:

   | Severity | When to use |
   |----------|-------------|
   | CRITICAL | Direct fund loss risk, key exposure |
   | HIGH | Significant security weakness |
   | MEDIUM | Suboptimal configuration |
   | LOW | Minor hardening opportunity |
   | INFO | Informational, good practice confirmed |

Every finding must include:

- A stable `ID`
- A `Module` that matches the report grouping
- A concise `Title`
- A clear `Description` of the risk
- A concrete `Remediation` operators can apply
- A `Reference` when the check maps to a known incident, CVE, or LND documentation

### Wiring and validation

1. Wire static checks in `cmd/scan.go` inside the config-check section of `executeScan`.
2. Wire live checks in the `liveChecks` slice in `cmd/scan.go`.
3. Write tests in the corresponding `_test.go` file.
4. Update README/docs when the check adds a new attack vector, module, or user-visible output.
5. Run `go test ./...` before opening a PR.

## Reporting Security Vulnerabilities

Please see [SECURITY.md](SECURITY.md) for instructions on reporting security vulnerabilities. **Do not open a public issue for security bugs.**

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Include tests for new functionality
- Update documentation if behavior changes
- Ensure `make check` passes
- Fill out the PR template

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Questions?

Open a [discussion](https://github.com/0xciph3r/lnaudit/discussions) or reach out in the issue tracker. We're happy to help you get started.
