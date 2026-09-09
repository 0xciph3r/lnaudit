# Channel-Jamming Threat Model and Observability Spec (PR1)

This document defines the v1 threat model and data contract for channel-jamming analysis in `lnaudit`.
It is intentionally scoped to modeling, observability, and measurable acceptance gates. It does not
introduce runtime detection code.

## Decision record

### Execution model

`lnaudit scan` remains fast and stateless.

Temporal jamming analysis will be implemented as a dedicated flow:

1. **Primary mode (v1): offline replay**
   - `lnaudit jamming analyze --from-file <timeline.json>`
   - Deterministic, CI-friendly, and testable.
2. **Secondary mode (v1.1): persisted sampling**
   - Repeated invocations can build history via `--history-db <path>`.
3. **Out of scope (v1): always-on daemon/watch mode**
   - Not required for first release of temporal scoring.

This avoids breaking existing `scan` latency expectations and CI behavior.

## Security goals

Protect operator decision quality by detecting **sustained jamming pressure signals** while minimizing
false positives and avoiding harmful remediation.

Assets in scope:

- HTLC slot availability per channel
- Liquidity availability for legitimate flow
- Routing availability and economic continuity
- Operator response quality under uncertainty

## Attacker model

Assume the adversary:

- Knows open-source detector logic and static thresholds
- Can distribute pressure across channels to evade fixed constants
- Can run sustained low-and-slow or burst patterns
- Can be remote/multi-hop (immediate peer is not reliable attribution)
- Can attempt detector manipulation around predictable scan schedules

## Confounders that must be handled explicitly

- Legitimate traffic bursts
- Hodl invoice behavior
- Fee-spike congestion and delayed settlement
- Restart/replay windows and temporary telemetry anomalies

Findings must carry evidence and confidence; one-snapshot observations are not enough for high-confidence
jamming conclusions.

## Safe claims / non-goals

`lnaudit` **may** claim:

- Observed pending-HTLC pressure and persistence over a sampled window
- Elevated jamming exposure posture from risky configuration values

`lnaudit` **must not** claim:

- Reliable attacker attribution to a specific peer
- Binary certainty for quick/burst-jam detection from node-local snapshots alone
- Automated "close channel now" style guidance without sustained multi-signal corroboration

## Observability contract (required signals)

The current live checks only use point-in-time channel fields (`NumPendingHTLCs`, balances, limits). Temporal
detection requires a timeline of samples with stable timestamps and channel identity.

Minimum required per-sample signals:

- Channel identifier and peer pubkey
- Pending HTLC count
- Negotiated HTLC limits
- Capacity/balance context
- Sample timestamp

Recommended expansion signals (phase 2+):

- Per-HTLC amount and age/expiry context
- Forwarding failure/throughput context for confounder separation
- Node-startup / degraded-telemetry markers

## Confidence policy

Confidence is a deterministic classification derived from evidence quality:

- **Observed**: single snapshot anomaly
- **Sustained**: anomaly persists across defined window/sample count
- **Corroborated**: sustained anomaly plus supporting secondary metrics

Confidence must map cleanly to existing severity/exit semantics so CI gating remains stable.

## Acceptance gates (numeric and falsifiable)

Before enabling release-grade temporal findings:

1. False-positive budget: `<= 1` HIGH false positive per node per 7 days on benign replay corpus
2. True-positive coverage: sustained slot and sustained liquidity jam fixtures are detected
3. Determinism: identical input timeline yields identical JSON/SARIF outputs
4. Explainability: each finding includes metric, threshold/baseline, window, sample count, and confidence
5. Compatibility: existing `scan`, `--min-severity`, `--fail-on`, and SARIF workflows stay backward-compatible

## PR decomposition

- **PR1 (this phase):** threat model + observability spec + measurable gates
- **PR2:** pure analyzer + fixture corpus + deterministic scoring tests
- **PR3:** CLI/report integration (`jamming analyze`, JSON/SARIF evidence/confidence fields)
- **PR4:** operator response playbook + migration guidance for legacy jamming checks
