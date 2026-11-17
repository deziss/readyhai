# Agent Evidence Ledger Module (`src/agent/ledger`)

## Responsibility
Computes and maintains the readiness evidence ledger for agent QA runs. Constructs the multi-pillar coverage matrix (Value, Authority, Safety, Evidence), synthesizes deterministic gate verdicts (`GO`, `CONDITIONAL_GO`, `NO_GO`, `NOT_EVALUATED`), manages blockers, handles defect acceptance waiving, and integrates post-run verification and LLM advisories.

## Files
- `constants.rs`: Scoring parameters, coverage weightings (`EVIDENCE_WEIGHT`), minimum confidence thresholds (`MIN_PILLAR_CONFIDENCE`, `MIN_OVERALL_CONFIDENCE`, `FULL_CONFIDENCE`), and pillar definitions (`PILLARS`).
- `types.rs`: `LedgerInput` data carrier, cell aggregation utilities (`add`, `bucket`), and metrics calculation (`conclusive`, `applicable`, `confidence_pct`, `points`, `merge`, `rank`).
- `blockers.rs`: Root-cause blocker classification (`blockers_of`), login wall detection, exploratory case isolation, defect gate-blocking rules (`is_blocking`), and empty-run ledger (`not_evaluated`).
- `scoring.rs`: Core multi-pillar evidence ledger computation (`compute_scored`), exit criteria checklist evaluation, and evidence claim generation.
- `enrich.rs`: Verification summary integration (`attach_verification`) and non-interfering LLM advisory reconciliation (`apply_llm`).
- `mod.rs`: Module facade, acceptance waiving logic, and public API facade (`compute`).
- `tests.rs`: Comprehensive test suite verifying deterministic gates, blockers, flaky replays, and score calculation.

## Public Interfaces
```rust
pub struct LedgerInput<'a> { ... }
pub fn compute(inp: &LedgerInput) -> EvidenceLedger;
pub fn is_blocking(d: &TriagedDefect) -> bool;
pub fn not_evaluated(verdict: &str, summary: impl Into<String>, checklist: Vec<ExitCheckItem>) -> EvidenceLedger;
pub fn attach_verification(l: &mut EvidenceLedger, v: VerificationSummary, defects: &[TriagedDefect]);
pub fn apply_llm(l: &mut EvidenceLedger, verdict: Option<&str>, scores: [Option<i64>; 5], summary: Option<String>);
```

## Test Commands
```bash
cargo test --bin readyhai -- agent::ledger::tests
cargo clippy --bin readyhai -- -D warnings
```
