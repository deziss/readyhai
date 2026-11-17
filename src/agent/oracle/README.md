# Agent Oracle Module (`src/agent/oracle/`)

## Responsibility
Provides deterministic typed assertion judging for all security techniques, HTTP observations, contract schemas, stateful multi-actor chains, and concurrency bursts in ReadyHai.

## File Structure (< 410 lines each)
- `mod.rs`: Clean re-export facade maintaining 100% backward compatibility for all callers.
- `types.rs`: Core domain models (`Verdict`, `Severity`, `Technique`, `OracleCheck`, `OracleOutcome`, `Observation`, `ProbeSnapshot`, `ProbeEvidence`).
- `signatures.rs`: Signature detection, auth wall patterns (`WallSignal`, `auth_wall_signal`), sensitive path rules, and client-side DOM XSS flows (`has_dom_xss_sink_flow`).
- `access.rs`: Access control verification (`sensitive_checks`, `denied_check`, `cors_check`).
- `expectations.rs`: Expected behavior derivation (`Expect`, `derive_expectation`, `expects_redirect`, `expects_denial`, `is_rejection`, `is_privileged_api_path`, `expectation_checks`).
- `contract.rs`: Contract schema enforcement (`contract_checks`), object isolation (`primary_object`), path traversal signatures, mass assignment reflection, and excessive data exposure detection.
- `probes.rs`: Specialized verification oracles (`probe_oracle_checks`: boolean differential, time delay, SSTI, open redirect, OAST, GraphQL introspection).
- `stateful.rs`: Stateful chain and cross-actor verification (`StatefulFacts`, `judge_stateful`).
- `burst.rs`: Concurrency burst oracles (`BurstFacts`, `BurstResponse`, `judge_burst`, `judge_burst_on_path`).
- `judge.rs`: Central orchestration engine (`judge(case: &PlannedCase, o: &Observation) -> OracleOutcome`).
- `tests.rs`: Comprehensive test suite (32 unit tests).

## Public Interfaces
- `judge(case: &PlannedCase, o: &Observation) -> OracleOutcome`: Main oracle evaluation function.
- `judge_stateful(f: &StatefulFacts) -> OracleOutcome`: Multi-actor IDOR and chain sequence verdict.
- `judge_burst(f: &BurstFacts) -> OracleOutcome`: Concurrency / race condition invariant verdict.
- `auth_wall_signal(...) -> Option<WallSignal>`: Auth wall heuristic for login redirect/form discovery.
- `disclosure_signature(...)`, `is_sensitive_path(...)`, `primary_object(...)`, `traversal_signature(...)`: Security primitives.

## Architectural Rules
1. **Deterministic Assertions Only**: An oracle must never rely on probabilistic guesses; verdicts are strictly `PASS`, `FAIL`, or `INCONCLUSIVE`.
2. **Exploratory Protection**: LLM-proposed cases bring unconfirmed hypotheses; only deterministic invariant violations (5xx, disclosures, reflections, traversals, schema errors) may trigger `FAIL`.
3. **No Network I/O**: The oracle operates strictly on borrowed memory representations (`Observation`), performing zero network requests.

## Test Commands
```bash
cargo test --bin readyhai -- agent::oracle::tests
```
