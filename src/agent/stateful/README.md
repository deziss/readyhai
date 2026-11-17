# Stateful Scenario Chains & TOCTOU Burst Module (`src/agent/stateful`)

## Responsibility
Executes stateful multi-step scenario chains (BOLA/IDOR cross-actor resource isolation) and TOCTOU concurrency burst attacks with zero credentials leakage and strict budget tracking.

## Architecture & Submodules
- `models.rs` (~45 lines): Data transfer models (`StatefulScenarioResult`, `BurstRun`) and default resource ID extraction keys (`DEFAULT_ID_KEYS`).
- `vars.rs` (~120 lines): Template variable substitution (`{{var}}`), secret key identification (`is_secret_key`), value masking (`storable_value`), and response JSON extraction (`extract_json_values`).
- `violation.rs` (~175 lines): Actor abstraction (`Actor`, `actor_bearer`), violation expression evaluation (`evaluate_violation`), and JSON path inspectors.
- `preflight.rs` (~130 lines): Gatekeeper deciding validity without sending HTTP requests (`preflight`, `strip_trailing_placeholder`, `access_index`).
- `exchange.rs` (~185 lines): HTTP exchange abstraction (`Exchange`, `Runner`, `skipped_result`, `status_matches`) with automatic ledger recording.
- `scenario.rs` (~285 lines): Scenario execution driver (`execute_stateful_scenario`) coordinating owner-control reads, anonymous checks, and oracle integration.
- `burst.rs` (~165 lines): Concurrent TOCTOU race testing (`run_concurrency_burst`, `run_concurrency_burst_auth`) with barrier synchronization.
- `mod.rs` (~25 lines): Facade providing 100% backward-compatible re-exports.
- `tests.rs` (~270 lines): Unit tests covering template substitution, secret masking, BOLA chains, and preflight rules.

## Public Interfaces
- `execute_stateful_scenario(clients, target, steps, creds, budget, host, case_id) -> StatefulScenarioResult`
- `run_concurrency_burst(clients, spec, bearer, burst_size, budget, host, case_id) -> Result<BurstRun, String>`
- `run_concurrency_burst_auth(clients, spec, auth, burst_size, budget, host, case_id) -> Result<BurstRun, String>`
- `preflight(steps, creds) -> Result<(), String>`
- `evaluate_violation(condition, status, body) -> bool`

## Security Invariants
1. Both actors' credentials must be present in preflight; single-actor cross-tenant checks are skipped before sending requests.
2. Sensitive keys (`token`, `password`, `key`, `secret`, `jwt`, `cookie`) are redacted with `[REDACTED]` prior to storage in results or curl repros.
3. Every 2xx POST response created during a scenario chain or burst is automatically registered on the run ledger for cleanup.

## Verification
```bash
cargo test --bin readyhai -- agent::stateful::tests
cargo clippy --bin readyhai -- -D warnings
```
