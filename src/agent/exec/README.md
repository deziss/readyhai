# Agent Execution Module (`readyhai::agent::exec`)

## Responsibility
Executes planned HTTP security and functional test cases against target services. Dispatches primary probes, follows same-origin redirects, attaches role-scoped credentials via cert-validating transport, handles concurrency bursts and adaptive mutation sub-cases, and verifies resource cleanup after mutating operations.

## Directory Structure & Submodules
- `mod.rs`: Facade re-exporting public API for 100% backward compatibility.
- `auth.rs`: Authentication models (`Auth`, `Bearer`, `ResolvedAuth`, `auth_for`, `resolve_auth`, `role_of`).
- `bootstrap.rs`: Login bootstrap engine, CSRF token extraction, and cookie jar handling.
- `credentials.rs`: Multi-modal credential registry (`Credentials`, `HeaderEnvKind`) from environment, roles.toml, and bootstraps.
- `builder.rs`: Safe HTTP request construction, header sanitization, payload encoding, and reproduction curl generators.
- `clients.rs`: Transport clients (`Clients`, `Seen`, `OutReq`, `Followed`, `follows_redirects`, `needs_validated_tls`).
- `delete.rs`: Deletion verification (`DeleteCheck`, `confirm_deleted`, `confirm_deleted_as`, `confirm_deleted_resolved`).
- `probe.rs`: Companion probes (`ProbeOutcome`, `send_with_probe_oracle`, baseline/control/OAST probe coordination).
- `dispatch.rs`: Execution orchestrator (`ExecOptions`, `CaseGate`, `execute_cases`, `execute_cases_with`, `execute_cases_gated`, `exec_http`).
- `subcases.rs`: Sub-case executions (`run_mutation`, `run_burst`, `run_stateful_case`).
- `fixture.rs`: In-process mock API server fixture for integration testing.
- `tests.rs`: Comprehensive unit and regression test suite.

## Public Interfaces
- `execute_cases(cases: &[PlannedCase], target: &str, is_spa: bool) -> Vec<CaseExecutionResult>`
- `execute_cases_with(cases, target, opts, budget) -> Vec<CaseExecutionResult>`
- `execute_cases_gated(cases, target, opts, budget, gate) -> Vec<CaseExecutionResult>`
- `Credentials`: Multi-role token, cookie, and header credential manager.
- `ExecOptions`: Execution flags (dry run, SPA detection, credentials, reruns, timeout).
- `CaseGate`: Synchronization hook around case lifecycles for coordinated test runners.
- `DeleteCheck`: Three-state validation of resource teardown (`Gone`, `StillPresent(u16)`, `Unknown`).

## Security Guarantees & Invariant Rules
1. **Target Origin Isolation**: Credentials (`RH_<ROLE>_TOKEN`, cookies, custom headers) are sent ONLY when the request's scheme, host, and port exactly match the run's target URL.
2. **TLS Certificate Enforcement**: Requests bearing real credentials travel only over clients that strictly validate TLS certificates; never over lax clients.
3. **Redirect Confinement**: Same-origin redirects are followed up to 5 hops for safe reads (`GET`/`HEAD`) only; auth probes, sensitive files, and mutating operations never follow redirects.
4. **Secret Redaction**: Credentials never appear in reproduction curl commands or report outputs; environment variable placeholders (`${RH_<ROLE>_TOKEN}`) are used instead.

## Verification & Testing
```bash
PATH="$HOME/.cargo/bin:$PATH" cargo test --bin readyhai -- agent::exec::tests
PATH="$HOME/.cargo/bin:$PATH" cargo clippy -- -D warnings
```
