# Agent Types Module (`src/agent/types/`)

## Responsibility
Core wire/storage data models, serde serialization fallbacks, thread-local resource creation ledger, cancellation registry, and execution records for the ReadyHai autonomous agent.

## Submodules
- `defaults.rs`: Default value provider functions for serde deserialization fallbacks.
- `discovery.rs`: Route discovery, redirect chains, input surfaces, soft-404 fingerprints, and blockers.
- `planning.rs`: Test planning models (`PlannedCase`, `ProbeOracle`, `ResponseContract`, prioritization keys).
- `execution.rs`: Case execution results, stateful step chains, and evidence sharing calculation.
- `reports.rs`: High-level run requests, reports, summaries, evidence ledgers, and triaged defects.
- `change.rs`: Code diff change impact, affected operations, and coverage analysis models.
- `created_ledger.rs`: Resource creation tracking, thread-local scopes, and cleanup teardown reporting.
- `verification.rs`: Independent failure verification models, replay records, and pass^k verification summaries.
- `lifecycle.rs`: Cooperative cancellation tokens, process registry, and run cancellation requests.
- `fixtures.rs`: Shared test fixtures for agent tests.
- `tests.rs`: Comprehensive unit tests covering ledger deduplication, thread scopes, prioritization, and cancellation.

## Public Interfaces
- `PlannedCase`, `CaseExecutionResult`, `AgentRunReport`, `AgentRunRequest`, `AgentsReport`
- `CreatedLedger`, `record_created`, `record_created_with`, `current_ledger`, `record_creation_response`
- `CancelToken`, `register_run`, `running_run_ids`, `request_cancel`
- `profile_case_cap`, `case_priority`, `plan_order`, `evidence_share`

## Rules
- All fields added after initial release must have `#[serde(default)]` to guarantee backward compatibility with older persisted reports.
- Thread-local ledgers restore previous scope on drop; threads in a pool must be passed explicit clones.
- Cancellation tokens support both atomic in-process flags and filesystem markers.

## Verification
```bash
cargo test --bin readyhai -- agent::types::tests
cargo clippy --bin readyhai -- -D warnings
```
