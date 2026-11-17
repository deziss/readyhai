# Agent Lead (`src/agent/lead`)

## Responsibility
Orchestrator-worker coordination for an agent run. Partitions planned test cases by functional `Area` (`auth`, `contract`, `state`, `ui`), calculates and allocates weighted resource budgets (steps, requests, wall-clock time, LLM calls), runs workers in parallel with live telemetry reporting, merges results deterministically, and executes at most one deterministic follow-up wave.

## Files
- `area.rs`: Functional `Area` enum, worker concurrency limits, env parsing, and case/request demand weighting.
- `alloc.rs`: Dynamic budget allocation (`Available`, `Grant`), fair-share capping, and write-operation gating.
- `schedule.rs`: Worker thread execution, turn tracking (`Turns`, `Live`), area gating, and wave runners (`run_wave`, `run_task`).
- `followup.rs`: Deterministic follow-up rules (`RULE_AUTH_TO_CONTRACT`, `RULE_REPROBE`, `RULE_RESUME`), natural sorting, and result merging.
- `report.rs`: Live progress skeleton generation, quota summation, recalculation, and status summary lines.
- `mod.rs`: Public API entry point (`run`), configuration (`LeadConfig`), outcome structures (`LeadOutcome`), and 100% backward-compatible re-exports.
- `tests.rs`: Comprehensive unit and integration test suite.

## Security & Architectural Rules
1. **Deterministic Follow-up Planning**: Follow-up cases in wave 2 are generated strictly through deterministic causal rules (`auth -> contract`, reprobe flaky/transient endpoints, resume budget-skipped cases), never unconstrained LLM loops.
2. **Strict Resource Quota Sandboxing**: Worker threads run with independent budget slices; no worker can starve the pool or exceed step, request, or time allowances.
3. **Write Conflict Avoidance**: Write operations are sequenced and resource-capped to avoid destructive race conditions across parallel area workers.

## Verification
```bash
PATH="$HOME/.cargo/bin:$PATH" cargo test --bin readyhai -- agent::lead::tests
PATH="$HOME/.cargo/bin:$PATH" cargo clippy -- -D warnings
```
