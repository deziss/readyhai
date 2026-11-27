# Agent Pipeline Modular Architecture

## Responsibility
The `agent::pipeline` module orchestrates the autonomous testing lifecycle: Discovery -> Intel (after memory recall, before Planning) -> Planning -> Multi-Worker Exploration -> Failure Verification -> Teardown/Cleanup -> Defect Triage (findings recorded back to the Vulns DB) -> Evidence Ledger & Readiness Gate.

## Submodules
| File | Lines | Responsibility |
|---|---|---|
| `options.rs` | 248 | `RunOptions`, `LlmMode`, token budgeting, LLM probing, slow endpoint capping |
| `cleanup.rs` | 478 | Resource creation tracking, non-prod teardown, 2xx DELETE verification defects |
| `order.rs` | 28 | Plan ordering by auth/stateful/OpenAPI priority and hard limit truncation |
| `gate.rs` | 95 | Advisory LLM readiness gate prompt, schema parsing, and ledger annotation |
| `change.rs` | 78 | Git diff analysis, changed endpoint mapping, and impact recording |
| `memory.rs` | 173 | Persistent target recall, unexpired defect acceptances, and observation commit |
| `intel.rs` | 765 | Intel stage between memory recall and planning: reads the target's open Vulns DB findings with verification stamps (gated on `[vulndb] enabled`), replays safe exploit-verification templates over them when `[exploits] enabled` and not a dry-run (within `max_probes`, through the scope egress guard with `intrusive = true`), collects passive network posture from `src/network` helpers and plugged-tool availability; after Defect Triage records the run's triaged findings via `vulndb::record_run` (skipped on dry-run) |
| `discovery.rs` | 203 | Lightweight discovery and attack-surface scanning without test execution |
| `stages.rs` | 976 | Core staged execution coordinator executing the 7 autonomous phases |
| `mod.rs` | 150 | Public facades, re-exports, panic guards, and checkpoint lifecycle |
| `tests.rs` | 1648 | Unit tests (20 test cases) and mock server fixture |

## Public Interfaces
- `run_agentic_loop(req: &AgentRunRequest, run_id: &str) -> Result<AgentRunReport>`
- `run_agentic_loop_with(req: &AgentRunRequest, run_id: &str, opts: RunOptions) -> Result<AgentRunReport>`
- `run_discovery_scan(target: &str, spec_url: Option<&str>) -> Result<AgentRunReport>`
- `RunOptions`, `LlmMode`
- Intel stage (`intel.rs`): builds the advisory per-run intel bundle from the Vulns DB, opt-in safe exploit-verification re-checks, passive `src/network` posture facts and plugged-tool availability; the resulting `PlanHints` carry `known_open` + `reproduced` so the planner re-tests proven weaknesses first (reproduced > memory regression probes > merely-open), and the post-triage pass records the run's findings via `vulndb::record_run`.

## Invariants & Rules
1. **Deterministic Primacy**: All verdicts and defect classifications are computed deterministically; LLM outputs are strictly advisory and never change verdicts.
2. **Safe Teardown**: Teardown only fires DELETE requests when the target is explicitly confirmed nonprod by scope rules; follow-up GET confirms deletion.
3. **Atomic Checkpointing**: Run state is saved after every stage with status `running`, finishing as `completed`, `failed`, or `cancelled`.
4. **Plan Truncation**: When truncated by budget or profile caps, cases are prioritized so that changed operations, authentication, stateful, and contract cases are preserved.
5. **Intel is Advisory & Deterministic**: Intel only reorders the plan (`PlanHints` `known_open` + `reproduced`) — it never creates, upgrades or changes verdicts, consistent with Deterministic Primacy. Its exploit-verification pass is strictly opt-in: it runs only when operator settings `[exploits] enabled` is true and the run is not a dry-run, stays within the `max_probes` budget, and every probe URL passes the scope egress guard with `intrusive = true`. Dry runs send zero probes and record nothing; Vulns DB reads and post-triage write-backs both respect the `[vulndb] enabled` gate.

## Verification
- Run pipeline unit tests:
  ```bash
  cargo test --bin readyhai -- agent::pipeline::tests
  ```
- Run linter:
  ```bash
  cargo clippy -- -D warnings
  ```
