# Agent Pipeline Modular Architecture

## Responsibility
The `agent::pipeline` module orchestrates the autonomous testing lifecycle: Discovery -> Planning -> Multi-Worker Exploration -> Failure Verification -> Teardown/Cleanup -> Defect Triage -> Evidence Ledger & Readiness Gate.

## Submodules
| File | Lines | Responsibility |
|---|---|---|
| `options.rs` | 248 | `RunOptions`, `LlmMode`, token budgeting, LLM probing, slow endpoint capping |
| `cleanup.rs` | 478 | Resource creation tracking, non-prod teardown, 2xx DELETE verification defects |
| `order.rs` | 28 | Plan ordering by auth/stateful/OpenAPI priority and hard limit truncation |
| `gate.rs` | 95 | Advisory LLM readiness gate prompt, schema parsing, and ledger annotation |
| `change.rs` | 78 | Git diff analysis, changed endpoint mapping, and impact recording |
| `memory.rs` | 173 | Persistent target recall, unexpired defect acceptances, and observation commit |
| `discovery.rs` | 203 | Lightweight discovery and attack-surface scanning without test execution |
| `stages.rs` | 976 | Core staged execution coordinator executing the 7 autonomous phases |
| `mod.rs` | 150 | Public facades, re-exports, panic guards, and checkpoint lifecycle |
| `tests.rs` | 1648 | Unit tests (20 test cases) and mock server fixture |

## Public Interfaces
- `run_agentic_loop(req: &AgentRunRequest, run_id: &str) -> Result<AgentRunReport>`
- `run_agentic_loop_with(req: &AgentRunRequest, run_id: &str, opts: RunOptions) -> Result<AgentRunReport>`
- `run_discovery_scan(target: &str, spec_url: Option<&str>) -> Result<AgentRunReport>`
- `RunOptions`, `LlmMode`

## Invariants & Rules
1. **Deterministic Primacy**: All verdicts and defect classifications are computed deterministically; LLM outputs are strictly advisory and never change verdicts.
2. **Safe Teardown**: Teardown only fires DELETE requests when the target is explicitly confirmed nonprod by scope rules; follow-up GET confirms deletion.
3. **Atomic Checkpointing**: Run state is saved after every stage with status `running`, finishing as `completed`, `failed`, or `cancelled`.
4. **Plan Truncation**: When truncated by budget or profile caps, cases are prioritized so that changed operations, authentication, stateful, and contract cases are preserved.

## Verification
- Run pipeline unit tests:
  ```bash
  cargo test --bin readyhai -- agent::pipeline::tests
  ```
- Run linter:
  ```bash
  cargo clippy -- -D warnings
  ```
