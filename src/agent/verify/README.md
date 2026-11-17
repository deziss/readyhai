# Agent Verify (`src/agent/verify`)

## Responsibility
Independent defect reproduction verifier. Before any FAIL reaches triage and the ledger, it is replayed `k` times and only preserved as a defect when reproduced. Manages replay budgets, safe write-method gating, oracle judging, and verdict reconciliation.

## Files
- `options.rs`: Verification configuration (`VerifyOptions`), environment parsing (`parse_k`, `k_from_env`), outcome structures (`VerifyOutcome`), and constants (`DEFAULT_K`, `MAX_K`, `MAX_UNREACHABLE`).
- `plan.rs`: Replay plan dispatch (`Plan`, `plan_for`), failure extraction (`fail_codes`, `severity_of`), unlikely ID detection (`targets_unlikely_id`), and replay vote evaluation (`Vote`, `vote`).
- `replay.rs`: Execution context (`Ctx`), HTTP replay (`replay_http`), stateful chain replay (`replay_chain`), and result reconciliation (`apply`, `record_for`).
- `mod.rs`: Verification entry point (`verify_failures`) and 100% backward-compatible re-export facade for `crate::agent::verify::*`.
- `tests.rs`: Comprehensive test suite verifying replay policies, SPA handling, auth detachment/reattachment, and verdict transitions.

## Security & Verification Rules
1. **Fresh Credential Attachment**: Rebuilt requests never reuse cached tokens or stored secrets; credentials are attached afresh through `exec::resolve_auth` adhering to target boundary checks.
2. **Safe Mutation Gating**: Write methods (POST/PUT/PATCH/DELETE) are only replayed if the original case created its own resource or targeted an unlikely synthetic ID (`999999`, `readyhai-nonexistent`).
3. **Budget and Transport Sandboxing**: All replays are charged against `RunBudget`. If a host is unreachable repeatedly (`MAX_UNREACHABLE`), verification stops early to prevent denial of service.

## Verification
```bash
PATH="$HOME/.cargo/bin:$PATH" cargo test --bin readyhai -- agent::verify::tests
PATH="$HOME/.cargo/bin:$PATH" cargo clippy -- -D warnings
```
