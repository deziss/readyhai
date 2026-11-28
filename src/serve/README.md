# Serve Module (`src/serve/`)

## Responsibility
The `serve` module provides the HTTP REST API, SSE event streams, agent studio controllers, background scan worker queues, and security gate endpoints for ReadyHai.

## Files
- `mod.rs`: Public facade and backward-compatible re-exports.
- `types.rs`: Request/response DTOs, payload structs, constants, and shared `App` state.
- `auth.rs`: Bearer token authentication, principal validation, and route access control.
- `guards.rs`: Target scope validation, async DNS preflight checks, and blocking pool executors.
- `worker.rs`: Background task queue, worker loop, startup run recovery, and state tracking.
- `scans.rs`: Vulnerability scan CRUD, artifact retrieval, and check listing endpoints.
- `agent_api.rs`: Agent Studio runs, SSE streaming, human-in-the-loop approvals, and discovery.
- `network_api.rs`: Network Lab routes (regressions, curl tests, deep audit, HAR export).
- `eval_api.rs`: AI evaluation, code mutation, automated patch generation, and PR comments.
- `badges.rs`: Dynamic SVG badge generation for CI/CD status embedding; text comes only from a verdict allowlist, a clamped score, or a stored run — never from caller prose.
- `router.rs`: Axum router assembly, static asset delivery, and graceful shutdown.
- `tests.rs`: Isolated unit and integration test suite (38 tests).

## Public Interfaces
- `serve(bind: &str) -> anyhow::Result<()>`: Launches the API server and worker pool.
- `build_router(app: Arc<App>) -> axum::Router`: Constructs the authenticated Axum routing tree.
- `max_custom_instructions_bytes() -> usize`: Returns the configured custom instructions size cap.
- `worker_count() -> usize`: Returns the number of background worker threads.

## Dependencies
- Internal: `crate::engine`, `crate::model`, `crate::network`, `crate::scope`, `crate::tools`, `crate::agent`, `crate::eval_ai`, `crate::fix`, `crate::mutate`.
- External: `axum`, `tokio`, `serde`, `serde_json`, `sha2`, `hyper`.

## Rules & Constraints
- All outbound HTTP actions must go through `guard()` to enforce scope and non-production checks.
- All routes except `/health` and the three public `/api/badges/{gate,ledger,network}` paths sit behind `require_auth` bearer token middleware; the `/api/badges/*/{id}` run badges are authenticated.
- Blocking I/O (filesystem, DNS lookups) must run via `offload()` or `blocking()`, never on the async worker threads.

## Tests
Run module unit tests:
```bash
cargo test --bin readyhai -- serve::tests
```
Run full test suite:
```bash
cargo test --all-targets
```
Run linter:
```bash
cargo clippy -- -D warnings
```
