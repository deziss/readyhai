# Engine Module (`src/engine/`)

## Responsibility
Core scan orchestration: target parsing, snapshot capture, rule and probe execution, gate verdict computation, and report persistence.

## Submodules
- `types.rs`: Scan configuration options (`ScanOpts`) and package version metadata.
- `storage.rs`: Data directory resolution, atomic file persistence (`write_atomic`), run id generation (`new_run_id`, `valid_run_id`), and run loading.
- `deadline.rs`: Execution deadline registry and RAII deadline guards (`DeadlineGuard`, `deadline_passed`).
- `target_parser.rs`: Target string parsing and classification into Web, Repo, Image, Host, or Android targets.
- `git.rs`: Remote repository cloning, URL normalization, non-interactive sandboxing, and credential redaction.
- `orchestrator.rs`: Core scan orchestrator pipeline (`scan()`, `error_status`).
- `tests.rs`: Comprehensive unit tests covering atomic writes, git commands, credential redaction, and deadlines.

## Public Interfaces
- `scan(opts: &ScanOpts, run_id: &str) -> Result<Run>`
- `parse_target(raw: &str, openapi: Option<String>) -> Result<Target>`
- `new_run_id() -> String`, `valid_run_id(id: &str) -> bool`, `run_dir(id: &str) -> PathBuf`
- `write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()>`
- `data_dir() -> PathBuf`, `load_run(id: &str) -> Result<Run>`
- `remote_repo_host(raw: &str) -> Result<String>`

## Invariants & Rules
- All file writes to run artifacts must use `write_atomic` to avoid exposing partial files during polling.
- Runs exceeding wall-clock deadlines fail fast without generating partial verdicts.
- Git clone commands run non-interactively with disabled hooks, disabled submodules, and credential redaction.

## Verification
```bash
cargo test --bin readyhai -- engine::tests
cargo clippy --bin readyhai -- -D warnings
```
