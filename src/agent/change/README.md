# Change-Aware Planning Module (`src/agent/change`)

## Responsibility
Calculates change impact from code diffs (`git diff base...HEAD`) against declared OpenAPI operations to steer prioritized test case generation without reducing baseline coverage.

## Architecture & Submodules
- `models.rs` (~65 lines): Constants (`MAX_LISTED_FILES`, `APPLIED`, `NO_CHANGES`, etc.) and data models (`ChangeSet`, `Analysis`, `Retriever`).
- `validation.rs` (~55 lines): Git ref sanitization (`validate_diff_base`), repository directory canonicalization (`resolve_repo`), and allowed roots confinement (`validate_request`).
- `git.rs` (~95 lines): Secure subprocess diff execution (`git_changed_files`) with timeouts, null-byte delimiter splitting, and symlink protection (`read_repo_file`).
- `matcher.rs` (~260 lines): Deterministic route extraction and operation heuristic matching (`op_infos`, `map_files`, `resource_names`).
- `analyze.rs` (~165 lines): Change impact pipeline driver (`analyze`, `analyze_with`) and test case coverage tracking (`coverage`, `coverage_totals`).
- `retriever.rs` (~155 lines): Advisory code context retriever runner (`retriever_from_env`, `retrieve_context`) with environment and credential scrubbing.
- `testkit.rs` (~65 lines): `#[cfg(test)]` ephemeral git repository test fixtures.
- `mod.rs` (~25 lines): Public facade and backward-compatible re-exports.
- `tests.rs` (~340 lines): Comprehensive unit test suite covering git diff parsing, route mounting, unreadable file fallbacks, symlink security, and retriever behavior.

## Public Interfaces
- `analyze(repo: &Path, base: &str, spec: Option<&SpecDoc>) -> Analysis`
- `coverage(labels: &[String], planned: &[PlannedCase], results: &[CaseExecutionResult]) -> Vec<ChangedOpCoverage>`
- `coverage_totals(cov: &[ChangedOpCoverage]) -> (usize, usize)`
- `validate_request(repo: &str, diff_base: Option<&str>, roots: Option<&[PathBuf]>) -> Result<(PathBuf, Option<String>), String>`
- `validate_diff_base(base: &str) -> Result<(), String>`
- `resolve_repo(repo: &str) -> Result<PathBuf, String>`
- `retriever_from_env(repo: &Path) -> Result<Retriever, String>`
- `retrieve_context(r: &Retriever, ops: &[ChangedOperation]) -> Result<Vec<String>, String>`

## Security Invariants
1. `diff_base` is strictly validated to alphanumeric plus `._/@^~+-` to prevent command injection.
2. `repo` paths are canonicalized and verified against `READYHAI_ALLOWED_ROOTS` when invoked via MCP/REST.
3. Symlinked files pointing outside repository boundaries are never read or traversed.
4. Test credentials (`RH_*_TOKEN`) are explicitly stripped before delegating to external context runners.

## Verification
```bash
cargo test --bin readyhai -- agent::change::tests
cargo clippy --bin readyhai -- -D warnings
```
