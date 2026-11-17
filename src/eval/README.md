# Evaluation Harness Module (`src/eval/`)

## Responsibility
Scores ReadyHai's QA engine and autonomous agent against fixtures with seeded defects, evaluating recall, precision, false positives, pass^k, inconclusive rate, and stability across multiple test runs.

## File Structure (< 440 lines each)
- `mod.rs`: Clean re-export facade maintaining 100% backward compatibility for all callers.
- `types.rs`: Core domain models (`SuiteKind`, `SuiteSpec`, `Thresholds`, `Expect`, `Allow`, `RunScore`, `RunStats`, `Check`, `SuiteResult`, `EvalSummary`, `EvalOpts`).
- `parser.rs`: Specification loader and schema validator (`parse_suite`, `load_suites`, `resolve_root`).
- `scoring.rs`: Scoring algorithms, glob matching, expectation matching, and suite statistical aggregation (`score_run`, `summarize_suite`, `glob_match`).
- `checks.rs`: Multi-run memory checks (`memory_checks`), change impact verification (`change_checks`), and fixture git repo builder (`build_fixture_repo`).
- `fixture.rs`: Ephemeral loopback mock server child processes (`Fixture`) and scan/agent executor dispatchers (`exec_qa`, `exec_agent`, `exec_repo`).
- `runner.rs`: Multi-suite execution coordinator and temp directory isolation (`run_eval`, `run_suite`, `run_once`).
- `report.rs`: Markdown summary generator and formatting tables (`render_markdown`).
- `tests.rs`: Unit test suite (35 unit tests).

## Public Interfaces
- `run_eval(opts: EvalOpts) -> Result<EvalSummary>`: Main evaluation suite entry point.
- `score_run(...) -> RunScore`: Scores single-run observations against expectations.
- `summarize_suite(...) -> SuiteResult`: Aggregates runs and evaluates thresholds.
- `parse_suite(text: &str, origin: &str) -> Result<SuiteSpec>`: Parses and validates suite specs.
- `load_suites(root: &Path, opts: &EvalOpts) -> Result<Vec<SuiteSpec>>`: Discovers suite files.
- `render_markdown(s: &EvalSummary) -> String`: Formats markdown report.

## Architectural Rules
1. **Isolated Execution**: Every run must use an isolated temp data directory and clean loopback socket; no state or network leaks.
2. **Environment Locking**: Process environment mutations are strictly guarded under `ENV_LOCK` with RAII `EnvGuard` cleanup.
3. **Deterministic Evaluation**: Threshold checks strictly gate without fuzzy tolerances; any unmet expectation fails the suite.

## Test Commands
```bash
cargo test --bin readyhai -- eval::tests
```
