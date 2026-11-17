# Browser Security Module (`src/agent/browser_sec`)

## Responsibility
Executes Phase 5 browser and client-side security verification for ReadyHai autonomous agent. Orchestrates real headless Chromium instrumentation (when Docker/Playwright container are available) and deterministic offline DOM/Stored XSS verification.

## Architecture & Submodules
- `models.rs` (~140 lines): Type-safe AST structures for Chromium security findings (`BrowserSecReport`, `BrowserXssHit`, `BrowserDomSink`, `BrowserStorageLeak`, etc.) and URL resolution helpers.
- `redact.rs` (~30 lines): Defense-in-depth secret scrubbing (`redact_secret_preview`, `jwt_re`) ensuring zero raw JWTs or credential previews escape to reports or disk.
- `report_parser.rs` (~280 lines): AST converter translating raw Chromium telemetry into structured `PlannedCase` and `CaseExecutionResult` records.
- `html_analyzer.rs` (~255 lines): Deterministic HTML DOM analyzer, form discovery (`extract_post_html_forms`), danger route filters, and snapshot accumulator.
- `playwright.rs` (~140 lines): Headless Chromium container runner (`agent_browser.mjs`) with credential isolation and automatic cleanup.
- `engine.rs` (~215 lines): Phase 5 pipeline orchestrator (`run_browser_security`) coordinating synthetic case generation, execution slicing, and budget absorption.
- `mod.rs` (~20 lines): Facade providing 100% backward-compatible re-exports.
- `tests.rs` (~255 lines): Unit tests for parser verification, AST translation, and end-to-end DOM/Stored XSS detection.

## Public Interfaces
- `run_browser_security(...) -> BrowserSecOutcome`
- `results_from_browser_report(rep: &BrowserSecReport, target: &str) -> (Vec<PlannedCase>, Vec<CaseExecutionResult>)`
- `BrowserSecOutcome`, `BrowserSecReport`, and related data transfer objects.

## Security Invariants
1. Raw JWTs and passwords must never be stored in findings, results, or evidence files.
2. Temporary input credentials on disk (`browser-sec-input.json`) must be chmod 0600 and deleted immediately after container execution.
3. Form actions targeting destructive keywords (`/delete`, `/remove`, `/drop`, `/reset`, `/logout`) are strictly excluded from automated mutation.

## Verification
```bash
cargo test --bin readyhai -- agent::browser_sec::tests
cargo clippy --bin readyhai -- -D warnings
```
