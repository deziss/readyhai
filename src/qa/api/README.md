# API Functional Testing Module (`src/qa/api`)

## Responsibility
Coordinates OpenAPI-driven functional testing: synthesizes positive/boundary/negative inputs, verifies schemas and contracts, assesses authorization matrices, tests stateful CRUD/BOLA workflows, and detects API breaking changes against stored baselines.

## Files
- `mod.rs`: Check registration (`qa.api.authz`, `qa.api.functional`, `qa.api.stateful`) and public facade re-exports.
- `baseline.rs`: Spec baseline storage, comparison, and promotion (`stage_dir`, `accept_spec_baseline`).
- `planning.rs`: Risk-weighted test planning and request budgeting across endpoints.
- `defect_types.rs`: Defect references, execution request payloads, and rerun status tracking.
- `helpers.rs`: Query helpers, envelope unnesting (`field`, `list_items`), unlikely IDs, and latency note formatters.
- `runner/`: Test execution harness:
  - `types.rs`: `Runner<'a>` structure and constructor.
  - `cases.rs`: Test registration, results recording, skip tracking, and reruns.
  - `exchange.rs`: HTTP dispatch, defect creation, resource cleanup tracking, and scratch IDs.
  - `finish.rs`: Latency calculation, evidence status derivation, and check finalization.
- `functional/`: Functional test execution:
  - `case_runner.rs`: Execution of individual positive, boundary, and negative test cases.
  - `probes.rs`: Pagination edge case tests, rate limit probes, and spec breaking change comparisons.
  - `mod.rs`: `functional` check coordinator.
- `authz.rs`: Authorization matrix testing.
- `contract.rs`: OpenAPI contract and schema conformance verification.
- `exec.rs`: Low-level HTTP exchange execution and curl command generator.
- `latency.rs`: Latency percentiles and threshold evaluation.
- `spec.rs`: OpenAPI 3.0/3.1 document parsing.
- `stateful.rs`: Multi-step CRUD and BOLA lifecycle tests.
- `synth.rs`: Automatic input generation from JSON schema.
- `tests.rs`: Comprehensive functional test suite.
- `testsrv.rs`: Mock HTTP server fixture for local test execution.

## Public Interfaces
- `checks() -> Vec<Check>`
- `functional(ctx: &Ctx) -> anyhow::Result<CheckOutput>`
- `plan_order<'a>(qa: &QaCtx, spec: &'a Spec) -> Vec<Planned<'a>>`
- `accept_spec_baseline_in(data: &Path, key: &str, run_dir: &Path) -> anyhow::Result<Vec<&'static str>>`

## Tests
```bash
cargo test --bin readyhai -- qa::api::tests
```
