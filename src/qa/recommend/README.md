# QA Recommend Module (`src/qa/recommend/`)

## Responsibility
Deterministic release recommendations (Go / Conditional Go / No-Go / Inconclusive), exit criteria validation, evidence adequacy checking, and executive summary synthesis.

## Submodules
- `fingerprint.rs`: Defect fingerprinting and baseline finding status resolution.
- `evidence.rs`: Execution thresholds (`MIN_EXECUTED_PCT`, `EVIDENCE_CRITERION`), area labels, and unexecuted area detection.
- `criteria.rs`: Exit criteria definitions and automated gate validation.
- `builder.rs`: Full QA report building (`build`), conditions generation, and executive summary synthesis.
- `tests.rs`: Comprehensive unit test suite covering recommendation gates, role coverage, and defect mapping.

## Public Interfaces
- `build(col: QaCollector, run: &Run, qa: &QaCtx, mode: &str) -> QaReport`
- `fingerprint(rule: &str, fp_key: &str) -> String`
- `MIN_EXECUTED_PCT`, `EVIDENCE_CRITERION`, `area_label`

## Rules
- Recommendations are computed strictly via deterministic criteria, never chosen by an LLM.
- Below 50% execution of planned cases yields `Inconclusive` unless a known failure or blocking defect is found (which forces `No-Go`).
- A merged defect is marked `New` if any member is new, and `Suppressed` only if all members are suppressed.

## Verification
```bash
cargo test --bin readyhai -- qa::recommend::tests
cargo clippy --bin readyhai -- -D warnings
```
