# Agent Triage Module (`src/agent/triage/`)

## Responsibility
Deterministic defect derivation, failure clustering, endpoint normalization, server error aggregation, independent verification mapping, and guarded LLM advisory notes for the ReadyHai agent.

## Submodules
- `rules.rs`: Deterministic severity rules table (`severity_for`) and OWASP/CWE category metadata (`class_meta`).
- `grouping.rs`: Endpoint URL path template normalization (`endpoint_template`, `path_of`), error signatures (`server_error_signature`), and multi-endpoint error clustering (`merge_same_server_error`).
- `derivation.rs`: Core defect derivation engine (`derive_defects`, `derive_defects_verified`), verification correlation (`verification_of`), and severity scoring.
- `llm_advisory.rs`: Advisory prose enrichment (`add_llm_notes`) with invariant guarding of deterministic fields.
- `tests.rs`: Comprehensive test suite covering severity rules, verification records, leftover cleanup, server error merging, and LLM prose safety.

## Public Interfaces
- `derive_defects`, `derive_defects_verified`
- `severity_for`, `endpoint_template`, `path_of`
- `add_llm_notes`

## Invariants & Rules
- Defect severity is strictly deterministic; the LLM may only attach advisory prose (`ai_note`) to already existing defects.
- Every `FAIL` execution result maps to exactly one defect.
- Failures on dynamic record paths (`/orders/1`, `/orders/2`) are clustered under their templated route (`/orders/{id}`).
- Same server errors on 3+ endpoints are folded into a single unified defect.

## Verification
```bash
cargo test --bin readyhai -- agent::triage::tests
cargo clippy --bin readyhai -- -D warnings
```
