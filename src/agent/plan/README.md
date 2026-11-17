# Agent Plan Module (`src/agent/plan/`)

## 1. Responsibility
Deterministic, ground-truth-first security test planning for autonomous agent execution. Constructs crawl-grounded baselines, OpenAPI schema-derived boundary and negative probes, stateful multi-step chains, concurrency bursts, and LLM-assisted adversarial test expansions.

## 2. Directory Structure & Single Responsibilities
- `mod.rs`: Pipeline facade and orchestration (`plan_cases`, `plan_cases_seeded`, `plan_cases_changed`, `plan_cases_remembered`).
- `types.rs`: Core domain models (`Depth`, `PlanOutcome`), PRNG seeding (`SeededRng`), and planning limits.
- `helpers.rs`: Case constructors (`mk`), user/actor resolution, case key deduplication, and template regexes.
- `surface.rs`: Route surface detection (`InputSurface`), login wall detection, route descriptions, and unexecutable ledger rows.
- `baseline.rs`: Grounded crawl baseline test case generation (liveness, sensitive files, CORS, client-side injection).
- `openapi.rs`: OpenAPI spec-driven planning (schema parameter sampling, contract extraction, boundary probes, concurrency bursts, and stateful BOLA chains).
- `llm.rs`: LLM-assisted adversarial test case synthesis, route verification against discovered endpoints, and JSON schema guards.
- `directives.rs`: Targeted operator directive handling (canary prompt injections, protected auth sessions, 100KB boundary limits).
- `tests.rs`: Comprehensive isolated unit and integration test suite (52 tests).

## 3. Public Interfaces
- `plan_cases(llm, target, profile, d, instructions, creds) -> PlanOutcome`
- `plan_cases_seeded(llm, target, profile, d, instructions, creds, seed) -> PlanOutcome`
- `plan_cases_changed(llm, target, profile, d, instructions, creds, seed, change) -> PlanOutcome`
- `plan_cases_remembered(llm, target, profile, d, instructions, creds, seed, change, memory) -> PlanOutcome`
- `plan_cases_remembered_with_whitebox(llm, target, profile, d, instructions, creds, seed, change, memory, whitebox) -> PlanOutcome`
- `seed_from_run_id(run_id) -> u64`
- `plans_from_spec(profile) -> bool`

## 4. Architectural Rules & Invariants
- **Deterministic Planning**: All randomness derives from `seed_from_run_id(run_id)` (SHA-256 of run id).
- **Grounded Routes**: The LLM may only ADD test cases; every proposed endpoint is strictly verified against `Known` discovered routes. Unknown routes are dropped, never remapped.
- **Change Awareness**: Changed operations identified in code diffs are prioritized and planned in full even under `Quick` profiles.
- **Memory Priority**: Re-tests of previously confirmed defects run first via fingerprinting (`regression_of`).

## 5. Verification Commands
- `cargo test --bin readyhai -- agent::plan::tests`
- `cargo clippy -- -D warnings`
