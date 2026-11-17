# Supply-Chain & API-Contract Checks Module (`src/supply`)

## Responsibility
Executes supply-chain and API-contract quality and security audits:
- OSV call-graph reachability and AST import verification.
- OpenSSF Scorecard remote repository analysis.
- Spectral OpenAPI schema linting.
- oasdiff backward-compatibility breaking change detection.
- Mutation test coverage report aggregation (cargo-mutants, Stryker, mutmut).

## Architecture & Submodules
- `helpers.rs` (~30 lines): Shared JSON field extraction (`sv`), workspace-relative path canonicalization (`src_rel`), severity demotion (`lower`), and repository target filtering.
- `osv.rs` (~285 lines): OSV vulnerability scanner runner (`osv_reachability`), CVSS rating resolver, fix version locator, reachability level adjustment, and AST import enrichment.
- `scorecard.rs` (~195 lines): OpenSSF Scorecard runner (`scorecard`), git remote URL resolution (`remote_url`), GitHub repository slug derivation (`github_slug`), and posture scoring.
- `api_contract.rs` (~265 lines): OpenAPI discovery (`find_specs`), baseline matching (`baseline_for`), Spectral schema linter (`spectral`), and oasdiff breaking change checker (`oasdiff`).
- `mutation.rs` (~175 lines): Multi-framework mutation test parser (`parse_cargo_mutants`, `parse_stryker`, `parse_mutmut_meta`) and threshold evaluator (`mutation`).
- `mod.rs` (~45 lines): Public registration suite (`checks()`) and facade re-exports.
- `tests.rs` (~245 lines): Comprehensive unit tests covering reachability demotion, AST enrichment, Scorecard findings, OpenAPI diffs, and mutation thresholds.

## Public Interfaces
- `checks() -> Vec<Check>`
- `parse_osv(json: &str) -> Result<Vec<Finding>>`
- `enrich_osv_with_ast(findings: &mut [Finding], root: &Path)`
- `parse_scorecard(json: &str) -> Result<Vec<Finding>>`
- `parse_spectral(json: &str) -> Result<Vec<Finding>>`
- `parse_oasdiff(json: &str, spec: &str) -> Result<Vec<Finding>>`
- `parse_cargo_mutants`, `parse_stryker`, `parse_mutmut_meta`

## Security Invariants
1. Offline vulnerability databases are strictly required; network access is disabled during local container execution.
2. AST import checks only verify presence in source code and never automatically demote finding severity.
3. Git remote URLs are stripped of authentication credentials before logging or querying Scorecard APIs.

## Verification
```bash
cargo test --bin readyhai -- supply::tests
cargo clippy --bin readyhai -- -D warnings
```
