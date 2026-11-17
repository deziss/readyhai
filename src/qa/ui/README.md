# UI Exploratory QA Module (`src/qa/ui`)

## Responsibility
Executes headless browser exploration (responsive layout, axe-core accessibility, web vitals, form boundaries, multi-persona user journeys, and visual regression baselines) using Playwright.

## Submodules
- `image.rs`: Resolves Playwright runner image tags (`READYHAI_PLAYWRIGHT_IMAGE`, local build, or published ghcr.io image) and rewrites target URLs for Docker networking.
- `baseline.rs`: Manages approved visual baseline screenshots and promotional workflow (`accept_visual_baseline_in`).
- `model.rs`: Type-safe AST structures deserializing `qa-ui.json` emitted by the runner script.
- `builder/`: Pure transformations compiling raw runner metrics into `TestCase`, `TestResult`, `Defect`, and `CoverageMatrix` data models:
  - `pages.rs`: Evaluates responsive horizontal overflows, axe-core a11y violations, Core Web Vitals (LCP/CLS), and screenshot pixel diffs.
  - `journeys.rs`: Detects client/server form validation gaps, evaluates multi-persona journeys with resilient self-healing locators, and detects Markov state graph navigation dead ends.
  - `mod.rs`: Combines section builders into `build()`.
- `exec.rs`: Orchestrates container lifecycle, temporary `SecretsGuard` storageState cleanup, and artifact publishing.
- `mod.rs`: Public check registration (`checks()`) and backward-compatible re-exports.
- `tests.rs`: Comprehensive test suite verifying report deserialization, visual baselines, and fault tolerance.

## Architectural Rules
1. **Secrets Hygiene**: Role authentication cookies are stored in ephemeral directories guarded by `SecretsGuard`, ensuring deletion on drop even on execution failure.
2. **Profile Gating**: Form submission fuzzing, visual baselines, and multi-step journeys require `--profile standard` on verified non-production targets.
3. **Resilient Locators**: Journey step failures report self-healing locator telemetry to prioritize stable DOM attributes.

## Verification
```bash
cargo test --bin readyhai -- qa::ui::tests
cargo clippy --bin readyhai -- -D warnings
```
