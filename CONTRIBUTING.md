# Contributing to ReadyHai

Thank you for contributing to ReadyHai! ReadyHai is a self-hosted security scanner, autonomous pentest & QA agent, and production-readiness gate.

## Local Development

### Prerequisites

- **Rust** (stable, 2024 edition) with `rustfmt` and `clippy`
- **Python 3.12+** (required for eval fixtures and context retriever tests)
- **Node.js 24+** (only needed for `frontend/` lint/typecheck/tests and Playwright runner changes)
- **Docker** (optional; required for container-based tool scanners and UI runner checks, not required for `cargo test` or `readyhai eval`)

### Verification Checks

CI (`.github/workflows/ci.yml`) enforces the following checks before merge:

```bash
# 1. Version consistency across VERSION, Cargo.toml, runners/playwright/package.json
./scripts/version.sh check

# 2. Formatting & linting
cargo fmt -- --check
cargo clippy -- -D warnings

# 3. Unit & integration tests
cargo test

# 4. Release binary & eval gate (10 deterministic suites, k = 2)
cargo build --release
cargo run --quiet -- eval --suite all --k 2

# 5. Context retriever unit tests
python3 -m unittest discover -s runners/context_retriever/tests -t . -v

# 6. Frontend checks (Node 24)
cd frontend && npm ci && npm run lint && npx tsc --noEmit && npm test
```

## Pull Request Guidelines

- Keep verdicts deterministic and fail-closed; never invent fallback scores or suppress missing evidence silently.
- Add or update unit tests and deterministic eval fixtures (`tests/eval/`) when adding detection rules, attack modules, or agent behavior.
- Update the matching documentation in `README.md`, `docs/`, and `CHANGELOG.md` whenever behavior, flags, configuration keys, or built-in check counts change.
- Never commit secrets, local `.env` files, `scope.toml`, or test runtime reports.

## Licensing

By submitting a contribution to this repository, you agree that your contribution is licensed under the **GNU Affero General Public License v3.0 only (`AGPL-3.0-only`)**. See [`LICENSE`](LICENSE) for the full license text.
