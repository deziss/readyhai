## Summary

Describe what changed and why.

## Verification

- [ ] `./scripts/version.sh check` passes
- [ ] `cargo fmt -- --check` passes
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo test` passes
- [ ] `cargo run --quiet -- eval --suite all --k 2` passes (if Rust/eval/agent logic changed)
- [ ] `python3 -m unittest discover -s runners/context_retriever/tests -t . -v` passes
- [ ] `cd frontend && npm ci && npm run lint && npx tsc --noEmit && npm test` passes (if `frontend/` changed)
- [ ] Docs (`README.md`, `docs/`, `CHANGELOG.md`) updated where behavior or config changed
