# Roles Init Module (`src/qa/roles/init`)

## Responsibility
Derives an automated `roles.toml` test-role skeleton and expected-access authorization matrix from an OpenAPI 3.x specification.

## Submodules
- `openapi.rs`: Parses OpenAPI 3.x security schemes, operations, and role declarations (`x-roles`).
- `trie.rs`: Hierarchical prefix trie (`Node`) for collapsing allowed and denied endpoints into compact globs.
- `derive.rs`: Derivation logic establishing ordinary vs privileged accounts (`derive()`) and access verification.
- `render.rs`: Serializes derived role configurations into formatted TOML markup.
- `fs.rs`: Filesystem persistence enforcing strict POSIX file mode 0600 and directory mode 0700.
- `mod.rs`: CLI command runner (`run()`) and module facade.
- `tests.rs`: Complete test suite covering scheme extraction, glob minimization, and permission gating.

## Security Rules
1. **Secret Redaction**: Only environment variable names (`RH_<ROLE>_TOKEN`) are written; credentials are never serialized.
2. **Permission Guard**: Output files are forced to mode `0600` inside `0700` directories. Symlinks are rejected.
3. **No Network**: Spec analysis operates solely on local files to prevent SSRF.

## Verification
```bash
cargo test --bin readyhai -- qa::roles::init::tests
cargo clippy --bin readyhai -- -D warnings
```
