# Code Audit Module (`src/code_audit`)

## Responsibility
Native Tree-sitter AST & cross-file security code audit for Python, JS/TS, Go, and PHP. Provides true AST function, import, endpoint, guard-middleware, and local variable taint parsing; cross-file taint traversal linking routes to dangerous sinks (SQLi, CmdExec, SSRF, Path Traversal, SSTI); and authentication guard consistency audits.

## Files
- `types.rs`: Core data structures (`Lang`, `SinkKind`, `SinkHit`, `DiscoveredEndpoint`, `CodeInventory`, `FunctionInfo`, `RawEndpoint`), bounds (`MAX_FILES`, `MAX_FILE_BYTES`), and remediation strings.
- `ast.rs`: Tree-sitter AST navigation, node extraction, quote stripping, guard detection, static string checks, and dynamic expression classification.
- `classify.rs`: Sink classification (`classify_sink`) across dangerous APIs and missing guard detection (`detect_missing_guards`).
- `python.rs`: Python AST parser, route decorator extraction (`parse_py_route_decorator`), FastAPI parameter inspection, and taint flow analysis.
- `javascript.rs`: JS/TS/Next.js App Router AST parser, import resolution (`js_pkg_name`), route registration, and middleware auditing.
- `go.rs`: Go AST parser, HTTP handler/route detection, and command/SQL sink inspection.
- `php.rs`: PHP AST parser, namespace use collection, and sink detection.
- `audit.rs`: Repository traversal (`audit_tree`, `audit_tree_filtered`), cross-file call-graph resolution (up to 3 hops), and check runner (`code_audit_check`).
- `mod.rs`: Module facade, public re-exports, and `checks()` catalog registration.
- `tests.rs`: Comprehensive test suite verifying cross-file taint analysis, missing guards, and false positive avoidance.

## Public Interfaces
```rust
pub fn checks() -> Vec<Check>;
pub fn audit_tree(root: &Path) -> CodeInventory;
pub fn audit_tree_filtered(root: &Path, denied: &BTreeSet<&str>) -> CodeInventory;
pub fn package_is_imported(imported: &BTreeSet<String>, pkg: &str) -> bool;
pub fn called_packages(root: &Path) -> BTreeSet<String>;
```

## Test Commands
```bash
cargo test --bin readyhai -- code_audit::tests
cargo clippy --bin readyhai -- -D warnings
```
