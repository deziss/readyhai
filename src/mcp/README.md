# MCP (Model Context Protocol) Module

## Responsibility
Implements the JSON-RPC 2.0 stdio server providing AI coding agents and MCP clients with tools to execute readiness scans, enumerate security checks, inspect findings, and orchestrate autonomous multi-agent testing swarms.

## Architecture & Submodules
- `protocol.rs`: JSON-RPC 2.0 stdio transport loop, stdio fd isolation, lifecycle events, and error framing.
- `tools.rs`: MCP Tool schemas (`tools/list`) and invocation routing table (`tools/call`).
- `scanner.rs`: Readiness scan engine interface, allowed roots validation, and findings summarizer.
- `agent_bridge.rs`: Autonomous agent swarm execution, job concurrency limiter, status checkpoints, and route discovery.
- `mod.rs`: Public re-export facade maintaining 100% backward compatibility for all existing callers.
- `tests.rs`: Comprehensive test suite verifying RPC lifecycle, root confinement, SSRF protections, argument typing, and stdio isolation.

## Key Public Interfaces
- `serve_stdio() -> Result<()>`: Main entrypoint for ReadyHai's MCP server mode over stdio.
- `precheck(opts: &ScanOpts) -> Result<()>`: Path containment and SSRF network validation policy.
- `under_roots(p: &Path, roots: &[PathBuf]) -> bool`: Canonical path confinement checking.
- `handle(st: &mut State, req: Value) -> Option<Value>`: Core JSON-RPC message dispatcher.

## Security & Architectural Constraints
1. **Stdio Isolation**: Private copies of stdin/stdout are isolated; file descriptors 0 and 1 are redirected to `/dev/null` and stderr to prevent child processes from corrupting the JSON-RPC stream.
2. **Untrusted Data Banner**: All target-derived strings (findings, route titles, defect notes) are wrapped with the `UNTRUSTED` safety banner.
3. **Dry Run Enforcement**: Swarm runs default to `dry_run = true`. State-changing operations require operator approval via `READYHAI_MCP_ALLOW_WRITES=1`.

## Verification Commands
```bash
PATH="$HOME/.cargo/bin:$PATH" cargo test --bin readyhai -- mcp::tests
PATH="$HOME/.cargo/bin:$PATH" cargo clippy --bin readyhai -- -D warnings
```
