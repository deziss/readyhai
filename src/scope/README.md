# Scope Module

The `scope` module implements strict, fail-closed target engagement policies and egress guards for network requests and git clones.

## Architecture

- **`url.rs`**: Canonical URL host parsing, scheme enforcement (`http`/`https`), and authority normalization.
- **`ip.rs`**: Single source of truth for internal IP ranges (loopback, RFC1918, link-local, CGNAT, documentation, multicast, IPv6 equivalents) and special internal hostnames.
- **`dns.rs`**: System resolver abstraction with test isolation mock support and wildcard domain matching.
- **`config.rs`**: TOML configuration parser for `scope.toml` (`Scope`, `ScopeHost`, `GitCfg`, `PerfLimits`, `ResilienceCfg`) with fail-closed validation.
- **`git_guard.rs`**: Remote repository clone destination allowlist validation.
- **`decision.rs`**: High-level egress enforcement decisions (`check`, `decide`, `egress_guard`).
- **`tests.rs`**: Comprehensive test suite verifying DNS overrides, security boundaries, and precedence rules.
