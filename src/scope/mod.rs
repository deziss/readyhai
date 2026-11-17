//! Rules of engagement for network targets (scope.toml).
//!
//! Policy:
//! - A **public** host is allowed without an entry and defaults to **full testing** (`nonprod = true`):
//!   both non-intrusive actions and intrusive actions (writes, attack payloads, load, agent swarm)
//!   are allowed for any URL unless it is explicitly marked `env = "prod"` in scope.toml.
//! - A **wildcard** `*` is supported in scope.toml to match any host (internal ones too). An exact
//!   entry beats a wildcard and `prod` beats `nonprod`, so `*` + a `prod` entry keeps that one host
//!   read-only.
//! - An **internal** host (loopback, RFC1918, link-local/metadata, CGNAT, unique-local v6, and the
//!   names `localhost`, `*.localhost`, `host.docker.internal`) is refused unless it is listed or
//!   matched by a scope entry (e.g. `host = "*"`).
//! - A listed host always uses its own `env`; `prod` stays read-only.
//! - Intrusive actions on an *unlisted* name that does not resolve are refused: it cannot be told
//!   apart from an internal host, so the guard fails closed.
//! - A scope file that is configured (`READYHAI_SCOPE` / `--scope`) but missing, a directory or
//!   invalid is an **error**, never "no scope".
//! - Remote git clones use the `[git]` host allowlist (seeded with the public
//!   code hosts, so github/gitlab work out of the box; `*` matches all).

#![allow(unused_imports)]

pub mod config;
pub mod decision;
pub mod dns;
pub mod git_guard;
pub mod ip;
pub mod url;

#[cfg(test)]
mod tests;

pub use config::{active, from_env, set_active, GitCfg, PerfLimits, ResilienceCfg, Scope, ScopeHost};
pub(crate) use config::load_configured;
pub use decision::{check, check_host, egress_guard, Egress};
pub(crate) use decision::{decide, Decision};
pub use dns::{host_is_internal, host_matches, resolve_name};
#[cfg(test)]
pub use dns::test_dns;
pub use git_guard::{check_git_host, DEFAULT_GIT_HOSTS};
pub use ip::{classify_host, is_internal_ip, is_internal_name, HostClass};
pub use url::{norm_host, parse_web_url, url_host};
