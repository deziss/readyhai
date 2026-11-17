//! Git remote host verification against built-in and scope allowlists.

use anyhow::{bail, Result};

use super::config::Scope;
use super::dns::{host_is_internal, host_matches};
use super::url::norm_host;

/// Public code hosts allowed for `git clone` with no scope.toml entry.
pub const DEFAULT_GIT_HOSTS: &[&str] = &[
    "github.com",
    "*.github.com",
    "gitlab.com",
    "*.gitlab.com",
    "bitbucket.org",
    "codeberg.org",
    "git.sr.ht",
];

/// A remote git clone host is allowed when it is a known public code host or is
/// listed under `[git] hosts`. (A listed host may be internal: that is the user
/// vouching for their own git server.) Public but unlisted hosts are allowed so
/// `github.com/...` just works; an unknown *internal* host is refused.
pub fn check_git_host(host: &str, scope: Option<&Scope>) -> Result<()> {
    let host = norm_host(host);
    if host.is_empty() {
        bail!("empty git host");
    }
    let listed = DEFAULT_GIT_HOSTS.iter().any(|p| host_matches(&host, p))
        || scope.is_some_and(|s| s.git.hosts.iter().any(|p| host_matches(&host, p)));
    if listed {
        return Ok(());
    }
    if host_is_internal(&host) {
        bail!(
            "git host '{host}' is internal and not listed — add it under [git] hosts in scope.toml to clone from it"
        );
    }
    Ok(())
}
