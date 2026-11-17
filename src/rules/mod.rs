//! Native readiness rules (owned by the rules agent).

pub mod ci;
pub mod compose;
pub mod deps;
pub mod dockerfile;
pub mod facts;
pub mod k8s;
pub mod repo;

#[cfg(test)]
mod tests;

pub use facts::detect_facts;

use crate::checks::Check;
use crate::ctx::Ctx;
use crate::model::{CheckOutput, CheckStatus, Profile, TargetKind};
use crate::snapshot::Snapshot;
use serde_norway::Value;

// ---------- YAML helpers ----------

pub(crate) fn path<'a>(v: &'a Value, p: &[&str]) -> Option<&'a Value> {
    p.iter().try_fold(v, |v, k| v.get(*k))
}

pub(crate) fn truthy(v: Option<&Value>) -> bool {
    v.is_some_and(|v| {
        v.as_bool()
            .unwrap_or_else(|| v.as_str().is_some_and(|s| s.eq_ignore_ascii_case("true")))
    })
}

pub(crate) fn non_empty_map(v: Option<&Value>) -> bool {
    v.and_then(Value::as_mapping).is_some_and(|m| !m.is_empty())
}

pub(crate) fn str_of(v: Option<&Value>) -> &str {
    v.and_then(Value::as_str).unwrap_or("?")
}

// ---------- check plumbing ----------

pub(crate) type CheckFn = fn(&Ctx, &Snapshot) -> CheckOutput;

pub(crate) fn repo_check(id: &str, title: &str, f: CheckFn) -> Check {
    Check::new(id, title, &[TargetKind::Repo], Profile::Quick, move |ctx| {
        Ok(match &ctx.snapshot {
            Some(s) => f(ctx, s),
            None => CheckOutput::status(CheckStatus::NotApplicable("no snapshot".into())),
        })
    })
}

pub(crate) fn na(why: &str) -> CheckOutput {
    CheckOutput::status(CheckStatus::NotApplicable(why.into()))
}

pub fn checks() -> Vec<Check> {
    vec![
        repo_check(
            "readiness.dockerfile",
            "Dockerfile hardening",
            dockerfile::dockerfile_check,
        ),
        repo_check(
            "readiness.deps",
            "Dependency pinning and lockfiles",
            deps::deps_check,
        ),
        repo_check(
            "readiness.compose",
            "Docker Compose hardening",
            compose::compose_check,
        ),
        repo_check(
            "readiness.k8s",
            "Kubernetes manifest hardening",
            k8s::k8s_check,
        ),
        repo_check("readiness.ci", "CI pipeline security stages", ci::ci_check),
        repo_check("readiness.repo", "Repository hygiene", repo::repo_check_fn),
    ]
}
