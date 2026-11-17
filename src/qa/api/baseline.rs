//! OpenAPI spec baseline capture, staging, promotion, and caching.
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::spec::{self, Spec};
use crate::ctx::Ctx;

static SPEC_CACHE: Mutex<Option<(String, Option<Arc<Spec>>)>> = Mutex::new(None);

/// Where the run keeps what `baseline accept` promotes (spec snapshot, op list).
pub fn stage_dir(run_dir: &Path) -> PathBuf {
    run_dir.join("artifacts").join("qa-baseline")
}

/// Promote the spec baselines staged by run `run_dir` (`<key>.spec-full.json` for breaking-change
/// diffs, `<key>.spec.json` for "new since baseline" risk). Returns what was promoted.
pub fn accept_spec_baseline_in(
    data: &Path,
    key: &str,
    run_dir: &Path,
) -> anyhow::Result<Vec<&'static str>> {
    let st = stage_dir(run_dir);
    let dir = data.join("baselines");
    let mut done = vec![];
    for (from, to, what) in [
        (
            "spec-full.json",
            format!("{key}.spec-full.json"),
            "spec snapshot",
        ),
        (
            "spec-ops.json",
            format!("{key}.spec.json"),
            "spec operation list",
        ),
    ] {
        let src = st.join(from);
        if src.is_file() {
            std::fs::create_dir_all(&dir)?;
            std::fs::copy(&src, dir.join(to))?;
            done.push(what);
        }
    }
    if done.is_empty() {
        anyhow::bail!("run recorded no OpenAPI spec snapshot (no --spec / spec not loaded)");
    }
    Ok(done)
}

/// `baseline accept <run>` hook for the spec baselines of that run.
#[allow(dead_code)]
pub fn accept_spec_baseline(target_key: &str, run_id: &str) -> anyhow::Result<Vec<&'static str>> {
    accept_spec_baseline_in(
        &crate::engine::data_dir(),
        target_key,
        &crate::engine::run_dir(run_id),
    )
}

pub(crate) fn cached_spec(ctx: &Ctx) -> anyhow::Result<Option<Arc<Spec>>> {
    let mut g = SPEC_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((id, s)) = g.as_ref()
        && *id == ctx.run_id
    {
        return Ok(s.clone());
    }
    let s = spec::load(ctx)?.map(Arc::new);
    *g = Some((ctx.run_id.clone(), s.clone()));
    Ok(s)
}
