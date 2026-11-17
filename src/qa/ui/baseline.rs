use std::path::{Path, PathBuf};
use anyhow::Result;

pub fn copy_dir_pngs(from: &Path, to: &Path, skip_diff: bool) -> usize {
    let Ok(rd) = std::fs::read_dir(from) else {
        return 0;
    };
    let _ = std::fs::create_dir_all(to);
    let mut n = 0;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.ends_with(".png")
            && !(skip_diff && name.ends_with(".diff.png"))
            && std::fs::copy(e.path(), to.join(&name)).is_ok()
        {
            n += 1;
        }
    }
    n
}

/// Directory holding the accepted visual baseline PNGs of a target.
pub fn visual_baseline_dir(data: &Path, target_key: &str) -> PathBuf {
    data.join("baselines").join(target_key).join("visual")
}

/// Promote the screenshots of run `run_dir` (`artifacts/ui/shots/*.png`, diff images excluded) to
/// the visual baseline, replacing the previous PNGs. Returns how many were promoted.
pub fn accept_visual_baseline_in(data: &Path, target_key: &str, run_dir: &Path) -> Result<usize> {
    let shots = run_dir.join("artifacts").join("ui").join("shots");
    let has_png = std::fs::read_dir(&shots)
        .map(|rd| {
            rd.flatten().any(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.ends_with(".png") && !n.ends_with(".diff.png")
            })
        })
        .unwrap_or(false);
    if !has_png {
        anyhow::bail!("run recorded no UI screenshots to promote");
    }
    let dst = visual_baseline_dir(data, target_key);
    let _ = std::fs::remove_dir_all(&dst);
    let n = copy_dir_pngs(&shots, &dst, true);
    if n == 0 {
        anyhow::bail!("could not copy the run's screenshots to {}", dst.display());
    }
    Ok(n)
}

/// `baseline accept <run>` hook for the visual baselines of that run.
#[allow(dead_code)]
pub fn accept_visual_baseline(target_key: &str, run_id: &str) -> Result<usize> {
    accept_visual_baseline_in(
        &crate::engine::data_dir(),
        target_key,
        &crate::engine::run_dir(run_id),
    )
}
