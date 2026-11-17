//! Evidence execution thresholds, area labels, and unexecuted area detection.

use super::super::model::Area;
use crate::model::{CheckStatus, Run};

/// Below this share of planned cases executed the run proves nothing either way.
pub const MIN_EXECUTED_PCT: f64 = 50.0;

/// Name of the exit criterion that decides "insufficient evidence" (blocking, but it yields
/// Inconclusive, not No-Go: nothing was shown to be broken, nothing was shown to work).
pub const EVIDENCE_CRITERION: &str =
    "Sufficient test evidence (≥50% of planned cases executed, requested core area ran)";

pub fn area_label(a: Area) -> &'static str {
    match a {
        Area::Api => "API functional testing",
        Area::Ui => "UI exploratory testing",
        Area::Perf => "Performance testing",
        Area::Resilience => "Resilience testing",
        Area::Suite => "Test-suite quality",
        Area::Release => "Release quality",
    }
}

/// Check-id prefixes whose checks produce the cases of `a`.
pub fn area_checks(a: Area) -> &'static [&'static str] {
    match a {
        Area::Api => &["qa.api."],
        Area::Ui => &["qa.ui"],
        Area::Perf => &["qa.perf"],
        Area::Resilience => &["qa.resilience"],
        Area::Suite | Area::Release => &["qa.suite", "qa.release"],
    }
}

/// An area that executed no case: why (from the check status, when a check of the area is in
/// the run) and whether it was requested (a check ran but ended Skipped/Errored/Partial).
pub struct NotRun {
    pub area: Area,
    pub reason: String,
    pub requested: bool,
}

pub fn not_run(area: Area, executed_in_area: usize, run: &Run) -> Option<NotRun> {
    if executed_in_area > 0 {
        return None;
    }
    let mut reason = String::new();
    let mut requested = false;
    let mut present = false;
    for c in run
        .checks
        .iter()
        .filter(|c| area_checks(area).iter().any(|p| c.id.starts_with(p)))
    {
        present = true;
        match &c.status {
            CheckStatus::Skipped(r) | CheckStatus::Errored(r) | CheckStatus::Partial(r) => {
                requested = true;
                if reason.is_empty() {
                    reason = r.clone();
                }
            }
            CheckStatus::NotApplicable(r) if reason.is_empty() => reason = r.clone(),
            _ => {}
        }
    }
    if reason.is_empty() {
        reason = if present {
            "no case executed".into()
        } else {
            "not part of this run (profile or target)".into()
        };
    }
    Some(NotRun {
        area,
        reason,
        requested,
    })
}
