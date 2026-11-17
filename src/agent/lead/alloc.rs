//! Budget slicing and fair-share allocation across areas.

use std::time::Duration;

use super::area::{Area, AreaNeed, MIN_AREA_WALL};
use crate::agent::budget::SliceLimits;
use crate::agent::exec::is_mutating;
use crate::agent::types::{PlannedCase, Quota};

/// What is there to share out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Available {
    pub steps: usize,
    pub requests: usize,
    pub wall: Duration,
    pub llm_calls: usize,
}

/// What one area is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    pub area: Area,
    pub steps: usize,
    pub requests: usize,
    pub wall: Duration,
    pub llm_calls: usize,
}

impl Grant {
    pub(super) fn limits(&self) -> SliceLimits {
        SliceLimits {
            steps: self.steps,
            requests: self.requests,
            wall: self.wall,
            llm_calls: self.llm_calls,
        }
    }

    pub(super) fn quota(&self) -> Quota {
        Quota {
            steps: self.steps,
            requests: self.requests,
            wall_ms: self.wall.as_millis() as u64,
            llm_calls: self.llm_calls,
        }
    }
}

/// Share `total` units by `weights`, no one above its cap; what the caps leave is not given out.
/// Integer arithmetic with the largest-remainder rule (ties to the earlier index), repeated while
/// capped shares free units for the others: the same inputs always give the same answer.
pub fn share_capped(total: usize, weights: &[u64], caps: &[usize]) -> Vec<usize> {
    let n = weights.len();
    let mut out = vec![0usize; n];
    let mut left = total;
    while left > 0 {
        let active: Vec<usize> = (0..n).filter(|&i| out[i] < caps[i]).collect();
        if active.is_empty() {
            break;
        }
        let wsum: u128 = active.iter().map(|&i| weights[i].max(1) as u128).sum();
        let mut give = vec![0usize; n];
        let mut rem: Vec<(u128, usize)> = vec![];
        let mut given = 0usize;
        for &i in &active {
            let exact = left as u128 * weights[i].max(1) as u128;
            let q = ((exact / wsum) as usize).min(caps[i] - out[i]);
            give[i] = q;
            given += q;
            rem.push((exact % wsum, i));
        }
        rem.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        let mut spare = left - given;
        for &(_, i) in &rem {
            if spare == 0 {
                break;
            }
            if out[i] + give[i] < caps[i] {
                give[i] += 1;
                spare -= 1;
            }
        }
        let moved: usize = give.iter().sum();
        if moved == 0 {
            break;
        }
        for i in 0..n {
            out[i] += give[i];
        }
        left -= moved;
    }
    out
}

/// Split `avail` over the areas. Steps are capped at the area's case count, requests at its demand
/// (and `reserve_requests` of them are held back), wall clock is the area's weighted share of the
/// window times the worker count (so a lone worker gets its fair share and parallel ones may each
/// use most of the window), never below [`MIN_AREA_WALL`] and never above the window.
pub fn allocate(
    needs: &[AreaNeed],
    avail: &Available,
    reserve_requests: usize,
    workers: usize,
) -> Vec<Grant> {
    let weights: Vec<u64> = needs.iter().map(|n| n.weight).collect();
    let steps = share_capped(
        avail.steps,
        &weights,
        &needs.iter().map(|n| n.cases).collect::<Vec<_>>(),
    );
    let requests = share_capped(
        avail.requests.saturating_sub(reserve_requests),
        &weights,
        &needs.iter().map(|n| n.requests).collect::<Vec<_>>(),
    );
    let llm = share_capped(
        avail.llm_calls,
        &weights,
        &vec![avail.llm_calls; needs.len()],
    );
    let window = avail.wall.as_millis();
    let wsum: u128 = weights
        .iter()
        .map(|w| (*w).max(1) as u128)
        .sum::<u128>()
        .max(1);
    let floor = MIN_AREA_WALL.as_millis().min(window);
    needs
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let raw = window * workers.max(1) as u128 * n.weight.max(1) as u128 / wsum;
            Grant {
                area: n.area,
                steps: steps[i],
                requests: requests[i],
                wall: Duration::from_millis(raw.clamp(floor, window) as u64),
                llm_calls: llm[i],
            }
        })
        .collect()
}

/// A case that may change the target: a write method, a chain with a write step, a burst.
pub fn is_write(c: &PlannedCase) -> bool {
    is_mutating(&c.method)
        || c.concurrency_burst.is_some_and(|n| n > 1)
        || c.stateful_steps
            .as_ref()
            .is_some_and(|s| s.iter().any(|st| is_mutating(&st.method)))
}
