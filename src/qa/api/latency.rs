//! The latency rule of the API checks, shared by the QA engine and the agent oracle: one
//! threshold, one percentile definition, no dependency on a run context.

/// An endpoint whose p95 is above this many milliseconds is slow.
pub const SLOW_P95_MS: u128 = 1000;

/// A read whose first answer is above this is sampled again before it is judged (the QA engine
/// takes two more samples), so one slow answer is not mistaken for a slow endpoint.
pub const RECHECK_MS: u128 = 800;

/// 95th percentile of `samples` (nearest rank); 0 when there are none.
pub fn p95(samples: &[u128]) -> u128 {
    if samples.is_empty() {
        return 0;
    }
    let mut v = samples.to_vec();
    v.sort_unstable();
    v[((v.len() as f64 * 0.95).ceil() as usize).clamp(1, v.len()) - 1]
}

/// The p95 is over the threshold.
pub fn is_slow(p95_ms: u128) -> bool {
    p95_ms > SLOW_P95_MS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p95_is_the_nearest_rank_and_slow_is_strictly_above_the_threshold() {
        assert_eq!(p95(&[]), 0);
        assert_eq!(p95(&[40]), 40);
        assert_eq!(
            p95(&[900, 10, 20]),
            900,
            "with 3 samples the p95 is the max"
        );
        let mut v: Vec<u128> = (1..=20).collect();
        v[19] = 5000;
        assert_eq!(p95(&v), 19, "the 20th sample is above the 95th rank");
        assert!(!is_slow(SLOW_P95_MS));
        assert!(is_slow(SLOW_P95_MS + 1));
        const { assert!(RECHECK_MS < SLOW_P95_MS) };
    }
}
