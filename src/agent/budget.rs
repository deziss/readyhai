//! Run budget: how much a single agent run may do to the target.
//!
//! * steps: executed test cases (a flaky re-run is a request, not a step) -- `--max-steps`
//! * requests: every HTTP request sent to the target, discovery and re-runs included
//! * wall clock: the whole run
//! * per-host rate: minimum gap between two requests to the same host
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BudgetUsage {
    pub steps: usize,
    pub max_steps: usize,
    pub requests: usize,
    pub max_requests: usize,
    pub elapsed_ms: u64,
    pub max_wall_ms: u64,
    pub rate_per_host_per_sec: f64,
    /// Set when a limit cut the run short.
    pub stopped: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RunBudget {
    max_steps: usize,
    max_requests: usize,
    max_wall: Duration,
    rate: f64,
    started: Instant,
    steps: usize,
    requests: usize,
    last_hit: HashMap<String, Instant>,
    stopped: Option<String>,
}

impl Default for RunBudget {
    fn default() -> Self {
        Self::new(60, 600, Duration::from_secs(900), 10.0)
    }
}

impl RunBudget {
    /// `rate_per_host`: requests per second per host; 0 or less disables pacing.
    pub fn new(max_steps: usize, max_requests: usize, max_wall: Duration, rate_per_host: f64) -> Self {
        RunBudget { max_steps, max_requests, max_wall, rate: rate_per_host, started: Instant::now(), steps: 0, requests: 0, last_hit: HashMap::new(), stopped: None }
    }

    /// Defaults, overridden by READYHAI_AGENT_MAX_STEPS / _MAX_REQUESTS / _MAX_SECONDS / _RATE_PER_HOST.
    pub fn from_env() -> Self {
        fn num<T: std::str::FromStr>(k: &str) -> Option<T> {
            std::env::var(k).ok().and_then(|v| v.trim().parse().ok())
        }
        let d = Self::default();
        Self::new(
            num("READYHAI_AGENT_MAX_STEPS").unwrap_or(d.max_steps),
            num("READYHAI_AGENT_MAX_REQUESTS").unwrap_or(d.max_requests),
            Duration::from_secs(num("READYHAI_AGENT_MAX_SECONDS").unwrap_or(d.max_wall.as_secs())),
            num("READYHAI_AGENT_RATE_PER_HOST").unwrap_or(d.rate),
        )
    }

    /// What `readyhai agent --max-steps N` should pass.
    pub fn with_max_steps(mut self, n: usize) -> Self {
        self.max_steps = n;
        self
    }

    pub fn with_max_requests(mut self, n: usize) -> Self {
        self.max_requests = n;
        self
    }

    pub fn with_max_wall(mut self, d: Duration) -> Self {
        self.max_wall = d;
        self
    }

    pub fn with_rate(mut self, per_host_per_sec: f64) -> Self {
        self.rate = per_host_per_sec;
        self
    }

    pub fn max_steps(&self) -> usize {
        self.max_steps
    }

    fn wall_check(&mut self) -> Result<(), String> {
        if self.started.elapsed() >= self.max_wall {
            let m = format!("wall-clock budget exhausted ({}s)", self.max_wall.as_secs());
            self.stopped.get_or_insert(m.clone());
            return Err(m);
        }
        Ok(())
    }

    /// One more test case may start.
    pub fn take_step(&mut self) -> Result<(), String> {
        self.wall_check()?;
        if self.steps >= self.max_steps {
            let m = format!("step budget exhausted (--max-steps {})", self.max_steps);
            self.stopped.get_or_insert(m.clone());
            return Err(m);
        }
        self.steps += 1;
        Ok(())
    }

    /// One more HTTP request to `host` may be sent; sleeps to honour the per-host rate.
    pub fn take_request(&mut self, host: &str) -> Result<(), String> {
        self.wall_check()?;
        if self.requests >= self.max_requests {
            let m = format!("request budget exhausted ({} requests)", self.max_requests);
            self.stopped.get_or_insert(m.clone());
            return Err(m);
        }
        if self.rate > 0.0 {
            let gap = Duration::from_secs_f64(1.0 / self.rate);
            if let Some(last) = self.last_hit.get(host) {
                let since = last.elapsed();
                if since < gap {
                    let wait = gap - since;
                    if self.started.elapsed() + wait >= self.max_wall {
                        return self.wall_check().and(Err("wall-clock budget would be exceeded by rate limiting".into()));
                    }
                    std::thread::sleep(wait);
                }
            }
        }
        self.last_hit.insert(host.to_string(), Instant::now());
        self.requests += 1;
        Ok(())
    }

    pub fn steps_used(&self) -> usize {
        self.steps
    }

    pub fn requests_used(&self) -> usize {
        self.requests
    }

    pub fn stopped(&self) -> Option<&str> {
        self.stopped.as_deref()
    }

    pub fn usage(&self) -> BudgetUsage {
        BudgetUsage {
            steps: self.steps,
            max_steps: self.max_steps,
            requests: self.requests,
            max_requests: self.max_requests,
            elapsed_ms: self.started.elapsed().as_millis() as u64,
            max_wall_ms: self.max_wall.as_millis() as u64,
            rate_per_host_per_sec: self.rate,
            stopped: self.stopped.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_and_requests_are_capped() {
        let mut b = RunBudget::new(2, 3, Duration::from_secs(60), 0.0);
        assert!(b.take_step().is_ok() && b.take_step().is_ok());
        assert!(b.take_step().unwrap_err().contains("step budget"));
        assert!(b.take_request("h").is_ok() && b.take_request("h").is_ok() && b.take_request("h").is_ok());
        assert!(b.take_request("h").unwrap_err().contains("request budget"));
        assert_eq!(b.usage().steps, 2);
        assert!(b.usage().stopped.is_some());
    }

    #[test]
    fn per_host_rate_is_paced_but_hosts_are_independent() {
        let mut b = RunBudget::new(10, 100, Duration::from_secs(60), 20.0); // 50 ms gap
        let t = Instant::now();
        for _ in 0..4 {
            b.take_request("a").unwrap();
        }
        assert!(t.elapsed() >= Duration::from_millis(140), "4 requests at 20/s need >= 150ms, took {:?}", t.elapsed());
        let t = Instant::now();
        b.take_request("b").unwrap();
        assert!(t.elapsed() < Duration::from_millis(40), "a different host is not paced by host a");
    }

    #[test]
    fn wall_clock_stops_everything() {
        let mut b = RunBudget::new(10, 100, Duration::from_millis(1), 0.0);
        std::thread::sleep(Duration::from_millis(5));
        assert!(b.take_step().unwrap_err().contains("wall-clock"));
        assert!(b.take_request("h").unwrap_err().contains("wall-clock"));
    }
}
