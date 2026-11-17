//! Types for rerun tracking, defect references, and defect creation requests.
use serde_json::Value;

use super::exec::Exchange;
use super::spec::Op;
use crate::model::{Category, Severity};
use crate::qa::model::{Evidence, Priority, ResultStatus};
use crate::qa::roles::Role;

/// Outcome of re-running a failed case: `fails` of `attempts` attempts failed (first included).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reruns {
    pub attempts: u32,
    pub fails: u32,
}

impl Reruns {
    /// Fail when every attempt failed, Flaky when at least one attempt passed.
    pub fn status(&self) -> ResultStatus {
        if self.fails >= self.attempts {
            ResultStatus::Fail
        } else {
            ResultStatus::Flaky
        }
    }
}

/// Reference to a defect recorded for a case.
#[derive(Clone)]
pub struct DefectRef {
    pub id: String,
    pub ev: Option<Evidence>,
}

pub struct Req<'a> {
    pub op: &'a Op,
    pub role: Option<&'a Role>,
    pub case_id: &'a str,
    /// Stable label of the probe (used in fp keys of server_error).
    pub kind: &'a str,
    pub method: &'a str,
    pub url: &'a str,
    pub body: Option<&'a Value>,
    /// Check documented status + schema.
    pub contract: bool,
}

pub struct NewDefect<'a> {
    pub rule: &'a str,
    pub cat: Category,
    pub sev: Severity,
    pub prio: Priority,
    pub title: String,
    pub expected: String,
    pub actual: String,
    pub fp: String,
    pub remediation: &'a str,
    pub area_cases: &'a str,
    pub component: String,
    pub role: Option<&'a Role>,
    pub method: &'a str,
    pub url: &'a str,
    pub body: Option<&'a Value>,
    pub ex: Option<&'a Exchange>,
}
