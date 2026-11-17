//! Execution and assertion evaluation for individual functional test cases.
use crate::model::{Category, Severity};
use crate::qa::api::defect_types::{DefectRef, NewDefect, Req};
use crate::qa::api::helpers::blocked_reason;
use crate::qa::api::latency;
use crate::qa::api::runner::Runner;
use crate::qa::api::spec::Op;
use crate::qa::api::synth::{self, Case, Expect};
use crate::qa::model::{Priority, ResultStatus};
use crate::qa::roles::Role;

pub struct CaseRun<'x> {
    pub op: &'x Op,
    pub case: &'x Case,
    pub role: Option<&'x Role>,
    pub cid: &'x str,
    pub url: &'x str,
    pub has_id: bool,
}

pub struct Outcome {
    pub status: ResultStatus,
    pub actual: String,
    pub ms: u128,
    pub defs: Vec<DefectRef>,
}

/// Execute one functional case and judge it. `first` = first attempt (re-runs must not register
/// created resources or add latency samples twice). Err = could not send (budget / write guard).
pub fn run_case(r: &mut Runner, c: &CaseRun, first: bool) -> Result<Outcome, String> {
    let (op, case, role, cid, url) = (c.op, c.case, c.role, c.cid, c.url);
    let key = op.key();
    let req = Req {
        op,
        role,
        case_id: cid,
        kind: &case.kind,
        method: &op.method,
        url,
        body: case.body.as_ref(),
        contract: case.expect == Expect::Success || case.expect == Expect::Reject,
    };
    let (ex, mut defs) = r.send(&req)?;
    if ex.status == 0 {
        let msg = ex.error.clone().unwrap_or_default();
        if case.expect != Expect::Success && r.responded && !r.down {
            // The target answered before; silence on a malformed input is a possible crash/hang.
            let alive = r.alive();
            if !alive {
                r.down = true;
            }
            let how = if ex.timed_out {
                "timed out"
            } else {
                "closed the connection / reset"
            };
            let d = r.defect(NewDefect {
                rule: "qa.api.crash_on_input",
                cat: Category::Reliability,
                sev: if alive {
                    Severity::High
                } else {
                    Severity::Critical
                },
                prio: if alive {
                    Priority::P2
                } else {
                    Priority::P1
                },
                title: format!("{key}: no HTTP response to malformed input ({})", case.kind),
                expected: "a 4xx rejection (the service stays up)".into(),
                actual: format!(
                    "request {how}: {msg}; the target {} answers afterwards (possible crash or hang)",
                    if alive { "still" } else { "no longer" }
                ),
                fp: format!("{key}|crash|{}", case.kind),
                remediation: "Reproduce locally: a malformed request must never crash a worker or hang; add input validation and request timeouts.",
                area_cases: cid,
                component: key.clone(),
                role,
                method: &op.method,
                url,
                body: case.body.as_ref(),
                ex: Some(&ex),
            });
            return Ok(Outcome {
                status: ResultStatus::Fail,
                actual: format!("no response ({how}); possible crash"),
                ms: ex.ms,
                defs: vec![d],
            });
        }
        return Ok(Outcome {
            status: ResultStatus::Blocked,
            actual: format!("transport error: {msg}"),
            ms: ex.ms,
            defs: vec![],
        });
    }
    if first && op.is_write() && ex.is_2xx() && case.expect != Expect::Success {
        r.register_created(op, &ex, role);
    }
    let mut status = ResultStatus::Pass;
    let mut actual = format!("HTTP {} in {} ms", ex.status, ex.ms);
    if let Some(why) = blocked_reason(op, ex.status, c.has_id) {
        status = ResultStatus::Blocked;
        actual = format!("HTTP {}: {why}", ex.status);
    } else {
        match case.expect {
            Expect::Success => {
                if !ex.is_2xx() {
                    status = ResultStatus::Fail;
                    if ex.status < 500 {
                        let d = r.defect(NewDefect {
                            rule: "qa.api.positive_failed",
                            cat: Category::Quality,
                            sev: Severity::Low,
                            prio: Priority::P4,
                            title: format!("{key} rejects a valid request (HTTP {})", ex.status),
                            expected: "2xx for a request built from the spec".into(),
                            actual: format!(
                                "HTTP {} for generated valid input ({})",
                                ex.status, case.kind
                            ),
                            fp: format!("{key}|positive_failed"),
                            remediation: "Check the spec against the implementation (required fields, formats, business preconditions); if the generated data is unrealistic add an `example` to the spec.",
                            area_cases: cid,
                            component: key.clone(),
                            role,
                            method: &op.method,
                            url,
                            body: case.body.as_ref(),
                            ex: Some(&ex),
                        });
                        defs.push(d);
                    }
                }
                if first && !op.is_write() && ex.ms > latency::RECHECK_MS && case.kind == "positive"
                {
                    for _ in 0..2 {
                        let _ = r.send(&Req {
                            op,
                            role,
                            case_id: cid,
                            kind: "latency",
                            method: &op.method,
                            url,
                            body: None,
                            contract: false,
                        });
                    }
                }
            }
            Expect::Reject => {
                if ex.is_2xx() {
                    status = ResultStatus::Fail;
                    let d = r.defect(NewDefect {
                        rule: "qa.api.validation_missing",
                        cat: Category::Quality,
                        sev: Severity::Medium,
                        prio: Priority::P3,
                        title: format!("{key} accepts invalid input ({})", case.title),
                        expected: "4xx rejection".into(),
                        actual: format!("HTTP {} accepted it", ex.status),
                        fp: format!("{key}|{}", case.kind),
                        remediation: "Enforce the documented schema constraints server-side.",
                        area_cases: cid,
                        component: key.clone(),
                        role,
                        method: &op.method,
                        url,
                        body: case.body.as_ref(),
                        ex: Some(&ex),
                    });
                    defs.push(d);
                }
            }
            Expect::NoServerError => {
                let ct = ex.header("content-type").unwrap_or("").to_ascii_lowercase();
                if case.marker && ct.contains("html") && ex.body.contains(synth::MARKER) {
                    status = ResultStatus::Fail;
                    let d = r.defect(NewDefect {
                        rule: "qa.api.reflection",
                        cat: Category::Security,
                        sev: Severity::Low,
                        prio: Priority::P3,
                        title: format!("{key} reflects input verbatim in HTML"),
                        expected: "input is encoded or not reflected".into(),
                        actual: "inert marker returned unescaped in text/html".into(),
                        fp: format!("{key}|{}", case.kind),
                        remediation: "HTML-encode reflected values.",
                        area_cases: cid,
                        component: key.clone(),
                        role,
                        method: &op.method,
                        url,
                        body: case.body.as_ref(),
                        ex: Some(&ex),
                    });
                    defs.push(d);
                }
            }
        }
    }
    if ex.status >= 500 || !defs.is_empty() {
        status = ResultStatus::Fail;
        actual = format!("HTTP {} ({} defect(s))", ex.status, defs.len());
    }
    Ok(Outcome {
        status,
        actual,
        ms: ex.ms,
        defs,
    })
}
