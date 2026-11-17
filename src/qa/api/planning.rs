//! Operation planning and prioritization by risk score.
use std::collections::HashMap;

use super::spec::{Op, Spec};
use crate::ctx::Ctx;
use crate::model::Profile;
use crate::qa::QaCtx;

pub struct Planned<'a> {
    pub op: &'a Op,
    pub risk: u8,
    pub budget: usize,
}

/// Spec operations ordered by plan risk (highest first, spec order within a tie). Risk and budget
/// come from the `qa.plan` items; an operation the plan does not know is scored on the fly.
/// Linear in operations + plan items (a hash lookup per operation, no operation is cloned).
pub fn plan_order<'a>(qa: &QaCtx, spec: &'a Spec) -> Vec<Planned<'a>> {
    let mut v: Vec<Planned<'a>> = qa.with(|c| {
        let mut by_key: HashMap<&str, (u8, usize)> = HashMap::with_capacity(c.plan.len());
        for p in &c.plan {
            // the first item of a component wins, as a front-to-back search did
            by_key
                .entry(p.component.as_str())
                .or_insert((p.risk, p.budget));
        }
        let mut key = String::new();
        spec.ops
            .iter()
            .map(|op| {
                use std::fmt::Write;
                key.clear();
                let _ = write!(key, "{} {}", op.method, op.path);
                match by_key.get(key.as_str()) {
                    Some(&(risk, budget)) => Planned { op, risk, budget },
                    None => Planned {
                        op,
                        risk: crate::qa::plan::risk_of(
                            &op.method,
                            &op.path,
                            op.secured,
                            op.body.is_some(),
                        ),
                        budget: 60,
                    },
                }
            })
            .collect()
    });
    v.sort_by(|a, b| b.risk.cmp(&a.risk));
    v
}

/// Requests held back from the functional check for the stateful lifecycle (nonprod standard+).
pub(crate) fn stateful_reserve(ctx: &Ctx, usable_roles: usize) -> usize {
    match ctx.qa.as_ref() {
        Some(q) if q.nonprod && ctx.profile >= Profile::Standard && usable_roles > 0 => {
            (q.max_requests / 10).clamp(20, 200)
        }
        _ => 0,
    }
}
