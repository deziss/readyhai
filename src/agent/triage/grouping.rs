//! Endpoint path normalization, error signatures, and defect grouping.

use std::collections::BTreeMap;

use super::super::oracle::Severity;
use super::super::types::CaseExecutionResult;

pub fn path_of(component: &str) -> &str {
    component.split(['?', '#']).next().unwrap_or(component)
}

pub(crate) fn is_id_segment(seg: &str) -> bool {
    let hex = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit());
    if !seg.is_empty() && seg.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    let parts: Vec<&str> = seg.split('-').collect();
    if parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(n, p)| p.len() == *n && hex(p))
    {
        return true;
    }
    seg.len() >= 16 && hex(seg)
}

/// The endpoint a path belongs to, with every record id collapsed: `/orders/12` and `/orders/7`
/// are both `/orders/{id}`. Two failures of the same check on the same endpoint have one root
/// cause, whichever record they hit (the QA engine's triage groups per rule and component).
pub fn endpoint_template(path: &str) -> String {
    let segs: Vec<&str> = path
        .split('/')
        .map(|s| if is_id_segment(s) { "{id}" } else { s })
        .collect();
    segs.join("/")
}

/// Most affected components named in a merged defect's text.
const MAX_LISTED: usize = 10;

pub(crate) fn listed(comps: &[String]) -> String {
    let mut s = comps
        .iter()
        .take(MAX_LISTED)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if comps.len() > MAX_LISTED {
        s.push_str(&format!(", +{} more", comps.len() - MAX_LISTED));
    }
    s
}

/// Failures that share one root cause. Its members are the FAIL results, each keeping its own
/// case id, reproduction and evidence file.
pub(crate) struct Group<'a> {
    pub code: String,
    pub technique: String,
    /// Display component: the one path all members hit, or the endpoint template / the list of
    /// endpoints of a merged group.
    pub component: String,
    /// Distinct concrete paths the members hit, first seen first.
    pub paths: Vec<String>,
    pub method: String,
    pub sev: Severity,
    pub reasons: Vec<String>,
    pub members: Vec<&'a CaseExecutionResult>,
    /// Set when the group folds failures of several endpoints that failed the same way.
    pub same_error_on: Option<usize>,
}

/// Root-cause signature of a server error: the status plus the normalised response body (ids,
/// numbers, quoted strings stripped). No body, no signature: two empty 500s can be unrelated.
pub(crate) fn server_error_signature(m: &CaseExecutionResult) -> Option<String> {
    let body = m.evidence.split_whitespace().collect::<Vec<_>>().join(" ");
    let body: String = body.chars().take(300).collect();
    if body.is_empty() {
        return None;
    }
    Some(format!(
        "{} {}",
        m.status_code.unwrap_or(0),
        crate::logs::signature(&body)
    ))
}

/// The QA engine folds server errors that fail the same way on three or more endpoints into one
/// defect ("Same server error on N endpoints"); the agent does the same.
pub const SAME_ERROR_MIN_ENDPOINTS: usize = 3;

/// Title prefix of such a merged defect (the memory recognises it: its identity is the error, not
/// the list of endpoints).
pub const SAME_ERROR_PREFIX: &str = "Same server error on ";

pub(crate) fn merge_same_server_error<'a>(groups: Vec<Group<'a>>) -> Vec<Group<'a>> {
    let mut by_sig: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, g) in groups.iter().enumerate() {
        if g.code == "server_error"
            && let Some(sig) = g.members.iter().find_map(|m| server_error_signature(m))
        {
            by_sig.entry(sig).or_default().push(i);
        }
    }
    let mut take: Vec<Option<Group>> = groups.into_iter().map(Some).collect();
    let mut merged_at: BTreeMap<usize, Group> = BTreeMap::new();
    for (_, mut idxs) in by_sig {
        if idxs.len() < SAME_ERROR_MIN_ENDPOINTS {
            continue;
        }
        idxs.sort_by(|a, b| {
            let (ga, gb) = (take[*a].as_ref().unwrap(), take[*b].as_ref().unwrap());
            ga.component.cmp(&gb.component)
        });
        let mut head = take[idxs[0]].take().unwrap();
        for &i in &idxs[1..] {
            let g = take[i].take().unwrap();
            head.sev = head.sev.max(g.sev);
            for r in g.reasons {
                if !head.reasons.contains(&r) {
                    head.reasons.push(r);
                }
            }
            for p in g.paths {
                if !head.paths.contains(&p) {
                    head.paths.push(p);
                }
            }
            head.members.extend(g.members);
        }
        head.component = listed(&head.paths);
        head.same_error_on = Some(idxs.len());
        merged_at.insert(idxs[0], head);
    }
    take.into_iter()
        .enumerate()
        .filter_map(|(i, g)| g.or_else(|| merged_at.remove(&i)))
        .collect()
}
