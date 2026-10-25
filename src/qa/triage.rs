//! Defect dedupe / root-cause grouping / priority.
use super::model::*;
use crate::model::Severity;
use std::collections::BTreeMap;

const AUTH_KW: [&str; 7] = ["auth", "login", "password", "token", "admin", "session", "oauth"];
const PII_KW: [&str; 8] = ["user", "account", "profile", "email", "customer", "payment", "billing", "invoice"];

fn is_write(component: &str) -> bool {
    let m = component.split_whitespace().next().unwrap_or("");
    matches!(m, "POST" | "PUT" | "PATCH" | "DELETE")
}

fn has_kw(s: &str, kws: &[&str]) -> bool {
    let l = s.to_ascii_lowercase();
    kws.iter().any(|k| l.contains(k))
}

/// Priority = f(severity, exposure). Critical is always P1.
pub fn priority_for(sev: Severity, component: &str) -> Priority {
    let auth = has_kw(component, &AUTH_KW);
    let exposed = auth || is_write(component) || has_kw(component, &PII_KW);
    match sev {
        Severity::Critical => Priority::P1,
        Severity::High if exposed => Priority::P1,
        Severity::High => Priority::P2,
        Severity::Medium if auth => Priority::P2,
        Severity::Medium => Priority::P3,
        _ => Priority::P4,
    }
}

fn merge_into(a: &mut Defect, b: Defect) {
    for c in b.cases {
        if !a.cases.contains(&c) {
            a.cases.push(c);
        }
    }
    for e in b.evidence {
        if !a.evidence.iter().any(|x| x.path == e.path) {
            a.evidence.push(e);
        }
    }
    a.reproduced = (a.reproduced.0 + b.reproduced.0, a.reproduced.1 + b.reproduced.1);
    if b.severity > a.severity {
        a.severity = b.severity;
    }
}

pub fn triage(col: &mut QaCollector) {
    let old = std::mem::take(&mut col.defects);
    // (old id, new key) so results can be re-linked.
    let mut id_map: Vec<(String, usize)> = vec![];

    // 1. dedupe by (rule, component)
    let mut by_key: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut ds: Vec<Defect> = vec![];
    for d in old {
        let key = (d.rule.clone(), d.component.clone());
        let old_id = d.id.clone();
        if let Some(&i) = by_key.get(&key) {
            merge_into(&mut ds[i], d);
            id_map.push((old_id, i));
        } else {
            by_key.insert(key, ds.len());
            id_map.push((old_id, ds.len()));
            ds.push(d);
        }
    }

    // 2. root-cause grouping of server errors by normalized actual signature
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, d) in ds.iter().enumerate() {
        if d.rule == "qa.api.server_error" && !d.actual.trim().is_empty() {
            groups.entry(crate::logs::signature(&d.actual)).or_default().push(i);
        }
    }
    let mut dead: Vec<bool> = vec![false; ds.len()];
    let mut redirect: Vec<usize> = (0..ds.len()).collect();
    for (_, mut idxs) in groups {
        if idxs.len() < 3 {
            continue;
        }
        idxs.sort_by(|a, b| ds[*a].component.cmp(&ds[*b].component));
        let head = idxs[0];
        let comps: Vec<String> = idxs.iter().map(|i| ds[*i].component.clone()).collect();
        for &i in &idxs[1..] {
            let d = ds[i].clone();
            merge_into(&mut ds[head], d);
            dead[i] = true;
            redirect[i] = head;
        }
        let h = &mut ds[head];
        h.title = format!("Same server error on {} endpoints", comps.len());
        h.actual = format!("{}\nAffected: {}", h.actual.lines().next().unwrap_or(""), comps.join(", "));
        h.component = comps.join(", ");
        // fp_key stays the first member's, so the fingerprint still matches its Finding.
    }

    // 3. priority, ordering, ids
    let mut kept: Vec<(usize, Defect)> =
        ds.into_iter().enumerate().filter(|(i, _)| !dead[*i]).collect();
    for (_, d) in kept.iter_mut() {
        d.priority = priority_for(d.severity, &d.component);
    }
    kept.sort_by(|a, b| {
        a.1.priority
            .cmp(&b.1.priority)
            .then(b.1.severity.cmp(&a.1.severity))
            .then(a.1.component.cmp(&b.1.component))
            .then(a.1.rule.cmp(&b.1.rule))
    });
    let mut new_id: BTreeMap<usize, String> = BTreeMap::new();
    for (n, (i, d)) in kept.iter_mut().enumerate() {
        d.id = format!("D-{:03}", n + 1);
        new_id.insert(*i, d.id.clone());
    }
    let old_to_new: BTreeMap<String, String> = id_map
        .into_iter()
        .filter(|(o, _)| !o.is_empty())
        .filter_map(|(o, i)| new_id.get(&redirect[i]).map(|n| (o, n.clone())))
        .collect();
    for r in col.results.iter_mut() {
        if let Some(id) = &r.defect_id {
            r.defect_id = old_to_new.get(id).cloned();
        }
    }
    col.defects = kept.into_iter().map(|(_, d)| d).collect();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, FindingStatus};

    pub fn defect(rule: &str, comp: &str, sev: Severity, actual: &str) -> Defect {
        Defect {
            id: format!("tmp-{comp}"),
            rule: rule.into(),
            category: Category::Reliability,
            severity: sev,
            priority: Priority::P4,
            area: Area::Api,
            title: format!("{rule} on {comp}"),
            component: comp.into(),
            environment: String::new(),
            steps_to_reproduce: vec![],
            expected: "2xx".into(),
            actual: actual.into(),
            evidence: vec![],
            reproduced: (1, 1),
            cases: vec![format!("case-{comp}")],
            remediation: String::new(),
            fp_key: format!("{rule}|{comp}"),
            fingerprint: String::new(),
            status: FindingStatus::New,
            regression: false,
            ai_note: None,
        }
    }

    #[test]
    fn dedupe_merges_cases() {
        let mut c = QaCollector::default();
        let mut a = defect("qa.api.contract_violation", "GET /a", Severity::Low, "x");
        let mut b = a.clone();
        b.cases = vec!["other".into()];
        b.severity = Severity::Medium;
        a.id = "x1".into();
        c.defects = vec![a, b];
        triage(&mut c);
        assert_eq!(c.defects.len(), 1);
        assert_eq!(c.defects[0].cases.len(), 2);
        assert_eq!(c.defects[0].severity, Severity::Medium);
        assert_eq!(c.defects[0].id, "D-001");
    }

    #[test]
    fn root_cause_merge_and_priority() {
        let mut c = QaCollector::default();
        for p in ["/a", "/b", "/c"] {
            c.defects.push(defect("qa.api.server_error", &format!("GET {p}"), Severity::Medium,
                &format!("HTTP 500 SQLSTATE 42P01 relation \"t{}\" missing", p.len() + 7)));
        }
        c.defects.push(defect("qa.api.authz_missing", "POST /login", Severity::High, "200"));
        c.defects.push(defect("qa.api.error_leak", "GET /x", Severity::Low, "trace"));
        triage(&mut c);
        assert_eq!(c.defects.len(), 3);
        assert_eq!(c.defects[0].priority, Priority::P1);
        assert_eq!(c.defects[0].id, "D-001");
        let m = c.defects.iter().find(|d| d.title.starts_with("Same server error on 3")).unwrap();
        assert_eq!(m.priority, Priority::P3);
        assert_eq!(c.defects[2].priority, Priority::P4);
    }

    #[test]
    fn priority_matrix() {
        assert_eq!(priority_for(Severity::High, "GET /status"), Priority::P2);
        assert_eq!(priority_for(Severity::High, "DELETE /things/{id}"), Priority::P1);
        assert_eq!(priority_for(Severity::Medium, "GET /auth/me"), Priority::P2);
        assert_eq!(priority_for(Severity::Info, "GET /a"), Priority::P4);
    }
}
