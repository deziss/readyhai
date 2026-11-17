//! Defect derivation engine, grouping, and verification evidence mapping.

use std::collections::BTreeMap;

use super::grouping::{
    endpoint_template, listed, merge_same_server_error, path_of, server_error_signature, Group,
    SAME_ERROR_PREFIX,
};
use super::rules::class_meta;
use super::super::oracle::Severity;
use super::super::types::{
    CaseExecutionResult, TriagedDefect, VerificationRecord, VerificationSummary, VerifyVerdict,
};

pub(crate) fn severity_of(r: &CaseExecutionResult) -> Severity {
    r.oracle
        .as_ref()
        .and_then(|o| o.max_fail_severity())
        .unwrap_or(Severity::High)
}

/// Verification facts of a defect, from its member cases: (verified, reproduced, status, flaky).
/// The strongest evidence among the members wins: confirmed, then flaky, then unverified. A defect
/// from the teardown check (a DELETE that left the resource in place) was observed directly by a
/// follow-up GET and counts as confirmed 1/1. Without verifier data nothing is claimed.
pub(crate) fn verification_of(
    members: &[&CaseExecutionResult],
    v: Option<&VerificationSummary>,
) -> (bool, Option<String>, Option<String>, bool) {
    let all_flaky = !members.is_empty() && members.iter().all(|m| m.flaky);
    let teardown = |m: &&CaseExecutionResult| {
        m.oracle
            .as_ref()
            .and_then(|o| o.first_fail())
            .is_some_and(|c| c.code == "delete_not_effective")
    };
    if !members.is_empty() && members.iter().all(teardown) {
        return (true, Some("1/1".into()), Some("confirmed".into()), false);
    }
    let Some(v) = v.filter(|v| v.k > 0) else {
        return (false, None, None, all_flaky);
    };
    let recs: Vec<&VerificationRecord> = members
        .iter()
        .filter_map(|m| v.record(&m.case_id))
        .collect();
    let best = |want: VerifyVerdict| {
        recs.iter()
            .filter(|r| r.verdict == want)
            .max_by_key(|r| r.reproduced)
    };
    if let Some(r) = best(VerifyVerdict::Confirmed) {
        return (true, r.ratio(), Some("confirmed".into()), all_flaky);
    }
    if let Some(r) = best(VerifyVerdict::Flaky) {
        return (false, r.ratio(), Some("flaky".into()), true);
    }
    (false, None, Some("unverified".into()), all_flaky)
}

pub fn derive_defects(results: &[CaseExecutionResult]) -> Vec<TriagedDefect> {
    derive_defects_verified(results, None)
}

/// [`derive_defects`] plus what the independent verifier found out about each defect (see
/// [`verification_of`]). The results passed in are those after the verifier applied its verdicts:
/// a failure that did not reproduce is no longer a FAIL and so is not a defect.
pub fn derive_defects_verified(
    results: &[CaseExecutionResult],
    verification: Option<&VerificationSummary>,
) -> Vec<TriagedDefect> {
    let mut index: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut found: Vec<Group> = vec![];
    for r in results.iter().filter(|r| r.status == "FAIL") {
        let code = r
            .oracle
            .as_ref()
            .and_then(|o| o.first_fail())
            .map(|c| c.code.clone())
            .unwrap_or_else(|| "expected_status".into());
        let path = path_of(&r.component).to_string();
        let i = *index
            .entry((code.clone(), endpoint_template(&path)))
            .or_insert_with(|| {
                found.push(Group {
                    code,
                    technique: r.technique.clone(),
                    component: path.clone(),
                    paths: vec![],
                    method: r.method.clone(),
                    sev: Severity::Low,
                    reasons: vec![],
                    members: vec![],
                    same_error_on: None,
                });
                found.len() - 1
            });
        let g = &mut found[i];
        g.sev = g.sev.max(severity_of(r));
        if !g.paths.contains(&path) {
            g.paths.push(path);
        }
        if let Some(reason) = &r.failure_reason
            && !g.reasons.contains(reason)
        {
            g.reasons.push(reason.clone());
        }
        g.members.push(r);
    }
    for g in found.iter_mut().filter(|g| g.paths.len() > 1) {
        g.component = endpoint_template(&g.paths[0]);
    }
    let mut list = merge_same_server_error(found);
    list.sort_by_key(|g| std::cmp::Reverse(g.sev)); // stable: ties keep execution order
    list.iter()
        .enumerate()
        .map(|(i, g)| {
            let (title, owasp, fix) = class_meta(&g.code, &g.technique);
            let forged = g
                .members
                .iter()
                .any(|m| m.title.to_ascii_lowercase().contains("forged"));
            let title = if g.code == "authz" && forged {
                "Forged token accepted".to_string()
            } else {
                title.to_string()
            };
            let sample_curl = g
                .members
                .iter()
                .map(|m| m.reproduction_curl.as_str())
                .find(|c| !c.is_empty())
                .unwrap_or("");
            let title = match g.same_error_on {
                Some(n) => format!(
                    "{SAME_ERROR_PREFIX}{n} endpoints: {} {}",
                    g.method, g.component
                ),
                None if g.paths.len() > 1 => format!(
                    "{title}: {} {} ({} resources)",
                    g.method,
                    g.component,
                    g.paths.len()
                ),
                None => format!("{title}: {} {}", g.method, g.component),
            };
            let mut observed = format!("Observed: {}", g.reasons.join("; "));
            if g.paths.len() > 1 {
                observed.push_str(&format!(
                    ". Affected ({}): {}",
                    g.paths.len(),
                    listed(&g.paths)
                ));
            }
            let mut defect = TriagedDefect {
                id: format!("DEF-{:03}", i + 1),
                title,
                severity: g.sev.as_str().into(),
                priority: g.sev.priority().into(),
                component: g.component.clone(),
                root_cause_hypothesis: observed,
                blast_radius: if matches!(g.code.as_str(), "authz" | "sensitive_exposure") {
                    "service"
                } else {
                    "isolated"
                }
                .into(),
                owasp_category: owasp.into(),
                recommended_fix: fix.into(),
                reproduction: g
                    .members
                    .iter()
                    .map(|m| m.reproduction_curl.as_str())
                    .filter(|c| !c.is_empty())
                    .collect::<Vec<_>>()
                    .join("\n"),
                case_ids: g.members.iter().map(|m| m.case_id.clone()).collect(),
                evidence_files: g
                    .members
                    .iter()
                    .filter_map(|m| m.evidence_file.clone())
                    .collect(),
                ai_note: None,
                remediation_patch: None,
                remediation_explanation: None,
                reproduction_script: None,
                ..Default::default()
            };
            // identity across runs: the failing check and the endpoint (record ids collapsed); a
            // merged server error is the error itself, whichever endpoints it shows up on
            defect.rule = super::super::memory::clean_ident(&g.code, super::super::memory::MAX_IDENT);
            defect.fingerprint = super::super::memory::fingerprint(
                &defect.rule,
                &match g.same_error_on {
                    Some(_) => format!(
                        "*{}",
                        g.members
                            .iter()
                            .find_map(|m| server_error_signature(m))
                            .unwrap_or_default()
                    ),
                    None => endpoint_template(&g.component),
                },
            );
            let (verified, reproduced, status, flaky) = verification_of(&g.members, verification);
            defect.verified = verified;
            defect.reproduced = reproduced;
            defect.verification = status;
            defect.flaky = flaky;

            let (patch, exp, script) = super::super::remediation::synthesize_remediation(
                &defect,
                &g.component,
                &g.method,
                sample_curl,
            );
            defect.remediation_patch = Some(patch);
            defect.remediation_explanation = Some(exp);
            defect.reproduction_script = Some(script);
            defect
        })
        .collect()
}
