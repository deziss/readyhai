//! OpenVEX export: exploitability statements for recorded findings.
//!
//! VEX (Vulnerability Exploitability eXchange) is what a security team consumes alongside an
//! SBOM: a scanner matched a package, the team then asks "is this affectable in our deployment?".
//! ReadyHai is unusually well placed to answer, because it is the only component here that can
//! safely probe. This module turns the vulndb records into an
//! [OpenVEX](https://openvex.dev) document (spec v0.2.0, which CISA's VEX guidance recommends
//! and CycloneDX 1.5/1.6 can embed).
//!
//! The honesty rule is the whole design: this module never invents exploitability.
//! * `verified` (an exploit template ran and demonstrated the flaw) -> `affected`. This is the
//!   only determination ReadyHai makes from evidence.
//! * Everything else -> `under_investigation`, with a status note saying exactly what was and was
//!   not done.
//! * `not_affected` is never emitted. Declaring it requires a reachability or inline-mitigation
//!   justification, and a probe that failed to reproduce is not one: a WAF can block a probe while
//!   the vulnerability ships.
//! * A triage `accepted` status is a risk decision, not an exploitability claim, so the status is
//!   unchanged and the note records the decision.
//!
//! Only findings carrying a standard vulnerability id (CVE, GHSA, OSV) are exported, because those
//! ids mean something to every consumer. Findings skipped for lacking one are counted in the
//! document, never silently dropped.

use serde_json::{Value, json};

use crate::engine::{VERSION, now};
use crate::vulndb::{Filter, VulnRecord, list};

const STATUS_AFFECTED: &str = "affected";
const STATUS_INVESTIGATING: &str = "under_investigation";
const AUTHOR: &str = "ReadyHai";

/// Ids a VEX consumer can resolve without ReadyHai. Upper-cased for the document.
///
/// A grype-style record puts the advisory id in `rule`, but other tools name the rule and leave
/// the id in the title or detail, so the three text fields are tried in that order. Returns the
/// first well-formed id; the shapes are checked rather than pattern-matched loosely, so a title
/// like "cve matches" is not mistaken for one.
fn vulnerability_id(rec: &VulnRecord) -> Option<String> {
    [&rec.rule as &str, &rec.title, &rec.message]
        .into_iter()
        .find_map(standard_id_in)
}

/// First standard advisory id inside `text`, if any token has one of the three accepted shapes.
fn standard_id_in(text: &str) -> Option<String> {
    // Tokens are split by anything that is not part of an id, so "GHSA-xxxx-yyyy-zzzz." and
    // "(CVE-2024-43788)" both yield the bare id. No regex: this runs per record, not per byte of
    // scanned input.
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .map(|t| t.trim_matches('-'))
        .find_map(|token| {
            let up = token.to_ascii_uppercase();
            standard_id_shape(&up).then_some(up)
        })
}

/// `true` for a syntactically real CVE, GHSA or OSV id.
fn standard_id_shape(id: &str) -> bool {
    if let Some(rest) = id.strip_prefix("CVE-") {
        // CVE-YYYY-NNNN(NNNN...): four-digit year, then four or more digits.
        let (year, tail) = match rest.split_once('-') {
            Some(parts) => parts,
            None => return false,
        };
        return year.len() == 4
            && year.bytes().all(|b| b.is_ascii_digit())
            && tail.len() >= 4
            && tail.bytes().all(|b| b.is_ascii_digit());
    }
    if let Some(rest) = id.strip_prefix("GHSA-") {
        // Four groups of four alphanumeric characters.
        let groups: Vec<&str> = rest.split('-').collect();
        return groups.len() == 3
            && groups
                .iter()
                .all(|g| g.len() == 4 && g.bytes().all(|b| b.is_ascii_alphanumeric()));
    }
    if let Some(rest) = id.strip_prefix("OSV-") {
        // OSV-SCOPE-NNNN and OSV-YYYY-NNNN style publish ids.
        let groups: Vec<&str> = rest.split('-').collect();
        return groups.len() == 2
            && groups[0].len() >= 4
            && groups[0]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.')
            && groups[1].len() >= 4
            && groups[1].bytes().all(|b| b.is_ascii_digit());
    }
    false
}

/// Stable product identity for a target: the same target hash the vulndb and agent memory key on,
/// so a VEX product lines up with `readyhai vulns --target`.
fn product_id(rec: &VulnRecord) -> String {
    format!("pkg:readyhai/target/{}", rec.target_key)
}

fn status_note(rec: &VulnRecord) -> String {
    let base = match rec.verification.as_str() {
        "verified" => format!(
            "Exploitation was demonstrated by template {} at {}. Recorded as affected because an \
             exploit was observed against the target.",
            rec.verified_by.as_deref().unwrap_or("unknown"),
            rec.verified_at.as_deref().unwrap_or("an unrecorded time"),
        ),
        "not_reproducible" => {
            "An exploit template ran and did not reproduce the flaw. That is not \
             a not-affected determination: a blocked or environment-dependent probe still leaves \
             the vulnerable code deployed."
                .to_string()
        }
        "inconclusive" => "An exploit template ran and the result was unclear.".to_string(),
        "skipped" => "Verification was skipped: no reviewed template covers this finding, or the \
             target was out of scope for probing. No exploitability evidence exists."
            .to_string(),
        _ => "No exploitation was attempted. This is the default state for every scanner match, \
             including grype/EPSS CVE matches: ReadyHai has no evidence either way."
            .to_string(),
    };
    match rec.status.as_str() {
        "accepted" => format!(
            "{base} Triaged as risk-accepted by an operator, which is a risk decision and not an exploitability determination."
        ),
        "forgotten" => {
            format!("{base} Triaged as forgotten: no longer listed as open, still recorded.")
        }
        _ => base,
    }
}

/// Statement timestamps must be RFC 3339; the database stores a bare `YYYY-MM-DD` for records
/// first seen before any verification stamped a full time.
fn rfc3339(stored: &str) -> String {
    match stored.len() {
        10 => format!("{stored}T00:00:00Z"),
        _ => stored.to_string(),
    }
}

fn statement(rec: &VulnRecord, vid: &str) -> Value {
    let affected = rec.verification == "verified";
    let mut st = json!({
        // @id must be unique per author; fingerprint+target is the identity ReadyHai uses.
        "@id": format!("urn:readyhai:vex:{}:{}", rec.target_key, rec.fingerprint),
        "vulnerability": { "@id": vid },
        "product": { "@id": product_id(rec) },
        "status": if affected { STATUS_AFFECTED } else { STATUS_INVESTIGATING },
        "status_notes": status_note(rec),
        "assigned_by": AUTHOR,
        "timestamp": rfc3339(&rec.last_seen),
    });
    // A remediation ReadyHai actually observed (a fix hint recorded by the scanner) belongs in
    // action_statement; nothing is invented here. The hint can appear mid-sentence in the detail,
    // so it is searched for rather than matched at the start.
    let lowered = rec.message.to_ascii_lowercase();
    if let Some(at) = lowered.find("fix available") {
        let rest = rec.message[at + "fix available".len()..].trim();
        let rest = rest.strip_prefix(':').unwrap_or(rest).trim();
        if !rest.is_empty() {
            // Cut at a sentence boundary (". ") so version numbers like 1.4.1 survive, but the
            // following sentence's advice is not copied into the VEX statement.
            let fix: String = rest
                .split(". ")
                .next()
                .unwrap_or("")
                .trim()
                .trim_end_matches('.')
                .to_string();
            if !fix.is_empty() {
                st["action_statement"] = json!(format!(
                    "Fix available: {fix}. Confirm by re-scanning after upgrading."
                ));
            }
        }
    }
    st
}

/// OpenVEX document for `records`. Statements are only ever `affected` or
/// `under_investigation`; the counts and the skip counter are top level so a consumer (and a
/// reviewer) can see how much of the picture is evidence and how much is not.
pub fn document(records: &[VulnRecord]) -> Value {
    let mut statements = Vec::new();
    let mut skipped_no_standard_id = 0usize;
    for rec in records {
        match vulnerability_id(rec) {
            Some(vid) => statements.push(statement(rec, &vid)),
            None => skipped_no_standard_id += 1,
        }
    }
    let affected = statements
        .iter()
        .filter(|s| s["status"] == STATUS_AFFECTED)
        .count();
    json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": format!("urn:readyhai:vex:doc:{}", crate::engine::today().replace('-', "")),
        "author": AUTHOR,
        "timestamp": now(),
        "version": 1,
        "tooling": format!("ReadyHai {VERSION}"),
        "statements": statements,
        "statements_affected": affected,
        "statements_under_investigation": statements.len() - affected,
        "findings_skipped_no_standard_vulnerability_id": skipped_no_standard_id,
        "note": "ReadyHai emits no not_affected or fixed statements: claiming either needs a reachability, mitigation or re-scan determination that a scanner has not made. Anything not demonstrated is under_investigation, and each statement says what would change it.",
    })
}

/// OpenVEX for the vulndb under `filters`. `Filter::default()`-style empty filters list every
/// record, mirroring `readyhai vulns --all`.
pub fn export(filters: Filter) -> Result<String, String> {
    serde_json::to_string_pretty(&document(&list(&filters))).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vulndb::VulnRecord;

    fn rec(rule: &str, verification: &str, status: &str) -> VulnRecord {
        VulnRecord {
            fingerprint: "a1b2c3d4e5f6".into(),
            target: "https://api.example.com".into(),
            target_key: "aabbccddeeff0011".into(),
            kind: "tool.grype".into(),
            rule: rule.into(),
            title: "radix before 1.4.1 has a ReDoS".into(),
            severity: "high".into(),
            resource: "pkg:npm/radix@1.4.0".into(),
            first_seen: "2026-01-01T00:00:00Z".into(),
            last_seen: "2026-01-02T00:00:00Z".into(),
            occurrences: 3,
            status: status.into(),
            message: "fix available: upgrade to 1.4.1".into(),
            verification: verification.into(),
            verified_by: (verification == "verified").then(|| "redos-radix-1".to_string()),
            verified_at: (verification == "verified").then(|| "2026-01-02T00:00:00Z".to_string()),
        }
    }

    #[test]
    fn only_demonstrated_exploits_are_affected() {
        let doc = document(&[
            rec("CVE-2024-43788", "verified", "open"),
            rec("CVE-2024-11111", "unverified", "open"),
            rec("CVE-2024-22222", "not_reproducible", "open"),
        ]);
        let st = doc["statements"].as_array().unwrap();
        assert_eq!(st.len(), 3);
        assert_eq!(st[0]["status"], "affected");
        assert_eq!(st[1]["status"], "under_investigation");
        assert_eq!(st[2]["status"], "under_investigation");
        assert_eq!(doc["statements_affected"], 1);
        for s in st {
            assert_ne!(s["status"], "not_affected");
            assert_ne!(s["status"], "fixed");
        }
    }

    #[test]
    fn a_probe_that_did_not_reproduce_is_evidence_not_a_verdict() {
        let doc = document(&[rec("GHSA-xxxx-yyyy-zzzz", "not_reproducible", "open")]);
        let note = doc["statements"][0]["status_notes"].as_str().unwrap();
        assert!(note.contains("not a not-affected determination"));
    }

    #[test]
    fn findings_without_a_standard_id_are_counted_not_dropped_silently() {
        let doc = document(&[
            rec("readiness.dockerfile.no_user", "unverified", "open"),
            rec("CVE-2024-43788", "verified", "open"),
        ]);
        assert_eq!(doc["statements"].as_array().unwrap().len(), 1);
        assert_eq!(doc["findings_skipped_no_standard_vulnerability_id"], 1);
    }

    #[test]
    fn risk_acceptance_does_not_change_exploitability() {
        let doc = document(&[rec("CVE-2024-43788", "verified", "accepted")]);
        let s = &doc["statements"][0];
        assert_eq!(s["status"], "affected");
        assert!(
            s["status_notes"]
                .as_str()
                .unwrap()
                .contains("risk-accepted")
        );
    }

    #[test]
    fn an_id_in_the_title_or_detail_counts_as_the_finding_id() {
        let mut r = rec("tool.sbom_cve", "unverified", "open");
        r.title = "CVE-2021-23337 in lodash 4.17.20".into();
        r.message = "Prototype pollution; see GHSA-67hx-6x53-jw92.".into();
        let doc = document(&[r]);
        // The rule is a scanner rule name here, so the id must come from the title.
        assert_eq!(
            doc["statements"][0]["vulnerability"]["@id"],
            "CVE-2021-23337"
        );
    }

    #[test]
    fn prose_about_ids_is_not_mistaken_for_one() {
        for text in [
            "review cve coverage",
            "CVE-20-24",
            "GHSA-xxxx-yyyy",
            "GHSA-xxxx-yyyy-zzzz-too-long-group",
            "OSV-24-1",
        ] {
            assert!(
                standard_id_in(text).is_none(),
                "{text} should not yield an id"
            );
        }
        assert_eq!(
            standard_id_in("affected by (cve-2024-43788), see GHSA-67hx-6x53-jw92"),
            Some("CVE-2024-43788".into())
        );
    }

    #[test]
    fn bare_dates_still_produce_rfc3339_timestamps() {
        let mut r = rec("CVE-2024-43788", "unverified", "open");
        r.last_seen = "2026-01-02".into();
        let doc = document(&[r]);
        assert_eq!(doc["statements"][0]["timestamp"], "2026-01-02T00:00:00Z");
    }

    #[test]
    fn a_fix_hint_anywhere_in_the_detail_becomes_an_action_statement() {
        let mut r = rec("CVE-2021-23337", "verified", "open");
        r.message = "lodash 4.17.20 is affected. Fix available: 4.17.21".into();
        let doc = document(&[r]);
        assert_eq!(
            doc["statements"][0]["action_statement"],
            "Fix available: 4.17.21. Confirm by re-scanning after upgrading."
        );
        // And a record with no hint must not grow one.
        let mut clean = rec("CVE-2021-23337", "verified", "open");
        clean.message = "Prototype pollution in merge().".into();
        assert!(
            document(&[clean])["statements"][0]
                .get("action_statement")
                .is_none()
        );
    }

    #[test]
    fn ids_are_canonical_and_products_key_on_the_target_hash() {
        let doc = document(&[rec("cve-2024-43788", "verified", "open")]);
        let s = &doc["statements"][0];
        assert_eq!(s["vulnerability"]["@id"], "CVE-2024-43788");
        assert_eq!(s["product"]["@id"], "pkg:readyhai/target/aabbccddeeff0011");
        assert!(s["action_statement"].as_str().unwrap().contains("1.4.1"));
    }
}
