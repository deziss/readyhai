//! Traceability: every QA/security rule maps to an OWASP WSTG work product, an
//! OWASP API Security Top 10 2023 id and an ASVS v4.2 requirement. QA leads sign off
//! against coverage of the standard rather than a list of ad-hoc checks, so the mapping
//! lives here as data and the report renders it as a coverage matrix.
//!
//! Identifiers follow the WSTG v4.1 scheme (`WSTG-ATHN-001`, `WSTG-ATHZ-01`, ...). A rule
//! may map to several work products, because one probe can satisfy several of them.
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Standard identifiers one rule satisfies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Mapping {
    pub rule: &'static str,
    /// WSTG work products, e.g. `WSTG-ATHZ-01`.
    pub wstg: &'static [&'static str],
    /// OWASP API Security Top 10 2023, e.g. `API1` (Broken Object Level Authorization).
    pub api_top10: &'static [&'static str],
    /// ASVS v4.2 requirement, e.g. `v4.2.04.01`.
    pub asvs: &'static [&'static str],
}

/// WSTG test groups (the token after `WSTG-`), in the order the standard lists them.
pub const WSTG_GROUPS: [(&str, &str); 12] = [
    ("INFO", "Information Gathering"),
    ("CONFIG", "Configuration and Deployment Management"),
    ("IDNT", "Identity Management"),
    ("ATHN", "Authentication Testing"),
    ("SESS", "Session Management Testing"),
    ("ATHZ", "Authorization Testing"),
    ("INPV", "Data Validation Testing"),
    ("ERRT", "Error Handling Testing"),
    ("CRYP", "Cryptography Testing"),
    ("BUSL", "Business Logic Testing"),
    ("CLNT", "Client-side Testing"),
    ("APIT", "API Testing"),
];

/// rule -> mapping, sorted by rule. Lookup is a scan: the table is small and is only
/// walked when a report is built.
const MAP: &[Mapping] = &[
    Mapping {
        rule: "qa.api.access_denied",
        wstg: &["WSTG-ATHZ-01"],
        api_top10: &[],
        asvs: &["v4.2.04"],
    },
    Mapping {
        rule: "qa.api.authz_missing",
        wstg: &["WSTG-ATHZ-01", "WSTG-APIT-02"],
        api_top10: &["API5"],
        asvs: &["v4.2.04.01"],
    },
    Mapping {
        rule: "qa.api.bola",
        wstg: &["WSTG-ATHZ-01", "WSTG-APIT-01"],
        api_top10: &["API1"],
        asvs: &["v4.2.04.01"],
    },
    Mapping {
        rule: "qa.api.breaking_change",
        wstg: &["WSTG-APIT-01"],
        api_top10: &[],
        asvs: &["v4.2.05"],
    },
    Mapping {
        rule: "qa.api.contract_violation",
        wstg: &["WSTG-APIT-01", "WSTG-APIT-04"],
        api_top10: &["API3"],
        asvs: &["v4.2.05"],
    },
    Mapping {
        rule: "qa.api.crash_on_input",
        wstg: &["WSTG-ERRT-01", "WSTG-INPV-12"],
        api_top10: &["API4"],
        asvs: &["v4.2.05.03"],
    },
    Mapping {
        rule: "qa.api.delete_not_effective",
        wstg: &["WSTG-BUSL-01", "WSTG-IDNT-02"],
        api_top10: &["API1"],
        asvs: &["v4.2.02.05"],
    },
    Mapping {
        rule: "qa.api.error_leak",
        wstg: &["WSTG-ERRT-01", "WSTG-ERRT-02", "WSTG-CONFIG-04"],
        api_top10: &["API2"],
        asvs: &["v4.2.07.04"],
    },
    Mapping {
        rule: "qa.api.idempotency",
        wstg: &["WSTG-APIT-04"],
        api_top10: &["API4"],
        asvs: &["v4.2.07.02"],
    },
    Mapping {
        rule: "qa.api.persistence_failure",
        wstg: &["WSTG-BUSL-01"],
        api_top10: &[],
        asvs: &["v4.2.01"],
    },
    Mapping {
        rule: "qa.api.positive_failed",
        wstg: &["WSTG-APIT-01"],
        api_top10: &[],
        asvs: &[],
    },
    Mapping {
        rule: "qa.api.privilege_escalation",
        wstg: &["WSTG-ATHZ-01", "WSTG-ATHZ-02"],
        api_top10: &["API5"],
        asvs: &["v4.2.04.05"],
    },
    Mapping {
        rule: "qa.api.reflection",
        wstg: &["WSTG-CLNT-01"],
        api_top10: &[],
        asvs: &["v4.2.05.01"],
    },
    Mapping {
        rule: "qa.api.server_error",
        wstg: &["WSTG-ERRT-01"],
        api_top10: &["API8"],
        asvs: &["v4.2.07.04"],
    },
    Mapping {
        rule: "qa.api.slow_response",
        wstg: &["WSTG-APIT-04"],
        api_top10: &["API4"],
        asvs: &["v4.2.05.03"],
    },
    Mapping {
        rule: "qa.api.undocumented_status",
        wstg: &["WSTG-APIT-01"],
        api_top10: &[],
        asvs: &["v4.2.05"],
    },
    Mapping {
        rule: "qa.api.validation_missing",
        wstg: &["WSTG-INPV-01", "WSTG-INPV-04"],
        api_top10: &["API8"],
        asvs: &["v4.2.05.01"],
    },
    Mapping {
        rule: "qa.graphql.authz_missing",
        wstg: &["WSTG-ATHZ-01"],
        api_top10: &["API5"],
        asvs: &["v4.2.04.01"],
    },
    Mapping {
        rule: "qa.graphql.circular_dos",
        wstg: &["WSTG-APIT-04"],
        api_top10: &["API4"],
        asvs: &["v4.2.05.03"],
    },
    Mapping {
        rule: "qa.graphql.deep_nesting_dos",
        wstg: &["WSTG-APIT-04"],
        api_top10: &["API4"],
        asvs: &["v4.2.05.03"],
    },
    Mapping {
        rule: "qa.graphql.error_leak",
        wstg: &["WSTG-ERRT-01"],
        api_top10: &[],
        asvs: &["v4.2.07.04"],
    },
    Mapping {
        rule: "qa.graphql.introspection_enabled",
        wstg: &["WSTG-CONFIG-05", "WSTG-APIT-02"],
        api_top10: &["API5"],
        asvs: &["v4.2.01.02"],
    },
    Mapping {
        rule: "qa.graphql.server_error",
        wstg: &["WSTG-ERRT-01"],
        api_top10: &[],
        asvs: &["v4.2.07.04"],
    },
    Mapping {
        rule: "qa.graphql.unauthorized_field",
        wstg: &["WSTG-ATHZ-04", "WSTG-APIT-02"],
        api_top10: &["API3"],
        asvs: &["v4.2.04.08"],
    },
    Mapping {
        rule: "qa.pentest.auth_bypass",
        wstg: &["WSTG-ATHZ-01", "WSTG-ATHN-001"],
        api_top10: &["API5"],
        asvs: &["v4.2.04.01"],
    },
    Mapping {
        rule: "qa.pentest.cookie_flags",
        wstg: &["WSTG-SESS-002"],
        api_top10: &["API2"],
        asvs: &["v4.2.03.04"],
    },
    Mapping {
        rule: "qa.pentest.cookie_no_httponly",
        wstg: &["WSTG-SESS-002"],
        api_top10: &["API2"],
        asvs: &["v4.2.03.04"],
    },
    Mapping {
        rule: "qa.pentest.cookie_no_secure",
        wstg: &["WSTG-SESS-002"],
        api_top10: &["API2"],
        asvs: &["v4.2.03.05"],
    },
    Mapping {
        rule: "qa.pentest.cookie_samesite_none_insecure",
        wstg: &["WSTG-SESS-002"],
        api_top10: &["API2"],
        asvs: &["v4.2.03.06"],
    },
    Mapping {
        rule: "qa.pentest.cors_null_origin",
        wstg: &["WSTG-CLNT-07"],
        api_top10: &["API8"],
        asvs: &["v4.2.09.01"],
    },
    Mapping {
        rule: "qa.pentest.cors_unvalidated_origin",
        wstg: &["WSTG-CLNT-07"],
        api_top10: &["API8"],
        asvs: &["v4.2.09.01"],
    },
    Mapping {
        rule: "qa.pentest.cors_wildcard",
        wstg: &["WSTG-CLNT-07"],
        api_top10: &["API8"],
        asvs: &["v4.2.09.02"],
    },
    Mapping {
        rule: "qa.pentest.csrf_missing",
        wstg: &["WSTG-SESS-005", "WSTG-CLNT-08"],
        api_top10: &["API2"],
        asvs: &["v4.2.03.05"],
    },
    Mapping {
        rule: "qa.pentest.dangerous_method",
        wstg: &["WSTG-CONFIG-01"],
        api_top10: &["API8"],
        asvs: &["v4.2.13.03"],
    },
    Mapping {
        rule: "qa.pentest.excessive_data",
        wstg: &["WSTG-ATHZ-04", "WSTG-APIT-02"],
        api_top10: &["API3"],
        asvs: &["v4.2.04.08"],
    },
    Mapping {
        rule: "qa.pentest.injection_reflected",
        wstg: &["WSTG-INPV-01", "WSTG-INPV-02", "WSTG-INPV-13"],
        api_top10: &["API3"],
        asvs: &["v4.2.05.01"],
    },
    Mapping {
        rule: "qa.pentest.mass_assignment",
        wstg: &["WSTG-APIT-02", "WSTG-INPV-23"],
        api_top10: &["API3"],
        asvs: &["v4.2.04.08"],
    },
    Mapping {
        rule: "qa.pentest.negative_value",
        wstg: &["WSTG-BUSL-04", "WSTG-INPV-07"],
        api_top10: &["API4"],
        asvs: &["v4.2.01.02"],
    },
    Mapping {
        rule: "qa.pentest.no_rate_limit",
        wstg: &["WSTG-ATHN-003", "WSTG-APIT-04"],
        api_top10: &["API4"],
        asvs: &["v4.2.02.02"],
    },
    Mapping {
        rule: "qa.pentest.open_redirect",
        wstg: &["WSTG-CLNT-04"],
        api_top10: &["API1"],
        asvs: &["v4.2.05.02"],
    },
    Mapping {
        rule: "qa.pentest.path_traversal",
        wstg: &["WSTG-INPV-10", "WSTG-CONFIG-06"],
        api_top10: &["API1"],
        asvs: &["v4.2.05.03"],
    },
    Mapping {
        rule: "qa.pentest.sensitive_file",
        wstg: &["WSTG-CONFIG-05", "WSTG-CONFIG-06"],
        api_top10: &["API2"],
        asvs: &["v4.2.01.14"],
    },
    Mapping {
        rule: "qa.pentest.session_fixation",
        wstg: &["WSTG-SESS-001"],
        api_top10: &["API2"],
        asvs: &["v4.2.03.01"],
    },
    Mapping {
        rule: "qa.pentest.session_not_revoked",
        wstg: &["WSTG-SESS-003", "WSTG-SESS-004"],
        api_top10: &["API2"],
        asvs: &["v4.2.03.03"],
    },
    Mapping {
        rule: "qa.pentest.ssrf_canary",
        wstg: &["WSTG-INPV-15"],
        api_top10: &["API3"],
        asvs: &["v4.2.05.03"],
    },
    Mapping {
        rule: "qa.pentest.private_cacheable",
        wstg: &["WSTG-CLNT-07", "WSTG-CONFIG-04"],
        api_top10: &["API8"],
        asvs: &["v4.2.09.02"],
    },
    Mapping {
        rule: "qa.pentest.weak_jwt",
        wstg: &["WSTG-SESS-011", "WSTG-CRYP-003"],
        api_top10: &["API2"],
        asvs: &["v4.2.03.02"],
    },
    Mapping {
        rule: "qa.data.duplicate_key",
        wstg: &["WSTG-INPV-07"],
        api_top10: &[],
        asvs: &["v4.2.05"],
    },
    Mapping {
        rule: "qa.data.invalid_format",
        wstg: &["WSTG-INPV-01"],
        api_top10: &[],
        asvs: &["v4.2.05.01"],
    },
    Mapping {
        rule: "qa.data.null_violation",
        wstg: &["WSTG-INPV-07"],
        api_top10: &[],
        asvs: &["v4.2.05"],
    },
    Mapping {
        rule: "qa.data.orphan_reference",
        wstg: &["WSTG-INPV-07"],
        api_top10: &[],
        asvs: &[],
    },
    Mapping {
        rule: "qa.data.pii_exposed",
        wstg: &["WSTG-ATHZ-04", "WSTG-IDNT-02"],
        api_top10: &["API3"],
        asvs: &["v4.2.09.01"],
    },
    Mapping {
        rule: "qa.data.schema_drift",
        wstg: &["WSTG-INPV-07"],
        api_top10: &[],
        asvs: &[],
    },
    Mapping {
        rule: "qa.data.stale",
        wstg: &["WSTG-INPV-07"],
        api_top10: &[],
        asvs: &[],
    },
    Mapping {
        rule: "qa.ui.a11y_violation",
        wstg: &["WSTG-CLNT-09"],
        api_top10: &[],
        asvs: &[],
    },
    Mapping {
        rule: "qa.ui.journey_failed",
        wstg: &["WSTG-BUSL-01"],
        api_top10: &[],
        asvs: &[],
    },
    Mapping {
        rule: "qa.ui.validation_gap",
        wstg: &["WSTG-CLNT-03", "WSTG-INPV-04"],
        api_top10: &[],
        asvs: &["v4.2.05.01"],
    },
    Mapping {
        rule: "qa.perf.slow",
        wstg: &["WSTG-APIT-04"],
        api_top10: &["API4"],
        asvs: &[],
    },
    Mapping {
        rule: "qa.resilience.health_lies",
        wstg: &["WSTG-CONFIG-04"],
        api_top10: &[],
        asvs: &["v4.2.07"],
    },
    Mapping {
        rule: "qa.resilience.no_recovery",
        wstg: &["WSTG-APIT-04"],
        api_top10: &["API4"],
        asvs: &["v4.2.05.03"],
    },
    Mapping {
        rule: "qa.release.eol_runtime",
        wstg: &["WSTG-CONFIG-02"],
        api_top10: &["API6"],
        asvs: &["v4.2.14.02"],
    },
    Mapping {
        rule: "qa.release.license",
        wstg: &["WSTG-CONFIG-02"],
        api_top10: &[],
        asvs: &[],
    },
    Mapping {
        rule: "qa.release.migration_failure",
        wstg: &["WSTG-IDNT-02"],
        api_top10: &[],
        asvs: &[],
    },
    Mapping {
        rule: "qa.suite.untested_routes",
        wstg: &["WSTG-APIT-01"],
        api_top10: &[],
        asvs: &[],
    },
];

/// All known mappings.
pub fn table() -> &'static [Mapping] {
    MAP
}

/// Mapping of one rule, if it is in the table.
pub fn lookup(rule: &str) -> Option<&'static Mapping> {
    MAP.iter().find(|m| m.rule == rule)
}

/// WSTG group of an id (`WSTG-ATHZ-02` -> `ATHZ`), or None for an unknown group.
pub fn group_of(id: &str) -> Option<&'static str> {
    let rest = id.strip_prefix("WSTG-")?;
    let g = rest.split('-').next()?;
    WSTG_GROUPS.iter().find(|(k, _)| *k == g).map(|(k, _)| *k)
}

/// Coverage of one WSTG group.
#[derive(Debug, Clone, Serialize)]
pub struct GroupCoverage {
    pub group: &'static str,
    pub label: &'static str,
    /// Rules mapped to this group.
    pub total: usize,
    /// 1 when at least one rule of the group ran, else 0.
    pub covered: usize,
    /// Rules of this group that ran.
    pub hit_rules: Vec<String>,
}

/// Per-group coverage, given the rules that actually ran or produced evidence.
pub fn coverage(executed: &BTreeSet<&str>) -> Vec<GroupCoverage> {
    let mut by_group: BTreeMap<&'static str, (usize, Vec<String>)> = BTreeMap::new();
    for m in MAP {
        for id in m.wstg {
            let Some(g) = group_of(id) else { continue };
            let e = by_group.entry(g).or_default();
            e.0 += 1;
            if executed.contains(m.rule) && !e.1.iter().any(|r| r == m.rule) {
                e.1.push(m.rule.to_string());
            }
        }
    }
    let keys: Vec<&'static str> = by_group.keys().copied().collect();
    WSTG_GROUPS
        .iter()
        .filter(|(g, _)| keys.contains(g))
        .filter_map(|(g, label)| {
            let (total, hit_rules) = by_group.remove(g)?;
            Some(GroupCoverage {
                group: g,
                label,
                total,
                covered: usize::from(!hit_rules.is_empty()),
                hit_rules,
            })
        })
        .collect()
}

/// Rules a check id executes when it runs (pass or fail), so coverage counts checks that
/// ran cleanly, not only checks that produced defects.
pub fn rules_of_check(check_id: &str) -> &'static [&'static str] {
    // check id -> the qa.pentest.* rules its probes cover. Derived from MAP by hand; the
    // test below keeps it in sync.
    match check_id {
        "qa.pentest.files" => &["qa.pentest.sensitive_file"],
        "qa.pentest.methods" => &["qa.pentest.dangerous_method"],
        "qa.pentest.jwt" | "qa.pentest.jwt_tamper" => &["qa.pentest.weak_jwt"],
        "qa.pentest.input" => &[
            "qa.pentest.injection_reflected",
            "qa.pentest.open_redirect",
            "qa.pentest.path_traversal",
            "qa.pentest.ssrf_canary",
        ],
        "qa.pentest.session" => &[
            "qa.pentest.session_fixation",
            "qa.pentest.session_not_revoked",
        ],
        "qa.pentest.headers" => &["qa.pentest.private_cacheable", "qa.pentest.csrf_missing"],
        "qa.pentest.ratelimit" => &["qa.pentest.no_rate_limit"],
        "qa.pentest.apilogic" => &["qa.pentest.auth_bypass"],
        "qa.pentest.cors" => &[
            "qa.pentest.cors_wildcard",
            "qa.pentest.cors_null_origin",
            "qa.pentest.cors_unvalidated_origin",
        ],
        "qa.pentest.cookies" => &[
            "qa.pentest.cookie_flags",
            "qa.pentest.cookie_no_httponly",
            "qa.pentest.cookie_no_secure",
            "qa.pentest.cookie_samesite_none_insecure",
        ],
        _ => &[],
    }
}

/// Rules of the table no run touched — the QA lead's "not tested" list.
pub fn unmapped(executed: &BTreeSet<&str>) -> Vec<&'static str> {
    MAP.iter()
        .filter(|m| !executed.contains(m.rule))
        .map(|m| m.rule)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_wstg_id_has_a_known_group() {
        for m in table() {
            for id in m.wstg {
                assert!(group_of(id).is_some(), "unknown WSTG group in {id}");
            }
        }
    }

    #[test]
    fn rules_are_unique() {
        let mut seen = BTreeSet::new();
        for m in table() {
            assert!(seen.insert(m.rule), "duplicate rule {}", m.rule);
        }
    }

    #[test]
    fn coverage_counts_hit_groups() {
        let mut s = BTreeSet::new();
        s.insert("qa.api.bola");
        let cov = coverage(&s);
        let authz = cov.iter().find(|c| c.group == "ATHZ").expect("ATHZ group");
        assert_eq!(authz.covered, 1);
        assert!(authz.hit_rules.contains(&"qa.api.bola".to_string()));
        let sess = cov.iter().find(|c| c.group == "SESS").expect("SESS group");
        assert_eq!(sess.covered, 0);
    }

    #[test]
    fn check_rule_map_stays_in_table() {
        for check in [
            "qa.pentest.files",
            "qa.pentest.methods",
            "qa.pentest.jwt",
            "qa.pentest.input",
            "qa.pentest.session",
            "qa.pentest.headers",
            "qa.pentest.ratelimit",
            "qa.pentest.apilogic",
            "qa.pentest.cors",
            "qa.pentest.cookies",
        ] {
            for rule in rules_of_check(check) {
                assert!(lookup(rule).is_some(), "{rule} mapped");
            }
        }
    }

    #[test]
    fn unmapped_lists_untouched_rules() {
        let mut s = BTreeSet::new();
        s.insert("qa.api.bola");
        let u = unmapped(&s);
        assert!(!u.contains(&"qa.api.bola"));
        assert!(u.contains(&"qa.data.pii_exposed"));
    }
}
