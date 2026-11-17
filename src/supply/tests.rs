use serde_json::Value;

use super::api_contract::{parse_oasdiff, parse_spectral};
use super::mutation::{
    parse_cargo_mutants, parse_mutmut_meta, parse_stryker,
};
use super::osv::{enrich_osv_with_ast, parse_osv};
use super::scorecard::{
    github_slug, parse_scorecard, remote_url, slug_from_target_raw,
};
use super::*;
use crate::model::{Category, Finding, Severity};

// Real outputs captured 2026-10-30: osv-scanner v2.7.0 (Go module, golang.org/x/text 0.3.7),
// scorecard v5.6.0 (--local), spectral 6.17.0, oasdiff (breaking, json).
const OSV: &str = include_str!("../../tests/fixtures/tool-outputs/osv-scanner.json");
const OSV_NOCALL: &str = include_str!("../../tests/fixtures/tool-outputs/osv-scanner-nocall.json");
const SCORECARD: &str = include_str!("../../tests/fixtures/tool-outputs/scorecard.json");
const SPECTRAL: &str = include_str!("../../tests/fixtures/tool-outputs/spectral.json");
const OASDIFF: &str = include_str!("../../tests/fixtures/tool-outputs/oasdiff.json");
// Format-faithful, hand-built (the real tools were not runnable here).
const CARGO_MUTANTS: &str =
    include_str!("../../tests/fixtures/tool-outputs/mutation-cargo-mutants.json");
const STRYKER: &str = include_str!("../../tests/fixtures/tool-outputs/mutation-stryker.json");

fn fin(mut v: Vec<Finding>) -> Vec<Finding> {
    v.iter_mut().for_each(|f| f.finalize());
    v
}

#[test]
fn osv_unreachable_lowers_one_level() {
    let f = fin(parse_osv(OSV).unwrap());
    assert_eq!(f.len(), 3);
    let a = f.iter().find(|x| x.rule == "CVE-2022-32149").unwrap();
    // CVSS 7.5 = High, lowered to Medium because call analysis found it uncalled.
    assert_eq!(a.severity, Severity::Medium);
    assert!(a.title.contains("(unreachable)"), "{}", a.title);
    assert!(a.detail.contains("lowered high -> medium"), "{}", a.detail);
    assert_eq!(a.package.as_deref(), Some("golang.org/x/text"));
    assert_eq!(a.fix_version.as_deref(), Some("0.3.8"));
    assert_eq!(a.location, "go.mod");
    assert!(a.ids.contains(&"GO-2022-1059".to_string()));
    assert_eq!(a.category, Category::SupplyChain);
    let g = fin(parse_osv(&OSV.replace("0.3.7", "0.3.6")).unwrap());
    let b = g.iter().find(|x| x.rule == "CVE-2022-32149").unwrap();
    assert_eq!(a.fingerprint, b.fingerprint);
}

#[test]
fn osv_unknown_never_lowers_and_reachable_keeps() {
    let u = fin(parse_osv(OSV_NOCALL).unwrap());
    let a = u.iter().find(|x| x.rule == "CVE-2022-32149").unwrap();
    assert_eq!(a.severity, Severity::High);
    assert!(a.title.contains("(unknown)"));
    // Ungraded groups (empty max_severity) fall back to Medium or the advisory rating.
    assert!(u.iter().all(|x| x.detail.contains("Reachability: unknown")));
    // Flip the first group to called=true: reachable, full severity.
    let r = OSV.replacen("\"called\": false", "\"called\": true", 1);
    let f = fin(parse_osv(&r).unwrap());
    let a = f.iter().find(|x| x.rule == "CVE-2022-32149").unwrap();
    assert_eq!(a.severity, Severity::High);
    assert!(a.title.contains("(reachable)"));
}

#[test]
fn osv_any_called_is_reachable_and_empty_is_unknown() {
    let mut v: Value = serde_json::from_str(OSV).unwrap();
    v["results"][0]["packages"][0]["groups"][0]["experimental_analysis"] = serde_json::json!({
        "GO-2022-1059": {"called": false},
        "GHSA-69ch-w2m2-3vjp": {"called": true}
    });
    let f = parse_osv(&v.to_string()).unwrap();
    let a = f.iter().find(|x| x.rule == "CVE-2022-32149").unwrap();
    assert!(a.title.contains("(reachable)"));
    assert_eq!(a.severity, Severity::High);
    v["results"][0]["packages"][0]["groups"][0]["experimental_analysis"] =
        serde_json::json!({});
    let f = parse_osv(&v.to_string()).unwrap();
    let a = f.iter().find(|x| x.rule == "CVE-2022-32149").unwrap();
    assert!(a.title.contains("(unknown)"));
    assert!(parse_osv("").unwrap().is_empty());
}

#[test]
fn scorecard_golden() {
    let f = fin(parse_scorecard(SCORECARD).unwrap());
    let rules: Vec<_> = f.iter().map(|x| x.rule.as_str()).collect();
    assert!(rules.contains(&"scorecard.token_permissions"), "{rules:?}");
    assert!(rules.contains(&"scorecard.pinned_dependencies"));
    // scores >= 5 and -1 (inconclusive) never produce findings
    assert!(!rules.contains(&"scorecard.binary_artifacts"));
    assert!(!rules.contains(&"scorecard.fuzzing"));
    let t = f
        .iter()
        .find(|x| x.rule == "scorecard.token_permissions")
        .unwrap();
    assert_eq!(t.severity, Severity::Medium);
    assert_eq!(t.category, Category::SupplyChain);
    assert!(t.title.contains("0/10"));
}

#[test]
fn github_remote_parsing() {
    let ok = Some("github.com/o/r".to_string());
    assert_eq!(github_slug("https://github.com/o/r.git"), ok);
    assert_eq!(github_slug("git@github.com:o/r.git"), ok);
    assert_eq!(github_slug("https://tok:x@github.com/o/r"), ok);
    assert_eq!(github_slug("ssh://git@github.com/o/r.git"), ok);
    assert_eq!(github_slug("https://gitlab.com/o/r.git"), None);
    assert_eq!(github_slug("https://github.com/o/r/extra"), None);
    assert_eq!(github_slug("https://github.com.evil.io/o/r"), None);
    let cfg = "[core]\n\tbare = false\n[remote \"fork\"]\n\turl = https://github.com/a/b\n[remote \"origin\"]\n\turl = git@github.com:o/r.git\n";
    assert_eq!(remote_url(cfg).as_deref(), Some("git@github.com:o/r.git"));
    assert_eq!(remote_url("[core]\n"), None);
}

#[test]
fn scorecard_slug_comes_from_the_remote_target_url() {
    // A remote clone is deleted after the snapshot, so the slug has to come from target.raw.
    let ok = Some("github.com/o/r".to_string());
    assert_eq!(slug_from_target_raw("https://github.com/o/r"), ok);
    assert_eq!(slug_from_target_raw("https://github.com/o/r.git"), ok);
    assert_eq!(slug_from_target_raw("git:https://github.com/o/r.git"), ok);
    assert_eq!(slug_from_target_raw("git@github.com:o/r.git"), ok);
    assert_eq!(slug_from_target_raw("https://tok:x@github.com/o/r"), ok);
    // not GitHub, or not a remote at all
    assert_eq!(slug_from_target_raw("https://gitlab.com/o/r.git"), None);
    assert_eq!(slug_from_target_raw("/targets/my-repo"), None);
    assert_eq!(slug_from_target_raw("image:nginx:1.27"), None);
}

#[test]
fn spectral_golden() {
    let f = fin(parse_spectral(SPECTRAL).unwrap());
    assert_eq!(f.len(), 8);
    let e = f.iter().find(|x| x.rule == "spectral.path-params").unwrap();
    assert_eq!(e.severity, Severity::Medium);
    assert_eq!(e.location, "openapi.yaml:13");
    assert!(e.detail.contains("/paths//pets/{id}/get"));
    let w = f
        .iter()
        .find(|x| x.rule == "spectral.info-contact")
        .unwrap();
    assert_eq!(w.severity, Severity::Low);
    assert_eq!(w.category, Category::Quality);
    assert!(parse_spectral("").unwrap().is_empty());
}

#[test]
fn oasdiff_golden() {
    let f = fin(parse_oasdiff(OASDIFF, "api/openapi.yaml").unwrap());
    assert_eq!(f.len(), 2);
    assert_eq!(f[0].rule, "oasdiff.request-parameter-became-required");
    assert_eq!(f[0].severity, Severity::High);
    assert_eq!(f[0].location, "api/openapi.yaml GET /pets");
    assert_eq!(f[1].rule, "oasdiff.api-path-removed-without-deprecation");
    assert_eq!(f[0].category, Category::Reliability);
    assert!(parse_oasdiff("[]", "x").unwrap().is_empty());
}

#[test]
fn mutation_scores() {
    let c = parse_cargo_mutants(CARGO_MUTANTS).unwrap();
    // 3 caught + 1 timeout vs 4 missed; unviable and Baseline excluded.
    assert_eq!((c.detected, c.total), (4, 8));
    assert!((c.percent() - 50.0).abs() < 0.1);
    let s = parse_stryker(STRYKER).unwrap();
    // Killed 2 + Timeout 1 vs Survived 1 + NoCoverage 1; CompileError excluded.
    assert_eq!((s.detected, s.total), (3, 5));
    assert!(parse_stryker("{").is_none());
    let m = parse_mutmut_meta(r#"{"exit_code_by_key":{"a":1,"b":0,"c":null,"d":36}}"#).unwrap();
    assert_eq!((m.detected, m.total), (2, 3));
    let top =
        parse_cargo_mutants(r#"{"caught":8,"missed":2,"timeout":0,"unviable":5}"#).unwrap();
    assert_eq!((top.detected, top.total), (8, 10));
}

#[test]
fn registered() {
    let ids: Vec<String> = checks().into_iter().map(|c| c.id).collect();
    for i in [
        "tool.osv_reachability",
        "tool.scorecard",
        "tool.spectral",
        "tool.oasdiff",
        "qa.suite.mutation",
    ] {
        assert!(ids.iter().any(|x| x == i), "{i}");
    }
    let e = crate::tools::lock_entries();
    for t in ["osv-scanner", "scorecard", "spectral", "oasdiff"] {
        assert!(e[t].digest.starts_with("sha256:"), "{t}");
    }
}

#[test]
fn osv_ast_import_enrichment_preserves_unknown_severity() {
    let dir = std::env::temp_dir().join(format!(
        "rh-osv-ast-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("main.go"),
        "package main\nimport \"golang.org/x/text/language\"\nfunc main() { _ = language.English }\n",
    )
    .unwrap();

    let mut findings = fin(parse_osv(OSV_NOCALL).unwrap());
    let before_sev = findings
        .iter()
        .find(|x| x.rule == "CVE-2022-32149")
        .unwrap()
        .severity;
    enrich_osv_with_ast(&mut findings, &dir);
    let _ = std::fs::remove_dir_all(&dir);

    let a = findings
        .iter()
        .find(|x| x.rule == "CVE-2022-32149")
        .unwrap();
    assert_eq!(a.severity, before_sev);
    assert!(
        a.detail.starts_with("Reachability: unknown"),
        "{}",
        a.detail
    );
    assert!(
        a.detail
            .contains("AST import check: package is imported in source code."),
        "{}",
        a.detail
    );
}
