use super::docker::{exec_with, rewrite_scrubbed};
use super::pinning::{
    digest_drift, pick_lock_text, plugin_pull_plan, pull_plugin_refs, ref_with_digest,
    resolve_entry,
};
use super::plugins::exit_incompleteness;
use super::types::LockFile;
use super::*;
use crate::ctx::Ctx;
use crate::model::{
    Category, CheckResult, CheckStatus, Finding, Profile, Severity, TargetKind, Verdict,
};
use anyhow::anyhow;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- run_capped

#[test]
fn run_capped_kills_on_timeout() {
    let t0 = Instant::now();
    let o = run_capped(
        Command::new("sh").args(["-c", "sleep 30"]),
        Duration::from_millis(300),
        1024,
        None,
    )
    .unwrap();
    assert!(o.timed_out && !o.success() && o.status.is_none());
    assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
}

#[test]
fn run_capped_bounds_output_and_keeps_the_tail() {
    // ~2 MiB of output with cap 1 KiB: head capped, tail retained, child not blocked
    let o = run_capped(
        Command::new("sh").args(["-c", "yes abcdefgh | head -c 2000000; echo END-MARKER"]),
        Duration::from_secs(20),
        1024,
        None,
    )
    .unwrap();
    assert!(o.success() && o.truncated);
    assert_eq!(o.stdout.len(), 1024);
    assert!(String::from_utf8_lossy(&o.stdout_tail).contains("END-MARKER"));
}

#[test]
fn run_capped_stdin_is_null_and_stdout_is_captured() {
    // `cat` would hang on an inherited terminal/pipe; with null stdin it returns at once
    let o = run_capped(&mut Command::new("cat"), Duration::from_secs(5), 1024, None).unwrap();
    assert!(o.success() && o.stdout.is_empty());
    let o = run_capped(
        &mut Command::new("cat"),
        Duration::from_secs(5),
        1024,
        Some(b"piped in"),
    )
    .unwrap();
    assert_eq!(o.stdout_lossy(), "piped in");
    let o = run_capped(
        Command::new("sh").args(["-c", "echo out; echo err >&2; exit 3"]),
        Duration::from_secs(5),
        1024,
        None,
    )
    .unwrap();
    assert_eq!(
        (
            o.stdout_lossy().trim(),
            o.stderr_lossy().trim(),
            o.status.and_then(|s| s.code())
        ),
        ("out", "err", Some(3))
    );
    assert!(
        run_capped(
            &mut Command::new("/nonexistent/binary"),
            Duration::from_secs(1),
            10,
            None
        )
        .is_err()
    );
}

#[test]
fn run_capped_does_not_wait_for_a_grandchild_holding_the_pipe() {
    // the shell exits at once but leaves `sleep` holding stdout open
    let t0 = Instant::now();
    let o = run_capped(
        Command::new("sh").args(["-c", "sleep 20 & echo started"]),
        Duration::from_secs(10),
        1024,
        None,
    )
    .unwrap();
    assert!(o.success());
    assert!(t0.elapsed() < Duration::from_secs(6), "{:?}", t0.elapsed());
}

const SECRET: &str = "FAKE-SECRET-VALUE-9f8e7d6c";
const GITLEAKS: &str = include_str!("../../tests/fixtures/tool-outputs/gitleaks.json");
const GRYPE: &str = include_str!("../../tests/fixtures/tool-outputs/grype.json");
const SEMGREP: &str = include_str!("../../tests/fixtures/tool-outputs/semgrep.json");
const HADOLINT: &str = include_str!("../../tests/fixtures/tool-outputs/hadolint.json");
const CHECKOV: &str = include_str!("../../tests/fixtures/tool-outputs/checkov.json");
const DOCKLE: &str = include_str!("../../tests/fixtures/tool-outputs/dockle.json");
const JUNIT: &str = include_str!("../../tests/fixtures/tool-outputs/junit.xml");
const SARIF: &str = include_str!("../../tests/fixtures/tool-outputs/sarif.json");
const SARIF_INCOMPLETE: &str =
    include_str!("../../tests/fixtures/tool-outputs/sarif-incomplete.json");
const SARIF_NOTIFICATION: &str =
    include_str!("../../tests/fixtures/tool-outputs/sarif-notification.json");

fn dump(f: &[Finding]) -> String {
    serde_json::to_string(f).unwrap()
}
fn fin(mut v: Vec<Finding>) -> Vec<Finding> {
    v.iter_mut().for_each(|f| f.finalize());
    v
}

#[test]
fn policy_rejects_bad_args() {
    let v = |a: &[&str]| {
        validate_create_policy(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    };
    assert!(v(&["--privileged"]).is_err());
    assert!(v(&["--network", "host"]).is_err());
    assert!(v(&["--network=host"]).is_err());
    assert!(v(&["-v", "/var/run/docker.sock:/var/run/docker.sock"]).is_err());
    assert!(v(&["-v", "/etc:/etc:ro"]).is_err());
    assert!(v(&["--mount", "type=bind,src=/,dst=/host"]).is_err());
    assert!(
        v(&[
            "-v",
            "/a/b:/src:ro",
            "--network",
            "none",
            "--cap-drop",
            "ALL"
        ])
        .is_ok()
    );
}

#[test]
fn lock_loads_and_pins() {
    let (img, pinned) = image_for("grype");
    // tools.lock.toml pins grype by digest
    assert!(img.starts_with("anchore/grype@sha256:"), "{img}");
    assert!(pinned);
    assert_eq!(
        ref_with_digest("a/b:1.0", "sha256:abc"),
        ("a/b@sha256:abc".to_string(), true)
    );
    assert_eq!(
        ref_with_digest("localhost:5000/b:1.0", "sha256:abc").0,
        "localhost:5000/b@sha256:abc"
    );
}

#[test]
fn gitleaks_golden() {
    let f = fin(parse_gitleaks(GITLEAKS).unwrap());
    assert_eq!(f.len(), 2);
    assert_eq!(f[0].rule, "secrets.aws-access-token");
    assert_eq!(f[0].severity, Severity::High);
    assert_eq!(f[0].location, "config/settings.py:12");
    assert!(!dump(&f).contains(SECRET));
    let scrubbed = scrub_gitleaks(GITLEAKS).unwrap();
    assert!(!scrubbed.contains(SECRET));
}

#[test]
fn grype_golden_and_fp_stability() {
    let f = fin(parse_grype(GRYPE).unwrap());
    assert_eq!(f.len(), 2);
    assert_eq!(f[0].rule, "GHSA-xxxx-yyyy-zzzz");
    assert_eq!(f[0].severity, Severity::High);
    assert_eq!(f[0].fix_version.as_deref(), Some("2.31.0"));
    assert_eq!(f[0].epss, Some(0.0123));
    assert_eq!(f[0].category, Category::SupplyChain);
    assert!(f[0].ids.contains(&"CVE-2024-35195".to_string()));
    assert_eq!(f[0].location, "requirements.txt");
    assert!(f[1].kev);
    assert_eq!(f[1].category, Category::Security);
    assert_eq!(f[1].severity, Severity::Critical);
    let g = fin(parse_grype(&GRYPE.replace("2.25.0", "2.26.0")).unwrap());
    assert_eq!(f[0].fingerprint, g[0].fingerprint);
    assert_ne!(f[0].version, g[0].version);
}

#[test]
fn semgrep_golden() {
    let f = fin(parse_semgrep(SEMGREP).unwrap());
    assert_eq!(f.len(), 2);
    assert_eq!(f[0].severity, Severity::High);
    assert_eq!(f[1].severity, Severity::Medium);
    assert_eq!(f[0].location, "app/db.py:42");
    assert!(!dump(&f).contains(SECRET));
    assert!(!scrub_semgrep(SEMGREP).unwrap().contains(SECRET));
    // line-number shift keeps the fingerprint
    let g = fin(parse_semgrep(&SEMGREP.replace("\"line\":42", "\"line\":50")).unwrap());
    assert_eq!(f[0].fingerprint, g[0].fingerprint);
}

#[test]
fn opengrep_golden_and_taint_trace() {
    let (img, pinned) = image_for("opengrep");
    assert!(img.starts_with("wollomatic/opengrep@sha256:"), "{img}");
    assert!(pinned);
    assert!(checks().iter().any(|c| c.id == "tool.opengrep"));

    let j = format!(
        r#"{{"results":[{{"check_id":"cache.opengrep.python.sqli.tainted-sql","path":"/src/app/routes.py","start":{{"line":27}},"extra":{{"severity":"ERROR","message":"SQL query constructed from user input","lines":"cur.execute(q) # {SECRET}","dataflow_trace":{{"taint_source":["CliLoc",[{{"path":"/src/app/routes.py","start":{{"line":12}}}},"request.args.get"]],"intermediate_vars":[{{"location":{{"path":"/src/app/routes.py","start":{{"line":19}}}},"content":"q"}}],"taint_sink":["CliLoc",[{{"path":"/src/app/routes.py","start":{{"line":27}}}},"cur.execute(q)"]]}}}}}}]}}"#
    );
    let f = fin(parse_opengrep(&j).unwrap());
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].check, "tool.opengrep");
    assert_eq!(f[0].rule, "python.sqli.tainted-sql");
    assert_eq!(f[0].severity, Severity::High);
    assert_eq!(f[0].location, "app/routes.py:27");
    assert!(
        f[0].detail.contains("12") && f[0].detail.contains("27"),
        "{}",
        f[0].detail
    );
    assert!(!dump(&f).contains(SECRET));
    let scrubbed = scrub_semgrep(&j).unwrap();
    assert!(!scrubbed.contains(SECRET));
}

#[test]
fn hadolint_golden() {
    let f = parse_hadolint(HADOLINT).unwrap();
    assert_eq!(f.len(), 3);
    assert_eq!(f[0].location, "Dockerfile:1");
    assert_eq!(f[0].severity, Severity::Medium);
    assert_eq!(f[1].category, Category::Security);
    assert_eq!(f[2].severity, Severity::High);
    assert_eq!(f[2].location, "sub/Dockerfile:3");
}

#[test]
fn checkov_golden() {
    let f = parse_checkov(CHECKOV).unwrap();
    assert_eq!(f.len(), 2);
    assert_eq!(f[0].rule, "CKV_K8S_23");
    assert_eq!(f[0].severity, Severity::Medium);
    assert_eq!(f[0].location, "deploy/app.yaml:1");
    assert_eq!(f[1].severity, Severity::High);
    assert!(!dump(&f).contains(SECRET));
    assert!(!scrub_checkov(CHECKOV).unwrap().contains(SECRET));
    // list form
    let l = format!("[{CHECKOV}]");
    assert_eq!(parse_checkov(&l).unwrap().len(), 2);
}

#[test]
fn dockle_golden() {
    let f = parse_dockle(DOCKLE, "app:1").unwrap();
    assert_eq!(f.len(), 3);
    assert_eq!(f[0].severity, Severity::Medium);
    assert_eq!(f[1].severity, Severity::High);
    assert_eq!(f[2].severity, Severity::Low);
    assert_eq!(f[0].location, "app:1");
}

#[test]
fn image_inspect_rules() {
    let j = r#"[{"Size":2000000000,"Config":{"User":"","Healthcheck":null}}]"#;
    let f = parse_image_inspect(j, "myapp:latest").unwrap();
    let rules: Vec<&str> = f.iter().map(|x| x.rule.as_str()).collect();
    for r in [
        "image.root_user",
        "image.no_healthcheck",
        "image.large",
        "image.latest_tag",
    ] {
        assert!(rules.contains(&r), "{r}");
    }
    let ok = r#"[{"Size":10,"Config":{"User":"1000","Healthcheck":{"Test":["CMD","true"]}}}]"#;
    assert!(parse_image_inspect(ok, "myapp:1.2").unwrap().is_empty());
}

#[test]
fn junit_golden() {
    let c = parse_junit(JUNIT);
    assert_eq!(c.len(), 4);
    assert!(c[1].failed);
    assert_eq!(c[1].message, "assert 1 < 0 && \"x\"");
    assert_eq!(c[1].suite, "tests.test_a");
    assert!(c[2].errored && !c[2].failed);
    assert!(c[3].skipped);
    let o = junit_output(JUNIT, 1);
    assert_eq!(o.findings.len(), 1);
    assert_eq!(o.findings[0].rule, "tests.failed");
    assert_eq!(o.findings[0].location, "tests.test_a::test_bad");
    let errs = r#"<testsuite><testcase classname="a" name="b"><error message="x"/></testcase></testsuite>"#;
    assert!(matches!(
        junit_output(errs, 1).status,
        Some(CheckStatus::Errored(_))
    ));
}

#[test]
fn sarif_golden() {
    let f = parse_sarif_report(SARIF, "plugin.x").unwrap().0;
    assert_eq!(f.len(), 2);
    assert_eq!(f[0].rule, "XR001");
    assert_eq!(f[0].severity, Severity::High);
    assert_eq!(f[0].location, "a/b.py:5");
    assert_eq!(f[1].severity, Severity::Low);
}

/// A tool that reports a broken run must never look like a clean scan: an empty `results`
/// with `executionSuccessful: false` yields an incompleteness note, not silence.
#[test]
fn sarif_incomplete_run_is_never_clean() {
    let (f, notes) = parse_sarif_report(SARIF_INCOMPLETE, "plugin.x").unwrap();
    assert!(f.is_empty());
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(notes[0].contains("executionSuccessful=false"), "{notes:?}");
    assert!(notes[0].contains("permission denied"), "{notes:?}");
    // Partial status is what keeps the gate from passing on unknown coverage.
    let out = partial(notes, f);
    let status = out.status.expect("partial status");
    assert!(matches!(status, CheckStatus::Partial(_)));
    let check = CheckResult {
        id: "plugin.x".into(),
        title: String::new(),
        tool: Some("x".into()),
        status,
        findings: 0,
        duration_ms: 0,
    };
    let pol = crate::policy::Policy::load(None).unwrap();
    let (v, reasons) = crate::policy::verdict(&pol, &[], std::slice::from_ref(&check));
    assert_ne!(v, Verdict::Pass, "{reasons:?}");
}

/// A note-level notification is normal chatter; an error/exception one is not.
#[test]
fn sarif_error_notification_is_incomplete_but_note_is_not() {
    let (_, notes) = parse_sarif_report(SARIF_NOTIFICATION, "plugin.x").unwrap();
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(notes[0].contains("error notification"), "{notes:?}");
    assert!(notes[0].contains("rule R7 crashed"), "{notes:?}");
    let (_, clean) = parse_sarif_report(SARIF, "plugin.x").unwrap();
    assert!(clean.is_empty(), "honest SARIF must stay clean: {clean:?}");
}

/// Every exit code decides it; only the exempt `lines` format stays silent on a non-zero exit.
#[test]
fn nonzero_exit_with_parseable_output_is_partial() {
    assert!(exit_incompleteness("sarif", 0, "").is_none());
    assert!(exit_incompleteness("lines", 1, "boom").is_none());
    let n = exit_incompleteness("sarif", 3, "line1\nline2").unwrap();
    assert!(n.contains("exited 3") && n.contains("line1"), "{n}");
}

#[test]
fn plugin_loading() {
    let dir = std::env::temp_dir().join(format!("readyhai-plug-{:08x}", rand::random::<u32>()));
    let p = dir.join("demo");
    std::fs::create_dir_all(&p).unwrap();
    std::fs::write(
        p.join("plugin.toml"),
        r#"
id = "demo"
title = "Demo plugin"
kinds = ["repo", "image"]
profile = "quick"
image = "example/demo@sha256:0000"
args = ["--src", "{src}", "--out", "{out}/demo.sarif"]
network = false
output = "/out/demo.sarif"
format = "sarif"
"#,
    )
    .unwrap();
    std::fs::create_dir_all(dir.join("bad")).unwrap();
    std::fs::write(dir.join("bad").join("plugin.toml"), "not toml [").unwrap();
    let c = plugin_checks(&dir);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].id, "plugin.demo");
    assert_eq!(c[0].kinds, vec![TargetKind::Repo, TargetKind::Image]);
    assert_eq!(c[0].min_profile, Profile::Quick);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn plugin_new_fields_parse_and_validate() {
    let dir = std::env::temp_dir().join(format!("readyhai-plug2-{:08x}", rand::random::<u32>()));
    let mk = |name: &str, body: &str| {
        let p = dir.join(name);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("plugin.toml"), body).unwrap();
    };
    mk(
        "ok",
        r#"
id = "ok"
kinds = ["web"]
image = "x/y@sha256:0000"
stdout = true
env = ["MY_TOKEN"]
cache_rw = true
host_gateway = true
user = "1000:1000"
intrusive = true
format = "readyhai-json"
"#,
    );
    mk(
        "baduser",
        r#"
id = "baduser"
kinds = ["web"]
image = "x/y"
output = "/out/x.sarif"
user = "root"
format = "sarif"
"#,
    );
    mk(
        "badenv",
        r#"
id = "badenv"
kinds = ["web"]
image = "x/y"
output = "/out/x.sarif"
env = ["OK_1", "not an ident!"]
format = "sarif"
"#,
    );
    mk(
        "noout",
        r#"
id = "noout"
kinds = ["web"]
image = "x/y"
format = "sarif"
"#,
    );
    let c = plugin_checks(&dir);
    assert_eq!(c.len(), 1, "only the valid plugin loads: {:?}", c.iter().map(|x| &x.id).collect::<Vec<_>>());
    assert_eq!(c[0].id, "plugin.ok");
    assert!(c[0].intrusive);
    assert_eq!(c[0].kinds, vec![TargetKind::Web]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A plugin dir with one loaded, one parse-broken, and one rule-violating pack.
/// `loaddemo` loads (no `[plugin]` output but stdout=true), `broken` fails to parse,
/// `noout` is a valid file format plugin with no output path.
fn plug_diag_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rh-{tag}-{:08x}", rand::random::<u32>()));
    let mk = |name: &str, body: &str| {
        let p = dir.join(name);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("plugin.toml"), body).unwrap();
    };
    mk(
        "loaddemo",
        r#"
id = "loaddemo"
kinds = ["repo"]
image = "demo/x@sha256:aaaa"
stdout = true
format = "json"
"#,
    );
    mk("broken", "this is = not valid toml [");
    mk(
        "noout",
        r#"
id = "noout"
kinds = ["repo"]
image = "demo/y"
format = "sarif"
"#,
    );
    dir
}

#[test]
fn plugin_diags_report_load_and_skip_reasons() {
    let dir = plug_diag_dir("diag");
    // A directory without a readable plugin.toml is not a candidate at all.
    std::fs::create_dir_all(dir.join("notapack")).unwrap();
    let d = plugin_diags(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    let loaded: Vec<&str> = d
        .iter()
        .filter(|x| matches!(x.status, PluginLoad::Loaded))
        .map(|x| x.id.as_str())
        .collect();
    let skipped: Vec<&str> = d
        .iter()
        .filter(|x| matches!(x.status, PluginLoad::Skipped))
        .map(|x| x.id.as_str())
        .collect();
    let order: Vec<&str> = d.iter().map(|x| x.id.as_str()).collect();
    assert_eq!(
        order,
        ["broken", "loaddemo", "noout"],
        "sorted by dir, one record per candidate pack"
    );
    assert_eq!(loaded, ["loaddemo"]);
    assert_eq!(skipped, ["broken", "noout"]);
    let broken = d.iter().find(|x| x.id == "broken").unwrap();
    let br = broken.reason.as_deref();
    assert!(br.is_some_and(|r| r.contains("parse")), "{br:?}");
    assert!(
        broken.image.is_empty(),
        "a plugin that won't parse has no image"
    );
    let loaded = d.iter().find(|x| x.id == "loaddemo").unwrap();
    assert!(loaded.reason.is_none(), "loaded plugins carry no reason");
    assert_eq!(loaded.image, "demo/x@sha256:aaaa");
    let noout = d.iter().find(|x| x.id == "noout").unwrap();
    let nr = noout.reason.as_deref();
    assert!(nr.is_some_and(|r| r.contains("no output path")), "{nr:?}");
}

#[test]
fn plugin_image_refs_only_lists_loaded() {
    let dir = plug_diag_dir("refs");
    let refs = plugin_image_refs(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        refs,
        vec![("loaddemo".to_string(), "demo/x@sha256:aaaa".to_string())]
    );
}

#[test]
fn plugin_pull_plan_dedups_across_plugins_and_lock() {
    let lock: LockFile =
        toml::from_str("[tools.grype]\nimage=\"ghcr.io/anchore/grype:v1\"\ndigest=\"sha256:g\"\n")
            .unwrap();
    let refs = vec![
        ("a".to_string(), "reg/x:1".to_string()),
        ("b".to_string(), "reg/x:1".to_string()), // dup across plugins
        ("c".to_string(), "ghcr.io/anchore/grype:v1".to_string()), // already in lock
        ("d".to_string(), String::new()),         // no image
        ("e".to_string(), "reg/y:2".to_string()),
    ];
    let plan = plugin_pull_plan(&lock, &refs);
    assert_eq!(
        plan,
        vec![
            ("a".to_string(), "reg/x:1".to_string()),
            ("e".to_string(), "reg/y:2".to_string())
        ]
    );
}

#[test]
fn digest_drift_only_when_both_pinned_and_differ() {
    // matching digests -> no warning
    assert!(
        digest_drift("r@sha256:aaa", "r@sha256:aaa").is_none(),
        "match is clean"
    );
    // differing digests -> warning naming both refs
    let w = digest_drift("r@sha256:aaa", "r@sha256:bbb").unwrap();
    assert!(
        w.contains("r@sha256:aaa") && w.contains("r@sha256:bbb"),
        "{w}"
    );
    // the plugin didn't pin a digest -> nothing to compare
    assert!(digest_drift("r:latest", "r@sha256:bbb").is_none());
    // image has no RepoDigests (locally built) -> nothing to compare
    assert!(digest_drift("r@sha256:aaa", "sha256:local").is_none());
}

#[test]
fn pull_plugin_refs_warns_and_continues_offline() {
    // No docker: the pull closure reports failure. Non-strict must not bail.
    let plan = [("x".to_string(), "reg/x:1".to_string())];
    let warns = std::cell::RefCell::new(Vec::new());
    let push = |w: String| warns.borrow_mut().push(w);
    let r = pull_plugin_refs(&plan, false, &|_| Ok(false), &|_| None, &push);
    assert!(r.is_ok(), "a failed pull without --lock is only a warning");
    let warns = warns.into_inner();
    let found = warns
        .iter()
        .any(|w| w.contains("x") && w.contains("could not be pulled"));
    assert!(found, "{warns:?}");

    // A pull that cannot even start (docker missing) is also a non-fatal warning.
    let warns2 = std::cell::RefCell::new(Vec::new());
    let push2 = |w: String| warns2.borrow_mut().push(w);
    let r2 = pull_plugin_refs(
        &plan,
        false,
        &|_| Err(anyhow!("docker: executable not found")),
        &|_| None,
        &push2,
    );
    assert!(r2.is_ok(), "docker missing must not fail the plugin pull");
    let warns2 = warns2.into_inner();
    let found2 = warns2.iter().any(|w| w.contains("executable not found"));
    assert!(found2, "{warns2:?}");

    // strict (--lock) turns a failed pull into an error.
    assert!(
        pull_plugin_refs(&plan, true, &|_| Ok(false), &|_| None, &|_| ())
            .unwrap_err()
            .to_string()
            .contains("docker pull"),
        "with --lock a failed plugin pull is fatal"
    );
}

#[test]
fn pull_plugin_refs_flags_digest_drift() {
    // Pinned plugin, digest present but different -> one drift warning.
    let plan = [("p".to_string(), "r@sha256:aaa".to_string())];
    let warns = std::cell::RefCell::new(Vec::new());
    let push = |w: String| warns.borrow_mut().push(w);
    pull_plugin_refs(
        &plan,
        false,
        &|_| Ok(true),
        &|_| Some("r@sha256:bbb".to_string()),
        &push,
    )
    .unwrap();
    let warns = warns.into_inner();
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains("drift"), "{warns:?}");

    // No RepoDigests back -> locally-built warning, no drift.
    let warns2 = std::cell::RefCell::new(Vec::new());
    let push2 = |w: String| warns2.borrow_mut().push(w);
    pull_plugin_refs(&plan, false, &|_| Ok(true), &|_| None, &push2).unwrap();
    let warns2 = warns2.into_inner();
    let found = warns2.iter().any(|w| w.contains("no registry digest"));
    assert!(found, "{warns2:?}");
}

#[test]
fn lock_precedence_env_data_embedded() {
    let d = std::env::temp_dir().join(format!("rh-lockprec-{:08x}", rand::random::<u32>()));
    std::fs::create_dir_all(&d).unwrap();
    // embedded
    assert!(pick_lock_text(None, &d).contains("anchore/grype"));
    // data dir lock beats embedded
    std::fs::write(
        d.join("tools.lock.toml"),
        "[tools.grype]\nimage=\"data/grype:1\"\n",
    )
    .unwrap();
    assert!(pick_lock_text(None, &d).contains("data/grype:1"));
    // env beats data dir
    let e = d.join("env.toml");
    std::fs::write(&e, "[tools.grype]\nimage=\"env/grype:1\"\n").unwrap();
    assert!(pick_lock_text(e.to_str(), &d).contains("env/grype:1"));
    // unreadable env falls through
    assert!(pick_lock_text(Some("/nonexistent/x"), &d).contains("data/grype:1"));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn image_resolves_by_id_when_present() {
    let e = LockEntry {
        image: "anchore/grype:latest".into(),
        digest: "sha256:aaa".into(),
        version: "x".into(),
        id: Some("sha256:bbb".into()),
    };
    let (r, pinned, by_id) = resolve_entry(&e, &|r| r == "sha256:bbb");
    assert_eq!((r.as_str(), pinned, by_id), ("sha256:bbb", true, true));
    // id not loaded -> falls back to digest ref
    let (r, pinned, by_id) = resolve_entry(&e, &|_| false);
    assert_eq!(
        (r.as_str(), pinned, by_id),
        ("anchore/grype@sha256:aaa", true, false)
    );
    // no id -> tag, unpinned
    let e2 = LockEntry {
        image: "a/b:1".into(),
        ..Default::default()
    };
    assert_eq!(
        resolve_entry(&e2, &|_| true),
        ("a/b:1".to_string(), false, false)
    );
}

#[test]
fn offline_refuses_pull_and_update() {
    let _g = crate::bundle::ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    unsafe { std::env::set_var("READYHAI_OFFLINE", "1") };
    let e1 = tools_pull(None, None).unwrap_err().to_string();
    let d = Docker {
        available: false,
        mode: MountMode::Bind,
        cache_dir: std::env::temp_dir().join("rh-off-cache"),
    };
    let e2 = tools_update(&d).unwrap_err().to_string();
    unsafe { std::env::remove_var("READYHAI_OFFLINE") };
    assert!(e1.contains("bundle import"), "{e1}");
    assert!(e2.contains("bundle import"), "{e2}");
}

#[test]
fn db_age_from_metadata() {
    let d = std::env::temp_dir().join(format!("rh-dbage-{:08x}", rand::random::<u32>()));
    std::fs::create_dir_all(d.join("grype/6")).unwrap();
    assert_eq!(db_age_days(&d), None);
    std::fs::write(d.join("grype/6/vulnerability.db"), "x").unwrap();
    assert_eq!(db_age_days(&d), Some(0));
    let _ = std::fs::remove_dir_all(&d);
}

// ---------------------------------------------------------------- bounded reads

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("readyhai-tools-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn out_ctx(tag: &str) -> Ctx {
    let d = scratch(tag);
    std::fs::create_dir_all(d.join("out")).unwrap();
    Ctx {
        run_id: "t".into(),
        target: crate::model::Target {
            kind: TargetKind::Repo,
            raw: "/t".into(),
            path: None,
            image: None,
            url: None,
            openapi: None,
            host: None,
            apk: None,
            device: None,
        },
        profile: Profile::Quick,
        run_dir: d,
        snapshot: None,
        facts: Default::default(),
        docker: Docker {
            available: false,
            mode: MountMode::Bind,
            cache_dir: PathBuf::new(),
        },
        cfg: Default::default(),
        error_lines: Default::default(),
        nonprod: false,
        qa: None,
    }
}

#[test]
fn read_text_capped_checks_the_size_first() {
    let d = scratch("cap");
    let f = d.join("big.json");
    std::fs::write(&f, "x".repeat(100)).unwrap();
    assert_eq!(read_text_capped(&f, 100).unwrap().len(), 100);
    let e = read_text_capped(&f, 99).unwrap_err();
    assert!(is_oversize(&e), "{e:#}");
    assert!(e.to_string().contains("exceeds"), "{e:#}");
    // a missing file is an ordinary error, not an oversize
    let e = read_text_capped(&d.join("nope.json"), 100).unwrap_err();
    assert!(!is_oversize(&e));
    // out_err keeps an oversize error and replaces everything else
    let kept = out_err(read_text_capped(&f, 10).unwrap_err(), || anyhow!("other"));
    assert!(is_oversize(&kept));
    let other = out_err(e, || anyhow!("other"));
    assert_eq!(other.to_string(), "other");
    #[cfg(unix)]
    {
        // a symlink planted in a tool's output dir is not followed
        let l = d.join("link.json");
        std::os::unix::fs::symlink(&f, &l).unwrap();
        let e = read_text_capped(&l, 1000).unwrap_err();
        assert!(e.to_string().contains("not a regular file"), "{e:#}");
    }
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn oversized_output_is_removed_not_left_unscrubbed_and_reads_as_partial() {
    let ctx = out_ctx("scrub");
    let p = ctx.out_dir().join("gitleaks.json");
    // normal file: scrubbed in place
    std::fs::write(&p, r#"[{"Secret":"hunter2","RuleID":"x"}]"#).unwrap();
    rewrite_scrubbed(&ctx, "gitleaks.json", scrub_gitleaks);
    let t = std::fs::read_to_string(&p).unwrap();
    assert!(!t.contains("hunter2") && t.contains("RuleID"), "{t}");
    // read_out over the cap: an oversize error, which the engine reports as Partial
    let big = std::fs::File::create(&p).unwrap();
    big.set_len(MAX_OUT_BYTES + 1).unwrap(); // sparse: no real disk or memory use
    drop(big);
    let e = read_out(&ctx, "gitleaks.json").unwrap_err();
    assert!(is_oversize(&e), "{e:#}");
    assert!(matches!(
        crate::engine::error_status(&e),
        CheckStatus::Partial(r) if r.contains("exceeds")
    ));
    // ...and the unscrubbable file is deleted rather than kept with secrets in it
    rewrite_scrubbed(&ctx, "gitleaks.json", scrub_gitleaks);
    assert!(!p.exists());
    // a missing output is untouched by the scrubber
    rewrite_scrubbed(&ctx, "gitleaks.json", scrub_gitleaks);
    let _ = std::fs::remove_dir_all(&ctx.run_dir);
}

#[cfg(unix)]
#[test]
fn exec_caps_a_tools_stdout() {
    use std::os::unix::fs::PermissionsExt;
    let d = scratch("fakedocker");
    // a stand-in `docker` that writes 200 000 bytes then a marker line
    let bin = d.join("docker");
    std::fs::write(
        &bin,
        "#!/bin/sh\nhead -c 200000 /dev/zero | tr '\\0' x\necho END\n",
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let docker = Docker {
        available: true,
        mode: MountMode::Bind,
        cache_dir: d.clone(),
    };
    let mut spec = ToolSpec::new("fake", &[]);
    spec.image = Some("example/fake:1".into());
    spec.timeout_secs = 30;
    let bin_s = bin.to_str().unwrap();
    // Another test thread forking while the script was open for writing can make the first exec
    // fail with "Text file busy"; that is a property of the test setup, so retry it.
    let run = |cap: usize| {
        for _ in 0..20 {
            match exec_with(bin_s, cap, &docker, "run-x", &[], &spec) {
                Err(e) if format!("{e:#}").contains("Text file busy") => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                r => return r.unwrap(),
            }
        }
        panic!("script stayed busy");
    };
    let r = run(1024);
    assert!(r.stdout_truncated);
    assert_eq!(r.stdout.len(), 1024, "head only, bounded by the cap");
    assert_eq!(r.exit_code, 0);
    // under the cap nothing is lost and nothing is flagged
    let r = run(1 << 20);
    assert!(!r.stdout_truncated);
    assert_eq!(r.stdout.len(), 200_004);
    assert!(r.stdout.ends_with("END\n"));
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn official_recon_chain_plugins_load() {
    // The Saturday recon chain (dnsx, tlsx, naabu, gau) must load from the
    // shipped packs. Assertions are narrow (ids only) so unrelated official
    // packs coming and going can't break this test.
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("plugins/official");
    let ids: Vec<String> = plugin_checks(&dir).into_iter().map(|c| c.id).collect();
    for i in ["plugin.dnsx", "plugin.tlsx", "plugin.naabu", "plugin.gau"] {
        assert!(ids.iter().any(|x| x == i), "{i} missing from {ids:?}");
    }
}

#[test]
fn builtin_checks_registered() {
    let ids: Vec<String> = checks().into_iter().map(|c| c.id).collect();
    for i in [
        "tool.gitleaks",
        "tool.sbom_cve",
        "tool.semgrep",
        "tool.hadolint",
        "tool.checkov",
        "tool.dockle",
        "image.inspect",
        "tests.own",
    ] {
        assert!(ids.iter().any(|x| x == i), "{i}");
    }
}
