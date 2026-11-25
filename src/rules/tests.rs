use super::facts::{k8s_docs_checked, split_yaml_docs};
use super::*;
use crate::model::{Finding, Severity};
use crate::model::{Target, TargetKind};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

fn ctx_for(src: &Path, tag: &str, mark_tracked: bool) -> Ctx {
    let tmp = std::env::temp_dir().join(format!("readyhai-rules-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    let mut snap = crate::snapshot::take(src, &tmp.join("src"), &[], &[]).unwrap();
    if mark_tracked {
        snap.denied.iter_mut().for_each(|d| d.tracked = true);
    }
    Ctx {
        run_id: "t".into(),
        target: Target {
            kind: TargetKind::Repo,
            raw: src.display().to_string(),
            path: Some(src.to_path_buf()),
            image: None,
            url: None,
            openapi: None,
            host: None,
            apk: None,
            device: None,
        },
        profile: Profile::Quick,
        run_dir: tmp.clone(),
        facts: detect_facts(&snap),
        snapshot: Some(snap),
        docker: crate::tools::Docker::detect(&tmp),
        cfg: Default::default(),
        error_lines: Default::default(),
        nonprod: false,
        qa: None,
    }
}

fn run_all(ctx: &Ctx) -> Vec<Finding> {
    checks()
        .iter()
        .flat_map(|c| (c.run)(ctx).unwrap().findings)
        .collect()
}

#[test]
fn fixture_findings() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vuln-app");
    let ctx = ctx_for(&src, "fx", true);
    let fc = &ctx.facts;
    assert_eq!(fc.web_framework.as_deref(), Some("fastapi"));
    assert!(fc.has_health_route && fc.has_tests && fc.has_readme && !fc.has_otel);
    assert_eq!((fc.total_deps, fc.unpinned_deps), (4, 1));
    assert_eq!(fc.k8s_files, vec!["k8s/deployment.yaml"]);
    let f = run_all(&ctx);
    let rules: HashSet<&str> = f.iter().map(|x| x.rule.as_str()).collect();
    for r in [
        "readiness.dockerfile.no_user",
        "readiness.dockerfile.no_healthcheck",
        "readiness.dockerfile.no_dockerignore",
        "readiness.deps.unpinned",
        "readiness.deps.no_lockfile",
        "readiness.compose.privileged",
        "readiness.compose.healthcheck_root_path",
        "readiness.compose.healthcheck_missing_binary",
        "readiness.compose.no_limits",
        "readiness.k8s.no_probes",
        "readiness.k8s.no_limits",
        "readiness.ci.no_sast",
        "readiness.ci.no_secret_scan",
        "readiness.ci.scanner_never_fails",
        "readiness.ci.scanner_optional",
        "readiness.repo.tracked_secret_file",
        "readiness.repo.no_otel",
    ] {
        assert!(rules.contains(r), "missing {r}; got {rules:?}");
    }
    assert!(
        !rules.contains("readiness.k8s.privileged"),
        "comment must not trigger privileged"
    );
    assert!(!rules.contains("readiness.ci.no_dep_scan"));
    assert!(
        f.iter()
            .all(|x| !x.detail.contains("rh_fixture_secret")
                && !x.title.contains("rh_fixture_secret"))
    );
}

fn dump(path: &str, tag: &str) {
    let src = PathBuf::from(path);
    let ctx = ctx_for(&src, tag, false);
    let mut ctx = ctx;
    // honor real tracked flags from the snapshot
    if let Some(s) = ctx.snapshot.as_mut() {
        s.denied
            .iter_mut()
            .for_each(|d| d.tracked = s.tracked.contains(&d.path));
    }
    println!("== {path} facts: {:?}", ctx.facts);
    for f in run_all(&ctx) {
        println!("{} | {} | {}", f.rule, f.location, f.title);
    }
}

#[test]
#[ignore]
fn nuhire_user_service() {
    dump(
        "[/home/user]/95095/Backup/Desktop/learn/nuhire/services/user-service",
        "nuhire",
    );
    dump(
        "[/home/user]/95095/Backup/Desktop/learn/nuhire/argocd",
        "argocd",
    );
}

fn tmp_repo(tag: &str, files: &[(&str, &str)]) -> PathBuf {
    let d = std::env::temp_dir().join(format!("readyhai-rules-src-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    for (p, c) in files {
        let f = d.join(p);
        fs::create_dir_all(f.parent().unwrap()).unwrap();
        fs::write(f, c).unwrap();
    }
    d
}

#[test]
fn compose_healthcheck_from_dockerfile() {
    let src = tmp_repo(
        "chc",
        &[
            (
                "docker-compose.yml",
                "services:\n  web:\n    build: ./web\n  bare:\n    build: ./bare\n",
            ),
            ("web/Dockerfile", "FROM alpine:3.19\nHEALTHCHECK CMD true\n"),
            ("bare/Dockerfile", "FROM alpine:3.19\n"),
        ],
    );
    let f = run_all(&ctx_for(&src, "chc", false));
    let hits: Vec<_> = f
        .iter()
        .filter(|x| x.rule == "readiness.compose.no_healthcheck")
        .map(|x| x.title.clone())
        .collect();
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(hits[0].contains("bare"));
}

#[test]
fn dockerfile_oneshot_skips_healthcheck() {
    let src = tmp_repo(
        "dhc",
        &[
            (
                "runners/Dockerfile",
                "FROM alpine:3.19\nUSER app\nCMD [\"server\"]\n",
            ),
            (
                "job/Dockerfile",
                "FROM alpine:3.19\nUSER app\nENTRYPOINT [\"/run.sh\"]\n",
            ),
            (
                "api/Dockerfile",
                "FROM alpine:3.19\nUSER app\nEXPOSE 80\nCMD [\"/app.sh\"]\n",
            ),
        ],
    );
    let f = run_all(&ctx_for(&src, "dhc", false));
    let locs: Vec<_> = f
        .iter()
        .filter(|x| x.rule == "readiness.dockerfile.no_healthcheck")
        .map(|x| x.location.clone())
        .collect();
    assert_eq!(locs.len(), 1, "{locs:?}");
    assert!(locs[0].starts_with("api/"));
}

#[test]
fn package_json_lockfile_downgrades() {
    let pkg = r#"{"dependencies":{"a":"^1.0.0","b":"~2.0.0"}}"#;
    let src = tmp_repo("pkg", &[("package.json", pkg), ("package-lock.json", "{}")]);
    let f = run_all(&ctx_for(&src, "pkg", false));
    let u = f
        .iter()
        .find(|x| x.rule == "readiness.deps.unpinned")
        .expect("unpinned");
    assert_eq!(u.severity, Severity::Low);
    assert!(u.detail.contains("ranges are locked by package-lock.json"));
    let src = tmp_repo("pkg2", &[("package.json", pkg)]);
    let f = run_all(&ctx_for(&src, "pkg2", false));
    let u = f
        .iter()
        .find(|x| x.rule == "readiness.deps.unpinned")
        .expect("unpinned");
    assert_eq!(u.severity, Severity::Medium);
}

fn out_of(ctx: &Ctx, id: &str) -> CheckOutput {
    let c = checks().into_iter().find(|c| c.id == id).unwrap();
    (c.run)(ctx).unwrap()
}

fn ci_findings(tag: &str, files: &[(&str, &str)]) -> Vec<Finding> {
    let src = tmp_repo(tag, files);
    out_of(&ctx_for(&src, tag, false), "readiness.ci").findings
}

fn never_fails_at(f: &[Finding]) -> Vec<String> {
    f.iter()
        .filter(|x| x.rule == "readiness.ci.scanner_never_fails")
        .map(|x| x.location.clone())
        .collect()
}

const GH: &str = ".github/workflows/ci.yml";

#[test]
fn unreadable_or_unparseable_files_make_the_check_partial_and_name_the_file() {
    let big = format!(
        "FROM alpine:3.19\nUSER app\n# {}\n",
        "x".repeat(2 * 1024 * 1024 + 10)
    );
    let src = tmp_repo(
        "partial",
        &[
            ("Dockerfile", &big),
            ("package.json", "{ not json"),
            ("docker-compose.yml", "services: [unclosed\n  web: {"),
        ],
    );
    let ctx = ctx_for(&src, "partial", false);
    for (id, file, why) in [
        ("readiness.dockerfile", "Dockerfile", "read limit"),
        ("readiness.deps", "package.json", "invalid JSON"),
        (
            "readiness.compose",
            "docker-compose.yml",
            "YAML parse error",
        ),
    ] {
        match out_of(&ctx, id).status {
            Some(CheckStatus::Partial(r)) => {
                assert!(r.contains(file) && r.contains(why), "{id}: {r}")
            }
            other => panic!("{id}: expected Partial, got {other:?}"),
        }
    }
    // a clean repo: no status override (Passed / Failed by findings)
    let ok = tmp_repo(
        "clean",
        &[(
            "Dockerfile",
            "FROM alpine:3.19\nUSER app\nHEALTHCHECK CMD true\n",
        )],
    );
    assert!(
        out_of(&ctx_for(&ok, "clean", false), "readiness.dockerfile")
            .status
            .is_none()
    );
}

#[test]
fn k8s_parsing_continues_past_a_bad_document() {
    let manifest = "\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: good
spec:
  template:
    spec:
      containers:
        - name: c
          image: nginx:1.25
          securityContext:
            privileged: true
---
apiVersion: v1
kind: ConfigMap
data: [unclosed
  - : :
---
apiVersion: v1
kind: Secret
metadata:
  name: leaked
stringData:
  k: v
";
    let src = tmp_repo("k8sbad", &[("k8s/all.yaml", manifest)]);
    let ctx = ctx_for(&src, "k8sbad", false);
    assert_eq!(ctx.facts.k8s_files, vec!["k8s/all.yaml"]);
    let o = out_of(&ctx, "readiness.k8s");
    let rules: Vec<&str> = o.findings.iter().map(|f| f.rule.as_str()).collect();
    assert!(rules.contains(&"readiness.k8s.privileged"), "{rules:?}");
    assert!(
        rules.contains(&"readiness.k8s.plaintext_secret"),
        "the document AFTER the bad one must still be checked: {rules:?}"
    );
    match o.status {
        Some(CheckStatus::Partial(r)) => assert!(
            r.contains("k8s/all.yaml") && r.contains("document 2"),
            "{r}"
        ),
        other => panic!("expected Partial, got {other:?}"),
    }
}

#[test]
fn yaml_documents_split_on_markers() {
    let d = split_yaml_docs("# c\n---\na: 1\n---\n\n---\nb: 2\n...\n");
    assert_eq!(
        d.iter().map(|x| x.1.trim().to_string()).collect::<Vec<_>>(),
        ["a: 1", "b: 2"]
    );
    assert_eq!(d[0].0, 3);
    let (docs, errs) = k8s_docs_checked("a: 1\n---\nb: [\n---\nc: 3\n");
    assert_eq!((docs.len(), errs.len()), (2, 1), "{errs:?}");
    assert!(errs[0].starts_with("document 2 (line 3)"), "{errs:?}");
}

#[test]
fn multi_line_continue_on_error_is_a_scanner_that_never_fails() {
    let wf = "\
name: ci
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Trivy scan
        uses: aquasecurity/trivy-action@0.20.0
        continue-on-error: true
      - name: Lint
        run: make lint
        continue-on-error: true
";
    let f = ci_findings("ci-step", &[(GH, wf)]);
    assert_eq!(
        never_fails_at(&f),
        [format!("{GH}:7")],
        "one finding for the Trivy step; the Lint step is not a scanner"
    );
    // the step that is a scanner but does NOT carry the key is fine, even when the next step does
    let wf = "\
jobs:
  scan:
    steps:
      - run: trivy fs .
      - run: echo done
        continue-on-error: true
";
    assert!(never_fails_at(&ci_findings("ci-next", &[(GH, wf)])).is_empty());
    // the key as the first line of the step
    let wf = "\
jobs:
  scan:
    steps:
      - continue-on-error: true
        run: |
          gitleaks detect
";
    assert_eq!(
        never_fails_at(&ci_findings("ci-first", &[(GH, wf)])).len(),
        1
    );
}

#[test]
fn job_level_continue_on_error_and_gitlab_allow_failure_are_detected() {
    let wf = "\
jobs:
  scan:
    continue-on-error: true
    steps:
      - run: gitleaks detect
  build:
    steps:
      - run: trivy fs .
";
    let f = ci_findings("ci-job", &[(GH, wf)]);
    assert_eq!(
        never_fails_at(&f),
        [format!("{GH}:5")],
        "only the job that swallows failure"
    );
    let gl = "\
trivy:
  stage: test
  script:
    - trivy fs .
  allow_failure: true
semgrep:
  script:
    - semgrep ci
";
    let f = ci_findings("ci-gl", &[(".gitlab-ci.yml", gl)]);
    assert_eq!(never_fails_at(&f), [".gitlab-ci.yml:4".to_string()]);
    // the single-line forms keep working
    let f = ci_findings(
        "ci-same",
        &[(
            GH,
            "jobs:\n  s:\n    steps:\n      - run: trivy fs . || true\n",
        )],
    );
    assert_eq!(never_fails_at(&f).len(), 1);
}

#[test]
fn the_word_readyhai_alone_does_not_satisfy_the_scan_rules() {
    let has = |f: &[Finding], r: &str| f.iter().any(|x| x.rule == format!("readiness.ci.{r}"));
    let all3 = |f: &[Finding]| {
        ["no_sast", "no_secret_scan", "no_dep_scan"]
            .iter()
            .all(|r| has(f, r))
    };
    // mentions of the name, an install, a tools update: no scan runs
    let wf = "\
name: readyhai
jobs:
  x:
    steps:
      - run: pip install readyhai
      - run: readyhai tools update
";
    let f = ci_findings("rh-word", &[(GH, wf)]);
    assert!(
        all3(&f),
        "{:?}",
        f.iter().map(|x| &x.rule).collect::<Vec<_>>()
    );
    // the actual scan step satisfies all three (it runs SAST, secrets and dependency scanners)
    let wf = "jobs:\n  x:\n    steps:\n      - run: readyhai scan . --profile quick\n";
    let f = ci_findings("rh-scan", &[(GH, wf)]);
    assert!(!has(&f, "no_sast") && !has(&f, "no_secret_scan") && !has(&f, "no_dep_scan"));
    // --no-tools turns the scanners off: it is not a scan stage
    let wf = "jobs:\n  x:\n    steps:\n      - run: readyhai scan . --no-tools\n";
    assert!(all3(&ci_findings("rh-notools", &[(GH, wf)])));
    // a Jenkins stage that only updates tools
    assert!(all3(&ci_findings(
        "rh-jenkins",
        &[(
            "Jenkinsfile",
            "pipeline { stages { stage('t') { steps { sh 'readyhai tools update' } } } }\n"
        )]
    )));
    // a real scanner still satisfies exactly its own rule
    let f = ci_findings(
        "rh-trivy",
        &[(GH, "jobs:\n  x:\n    steps:\n      - run: trivy fs .\n")],
    );
    assert!(has(&f, "no_sast") && has(&f, "no_secret_scan") && !has(&f, "no_dep_scan"));
}

// ---------- wireguard ----------

const WG_PRIV: &str = "hAlu3NlEqZeF8lN4XWa8vRz5Cb6dEfGhIjKlMnOpQrU=";
const WG_PUB: &str = "q3G2YV3jP7cFq7U8ZB5oQeD8mH0rT1sX2vW9yLkMnAo=";
const WG_PUB2: &str = "lZ9tR4wY7kD2sA0tC6eU8bR1jM5vZ3xY0pF4gH7iN2c=";
const WG_PSK: &str = "0nxX3p1sTqL8c5hUf9E7bR2jM6vZ4wY1kD0sA8tC3eU=";

fn wg_findings(tag: &str, files: &[(&str, &str)]) -> Vec<Finding> {
    let src = tmp_repo(tag, files);
    let ctx = ctx_for(&src, tag, false);
    out_of(&ctx, "wireguard").findings
}

#[test]
fn wireguard_server_roster_config_is_silent() {
    // A server-side peer roster (public keys only, no private material) is clean.
    let f = wg_findings(
        "wgok",
        &[(
            "peers.conf",
            &format!(
                "[Peer] # laptop\nPublicKey = {WG_PUB}\nAllowedIPs = 10.8.0.2/32\n\n[Peer] # phone\nPublicKey = {WG_PUB2}\nAllowedIPs = 10.8.0.3/32\n"
            ),
        )],
    );
    assert!(
        f.is_empty(),
        "public-key-only roster should be clean: {f:?}"
    );
}

#[test]
fn wireguard_non_wg_conf_files_are_ignored() {
    let f = wg_findings(
        "wgnginx",
        &[(
            "nginx.conf",
            "worker_processes auto;\nevents { worker_connections 1024; }\n",
        )],
    );
    assert!(
        f.is_empty(),
        "nginx.conf must not parse as WireGuard: {f:?}"
    );
}

#[test]
fn wireguard_bad_config_fires_expected_rules_without_leaking_keys() {
    let f = wg_findings(
        "wgbad",
        &[
            (
                "wg0.conf",
                &format!(
                    "[Interface]\nPrivateKey = {WG_PRIV}\nListenPort = 51820\n\n[Peer]\nPublicKey = not-base64!\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.com:51820\n"
                ),
            ),
            ("nginx.conf", "user www;\n"),
        ],
    );
    let rules: HashSet<&str> = f.iter().map(|x| x.rule.as_str()).collect();
    for want in [
        "wireguard.private-key-committed",
        "wireguard.weak-key-material",
        "wireguard.allowed-ips-overreach",
        "wireguard.no-keepalive",
        "wireguard.missing-address",
    ] {
        assert!(rules.contains(want), "missing {want}: {rules:?}");
    }
    for finding in &f {
        assert!(
            !finding.title.contains(WG_PRIV) && !finding.detail.contains(WG_PRIV),
            "key material leaked into: {}",
            finding.title
        );
    }
    assert!(!f.iter().any(|x| x.location.contains("nginx")));
}

#[test]
fn wireguard_duplicate_listen_port_is_flagged() {
    let f = wg_findings(
        "wgport",
        &[
            (
                "a.conf",
                "[Interface]\nPrivateKey = PLACEHOLDER\nAddress = 10.0.0.1/24\nListenPort = 51820\n",
            ),
            (
                "b.conf",
                "[Interface]\nPrivateKey = PLACEHOLDER-OTHER\nAddress = 10.9.0.1/24\nListenPort = 51820\n",
            ),
        ],
    );
    assert!(
        f.iter().any(|x| x.rule == "wireguard.listen-port-conflict"),
        "{:?}",
        f.iter().map(|x| x.rule.as_str()).collect::<Vec<_>>()
    );
}

#[test]
fn wireguard_reused_key_is_flagged() {
    // The same PSK across two peers: one compromised key decrypts both channels.
    let f = wg_findings(
        "wgreuse",
        &[(
            "peers.conf",
            &format!(
                "[Peer]\nPublicKey = {WG_PUB}\nPresharedKey = {WG_PSK}\n\n[Peer]\nPublicKey = {WG_PUB2}\nPresharedKey = {WG_PSK}\n"
            ),
        )],
    );
    assert!(
        f.iter()
            .any(|x| x.rule == "wireguard.key-reuse" && x.title.contains("redacted")),
        "expected redacted key-reuse finding, got {:?}",
        f.iter()
            .map(|x| (x.rule.as_str(), x.title.as_str()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn is_wireguard_detects_sections_and_directives() {
    assert!(super::wireguard::is_wireguard(
        "[Interface]\nPrivateKey = x\n"
    ));
    assert!(!super::wireguard::is_wireguard("[server]\nuser nginx;\n"));
    assert!(!super::wireguard::is_wireguard(
        "[Interface]\ntimeout = 5\n"
    ));
}
