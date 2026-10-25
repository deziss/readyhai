//! Performance QA (`qa.perf`): bounded k6 smoke + baseline compare. Nonprod only.
//! Limits: default 5 VUs / 60 s, hard caps 10 VUs / 120 s (unless scope `allow_heavy`),
//! the run aborts when http_req_failed > max_error_rate (default 5%).
//! Credentials reach k6 only as container env (`__ENV`), never in the script file.
use super::model::*;
use crate::checks::Check;
use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, CheckStatus, Profile, Severity, TargetKind};
use crate::scope::PerfLimits;
use crate::tools::ToolSpec;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

pub const MAX_VUS: u32 = 10;
pub const MAX_DURATION: u32 = 120;
pub const MAX_ENDPOINTS: usize = 8;
const SLOW_MS: f64 = 1000.0;
const REGRESSION: f64 = 1.20;
/// Ignore sub-20 ms jitter on very fast endpoints.
const MIN_DELTA_MS: f64 = 20.0;
const ERR_DEFECT: f64 = 0.01;
const HEALTH: [&str; 4] = ["/health", "/healthz", "/api/health", "/ready"];
static SEQ: AtomicUsize = AtomicUsize::new(1);

pub fn checks() -> Vec<Check> {
    vec![
        Check::new("qa.perf", "Performance smoke + baseline (k6, nonprod)", &[TargetKind::Web], Profile::Standard, run)
            .qa()
            .tool("k6"),
    ]
}

#[derive(Debug, Clone, PartialEq)]
pub struct Limits {
    pub vus: u32,
    pub duration_secs: u32,
    pub max_error_rate: f64,
}

pub fn effective_limits(o: Option<&PerfLimits>) -> Limits {
    let heavy = o.map(|p| p.allow_heavy).unwrap_or(false);
    let (cv, cd) = if heavy { (u32::MAX, u32::MAX) } else { (MAX_VUS, MAX_DURATION) };
    Limits {
        vus: o.and_then(|p| p.vus).unwrap_or(5).clamp(1, cv),
        duration_secs: o.and_then(|p| p.duration_secs).unwrap_or(60).clamp(5, cd),
        max_error_rate: o.and_then(|p| p.max_error_rate).unwrap_or(0.05).clamp(0.001, 0.5),
    }
}

/// One virtual-user population: anonymous or a role. Header NAME/VALUE come from env at run time.
#[derive(Debug, Clone)]
pub struct Persona {
    pub name: String,
    pub has_auth: bool,
}

/// Top-N GET paths without path parameters, spec order, health appended.
pub fn pick_endpoints(spec: Option<&Value>, health: Option<&str>) -> Vec<String> {
    let mut v: Vec<String> = vec![];
    if let Some(doc) = spec {
        for op in super::plan::ops_from_doc(doc) {
            if op.method.eq_ignore_ascii_case("get") && !op.path.contains('{') && !v.contains(&op.path) {
                v.push(op.path.clone());
            }
        }
    }
    v.truncate(MAX_ENDPOINTS - 1);
    if let Some(h) = health {
        if !v.iter().any(|p| p == h) {
            v.push(h.to_string());
        }
    }
    if v.is_empty() {
        v.push("/".into());
    }
    v.truncate(MAX_ENDPOINTS);
    v
}

fn js(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

/// Generate the k6 script. Auth headers are read from `__ENV.RH_HN_<i>` / `__ENV.RH_HV_<i>`
/// (persona index i); no secret is ever interpolated here.
pub fn gen_script(base: &str, endpoints: &[String], personas: &[Persona], l: &Limits) -> String {
    let per = (l.vus as usize).div_ceil(personas.len().max(1)).max(1);
    let mut s = String::from("import http from 'k6/http';\nimport { sleep } from 'k6';\n\nhttp.setResponseCallback(http.expectedStatuses({ min: 200, max: 499 })); // only 5xx / network errors count as failed\n\n");
    s.push_str(&format!("const BASE = {};\nconst EPS = {};\n", js(base.trim_end_matches('/')),
        serde_json::to_string(endpoints).unwrap_or("[]".into())));
    s.push_str("export const options = {\n  scenarios: {\n");
    for (i, p) in personas.iter().enumerate() {
        s.push_str(&format!(
            "    p{i}: {{ executor: 'constant-vus', vus: {per}, duration: '{}s', exec: 'persona{i}' }},\n",
            l.duration_secs
        ));
        let _ = p;
    }
    s.push_str("  },\n  thresholds: {\n");
    s.push_str(&format!(
        "    http_req_failed: [{{ threshold: 'rate<{}', abortOnFail: true, delayAbortEval: '10s' }}],\n",
        l.max_error_rate
    ));
    s.push_str("    http_req_duration: ['p(95)<3600000'],\n");
    for e in endpoints {
        s.push_str(&format!("    {}: ['p(95)<3600000'],\n", js(&format!("http_req_duration{{name:{e}}}"))));
    }
    s.push_str("  },\n};\n\n");
    s.push_str("function hit(i) {\n  const h = __ENV['RH_HV_' + i] ? { [__ENV['RH_HN_' + i]]: __ENV['RH_HV_' + i] } : {};\n");
    s.push_str("  for (const e of EPS) {\n    http.get(BASE + e, { headers: h, tags: { name: e } });\n    sleep(0.2);\n  }\n}\n");
    for (i, p) in personas.iter().enumerate() {
        s.push_str(&format!("export function persona{i}() {{ hit({}); }} // {}\n", if p.has_auth { i.to_string() } else { "-1".into() }, p.name));
    }
    s
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PerfMetrics {
    pub p50: f64,
    pub p90: f64,
    pub p95: f64,
    pub p99: f64,
    pub error_rate: f64,
    pub rps: f64,
    pub requests: u64,
    #[serde(default)]
    pub endpoints_p95: BTreeMap<String, f64>,
}

fn num(m: &Value, k: &str) -> Option<f64> {
    m.get(k).or_else(|| m.get("values").and_then(|v| v.get(k))).and_then(|x| x.as_f64())
}

/// Parse a `k6 run --summary-export` file (legacy flat or `values`-nested layout).
pub fn parse_summary(text: &str) -> Result<PerfMetrics> {
    let v: Value = serde_json::from_str(text).context("k6 summary is not JSON")?;
    let m = v.get("metrics").context("no metrics in k6 summary")?;
    let d = m.get("http_req_duration").context("no http_req_duration")?;
    let reqs = m.get("http_reqs");
    let mut out = PerfMetrics {
        p50: num(d, "med").or_else(|| num(d, "p(50)")).unwrap_or(0.0),
        p90: num(d, "p(90)").unwrap_or(0.0),
        p95: num(d, "p(95)").unwrap_or(0.0),
        p99: num(d, "p(99)").unwrap_or(0.0),
        error_rate: m.get("http_req_failed").and_then(|f| num(f, "value").or_else(|| num(f, "rate"))).unwrap_or(0.0),
        rps: reqs.and_then(|r| num(r, "rate")).unwrap_or(0.0),
        requests: reqs.and_then(|r| num(r, "count")).unwrap_or(0.0) as u64,
        endpoints_p95: BTreeMap::new(),
    };
    if let Some(o) = m.as_object() {
        for (k, val) in o {
            if let Some(n) = k.strip_prefix("http_req_duration{name:").and_then(|x| x.strip_suffix('}')) {
                if let Some(p) = num(val, "p(95)") {
                    out.endpoints_p95.insert(n.to_string(), p);
                }
            }
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq)]
pub enum PerfIssue {
    Regression { old: f64, new: f64, worst: Vec<(String, f64, f64)> },
    Errors { rate: f64 },
    Slow { p95: f64 },
}

/// Baseline compare. `old = None` means no baseline yet (only absolute checks apply).
pub fn compare(old: Option<&PerfMetrics>, new: &PerfMetrics) -> Vec<PerfIssue> {
    let mut v = vec![];
    if let Some(o) = old {
        if o.p95 > 0.0 && new.p95 > o.p95 * REGRESSION && new.p95 - o.p95 >= MIN_DELTA_MS {
            let mut worst: Vec<(String, f64, f64)> = new
                .endpoints_p95
                .iter()
                .filter_map(|(k, n)| o.endpoints_p95.get(k).map(|ov| (k.clone(), *ov, *n)))
                .filter(|(_, ov, n)| *n > *ov * REGRESSION)
                .collect();
            worst.sort_by(|a, b| (b.2 - b.1).total_cmp(&(a.2 - a.1)));
            worst.truncate(3);
            v.push(PerfIssue::Regression { old: o.p95, new: new.p95, worst });
        }
    }
    if new.error_rate > ERR_DEFECT {
        v.push(PerfIssue::Errors { rate: new.error_rate });
    }
    if new.p95 > SLOW_MS {
        v.push(PerfIssue::Slow { p95: new.p95 });
    }
    v
}

pub fn baseline_path(data: &Path, key: &str) -> PathBuf {
    data.join("baselines").join(format!("{key}.perf.json"))
}

pub fn load_baseline(data: &Path, key: &str) -> Option<PerfMetrics> {
    serde_json::from_str(&std::fs::read_to_string(baseline_path(data, key)).ok()?).ok()
}

pub fn store_baseline(data: &Path, key: &str, m: &PerfMetrics) -> Result<()> {
    let p = baseline_path(data, key);
    std::fs::create_dir_all(p.parent().unwrap())?;
    std::fs::write(&p, serde_json::to_string_pretty(m)?)?;
    Ok(())
}

/// Pending result of the last run is stored next to the baseline so `baseline accept`
/// can promote it (`<key>.perf.last.json` -> `<key>.perf.json`).
pub fn accept_baseline(target_key: &str) -> Result<()> {
    accept_baseline_in(&crate::engine::data_dir(), target_key)
}

pub fn accept_baseline_in(data: &Path, key: &str) -> Result<()> {
    let last = data.join("baselines").join(format!("{key}.perf.last.json"));
    if !last.exists() {
        bail!("no recorded perf run for target {key}");
    }
    std::fs::copy(&last, baseline_path(data, key))?;
    Ok(())
}

/// Rewrite loopback hosts for a container (host.docker.internal). Returns (url, rewritten).
pub fn container_base(url: &str) -> (String, bool) {
    let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
    let (auth, tail) = match rest.find(['/', '?', '#']) {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    let host = crate::scope::url_host(url).unwrap_or_default();
    if matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1" | "0.0.0.0") || host.ends_with(".localhost") {
        let port = if host == "::1" { auth.rsplit_once("]:").map(|x| x.1) } else { auth.rsplit_once(':').map(|x| x.1) };
        let port = port.filter(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
        let a = match port {
            Some(p) => format!("host.docker.internal:{p}"),
            None => "host.docker.internal".into(),
        };
        (format!("{scheme}://{a}{tail}"), true)
    } else {
        (url.to_string(), false)
    }
}

fn run(ctx: &Ctx) -> Result<CheckOutput> {
    let qa = ctx.qa.as_ref().context("not a QA run")?;
    if !qa.nonprod {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable("perf tests run only on nonprod hosts".into())));
    }
    let Some(url) = ctx.target.url.clone() else {
        return Ok(CheckOutput::status(CheckStatus::NotApplicable("no web target".into())));
    };
    let host = crate::scope::url_host(&url)?;
    let scope = crate::scope::active();
    let limits = effective_limits(scope.as_ref().and_then(|s| s.find(&host)).and_then(|h| h.perf.as_ref()));

    // Endpoints: spec GETs (no path params) + health.
    let spec = super::plan::load_spec(ctx).ok().flatten();
    let base = url.trim_end_matches('/').to_string();
    let health = HEALTH.iter().find(|p| {
        qa.throttle().is_ok()
            && reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .ok()
                .and_then(|c| c.get(format!("{}{p}", origin(&base))).send().ok())
                .map(|r| r.status().is_success())
                .unwrap_or(false)
    });
    let endpoints = pick_endpoints(spec.as_ref(), health.copied());

    // Personas: anonymous + first role with credentials.
    let mut personas = vec![Persona { name: "anonymous".into(), has_auth: false }];
    let mut env: Vec<(String, String)> = vec![];
    if let Some(r) = qa.roles.roles.iter().find(|r| r.credential().is_some()) {
        if let Some((hn, hv)) = r.credential() {
            let i = personas.len();
            env.push((format!("RH_HN_{i}"), hn));
            env.push((format!("RH_HV_{i}"), hv));
            personas.push(Persona { name: r.name.clone(), has_auth: true });
        }
    }

    let (cbase, local) = container_base(&base);
    let script = gen_script(&cbase, &endpoints, &personas, &limits);
    let out = ctx.out_dir();
    std::fs::create_dir_all(&out)?;
    std::fs::write(out.join("perf.js"), &script)?;
    let _ = std::fs::remove_file(out.join("k6-summary.json"));

    let mut spec_t = ToolSpec::new(
        "k6",
        &["run", "--quiet", "--no-usage-report", "--summary-trend-stats", "avg,min,med,max,p(90),p(95),p(99)",
          "--summary-export", "/out/k6-summary.json", "/out/perf.js"],
    );
    spec_t.network = true;
    spec_t.host_gateway = local;
    spec_t.env = env;
    spec_t.timeout_secs = limits.duration_secs as u64 + 90;
    spec_t.memory = "512m".into();
    let (img, _) = crate::tools::image_for("k6");
    if img == "k6" {
        spec_t.image = Some("grafana/k6:latest".into()); // fallback: no [tools.k6] lock entry
    }
    let started = std::time::Instant::now();
    let tr = ctx.docker.run(ctx, &spec_t)?;
    let ms = started.elapsed().as_millis();
    let summary_p = out.join("k6-summary.json");
    let text = std::fs::read_to_string(&summary_p)
        .with_context(|| format!("k6 produced no summary (exit {}): {}", tr.exit_code, tr.stderr_tail.lines().last().unwrap_or("")))?;
    let m = parse_summary(&text)?;
    let aborted = tr.exit_code == 99 && m.error_rate > limits.max_error_rate;

    // Evidence
    let ev_dir = ctx.run_dir.join("artifacts").join("perf");
    std::fs::create_dir_all(&ev_dir)?;
    std::fs::write(ev_dir.join("k6-summary.json"), &text)?;
    let evidence = vec![Evidence { kind: EvidenceKind::K6Summary, path: "perf/k6-summary.json".into(), note: String::new() }];

    let data = crate::engine::data_dir();
    let key = crate::engine::target_key(&ctx.target);
    let old = load_baseline(&data, &key);
    let issues = compare(old.as_ref(), &m);
    let _ = std::fs::create_dir_all(data.join("baselines"));
    if !aborted && m.error_rate <= limits.max_error_rate && m.requests > 0 {
        let _ = std::fs::write(data.join("baselines").join(format!("{key}.perf.last.json")), serde_json::to_string_pretty(&m)?);
    }
    let mut note = format!(
        "perf: {} req, {:.1} rps, p50 {:.0} ms, p95 {:.0} ms, p99 {:.0} ms, errors {:.2}% ({} VUs, {} s, {} personas)",
        m.requests, m.rps, m.p50, m.p95, m.p99, m.error_rate * 100.0, limits.vus, limits.duration_secs, personas.len()
    );
    if old.is_none() && !aborted && m.error_rate <= limits.max_error_rate && m.requests > 0 {
        store_baseline(&data, &key, &m)?;
        note.push_str("; perf baseline recorded");
    } else if old.is_none() {
        note.push_str("; no baseline recorded (unhealthy run; is the target reachable from the container?)");
    }
    if aborted {
        note.push_str("; ABORTED: error rate above threshold");
    }

    let case_id = "perf.baseline".to_string();
    let comp = format!("GET {}", endpoints.join(", "));
    let mut findings = vec![];
    let mut defect_ids = vec![];
    for iss in &issues {
        let (rule, sev, cat, title, actual) = match iss {
            PerfIssue::Regression { old, new, worst } => {
                let mut a = format!("p95 {old:.0} ms -> {new:.0} ms (+{:.0}%)", (new / old - 1.0) * 100.0);
                for (e, o, n) in worst {
                    a.push_str(&format!("; {e}: {o:.0} -> {n:.0} ms"));
                }
                ("qa.perf.regression", Severity::Medium, Category::Performance, "Latency regression versus baseline (p95 > +20%)", a)
            }
            PerfIssue::Errors { rate } => (
                "qa.perf.errors", Severity::High, Category::Reliability,
                "Errors under light load (> 1%)", format!("error rate {:.2}%{}", rate * 100.0, if aborted { " (run aborted)" } else { "" }),
            ),
            PerfIssue::Slow { p95 } => (
                "qa.perf.slow", Severity::Low, Category::Performance, "p95 latency above 1000 ms", format!("p95 {p95:.0} ms"),
            ),
        };
        let id = format!("D-PERF-{:03}", SEQ.fetch_add(1, Ordering::SeqCst));
        let d = Defect {
            id: id.clone(), rule: rule.into(), category: cat, severity: sev,
            priority: if sev >= Severity::High { Priority::P2 } else { Priority::P3 },
            area: Area::Perf, title: title.into(), component: comp.clone(),
            environment: "nonprod".into(),
            steps_to_reproduce: vec![
                format!("Run `readyhai qa` with perf enabled ({} VUs, {} s) against {}", limits.vus, limits.duration_secs, base),
                "Open perf/k6-summary.json in the run artifacts".into(),
            ],
            expected: match iss {
                PerfIssue::Regression { .. } => "p95 within 20% of the accepted baseline".into(),
                PerfIssue::Errors { .. } => "error rate <= 1%".into(),
                PerfIssue::Slow { .. } => "p95 <= 1000 ms".into(),
            },
            actual, evidence: evidence.clone(), reproduced: (1, 1), cases: vec![case_id.clone()],
            remediation: "Profile the slow endpoints (see per-endpoint p95 in the k6 summary); if the change is intended run `readyhai baseline accept`.".into(),
            fp_key: format!("{rule}|{}", ctx.target.url.as_deref().unwrap_or("")),
            fingerprint: String::new(), status: Default::default(), regression: false, ai_note: None,
        };
        findings.push(d.to_finding("qa.perf"));
        defect_ids.push(id);
        qa.with(|c| c.defects.push(d));
    }
    qa.with(|c| {
        c.cases.push(TestCase {
            id: case_id.clone(), area: Area::Perf, technique: Technique::PerfBaseline,
            title: "Light load (smoke) latency/error baseline".into(), priority: Priority::P2,
            component: comp.clone(), role: None,
            steps: vec![format!("k6 {} VUs x {} s over {} endpoint(s)", limits.vus, limits.duration_secs, endpoints.len())],
            expected: "p95 within +20% of baseline, errors <= 1%, p95 <= 1000 ms".into(), source: CaseSource::Deterministic,
        });
        c.results.push(TestResult {
            case_id: case_id.clone(),
            status: if issues.is_empty() { ResultStatus::Pass } else { ResultStatus::Fail },
            actual: note.clone(), duration_ms: ms, attempts: 1, evidence: evidence.clone(),
            defect_id: defect_ids.first().cloned(),
        });
        c.coverage.set(&comp, "perf_baseline", if issues.is_empty() { Cell::Pass } else { Cell::Fail });
        c.notes.push(note.clone());
    });
    Ok(CheckOutput::findings(findings))
}

fn origin(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
    format!("{scheme}://{}", rest.split(['/', '?', '#']).next().unwrap_or(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUMMARY: &str = include_str!("../../tests/fixtures/qa-perf/k6-summary.json");

    fn pl(vus: Option<u32>, d: Option<u32>, heavy: bool) -> PerfLimits {
        PerfLimits { vus, duration_secs: d, max_error_rate: None, allow_heavy: heavy }
    }

    #[test]
    fn caps() {
        assert_eq!(effective_limits(None), Limits { vus: 5, duration_secs: 60, max_error_rate: 0.05 });
        let l = effective_limits(Some(&pl(Some(500), Some(3600), false)));
        assert_eq!((l.vus, l.duration_secs), (10, 120));
        let l = effective_limits(Some(&pl(Some(50), Some(300), true)));
        assert_eq!((l.vus, l.duration_secs), (50, 300));
    }

    #[test]
    fn script_has_thresholds_and_no_secret() {
        let personas = vec![
            Persona { name: "anonymous".into(), has_auth: false },
            Persona { name: "admin".into(), has_auth: true },
        ];
        let s = gen_script("http://host.docker.internal:8080/", &["/health".into(), "/api/x".into()], &personas, &effective_limits(None));
        assert!(s.contains("abortOnFail: true") && s.contains("rate<0.05"));
        assert!(s.contains("http_req_duration{name:/api/x}"));
        assert!(s.contains("__ENV['RH_HV_'") && s.contains("vus: 3"));
        assert!(!s.contains("Bearer") && !s.contains("SECRET-TOKEN"));
        assert!(s.contains("duration: '60s'"));
    }

    #[test]
    fn parse_fixture() {
        let m = parse_summary(SUMMARY).unwrap();
        assert_eq!((m.p50, m.p95, m.p99), (48.2, 164.9, 402.6));
        assert!((m.error_rate - 0.004975).abs() < 1e-9);
        assert_eq!(m.requests, 2412);
        assert_eq!(m.endpoints_p95.get("/api/orders"), Some(&330.4));
        // nested "values" layout
        let n = parse_summary(r#"{"metrics":{"http_req_duration":{"type":"trend","values":{"med":1,"p(90)":2,"p(95)":3,"p(99)":4}}}}"#).unwrap();
        assert_eq!(n.p95, 3.0);
    }

    #[test]
    fn compare_logic() {
        let base = parse_summary(SUMMARY).unwrap();
        assert!(compare(Some(&base), &base).is_empty());
        assert!(compare(None, &base).is_empty());
        let mut worse = base.clone();
        worse.p95 = base.p95 * 1.25;
        worse.endpoints_p95.insert("/api/orders".into(), 600.0);
        let v = compare(Some(&base), &worse);
        assert!(matches!(&v[0], PerfIssue::Regression { worst, .. } if worst[0].0 == "/api/orders"));
        let mut e = base.clone();
        e.error_rate = 0.02;
        e.p95 = 1500.0;
        let v = compare(None, &e);
        assert!(v.contains(&PerfIssue::Errors { rate: 0.02 }) && v.contains(&PerfIssue::Slow { p95: 1500.0 }));
        let mut ok = base.clone();
        ok.p95 = base.p95 * 1.15;
        assert!(compare(Some(&base), &ok).is_empty());
    }

    #[test]
    fn baseline_roundtrip_and_accept() {
        let d = std::env::temp_dir().join(format!("rh-perf-{}", std::process::id()));
        let m = parse_summary(SUMMARY).unwrap();
        assert!(load_baseline(&d, "k").is_none());
        assert!(accept_baseline_in(&d, "k").is_err());
        store_baseline(&d, "k", &m).unwrap();
        assert_eq!(load_baseline(&d, "k").unwrap(), m);
        std::fs::write(d.join("baselines/k.perf.last.json"), serde_json::to_string(&PerfMetrics { p95: 9.0, ..m }).unwrap()).unwrap();
        accept_baseline_in(&d, "k").unwrap();
        assert_eq!(load_baseline(&d, "k").unwrap().p95, 9.0);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn endpoints_and_rewrite() {
        let doc: Value = serde_json::json!({"paths": {"/a": {"get": {}}, "/b/{id}": {"get": {}}, "/c": {"post": {}}, "/health": {"get": {}}}});
        assert_eq!(pick_endpoints(Some(&doc), Some("/health")), vec!["/a", "/health"]);
        assert_eq!(pick_endpoints(None, None), vec!["/"]);
        assert_eq!(container_base("http://localhost:18095/x"), ("http://host.docker.internal:18095/x".into(), true));
        assert_eq!(container_base("https://app.example.com").1, false);
    }
}
