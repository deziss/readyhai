//! Project-intel gather for the agent pipeline (v3.8.0).
//!
//! The autonomous agent consumes the project's own subsystems — the vulnerability
//! database, the operator's opt-in exploitation engine, and the plugged-tool
//! registry — and hands the planner *advisory context*. Three invariants,
//! inherited from the crate constitution and enforced here:
//!
//! 1. **Deterministic primacy.** Intel is deterministic data. It prioritises and
//!    informs planning; it NEVER changes a verdict and NEVER creates a defect.
//!    Nothing in this module is read by the triager or the verifier.
//! 2. **No self-authorization.** Active exploitation verification runs only when
//!    the operator settings say `[exploits] enabled = true` *and* the run is not a
//!    dry-run, and every probe URL passes [`crate::scope::egress_guard`] with
//!    intrusive semantics plus the settings' `max_probes` budget — exactly like
//!    `readyhai exploits` does. A guard refusal becomes an engine
//!    "inconclusive", never a fake or bypassed probe.
//! 3. **Advisory everywhere.** Every failure path here degrades into a note on
//!    the pipeline step, never a panic and never a silent skip. A missing
//!    settings file means defaults; a *broken* settings file is a hard run error
//!    (the same rule scans and `Cmd::Exploits` apply, enforced by the caller at
//!    load time); a configured-but-broken scope file makes the exploitation step
//!    refuse and say so. Verification stamps live on vulndb rows only — they
//!    never touch any triage status.

use std::path::Path;

use crate::agent::types::reports::TriagedDefect;
use crate::scope::Scope;
use crate::settings::Settings;
use crate::{exploits, scope, tools, vulndb};

/// How many known-open rows are handed to the planner at most.
const OPEN_CAP: usize = 25;

/// Everything the run learned from the project's own subsystems, before planning.
///
/// Purely advisory: the planner may reorder or annotate cases with it; nothing
/// downstream may treat it as evidence, and it never gates the verdict.
#[derive(Debug, Default, Clone)]
pub(crate) struct Intel {
    /// This target's *open* rows in the vulnerability database, severity then
    /// recency descending (the database's own order), capped to [`OPEN_CAP`].
    pub open: Vec<vulndb::VulnRecord>,
    /// Fingerprints that safe exploitation templates re-confirmed during this run.
    pub reproduced: Vec<String>,
    /// Human-readable one-liners for pipeline notes: why each source ran or skipped.
    pub notes: Vec<String>,
    /// Deterministic tool-availability lines (docker daemon, tool lock, packs).
    pub tooling: Vec<String>,
}

/// Rows we consider "open": `status == "open"`.
///
/// The database's whole status vocabulary is `open|accepted|forgotten`
/// (`vulndb::STATUSES`); `accepted` and `forgotten` are explicit operator
/// dispositions ("seen and decided"), so presenting them as open would
/// contradict the operator. Only `open` counts — a deliberate, documented choice.
fn is_open(row: &vulndb::VulnRecord) -> bool {
    row.status == "open"
}

/// Host of a URL-ish string, normalised (lowercase, no trailing dot). `None` for
/// anything that is not an http(s) URL (file paths, git refs, bare ports).
fn host_of(s: &str) -> Option<String> {
    scope::url_host(s).ok().filter(|h| !h.is_empty())
}

/// True when the row belongs to `host`: the row's `resource` first (the URL the
/// finding is about), falling back to the row's `target`. Host-only,
/// case-insensitive comparison; non-URL resources never match a host.
fn row_matches_host(row: &vulndb::VulnRecord, host: &str) -> bool {
    host_of(&row.resource).as_deref() == Some(host) || host_of(&row.target).as_deref() == Some(host)
}

/// Collect this run's project intel.
///
/// `settings` is passed by reference on purpose: a *broken* settings file must
/// hard-error the run, and the caller (the pipeline stage) does that with `?` at
/// load time, exactly like the scan path and `readyhai exploits` do. When the
/// file is absent the caller passes [`Settings::default`] — vulndb ON, exploits
/// OFF — so gather itself never fails and never panics.
///
/// `scope` is the run's scope when a usable scope file was configured; a
/// configured file that cannot load is handled by the caller as "degrade with a
/// note", and gathering continues with `None`, which switches active probing off
/// — the safest answer when the operator's boundaries are unreadable.
///
/// `nonprod` only labels the posture note; every actual prod-boundary decision is
/// made by the egress guard, never here.
pub(crate) fn gather(
    req_dry_run: bool,
    target: &str,
    settings: &Settings,
    scope_opt: Option<&Scope>,
    nonprod: bool,
    data: &Path,
) -> Intel {
    let mut intel = Intel::default();
    let db = vulndb::path_in(data, settings.vulndb.path.as_deref());

    // --- 1. vulnerability database: this host's open rows -----------------------
    if !settings.vulndb.enabled {
        intel
            .notes
            .push("vulndb: skipped (disabled in settings)".to_string());
    } else {
        match host_of(target) {
            None => intel.notes.push(format!(
                "vulndb: no host lookup — target {target} is not an http(s) URL"
            )),
            Some(host) => {
                let (rows, warnings) = vulndb::list_at(&db, &vulndb::Filter::default());
                for w in warnings {
                    intel.notes.push(format!("vulndb: {w}"));
                }
                let total = rows.len();
                // list_at already sorts severity desc, last_seen desc, fingerprint asc.
                intel.open = rows
                    .into_iter()
                    .filter(|r| is_open(r) && row_matches_host(r, &host))
                    .take(OPEN_CAP)
                    .collect();
                intel.notes.push(format!(
                    "vulndb: {} open record(s) for host {host} ({total} total row(s) in {})",
                    intel.open.len(),
                    db.display()
                ));
            }
        }
    }

    // --- 2. opt-in exploitation verification -------------------------------------
    intel.notes.push(exploitation_note(
        req_dry_run,
        settings,
        scope_opt,
        &db,
        &intel.open,
        &mut intel.reproduced,
        &RealEngine,
    ));

    // --- 3. plugged-tool availability (deterministic, no probing) -----------------
    intel.tooling = tooling_lines(data);
    intel.notes.extend(intel.tooling.clone());

    // --- 4. light posture: URL facts only, never a network probe ------------------
    intel.notes.push(posture_note(target, nonprod));
    intel
}

/// Run (or refuse) exploitation verification; returns the note and fills
/// `reproduced` with fingerprints whose verdict was `verified`.
///
/// Skips, in priority order: engine disabled, dry-run (a dry run must not emit a
/// single packet), no usable scope file (boundaries unreadable → refuse to probe),
/// no open records for this host. The probe budget is the settings' `max_probes`;
/// the guard is the intrusive egress guard, so a production-tagged host is
/// refused as *inconclusive* by the engine — never probed, never faked.
/// How [`exploitation_note`] reaches the engine: the real one in production, a
/// counting stand-in in tests (a skip branch must call it exactly zero times).
struct RealEngine;
trait Engine {
    fn verify(
        &self,
        db: &Path,
        fps: &[String],
        max_probes: u32,
        guard: &dyn Fn(&str) -> Result<String, String>,
    ) -> Result<Vec<exploits::Verdict>, anyhow::Error>;
}
impl Engine for RealEngine {
    fn verify(
        &self,
        db: &Path,
        fps: &[String],
        max_probes: u32,
        guard: &dyn Fn(&str) -> Result<String, String>,
    ) -> Result<Vec<exploits::Verdict>, anyhow::Error> {
        exploits::run_at(db, fps, max_probes, guard)
    }
}

fn exploitation_note(
    req_dry_run: bool,
    settings: &Settings,
    scope_opt: Option<&Scope>,
    db: &Path,
    open: &[vulndb::VulnRecord],
    reproduced: &mut Vec<String>,
    engine: &dyn Engine,
) -> String {
    if !settings.exploits.enabled {
        return "exploitation: skipped (disabled in settings)".into();
    }
    if req_dry_run {
        return "exploitation: skipped (dry-run)".into();
    }
    let Some(sc) = scope_opt else {
        return "exploitation: skipped (no usable scope file — refusing to probe without it)"
            .into();
    };
    if open.is_empty() {
        return "exploitation: skipped (no open records for this host)".into();
    }
    let max_probes = settings.exploits.max_probes;
    let fps: Vec<String> = open.iter().map(|r| r.fingerprint.clone()).collect();
    let guard = |u: &str| -> Result<String, String> {
        scope::egress_guard(u, Some(sc), true)
            .map(|eg| eg.url)
            .map_err(|e| format!("{e:#}"))
    };
    match engine.verify(db, &fps, max_probes, &guard) {
        Ok(verdicts) => {
            let rechecked = verdicts.len();
            for v in &verdicts {
                if v.verdict == "verified" {
                    reproduced.push(v.fingerprint.clone());
                }
            }
            format!(
                "exploitation: {rechecked} re-checked, {} verified under safe templates",
                reproduced.len()
            )
        }
        Err(e) => format!("exploitation: failed ({e:#})"),
    }
}

/// One-line summary of the per-source outcomes, for the pipeline step's details.
pub(crate) fn step_summary(intel: &Intel) -> String {
    let pick = |prefix: &str| {
        intel
            .notes
            .iter()
            .find(|n| n.starts_with(prefix))
            .cloned()
            .unwrap_or_else(|| format!("{prefix}no data"))
    };
    format!("{}; {}", pick("vulndb: "), pick("exploitation: "))
}

/// Tool availability, deterministic and cheap: docker daemon status (a capped
/// local `docker version`, the same probe doctor uses), tool-lock entry count,
/// installed pack count. No network.
fn tooling_lines(data: &Path) -> Vec<String> {
    let docker = tools::Docker::detect(data);
    let mut lines = vec![format!(
        "tooling: docker {}",
        if docker.available {
            "available"
        } else {
            "unavailable"
        }
    )];
    lines.push(format!(
        "tooling: {} tool lock entries",
        tools::lock_entries().len()
    ));
    let packs = tools::plugins_dir()
        .read_dir()
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter(|e| e.path().join("plugin.toml").is_file())
                .count()
        })
        .unwrap_or(0);
    lines.push(format!("tooling: {packs} plugged pack(s)"));
    lines
}

/// One-line posture summary built from the target string alone — URL shape and
/// whether the run treats the host as non-production. Deliberately no active
/// probing: the pipeline's network behaviour stays scoped tool calls, not nmap.
fn posture_note(target: &str, nonprod: bool) -> String {
    match scope::parse_web_url(target).ok() {
        Some(u) => format!(
            "posture: target {} (host {}, {}) — URL facts only, no active probes",
            u,
            u.host_str().unwrap_or("?"),
            if nonprod {
                "non-production"
            } else {
                "production/unknown"
            }
        ),
        None => format!("posture: target {target} is not an http(s) URL — no network posture"),
    }
}

/// Convert this run's triaged agent defects into the database's `Finding` shape
/// and record them through [`vulndb::record_run`], keeping all of its gates
/// (settings enabled, non-Info severity, never fails the run).
///
/// Returns the note to display: `record_run`'s own note, or an explicit skip
/// reason. Dry runs are deliberately not recorded — reduced-effort results must
/// not age or seed the operator's database. This maps severities into an
/// *advisory* DB row; it never touches any verdict or triage status.
pub(crate) fn record_to_vulndb(
    data: &Path,
    settings: &Settings,
    target: &str,
    defects: &[TriagedDefect],
    dry_run: bool,
) -> Option<String> {
    if dry_run {
        return Some("vulnerability DB: skipped (dry-run)".into());
    }
    if !settings.vulndb.enabled {
        return Some("vulnerability DB: skipped (off in settings)".into());
    }
    if defects.is_empty() {
        return None;
    }
    // Category is not persisted by the database (kind/rule/severity/resource are),
    // so the exact variant is cosmetic; findings here are agent QA results.
    let findings: Vec<crate::model::Finding> = defects
        .iter()
        .map(|d| {
            let mut f = crate::model::Finding::new(
                "agent",
                if d.rule.is_empty() { &d.id } else { &d.rule },
                crate::model::Category::Security,
                crate::model::Severity::parse(&d.severity),
                &d.title,
                if d.component.is_empty() {
                    target
                } else {
                    &d.component
                },
            );
            if !d.root_cause_hypothesis.is_empty() {
                f = f.detail(&d.root_cause_hypothesis);
            }
            f
        })
        .collect();
    // record_run resolves the database from the *process* data directory; pin the
    // path explicitly so an injected `data` (tests, future per-run dirs) is honoured.
    let mut pinned = settings.clone();
    pinned.vulndb.path = Some(
        vulndb::path_in(data, settings.vulndb.path.as_deref())
            .to_string_lossy()
            .into_owned(),
    );
    let note = vulndb::record_run(&pinned, target, &findings);
    Some(note.unwrap_or_else(|| "vulnerability DB: nothing worth recording".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, Finding, Severity};
    use std::path::PathBuf;
    use vulndb::VulnEntry;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rh-intel-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn settings_with_db(dir: &Path, exploits_on: bool) -> Settings {
        let mut s = Settings::default();
        s.vulndb
            .path
            .replace(dir.join("vulns.jsonl").to_string_lossy().into_owned());
        s.exploits.enabled = exploits_on;
        s
    }

    /// Three open rows on one host (low/high/medium) — plus a foreign-host row and,
    /// separately, rows an `accepted` disposition must hide.
    fn seed_rows(db: &Path) {
        vulndb::record_findings_at(
            db,
            "http://ex.io",
            &[
                VulnEntry {
                    kind: "tool.a",
                    rule: "R-low",
                    title: "low one",
                    severity: "low",
                    resource: "http://ex.io/a",
                    message: "m",
                },
                VulnEntry {
                    kind: "tool.a",
                    rule: "R-high",
                    title: "high one",
                    severity: "high",
                    resource: "http://ex.io/b",
                    message: "m",
                },
                VulnEntry {
                    kind: "tool.a",
                    rule: "R-med",
                    title: "medium one",
                    severity: "medium",
                    resource: "http://ex.io/c",
                    message: "m",
                },
            ],
        )
        .unwrap();
        vulndb::record_findings_at(
            db,
            "http://other.example",
            &[VulnEntry {
                kind: "tool.a",
                rule: "R-other",
                title: "elsewhere",
                severity: "critical",
                resource: "http://other.example/z",
                message: "m",
            }],
        )
        .unwrap();
    }

    fn defect(title: &str, severity: &str, rule: &str) -> TriagedDefect {
        TriagedDefect {
            id: "D1".into(),
            title: title.into(),
            severity: severity.into(),
            component: "app".into(),
            root_cause_hypothesis: "rc".into(),
            rule: rule.into(),
            ..Default::default()
        }
    }

    #[test]
    fn gather_finds_open_rows_for_host_sorted() {
        let d = tmp("gather-sort");
        let db = d.join("vulns.jsonl");
        seed_rows(&db);
        let s = settings_with_db(&d, false);
        let intel = gather(true, "http://ex.io", &s, None, true, &d);
        let rules: Vec<&str> = intel.open.iter().map(|r| r.rule.as_str()).collect();
        // severity desc (high > medium > low), foreign host excluded, order is the DB's.
        assert_eq!(rules, vec!["R-high", "R-med", "R-low"], "{rules:?}");
        assert!(
            intel
                .notes
                .iter()
                .any(|n| n.starts_with("vulndb: 3 open record(s) for host ex.io")),
            "{:?}",
            intel.notes
        );
        // exploits off by default → nothing probed, explicit skip note, and the
        // engine never ran so no row carries a stamp.
        assert!(intel.reproduced.is_empty());
        assert!(
            intel
                .notes
                .iter()
                .any(|n| n == "exploitation: skipped (disabled in settings)")
        );
        let rows = vulndb::list_at(&db, &vulndb::Filter::default()).0;
        assert!(
            rows.iter()
                .all(|r| r.verification == "unverified" && r.verified_at.is_none()),
            "disabled engine must not stamp: {rows:?}"
        );
        // tooling and posture are present and deterministic in shape.
        assert!(
            intel
                .tooling
                .iter()
                .any(|t| t.starts_with("tooling: docker"))
        );
        assert!(
            intel
                .notes
                .iter()
                .any(|n| n.starts_with("posture:") && n.contains("host ex.io"))
        );
    }

    #[test]
    fn gather_non_url_target_notes_no_lookup() {
        let d = tmp("gather-path");
        let s = settings_with_db(&d, false);
        let intel = gather(true, "./some/dir", &s, None, true, &d);
        assert!(intel.open.is_empty());
        assert!(
            intel
                .notes
                .iter()
                .any(|n| n.starts_with("vulndb: no host lookup")),
            "{:?}",
            intel.notes
        );
        assert!(
            intel
                .notes
                .iter()
                .any(|n| n.starts_with("posture:") && n.contains("not an http(s) URL"))
        );
    }

    #[test]
    fn exploits_disabled_never_touches_the_database() {
        // Exploits ON in the file would stamp even skipped rows; with the engine
        // disabled, gather must leave every row exactly as it found it — the
        // observable stand-in for "the guard closure was never called".
        let d = tmp("guard-off");
        let db = d.join("vulns.jsonl");
        seed_rows(&db);
        let s = settings_with_db(&d, false);
        let before = vulndb::list_at(&db, &vulndb::Filter::default()).0;
        let intel = gather(false, "http://ex.io", &s, None, true, &d);
        let after = vulndb::list_at(&db, &vulndb::Filter::default()).0;
        assert_eq!(before, after, "no stamp, no touch at all");
        assert!(intel.reproduced.is_empty());
        assert!(
            intel
                .notes
                .iter()
                .any(|n| n == "exploitation: skipped (disabled in settings)")
        );
    }

    #[test]
    fn dry_run_sends_no_probes() {
        // Exploits ON, a permissive scope, three open rows — yet the dry run must
        // refuse before the engine: run_at stamps even no-match skips, so an
        // untouched database proves the probe loop never started.
        let d = tmp("guard-dry");
        let db = d.join("vulns.jsonl");
        seed_rows(&db);
        let sd = tmp("guard-dry-scope");
        let sc_file = sd.join("scope.toml");
        std::fs::write(&sc_file, "[[hosts]]\nhost = \"ex.io\"\nenv = \"nonprod\"\n").unwrap();
        let sc = Scope::load(&sc_file).unwrap();
        let s = settings_with_db(&d, true);
        let before = vulndb::list_at(&db, &vulndb::Filter::default()).0;
        let intel = gather(true, "http://ex.io", &s, Some(&sc), true, &d);
        let after = vulndb::list_at(&db, &vulndb::Filter::default()).0;
        assert_eq!(before, after, "a dry run must not stamp or touch");
        assert!(
            intel
                .notes
                .iter()
                .any(|n| n == "exploitation: skipped (dry-run)"),
            "{:?}",
            intel.notes
        );
    }

    #[test]
    fn guard_refusal_is_inconclusive_not_fake() {
        // Exploits on, scope configured but listing nothing: the template-matched
        // row's probe URL (127.0.0.1, internal) dies in the egress guard before
        // any socket, the engine stamps `inconclusive`, reproduced stays empty.
        let d = tmp("guard-err");
        let db = d.join("vulns.jsonl");
        vulndb::record_findings_at(
            &db,
            "http://127.0.0.1:9",
            &[VulnEntry {
                kind: "http",
                rule: "git-exposure",
                title: "Exposed .git configuration served",
                severity: "high",
                resource: "http://127.0.0.1:9/.git",
                message: "m",
            }],
        )
        .unwrap();
        let s = settings_with_db(&d, true);
        let sc = Scope::default(); // no hosts: internal 127.0.0.1 is refused
        let intel = gather(false, "http://127.0.0.1:9", &s, Some(&sc), true, &d);
        assert!(intel.reproduced.is_empty(), "{:?}", intel.reproduced);
        assert!(
            intel
                .notes
                .iter()
                .any(|n| n.starts_with("exploitation: 1 re-checked, 0 verified")),
            "{:?}",
            intel.notes
        );
        let rows = vulndb::list_at(&db, &vulndb::Filter::default()).0;
        assert_eq!(rows[0].verification, "inconclusive", "{rows:?}");
        assert_eq!(intel.open.len(), 1, "row belongs to the target host");
    }

    #[test]
    fn vulndb_disabled_records_nothing() {
        let d = tmp("record-off");
        let mut s = Settings::default();
        s.vulndb.enabled = false;
        s.vulndb
            .path
            .replace(d.join("vulns.jsonl").to_string_lossy().into_owned());
        let defects = vec![defect("Exposed .env file", "high", "secret")];
        let note = record_to_vulndb(&d, &s, "http://127.0.0.1:9", &defects, false);
        assert_eq!(
            note.as_deref(),
            Some("vulnerability DB: skipped (off in settings)")
        );
        assert!(
            !d.join("vulns.jsonl").exists(),
            "a disabled DB must not be written"
        );
    }

    #[test]
    fn dry_run_records_nothing() {
        let d = tmp("record-dry");
        let mut s = Settings::default();
        s.vulndb
            .path
            .replace(d.join("vulns.jsonl").to_string_lossy().into_owned());
        let defects = vec![defect("Exposed .env file", "high", "secret")];
        let note = record_to_vulndb(&d, &s, "http://127.0.0.1:9", &defects, true);
        assert_eq!(note.as_deref(), Some("vulnerability DB: skipped (dry-run)"));
        assert!(
            !d.join("vulns.jsonl").exists(),
            "a dry run must not write rows"
        );
    }

    #[test]
    fn record_maps_defects_and_skips_info() {
        let d = tmp("record-on");
        let mut s = Settings::default();
        s.vulndb
            .path
            .replace(d.join("vulns.jsonl").to_string_lossy().into_owned());
        s.vulndb.enabled = true;
        let defects = vec![
            defect("Exposed .git config", "medium", "git-exposure"),
            defect("style nit", "info", "nit"), // Info is a note, not a finding
        ];
        let note = record_to_vulndb(&d, &s, "http://127.0.0.1:9", &defects, false).unwrap();
        assert!(note.contains("1 finding(s) recorded"), "{note}");
        let rows = vulndb::list_at(&d.join("vulns.jsonl"), &vulndb::Filter::default()).0;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].rule, "git-exposure");
        assert_eq!(rows[0].kind, "agent");
        assert_eq!(rows[0].status, "open");
        assert_eq!(rows[0].severity, "medium");
        assert_eq!(rows[0].verification, "unverified");
        // shape sanity for the mapping used above
        let f = Finding::new(
            "agent",
            "git-exposure",
            Category::Security,
            Severity::Medium,
            "Exposed .git config",
            "app",
        );
        assert!(!f.path().is_empty());
    }

    /// A stand-in engine that counts invocations, so a test can prove the
    /// pipeline refuses to reach the engine at all (the engine is the only
    /// consumer of the egress guard — zero calls means zero guard calls).
    struct CountingEngine {
        calls: std::cell::Cell<usize>,
        seen_max_probes: std::cell::Cell<u32>,
    }
    impl CountingEngine {
        fn new() -> Self {
            Self {
                calls: std::cell::Cell::new(0),
                seen_max_probes: std::cell::Cell::new(u32::MAX),
            }
        }
    }
    impl Engine for CountingEngine {
        fn verify(
            &self,
            _db: &Path,
            _fps: &[String],
            max_probes: u32,
            _guard: &dyn Fn(&str) -> Result<String, String>,
        ) -> Result<Vec<exploits::Verdict>, anyhow::Error> {
            self.calls.set(self.calls.get() + 1);
            self.seen_max_probes.set(max_probes);
            Ok(vec![])
        }
    }

    #[test]
    fn skip_branches_never_reach_the_engine() {
        let d = tmp("engine-zero");
        let db = d.join("vulns.jsonl");
        seed_rows(&db);
        let sd = tmp("engine-zero-scope");
        let sc_file = sd.join("scope.toml");
        std::fs::write(&sc_file, "[[hosts]]\nhost = \"ex.io\"\nenv = \"nonprod\"\n").unwrap();
        let sc = Scope::load(&sc_file).unwrap();
        let open: Vec<vulndb::VulnRecord> = vulndb::list_at(&db, &vulndb::Filter::default())
            .0
            .into_iter()
            .filter(|r| r.target.contains("ex.io"))
            .collect();

        let eng = CountingEngine::new();
        let mut rep = Vec::new();

        // 1. engine disabled in settings.
        let s_off = settings_with_db(&d, false);
        let n = exploitation_note(false, &s_off, Some(&sc), &db, &open, &mut rep, &eng);
        assert_eq!(n, "exploitation: skipped (disabled in settings)");

        // 2. dry-run with the engine enabled.
        let s_on = settings_with_db(&d, true);
        let n = exploitation_note(true, &s_on, Some(&sc), &db, &open, &mut rep, &eng);
        assert_eq!(n, "exploitation: skipped (dry-run)");

        // 3. no usable scope file.
        let n = exploitation_note(false, &s_on, None, &db, &open, &mut rep, &eng);
        assert!(
            n.starts_with("exploitation: skipped (no usable scope"),
            "{n}"
        );

        // 4. nothing open for this host.
        let n = exploitation_note(false, &s_on, Some(&sc), &db, &[], &mut rep, &eng);
        assert_eq!(n, "exploitation: skipped (no open records for this host)");

        assert_eq!(eng.calls.get(), 0, "no skip branch may reach the engine");

        // With everything on, it does reach the engine — once, with the budget.
        let n = exploitation_note(false, &s_on, Some(&sc), &db, &open, &mut rep, &eng);
        assert!(n.starts_with("exploitation: 0 re-checked"), "{n}");
        assert_eq!(eng.calls.get(), 1);
        assert_eq!(eng.seen_max_probes.get(), s_on.exploits.max_probes);
    }

    #[test]
    fn open_rows_are_capped_at_twentyfive() {
        let d = tmp("gather-cap");
        let db = d.join("vulns.jsonl");
        let mut entries = Vec::new();
        for i in 0..30 {
            let rule: &'static str = Box::leak(format!("R{i:02}").into_boxed_str());
            let resource: &'static str = Box::leak(format!("http://ex.io/{i}").into_boxed_str());
            entries.push(VulnEntry {
                kind: "tool.a",
                rule,
                title: "row",
                severity: if i < 10 { "high" } else { "low" },
                resource,
                message: "m",
            });
        }
        vulndb::record_findings_at(&db, "http://ex.io", &entries).unwrap();
        let s = settings_with_db(&d, false);
        let intel = gather(true, "http://ex.io", &s, None, true, &d);
        assert_eq!(
            intel.open.len(),
            OPEN_CAP,
            "the planner gets at most 25 rows",
        );
        // Severity-first order survives the cap: first all 10 highs, then lows.
        assert!(intel.open.iter().take(10).all(|r| r.severity == "high"));
        assert!(intel.open.iter().skip(10).all(|r| r.severity == "low"));
    }
}
