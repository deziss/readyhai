//! Behaviour of the global vulnerability database: fingerprint stability, dedupe and
//! status semantics against the file, tolerant reads, filters, and the scan hook.

use super::*;
use crate::settings::VulnDb;
use std::path::PathBuf;

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rh-vulndb-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn entry<'a>(kind: &'a str, rule: &'a str, sev: &'a str, resource: &'a str) -> VulnEntry<'a> {
    VulnEntry {
        kind,
        rule,
        title: "Open port",
        severity: sev,
        resource,
        message: "something is listening",
    }
}

fn rows_at(p: &Path) -> Vec<VulnRecord> {
    read_at(p).unwrap().0
}

#[test]
fn fingerprint_is_stable_and_positional() {
    let a = fingerprint("http://h:8080", "plugin.nmap", "tcp/22", "/");
    assert_eq!(
        a,
        fingerprint("http://h:8080", "plugin.nmap", "tcp/22", "/")
    );
    assert_eq!(a.len(), 24);
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    // each slot means something specific, so changing any one of them is a different finding
    assert_ne!(
        a,
        fingerprint("http://h:8080", "plugin.nmap", "tcp/22", "/api")
    );
    assert_ne!(
        a,
        fingerprint("http://h:8080", "plugin.nmap", "tcp/80", "/")
    );
    assert_ne!(
        a,
        fingerprint("http://h:8080", "plugin.httpx", "tcp/22", "/")
    );
    assert_ne!(
        a,
        fingerprint("http://other:8080", "plugin.nmap", "tcp/22", "/")
    );
    // the target is canonicalized: a trailing slash is the same target
    assert_eq!(
        fingerprint("http://h:8080/", "plugin.nmap", "tcp/22", "/"),
        a
    );
}

#[test]
fn path_honors_the_override_and_trims_it() {
    let data = PathBuf::from("/data");
    assert_eq!(
        path_in(&data, None),
        PathBuf::from("/data/vulns/vulns.jsonl")
    );
    assert_eq!(
        path_in(&data, Some("  /shared/vulns.jsonl  ")),
        PathBuf::from("/shared/vulns.jsonl")
    );
    // an empty override means "unset" here; validate() rejects it long before this point
    assert_eq!(
        path_in(&data, Some("   ")),
        PathBuf::from("/data/vulns/vulns.jsonl")
    );
}

#[test]
fn the_file_is_created_lazily_through_nested_dirs() {
    let d = tmp("lazy");
    let p = d.join("deep").join("vulns.jsonl");
    assert!(
        !d.exists(),
        "nothing touches the data dir before the first write"
    );
    record_findings_at(
        &p,
        "http://h:9",
        &[entry("tool.grype", "CVE-1", "high", "openssl")],
    )
    .expect("first record");
    assert!(p.is_file());
    assert_eq!(rows_at(&p).len(), 1);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_repeat_finding_updates_the_row_instead_of_adding_one() {
    let d = tmp("dedupe");
    let p = d.join("vulns.jsonl");
    let e = [entry("plugin.nmap", "tcp/2222", "medium", "/")];
    assert_eq!(
        record_findings_at(&p, "http://h:9", &e).unwrap(),
        Report {
            added: 1,
            updated: 0
        }
    );
    let first = rows_at(&p);
    assert_eq!(
        first[0].first_seen, first[0].last_seen,
        "a new row is stamped once, with the same time in both fields"
    );
    let first_stamp = first[0].last_seen.clone();
    assert_eq!(
        record_findings_at(&p, "http://h:9", &e).unwrap(),
        Report {
            added: 0,
            updated: 1
        },
        "the same fingerprint must not add a row"
    );

    let rows = rows_at(&p);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].occurrences, 2);
    assert_eq!(rows[0].status, "open");
    assert_eq!(rows[0].target, "http://h:9");
    assert_eq!(rows[0].target_key, target_key("http://h:9"));
    assert_eq!(rows[0].severity, "medium");
    assert_eq!(rows[0].resource, "/");
    assert_eq!(
        rows[0].first_seen, first_stamp,
        "the first sighting is never rewritten"
    );
    assert!(
        rows[0].last_seen >= first_stamp,
        "the repeat refreshed last_seen"
    );
    assert_eq!(
        rows[0].fingerprint,
        fingerprint("http://h:9", "plugin.nmap", "tcp/2222", "/")
    );

    // an operator decision survives the next scan...
    assert!(set_status_at(&p, &rows[0].fingerprint, "accepted").unwrap());
    record_findings_at(&p, "http://h:9", &e).unwrap();
    let rows = rows_at(&p);
    assert_eq!(rows[0].status, "accepted", "accept survives a re-scan");
    assert_eq!(rows[0].occurrences, 3);
    // ...until what comes back is not what was accepted
    record_findings_at(
        &p,
        "http://h:9",
        &[entry("plugin.nmap", "tcp/2222", "high", "/")],
    )
    .unwrap();
    let rows = rows_at(&p);
    assert_eq!(
        rows[0].status, "open",
        "a severity change is a new decision, not the old one"
    );
    assert_eq!(rows[0].severity, "high");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn forgotten_stays_forgotten_and_untouched() {
    let d = tmp("forgotten");
    let p = d.join("vulns.jsonl");
    record_findings_at(
        &p,
        "https://app",
        &[entry("tool.osv", "GHSA-4", "low", "left-pad")],
    )
    .unwrap();
    let fp = rows_at(&p)[0].fingerprint.clone();
    assert!(set_status_at(&p, &fp, "forgotten").unwrap());
    record_findings_at(
        &p,
        "https://app",
        &[VulnEntry {
            kind: "tool.osv",
            rule: "GHSA-4",
            title: "renamed by the tool",
            severity: "critical",
            resource: "left-pad",
            message: "changed",
        }],
    )
    .unwrap();
    let rows = rows_at(&p);
    assert_eq!(rows.len(), 1, "it is still counted, not re-added");
    assert_eq!(rows[0].status, "forgotten");
    assert_eq!(rows[0].occurrences, 2);
    assert_eq!(
        rows[0].severity, "low",
        "a forgotten row keeps what the operator saw"
    );
    assert_eq!(rows[0].title, "Open port");
    // and it only shows up when it is asked for
    let open = list_at(
        &p,
        &Filter {
            status: Some("open".into()),
            ..Default::default()
        },
    )
    .0;
    assert!(open.is_empty(), "the default open view must not show it");
    let forgotten = list_at(
        &p,
        &Filter {
            status: Some("forgotten".into()),
            ..Default::default()
        },
    )
    .0;
    assert_eq!(forgotten.len(), 1);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn an_unparseable_line_is_skipped_with_a_warning_and_dropped_on_write() {
    let d = tmp("tolerant");
    let p = d.join("vulns.jsonl");
    record_findings_at(&p, "http://h:9", &[entry("tool.x", "R1", "low", "")]).unwrap();
    let good = std::fs::read_to_string(&p).unwrap();
    std::fs::write(
        &p,
        format!("{good}not json at all\n\n{{\"target\":\"x\"}}\n"),
    )
    .unwrap();

    let (rows, warnings) = read_at(&p).unwrap();
    assert_eq!(rows.len(), 1, "the readable line survives");
    assert_eq!(warnings.len(), 2, "one warning per bad line");
    assert!(
        warnings[0].contains(":2:"),
        "a warning names its line: {warnings:?}"
    );

    let (listed, w2) = list_at(&p, &Filter::default());
    assert_eq!(listed.len(), 1, "a bad line never hides the good ones");
    assert_eq!(w2.len(), 2);

    record_findings_at(&p, "http://h:9", &[entry("tool.y", "R2", "high", "")]).unwrap();
    let text = std::fs::read_to_string(&p).unwrap();
    assert_eq!(
        text.lines().count(),
        2,
        "the rewrite leaves clean rows only"
    );
    assert!(
        rows_at(&p)
            .iter()
            .all(|r| valid_fingerprint(&r.fingerprint))
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn list_filters_by_target_and_status_and_sorts_by_severity_then_recency() {
    let d = tmp("filter");
    let p = d.join("vulns.jsonl");
    record_findings_at(
        &p,
        "http://a:9",
        &[
            entry("tool.a", "low-one", "low", ""),
            entry("tool.a", "high-one", "high", ""),
        ],
    )
    .unwrap();
    record_findings_at(
        &p,
        "https://b:9/",
        &[entry("tool.b", "mid-one", "medium", "/x")],
    )
    .unwrap();

    let all = list_at(&p, &Filter::default()).0;
    assert_eq!(all.len(), 3);
    assert_eq!(
        all.iter().map(|r| r.severity.as_str()).collect::<Vec<_>>(),
        ["high", "medium", "low"],
        "severity desc"
    );

    // target filter: canonical form, so a trailing slash is the same target
    let by_target = list_at(
        &p,
        &Filter {
            target: Some("https://b:9".into()),
            ..Default::default()
        },
    )
    .0;
    assert_eq!(by_target.len(), 1);
    assert_eq!(by_target[0].rule, "mid-one");
    assert!(
        list_at(
            &p,
            &Filter {
                target: Some("http://nope:9".into()),
                ..Default::default()
            }
        )
        .0
        .is_empty()
    );

    // target + status together
    let open = |p: &Path| {
        list_at(
            p,
            &Filter {
                target: Some("http://a:9".into()),
                status: Some("open".into()),
                severity: None,
                verification: None,
            },
        )
        .0
    };
    let rows = open(&p);
    assert_eq!(rows.len(), 2);
    assert!(set_status_at(&p, &rows[0].fingerprint, "accepted").unwrap());
    let rows = open(&p);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].rule, "low-one",
        "high-one is the row that was accepted"
    );

    // severity outranks recency even for an old high and a brand new medium
    let mut rows = rows_at(&p);
    for r in rows.iter_mut() {
        r.last_seen = match r.severity.as_str() {
            "high" => "2026-01-01T00:00:00+00:00".into(),
            "medium" => "2026-01-09T00:00:00+00:00".into(),
            _ => "2026-01-05T00:00:00+00:00".into(),
        };
    }
    write_rows(&p, &rows).unwrap();
    let ordered = list_at(&p, &Filter::default()).0;
    assert_eq!(
        ordered
            .iter()
            .map(|r| r.severity.as_str())
            .collect::<Vec<_>>(),
        ["high", "medium", "low"]
    );
    assert!(set_status_at(&p, &ordered[0].fingerprint, "open").is_ok());
    let sev = list_at(
        &p,
        &Filter {
            severity: Some("high".into()),
            ..Default::default()
        },
    )
    .0;
    assert_eq!(sev.len(), 1);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn equal_severity_rows_are_ordered_newest_first() {
    let d = tmp("recency");
    let p = d.join("vulns.jsonl");
    record_findings_at(
        &p,
        "http://h:9",
        &[
            entry("tool.a", "older", "medium", ""),
            entry("tool.a", "newer", "medium", ""),
        ],
    )
    .unwrap();
    let mut rows = rows_at(&p);
    assert_eq!(rows.len(), 2, "two rules are two rows");
    for r in rows.iter_mut() {
        r.last_seen = if r.rule == "newer" {
            "2026-02-02T00:00:00+00:00".into()
        } else {
            "2026-01-01T00:00:00+00:00".into()
        };
    }
    write_rows(&p, &rows).unwrap();
    let ordered = list_at(&p, &Filter::default()).0;
    assert_eq!(
        ordered.iter().map(|r| r.rule.as_str()).collect::<Vec<_>>(),
        ["newer", "older"],
        "same severity: the row seen most recently comes first"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn set_status_and_resolve_use_the_agent_memory_prefix_rule() {
    let d = tmp("status");
    let p = d.join("vulns.jsonl");
    record_findings_at(
        &p,
        "http://h:9",
        &[
            entry("tool.a", "R1", "low", ""),
            entry("tool.a", "R2", "low", ""),
        ],
    )
    .unwrap();
    let rows = rows_at(&p);
    let fp = &rows[0].fingerprint;
    assert!(!set_status_at(&p, "deadbeefdeadbeefdeadbeef", "accepted").unwrap());
    assert!(
        set_status_at(&p, fp, "wontfix").is_err(),
        "an unknown status is refused"
    );
    // a unique prefix of 6+ characters is enough; a shorter one is not
    assert_eq!(
        resolve(rows.as_slice(), &fp[..6]).as_deref(),
        Some(fp.as_str())
    );
    assert!(resolve(rows.as_slice(), &fp[..5]).is_none());
    assert!(
        resolve(rows.as_slice(), fp.to_uppercase().as_str()).is_some(),
        "case-insensitive"
    );
    assert!(set_status_at(&p, &fp[..8], "forgotten").unwrap());
    let after = rows_at(&p);
    assert_eq!(
        after.iter().find(|r| &r.fingerprint == fp).unwrap().status,
        "forgotten"
    );
    assert!(
        after.iter().any(|r| r.status == "open"),
        "only that row changed"
    );
    assert!(set_status_at(&p, fp, "open").unwrap());
    assert_eq!(
        rows_at(&p)
            .iter()
            .find(|r| &r.fingerprint == fp)
            .unwrap()
            .status,
        "open"
    );
    assert!(!valid_status("maybe"));
    assert!(valid_status(" ACCEPTED "));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn an_oversized_file_is_refused_rather_than_rewritten() {
    let d = tmp("oversized");
    let p = d.join("vulns.jsonl");
    std::fs::create_dir_all(&d).unwrap();
    // a sparse file: the cap is about size, not content
    let f = std::fs::File::create(&p).unwrap();
    f.set_len(MAX_FILE_BYTES + 1).unwrap();
    let e = record_findings_at(&p, "http://h:9", &[entry("tool.a", "R", "low", "")])
        .unwrap_err()
        .to_string();
    assert!(e.contains("byte limit"), "{e}");
    read_at(&p).unwrap_err();
    drop(f);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn records_survive_a_json_round_trip() {
    let d = tmp("roundtrip");
    let p = d.join("vulns.jsonl");
    record_findings_at(
        &p,
        "https://app.example/x",
        &[entry("tool.a", "R", "medium", "/y")],
    )
    .unwrap();
    let before = rows_at(&p);
    let back: Vec<VulnRecord> =
        serde_json::from_str(&serde_json::to_string(&before).unwrap()).unwrap();
    assert_eq!(back, before);
    assert_eq!(back[0].message, "something is listening");
    let _ = std::fs::remove_dir_all(&d);
}

fn finding(check: &str, rule: &str, sev: Severity, location: &str) -> Finding {
    let mut f = Finding::new(
        check,
        rule,
        crate::model::Category::Security,
        sev,
        "Something needs attention",
        location,
    );
    f.detail = "more detail".into();
    f.finalize();
    f
}

#[test]
fn the_record_helper_keeps_only_actionable_unsuppressed_findings() {
    let d = tmp("entries");
    let p = d.join("vulns.jsonl");
    let mut suppressed = finding(
        "tool.grype",
        "CVE-2024-0001",
        Severity::Medium,
        "pkg:lodash@4",
    );
    suppressed.status = FindingStatus::Suppressed;
    let findings = vec![
        finding(
            "plugin.nmap",
            "tcp/2222",
            Severity::High,
            "http://127.0.0.1:9:2222",
        ),
        // info is a note, not a finding
        finding(
            "readiness.readme",
            "readiness.readme.short",
            Severity::Info,
            "README.md:3",
        ),
        suppressed,
    ];
    let kept: Vec<VulnEntry> = findings
        .iter()
        .filter(|f| worth_recording(f))
        .map(entry_of)
        .collect();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].kind, "plugin.nmap");
    assert_eq!(kept[0].severity, "high");
    assert_eq!(
        kept[0].resource, "http://127.0.0.1:9",
        "`Finding::path` drops a trailing `:line`, and `:2222` looks like one"
    );
    record_findings_at(&p, "http://127.0.0.1:9", &kept).unwrap();
    assert_eq!(rows_at(&p).len(), 1);
    assert!(
        record_findings_at(&p, "http://127.0.0.1:9", &[])
            .unwrap()
            .total()
            == 0,
        "recording nothing changes nothing"
    );
    assert_eq!(rows_at(&p).len(), 1);
    let _ = std::fs::remove_dir_all(&d);
}

/// The plain API (`record_findings` / `list` / `set_status`) works against `<data>` with no
/// settings in play — this is what the CLI and the later `/api/vulns` routes use.
#[test]
fn the_plain_api_works_against_the_data_dir() {
    let _g = crate::engine::ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let d = tmp("api");
    unsafe { std::env::set_var("READYHAI_DATA", &d) };
    assert_eq!(path(), d.join("vulns").join("vulns.jsonl"));
    assert!(
        list(&Filter::default()).is_empty(),
        "no file yet is an empty answer"
    );
    record_findings("http://h:9", &[entry("tool.a", "R", "low", "")]).unwrap();
    record_findings("http://h:9", &[entry("tool.a", "R", "low", "")]).unwrap();
    let rows = list(&Filter::default());
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].occurrences, 2);
    assert!(set_status(&rows[0].fingerprint, "accepted").unwrap());
    assert!(
        list(&Filter {
            status: Some("accepted".into()),
            ..Default::default()
        })
        .len()
            == 1
    );
    assert!(!set_status("000000", "open").unwrap());
    unsafe { std::env::remove_var("READYHAI_DATA") };
    let _ = std::fs::remove_dir_all(&d);
}

/// The full hook: notes, path from settings, the off switch, and a failure that stays a note.
#[test]
fn the_scan_hook_records_notes_and_never_fails() {
    let _g = crate::engine::ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let d = tmp("hook");
    unsafe { std::env::set_var("READYHAI_DATA", &d) };
    let findings = vec![finding(
        "plugin.nmap",
        "tcp/2222",
        Severity::High,
        "http://127.0.0.1:9:2222",
    )];

    let note = record_run(&Settings::default(), "http://127.0.0.1:9", &findings).expect("a note");
    assert!(note.contains("vulndb: 1 finding(s) recorded"), "{note}");
    assert_eq!(path(), d.join("vulns").join("vulns.jsonl"));
    let rows = rows_at(&path());
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].kind, "plugin.nmap");

    // nothing actionable, or the section switched off: no note at all
    assert!(record_run(&Settings::default(), "http://x", &[]).is_none());
    let off = Settings {
        vulndb: VulnDb {
            enabled: false,
            path: None,
        },
        ..Default::default()
    };
    assert!(record_run(&off, "http://127.0.0.1:9", &findings).is_none());
    assert_eq!(
        rows_at(&path()).len(),
        1,
        "disabling it does not touch the file"
    );

    // an unusable path is a warning + a note, never an error
    std::fs::write(d.join("blocker"), b"x").unwrap();
    let blocked = Settings {
        vulndb: VulnDb {
            enabled: true,
            path: Some(
                d.join("blocker")
                    .join("vulns.jsonl")
                    .to_string_lossy()
                    .into_owned(),
            ),
        },
        ..Default::default()
    };
    let note = record_run(&blocked, "http://127.0.0.1:9", &findings).expect("a note");
    assert!(note.contains("NOT updated"), "{note}");

    // a [vulndb] path override is where the rows land
    let moved = d.join("elsewhere.jsonl");
    let custom = Settings {
        vulndb: VulnDb {
            enabled: true,
            path: Some(moved.to_string_lossy().into_owned()),
        },
        ..Default::default()
    };
    assert!(
        record_run(&custom, "https://other", &findings)
            .unwrap()
            .contains("recorded")
    );
    assert_eq!(rows_at(&moved).len(), 1);
    unsafe { std::env::remove_var("READYHAI_DATA") };
    let _ = std::fs::remove_dir_all(&d);
}
