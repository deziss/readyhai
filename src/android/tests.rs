use serde_json::Value;

use super::*;
use crate::model::{Category, Severity};

fn fixture(n: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/android/{n}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn mapping_counts_and_severities() {
    let rep: Value = serde_json::from_str(&fixture("mobsf_report.json")).unwrap();
    let fs = map_report(&rep);
    let by = |r: &str| {
        fs.iter().find(|f| f.rule == r).unwrap_or_else(|| {
            panic!(
                "missing {r}: {:?}",
                fs.iter().map(|f| &f.rule).collect::<Vec<_>>()
            )
        })
    };
    assert_eq!(
        by("mobsf.manifest_analysis.debuggable").severity,
        Severity::High
    );
    assert_eq!(
        by("mobsf.manifest_analysis.allow_backup").severity,
        Severity::Medium
    );
    assert_eq!(
        by("mobsf.manifest_analysis.cleartext_traffic").severity,
        Severity::Medium
    );
    assert_eq!(
        by("mobsf.manifest_analysis.exported_activity").severity,
        Severity::Medium
    );
    assert_eq!(
        by("mobsf.manifest_analysis.target_sdk_info").severity,
        Severity::Low
    );
    assert!(!fs.iter().any(|f| f.rule.ends_with("good_one")));
    assert_eq!(
        by("mobsf.code_analysis.android_sql_raw_query").severity,
        Severity::High
    );
    assert_eq!(
        by("mobsf.code_analysis.android_sql_raw_query").ids,
        vec!["CWE-89"]
    );
    assert_eq!(
        by("mobsf.code_analysis.android_insecure_random").location,
        "jakhar/aseem/diva/Other.java"
            .to_string()
            .min("jakhar/aseem/diva/Rng.java".to_string())
    );
    assert_eq!(by("mobsf.permissions.dangerous").severity, Severity::Low);
    assert!(
        by("mobsf.permissions.dangerous")
            .detail
            .contains("WRITE_EXTERNAL_STORAGE")
    );
    assert!(
        !by("mobsf.permissions.dangerous")
            .detail
            .contains("INTERNET")
    );
    assert_eq!(by("mobsf.trackers.detected").severity, Severity::Low);
    assert_eq!(
        by("mobsf.target_sdk.outdated").category,
        Category::SupplyChain
    );
    assert_eq!(by("mobsf.secrets.hardcoded").severity, Severity::Medium);
    assert!(fs.iter().any(|f| f.rule.starts_with("mobsf.certificate.")));
    assert!(
        fs.iter()
            .any(|f| f.rule.starts_with("mobsf.binary_analysis."))
    );
    assert!(
        fs.iter()
            .any(|f| f.rule.starts_with("mobsf.network_security."))
    );
    assert!(fs.iter().all(|f| f.check == "android.mobsf"));
}

#[test]
fn secrets_never_leak() {
    let raw = fixture("mobsf_report.json");
    let rep: Value = serde_json::from_str(&raw).unwrap();
    let all = serde_json::to_string(&map_report(&rep)).unwrap();
    let saved = serde_json::to_string(&scrub_report(&rep)).unwrap();
    for bad in [
        "AIzaSyFAKE",
        "wJalrFAKE",
        "SUPERSECRETURLTOKEN",
        "FAKEPASSWORD",
        "dev@fake.example.com",
    ] {
        assert!(!all.contains(bad), "finding leaked {bad}");
        assert!(!saved.contains(bad), "saved report leaked {bad}");
    }
    let s: Value = serde_json::from_str(&saved).unwrap();
    assert_eq!(s["secrets"]["count"], 2);
    assert_eq!(s["urls"]["count"], 1);
    assert_eq!(s["package_name"], "jakhar.aseem.diva");
}

#[test]
fn crash_parsing() {
    let sc = scan_logcat(&fixture("logcat.txt"), "jakhar.aseem.diva");
    let crashes: Vec<_> = sc.events.iter().filter(|e| e.0 == "crash").collect();
    let anrs: Vec<_> = sc.events.iter().filter(|e| e.0 == "anr").collect();
    assert_eq!(crashes.len(), 1);
    assert_eq!(anrs.len(), 1);
    assert!(crashes[0].1.starts_with("java.lang.NullPointerException"));
    assert_eq!(crashes[0].2.lines().count(), 5);
    assert!(crashes[0].2.contains("MainActivity.onCreate"));
    assert!(!sc.events.iter().any(|e| e.1.contains("not ours")));
    assert!(anrs[0].1.contains("ANR in jakhar.aseem.diva"));
    let joined = sc.error_lines.join("\n");
    assert!(!joined.contains("dev@fake.example.com"));
    assert!(!joined.contains("abcdef0123456789abcdef0123456789abcd"));
    assert!(!joined.contains("other.app"));
    assert!(joined.contains("Failed to load config"));
}

#[test]
fn multipart_and_form() {
    let b = multipart_body("BND", "file", "a b/../x.apk", b"PK\x03\x04");
    let t = String::from_utf8_lossy(&b).to_string();
    assert!(t.starts_with(
        "--BND\r\nContent-Disposition: form-data; name=\"file\"; filename=\"ab..x.apk\""
    ));
    assert!(t.contains("\r\n\r\nPK"));
    assert!(t.ends_with("\r\n--BND--\r\n"));
    assert_eq!(
        form_body(&[("hash", "ab"), ("file_name", "a b.apk")]),
        "hash=ab&file_name=a%20b.apk"
    );
}

#[test]
fn emulator_and_port() {
    assert!(is_emulator("emulator-5554", ""));
    assert!(is_emulator("10.0.0.5:5555", "1\n"));
    assert!(!is_emulator("R58M123ABC", "0"));
    assert_eq!(parse_docker_port("127.0.0.1:49153\n"), Some(49153));
    assert_eq!(parse_docker_port("0.0.0.0:32768\n[::]:32768"), Some(32768));
    assert_eq!(parse_docker_port(""), None);
}

#[test]
fn redaction() {
    let r = redact(
        "user a@b.io password=hunter2 Bearer abcdefabcdefabcdefabcdefabcdef12 eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4",
    );
    assert!(
        !r.contains("a@b.io")
            && !r.contains("hunter2")
            && !r.contains("eyJhbGci")
            && !r.contains("abcdefabcdef")
    );
}
