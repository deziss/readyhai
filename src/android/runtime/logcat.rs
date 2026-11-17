//! Android logcat parsing, crash/ANR detection, and emulator heuristics.
use regex::Regex;
use std::sync::OnceLock;

use crate::android::util::{re, redact};

/// Emulator if serial is `emulator-*` or ro.kernel.qemu == 1.
pub fn is_emulator(serial: &str, qemu_prop: &str) -> bool {
    serial.starts_with("emulator-") || qemu_prop.trim() == "1"
}

#[derive(Debug, Default, PartialEq)]
pub struct LogScan {
    /// (kind "crash"|"anr", title, detail)
    pub events: Vec<(String, String, String)>,
    pub error_lines: Vec<String>,
}

struct LogLine<'a> {
    tag: &'a str,
    pid: &'a str,
    msg: &'a str,
}

fn parse_brief(l: &str) -> Option<(char, LogLine<'_>)> {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = re(&R, r"^([EWIDVFA])/([^(]+?)\s*\(\s*(\d+)\):\s?(.*)$");
    let c = r.captures(l)?;
    let lv = c.get(1)?.as_str().chars().next()?;
    Some((
        lv,
        LogLine {
            tag: c.get(2)?.as_str(),
            pid: c.get(3)?.as_str(),
            msg: c.get(4)?.as_str(),
        },
    ))
}

pub fn scan_logcat(text: &str, pkg: &str) -> LogScan {
    let mut sc = LogScan::default();
    // crash blocks keyed by pid, in order
    struct Blk {
        lines: Vec<String>,
        pid: String,
    }
    let mut blocks: Vec<Blk> = vec![];
    for raw in text.lines() {
        let Some((lv, ll)) = parse_brief(raw) else {
            continue;
        };
        if lv != 'E' && lv != 'F' {
            // "Process <pkg> (pid N) has died"
            if ll.msg.contains(pkg) && ll.msg.contains("has died") {
                sc.events.push((
                    "crash".into(),
                    format!("Process {pkg} has died"),
                    redact(ll.msg),
                ));
            }
            continue;
        }
        if ll.tag == "AndroidRuntime" {
            if ll.msg.starts_with("FATAL EXCEPTION") {
                blocks.push(Blk {
                    lines: vec![ll.msg.to_string()],
                    pid: ll.pid.to_string(),
                });
            } else if let Some(b) = blocks.last_mut().filter(|b| b.pid == ll.pid) {
                b.lines.push(ll.msg.to_string());
            }
            continue;
        }
        if ll.msg.contains(&format!("ANR in {pkg}")) {
            sc.events
                .push(("anr".into(), redact(ll.msg), String::new()));
        }
        if ll.msg.contains(pkg) || ll.tag.contains(pkg) {
            sc.error_lines
                .push(redact(&format!("{}: {}", ll.tag, ll.msg)));
        }
    }
    for b in blocks {
        if !b.lines.iter().any(|l| l.contains(pkg)) {
            continue;
        }
        let body: Vec<&String> = b
            .lines
            .iter()
            .skip(1)
            .filter(|l| !l.trim_start().starts_with("Process:"))
            .collect();
        let first = body
            .first()
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "FATAL EXCEPTION".into());
        let detail = body
            .iter()
            .take(5)
            .map(|s| s.trim())
            .collect::<Vec<_>>()
            .join("\n");
        for l in &b.lines {
            sc.error_lines.push(redact(l));
        }
        sc.events
            .push(("crash".into(), redact(&first), redact(&detail)));
    }
    sc
}
