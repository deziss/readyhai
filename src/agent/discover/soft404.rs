//! Soft-404 calibration: how does the target answer a path that cannot exist?
//!
//! Many SPAs and "friendly" servers answer 200 (the app shell, a custom not-found page, the login
//! page) for any path. Such a response says nothing about whether a route exists, so discovery
//! asks for three random paths first, fingerprints the answers (status, length, hash of the
//! normalised visible text) and flags every later response that matches as a catch-all.
use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

use super::{Fetched, fetch};
use crate::agent::budget::RunBudget;
use crate::agent::types::Soft404Fingerprint;

/// Calibration (and sensitive-file probe) bodies are read up to this size.
pub(super) const CALIBRATION_BODY_CAP: usize = 1024 * 1024;

fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pat).unwrap())
}

/// The text a visitor would read: scripts, styles, comments and tags removed, whitespace collapsed,
/// the requested path, numbers and long hex tokens (ids, hashes, nonces, timestamps) dropped, so
/// two answers of the same template compare equal whatever the request or the clock was.
pub fn normalise_text(body: &str, path: &str) -> String {
    static SCRIPT: OnceLock<Regex> = OnceLock::new();
    static STYLE: OnceLock<Regex> = OnceLock::new();
    static OPEN_SCRIPT: OnceLock<Regex> = OnceLock::new();
    static COMMENT: OnceLock<Regex> = OnceLock::new();
    static TAG: OnceLock<Regex> = OnceLock::new();
    static HEX: OnceLock<Regex> = OnceLock::new();
    static DIGITS: OnceLock<Regex> = OnceLock::new();
    let mut s = re(&SCRIPT, r"(?is)<script\b[^>]*>.*?</script\s*>")
        .replace_all(body, " ")
        .into_owned();
    s = re(&STYLE, r"(?is)<style\b[^>]*>.*?</style\s*>")
        .replace_all(&s, " ")
        .into_owned();
    // a script cut off by the body cap would otherwise leak its source into the text
    s = re(&OPEN_SCRIPT, r"(?is)<(?:script|style)\b.*$")
        .replace_all(&s, " ")
        .into_owned();
    s = re(&COMMENT, r"(?s)<!--.*?-->")
        .replace_all(&s, " ")
        .into_owned();
    s = re(&TAG, r"<[^>]*>").replace_all(&s, " ").into_owned();
    let p = path.split(['?', '#']).next().unwrap_or("");
    if p.len() > 1 {
        s = s.replace(p, " ");
        if let Some(last) = p.rsplit('/').find(|x| x.len() > 2) {
            s = s.replace(last, " ");
        }
    }
    s = re(&HEX, r"\b[0-9a-fA-F]{8,}\b")
        .replace_all(&s, " ")
        .into_owned();
    s = re(&DIGITS, r"[0-9]+").replace_all(&s, " ").into_owned();
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Fingerprint of one answer: `status` is the status the server answered with (the first hop of
/// a redirect), the text and length are those of the final body.
pub fn fingerprint(status: u16, body: &str, path: &str) -> Soft404Fingerprint {
    let text = normalise_text(body, path);
    let digest = Sha256::digest(text.as_bytes());
    Soft404Fingerprint {
        status,
        len: body.len(),
        text_hash: hex::encode(&digest[..8]),
    }
}

/// Two lengths are the same page when they differ by at most 5% (or a few bytes, for tiny bodies).
fn len_close(a: usize, b: usize) -> bool {
    let (lo, hi) = (a.min(b), a.max(b));
    let diff = hi - lo;
    diff <= 8 || diff * 20 <= hi
}

/// Does `other` look like the calibrated not-found answer?
pub fn matches(cal: &Soft404Fingerprint, other: &Soft404Fingerprint) -> bool {
    cal.status == other.status && cal.text_hash == other.text_hash && len_close(cal.len, other.len)
}

/// The fingerprint a fetched answer for `path` has.
pub(super) fn of_fetched(f: &Fetched, path: &str) -> Soft404Fingerprint {
    fingerprint(f.status, &f.body, path)
}

/// Pick the fingerprint at least two of the samples agree on (None: they all differ, so the
/// target's not-found answer is not stable enough to compare against).
pub fn consensus(samples: &[Soft404Fingerprint]) -> Option<Soft404Fingerprint> {
    samples
        .iter()
        .find(|a| samples.iter().filter(|b| matches(a, b)).count() >= 2)
        .cloned()
}

fn random_hex(bytes: usize) -> String {
    (0..bytes)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect()
}

/// Three random paths that cannot exist: a root-level one, a second one, and a nested one (some
/// routers treat the nested case differently). Prefixed so a human reading logs knows why.
pub fn random_paths() -> [String; 3] {
    [
        format!("/rh{}", random_hex(8)),
        format!("/rh{}", random_hex(8)),
        format!("/rh{}/rh{}", random_hex(6), random_hex(6)),
    ]
}

/// Ask the target for three random paths. Returns the fingerprint of its not-found answer (None
/// when it could not be established) and the notes to report.
pub(super) fn calibrate(
    cl: &reqwest::blocking::Client,
    base: &str,
    host: &str,
    budget: &mut RunBudget,
) -> (Option<Soft404Fingerprint>, Vec<String>) {
    let mut samples = vec![];
    for path in random_paths() {
        match fetch(
            cl,
            &format!("{base}{path}"),
            host,
            budget,
            CALIBRATION_BODY_CAP,
        ) {
            Ok(f) => samples.push(of_fetched(&f, &path)),
            Err(_) => {
                if budget.stopped().is_some() {
                    break;
                }
            }
        }
    }
    if samples.len() < 2 {
        return (
            None,
            vec!["soft-404 calibration skipped: the target did not answer the random paths".into()],
        );
    }
    match consensus(&samples) {
        Some(fp) => {
            let note = if matches!(fp.status, 404 | 410) {
                format!(
                    "soft-404 calibration: unknown paths answer HTTP {} (no catch-all)",
                    fp.status
                )
            } else {
                format!(
                    "soft-404 calibration: unknown paths answer HTTP {} with one fixed page (catch-all); \
                     responses identical to it are not counted as routes",
                    fp.status
                )
            };
            (Some(fp), vec![note])
        }
        None => (
            None,
            vec![
                "soft-404 calibration: the answers to random paths differ from each other, so catch-all detection is off"
                    .into(),
            ],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHELL: &str = r#"<!DOCTYPE html><html><head><title>App</title>
        <script nonce="a1b2c3d4e5f60718">window.__BOOT={"t":1730000000}</script><style>body{margin:0}</style></head>
        <body><!-- build 4412 --><div id="root">Loading&hellip;</div><script src="/static/app.3f9a1c7e5d2b.js"></script></body></html>"#;

    #[test]
    fn normalise_keeps_only_what_a_visitor_reads() {
        assert_eq!(normalise_text(SHELL, "/zzz"), "App Loading&hellip;");
        // numbers, long hex tokens and the requested path do not count
        let page = "<p>Page /rh0123456789abcdef not found (error 404) at 2026-11-06 12:30:55, ref deadbeefcafe1234</p>";
        assert_eq!(
            normalise_text(page, "/rh0123456789abcdef"),
            "Page not found (error ) at - - : : , ref"
        );
        // a script cut off by the body cap does not leak into the text
        assert_eq!(
            normalise_text("<p>hi</p><script>var secret = 1;", "/"),
            "hi"
        );
    }

    #[test]
    fn the_same_template_matches_whatever_the_request_or_the_clock() {
        let a = fingerprint(200, SHELL, "/rhaaaaaaaaaaaaaaaa");
        let b = fingerprint(
            200,
            &SHELL
                .replace("1730000000", "1730009999")
                .replace("4412", "4413"),
            "/rhbbbbbbbbbbbbbbbb/rhcccccccccccc",
        );
        assert!(matches(&a, &b), "{a:?} vs {b:?}");
        // a different status is a different answer
        assert!(!matches(&a, &fingerprint(404, SHELL, "/x")));
        // different visible text is a different page, even at the same length
        let other = SHELL.replace("Loading", "Welcome");
        assert!(!matches(&a, &fingerprint(200, &other, "/x")));
        // the length tolerance is 5%: a page 2% longer matches, one 20% longer does not
        let long = |pad: usize| format!("{SHELL}{}", " ".repeat(pad));
        let base = fingerprint(200, &long(0), "/x");
        assert!(matches(
            &base,
            &fingerprint(200, &long(SHELL.len() / 50), "/x")
        ));
        assert!(!matches(
            &base,
            &fingerprint(200, &long(SHELL.len() / 5), "/x")
        ));
    }

    #[test]
    fn calibration_needs_two_samples_that_agree() {
        let fp = |status: u16, text: &str| fingerprint(status, text, "/x");
        let (a, b, c) = (
            fp(200, "<p>one</p>"),
            fp(200, "<p>one</p>"),
            fp(200, "<p>two</p>"),
        );
        assert_eq!(
            consensus(&[a.clone(), c.clone(), b.clone()]),
            Some(a.clone())
        );
        assert_eq!(consensus(&[a.clone(), c.clone()]), None);
        assert_eq!(consensus(&[]), None);
        assert_eq!(consensus(&[a.clone(), a.clone()]), Some(a));
    }

    #[test]
    fn the_random_paths_are_random_and_cannot_be_routes() {
        let (a, b) = (random_paths(), random_paths());
        assert_ne!(a, b);
        assert!(a.iter().all(|p| p.starts_with("/rh") && p.len() > 10));
        assert!(a[2].matches('/').count() == 2, "one nested path: {a:?}");
    }
}
