//! Process-wide cache for regexes whose *pattern* is only known at run time.
//!
//! Compiling a pattern costs roughly 10–100µs, which is nothing once and everything when it
//! happens per XML element: the report parsers in `tools/` build one pattern per element name and
//! were recompiling it for every `<host>`, `<port>` and `<testcase>` in a large scan.
//!
//! Patterns whose text is a literal belong in a `static OnceLock<Regex>` at their call site
//! instead (the pattern used by `host::redact` and `android::util`); this cache exists for the
//! cases where the pattern is assembled with `format!`.
//!
//! Every caller here assembles patterns from a handful of code-controlled element and attribute
//! names, never from scanned-target text (compiling a regex from input would be its own hazard,
//! and a pattern per response would grow this map forever). `MAX_CACHED_PATTERNS` is only a
//! backstop against a programming mistake, so it costs an inserted entry only, never a lookup.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use regex::Regex;

/// One entry is ~100ns to look up after the first call, so caching is a pure win even for patterns
/// used twice. The cap only exists so a programming mistake (a pattern per iteration) cannot
/// exhaust memory; at the cap the cache stops inserting and every caller still works.
const MAX_CACHED_PATTERNS: usize = 256;

fn cache() -> &'static Mutex<BTreeMap<String, Arc<Regex>>> {
    static CACHE: OnceLock<Mutex<BTreeMap<String, Arc<Regex>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Define a process-wide compiled regex for a pattern that is a compile-time literal.
///
/// `Regex::new` inside a function body runs on *every call*, which is invisible once and costly
/// inside a per-file or per-response loop. `static RE: LazyLock<Regex>` is the same code without
/// the repeat cost, and reading it needs no lock. Use this instead of `Regex::new(...).unwrap()`
/// whenever the pattern text is a literal; only run-time-assembled patterns need [`compiled`].
///
/// ```ignore
/// regex_cached!(SCANNED, r"(?i)(trufflehog|semgrep|trivy)");
/// if SCANNED.is_lazy_match(text) { /* ... */ }
/// ```
macro_rules! regex_cached {
    ($name:ident, $pattern:expr) => {
        static $name: ::std::sync::LazyLock<::regex::Regex> =
            ::std::sync::LazyLock::new(|| ::regex::Regex::new($pattern).unwrap());
    };
}

/// Compiled form of `pattern`, shared across every caller that asks for the same text.
///
/// Panics on an invalid pattern, exactly like `Regex::new().unwrap()` at the call sites this
/// replaces: every pattern here is built from code-controlled names, so a bad pattern is a bug.
pub(crate) fn compiled(pattern: &str) -> Arc<Regex> {
    let mut map = cache().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(re) = map.get(pattern) {
        return Arc::clone(re);
    }
    let re = Arc::new(
        Regex::new(pattern).unwrap_or_else(|e| panic!("invalid pattern {pattern:?}: {e}")),
    );
    if map.len() < MAX_CACHED_PATTERNS {
        map.insert(pattern.to_string(), Arc::clone(&re));
    }
    re
}

#[cfg(test)]
mod tests {
    use super::compiled;
    use std::sync::Arc;
    use std::time::Instant;

    #[test]
    fn the_same_pattern_keeps_its_compiled_form() {
        let a = compiled(r"<(host)\b([^>]*?)>");
        let b = compiled(r"<(host)\b([^>]*?)>");
        assert!(Arc::ptr_eq(&a, &b), "second lookup must not recompile");
        assert!(a.is_match("<host addr=\"1\">"));
    }

    #[test]
    fn different_patterns_stay_distinct_and_a_repeat_is_fast() {
        let x = compiled(r"^alpha\d+$");
        let y = compiled(r"^beta\d+$");
        assert!(!Arc::ptr_eq(&x, &y));
        assert!(x.is_match("alpha1"));
        assert!(y.is_match("beta2"));

        // the reason this module exists: 2000 lookups of a repeat pattern beat 2000 compiles
        // assembled per attribute name, exactly like `tools::sarif_junit::attr`
        let start = Instant::now();
        for name in std::iter::repeat_n("name", 2000) {
            let re = compiled(&format!(
                r#"(?:^|\s){}\s*=\s*(?:"([^"]*)"|'([^']*)')"#,
                regex::escape(name)
            ));
            let _ = re.is_match("name=\"x\"");
        }
        let reused = start.elapsed();
        let start = Instant::now();
        for _ in 0..2000 {
            let re = regex::Regex::new(&format!(
                r#"(?:^|\s){}\s*=\s*(?:"([^"]*)"|'([^']*)')"#,
                regex::escape("name")
            ))
            .unwrap();
            let _ = re.is_match("name=\"x\"");
        }
        let fresh = start.elapsed();
        assert!(
            reused < fresh,
            "cached lookups ({reused:?}) should beat compiling each time ({fresh:?})"
        );
    }

    #[test]
    fn patterns_without_capture_groups_still_work_after_caching() {
        static P: &str = r"(?-i)READYHAI_CACHE_PROBE";
        let a = compiled(P);
        let b = compiled(P);
        assert!(Arc::ptr_eq(&a, &b));
        assert!(a.is_match("READYHAI_CACHE_PROBE"));
        assert!(!a.is_match("readyhai_cache_probe"));
    }
}
