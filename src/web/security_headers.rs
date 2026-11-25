use crate::model::*;
use reqwest::header::{HeaderMap, SET_COOKIE};

pub fn hdr(h: &HeaderMap, name: &str) -> Option<String> {
    h.get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

pub fn csp_findings(csp: &str, url: &str, out: &mut Vec<Finding>) {
    let mut issues: Vec<&'static str> = Vec::new();
    for raw_dir in csp.split(';') {
        let mut toks = raw_dir.split_whitespace();
        let Some(name) = toks.next().map(|s| s.to_ascii_lowercase()) else {
            continue;
        };
        let vals: Vec<String> = toks.map(|t| t.to_ascii_lowercase()).collect();
        if matches!(
            name.as_str(),
            "default-src" | "script-src" | "script-src-elem"
        ) {
            if vals.iter().any(|v| v == "'unsafe-inline'") && !issues.contains(&"unsafe-inline") {
                issues.push("unsafe-inline");
            }
            if vals.iter().any(|v| v == "'unsafe-eval'") && !issues.contains(&"unsafe-eval") {
                issues.push("unsafe-eval");
            }
            if vals.iter().any(|v| v == "*") && !issues.contains(&"wildcard *") {
                issues.push("wildcard *");
            }
            if vals.iter().any(|v| v.starts_with("http:")) && !issues.contains(&"http: source") {
                issues.push("http: source");
            }
        }
    }
    if !issues.is_empty() {
        let mut f = Finding::new(
            "web.smoke",
            "web.weak_csp",
            Category::Security,
            Severity::Medium,
            format!("Weak Content-Security-Policy ({})", issues.join(", ")),
            url,
        )
        .detail(format!(
            "CSP permits risky script directives: {}.",
            issues.join(", ")
        ))
        .remediation("Remove 'unsafe-inline', 'unsafe-eval', wildcards, and http: sources; enforce nonces or strict-dynamic.")
        .fp_key(format!("{url}#weak_csp"));
        f.finalize();
        out.push(f);
    }
}

pub fn tls_findings(
    audit: &crate::network::TlsChainAudit,
    url: &str,
    local: bool,
    out: &mut Vec<Finding>,
) {
    if !audit.is_https || !audit.measured {
        return;
    }
    let tv = audit.tls_version.to_ascii_lowercase();
    if tv.contains("tlsv1.0") || tv.contains("tlsv1.1") || tv == "tlsv1" || tv.contains("sslv") {
        let mut f = Finding::new(
            "web.smoke",
            "web.tls_weak_protocol",
            Category::Security,
            Severity::High,
            format!("Deprecated TLS protocol negotiated ({})", audit.tls_version),
            url,
        )
        .detail(format!(
            "Server negotiated {} with cipher {}.",
            audit.tls_version, audit.cipher
        ))
        .remediation("Disable SSLv3, TLS 1.0, and TLS 1.1; require TLS 1.2 or TLS 1.3.")
        .fp_key(format!("{url}#tls_proto"));
        f.finalize();
        out.push(f);
    }
    if let Some(days) = audit.days_remaining
        && days <= 14
    {
        let sev = if days <= 0 {
            Severity::High
        } else {
            Severity::Medium
        };
        let msg = if days <= 0 {
            "TLS certificate expired".to_string()
        } else {
            format!("TLS certificate expires in {days} day(s)")
        };
        let mut f = Finding::new(
            "web.smoke",
            "web.tls_expiring",
            Category::Security,
            sev,
            msg,
            url,
        )
        .detail(format!(
            "Certificate notAfter: {} ({days} days remaining).",
            audit.not_after.as_deref().unwrap_or("unknown")
        ))
        .remediation("Renew and deploy a valid TLS certificate with automated rotation.")
        .fp_key(format!("{url}#tls_expiry"));
        f.finalize();
        out.push(f);
    }
    let untrusted = audit.is_intermediate_missing
        || audit.is_self_signed
        || audit
            .verify_result
            .as_deref()
            .is_some_and(|v| !v.starts_with("0 "));
    if !local && untrusted {
        let mut f = Finding::new(
            "web.smoke",
            "web.tls_untrusted",
            Category::Security,
            Severity::Medium,
            "TLS certificate chain fails trust validation",
            url,
        )
        .detail(audit.diagnosis.clone())
        .remediation("Install the full intermediate certificate chain issued by a trusted CA.")
        .fp_key(format!("{url}#tls_trust"));
        f.finalize();
        out.push(f);
    }
}

pub fn cookie_findings(h: &HeaderMap, url: &str, out: &mut Vec<Finding>) {
    for v in h.get_all(SET_COOKIE) {
        let Ok(s) = v.to_str() else { continue };
        let mut parts = s.split(';');
        let name = parts
            .next()
            .unwrap_or("")
            .split('=')
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        let attrs: Vec<String> = parts.map(|a| a.trim().to_ascii_lowercase()).collect();
        let mut missing = vec![];
        if !attrs.iter().any(|a| a == "secure") {
            missing.push("Secure");
        }
        if !attrs.iter().any(|a| a == "httponly") {
            missing.push("HttpOnly");
        }
        if !attrs.iter().any(|a| a.starts_with("samesite")) {
            missing.push("SameSite");
        }
        if !missing.is_empty() {
            let mut f = Finding::new(
                "web.smoke",
                "web.insecure_cookie",
                Category::Security,
                Severity::Medium,
                format!("Cookie '{name}' lacks {}", missing.join(", ")),
                url,
            )
            .detail(format!(
                "Cookie '{name}' is missing attributes: {}.",
                missing.join(", ")
            ))
            .remediation("Set Secure, HttpOnly and SameSite on session cookies.")
            .fp_key(format!("{url}#{name}"));
            f.finalize();
            out.push(f);
        }
    }
}
