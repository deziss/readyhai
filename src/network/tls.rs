//! TLS handshake, certificate chain auditing, and OpenSSL s_client parser.

use super::types::{MAX_CAPTURE_BYTES, NOT_MEASURED, TlsChainAudit};
use super::utils::hostport;
use crate::tools::run_capped;
use std::process::Command;
use std::time::Duration;

#[derive(Default)]
pub(crate) struct SClient {
    pub(crate) version: Option<String>,
    pub(crate) cipher: Option<String>,
    pub(crate) verify_code: Option<i32>,
    pub(crate) verify_text: Option<String>,
    /// Some(true) = a stapled OCSP response was sent, Some(false) = none sent, None = no statement.
    pub(crate) ocsp_stapled: Option<bool>,
    pub(crate) chain_len: usize,
    pub(crate) leaf_pem: Option<String>,
}

pub(crate) fn parse_s_client(text: &str) -> SClient {
    let mut s = SClient::default();
    for line in text.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("New, ") {
            // "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384"
            if let Some((ver, cipher)) = rest.split_once(", Cipher is ")
                && !cipher.contains("(NONE)")
            {
                s.version = Some(ver.trim().to_string());
                s.cipher = Some(cipher.trim().to_string());
            }
        } else if let Some(rest) = l.strip_prefix("Verify return code:") {
            // "Verify return code: 20 (unable to get local issuer certificate)"
            let rest = rest.trim();
            s.verify_code = rest.split_whitespace().next().and_then(|c| c.parse().ok());
            s.verify_text = Some(rest.to_string());
        } else if l.starts_with("OCSP response: no response sent") {
            s.ocsp_stapled = Some(false);
        } else if l.starts_with("OCSP Response Status: successful") || l == "OCSP Response Data:" {
            s.ocsp_stapled = Some(true);
        }
    }
    let mut in_pem = false;
    let mut pem = String::new();
    for line in text.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            in_pem = true;
            s.chain_len += 1;
            if s.chain_len == 1 {
                pem.clear();
            }
        }
        if in_pem && s.chain_len == 1 {
            pem.push_str(line);
            pem.push('\n');
        }
        if line.starts_with("-----END CERTIFICATE-----") {
            in_pem = false;
        }
    }
    if s.chain_len >= 1 {
        s.leaf_pem = Some(pem);
    }
    s
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Hinnant's algorithm).
pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// "Jan  1 00:00:00 2027 GMT" (openssl's notAfter format) to unix seconds.
pub(crate) fn parse_openssl_date(s: &str) -> Option<i64> {
    let mut it = s.split_whitespace();
    let mon = it.next()?;
    let day: i64 = it.next()?.parse().ok()?;
    let mut hms = it.next()?.split(':');
    let (h, mi, sec): (i64, i64, i64) = (
        hms.next()?.parse().ok()?,
        hms.next()?.parse().ok()?,
        hms.next()?.parse().ok()?,
    );
    let year: i64 = it.next()?.parse().ok()?;
    let m = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|x| *x == mon)? as i64
        + 1;
    Some(days_from_civil(year, m, day) * 86_400 + h * 3600 + mi * 60 + sec)
}

#[derive(Debug, Default, PartialEq)]
pub(crate) struct LeafInfo {
    pub(crate) subject: Option<String>,
    pub(crate) issuer: Option<String>,
    pub(crate) not_after: Option<String>,
    pub(crate) sans: Vec<String>,
}

/// Parse `openssl x509 -noout -subject -issuer -enddate [-ext subjectAltName]` output.
pub(crate) fn parse_x509(text: &str) -> LeafInfo {
    let mut leaf = LeafInfo::default();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let l = line.trim();
        if let Some(v) = l.strip_prefix("subject=") {
            leaf.subject = Some(v.trim().to_string());
        } else if let Some(v) = l.strip_prefix("issuer=") {
            leaf.issuer = Some(v.trim().to_string());
        } else if let Some(v) = l.strip_prefix("notAfter=") {
            leaf.not_after = Some(v.trim().to_string());
        } else if l.starts_with("X509v3 Subject Alternative Name")
            && let Some(next) = lines.next()
        {
            leaf.sans = next
                .split(',')
                .filter_map(|e| e.trim().strip_prefix("DNS:").map(str::to_string))
                .collect();
        }
    }
    leaf
}

pub(crate) fn unmeasured_tls(is_https: bool, why: &str) -> TlsChainAudit {
    TlsChainAudit {
        is_https,
        measured: false,
        tls_version: NOT_MEASURED.to_string(),
        cipher: NOT_MEASURED.to_string(),
        cert_issuer: NOT_MEASURED.to_string(),
        cert_subject: NOT_MEASURED.to_string(),
        cert_sans: Vec::new(),
        not_after: None,
        days_remaining: None,
        is_self_signed: false,
        is_intermediate_missing: false,
        ocsp_stapled: None,
        chain_length: None,
        verify_result: None,
        not_measured: vec![why.to_string()],
        diagnosis: format!("TLS was not measured: {why}."),
    }
}

pub fn audit_tls_chain(
    url: &reqwest::Url,
    host: &str,
    port: u16,
    timeout_ms: u64,
) -> TlsChainAudit {
    if url.scheme() != "https" {
        return TlsChainAudit {
            is_https: false,
            measured: true,
            tls_version: "None".to_string(),
            cipher: "None (Plaintext HTTP)".to_string(),
            cert_issuer: "None".to_string(),
            cert_subject: "None".to_string(),
            cert_sans: Vec::new(),
            not_after: None,
            days_remaining: None,
            is_self_signed: false,
            is_intermediate_missing: false,
            ocsp_stapled: None,
            chain_length: None,
            verify_result: None,
            not_measured: Vec::new(),
            diagnosis: "Target uses unencrypted plaintext HTTP transport.".to_string(),
        };
    }

    let limit = Duration::from_millis(timeout_ms.clamp(2000, 10_000));
    let mut cmd = Command::new("openssl");
    cmd.arg("s_client")
        .arg("-connect")
        .arg(hostport(host, port))
        .args(["-status", "-showcerts"]);
    if host.parse::<std::net::IpAddr>().is_err() {
        cmd.arg("-servername").arg(host);
    }
    // stdin is null: s_client otherwise waits for input and the call hangs
    let out = match run_capped(&mut cmd, limit, MAX_CAPTURE_BYTES, None) {
        Ok(o) if o.timed_out => return unmeasured_tls(true, "openssl s_client timed out"),
        Ok(o) => o,
        Err(_) => return unmeasured_tls(true, "openssl is not available"),
    };
    let text = format!("{}\n{}", out.stdout_lossy(), out.stderr_lossy());
    let sc = parse_s_client(&text);
    let (Some(tls_version), Some(cipher)) = (sc.version.clone(), sc.cipher.clone()) else {
        return unmeasured_tls(true, "TLS handshake failed or no TLS output was returned");
    };

    // Certificate details come from the leaf PEM s_client printed.
    let mut leaf = LeafInfo::default();
    if let Some(pem) = &sc.leaf_pem {
        let run_x509 = |args: &[&str]| {
            let mut c = Command::new("openssl");
            c.arg("x509").arg("-noout").args(args);
            run_capped(
                &mut c,
                Duration::from_secs(5),
                64 * 1024,
                Some(pem.as_bytes()),
            )
            .ok()
            .filter(|o| o.success())
        };
        let o = run_x509(&["-subject", "-issuer", "-enddate", "-ext", "subjectAltName"])
            .or_else(|| run_x509(&["-subject", "-issuer", "-enddate"]));
        if let Some(o) = o {
            leaf = parse_x509(&o.stdout_lossy());
        }
    }

    let days_remaining = leaf
        .not_after
        .as_deref()
        .and_then(parse_openssl_date)
        .map(|exp| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            (exp - now).div_euclid(86_400)
        });
    let code = sc.verify_code;
    let is_self_signed =
        matches!(code, Some(18 | 19)) || (leaf.subject.is_some() && leaf.subject == leaf.issuer);
    // 21 = "unable to verify the first certificate"; 20 with a single certificate sent means the
    // server did not send the intermediate. With a longer chain, 20 is an untrusted root instead.
    let is_intermediate_missing =
        !is_self_signed && (code == Some(21) || (code == Some(20) && sc.chain_len <= 1));

    let mut not_measured = Vec::new();
    if leaf.subject.is_none() {
        not_measured.push("certificate details (could not parse the leaf certificate)".to_string());
    }
    if sc.ocsp_stapled.is_none() {
        not_measured.push("ocsp_stapled".to_string());
    }
    let diagnosis = if is_intermediate_missing {
        "CRITICAL: Intermediate certificate missing or invalid issuer! Modern desktop browsers cache intermediates, but mobile devices and fresh sessions will fail with SSL errors.".to_string()
    } else if is_self_signed {
        "WARNING: Self-signed certificate detected. Public clients without explicit trust roots will reject this connection.".to_string()
    } else if let Some(t) = sc.verify_text.as_deref().filter(|_| code != Some(0)) {
        format!("WARNING: certificate verification against this host's trust store failed: {t}.")
    } else {
        format!("TLS handshake succeeded using {tls_version} with cipher {cipher}.")
    };

    TlsChainAudit {
        is_https: true,
        measured: true,
        tls_version,
        cipher,
        cert_issuer: leaf.issuer.unwrap_or_else(|| NOT_MEASURED.to_string()),
        cert_subject: leaf.subject.unwrap_or_else(|| NOT_MEASURED.to_string()),
        cert_sans: leaf.sans,
        not_after: leaf.not_after,
        days_remaining,
        is_self_signed,
        is_intermediate_missing,
        ocsp_stapled: sc.ocsp_stapled,
        chain_length: Some(sc.chain_len),
        verify_result: sc.verify_text,
        not_measured,
        diagnosis,
    }
}
