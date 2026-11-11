//! Authentication & Authorization adversarial probes:
//! 1. JWT tampering (`alg: none`, stripped signature, escalated claims with bogus signature,
//!    `kid` directory traversal).
//! 2. BFLA (Broken Function Level Authorization): non-privileged role exercising admin/internal
//!    operations.
//! 3. Reverse-proxy path-normalization & header-override ACL bypass (`/.`, `..;/`, case toggle,
//!    `X-Forwarded-For: 127.0.0.1`, `X-Original-URL`, `X-Rewrite-URL`).

use std::collections::BTreeSet;

use serde_json::Value;

use crate::agent::discover::Discovery;
use crate::agent::exec::Credentials;
use crate::agent::plan::{Depth, mk};
use crate::agent::types::PlannedCase;

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = *chunk.get(1).unwrap_or(&0) as usize;
        let b2 = *chunk.get(2).unwrap_or(&0) as usize;
        out.push(B64URL[b0 >> 2] as char);
        out.push(B64URL[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        if chunk.len() > 1 {
            out.push(B64URL[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL[b2 & 0x3f] as char);
        }
    }
    out
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits: u8 = 0;
    for b in s.bytes() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Parse a 3-segment JWT string into `(header_json, payload_json)` when both base64url-decode
/// cleanly into JSON objects.
pub fn looks_like_jwt(tok: &str) -> Option<(Value, Value)> {
    let mut parts = tok.trim().split('.');
    let (h, p, s) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || h.len() < 4 || p.len() < 4 {
        return None;
    }
    // Signature part may be empty in an already-unsigned `alg:none` JWT or non-empty JWS.
    let _ = s;
    let h_bytes = b64url_decode(h)?;
    let p_bytes = b64url_decode(p)?;
    let hdr: Value = serde_json::from_slice(&h_bytes).ok()?;
    let pay: Value = serde_json::from_slice(&p_bytes).ok()?;
    if !hdr.is_object() || !pay.is_object() {
        return None;
    }
    if hdr.get("alg").is_none()
        && hdr.get("typ").is_none()
        && pay.get("sub").is_none()
        && pay.get("role").is_none()
        && pay.get("exp").is_none()
        && pay.get("iat").is_none()
    {
        return None;
    }
    Some((hdr, pay))
}

/// Construct tampered JWT variants from an observed 3-part JWT.
/// Every variant alters the header, claims, or strips/invalidates the signature so the resulting
/// string never equals the original credential.
pub fn jwt_tamper_variants(tok: &str) -> Vec<(&'static str, String)> {
    let Some((orig_hdr, orig_pay)) = looks_like_jwt(tok) else {
        return Vec::new();
    };
    let mut parts = tok.trim().split('.');
    let (h_b64, p_b64) = match (parts.next(), parts.next()) {
        (Some(h), Some(p)) => (h, p),
        _ => return Vec::new(),
    };

    let mut out = Vec::new();
    let none_hdr = serde_json::json!({ "alg": "none", "typ": "JWT" });
    let none_hdr_b64 = b64url_encode(none_hdr.to_string().as_bytes());
    out.push(("alg_none", format!("{none_hdr_b64}.{p_b64}.")));
    out.push(("stripped_sig", format!("{h_b64}.{p_b64}.")));

    let mut esc_pay = orig_pay;
    if let Some(obj) = esc_pay.as_object_mut() {
        obj.insert("role".into(), Value::String("admin".into()));
        obj.insert("is_admin".into(), Value::Bool(true));
        obj.insert("admin".into(), Value::Bool(true));
    }
    let esc_pay_b64 = b64url_encode(esc_pay.to_string().as_bytes());
    if esc_pay_b64 != p_b64 {
        out.push((
            "alg_none_escalated",
            format!("{none_hdr_b64}.{esc_pay_b64}."),
        ));
    }
    out.push((
        "tampered_claims_invalid_sig",
        format!("{h_b64}.{esc_pay_b64}.readyhai_invalid_sig"),
    ));

    let mut kid_hdr = orig_hdr;
    if let Some(obj) = kid_hdr.as_object_mut() {
        obj.insert("alg".into(), Value::String("HS256".into()));
        obj.insert("kid".into(), Value::String("../../../../dev/null".into()));
    }
    out.push((
        "kid_traversal",
        format!(
            "{}.{esc_pay_b64}.",
            b64url_encode(kid_hdr.to_string().as_bytes())
        ),
    ));

    out.retain(|(_, v)| v != tok.trim());
    out
}

use crate::agent::oracle::is_privileged_api_path as is_privileged_path;

fn is_static_or_probe_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.starts_with("/.")
        || p.ends_with(".env")
        || p.ends_with(".config")
        || p.ends_with(".bak")
        || p.ends_with(".json")
        || p.ends_with(".yml")
        || p.ends_with(".yaml")
        || p.ends_with(".css")
        || p.ends_with(".js")
}

fn target_secured_routes(
    d: &Discovery,
    limit: usize,
) -> Vec<(String, String, Option<u16>, &'static str)> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for r in d.routes.iter().filter(|r| {
        matches!(r.status_code, 401 | 403)
            && !r.catch_all
            && !matches!(r.source.as_str(), "probe" | "openapi")
            && !is_static_or_probe_path(&r.path)
    }) {
        if seen.insert(r.path.clone()) {
            out.push((
                r.method.to_ascii_uppercase(),
                r.path.clone(),
                Some(r.status_code),
                if d.spec.is_some() {
                    "openapi"
                } else {
                    "deterministic"
                },
            ));
        }
    }
    if let Some(spec) = &d.spec {
        for op in spec.ops.iter().filter(|o| o.secured && o.method == "GET") {
            let full = format!("{}{}", spec.base_path, op.path);
            if !full.contains('{') && seen.insert(full.clone()) {
                out.push(("GET".into(), full, None, "openapi"));
            }
        }
    }
    // Prioritize admin/internal endpoints first so JWT tampering doesn't spend its budget on
    // public/profile endpoints ahead of privileged targets.
    out.sort_by_key(|r| !is_privileged_path(&r.1));
    out.truncate(limit);
    out
}

fn jwt_cases(d: &Discovery, creds: &Credentials, depth: Depth) -> Vec<PlannedCase> {
    let Some((_, tok)) = creds.jwt_sample() else {
        return Vec::new();
    };
    let variants = jwt_tamper_variants(tok);
    if variants.is_empty() {
        return Vec::new();
    }
    let route_limit = match depth {
        Depth::Quick => 0,
        Depth::Standard => 2,
        Depth::Deep => 4,
    };
    let routes = target_secured_routes(d, route_limit);
    let mut out = Vec::new();
    for (method, path, st, src) in routes {
        for (kind, forged_jwt) in &variants {
            let label = match *kind {
                "alg_none" => "JWT alg=none unsigned token accepted check",
                "alg_none_escalated" => "JWT alg=none admin-claim escalation check",
                "stripped_sig" => "JWT stripped signature bypass check",
                "tampered_claims_invalid_sig" => {
                    "JWT tampered admin claims invalid signature check"
                }
                "kid_traversal" => "JWT kid path-traversal /dev/null check",
                _ => "JWT tampering check",
            };
            let mut c = mk(
                "authz",
                format!("{label} ({path})"),
                &method,
                path.clone(),
                "Send a tampered JWT without a valid signature",
                None,
                "HTTP 401 or 403",
                Some(401),
                "critical",
                "raw_jwt",
                src,
            );
            c.secured = Some(true);
            c.route_status = st;
            c.headers = vec![("Authorization".into(), format!("Bearer {forged_jwt}"))];
            out.push(c);
        }
    }
    out
}

fn bfla_cases(d: &Discovery, creds: &Credentials, depth: Depth) -> Vec<PlannedCase> {
    let non_admins = creds.non_admin_roles();
    let Some(low_role) = non_admins.first() else {
        return Vec::new();
    };
    let cap = match depth {
        Depth::Quick => 0,
        Depth::Standard => 4,
        Depth::Deep => 8,
    };
    if cap == 0 {
        return Vec::new();
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();

    if let Some(spec) = &d.spec {
        for op in spec.ops.iter().filter(|o| {
            o.secured && is_privileged_path(&o.path) && !o.path.contains('{') && !o.has_body
        }) {
            let full = format!("{}{}", spec.base_path, op.path);
            if seen.insert((op.method.clone(), full.clone())) {
                let mut c = mk(
                    "authz",
                    format!(
                        "BFLA privilege separation ({} {} as {low_role})",
                        op.method, full
                    ),
                    &op.method,
                    full,
                    "Call a privileged/admin route using a non-admin user token",
                    None,
                    "HTTP 401 or 403",
                    Some(401),
                    "critical",
                    low_role,
                    "openapi",
                );
                c.secured = Some(true);
                out.push(c);
                if out.len() >= cap {
                    return out;
                }
            }
        }
    }

    for r in d.routes.iter().filter(|r| {
        matches!(r.status_code, 401 | 403)
            && !r.catch_all
            && !matches!(r.source.as_str(), "probe" | "openapi")
            && is_privileged_path(&r.path)
            && !is_static_or_probe_path(&r.path)
    }) {
        let method = r.method.to_ascii_uppercase();
        if seen.insert((method.clone(), r.path.clone())) {
            let mut c = mk(
                "authz",
                format!(
                    "BFLA privilege separation ({method} {} as {low_role})",
                    r.path
                ),
                &method,
                r.path.clone(),
                "Access an admin/internal route with a non-privileged role credential",
                None,
                "HTTP 401 or 403",
                Some(401),
                "critical",
                low_role,
                "deterministic",
            );
            c.secured = Some(true);
            c.route_status = Some(r.status_code);
            out.push(c);
            if out.len() >= cap {
                return out;
            }
        }
    }
    out
}

fn path_bypass_cases(d: &Discovery, depth: Depth) -> Vec<PlannedCase> {
    let route_limit = match depth {
        Depth::Quick => 0,
        Depth::Standard => 1,
        Depth::Deep => 2,
    };
    if route_limit == 0 {
        return Vec::new();
    }
    let include_path_mutations = depth == Depth::Deep;
    let has_catch_all = d.routes.iter().any(|r| r.catch_all || r.is_spa_shell);
    let protected: Vec<(String, String, u16)> = d
        .routes
        .iter()
        .filter(|r| {
            matches!(r.status_code, 401 | 403)
                && !r.catch_all
                && !r.is_spa_shell
                && !matches!(r.source.as_str(), "probe" | "openapi")
                && !is_static_or_probe_path(&r.path)
                && r.path != "/"
                && !r.path.contains('?')
        })
        .take(route_limit)
        .map(|r| (r.method.to_ascii_uppercase(), r.path.clone(), r.status_code))
        .collect();

    let mut out = Vec::new();
    for (method, path, st) in protected {
        let mut ip_case = mk(
            "authz",
            format!("Trust-header X-Forwarded-For IP ACL bypass ({path})"),
            &method,
            path.clone(),
            "Send X-Forwarded-For and X-Real-IP loopback headers to test IP-trust ACL bypass",
            None,
            "HTTP 401 or 403",
            Some(401),
            "critical",
            "anon",
            "deterministic",
        );
        ip_case.secured = Some(true);
        ip_case.route_status = Some(st);
        ip_case.headers = vec![
            ("X-Forwarded-For".to_string(), "127.0.0.1".to_string()),
            ("X-Real-IP".to_string(), "127.0.0.1".to_string()),
        ];
        out.push(ip_case);

        if !include_path_mutations {
            continue;
        }

        let trimmed = path.trim_end_matches('/');
        let matrix_norm = format!("{trimmed}..;/");
        let slash_toggle = if path.ends_with('/') {
            trimmed.to_string()
        } else {
            format!("{trimmed}/")
        };
        let encoded_dot = format!("{trimmed}/%2e");
        let path_variants = [
            (
                format!("Reverse-proxy matrix-parameter ACL bypass ({path})"),
                matrix_norm,
            ),
            (format!("Trailing-slash ACL bypass ({path})"), slash_toggle),
            (format!("URL-encoded dot ACL bypass ({path})"), encoded_dot),
        ];

        for (title, comp) in path_variants {
            let mut c = mk(
                "authz",
                title,
                &method,
                comp,
                "Test whether reverse-proxy path normalization bypasses 401/403 ACL",
                None,
                "HTTP 401 or 403",
                Some(401),
                "critical",
                "anon",
                "deterministic",
            );
            c.secured = Some(true);
            c.route_status = Some(st);
            out.push(c);
        }

        if let Some(last) = trimmed.rsplit('/').next()
            && last.chars().any(|ch| ch.is_ascii_lowercase())
        {
            let prefix = &trimmed[..trimmed.len() - last.len()];
            let upper = format!("{prefix}{}", last.to_ascii_uppercase());
            let mut c = mk(
                "authz",
                format!("Case-folding ACL bypass ({path})"),
                &method,
                upper,
                "Test whether case-insensitive backend routing bypasses path ACL",
                None,
                "HTTP 401 or 403",
                Some(401),
                "critical",
                "anon",
                "deterministic",
            );
            c.secured = Some(true);
            c.route_status = Some(st);
            out.push(c);
        }

        if !has_catch_all {
            for hdr_name in ["X-Original-URL", "X-Rewrite-URL"] {
                let mut c = mk(
                    "authz",
                    format!("Reverse-proxy {hdr_name} rewrite bypass ({path})"),
                    &method,
                    "/__readyhai_nonexistent_override".into(),
                    "Send path override header against a nonexistent path to test proxy URL rewrite bypass",
                    None,
                    "HTTP 401, 403, or 404",
                    Some(401),
                    "critical",
                    "anon",
                    "deterministic",
                );
                c.secured = Some(true);
                c.route_status = Some(st);
                c.headers = vec![(hdr_name.into(), path.clone())];
                out.push(c);
            }
        }
    }
    out
}

/// Plan authentication, JWT, BFLA, and path-normalization bypass probes for a target.
pub fn plan_auth_attacks(d: &Discovery, creds: &Credentials, depth: Depth) -> Vec<PlannedCase> {
    if depth == Depth::Quick {
        return Vec::new();
    }
    let mut out = Vec::new();
    out.extend(jwt_cases(d, creds, depth));
    out.extend(bfla_cases(d, creds, depth));
    out.extend(path_bypass_cases(d, depth));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::budget::RunBudget;
    use crate::agent::discover::{Discovery, SpecDoc};
    use crate::agent::exec::{self, Auth, ExecOptions, execute_cases_gated};
    use crate::agent::types::{DiscoveredRoute, InputSurface};
    use crate::qa::plan::Op;
    use axum::extract::Request;
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::{Json, Router};
    use tokio::net::TcpListener;

    fn b64url_str(s: &str) -> String {
        b64url_encode(s.as_bytes())
    }

    fn make_hs256_sample() -> String {
        let hdr = b64url_str(r#"{"alg":"HS256","typ":"JWT"}"#);
        let pay = b64url_str(r#"{"sub":"42","role":"user","iat":1700000000}"#);
        format!("{hdr}.{pay}.real_hmac_signature_placeholder")
    }

    #[test]
    fn jwt_variants_include_alg_none_stripped_tampered_and_kid_without_repeating_original() {
        let orig = make_hs256_sample();
        let parsed = looks_like_jwt(&orig).expect("sample should parse as JWT");
        assert_eq!(parsed.0["alg"], "HS256");
        assert_eq!(parsed.1["role"], "user");

        let vars = jwt_tamper_variants(&orig);
        let kinds: Vec<&str> = vars.iter().map(|(k, _)| *k).collect();
        assert!(kinds.contains(&"alg_none"));
        assert!(kinds.contains(&"stripped_sig"));
        assert!(kinds.contains(&"tampered_claims_invalid_sig"));
        assert!(kinds.contains(&"kid_traversal"));
        for (_, v) in &vars {
            assert_ne!(
                v, &orig,
                "tampered variant must differ from original secret"
            );
            assert_eq!(
                v.split('.').count(),
                3,
                "must remain 3-part JWS compact shape"
            );
        }
        let (_, tampered) = vars
            .iter()
            .find(|(k, _)| *k == "tampered_claims_invalid_sig")
            .unwrap();
        let (_, pay) = looks_like_jwt(tampered).unwrap();
        assert_eq!(pay["role"], "admin");
    }

    #[test]
    fn non_jwt_opaque_tokens_plan_zero_jwt_cases() {
        let mut d = Discovery::default();
        d.routes.push(DiscoveredRoute {
            path: "/orders".into(),
            method: "GET".into(),
            status_code: 401,
            input_surface: InputSurface::None,
            ..Default::default()
        });
        let creds = Credentials::default().with("user", "alice-opaque-token");
        let cases = plan_auth_attacks(&d, &creds, Depth::Standard);
        assert!(
            !cases.iter().any(|c| c.role.as_deref() == Some("raw_jwt")),
            "opaque tokens must not emit JWT tampering cases: {cases:?}"
        );
    }

    #[test]
    fn plans_jwt_bfla_and_path_bypass_for_secured_and_privileged_routes() {
        let mut d = Discovery::default();
        d.routes.push(DiscoveredRoute {
            path: "/admin/stats".into(),
            method: "GET".into(),
            status_code: 403,
            input_surface: InputSurface::None,
            ..Default::default()
        });
        d.spec = Some(SpecDoc {
            base_path: "".into(),
            source: "openapi.json".into(),
            ops: vec![Op {
                method: "GET".into(),
                path: "/admin/stats".into(),
                operation_id: None,
                secured: true,
                has_body: false,
            }],
            doc: serde_json::json!({}),
        });
        let jwt = make_hs256_sample();
        let creds = Credentials::default()
            .with("alice", &jwt)
            .with("admin", "admin-token");

        let quick = plan_auth_attacks(&d, &creds, Depth::Quick);
        assert!(quick.is_empty(), "quick profile stays minimal");

        let std_cases = plan_auth_attacks(&d, &creds, Depth::Standard);
        assert!(
            std_cases
                .iter()
                .any(|c| c.role.as_deref() == Some("raw_jwt")),
            "expected JWT tampering cases in Standard: {std_cases:?}"
        );
        assert!(
            std_cases
                .iter()
                .any(|c| c.role.as_deref() == Some("alice") && c.component == "/admin/stats"),
            "expected BFLA cross-role check for alice on /admin/stats: {std_cases:?}"
        );
        assert!(
            std_cases.iter().any(|c| {
                c.headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("X-Forwarded-For"))
            }),
            "expected X-Forwarded-For bypass probe in Standard: {std_cases:?}"
        );

        let deep_cases = plan_auth_attacks(&d, &creds, Depth::Deep);
        assert!(
            deep_cases
                .iter()
                .any(|c| c.component == "/admin/stats..;/" || c.component == "/admin/stats/%2e"),
            "expected path normalization probes in Deep: {deep_cases:?}"
        );
    }

    #[test]
    fn executes_and_detects_jwt_alg_none_path_bypass_bfla_and_clean_server_no_fp() {
        let jwt = make_hs256_sample();
        let valid_alice = jwt.clone();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let url = rt.block_on(async move {
            let app = Router::new()
                .route("/", get(|| async { (StatusCode::OK, "home") }))
                .route(
                    "/admin/panel",
                    get(move |req: Request| {
                        let valid_alice = valid_alice.clone();
                        async move {
                            let auth = req
                                .headers()
                                .get("authorization")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("");
                            if auth == format!("Bearer {valid_alice}") {
                                // Bug 3 (BFLA): authenticated non-admin gets 200 on /admin/panel
                                return (
                                    StatusCode::OK,
                                    Json(serde_json::json!({"admin": true, "via": "bfla"})),
                                );
                            }
                            if let Some(tok) = auth.strip_prefix("Bearer ")
                                && let Some((hdr, pay)) = looks_like_jwt(tok)
                                && hdr["alg"] == "none"
                                && pay["role"] == "user"
                            {
                                // Bug 1: accepts alg=none without checking signature
                                return (
                                    StatusCode::OK,
                                    Json(serde_json::json!({"admin": true, "via": "alg_none"})),
                                );
                            }
                            (
                                StatusCode::UNAUTHORIZED,
                                Json(serde_json::json!({"error": "denied"})),
                            )
                        }
                    }),
                )
                .route(
                    "/admin/panel..;/",
                    get(|| async {
                        // Bug 2: proxy checked exact /admin/panel, backend serves /admin/panel..;/
                        (
                            StatusCode::OK,
                            Json(serde_json::json!({"admin": true, "via": "matrix_norm"})),
                        )
                    }),
                );
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            format!("http://{addr}")
        });

        let mut d = Discovery::default();
        d.routes.push(DiscoveredRoute {
            path: "/admin/panel".into(),
            method: "GET".into(),
            status_code: 401,
            input_surface: InputSurface::None,
            ..Default::default()
        });
        let creds = Credentials::default().with("alice", &jwt);
        let mut cases = plan_auth_attacks(&d, &creds, Depth::Deep);
        for (i, c) in cases.iter_mut().enumerate() {
            c.id = format!("AUTH-{:03}", i + 1);
            assert_ne!(
                exec::auth_for(c),
                Auth::Role("raw_jwt".into()),
                "raw_jwt must map to Auth::None"
            );
        }
        let opts = ExecOptions {
            credentials: creds,
            ..Default::default()
        };
        let mut budget = RunBudget::new(100, 100, std::time::Duration::from_secs(30), 50.0);
        let results = execute_cases_gated(&cases, &url, &opts, &mut budget, None);
        assert!(
            results.iter().any(|r| r.status == "FAIL"
                && r.component == "/admin/panel"
                && r.title.contains("alg=none")),
            "expected FAIL for JWT alg=none bypass: {results:?}"
        );
        assert!(
            results.iter().any(|r| r.status == "FAIL"
                && r.component == "/admin/panel"
                && r.title.contains("BFLA")),
            "expected FAIL for BFLA non-admin bypass: {results:?}"
        );
        assert!(
            results
                .iter()
                .any(|r| r.status == "FAIL" && r.component == "/admin/panel..;/"),
            "expected FAIL for path normalization bypass: {results:?}"
        );
        // X-Original-URL against /__readyhai_nonexistent_override got 404 -> must NEVER fail!
        assert!(
            !results
                .iter()
                .any(|r| r.status == "FAIL" && r.component == "/__readyhai_nonexistent_override"),
            "clean 404 override target must not false-positive: {results:?}"
        );
    }
}
