//! Remediation guidance for a triaged defect.
//!
//! What this is NOT: a patch. The agent only ever saw HTTP responses; it never saw the target's
//! source, so it cannot know a file name, a line number, a framework or a data model. Earlier
//! builds printed unified diffs with invented paths and hunks; those were fabrications and are gone.
//!
//! What this is: short, generic, clearly labelled example guidance ("example — adapt to your code")
//! keyed by the DEFECT CLASS, which the deterministic triager decides from the failed oracle check.
//! The class is read from the fixed title template and the fixed OWASP label triage writes, never
//! from substrings of text the target controls (route paths, response excerpts, failure reasons).
//! A 5xx is a server-error class (validate input, handle the failing path); it never becomes a
//! rate-limit recommendation.
//!
//! Reproduction scripts embed the exact curl the run sent. Without one they use a `BASE_URL`
//! placeholder for the real target origin; they never assume a local address.

use super::types::TriagedDefect;

/// Label every piece of guidance carries.
pub const EXAMPLE_LABEL: &str = "example — adapt to your code";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefectClass {
    AccessControl,
    SensitiveExposure,
    ErrorDisclosure,
    ReflectedInjection,
    InjectionServerError,
    ServerError,
    Contract,
    ContentType,
    Generic,
}

impl DefectClass {
    pub fn label(self) -> &'static str {
        match self {
            DefectClass::AccessControl => "access control",
            DefectClass::SensitiveExposure => "sensitive exposure",
            DefectClass::ErrorDisclosure => "error disclosure",
            DefectClass::ReflectedInjection => "reflected injection (XSS)",
            DefectClass::InjectionServerError => "server error on injection-style input",
            DefectClass::ServerError => "unhandled server error",
            DefectClass::Contract => "API contract violation",
            DefectClass::ContentType => "unexpected content type",
            DefectClass::Generic => "unexpected response",
        }
    }
}

/// The defect class, from the deterministic parts of the defect only: the fixed title template
/// (the text before the first ": " -- everything after it is `METHOD route`, target-controlled and
/// never read) and, failing that, the fixed OWASP label.
pub fn classify(d: &TriagedDefect) -> DefectClass {
    let head = d.title.split(": ").next().unwrap_or("");
    match head {
        "Access control bypass" | "Forged token accepted" => return DefectClass::AccessControl,
        "Sensitive file publicly readable" => return DefectClass::SensitiveExposure,
        "Internal error details disclosed" => return DefectClass::ErrorDisclosure,
        "Injected markup reflected unescaped" => return DefectClass::ReflectedInjection,
        "Server error after injection-style input" => return DefectClass::InjectionServerError,
        "Unhandled server error on invalid input" => return DefectClass::ServerError,
        "Response violates the API contract" => return DefectClass::Contract,
        "Unexpected response content type" => return DefectClass::ContentType,
        "Unexpected response status" => return DefectClass::Generic,
        _ => {}
    }
    let o = d.owasp_category.as_str();
    if o.starts_with("OWASP API1:2023") || o.starts_with("OWASP API5:2023") {
        DefectClass::AccessControl
    } else if o.starts_with("OWASP A03:2021 Injection (XSS)") {
        DefectClass::ReflectedInjection
    } else if o.starts_with("OWASP A03:2021") {
        DefectClass::InjectionServerError
    } else if o.starts_with("OWASP API4:2023") {
        DefectClass::ServerError
    } else if o.starts_with("OWASP API9:2023") {
        DefectClass::Contract
    } else {
        DefectClass::Generic
    }
}

/// A path safe to print and to put inside single quotes: no query, no whitespace/control
/// characters, no quote characters, at most 120 chars. Anything else becomes `_`.
fn display_path(component: &str) -> String {
    let p = component.split(['?', '#']).next().unwrap_or("");
    let mut s: String = p
        .chars()
        .take(120)
        .map(|c| {
            if c.is_ascii_alphanumeric() || "/_-.~%:@+,;=!*(){}".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    if !s.starts_with('/') {
        s.insert(0, '/');
    }
    s
}

fn safe_method(method: &str) -> String {
    let m = method.trim().to_ascii_uppercase();
    if !m.is_empty() && m.len() <= 8 && m.chars().all(|c| c.is_ascii_alphabetic()) {
        m
    } else {
        "GET".into()
    }
}

/// The curl the run sent, if it is a single plain line we are willing to put in a script.
fn usable_curl(sample: &str) -> Option<&str> {
    let s = sample.trim();
    (s.starts_with("curl ") && s.len() <= 4000 && !s.chars().any(|c| c.is_control())).then_some(s)
}

fn script(
    defect: &TriagedDefect,
    class: DefectClass,
    method: &str,
    path: &str,
    curl: &str,
    note: &str,
) -> String {
    let id: String = defect
        .id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(24)
        .collect();
    let request = match usable_curl(curl) {
        Some(c) => format!("# the exact request the run sent\n{c}"),
        None => format!(
            ": \"${{BASE_URL:?set BASE_URL to the target origin the run used, e.g. https://app.example.test}}\"\ncurl -g -sS -i -X {} \"$BASE_URL\"'{}'",
            safe_method(method),
            path
        ),
    };
    format!(
        "#!/usr/bin/env bash\n# Reproduction for {id} ({}). {note}\n# Run it only against a target you are allowed to test.\nset -euo pipefail\n{request}\n",
        class.label()
    )
}

struct Guidance {
    explanation: &'static str,
    snippet: &'static str,
    expect: &'static str,
}

fn guidance(class: DefectClass) -> Guidance {
    match class {
        DefectClass::AccessControl => Guidance {
            explanation: "The run observed the request being served although it carried no valid credentials, a forged token, or the wrong role. Authentication and authorization should be enforced centrally and deny by default: verify the token (signature, issuer, audience, expiry), then check the caller's right to this action and to this specific object (owner / tenant) before any data is read or changed.",
            snippet: "def guard(request):\n    identity = verify_token(request.headers.get(\"Authorization\"))   # signature, issuer, audience, expiry\n    if identity is None:\n        return respond(401)                                        # unauthenticated or forged\n    if not identity.is_allowed(request.action, request.object):    # role AND ownership/tenant\n        return respond(403)\n    return handle(request)",
            expect: "Expected 401 or 403; the run saw access granted.",
        },
        DefectClass::SensitiveExposure => Guidance {
            explanation: "A file that normally holds configuration, credentials or repository metadata answered with content. Remove it from the document root, deny dotfiles, backups and VCS folders at the web server or reverse proxy, and rotate every secret it may have contained.",
            snippet: "# web server / reverse proxy: deny hidden files and backups by default\ndeny requests matching  /\\.(?!well-known/)  and  *.bak, *.old, *.swp, *~\nanswer 404 (not 403, so the file's existence is not confirmed)\n# then: rotate any secret that was readable",
            expect: "Expected 404 (or 403); the run received file content.",
        },
        DefectClass::ErrorDisclosure => Guidance {
            explanation: "A response exposed internal details such as a stack trace, a SQL fragment or a file path. Return a generic error body to the client, keep the details in server-side logs keyed by a request id, and turn debug output off in this environment.",
            snippet: "on unhandled error:\n    log.error(error, request_id=request.id)          # details stay on the server\n    return respond(500, {\"error\": \"internal error\", \"request_id\": request.id})\n# framework setting: debug / verbose errors = off outside local development",
            expect: "Expected a generic error body; the response contained internal details.",
        },
        DefectClass::ReflectedInjection => Guidance {
            explanation: "Injected markup came back in the response unescaped, which is the precondition for reflected cross-site scripting. Encode untrusted values for the context they are written into (HTML body, attribute, JavaScript, URL), prefer a templating layer that escapes by default, and add a Content-Security-Policy as a second layer.",
            snippet: "output = html_escape(untrusted_value)           # context-aware encoding at the point of output\n# response header (defence in depth):\n# Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
            expect: "Expected the payload to be encoded or rejected; it was reflected verbatim.",
        },
        DefectClass::InjectionServerError => Guidance {
            explanation: "Injection-style input made the server fail (5xx). Hostile input should be rejected with a 4xx before it reaches the failing code path: validate type, length and format at the edge, and keep untrusted values out of query strings, commands and templates by using parameterised queries and strict parsers.",
            snippet: "params = parse_and_validate(request, schema)      # reject bad type / length / format with 400 or 422\nrows = db.query(\"... WHERE name = :name\", {\"name\": params.name})   # bound parameter, never string-built SQL",
            expect: "Expected a 4xx rejection; the server answered 5xx.",
        },
        DefectClass::ServerError => Guidance {
            explanation: "Invalid or unexpected input produced an unhandled server error (5xx). That is an input-validation and error-handling gap, not a rate-limiting one: validate the shape and size of the input at the edge, answer 4xx for what is invalid, and handle the failing code path so it cannot surface as a crash.",
            snippet: "params = parse_and_validate(request, schema)      # 400 / 413 / 422 for invalid or oversized input\ntry:\n    result = handle(params)\nexcept ExpectedFailure as e:\n    return respond(e.status, e.public_message)   # a client-side problem is a 4xx\n# unexpected errors: log with a request id, return a generic 500",
            expect: "Expected a 4xx (or a handled response); the server answered 5xx.",
        },
        DefectClass::Contract => Guidance {
            explanation: "The response did not contain every field the API description marks as required. Either make the implementation return the documented fields, or correct the description if the description is what is wrong; then check the response in a contract test.",
            snippet: "response = serialize(resource, fields=REQUIRED_FIELDS_FROM_SPEC)\n# contract test: assert every required field of the spec is present for this operation",
            expect: "Expected every required response field to be present.",
        },
        DefectClass::ContentType => Guidance {
            explanation: "The response used a different Content-Type than the API description documents. Return the documented media type for this operation, and keep the description and the implementation in step.",
            snippet: "return respond(200, body, content_type=\"<media type from the spec>\")",
            expect: "Expected the documented Content-Type.",
        },
        DefectClass::Generic => Guidance {
            explanation: "The endpoint answered with a status other than the one expected for this case. Decide which side is right: align the endpoint's status codes with the documented behaviour, or update the expectation if the endpoint is correct.",
            snippet: "# compare the observed status with the documented one for this operation,\n# then change the handler (or the documentation) so they agree",
            expect: "The observed status differed from the expected one.",
        },
    }
}

/// Generic, labelled guidance for a triaged defect: (example snippet, explanation, reproduction
/// script). Nothing here names a file of the target, a line, or a framework.
pub fn synthesize_remediation(
    defect: &TriagedDefect,
    component: &str,
    method: &str,
    sample_curl: &str,
) -> (String, String, String) {
    let class = classify(defect);
    let g = guidance(class);
    let path = display_path(component);
    let m = safe_method(method);

    let snippet = format!(
        "# {EXAMPLE_LABEL}\n# Illustrative pseudocode for the \"{}\" class. It is not a patch: the agent saw HTTP\n# responses only and never your source code, so no file, line or framework is assumed.\n{}",
        class.label(),
        g.snippet
    );
    let explanation = format!(
        "Guidance ({EXAMPLE_LABEL}) for {} on {m} {path}. {} Generic advice for this class of defect; check it against how your service is built.",
        class.label(),
        g.explanation
    );
    let repro = script(defect, class, &m, &path, sample_curl, g.expect);
    (snippet, explanation, repro)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defect(id: &str, title: &str, owasp: &str, cause: &str) -> TriagedDefect {
        TriagedDefect {
            id: id.into(),
            title: title.into(),
            severity: "high".into(),
            priority: "P1".into(),
            component: "/api/orders/1".into(),
            root_cause_hypothesis: cause.into(),
            blast_radius: "service".into(),
            owasp_category: owasp.into(),
            recommended_fix: "fix it".into(),
            reproduction: "curl http://test".into(),
            case_ids: vec!["TC-001".into()],
            evidence_files: vec![],
            ai_note: None,
            remediation_patch: None,
            remediation_explanation: None,
            reproduction_script: None,
            ..Default::default()
        }
    }

    const ALL: [(&str, &str); 9] = [
        (
            "Access control bypass: GET /a",
            "OWASP API5:2023 Broken Function Level Authorization",
        ),
        (
            "Sensitive file publicly readable: GET /.env",
            "OWASP API8:2023 Security Misconfiguration",
        ),
        (
            "Internal error details disclosed: GET /a",
            "OWASP API8:2023 Security Misconfiguration",
        ),
        (
            "Injected markup reflected unescaped: GET /a",
            "OWASP A03:2021 Injection (XSS)",
        ),
        (
            "Server error after injection-style input: GET /a",
            "OWASP A03:2021 Injection",
        ),
        (
            "Unhandled server error on invalid input: POST /a",
            "OWASP API4:2023 Unrestricted Resource Consumption",
        ),
        (
            "Response violates the API contract: GET /a",
            "OWASP API9:2023 Improper Inventory Management",
        ),
        (
            "Unexpected response content type: GET /a",
            "OWASP API8:2023 Security Misconfiguration",
        ),
        (
            "Unexpected response status: GET /a",
            "OWASP API8:2023 Security Misconfiguration",
        ),
    ];

    #[test]
    fn no_fabricated_diffs_paths_or_local_addresses_for_any_class() {
        for (i, (title, owasp)) in ALL.iter().enumerate() {
            let d = defect(&format!("DEF-{i:03}"), title, owasp, "Observed: x");
            let (patch, exp, script) = synthesize_remediation(&d, "/api/orders/1", "GET", "");
            for text in [&patch, &exp, &script] {
                for bad in [
                    "--- a/",
                    "+++ b/",
                    "@@ ",
                    "localhost:8000",
                    "src/",
                    ".py",
                    ".conf",
                ] {
                    assert!(!text.contains(bad), "{title}: '{bad}' in {text}");
                }
                assert!(
                    !text
                        .lines()
                        .any(|l| l.starts_with('+') || l.starts_with('-')),
                    "{title}: a diff-looking line in {text}"
                );
            }
            assert!(
                patch.contains(EXAMPLE_LABEL) && exp.contains(EXAMPLE_LABEL),
                "{title}"
            );
            assert!(
                script.contains("BASE_URL"),
                "{title}: placeholder, not a hard-coded host"
            );
        }
    }

    #[test]
    fn a_5xx_never_maps_to_a_rate_limit_patch() {
        // the server-error classes, with target-controlled text that screams "rate limit"
        let d = defect(
            "DEF-001",
            "Unhandled server error on invalid input: POST /ratelimit-burst",
            "OWASP API4:2023 Unrestricted Resource Consumption",
            "Observed: HTTP 429 500 too many requests rate limit race idor burst",
        );
        assert_eq!(classify(&d), DefectClass::ServerError);
        let (patch, exp, _) = synthesize_remediation(&d, "/ratelimit-burst", "POST", "");
        let all = format!("{patch}\n{exp}").to_ascii_lowercase();
        assert!(
            !all.contains("429") && !all.contains("rate limit") && !all.contains("sliding window"),
            "{all}"
        );
        assert!(all.contains("validate") && all.contains("5xx"), "{all}");
        // the OWASP API4 label alone (title missing) is still a server error, not rate limiting
        let d2 = defect(
            "DEF-002",
            "",
            "OWASP API4:2023 Unrestricted Resource Consumption",
            "",
        );
        assert_eq!(classify(&d2), DefectClass::ServerError);
    }

    #[test]
    fn class_comes_from_the_template_not_from_target_controlled_text() {
        // the route and the failure reason try to steer the class toward BOLA / SQLi / XSS / TOCTOU
        let d = defect(
            "DEF-003",
            "Unexpected response status: GET /idor-bola-sql-xss-toctou-tenant",
            "OWASP API8:2023 Security Misconfiguration",
            "Observed: BOLA cross-tenant IDOR SQL injection <script> TOCTOU race burst",
        );
        assert_eq!(classify(&d), DefectClass::Generic);
        let (patch, exp, _) = synthesize_remediation(
            &d,
            "/idor-bola-sql-xss-toctou-tenant",
            "GET",
            "' OR '1'='1 <script>",
        );
        for k in ["tenant_id", "FOR UPDATE", "html.escape", "parameterized"] {
            assert!(!patch.contains(k) && !exp.contains(k), "{k}");
        }
        assert_eq!(
            classify(&defect(
                "D",
                "Forged token accepted: GET /x",
                "OWASP API5:2023 x",
                ""
            )),
            DefectClass::AccessControl
        );
    }

    #[test]
    fn repro_script_uses_the_real_curl_or_a_base_url_placeholder_and_cannot_be_injected() {
        let d = defect(
            "DEF-004",
            "Access control bypass: GET /admin",
            "OWASP API5:2023 x",
            "",
        );
        let real = "curl -sS -i -X GET 'https://qa.example.test/admin'";
        let (_, _, s) = synthesize_remediation(&d, "/admin", "GET", real);
        assert!(
            s.contains(real) && !s.contains("BASE_URL") && !s.contains("localhost"),
            "{s}"
        );
        // a curl line with a newline (or anything that is not one plain curl line) is not embedded
        let (_, _, s) = synthesize_remediation(&d, "/admin", "GET", "curl x\nrm -rf /");
        assert!(!s.contains("rm -rf") && s.contains("BASE_URL"), "{s}");
        // a hostile route: quotes, command substitution, newlines and spaces cannot leave the quotes
        let (_, exp, s) = synthesize_remediation(
            &d,
            "/a'; touch /tmp/pwn; echo '$(id)`id`\n x",
            "GET; rm",
            "",
        );
        let url_line = s.lines().find(|l| l.starts_with("curl")).unwrap();
        assert!(
            !url_line.contains('`')
                && !url_line.contains("$(")
                && url_line.matches('\'').count() == 2,
            "{url_line}"
        );
        assert!(url_line.contains("-X GET"), "{url_line}");
        assert!(
            !exp.contains('\n') && !exp.contains('`') && !exp.contains('$'),
            "{exp}"
        );
    }
}
