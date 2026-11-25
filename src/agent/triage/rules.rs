//! Deterministic severity rule table and failure classification metadata.

use super::super::oracle::{Severity, Technique};

/// The single severity rule table. Every failed check in the agent (oracle::judge, the stateful
/// and burst oracles, mutation sub-cases) takes its severity from here, so no executor decides
/// "how bad" on its own. `tech` only matters for classes whose impact depends on the input class.
pub fn severity_for(code: &str, tech: Technique) -> Severity {
    match code {
        // access to data or files the caller must not see
        "authz"
        | "sensitive_exposure"
        | "path_traversal"
        | "oast_callback"
        | "blind_boolean_injection"
        | "blind_time_injection"
        | "ssti" => Severity::Critical,
        // exploitable behaviour, but needs a precondition or a second step
        "race_condition"
        | "mass_assignment"
        | "business_logic"
        | "error_disclosure"
        | "injection_reflection"
        | "cors_credentialed"
        | "open_redirect"
        | "excessive_data_exposure" => Severity::High,
        "server_error" => match tech {
            Technique::Injection | Technique::Authz => Severity::High,
            _ => Severity::Medium,
        },
        // spec / hygiene deviations
        "expected_redirect" | "content_type" => Severity::Low,
        "cors" | "expected_status" | "contract_fields" | "graphql_introspection" => {
            Severity::Medium
        }
        // the QA engine's own ratings (qa.api.slow_response P3, qa.api.undocumented_status P4)
        "slow_response" | "undocumented_status" => Severity::Low,
        // a DELETE that answers 2xx and leaves the resource in place: functional, not a security issue
        "delete_not_effective" => Severity::Medium,
        _ => Severity::Medium,
    }
}

pub(crate) fn class_meta(
    code: &str,
    technique: &str,
) -> (&'static str, &'static str, &'static str) {
    // (title template, owasp category, recommended fix)
    match code {
        "authz" => (
            "Access control bypass",
            "OWASP API5:2023 Broken Function Level Authorization",
            "Enforce authentication and authorization in middleware for every route, deny by default, and reject unsigned or forged tokens.",
        ),
        "path_traversal" => (
            "Path traversal reads server files",
            "OWASP API8:2023 Security Misconfiguration (CWE-22)",
            "Resolve user-supplied paths against a fixed base directory, reject `..` and encoded variants after normalisation, and never pass request input to filesystem calls directly.",
        ),
        "mass_assignment" => (
            "Mass assignment of privileged attributes",
            "OWASP API3:2023 Broken Object Property Level Authorization",
            "Bind request bodies to an explicit allow-list of writable fields; never accept role, admin or permission attributes from the client.",
        ),
        "cors" | "cors_credentialed" => (
            "Permissive CORS policy",
            "OWASP API8:2023 Security Misconfiguration",
            "Return Access-Control-Allow-Origin only for an explicit allow-list of origins; never reflect the request Origin, and never combine a wildcard or reflected origin with credentials.",
        ),
        "race_condition" => (
            "Race condition under concurrent requests",
            "OWASP API6:2023 Unrestricted Access to Sensitive Business Flows",
            "Make the state change atomic (database transaction with a uniqueness constraint, row lock or compare-and-swap) and generate identifiers server-side under that lock.",
        ),
        "sensitive_exposure" => (
            "Sensitive file publicly readable",
            "OWASP API8:2023 Security Misconfiguration",
            "Remove the file from the web root and deny dotfiles/backups at the web server; rotate every secret it contained.",
        ),
        "error_disclosure" => (
            "Internal error details disclosed",
            "OWASP API8:2023 Security Misconfiguration",
            "Return a generic error body, log the details server-side, and disable debug/stack-trace output in production.",
        ),
        "injection_reflection" => (
            "Injected markup reflected unescaped",
            "OWASP A03:2021 Injection (XSS)",
            "Contextually HTML-encode untrusted input on output and add a Content-Security-Policy.",
        ),
        "dom_xss" => (
            "DOM-based Cross-Site Scripting (DOM XSS)",
            "OWASP A03:2021 Injection (DOM XSS)",
            "Use safe DOM text APIs (textContent/innerText) or a strict HTML sanitizer (e.g., DOMPurify) instead of sinking location, URLSearchParams, or postMessage data into innerHTML/document.write/eval.",
        ),
        "stored_xss" => (
            "Stored Cross-Site Scripting (Stored XSS)",
            "OWASP A03:2021 Injection (Stored XSS)",
            "Contextually HTML-encode all user-supplied persisted content on render and enforce a restrictive Content-Security-Policy.",
        ),
        "client_secret_leak" => (
            "Client-side token or secret exposed in browser storage",
            "OWASP A02:2021 Cryptographic Failures / A04:2021 Insecure Design",
            "Store session tokens only in HttpOnly, Secure, SameSite cookies and never serialize secrets into localStorage, sessionStorage, or SSR state.",
        ),
        "sourcemap_exposure" => (
            "JavaScript source map publicly accessible",
            "OWASP A05:2021 Security Misconfiguration",
            "Remove *.js.map files from public web roots or restrict access to internal symbol servers.",
        ),
        "clickjacking" => (
            "Clickjacking via missing anti-framing protections",
            "OWASP A05:2021 Security Misconfiguration",
            "Set Content-Security-Policy frame-ancestors 'none' (or explicit allow-listed origins) and X-Frame-Options.",
        ),
        "cookie_hygiene" => (
            "Session cookie missing HttpOnly or Secure attributes",
            "OWASP A05:2021 Security Misconfiguration",
            "Set HttpOnly, Secure, and SameSite=Lax/Strict on every authentication/session cookie.",
        ),
        "oast_callback" => (
            "Out-of-band server-side callback (SSRF / blind RCE)",
            "OWASP A10:2021 Server-Side Request Forgery (SSRF) / API7:2023",
            "Validate user-supplied URLs/hosts against an explicit domain/IP allow-list, block loopback and link-local metadata ranges, and never invoke shell commands or external fetchers from untrusted input.",
        ),
        "blind_boolean_injection" => (
            "Blind injection via boolean differential response",
            "OWASP A03:2021 Injection",
            "Use parameterized queries / prepared statements for every dynamic parameter and reject malformed filter expressions.",
        ),
        "blind_time_injection" => (
            "Blind injection via measurable execution delay",
            "OWASP A03:2021 Injection",
            "Use parameterized queries / prepared statements and strict allow-listed APIs instead of dynamic SQL or OS command execution.",
        ),
        "ssti" => (
            "Server-Side Template Injection (SSTI)",
            "OWASP A03:2021 Injection",
            "Never pass untrusted input into a template source string; pass user data strictly as template context variables with auto-escaping enabled.",
        ),
        "open_redirect" => (
            "Open redirect to untrusted external origin",
            "OWASP A01:2021 Broken Access Control (CWE-601)",
            "Restrict redirect targets to relative paths starting with `/` (and not `//` or `/\\`) or an explicit allow-list of trusted hostnames.",
        ),
        "excessive_data_exposure" => (
            "Sensitive credentials or PII exposed in API response",
            "OWASP API3:2023 Broken Object Property Level Authorization",
            "Return explicit response DTOs that exclude password hashes, salts, private keys, TOTP secrets, and payment/PII attributes.",
        ),
        "business_logic" => (
            "Business-logic or workflow validation bypass",
            "OWASP A04:2021 Insecure Design / API6:2023",
            "Enforce server-side state transitions, workflow prerequisites, and positive/bounded business quantities at the transactional domain layer.",
        ),
        "graphql_introspection" => (
            "GraphQL schema introspection enabled",
            "OWASP API8:2023 Security Misconfiguration / API9:2023",
            "Disable GraphQL __schema and __type introspection queries in non-local/production deployments.",
        ),
        "server_error" if technique == "injection" => (
            "Server error after injection-style input",
            "OWASP A03:2021 Injection",
            "Use parameterised queries / strict input parsing so hostile input is rejected with a 4xx instead of reaching the failing code path.",
        ),
        "server_error" => (
            "Unhandled server error on invalid input",
            "OWASP API4:2023 Unrestricted Resource Consumption",
            "Validate input size and shape at the edge and return 4xx for invalid or oversized input; handle the failing code path.",
        ),
        "contract_fields" => (
            "Response violates the API contract",
            "OWASP API9:2023 Improper Inventory Management",
            "Make the implementation return every field the spec marks required, or correct the spec.",
        ),
        "undocumented_status" => (
            "Response status is not documented",
            "OWASP API9:2023 Improper Inventory Management",
            "Document the status in the OpenAPI responses of the operation, or change the implementation to answer with a documented one.",
        ),
        "slow_response" => (
            "Slow response",
            "OWASP API4:2023 Unrestricted Resource Consumption",
            "Profile the endpoint; add caching, pagination or asynchronous processing so its p95 stays under the limit.",
        ),
        "content_type" => (
            "Unexpected response content type",
            "OWASP API8:2023 Security Misconfiguration",
            "Return the documented Content-Type for the operation.",
        ),
        "delete_not_effective" => (
            "DELETE reports success but the resource remains",
            "Quality: resource lifecycle (functional defect, not an OWASP API category)",
            "Make DELETE remove the record (or soft-delete it so that reads answer 404/410) and answer 2xx only once it is actually gone.",
        ),
        _ => (
            "Unexpected response status",
            "OWASP API8:2023 Security Misconfiguration",
            "Align the endpoint's status codes with the documented/expected behaviour.",
        ),
    }
}
