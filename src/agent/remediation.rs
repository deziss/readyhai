//! Auto-Remediation & Patch Engine.
//!
//! Generates actionable git unified diff patches, architectural explanations, and minimal reproduction
//! scripts customized to the defect class (OWASP API1 BOLA/IDOR, API5 BFLA, SQLi, XSS, TOCTOU, rate limiting).

use super::types::TriagedDefect;

/// Synthesizes a unified diff patch, fix explanation, and reproduction script for a triaged defect.
pub fn synthesize_remediation(
    defect: &TriagedDefect,
    component: &str,
    method: &str,
    sample_curl: &str,
) -> (String, String, String) {
    let method_upper = method.to_ascii_uppercase();
    let method_lower = method.to_ascii_lowercase();
    let norm_comp = if component.starts_with('/') {
        component.to_string()
    } else {
        format!("/{component}")
    };

    let title_lower = defect.title.to_ascii_lowercase();
    let owasp = &defect.owasp_category;
    let root_cause = defect.root_cause_hypothesis.to_ascii_lowercase();

    // 1. OWASP API1:2023 BOLA / IDOR (Broken Object Level Authorization)
    if owasp.contains("API1")
        || title_lower.contains("bola")
        || title_lower.contains("idor")
        || title_lower.contains("tenant isolation")
        || root_cause.contains("bola")
        || root_cause.contains("tenant")
    {
        let patch = format!(
            r#"--- a/src/api/handlers.py
+++ b/src/api/handlers.py
@@ -32,8 +32,12 @@
 @router.{method_lower}("{norm_comp}")
 async def handle_resource(resource_id: str, current_user: CurrentUser = Depends(get_current_user)):
-    # Vulnerable: fetches object without verifying user/tenant ownership
-    resource = await db.fetch_one("SELECT * FROM resources WHERE id = :id", {{"id": resource_id}})
+    # Mitigated: enforce strict tenant boundary and object ownership (BOLA/IDOR prevention)
+    resource = await db.fetch_one(
+        "SELECT * FROM resources WHERE id = :id AND tenant_id = :tenant_id",
+        {{"id": resource_id, "tenant_id": current_user.tenant_id}}
+    )
     if not resource:
-        raise HTTPException(status_code=404, detail="Resource not found")
+        raise HTTPException(status_code=404, detail="Resource not found or access denied")
     return resource"#
        );

        let explanation = format!(
            "Broken Object Level Authorization (BOLA/IDOR) on {method_upper} {norm_comp}. \
             The endpoint queried or mutated records by raw identifier without scoping to the authenticated caller's tenant. \
             Enforce ownership checks (`tenant_id = current_user.tenant_id`) at the data access layer or middleware so cross-tenant queries return 404/403."
        );

        let repro = format!(
            r#"#!/usr/bin/env python3
"""Reproduction script for BOLA defect: {defect_id}"""
import requests

TARGET = "http://localhost:8000"

def test_bola():
    alice_headers = {{"Authorization": "Bearer token-alice"}}
    bob_headers = {{"Authorization": "Bearer token-bob"}}

    # Step 1: Alice creates or owns an object
    print("[1] Alice creating private resource on {norm_comp}...")
    create_res = requests.post(f"{{TARGET}}{norm_comp}", json={{"title": "Alice Private Data"}}, headers=alice_headers)
    print(f"    Alice creation status: {{create_res.status_code}}")
    resource_id = create_res.json().get("id", "1")

    # Step 2: Bob attempts to read/mutate Alice's object
    print(f"[2] Bob accessing Alice's resource: {norm_comp}/{{resource_id}}...")
    access_res = requests.get(f"{{TARGET}}{norm_comp}/{{resource_id}}", headers=bob_headers)
    print(f"    Bob access status: {{access_res.status_code}}")

    if access_res.status_code in [200, 204]:
        print("[FAIL] BOLA Confirmed: Bob accessed Alice's private resource!")
    else:
        print("[PASS] Access denied correctly (HTTP 403/404).")

if __name__ == "__main__":
    test_bola()
"#,
            defect_id = defect.id,
            norm_comp = norm_comp
        );

        return (patch, explanation, repro);
    }

    // 2. OWASP API5:2023 BFLA (Broken Function Level Authorization / Forged Token / Unauthenticated)
    if owasp.contains("API5")
        || title_lower.contains("access control")
        || title_lower.contains("forged")
        || title_lower.contains("unauth")
    {
        let patch = format!(
            r#"--- a/src/middleware/auth.py
+++ b/src/middleware/auth.py
@@ -14,6 +14,13 @@
 async def auth_guard(request: Request, call_next):
+    # Enforce authentication & cryptographic signature validation on protected endpoints
+    auth_header = request.headers.get("Authorization")
+    if not auth_header or not auth_header.startswith("Bearer "):
+        return JSONResponse(status_code=401, content={{"error": "Unauthorized: missing bearer token"}})
+    
+    token = auth_header.split(" ", 1)[1]
+    if not verify_jwt_signature(token, expected_issuer="ReadyHaiAuth"):
+        return JSONResponse(status_code=401, content={{"error": "Unauthorized: invalid or forged token"}})
     return await call_next(request)"#
        );

        let explanation = format!(
            "Broken Function Level Authorization / Missing Authentication on {method_upper} {norm_comp}. \
             The endpoint permitted access with missing, forged, or improperly signed credentials. \
             Enforce mandatory cryptographic signature verification and role checks in middleware before routing to handler logic."
        );

        let repro = if !sample_curl.is_empty() {
            format!(
                r#"#!/usr/bin/env bash
# Reproduction script for Authorization defect: {defect_id}
set -euo pipefail
echo "Executing reproduction curl (expecting 401/403, observed bypass):"
{sample_curl}
"#,
                defect_id = defect.id
            )
        } else {
            format!(
                r#"#!/usr/bin/env bash
set -euo pipefail
curl -sS -i -X {method_upper} 'http://localhost:8000{norm_comp}' \
  -H 'Authorization: Bearer forged.signature.token123'
"#
            )
        };

        return (patch, explanation, repro);
    }

    // 3. TOCTOU Concurrency / Race Condition
    if title_lower.contains("toctou")
        || title_lower.contains("race")
        || root_cause.contains("burst")
        || root_cause.contains("concurrent")
    {
        let patch = format!(
            r#"--- a/src/services/action.py
+++ b/src/services/action.py
@@ -21,8 +21,11 @@
 async def execute_state_action(record_id: str, caller_id: str):
-    record = await db.fetch_one("SELECT * FROM records WHERE id = :id", {{"id": record_id}})
-    if record.status == "PENDING":
-        await db.execute("UPDATE records SET status = 'COMPLETED' WHERE id = :id", {{"id": record_id}})
+    # Use atomic transaction with pessimistic lock (SELECT ... FOR UPDATE) to prevent TOCTOU races
+    async with db.transaction():
+        record = await db.fetch_one(
+            "SELECT * FROM records WHERE id = :id FOR UPDATE", {{"id": record_id}}
+        )
+        if record.status != "PENDING":
+            raise HTTPException(status_code=409, detail="Resource state collision or already processed")
+        await db.execute("UPDATE records SET status = 'COMPLETED' WHERE id = :id", {{"id": record_id}})"#
        );

        let explanation = format!(
            "TOCTOU (Time-of-Check to Time-of-Use) race condition detected on {method_upper} {norm_comp}. \
             Multiple parallel requests executed simultaneously without mutual exclusion. \
             Enforce atomic transactions with database pessimistic locking (`FOR UPDATE`) or optimistic version concurrency control (`WHERE version = :expected`)."
        );

        let repro = format!(
            r#"#!/usr/bin/env python3
"""Reproduction script for TOCTOU Concurrency Burst: {defect_id}"""
import concurrent.futures
import requests

TARGET = "http://localhost:8000"

def fire_burst_request(req_id):
    headers = {{"Authorization": "Bearer test-user-token"}}
    resp = requests.{method_lower}(f"{{TARGET}}{norm_comp}", headers=headers)
    return resp.status_code

def test_race():
    print("Firing 5 concurrent requests against {norm_comp}...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(fire_burst_request, i) for i in range(5)]
        statuses = [f.result() for f in futures]
    print(f"Burst response status codes: {{statuses}}")

if __name__ == "__main__":
    test_race()
"#,
            defect_id = defect.id,
            method_lower = method_lower,
            norm_comp = norm_comp
        );

        return (patch, explanation, repro);
    }

    // 4. SQL Injection
    if owasp.contains("Injection")
        && (title_lower.contains("sql")
            || root_cause.contains("sql")
            || sample_curl.contains("' OR '1'='1"))
    {
        let patch = format!(
            r#"--- a/src/db/repository.py
+++ b/src/db/repository.py
@@ -10,5 +10,5 @@
 def search_query(query_param: str):
-    # Vulnerable: string concatenation leads to SQL injection
-    return db.execute(f"SELECT * FROM entries WHERE name LIKE '%{{query_param}}%'")
+    # Mitigated: parameterized query binding
+    return db.execute("SELECT * FROM entries WHERE name LIKE :pattern", {{"pattern": f"%{{query_param}}%"}})"#
        );

        let explanation = format!(
            "SQL Injection detected on {method_upper} {norm_comp}. \
             Untrusted user input was interpolated directly into SQL syntax. \
             Replace raw string formatting with prepared statements / parameterized bindings."
        );

        let repro = if !sample_curl.is_empty() {
            format!(
                r#"#!/usr/bin/env bash
# Reproduction script for SQLi defect: {defect_id}
set -euo pipefail
echo "Sending SQL injection tautology vector:"
{sample_curl}
"#,
                defect_id = defect.id
            )
        } else {
            format!(
                r#"#!/usr/bin/env bash
curl -sS -i -G 'http://localhost:8000{norm_comp}' --data-urlencode "q=' OR '1'='1' --"
"#
            )
        };

        return (patch, explanation, repro);
    }

    // 5. Cross-Site Scripting (XSS)
    if owasp.contains("Injection")
        && (title_lower.contains("xss")
            || root_cause.contains("xss")
            || sample_curl.contains("<script>"))
    {
        let patch = format!(
            r#"--- a/src/views/render.py
+++ b/src/views/render.py
@@ -4,5 +4,6 @@
+import html
 def render_response(user_value: str) -> str:
-    # Vulnerable: reflects raw unescaped input into HTML
-    return f"<div class=\"output\">{{user_value}}</div>"
+    # Mitigated: context-aware HTML encoding
+    escaped = html.escape(user_value, quote=True)
+    return f"<div class=\"output\">{{escaped}}</div>""#
        );

        let explanation = format!(
            "Reflected Cross-Site Scripting (XSS) on {method_upper} {norm_comp}. \
             Injected markup was echoed back in the response body without contextual HTML entity encoding. \
             Encode all dynamic values before rendering and enforce Content-Security-Policy (CSP)."
        );

        let repro = if !sample_curl.is_empty() {
            format!(
                r#"#!/usr/bin/env bash
# Reproduction script for XSS defect: {defect_id}
set -euo pipefail
echo "Sending reflected XSS vector:"
{sample_curl}
"#,
                defect_id = defect.id
            )
        } else {
            format!(
                r#"#!/usr/bin/env bash
curl -sS -i -G 'http://localhost:8000{norm_comp}' --data-urlencode "q=\"><script>alert(1)</script>"
"#
            )
        };

        return (patch, explanation, repro);
    }

    // 6. Rate Limiting / Resource Consumption (OWASP API4)
    if owasp.contains("API4")
        || title_lower.contains("rate")
        || title_lower.contains("oversized")
        || root_cause.contains("resource consumption")
    {
        let patch = format!(
            r#"--- a/src/middleware/rate_limit.py
+++ b/src/middleware/rate_limit.py
@@ -8,6 +8,11 @@
 async def rate_limiter(request: Request, call_next):
+    client_ip = request.client.host
+    key = f"rl:{{client_ip}}"
+    count = await redis.incr(key)
+    if count == 1:
+        await redis.expire(key, 60)
+    if count > 100:
+        return JSONResponse(status_code=429, content={{"error": "Rate limit exceeded. Try again in 60s."}})
     return await call_next(request)"#
        );

        let explanation = format!(
            "Unrestricted Resource Consumption / Missing Rate Limiting on {method_upper} {norm_comp}. \
             The endpoint does not restrict request frequencies or payload size limits. \
             Implement sliding window rate limiting (HTTP 429) and request body size caps."
        );

        let repro = if !sample_curl.is_empty() {
            format!(
                r#"#!/usr/bin/env bash
# Reproduction script for Resource Consumption defect: {defect_id}
set -euo pipefail
echo "Sending payload:"
{sample_curl}
"#,
                defect_id = defect.id
            )
        } else {
            format!(
                r#"#!/usr/bin/env bash
for i in {{1..20}}; do
  curl -sS -o /dev/null -w "%%{{http_code}}\n" 'http://localhost:8000{norm_comp}'
done
"#
            )
        };

        return (patch, explanation, repro);
    }

    // 7. Sensitive Exposure (OWASP API8)
    if owasp.contains("API8") && (norm_comp.starts_with("/.") || title_lower.contains("sensitive")) {
        let patch = r#"--- a/nginx.conf
+++ b/nginx.conf
@@ -20,6 +20,10 @@
     server {
         listen 80;
+        # Deny access to sensitive hidden files (.env, .git, etc.)
+        location ~ /\.(?!well-known) {
+            deny all;
+            return 404;
+        }
         location / {
             proxy_pass http://app_upstream;
         }"#
            .to_string();

        let explanation = format!(
            "Sensitive file exposure on {norm_comp}. \
             Configuration metadata or secrets are publicly readable from the web root. \
             Deny access to hidden dotfiles at the web server / reverse proxy layer and rotate any exposed secrets."
        );

        let repro = format!(
            r#"#!/usr/bin/env bash
set -euo pipefail
curl -sS -i 'http://localhost:8000{norm_comp}'
"#
        );

        return (patch, explanation, repro);
    }

    // 8. General / Contract / Unexpected Status
    let patch = format!(
        r#"--- a/src/api/routes.py
+++ b/src/api/routes.py
@@ -16,4 +16,7 @@
 async def route_handler(payload: RequestSchema):
+    # Validate input schema and reject invalid requests with 400
+    if not payload.validate():
+        return JSONResponse(status_code=400, content={{"error": "Invalid input format"}})
     return await service.process(payload)"#
    );

    let explanation = format!(
        "Unexpected response status or contract violation on {method_upper} {norm_comp}. \
         Align endpoint validation and status codes with expected API contracts and handle error edge cases gracefully."
    );

    let repro = if !sample_curl.is_empty() {
        format!(
            r#"#!/usr/bin/env bash
# Reproduction script for defect: {defect_id}
set -euo pipefail
{sample_curl}
"#,
            defect_id = defect.id
        )
    } else {
        format!(
            r#"#!/usr/bin/env bash
curl -sS -i -X {method_upper} 'http://localhost:8000{norm_comp}'
"#
        )
    };

    (patch, explanation, repro)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_defect(id: &str, title: &str, owasp: &str, cause: &str) -> TriagedDefect {
        TriagedDefect {
            id: id.into(),
            title: title.into(),
            severity: "critical".into(),
            priority: "P0".into(),
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
        }
    }

    #[test]
    fn test_bola_remediation_generation() {
        let defect = sample_defect(
            "DEF-001",
            "BOLA multi-tenant isolation bypass",
            "OWASP API1:2023 Broken Object Level Authorization",
            "Observed BOLA cross-tenant access",
        );
        let (patch, exp, repro) =
            synthesize_remediation(&defect, "/api/orders/1", "GET", "curl -i http://target/api/orders/1");

        assert!(patch.contains("--- a/src/api/handlers.py"));
        assert!(patch.contains("tenant_id"));
        assert!(exp.contains("Broken Object Level Authorization"));
        assert!(repro.contains("requests.post"));
        assert!(repro.contains("requests.get"));
    }

    #[test]
    fn test_toctou_remediation_generation() {
        let defect = sample_defect(
            "DEF-002",
            "TOCTOU race condition burst check",
            "OWASP API4:2023 Unrestricted Resource Consumption",
            "Observed concurrent burst race condition",
        );
        let (patch, exp, repro) =
            synthesize_remediation(&defect, "/api/checkout", "POST", "");

        assert!(patch.contains("FOR UPDATE"));
        assert!(exp.contains("TOCTOU"));
        assert!(repro.contains("ThreadPoolExecutor"));
    }

    #[test]
    fn test_sqli_remediation_generation() {
        let defect = sample_defect(
            "DEF-003",
            "SQL injection error probe",
            "OWASP A03:2021 Injection",
            "Observed SQL syntax error disclosure",
        );
        let (patch, exp, repro) =
            synthesize_remediation(&defect, "/search", "GET", "curl -i 'http://target/search?q=%27'");

        assert!(patch.contains("parameterized query binding"));
        assert!(exp.contains("SQL Injection"));
        assert!(repro.contains("curl"));
    }

    #[test]
    fn test_xss_remediation_generation() {
        let defect = sample_defect(
            "DEF-004",
            "Reflected XSS probe",
            "OWASP A03:2021 Injection",
            "Observed script vector reflection",
        );
        let (patch, exp, repro) =
            synthesize_remediation(&defect, "/view", "GET", "curl -i 'http://target/view?q=<script>'");

        assert!(patch.contains("html.escape"));
        assert!(exp.contains("Cross-Site Scripting"));
        assert!(repro.contains("curl"));
    }
}
