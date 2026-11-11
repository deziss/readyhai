#!/usr/bin/env python3
"""
Deterministic deep-security evaluation fixture for ReadyHai.
Usage: python3 server.py <port> [log_file]

Seeded security loopholes:
  1. GET  /api/users/lookup?filter=...   -> Blind Boolean SQLi (differential response)
  2. GET  /api/reports/export?search=... -> Blind Time SQLi (SLEEP() delay > 2.5s)
  3. GET  /api/render?tpl=...            -> SSTI ({{1337*79}} -> 105623)
  4. POST /api/webhooks/test             -> Blind SSRF (executes outbound HTTP callback)
  5. GET  /api/redirect?next=...         -> Open Redirect (unvalidated 302 Location)
  6. GET  /api/admin/audit               -> JWT alg=none signature bypass
  7. GET  /api/admin/users               -> BFLA (non-admin role granted admin data)
  8. POST /api/users + GET /api/users/id -> Mass Assignment (is_admin / role persisted)
  9. POST /api/checkout                  -> Business logic accepts negative qty (<= 0)
 10. POST /api/coupons/redeem            -> TOCTOU concurrent double-redemption (no conflict lock)
 11. GET  /dom                           -> DOM XSS (location.hash -> innerHTML)
 12. GET/POST /comments                  -> Stored XSS (raw form comment rendered unescaped)

Clean negative controls:
  - GET /api/profile                     -> Strict HS256 JWT enforcement
  - GET /api/safe/search?q=...           -> Parameterized & escaped lookup
  - GET /safe                            -> textContent DOM assignment + X-Frame-Options: DENY
"""

import base64
import hashlib
import hmac
import html
import http.server
import json
import os
import sys
import threading
import time
import urllib.parse
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
LOG_FILE = sys.argv[2] if len(sys.argv) > 2 else None
HERE = os.path.dirname(os.path.abspath(__file__))
OPENAPI_BYTES = open(os.path.join(HERE, "openapi.json"), "rb").read()
JWT_SECRET = b"readyhai-eval-jwt-secret"

STATE_LOCK = threading.Lock()
USERS = {
    1: {"id": 1, "name": "alice", "role": "user", "owner": "alice"}
}
NEXT_USER_ID = 2
NEXT_ORDER_ID = 10
COMMENTS = ["Welcome to ReadyHai security benchmark!"]


def log_hit(method: str, path: str) -> None:
    if not LOG_FILE:
        return
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as fp:
            fp.write(f"{method} {path}\n")
    except OSError:
        pass


def b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def parse_jwt(auth_hdr: str, allow_alg_none: bool = False):
    if not auth_hdr or not auth_hdr.startswith("Bearer "):
        return None
    tok = auth_hdr[7:].strip()
    parts = tok.split(".")
    if len(parts) != 3:
        return None
    try:
        hdr = json.loads(b64url_decode(parts[0]).decode("utf-8"))
        pay = json.loads(b64url_decode(parts[1]).decode("utf-8"))
    except Exception:
        return None
    if not isinstance(hdr, dict) or not isinstance(pay, dict):
        return None

    alg = str(hdr.get("alg", ""))
    if allow_alg_none and alg.lower() == "none":
        return pay

    if alg != "HS256" or not parts[2]:
        return None
    expected_sig = b64url_encode(
        hmac.new(JWT_SECRET, f"{parts[0]}.{parts[1]}".encode("utf-8"), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(parts[2], expected_sig):
        return None
    return pay


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def send_json(self, code: int, obj, extra_headers=None):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, code: int, body_str: str, xfo: bool = True):
        body = body_str.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if xfo:
            self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def read_body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or "0")
        if n <= 0:
            return b""
        return self.rfile.read(n)

    def do_HEAD(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        log_hit("HEAD", path)
        auth_hdr = self.headers.get("Authorization", "")
        if path in ("/health", "/openapi.json", "/", "/dom", "/safe", "/comments"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8" if path in ("/", "/dom", "/safe", "/comments") else "application/json")
            self.send_header("Content-Length", "0")
            if path in ("/", "/dom", "/safe", "/comments"):
                self.send_header("X-Frame-Options", "DENY")
            return self.end_headers()
        if path in ("/api/users/lookup", "/api/reports/export", "/api/render", "/api/redirect", "/api/safe/search"):
            self.send_response(200)
            self.send_header("Content-Length", "0")
            return self.end_headers()
        if path == "/api/admin/audit":
            claims = parse_jwt(auth_hdr, allow_alg_none=True)
            code = 200 if (claims and str(claims.get("role", "")).lower() == "admin") else (403 if claims else 401)
            self.send_response(code)
            self.send_header("Content-Length", "0")
            return self.end_headers()
        if path == "/api/admin/users" or path == "/api/profile" or path == "/api/users" or (
            path.startswith("/api/users/") and path != "/api/users/lookup"
        ):
            claims = parse_jwt(auth_hdr, allow_alg_none=False)
            self.send_response(200 if claims else 401)
            self.send_header("Content-Length", "0")
            return self.end_headers()
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_OPTIONS(self):
        parsed = urllib.parse.urlsplit(self.path)
        log_hit("OPTIONS", parsed.path)
        self.send_response(204)
        self.send_header("Allow", "GET, POST, DELETE, HEAD, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PUT(self):
        parsed = urllib.parse.urlsplit(self.path)
        log_hit("PUT", parsed.path)
        self.read_body()
        self.send_json(405, {"error": "method not allowed"})

    def do_PATCH(self):
        parsed = urllib.parse.urlsplit(self.path)
        log_hit("PATCH", parsed.path)
        self.read_body()
        self.send_json(405, {"error": "method not allowed"})

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        log_hit("GET", path)
        auth_hdr = self.headers.get("Authorization", "")

        if path == "/health":
            return self.send_json(200, {"ok": True})
        if path == "/openapi.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(OPENAPI_BYTES)))
            self.end_headers()
            return self.wfile.write(OPENAPI_BYTES)

        if path == "/":
            return self.send_html(
                200,
                "<!doctype html><html><body>"
                "<a href='/dom'>DOM Viewer</a> "
                "<a href='/comments'>Comments</a> "
                "<a href='/safe'>Safe Viewer</a>"
                "</body></html>",
            )
        if path == "/dom":
            return self.send_html(
                200,
                "<!doctype html><html><body>"
                "<div id='out'></div>"
                "<script>document.getElementById('out').innerHTML = location.hash;</script>"
                "</body></html>",
            )
        if path == "/safe":
            return self.send_html(
                200,
                "<!doctype html><html><body>"
                "<div id='safe'></div>"
                "<script>document.getElementById('safe').textContent = location.hash;</script>"
                "</body></html>",
                xfo=True,
            )
        if path == "/comments":
            with STATE_LOCK:
                items = "".join(f"<li>{c}</li>" for c in COMMENTS)
            return self.send_html(
                200,
                "<!doctype html><html><body>"
                "<form method='POST' action='/comments'>"
                "<input type='text' name='comment' />"
                "<button type='submit'>Post</button>"
                "</form>"
                f"<ul>{items}</ul>"
                "</body></html>",
            )

        if path == "/api/admin/audit":
            claims = parse_jwt(auth_hdr, allow_alg_none=True)
            if not claims:
                return self.send_json(401, {"error": "unauthorized"})
            if str(claims.get("role", "")).lower() != "admin":
                return self.send_json(403, {"error": "forbidden"})
            return self.send_json(200, {"audit": [{"event": "startup", "ok": True}]})

        if path == "/api/admin/users":
            claims = parse_jwt(auth_hdr, allow_alg_none=False)
            if not claims:
                return self.send_json(401, {"error": "unauthorized"})
            # Seeded BFLA bug: forgets to check claims["role"] == "admin"
            return self.send_json(200, {"admin_users": [{"id": 1, "name": "alice", "role": "user"}]})

        if path == "/api/profile":
            claims = parse_jwt(auth_hdr, allow_alg_none=False)
            if not claims:
                return self.send_json(401, {"error": "unauthorized"})
            return self.send_json(
                200,
                {"sub": claims.get("sub", "user"), "role": claims.get("role", "user")},
            )

        if path == "/api/users":
            claims = parse_jwt(auth_hdr, allow_alg_none=False)
            if not claims:
                return self.send_json(401, {"error": "unauthorized"})
            caller = claims.get("sub", "")
            with STATE_LOCK:
                rows = [
                    {"id": u["id"], "name": u["name"], "role": u["role"]}
                    for u in USERS.values()
                    if u["owner"] == caller or caller == "admin"
                ]
            return self.send_json(200, {"items": rows})

        if path.startswith("/api/users/") and path != "/api/users/lookup":
            claims = parse_jwt(auth_hdr, allow_alg_none=False)
            if not claims:
                return self.send_json(401, {"error": "unauthorized"})
            tail = path[len("/api/users/"):]
            if not tail.isdigit():
                return self.send_json(404, {"error": "not found"})
            uid = int(tail)
            caller = claims.get("sub", "")
            with STATE_LOCK:
                rec = USERS.get(uid)
                if not rec or (rec["owner"] != caller and caller != "admin"):
                    return self.send_json(404, {"error": "not found"})
                out = {k: v for k, v in rec.items() if k != "owner"}
            return self.send_json(200, out)

        if path == "/api/users/lookup":
            if "filter" not in qs:
                return self.send_json(400, {"error": "filter query parameter is required"})
            val = qs.get("filter", [""])[0]
            # Blind Boolean SQLi differential (no 500/time delay on quotes/sleep here).
            if "'1'='2" in val or "1'='2" in val or "1=2" in val:
                return self.send_json(200, {"matches": [], "total": 0})
            return self.send_json(
                200,
                {
                    "matches": [
                        {
                            "id": 1,
                            "name": "alice",
                            "tier": "enterprise",
                            "department": "platform engineering",
                        }
                    ],
                    "total": 1,
                },
            )

        if path == "/api/reports/export":
            if "search" not in qs:
                return self.send_json(400, {"error": "search query parameter is required"})
            val = qs.get("search", [""])[0]
            if "sleep(" in val.lower() or "pg_sleep(" in val.lower() or "waitfor" in val.lower():
                time.sleep(2.7)
            return self.send_json(200, {"rows": [{"report": "daily-summary", "status": "ok"}]})

        if path == "/api/render":
            if "tpl" not in qs:
                return self.send_json(400, {"error": "tpl query parameter is required"})
            tpl = qs.get("tpl", [""])[0]
            if "{{1337*79}}" in tpl or "${1337*79}" in tpl:
                return self.send_json(200, {"rendered": "Hello 105623"})
            return self.send_json(200, {"rendered": f"Hello {html.escape(tpl)}"})

        if path == "/api/redirect":
            if "next" not in qs:
                return self.send_json(400, {"error": "next query parameter is required"})
            nxt = qs.get("next", [""])[0]
            if nxt.startswith("http://") or nxt.startswith("https://") or nxt.startswith("//"):
                self.send_response(302)
                self.send_header("Location", nxt)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            return self.send_json(200, {"redirect": "/home"})

        if path == "/api/safe/search":
            if "q" not in qs:
                return self.send_json(400, {"error": "q query parameter is required"})
            q = qs.get("q", [""])[0]
            return self.send_json(200, {"safe_query": html.escape(q), "results": [{"id": 1, "label": "clean"}]})

        return self.send_json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        log_hit("POST", path)
        auth_hdr = self.headers.get("Authorization", "")
        raw = self.read_body()

        if path == "/comments":
            claims = parse_jwt(auth_hdr, allow_alg_none=False)
            if not claims:
                return self.send_html(401, "Unauthorized")
            text = ""
            ct = self.headers.get("Content-Type", "").lower()
            if "json" in ct:
                try:
                    data = json.loads(raw.decode("utf-8"))
                    text = str(data.get("comment", ""))
                except Exception:
                    return self.send_html(400, "Invalid JSON")
            else:
                form = urllib.parse.parse_qs(raw.decode("utf-8", errors="replace"), keep_blank_values=True)
                text = form.get("comment", [""])[0]
            with STATE_LOCK:
                if len(COMMENTS) < 25:
                    COMMENTS.append(text)
            return self.send_html(201, "Stored")

        claims = parse_jwt(auth_hdr, allow_alg_none=False)
        if not claims:
            return self.send_json(401, {"error": "unauthorized"})
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            return self.send_json(400, {"error": "invalid json"})
        if not isinstance(data, dict):
            return self.send_json(400, {"error": "object required"})

        if path == "/api/coupons/redeem":
            code = data.get("code")
            if not isinstance(code, str) or not code:
                return self.send_json(400, {"error": "code required"})
            # Seeded TOCTOU bug: missing mutex/single-use conflict check -> all concurrent requests return 200.
            return self.send_json(200, {"redeemed": True, "discount": 50})

        if path == "/api/users":
            name = data.get("name")
            if not isinstance(name, str) or not name:
                return self.send_json(400, {"error": "name required"})
            global NEXT_USER_ID
            with STATE_LOCK:
                uid = NEXT_USER_ID
                NEXT_USER_ID += 1
                rec = {
                    "id": uid,
                    "name": name,
                    "role": data.get("role", "user"),
                    "owner": claims.get("sub", "alice"),
                }
                if "is_admin" in data:
                    rec["is_admin"] = data["is_admin"]
                USERS[uid] = rec
                out = {k: v for k, v in rec.items() if k != "owner"}
            return self.send_json(201, out)

        if path == "/api/webhooks/test":
            wh = data.get("webhook_url")
            if not isinstance(wh, str) or not wh:
                return self.send_json(400, {"error": "webhook_url required"})
            delivered = False
            if wh.startswith("http://127.0.0.1:") or wh.startswith("http://localhost:"):
                try:
                    urllib.request.urlopen(wh, timeout=1.5).read(256)
                    delivered = True
                except Exception:
                    pass
            return self.send_json(200, {"delivered": delivered})

        if path == "/api/checkout":
            item_id = data.get("item_id")
            qty = data.get("qty")
            if (
                not isinstance(item_id, int)
                or isinstance(item_id, bool)
                or item_id < 1
                or item_id > 100
                or not isinstance(qty, int)
                or isinstance(qty, bool)
                or qty > 100
            ):
                return self.send_json(400, {"error": "invalid checkout item_id or qty"})
            # Seeded business logic bug: forgets `qty >= 0` / positive lower bound check!
            global NEXT_ORDER_ID
            with STATE_LOCK:
                oid = NEXT_ORDER_ID
                NEXT_ORDER_ID += 1
            return self.send_json(201, {"id": oid, "item_id": item_id, "qty": qty, "total": qty * 10})

        return self.send_json(404, {"error": "not found"})

    def do_DELETE(self):
        parsed = urllib.parse.urlsplit(self.path)
        log_hit("DELETE", parsed.path)
        claims = parse_jwt(self.headers.get("Authorization", ""), allow_alg_none=False)
        if not claims:
            return self.send_json(401, {"error": "unauthorized"})
        if parsed.path.startswith("/api/users/"):
            tail = parsed.path[len("/api/users/"):]
            if tail.isdigit():
                uid = int(tail)
                with STATE_LOCK:
                    if uid in USERS and uid != 1:
                        del USERS[uid]
                        self.send_response(204)
                        self.send_header("Content-Length", "0")
                        return self.end_headers()
        return self.send_json(404, {"error": "not found"})


if __name__ == "__main__":
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    srv.serve_forever()

