#!/usr/bin/env python3
"""ReadyHai qa-api fixture: a tiny in-memory orders API with SEEDED BUGS (stdlib only).

usage: server.py PORT [REQUEST_LOG]      (REQUEST_LOG may also come from $RH_FIXTURE_LOG)
Every request is appended to the log as "METHOD /path" so tests can assert that a
prod-tagged run sent zero non-GET requests.

Seeded bugs:
 1 IDOR            GET /orders/{id} returns any user's order
 2 no auth         GET /admin/stats needs no token
 3 500             POST /orders with note longer than 100 chars
 4 leak            GET /search?q=<contains '> -> 500 with a Python traceback in the body
 5 contract        GET /orders/2 omits the required field "total"
 6 delete no-op    DELETE /orders/{id} returns 204 but keeps the order
 7 slow            GET /reports/slow sleeps 1.5 s
Tokens are FAKE fixture values: Authorization: Bearer alice-token | bob-token | admin-token
"""
import json, os, sys, time, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

TOKENS = {"alice-token": "alice", "bob-token": "bob", "admin-token": "admin"}
LOCK = threading.Lock()
ORDERS = {
    1: {"id": 1, "item": "keyboard", "qty": 2, "total": 20, "note": "", "owner": "alice"},
    2: {"id": 2, "item": "monitor", "qty": 1, "total": 10, "note": "", "owner": "alice"},
    3: {"id": 3, "item": "mouse", "qty": 3, "total": 30, "note": "", "owner": "bob"},
}
NEXT = [4]
LOGFILE = None


def validate(b, partial=False):
    if not isinstance(b, dict):
        return "body must be an object"
    for f in ("item", "qty"):
        if f not in b or b[f] is None:
            return "missing " + f
    if not isinstance(b["item"], str) or not b["item"]:
        return "item must be a non-empty string"
    if isinstance(b["qty"], bool) or not isinstance(b["qty"], int) or not (1 <= b["qty"] <= 100):
        return "qty must be an integer 1..100"
    if "note" in b and b["note"] is not None and not isinstance(b["note"], str):
        return "note must be a string"
    return None


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def send(self, code, obj=None, headers=None, raw=None, ctype="application/json"):
        data = raw if raw is not None else (json.dumps(obj).encode() if obj is not None else b"")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def user(self):
        a = self.headers.get("Authorization", "")
        return TOKENS.get(a[7:]) if a.startswith("Bearer ") else None

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            return json.loads(raw) if raw else None
        except ValueError:
            return "__bad__"

    def handle_any(self):
        u = urlparse(self.path)
        p, q = u.path.rstrip("/") or "/", parse_qs(u.query)
        if LOGFILE:
            with LOCK, open(LOGFILE, "a") as f:
                f.write("%s %s\n" % (self.command, p))
        body = self.body() if self.command in ("POST", "PUT", "PATCH") else None
        if self.command not in ("GET", "HEAD") and body == "__bad__":
            return self.send(400, {"error": "invalid json"})
        m = self.command
        if p == "/health" and m == "GET":
            return self.send(200, {"status": "ok"})
        if p == "/search" and m == "GET":
            s = (q.get("q") or [None])[0]
            if s is None:
                return self.send(400, {"error": "q required"})
            if "'" in s:  # BUG 4: unescaped quote blows up, trace leaks
                tb = ('Traceback (most recent call last):\n  File "/home/app/server.py", line 88, in search\n'
                      '    cur.execute("SELECT * FROM items WHERE name = \'%s\'" % q)\nsqlite3.OperationalError: unrecognized token')
                return self.send(500, raw=tb.encode(), ctype="text/plain")
            return self.send(200, {"results": [], "q": s})
        if p == "/admin/stats" and m == "GET":  # BUG 2: no auth check
            return self.send(200, {"orders": len(ORDERS)})
        user = self.user()
        if user is None:
            return self.send(401, {"error": "unauthorized"})
        if p == "/reports/slow" and m == "GET":
            time.sleep(1.5)  # BUG 7
            return self.send(200, {"ok": True})
        if p == "/orders":
            if m == "GET":
                try:
                    limit = int((q.get("limit") or ["50"])[0]); page = int((q.get("page") or ["1"])[0])
                except ValueError:
                    return self.send(400, {"error": "limit/page must be integers"})
                if limit < 1 or page < 1:
                    return self.send(400, {"error": "limit/page must be >= 1"})
                rows = [o for o in ORDERS.values() if user == "admin" or o["owner"] == user]
                return self.send(200, rows[(page - 1) * min(limit, 100): page * min(limit, 100)])
            if m == "POST":
                err = validate(body)
                if err:
                    return self.send(422, {"error": err})
                note = body.get("note") or ""
                if len(note) > 100:  # BUG 3: unhandled -> 500
                    return self.send(500, {"error": "internal server error"})
                with LOCK:
                    oid = NEXT[0]; NEXT[0] += 1
                    ORDERS[oid] = {"id": oid, "item": body["item"], "qty": body["qty"], "total": body["qty"] * 10, "note": note, "owner": user}
                return self.send(201, ORDERS[oid], {"Location": "/orders/%d" % oid})
        if p.startswith("/orders/"):
            try:
                oid = int(p.split("/")[2])
            except ValueError:
                return self.send(400, {"error": "bad id"})
            o = ORDERS.get(oid)
            if o is None:
                return self.send(404, {"error": "not found"})
            if m == "GET":  # BUG 1: no ownership check
                out = dict(o)
                if oid == 2:  # BUG 5: contract violation, "total" missing
                    out.pop("total")
                return self.send(200, out)
            if m in ("PUT", "PATCH"):
                if o["owner"] != user and user != "admin":
                    return self.send(403, {"error": "forbidden"})
                err = validate(body)
                if err:
                    return self.send(422, {"error": err})
                note = body.get("note") or ""
                if len(note) > 100:
                    return self.send(422, {"error": "note too long"})
                o.update(item=body["item"], qty=body["qty"], total=body["qty"] * 10, note=note)
                return self.send(200, o)
            if m == "DELETE":
                if o["owner"] != user and user != "admin":
                    return self.send(403, {"error": "forbidden"})
                return self.send(204)  # BUG 6: nothing deleted
        return self.send(404, {"error": "no such route"})

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = handle_any


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18090
    LOGFILE = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("RH_FIXTURE_LOG")
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
