#!/usr/bin/env python3
"""ReadyHai spa-next fixture: a tiny fake Next.js app behind a login wall, with SEEDED BUGS (stdlib only).

usage: server.py PORT [REQUEST_LOG] [--clean]   (REQUEST_LOG may also come from $RH_FIXTURE_LOG)
Every request is appended to the log as "METHOD /path" (same convention as the qa-api fixture).
--clean turns every seeded bug off: the same app, behaving correctly (the false-positive guard).

What it mimics (what a thin SPA looks like to a scanner that has no OpenAPI spec):
 * GET /  -> 307 Location /login unless a session cookie / Bearer token is valid (a login wall)
 * GET /login -> 200 HTML with <input type="password"> and the Next.js markers
 * every other path -> the SAME 200 HTML shell (a catch-all / soft-404), except /_next/static/*
   (404 when unknown), /api/* (JSON) and /health
 * the shell loads /_next/static/rhBuild01/_buildManifest.js (pages-router route table, minified,
   with __rewrites) and an app-router chunk /_next/static/chunks/app/(main)/settings/page-abc123.js
 * the JS chunks hold the API calls: fetch("/api/orders"), fetch(`/api/orders/${id}`), "/api/profile"
   and an absolute https://api.example.invalid/v1/x (a host outside any scope: reported, never called)
 * /robots.txt and /sitemap.xml list /dashboard and /pricing
 * JSON API under /api/*, Bearer token required (401 JSON otherwise): /api/orders (GET list with
   ?q= ?limit= ?offset=, POST create), /api/orders/{id} (GET, DELETE), /api/profile

Seeded bugs (all off with --clean):
 1 IDOR            GET /api/orders/{id} returns any user's order (alice reads bob's)
 2 error leak      GET /api/orders?q=<contains '> -> 500 with a SQL error and a Node stack trace
 3 500 on boundary GET /api/orders?limit=<negative or huge> / ?offset=<negative> -> 500
Tokens are FAKE fixture values: Authorization: Bearer alice-token | bob-token
(the clean server answers another user's order with 404 and bad paging with 400)
"""
import json, os, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

BUILD = "rhBuild01"
TOKENS = {"alice-token": "alice", "bob-token": "bob"}
LOCK = threading.Lock()
ORDERS = {
    1: {"id": 1, "item": "keyboard", "qty": 2, "owner": "alice"},
    2: {"id": 2, "item": "monitor", "qty": 1, "owner": "alice"},
    3: {"id": 3, "item": "mouse", "qty": 3, "owner": "bob"},
}
NEXT = [4]
PROFILES = {
    "alice": {"id": "u_alice", "name": "Alice Example", "email": "alice@example.invalid"},
    "bob": {"id": "u_bob", "name": "Bob Example", "email": "bob@example.invalid"},
}
LOGFILE = None
CLEAN = False

SCRIPTS = [
    "/_next/static/chunks/webpack-aa11bb22.js",
    "/_next/static/chunks/framework-bb22cc33.js",
    "/_next/static/chunks/main-cc33dd44.js",
    "/_next/static/chunks/pages/_app-dd44ee55.js",
    "/_next/static/chunks/app/(main)/settings/page-abc123.js",
    "/_next/static/%s/_buildManifest.js" % BUILD,
    "/_next/static/%s/_ssgManifest.js" % BUILD,
]

NEXT_DATA = json.dumps({
    "props": {"pageProps": {}}, "page": "/", "query": {}, "buildId": BUILD,
    "nextExport": True, "autoExport": True, "isFallback": False, "scriptLoader": [],
}, separators=(",", ":"))

# App-router flight payload: the segment tree names the routes ((main) is a route group)
RSC = (
    'self.__next_f.push([1,"0:[\\"$\\",\\"$L1\\",null,{\\"buildId\\":\\"%s\\",\\"tree\\":'
    '[\\"\\",{\\"children\\":[\\"(main)\\",{\\"children\\":[\\"settings\\",{\\"children\\":'
    '[\\"__PAGE__\\",{}]}]}]}]}]\\n"])' % BUILD
)


def page(body_html, title="Acme Console"):
    scripts = "".join('<script src="%s" defer=""></script>' % s for s in SCRIPTS)
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charSet="utf-8"/>'
        '<meta name="viewport" content="width=device-width"/><title>%s</title>'
        '<link rel="preload" href="/_next/static/css/app-1a2b3c.css" as="style"/></head>'
        '<body><div id="__next">%s</div>%s'
        '<script id="__NEXT_DATA__" type="application/json">%s</script>'
        '<script>%s</script></body></html>' % (title, body_html, scripts, NEXT_DATA, RSC)
    ).encode()


SHELL = page("")
LOGIN = page(
    '<main><h1>Sign in</h1><form id="login-form"><input type="email" name="email" placeholder="Email"/>'
    '<input type="password" name="password" placeholder="Password"/>'
    '<button type="submit">Sign in</button></form></main>',
    title="Sign in - Acme Console",
)

# pages-router route table, minified as `next build` writes it; __rewrites destinations are not routes
BUILD_MANIFEST = (
    'self.__BUILD_MANIFEST={__rewrites:{beforeFiles:[],afterFiles:[{has:void 0,source:"/legacy/:path*",'
    'destination:"/internal-rewrite-target/:path*"}],fallback:[]},"/":["static/chunks/pages/index-11aa22bb.js"],'
    '"/_error":["static/chunks/pages/_error-22bb33cc.js"],"/dashboard":["static/chunks/pages/dashboard-33cc44dd.js"],'
    '"/login":["static/chunks/pages/login-44dd55ee.js"],'
    '"/orders/[id]":["static/chunks/pages/orders/[id]-55ee66ff.js"],'
    'sortedPages:["/","/_app","/_error","/dashboard","/login","/orders/[id]"]};'
    'self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB();'
)
SSG_MANIFEST = "self.__SSG_MANIFEST=new Set;self.__SSG_MANIFEST_CB&&self.__SSG_MANIFEST_CB();"

_WP = '(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[%d],{%d:function(e,t,n){"use strict";%s}}]);'
CHUNKS = {
    "chunks/webpack-aa11bb22.js": "(()=>{\"use strict\";var e={},t={};function n(r){var o=t[r];return void 0!==o?o.exports:(o=t[r]={exports:{}},e[r](o,o.exports,n),o.exports)}n.m=e})();",
    "chunks/framework-bb22cc33.js": '"use strict";(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[774],{1:function(e){e.exports={}}}]);',
    # the shared client: search box, order list and order detail calls (query shape included)
    "chunks/main-cc33dd44.js": _WP % (179, 7, (
        'n.d(t,{Zp:function(){return r}});'
        'var r=function(e){return fetch("/api/orders?q="+encodeURIComponent(e)+"&limit=20",'
        '{headers:{accept:"application/json"}}).then(function(e){return e.json()})};'
    )),
    "chunks/pages/_app-dd44ee55.js": _WP % (888, 9, (
        'n.d(t,{lj:function(){return o},kr:function(){return i},dM:function(){return u}});'
        'var o=async function(){const e=await fetch("/api/orders");return e.json()};'
        'var i=async function(id){const e=await fetch(`/api/orders/${id}`);return e.json()};'
        'var u=async function(b){return fetch("/api/orders",{method:"POST",'
        'headers:{"content-type":"application/json"},body:JSON.stringify(b)})};'
    )),
    "chunks/app/(main)/settings/page-abc123.js": _WP % (301, 12, (
        'n.d(t,{default:function(){return s}});'
        'var cfg={profile:"/api/profile",billing:"https://api.example.invalid/v1/x"};'
        'function s(){return fetch("/api/profile").then(function(e){return e.json()})}'
    )),
    "chunks/pages/dashboard-33cc44dd.js": _WP % (410, 14, 'n.d(t,{default:function(){return 1}});'),
    "chunks/pages/login-44dd55ee.js": _WP % (411, 15, 'n.d(t,{default:function(){return 1}});'),
    "chunks/pages/index-11aa22bb.js": _WP % (412, 16, 'n.d(t,{default:function(){return 1}});'),
    "chunks/pages/_error-22bb33cc.js": _WP % (413, 17, 'n.d(t,{default:function(){return 1}});'),
    "chunks/pages/orders/[id]-55ee66ff.js": _WP % (414, 18, 'n.d(t,{default:function(){return 1}});'),
    "%s/_buildManifest.js" % BUILD: BUILD_MANIFEST,
    "%s/_ssgManifest.js" % BUILD: SSG_MANIFEST,
}

LEAK = {
    "error": "Internal Server Error",
    "message": "SQLITE_ERROR: unrecognized token: \"'%'\"",
    "stack": (
        "Error: SQLITE_ERROR: unrecognized token: \"'%'\"\n"
        "    at Database.<anonymous> (/app/node_modules/sqlite3/lib/sqlite3.js:47:19)\n"
        "    at listOrders (/app/.next/server/app/api/orders/route.js:41:19)\n"
        "    at async handler (/app/.next/server/app/api/orders/route.js:77:5)"
    ),
}


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def send(self, code, obj=None, headers=None, raw=None, ctype="application/json"):
        data = raw if raw is not None else (json.dumps(obj).encode() if obj is not None else b"")
        self.send_response(code)
        if data or code not in (204, 307):
            self.send_header("Content-Type", ctype)
        if code != 204:
            self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD" and code != 204:
            self.wfile.write(data)

    def user(self):
        a = self.headers.get("Authorization", "")
        if a.startswith("Bearer "):
            return TOKENS.get(a[7:])
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "rh_session" and v in TOKENS:
                return TOKENS[v]
        return None

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            return json.loads(raw) if raw else None
        except ValueError:
            return "__bad__"

    def handle_any(self):
        u = urlparse(self.path)
        p, q = unquote(u.path).rstrip("/") or "/", parse_qs(u.query)
        if LOGFILE:
            with LOCK, open(LOGFILE, "a") as f:
                f.write("%s %s\n" % (self.command, p))
        m = self.command
        body = self.body() if m in ("POST", "PUT", "PATCH") else None
        if m == "OPTIONS":  # no CORS headers: a foreign Origin is never granted
            return self.send(204, headers={"Allow": "GET, HEAD, POST, DELETE, OPTIONS"})
        if p == "/health" and m == "GET":
            return self.send(200, {"status": "ok"})
        if p.startswith("/api/") or p == "/api":
            return self.api(m, p, q, body)
        if m not in ("GET", "HEAD"):
            return self.send(405, raw=b"Method Not Allowed", ctype="text/plain", headers={"Allow": "GET, HEAD"})
        host = self.headers.get("Host") or "127.0.0.1"
        if p == "/robots.txt":
            txt = "User-agent: *\nAllow: /\nDisallow: /dashboard\nDisallow: /admin\nSitemap: http://%s/sitemap.xml\n" % host
            return self.send(200, raw=txt.encode(), ctype="text/plain")
        if p == "/sitemap.xml":
            urls = "".join("<url><loc>http://%s%s</loc></url>" % (host, x) for x in ("/dashboard", "/pricing"))
            xml = '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">%s</urlset>' % urls
            return self.send(200, raw=xml.encode(), ctype="application/xml")
        if p.startswith("/_next/static/"):
            js = CHUNKS.get(p[len("/_next/static/"):])
            if js is None:
                return self.send(404, raw=b"Not Found", ctype="text/plain")
            return self.send(200, raw=js.encode(), ctype="application/javascript; charset=UTF-8",
                             headers={"Cache-Control": "public, max-age=31536000, immutable"})
        if p == "/login":
            return self.send(200, raw=LOGIN, ctype="text/html; charset=utf-8")
        if p == "/" and self.user() is None:  # the login wall
            return self.send(307, headers={"Location": "/login?next=%2F"})
        # everything else, real route or not, is the same shell: a catch-all (soft-404)
        return self.send(200, raw=SHELL, ctype="text/html; charset=utf-8")

    def api(self, m, p, q, body):
        user = self.user()
        if user is None:
            return self.send(401, {"error": "unauthorized"}, {"WWW-Authenticate": "Bearer"})
        if m not in ("GET", "HEAD", "POST", "DELETE"):
            return self.send(405, {"error": "method not allowed"}, {"Allow": "GET, POST, DELETE"})
        if m != "GET" and m != "HEAD" and body == "__bad__":
            return self.send(400, {"error": "invalid json"})
        if p == "/api/profile":
            if m in ("GET", "HEAD"):
                return self.send(200, PROFILES[user])
            return self.send(405, {"error": "method not allowed"}, {"Allow": "GET, HEAD"})
        if p == "/api/orders":
            if m in ("GET", "HEAD"):
                return self.list_orders(user, q)
            if m == "POST":
                if not isinstance(body, dict) or not (body.get("item") or body.get("title")):
                    return self.send(422, {"error": "item or title required"})
                item = body.get("item") or body.get("title")
                qty = body.get("qty", 1)
                if not isinstance(item, str) or len(item) > 200 or isinstance(qty, bool) or not isinstance(qty, int) or not 1 <= qty <= 100:
                    return self.send(422, {"error": "item must be a string up to 200 chars, qty an integer 1..100"})
                with LOCK:
                    oid = NEXT[0]
                    NEXT[0] += 1
                    ORDERS[oid] = {"id": oid, "item": item, "qty": qty, "owner": user}
                return self.send(201, ORDERS[oid], {"Location": "/api/orders/%d" % oid})
            return self.send(405, {"error": "method not allowed"}, {"Allow": "GET, HEAD, POST"})
        if p.startswith("/api/orders/"):
            try:
                oid = int(p.split("/")[3])
            except (ValueError, IndexError):
                return self.send(400, {"error": "bad id"})
            o = ORDERS.get(oid)
            if o is None:
                return self.send(404, {"error": "not found"})
            if m in ("GET", "HEAD"):
                if o["owner"] != user and CLEAN:  # the fix: other people's orders do not exist for you
                    return self.send(404, {"error": "not found"})
                return self.send(200, o)  # BUG 1 (buggy mode): no ownership check
            if m == "DELETE":
                if o["owner"] != user:
                    return self.send(404, {"error": "not found"})
                with LOCK:
                    ORDERS.pop(oid, None)
                return self.send(204)
            return self.send(405, {"error": "method not allowed"}, {"Allow": "GET, HEAD, DELETE"})
        return self.send(404, {"error": "no such route"})

    def list_orders(self, user, q):
        s = (q.get("q") or [None])[0]
        try:
            limit = int((q.get("limit") or ["50"])[0])
            offset = int((q.get("offset") or ["0"])[0])
        except ValueError:
            return self.send(400, {"error": "limit and offset must be integers"})
        if not CLEAN:
            if s is not None and "'" in s:  # BUG 2: the quote breaks the query and the error leaks
                return self.send(500, LEAK)
            if limit < 0 or limit > 1000000 or offset < 0:  # BUG 3: unhandled -> 500
                return self.send(500, {"error": "Internal Server Error"})
        elif not 1 <= limit <= 100 or offset < 0:
            return self.send(400, {"error": "limit must be 1..100 and offset >= 0"})
        rows = [o for o in ORDERS.values() if o["owner"] == user]
        if s:
            rows = [o for o in rows if s.lower() in o["item"].lower()]
        return self.send(200, rows[offset: offset + max(limit, 0)])

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = handle_any


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    CLEAN = "--clean" in sys.argv[1:] or os.environ.get("RH_FIXTURE_CLEAN") == "1"
    port = int(args[0]) if args else 18091
    LOGFILE = args[1] if len(args) > 1 else os.environ.get("RH_FIXTURE_LOG")
    ThreadingHTTPServer((os.environ.get("RH_FIXTURE_BIND", "127.0.0.1"), port), H).serve_forever()
