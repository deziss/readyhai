"""Tiny resilience fixture: HTTP app that depends on redis (speaks raw RESP, stdlib only).
GET /health and GET / both PING redis. Redis unreachable/paused -> 503 (RH_MODE=ok, default),
or an unhandled 500 (RH_MODE=storm, the seeded-bug variant)."""
import os, socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST, PORT = os.environ.get("REDIS_HOST", "redis"), 6379
STORM = os.environ.get("RH_MODE") == "storm"


def ping():
    with socket.create_connection((HOST, PORT), timeout=1) as s:
        s.settimeout(1)
        s.sendall(b"*1\r\n$4\r\nPING\r\n")
        if not s.recv(16).startswith(b"+PONG"):
            raise RuntimeError("bad reply")


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            ping()
            code, body = 200, b'{"status":"ok"}'
        except Exception:
            code, body = (500, b"boom") if STORM else (503, b'{"status":"degraded"}')
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if code == 503:
            self.send_header("Retry-After", "5")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
