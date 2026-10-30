//! In-process HTTP fixture for the API QA tests: a port of `tests/fixtures/qa-api/server.py`
//! (the orders API with seeded bugs) plus switches for the behaviours the tests need
//! (`{data:{...}}` envelopes, a PUT that does not persist, flaky / always-broken / crashing
//! routes). Plain `std::net`, one thread per connection, `Connection: close`.
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct HReq {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HReq {
    pub fn json(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }
    pub fn user(&self) -> Option<&'static str> {
        match self.headers.get("authorization").map(String::as_str) {
            Some("Bearer alice-token") => Some("alice"),
            Some("Bearer bob-token") => Some("bob"),
            Some("Bearer admin-token") => Some("admin"),
            _ => None,
        }
    }
}

pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Close the connection without answering.
    pub drop_conn: bool,
}

impl Resp {
    pub fn json(status: u16, v: Value) -> Resp {
        Resp {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: v.to_string().into_bytes(),
            drop_conn: false,
        }
    }
    pub fn raw(status: u16, ctype: &str, body: Vec<u8>) -> Resp {
        Resp {
            status,
            headers: vec![("Content-Type".into(), ctype.into())],
            body,
            drop_conn: false,
        }
    }
    pub fn empty(status: u16) -> Resp {
        Resp {
            status,
            headers: vec![],
            body: vec![],
            drop_conn: false,
        }
    }
    pub fn dropped() -> Resp {
        Resp {
            status: 0,
            headers: vec![],
            body: vec![],
            drop_conn: true,
        }
    }
    pub fn with_header(mut self, k: &str, v: &str) -> Resp {
        self.headers.push((k.into(), v.into()));
        self
    }
}

pub struct Server {
    pub base: String,
    /// One "METHOD /path" per request, in arrival order.
    pub log: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    addr: std::net::SocketAddr,
}

impl Server {
    pub fn requests(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
    pub fn count(&self, prefix: &str) -> usize {
        self.requests()
            .iter()
            .filter(|l| l.starts_with(prefix))
            .count()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr); // wake the accept loop
    }
}

fn read_request(s: &mut TcpStream) -> Option<HReq> {
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        let n = s.read(&mut tmp).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > 1 << 20 {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.to_string();
    let target = first.next()?.to_string();
    let headers: HashMap<String, String> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    while buf.len() < head_end + len {
        let n = s.read(&mut tmp).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = buf[head_end..(head_end + len).min(buf.len())].to_vec();
    let (path, q) = target.split_once('?').unwrap_or((&target, ""));
    let pct = |s: &str| {
        let b = s.as_bytes();
        let mut o = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%'
                && i + 3 <= b.len()
                && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
            {
                o.push(v);
                i += 3;
                continue;
            }
            o.push(if b[i] == b'+' { b' ' } else { b[i] });
            i += 1;
        }
        String::from_utf8_lossy(&o).into_owned()
    };
    let query = q
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (pct(k), pct(v))
        })
        .collect();
    Some(HReq {
        method,
        path: pct(path),
        query,
        headers,
        body,
    })
}

fn write_response(s: &mut TcpStream, r: Resp) {
    if r.drop_conn {
        return; // dropping the stream closes it without a response
    }
    let reason = match r.status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        422 => "Unprocessable Entity",
        500 => "Internal Server Error",
        _ => "X",
    };
    let mut h = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
        r.status,
        r.body.len()
    );
    for (k, v) in &r.headers {
        h.push_str(&format!("{k}: {v}\r\n"));
    }
    h.push_str("\r\n");
    let _ = s.write_all(h.as_bytes());
    let _ = s.write_all(&r.body);
    let _ = s.flush();
}

pub fn serve(handler: impl Fn(&HReq) -> Resp + Send + Sync + 'static) -> Server {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let h = Arc::new(handler);
    let (log2, stop2) = (log.clone(), stop.clone());
    std::thread::spawn(move || {
        for conn in l.incoming() {
            if stop2.load(Ordering::SeqCst) {
                break;
            }
            let Ok(mut s) = conn else { continue };
            let (h, log) = (h.clone(), log2.clone());
            std::thread::spawn(move || {
                if let Some(req) = read_request(&mut s) {
                    log.lock()
                        .unwrap()
                        .push(format!("{} {}", req.method, req.path));
                    let r = h(&req);
                    write_response(&mut s, r);
                }
            });
        }
    });
    Server {
        base: format!("http://{addr}"),
        log,
        stop,
        addr,
    }
}

// ------------------------------------------------------------------ orders API (port of server.py)

#[derive(Clone, Default)]
pub struct Opts {
    /// Wrap success bodies as {"data": ...}.
    pub envelope: bool,
    /// PUT answers 200 but changes nothing.
    pub no_persist: bool,
    /// PUT always answers 400.
    pub put_rejects: bool,
    /// POST answers 201 without a Location header or an id in the body.
    pub no_id: bool,
}

pub struct Orders {
    orders: Mutex<BTreeMap<u64, Value>>,
    next: Mutex<u64>,
    opts: Opts,
    pub flaky_calls: AtomicUsize,
}

impl Orders {
    pub fn new(opts: Opts) -> Arc<Orders> {
        let mut m = BTreeMap::new();
        for (id, item, qty, total, owner) in [
            (1, "keyboard", 2, 20, "alice"),
            (2, "monitor", 1, 10, "alice"),
            (3, "mouse", 3, 30, "bob"),
        ] {
            m.insert(id, json!({"id": id, "item": item, "qty": qty, "total": total, "note": "", "owner": owner}));
        }
        Arc::new(Orders {
            orders: Mutex::new(m),
            next: Mutex::new(4),
            opts,
            flaky_calls: AtomicUsize::new(0),
        })
    }

    fn wrap(&self, v: Value) -> Value {
        if self.opts.envelope {
            json!({"data": v})
        } else {
            v
        }
    }

    fn validate(b: &Option<Value>) -> Option<String> {
        let Some(Value::Object(o)) = b else {
            return Some("body must be an object".into());
        };
        for f in ["item", "qty"] {
            if o.get(f).map(|v| v.is_null()).unwrap_or(true) {
                return Some(format!("missing {f}"));
            }
        }
        if !o["item"].as_str().map(|s| !s.is_empty()).unwrap_or(false) {
            return Some("item must be a non-empty string".into());
        }
        match o["qty"].as_i64() {
            Some(q) if (1..=100).contains(&q) && !o["qty"].is_boolean() => {}
            _ => return Some("qty must be an integer 1..100".into()),
        }
        if let Some(n) = o.get("note")
            && !n.is_null()
            && !n.is_string()
        {
            return Some("note must be a string".into());
        }
        None
    }

    pub fn handle(&self, r: &HReq) -> Resp {
        let m = r.method.as_str();
        let p = if r.path.len() > 1 {
            r.path.trim_end_matches('/')
        } else {
            r.path.as_str()
        };
        let body = r.json();
        if matches!(m, "POST" | "PUT" | "PATCH") && !r.body.is_empty() && body.is_none() {
            return Resp::json(400, json!({"error": "invalid json"}));
        }
        match (m, p) {
            ("GET", "/health") => return Resp::json(200, json!({"status": "ok"})),
            ("GET", "/search") => {
                let Some(q) = r.query.get("q") else { return Resp::json(400, json!({"error": "q required"})) };
                if q.contains('\'') {
                    let tb = "Traceback (most recent call last):\n  File \"/home/app/server.py\", line 88, in search\nsqlite3.OperationalError: unrecognized token";
                    return Resp::raw(500, "text/plain", tb.as_bytes().to_vec());
                }
                return Resp::json(200, json!({"results": [], "q": q}));
            }
            ("GET", "/admin/stats") => return Resp::json(200, json!({"orders": self.orders.lock().unwrap().len()})), // BUG: no auth
            // a normal page: nav links and the words "stack trace" in prose must never be a leak
            ("GET", "/page") => return Resp::raw(200, "text/html", br#"<nav><a href="/home/">Home</a> <a href="/usr/src/docs.py">Docs</a></nav><p>We never show a stack trace. Traceback (most recent call last) is a python phrase.</p>"#.to_vec()),
            // 404 page that really leaks
            ("GET", "/leaky") => return Resp::raw(404, "text/plain", b"Traceback (most recent call last):\n  File \"/srv/app/x.py\", line 3, in h".to_vec()),
            // fails on the first call only
            ("GET", "/flaky") => {
                return if self.flaky_calls.fetch_add(1, Ordering::SeqCst) == 0 { Resp::json(500, json!({"message": "transient glitch"})) } else { Resp::json(200, json!({"ok": true})) };
            }
            ("GET", "/broken") => return Resp::json(500, json!({"message": "always broken"})),
            ("GET", "/broken2") => return Resp::json(500, json!({"message": "always broken"})),
            ("GET", "/broken3") => return Resp::json(500, json!({"message": "always broken"})),
            ("GET", "/big") => {
                let n: usize = r.query.get("n").and_then(|v| v.parse().ok()).unwrap_or(4000);
                let items: Vec<Value> = (0..n).map(|i| json!({"id": i, "name": format!("item-{i}-padding-padding-padding")})).collect();
                return Resp::json(200, Value::Array(items));
            }
            ("POST", "/items") => {
                // crashes (drops the connection) on a malformed payload
                return match body.as_ref().and_then(|b| b.get("name")) {
                    Some(Value::String(_)) => Resp::json(201, json!({"id": 1})),
                    _ => Resp::dropped(),
                };
            }
            _ => {}
        }
        let Some(user) = r.user() else {
            return Resp::json(401, json!({"error": "unauthorized"}));
        };
        if p == "/orders" {
            if m == "GET" {
                let (limit, page) = (
                    r.query.get("limit").map(|v| v.parse::<i64>()),
                    r.query.get("page").map(|v| v.parse::<i64>()),
                );
                if matches!(limit, Some(Err(_))) || matches!(page, Some(Err(_))) {
                    return Resp::json(400, json!({"error": "limit/page must be integers"}));
                }
                if limit.map(|l| l.unwrap() < 1).unwrap_or(false)
                    || page.map(|p| p.unwrap() < 1).unwrap_or(false)
                {
                    return Resp::json(400, json!({"error": "limit/page must be >= 1"}));
                }
                let rows: Vec<Value> = self
                    .orders
                    .lock()
                    .unwrap()
                    .values()
                    .filter(|o| user == "admin" || o["owner"] == user)
                    .cloned()
                    .collect();
                return Resp::json(200, self.wrap(Value::Array(rows)));
            }
            if m == "POST" {
                if let Some(e) = Self::validate(&body) {
                    return Resp::json(422, json!({"error": e}));
                }
                let b = body.unwrap();
                let note = b
                    .get("note")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                if note.len() > 100 {
                    return Resp::json(500, json!({"error": "internal server error"})); // BUG: unhandled
                }
                if self.opts.no_id {
                    return Resp::json(201, json!({"ok": true}));
                }
                let mut next = self.next.lock().unwrap();
                let id = *next;
                *next += 1;
                let o = json!({"id": id, "item": b["item"], "qty": b["qty"], "total": b["qty"].as_i64().unwrap() * 10, "note": note, "owner": user});
                self.orders.lock().unwrap().insert(id, o.clone());
                return Resp::json(201, self.wrap(o))
                    .with_header("Location", &format!("/orders/{id}"));
            }
        }
        if let Some(rest) = p.strip_prefix("/orders/") {
            let Ok(oid) = rest.parse::<u64>() else {
                return Resp::json(400, json!({"error": "bad id"}));
            };
            let mut orders = self.orders.lock().unwrap();
            let Some(o) = orders.get(&oid).cloned() else {
                return Resp::json(404, json!({"error": "not found"}));
            };
            match m {
                "GET" => {
                    let mut out = o.clone();
                    if oid == 2 {
                        out.as_object_mut().unwrap().remove("total"); // BUG: contract violation
                    }
                    return Resp::json(200, self.wrap(out)); // BUG: no ownership check
                }
                "PUT" | "PATCH" => {
                    if o["owner"] != user && user != "admin" {
                        return Resp::json(403, json!({"error": "forbidden"}));
                    }
                    if self.opts.put_rejects {
                        return Resp::json(400, json!({"error": "nope"}));
                    }
                    if let Some(e) = Self::validate(&body) {
                        return Resp::json(422, json!({"error": e}));
                    }
                    let b = body.unwrap();
                    let note = b
                        .get("note")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string();
                    if note.len() > 100 {
                        return Resp::json(422, json!({"error": "note too long"}));
                    }
                    let mut upd = o.clone();
                    upd["item"] = b["item"].clone();
                    upd["qty"] = b["qty"].clone();
                    upd["total"] = json!(b["qty"].as_i64().unwrap() * 10);
                    upd["note"] = json!(note);
                    if !self.opts.no_persist {
                        orders.insert(oid, upd.clone());
                    }
                    return Resp::json(200, self.wrap(upd));
                }
                "DELETE" => {
                    if o["owner"] != user && user != "admin" {
                        return Resp::json(403, json!({"error": "forbidden"}));
                    }
                    return Resp::empty(204); // BUG: nothing deleted
                }
                _ => {}
            }
        }
        Resp::json(404, json!({"error": "no such route"}))
    }
}

/// The orders fixture as a running server.
pub fn orders_server(opts: Opts) -> (Server, Arc<Orders>) {
    let o = Orders::new(opts);
    let o2 = o.clone();
    (serve(move |r| o2.handle(r)), o)
}
