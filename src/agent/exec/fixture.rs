//! In-process mirror of `tests/fixtures/qa-api/server.py` (the orders API) for tests that need a
//! real server: token auth (`alice-token`, `bob-token`, `admin-token`), `POST /orders` validated
//! like the fixture's `validate`, `GET`/`DELETE /orders/{id}` (a DELETE that keeps the order when
//! `delete_noop`: the fixture's seeded bug 6), `/boom` (500) and `/redir` (302). Plain `std::net`,
//! one thread per connection, `Connection: close`.

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct Api {
    pub base: String,
    /// One `"METHOD /path"` per request, in arrival order.
    pub log: Arc<Mutex<Vec<String>>>,
    orders: Arc<Mutex<BTreeMap<u64, String>>>,
    stop: Arc<AtomicBool>,
    addr: std::net::SocketAddr,
}

impl Api {
    pub fn requests(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
    /// Ids of the orders that exist now.
    pub fn order_ids(&self) -> Vec<u64> {
        self.orders.lock().unwrap().keys().copied().collect()
    }
}

impl Drop for Api {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr); // wake the accept loop
    }
}

/// server.py's `validate`: why `POST /orders` would answer 422, if it would.
pub fn order_input_error(b: &Value) -> Option<String> {
    let Some(o) = b.as_object() else {
        return Some("body must be an object".into());
    };
    for f in ["item", "qty"] {
        if o.get(f).is_none_or(Value::is_null) {
            return Some(format!("missing {f}"));
        }
    }
    if !o["item"].as_str().is_some_and(|s| !s.is_empty()) {
        return Some("item must be a non-empty string".into());
    }
    if !o["qty"].as_i64().is_some_and(|q| (1..=100).contains(&q)) {
        return Some("qty must be an integer 1..100".into());
    }
    match o.get("note") {
        Some(n) if !n.is_null() && !n.is_string() => Some("note must be a string".into()),
        _ => None,
    }
}

fn token_user(auth: &str) -> Option<&'static str> {
    match auth {
        "Bearer alice-token" => Some("alice"),
        "Bearer bob-token" => Some("bob"),
        "Bearer admin-token" => Some("admin"),
        _ => None,
    }
}

fn reply(s: &mut TcpStream, code: u16, headers: &[(&str, &str)], body: &Value) {
    let body = if body.is_null() {
        String::new()
    } else {
        body.to_string()
    };
    let mut h = format!(
        "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in headers {
        h.push_str(&format!("{k}: {v}\r\n"));
    }
    h.push_str("\r\n");
    let _ = s.write_all(h.as_bytes());
    let _ = s.write_all(body.as_bytes());
}

fn serve_one(
    mut s: TcpStream,
    orders: &Mutex<BTreeMap<u64, String>>,
    next: &Mutex<u64>,
    log: &Mutex<Vec<String>>,
    delete_noop: bool,
) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        let Ok(n) = s.read(&mut tmp) else { return };
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split_whitespace();
    let (method, target) = (
        first.next().unwrap_or("").to_string(),
        first.next().unwrap_or("").to_string(),
    );
    let header = |name: &str| {
        lines
            .clone()
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim().to_string())
    };
    let len: usize = header("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    while buf.len() < head_end + len {
        match s.read(&mut tmp) {
            Ok(n) if n > 0 => buf.extend_from_slice(&tmp[..n]),
            _ => break,
        }
    }
    let body: Option<Value> = serde_json::from_slice(&buf[head_end..]).ok();
    let path = target
        .split('?')
        .next()
        .unwrap_or("/")
        .trim_end_matches('/')
        .to_string();
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path
    };
    log.lock().unwrap().push(format!("{method} {path}"));
    let m = method.as_str();
    if (m, path.as_str()) == ("GET", "/health") {
        return reply(&mut s, 200, &[], &json!({"status": "ok"}));
    }
    let Some(user) = token_user(&header("authorization").unwrap_or_default()) else {
        return reply(&mut s, 401, &[], &json!({"error": "unauthorized"}));
    };
    match (m, path.as_str()) {
        ("GET", "/boom") => reply(&mut s, 500, &[], &json!({"error": "internal"})),
        ("GET", "/redir") => reply(
            &mut s,
            302,
            &[("Location", "http://other.invalid/x")],
            &Value::Null,
        ),
        ("POST", "/orders") => {
            let b = body.unwrap_or(Value::Null);
            if let Some(e) = order_input_error(&b) {
                return reply(&mut s, 422, &[], &json!({"error": e}));
            }
            let id = {
                let mut n = next.lock().unwrap();
                *n += 1;
                *n - 1
            };
            orders.lock().unwrap().insert(id, user.to_string());
            let loc = format!("/orders/{id}");
            reply(
                &mut s,
                201,
                &[("Location", &loc)],
                &json!({"id": id, "item": b["item"], "qty": b["qty"], "owner": user}),
            );
        }
        (_, p) if p.starts_with("/orders/") => {
            let Ok(id) = p["/orders/".len()..].parse::<u64>() else {
                return reply(&mut s, 400, &[], &json!({"error": "bad id"}));
            };
            let owner = orders.lock().unwrap().get(&id).cloned();
            let Some(owner) = owner else {
                return reply(&mut s, 404, &[], &json!({"error": "not found"}));
            };
            match m {
                "GET" => reply(&mut s, 200, &[], &json!({"id": id, "owner": owner})),
                "DELETE" if owner != user && user != "admin" => {
                    reply(&mut s, 403, &[], &json!({"error": "forbidden"}))
                }
                "DELETE" => {
                    if !delete_noop {
                        orders.lock().unwrap().remove(&id);
                    }
                    reply(&mut s, 204, &[], &Value::Null)
                }
                _ => reply(&mut s, 404, &[], &json!({"error": "no such route"})),
            }
        }
        _ => reply(&mut s, 404, &[], &json!({"error": "no such route"})),
    }
}

/// Start the fixture with orders 1 and 2 (alice) and 3 (bob) present.
pub fn start(delete_noop: bool) -> Api {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().unwrap();
    let orders = Arc::new(Mutex::new(BTreeMap::from([
        (1, "alice".to_string()),
        (2, "alice".to_string()),
        (3, "bob".to_string()),
    ])));
    let next = Arc::new(Mutex::new(4u64));
    let log = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let (o2, n2, l2, s2) = (orders.clone(), next.clone(), log.clone(), stop.clone());
    std::thread::spawn(move || {
        for conn in l.incoming() {
            if s2.load(Ordering::SeqCst) {
                break;
            }
            let Ok(c) = conn else { continue };
            let (o, n, lg) = (o2.clone(), n2.clone(), l2.clone());
            std::thread::spawn(move || serve_one(c, &o, &n, &lg, delete_noop));
        }
    });
    Api {
        base: format!("http://{addr}"),
        log,
        orders,
        stop,
        addr,
    }
}
