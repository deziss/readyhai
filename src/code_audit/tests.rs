use super::*;

#[test]
fn detects_cross_file_python_sqli_missing_auth_guard_and_clean_parameterized_no_fp() {
    let dir = std::env::temp_dir().join(format!(
        "rh-codeaudit-py-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(dir.join("app")).unwrap();

    std::fs::write(
        dir.join("app/db.py"),
        r#"import sqlite3

def find_user_unsafe(conn, user_q):
    query = f"SELECT * FROM users WHERE name = '{user_q}'"
    return conn.execute(query).fetchall()

def find_user_safe(conn, user_q):
    return conn.execute("SELECT * FROM users WHERE name = ?", (user_q,)).fetchall()
"#,
    )
    .unwrap();

    std::fs::write(
        dir.join("app/routes.py"),
        r#"from flask import request
import requests
from app.db import find_user_unsafe, find_user_safe

@app.get("/api/orders")
@login_required
def list_orders(conn):
    return find_user_safe(conn, request.args.get("q"))

@app.post("/api/orders")
@login_required
def create_order(conn):
    return find_user_safe(conn, request.json.get("item"))

@app.get("/api/users/search")
def search_users(conn):
    return find_user_unsafe(conn, request.args.get("username"))

@app.delete("/api/admin/purge")
def purge_all(conn):
    return {"ok": True}
"#,
    )
    .unwrap();

    let inv = audit_tree(&dir);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        inv.findings
            .iter()
            .any(|f| f.rule == "security.taint.sql_injection" && f.location.starts_with("app/")),
        "expected cross-file SQLi finding: {:?}",
        inv.findings
    );
    assert!(
        inv.findings
            .iter()
            .any(|f| f.rule == "security.auth.missing_guard" && f.location.contains("routes.py")),
        "expected missing auth guard finding on /api/admin/purge: {:?}",
        inv.findings
    );
    // Parameterized helper should not trigger SQLi on find_user_safe
    assert!(
        !inv.findings.iter().any(
            |f| f.rule == "security.taint.sql_injection" && f.detail.contains("find_user_safe")
        ),
        "parameterized query must not false-positive: {:?}",
        inv.findings
    );
    assert!(
        inv.imported_packages.contains("requests"),
        "{:?}",
        inv.imported_packages
    );
    assert!(
        inv.imported_packages.contains("flask"),
        "{:?}",
        inv.imported_packages
    );
    assert!(
        inv.endpoints
            .iter()
            .any(|e| e.path == "/api/admin/purge" && e.guards.is_empty()),
        "{:?}",
        inv.endpoints
    );
}

#[test]
fn detects_js_express_missing_guard_and_go_cmd_injection() {
    let dir = std::env::temp_dir().join(format!(
        "rh-codeaudit-jsgo-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(dir.join("src")).unwrap();

    std::fs::write(
        dir.join("src/server.ts"),
        r#"import express from "express";
const app = express();
app.get("/api/items", requireAuth, listItems);
app.post("/api/items", requireAuth, createItem);
app.delete("/api/admin/reset", (req, res) => res.json({ ok: true }));
"#,
    )
    .unwrap();

    std::fs::write(
        dir.join("src/ping.go"),
        r#"package main
import (
    "net/http"
    "os/exec"
)
func pingHandler(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    exec.Command("sh", "-c", "ping -c 1 " + host).Run()
}
"#,
    )
    .unwrap();

    let inv = audit_tree(&dir);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        inv.findings
            .iter()
            .any(|f| f.rule == "security.auth.missing_guard"),
        "expected missing guard on /api/admin/reset: {:?}",
        inv.findings
    );
    assert!(
        inv.findings
            .iter()
            .any(|f| f.rule == "security.taint.command_exec"),
        "expected Go command injection finding: {:?}",
        inv.findings
    );
    assert!(
        inv.imported_packages.contains("express"),
        "{:?}",
        inv.imported_packages
    );
}
