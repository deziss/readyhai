use serde_json::{Value, json};
use std::path::{Path, PathBuf};

use super::super::{AuthKind, Roles, env_var};
use super::derive::{Derived, DerivedRole, derive};
use super::fs::{default_out_in, write_secret_file};
use super::render::render;
use super::run;

fn role<'a>(d: &'a Derived, name: &str) -> &'a DerivedRole {
    d.roles.iter().find(|r| r.name == name).unwrap_or_else(|| {
        panic!(
            "no role {name}: {:?}",
            d.roles.iter().map(|r| &r.name).collect::<Vec<_>>()
        )
    })
}

fn parsed(d: &Derived) -> Roles {
    toml::from_str(&render(d, "spec.json")).expect("derived file must parse as roles.toml")
}

fn get(sec: Value) -> Value {
    json!({"security": sec, "responses": {"200": {"description": "ok"}}})
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rh-rolesinit-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

impl DerivedRole {
    fn env(&self) -> String {
        env_var(&self.name, "TOKEN")
    }
}

#[test]
fn bearer_spec_with_admin_paths_denies_them_to_ordinary_users() {
    let doc = json!({"openapi": "3.0.3", "servers": [{"url": "https://x.test/api/v1"}],
    "security": [{"bearerAuth": []}],
    "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
    "paths": {
        "/health": {"get": get(json!([]))},
        "/orders": {"get": {}, "post": {}},
        "/orders/{id}": {"get": {}, "delete": {}},
        "/admin/users": {"get": {}},
        "/admin/users/{id}": {"delete": {}}
    }});
    let d = derive(&doc).unwrap();
    assert_eq!(
        d.roles.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
        ["user", "user2", "admin"]
    );
    assert_eq!(d.base_path, "/api/v1");
    let user = role(&d, "user");
    assert_eq!(user.auth, AuthKind::Bearer);
    // the server's base path is part of every glob: that is the path the runner matches
    assert_eq!(user.deny, ["/api/v1/admin/**"]);
    assert_eq!(
        user.allow,
        ["/api/v1/health", "/api/v1/orders", "/api/v1/orders/**"]
    );
    assert_eq!(role(&d, "admin").allow, ["/api/v1/**"]);
    assert!(role(&d, "admin").deny.is_empty());
    // the file loads through the real roles.toml code and the globs behave
    let r = parsed(&d);
    let u = &r.roles[0];
    assert_eq!(u.expects("/api/v1/admin/users/7"), Some(false));
    assert_eq!(u.expects("/api/v1/admin/users"), Some(false));
    assert_eq!(u.expects("/api/v1/orders/7"), Some(true));
    assert_eq!(u.expects("/api/v1/health"), Some(true));
    assert_eq!(r.roles[2].expects("/api/v1/admin/users"), Some(true));
    assert!(d.warnings.is_empty(), "{:?}", d.warnings);
}

#[test]
fn oauth2_scopes_split_admin_from_user_and_the_note_names_the_scopes() {
    let doc = json!({"openapi": "3.0.3",
    "components": {"securitySchemes": {"oauth": {"type": "oauth2", "flows": {"clientCredentials": {
        "tokenUrl": "https://x/t", "scopes": {"read:orders": "r", "write:orders": "w", "admin:users": "a"}}}}}},
    "paths": {
        "/orders": {"get": {"security": [{"oauth": ["read:orders"]}]},
                    "post": {"security": [{"oauth": ["write:orders"]}]}},
        "/users": {"get": {"security": [{"oauth": ["admin:users"]}]}},
        "/users/{id}": {"delete": {"security": [{"oauth": ["write:orders", "admin:users"]}]}}
    }});
    let d = derive(&doc).unwrap();
    let user = role(&d, "user");
    // `/users` and everything under it (one glob each: `/users/**` does not match `/users`)
    assert_eq!(user.deny, ["/users", "/users/**"]);
    assert_eq!(user.allow, ["/orders"]);
    assert!(
        user.note.contains("read:orders write:orders") && !user.note.contains("admin:users"),
        "{}",
        user.note
    );
    let admin = role(&d, "admin");
    assert!(admin.note.contains("admin:users") && admin.note.contains("read:orders"));
    assert_eq!(admin.allow, ["/**"]);
    // an operation that ALSO accepts an ordinary scope is not admin-only
    let doc2 = json!({"openapi": "3.0.0", "components": {"securitySchemes": {"o": {"type": "oauth2", "flows": {}}}},
        "paths": {"/a": {"get": {"security": [{"o": ["admin"]}, {"o": ["read"]}]}},
                  "/b": {"get": {"security": [{"o": ["admin"]}]}}}});
    let d2 = derive(&doc2).unwrap();
    assert_eq!(role(&d2, "user").deny, ["/b"]);
    assert_eq!(role(&d2, "user").allow, ["/a"]);
}

#[test]
fn x_roles_make_one_role_each_with_allow_and_deny_from_the_operations() {
    let doc = json!({"openapi": "3.0.0", "x-roles": ["Customer", "Support Agent", "admin"],
    "security": [{"b": []}],
    "components": {"securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}},
    "paths": {
        "/orders": {"get": {"x-roles": ["customer", "support agent", "admin"]}},
        "/tickets": {"get": {"x-required-roles": ["support agent", "admin"]}},
        "/billing/**x": {"get": {"x-roles": "admin"}},
        "/me": {"get": {}}
    }});
    let d = derive(&doc).unwrap();
    assert_eq!(
        d.roles.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
        ["admin", "customer", "support_agent"]
    );
    assert_eq!(role(&d, "customer").deny, ["/billing/**", "/tickets"]);
    assert_eq!(role(&d, "customer").allow, ["/me", "/orders"]);
    assert!(role(&d, "admin").deny.is_empty());
    assert_eq!(role(&d, "support_agent").deny, ["/billing/**"]);
    assert_eq!(role(&d, "support_agent").env(), "RH_SUPPORT_AGENT_TOKEN");
    parsed(&d);
}

#[test]
fn schemes_map_to_auth_kinds_and_other_schemes_become_their_own_role() {
    let doc = json!({"openapi": "3.0.0",
    "components": {"securitySchemes": {
        "jwt": {"type": "http", "scheme": "Bearer"},
        "svcKey": {"type": "apiKey", "in": "header", "name": "X-Service-Key"},
        "legacy": {"type": "http", "scheme": "basic"},
        "q": {"type": "apiKey", "in": "query", "name": "k"},
        "mtls": {"type": "mutualTLS"}}},
    "paths": {
        "/a": {"get": {"security": [{"jwt": []}]}},
        "/b": {"get": {"security": [{"jwt": []}]}},
        "/jobs": {"post": {"security": [{"svcKey": []}]}},
        "/old": {"get": {"security": [{"legacy": []}, {"jwt": []}]}},
        "/k": {"get": {"security": [{"q": []}]}},
        "/m": {"get": {"security": [{"mtls": []}]}}
    }});
    let d = derive(&doc).unwrap();
    let names: Vec<&str> = d.roles.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["user", "user2", "legacy", "svckey"], "{names:?}");
    assert_eq!(role(&d, "user").auth, AuthKind::Bearer);
    let svc = role(&d, "svckey");
    assert_eq!(
        (svc.auth, svc.header_name.as_deref()),
        (AuthKind::Header, Some("X-Service-Key"))
    );
    assert_eq!(role(&d, "legacy").auth, AuthKind::Basic);
    // the other scheme's role reaches what accepts that scheme, and is denied the rest
    assert_eq!(svc.allow, ["/jobs"]);
    assert!(svc.deny.contains(&"/a".to_string()) && svc.deny.contains(&"/b".to_string()));
    assert_eq!(role(&d, "legacy").allow, ["/old"]);
    // unsupported schemes are said, not guessed
    let w = d.warnings.join("\n");
    assert!(
        w.contains("apiKey in the query") && w.contains("mutualTLS"),
        "{w}"
    );
    let text = render(&d, "spec.yaml");
    assert!(
        text.contains("username_env = \"RH_LEGACY_USER\"")
            && text.contains("password_env = \"RH_LEGACY_PASS\"")
    );
    assert!(
        text.contains("header_name = \"X-Service-Key\"")
            && text.contains("token_env = \"RH_SVCKEY_TOKEN\"")
    );
    let r = parsed(&d);
    assert_eq!(r.roles.len(), 4);
}

#[test]
fn only_env_var_names_are_ever_written() {
    let doc = json!({"openapi": "3.0.0", "security": [{"b": []}, {"k": []}],
        "components": {"securitySchemes": {"b": {"type": "http", "scheme": "basic"},
            "k": {"type": "apiKey", "in": "cookie", "name": "sid"}}},
        "paths": {"/admin/x": {"get": {}}, "/y": {"get": {}}}});
    let text = render(&derive(&doc).unwrap(), "s.json");
    for line in text.lines().filter(|l| !l.trim_start().starts_with('#')) {
        if let Some((k, v)) = line.split_once(" = ")
            && k.ends_with("_env")
        {
            let v = v.split('#').next().unwrap().trim().trim_matches('"');
            assert!(
                v.starts_with("RH_")
                    && v.chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'),
                "{line}"
            );
        }
    }
    assert!(
        text.contains("export RH_USER_USER=... RH_USER_PASS=..."),
        "{text}"
    );
    assert!(text.contains("Never write a token, password or key into this file"));
    assert!(
        text.contains("storage_state") || !text.contains("cookie"),
        "{text}"
    );
    parsed(&derive(&doc).unwrap());
}

#[test]
fn a_spec_with_no_security_still_gets_two_bearer_roles_and_says_so() {
    let doc = json!({"openapi": "3.1.0", "paths": {"/a": {"get": {}}}});
    let d = derive(&doc).unwrap();
    assert_eq!(d.roles.len(), 2);
    assert!(d.roles.iter().all(|r| r.auth == AuthKind::Bearer));
    assert!(d.warnings.iter().any(|w| w.contains("no securitySchemes")));
    // nothing is secured, so nothing is denied: one allow-all glob each
    assert!(
        d.roles
            .iter()
            .all(|r| r.allow == ["/**"] && r.deny.is_empty())
    );
}

#[test]
fn paths_whose_methods_disagree_get_no_glob_and_a_note() {
    let doc = json!({"openapi": "3.0.0", "security": [{"o": ["read"]}],
        "components": {"securitySchemes": {"o": {"type": "oauth2", "flows": {}}}},
        "paths": {"/things": {"get": {"security": []}, "delete": {"security": [{"o": ["admin"]}]}},
                  "/admin/z": {"get": {"security": [{"o": ["admin"]}]}}}});
    let d = derive(&doc).unwrap();
    let user = role(&d, "user");
    assert!(
        !user
            .allow
            .iter()
            .chain(&user.deny)
            .any(|p| p.contains("things")),
        "{user:?}"
    );
    assert_eq!(user.deny, ["/admin/**"]);
    assert!(
        d.warnings
            .iter()
            .any(|w| w.contains("/things") && w.contains("allows some methods and denies others")),
        "{:?}",
        d.warnings
    );
}

#[test]
fn globs_that_cannot_express_a_case_are_flagged_by_the_self_check() {
    // `/users/{id}` is admin-only, `/users/export` is open: `deny /users/*` would also catch
    // `/users/export`, and deny wins, so no glob list can say it
    let doc = json!({"openapi": "3.0.0",
        "components": {"securitySchemes": {"o": {"type": "oauth2", "flows": {}}}},
        "paths": {"/users/{id}": {"get": {"security": [{"o": ["admin"]}]}},
                  "/users/export": {"get": {"security": [{"o": ["read"]}]}}}});
    let d = derive(&doc).unwrap();
    assert!(
        d.warnings.iter().any(|w| w.contains("role 'user'")
            && w.contains("do not express")
            && w.contains("/users/export")),
        "{:?}",
        d.warnings
    );
    // and the note lands in the file header so a reviewer sees it
    assert!(render(&d, "x").contains("# NOTE: role 'user'"));
}

#[test]
fn rejects_non_openapi3_and_empty_specs() {
    assert!(derive(&json!({"swagger": "2.0", "paths": {}})).is_err());
    let e = derive(&json!({"openapi": "3.0.0", "paths": {}})).unwrap_err();
    assert!(format!("{e}").contains("no operations"));
}

#[test]
fn a_path_item_ref_is_followed() {
    let doc = json!({"openapi": "3.0.0",
        "components": {"pathItems": {"Adm": {"get": {"security": [{"o": ["admin"]}]}}},
                       "securitySchemes": {"o": {"type": "oauth2", "flows": {}}}},
        "paths": {"/admin/a": {"$ref": "#/components/pathItems/Adm"}, "/p": {"get": {"security": [{"o": ["x"]}]}}}});
    let d = derive(&doc).unwrap();
    assert_eq!(d.operations, 2);
    assert_eq!(role(&d, "user").deny, ["/admin/**"]);
}

#[test]
fn a_big_spec_stays_fast_and_compact() {
    let mut paths = serde_json::Map::new();
    for i in 0..1000 {
        paths.insert(
            format!("/svc{}/res{i}", i % 20),
            json!({"get": {}, "post": {}}),
        );
        paths.insert(
            format!("/svc{}/res{i}/{{id}}", i % 20),
            json!({"get": {}, "put": {}, "delete": {}}),
        );
        paths.insert(
            format!("/admin/area{i}"),
            json!({"get": {"security": [{"o": ["admin:all"]}]}}),
        );
    }
    let doc = json!({"openapi": "3.0.0", "security": [{"o": ["user"]}],
        "components": {"securitySchemes": {"o": {"type": "oauth2", "flows": {}}}}, "paths": paths});
    let t = std::time::Instant::now();
    let d = derive(&doc).unwrap();
    assert_eq!(d.operations, 6000);
    assert!(
        t.elapsed() < std::time::Duration::from_secs(5),
        "{:?}",
        t.elapsed()
    );
    // the 1000 admin areas collapse into one glob, the 20 service prefixes into 20
    let user = role(&d, "user");
    assert_eq!(user.deny, ["/admin/**"]);
    assert_eq!(user.allow.len(), 20, "{:?}", &user.allow[..3]);
    assert!(d.warnings.is_empty(), "{:?}", d.warnings);
}

#[test]
fn default_output_is_the_config_secrets_dir() {
    let o = |s: &str| Some(std::ffi::OsString::from(s));
    assert_eq!(
        default_out_in(o("/xdg"), o("/home/u")).unwrap(),
        PathBuf::from("/xdg/readyhai/secrets/roles.toml")
    );
    assert_eq!(
        default_out_in(None, o("/home/u")).unwrap(),
        PathBuf::from("/home/u/.config/readyhai/secrets/roles.toml")
    );
    assert_eq!(
        default_out_in(o(""), o("/home/u")).unwrap(),
        PathBuf::from("/home/u/.config/readyhai/secrets/roles.toml")
    );
    assert!(default_out_in(None, None).is_err());
}

#[cfg(unix)]
#[test]
fn the_file_is_0600_in_a_0700_dir_and_never_overwritten_without_force() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmpdir("write");
    let out = dir.join("new").join("secrets").join("roles.toml");
    write_secret_file(&out, "a = 1\n", false).unwrap();
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&out), 0o600);
    assert_eq!(mode(out.parent().unwrap()), 0o700);
    // second write: refused, file untouched
    let e = write_secret_file(&out, "b = 2\n", false).unwrap_err();
    assert!(format!("{e}").contains("--force"), "{e}");
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "a = 1\n");
    // --force replaces it (shorter content: no stale tail) and tightens a loose mode
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o644)).unwrap();
    write_secret_file(&out, "b\n", true).unwrap();
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "b\n");
    assert_eq!(mode(&out), 0o600);
    // a symlink is never written through, even with --force
    let target = dir.join("victim");
    std::fs::write(&target, "keep").unwrap();
    let link = dir.join("link.toml");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(
        write_secret_file(&link, "x", true)
            .unwrap_err()
            .to_string()
            .contains("symlink")
    );
    assert!(write_secret_file(&link, "x", false).is_err());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn run_reads_yaml_writes_a_loadable_file_and_refuses_urls_and_overwrites() {
    let dir = tmpdir("run");
    let spec = dir.join("api.yaml");
    std::fs::write(
        &spec,
        "openapi: 3.0.0\nsecurity:\n  - bearerAuth: []\ncomponents:\n  securitySchemes:\n    bearerAuth: {type: http, scheme: bearer}\npaths:\n  /admin/x: {get: {}}\n  /p: {get: {}}\n",
    )
    .unwrap();
    let out = dir.join("roles.toml");
    let wrote = run(spec.to_str().unwrap(), Some(&out), false).unwrap();
    assert_eq!(wrote.as_deref(), Some(out.as_path()));
    // the real loader accepts it, with no loose-mode warning, and the role set is usable
    let r = Roles::load(&out).unwrap();
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    assert_eq!(r.names(), ["user", "user2", "admin"]);
    assert_eq!(r.roles[0].expects("/admin/x"), Some(false));
    assert_eq!(
        r.roles[0].credential(),
        None,
        "no env var is set: nothing resolves"
    );
    assert!(std::fs::read_to_string(&out).unwrap().contains("api.yaml"));
    // second run without --force: refused; with: fine
    assert!(run(spec.to_str().unwrap(), Some(&out), false).is_err());
    run(spec.to_str().unwrap(), Some(&out), true).unwrap();
    // no network
    let e = run("https://example.test/openapi.json", Some(&out), true).unwrap_err();
    assert!(format!("{e}").contains("local file"));
    assert!(run(dir.join("missing.json").to_str().unwrap(), Some(&out), true).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_fixture_spec_derives_roles_that_match_the_hand_written_ones() {
    let doc: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/qa-api/openapi.json"
    ))
    .unwrap();
    let d = derive(&doc).unwrap();
    // the fixture has an /admin area: ordinary roles are denied it, an admin reaches all
    let user = role(&d, "user");
    assert!(
        user.deny.iter().any(|p| p.starts_with("/admin")),
        "{user:?}"
    );
    assert_eq!(role(&d, "admin").allow, ["/**"]);
    let hand: Roles =
        toml::from_str(include_str!("../../../../tests/fixtures/qa-api/roles.toml")).unwrap();
    let derived = parsed(&d);
    for path in ["/admin/stats", "/orders", "/orders/3", "/health", "/search"] {
        assert_eq!(
            derived.roles[0].expects(path),
            hand.roles[0].expects(path),
            "user vs alice on {path}"
        );
    }
}
