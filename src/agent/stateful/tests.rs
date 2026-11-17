use std::collections::HashMap;
use serde_json::Value;

use super::models::DEFAULT_ID_KEYS;
use super::preflight::preflight;
use super::vars::{
    extract_json_values, is_secret_key, placeholder_names, storable_value, substitute_vars,
};
use super::violation::{actor_bearer, evaluate_violation, extract_violation_tag};
use crate::agent::exec::Credentials;
use crate::agent::types::StatefulStep;

fn step(n: u32, actor: &str, method: &str, path: &str) -> StatefulStep {
    StatefulStep {
        step_number: n,
        actor: actor.into(),
        method: method.into(),
        path: path.into(),
        payload: None,
        extract_vars: None,
        expected_status: None,
        violation_condition: None,
    }
}

fn chain() -> Vec<StatefulStep> {
    let mut create = step(1, "alice", "POST", "/api/items");
    create.extract_vars = Some(vec!["id".into()]);
    let mut read = step(2, "bob", "GET", "/api/items/{{id}}");
    read.violation_condition = Some("status == 200".into());
    vec![create, read]
}

fn creds() -> Credentials {
    Credentials::none().with("alice", "a").with("bob", "b")
}

#[test]
fn test_variable_substitution() {
    let mut ctx = HashMap::new();
    ctx.insert("item_id".into(), "item_987".into());
    ctx.insert("tenant".into(), "acme".into());

    let path = substitute_vars("/api/{{tenant}}/items/{{item_id}}", &ctx);
    assert_eq!(path, "/api/acme/items/item_987");

    let body = substitute_vars("{\"ref\": \"{{ item_id }}\"}", &ctx);
    assert_eq!(body, "{\"ref\": \"item_987\"}");
    // unknown placeholders survive substitution so the caller can reject them
    let left = substitute_vars("/x/{{ nope }}/{{tenant}}", &ctx);
    assert_eq!(left, "/x/{{ nope }}/acme");
    assert_eq!(placeholder_names(&left), ["nope"]);
    assert!(
        placeholder_names("{\"a\":{\"b\":1}}").is_empty(),
        "JSON braces are not placeholders"
    );
}

#[test]
fn ids_come_from_the_top_level_or_primary_object_only() {
    let ex = |json: &str, wanted: Option<Vec<String>>| {
        let v: Value = serde_json::from_str(json).unwrap();
        let mut out = HashMap::new();
        extract_json_values(&v, wanted.as_deref(), &mut out);
        out
    };
    // a nested sub-resource's id never wins or leaks in
    let o = ex(
        r#"{"id": "ord_1", "owner": {"id": 77, "uuid": "u-9"}, "items": [{"id": 5}]}"#,
        None,
    );
    assert_eq!(o.get("id").map(String::as_str), Some("ord_1"));
    assert!(!o.contains_key("uuid"), "{o:?}");
    // an envelope is looked through exactly once, into the primary object
    let o = ex(
        r#"{"status": "ok", "data": {"id": "ord_2", "nested": {"uuid": "u-1"}}}"#,
        Some(vec!["token".into(), "id".into()]),
    );
    assert_eq!(o.get("id").map(String::as_str), Some("ord_2"));
    assert!(
        !o.contains_key("uuid"),
        "nested uuid must not be extracted: {o:?}"
    );
    // a list response has no primary object
    assert!(ex(r#"[{"id": 1}, {"id": 2}]"#, None).is_empty());
    // numbers become strings; an explicit name is aliased to the primary id
    let o = ex(r#"{"id": 4}"#, Some(vec!["item_id".into()]));
    assert_eq!(
        (
            o.get("id").map(String::as_str),
            o.get("item_id").map(String::as_str)
        ),
        (Some("4"), Some("4"))
    );
    // wanted secret names are extractable (chaining), but never by default
    let o = ex(r#"{"id": 1, "token": "tok_x"}"#, None);
    assert!(!o.contains_key("token"));
    let o = ex(r#"{"id": 1, "token": "tok_x"}"#, Some(vec!["token".into()]));
    assert_eq!(o.get("token").map(String::as_str), Some("tok_x"));
}

#[test]
fn secret_looking_keys_are_redacted_before_they_are_stored() {
    for k in [
        "token",
        "access_token",
        "api_key",
        "apiKey",
        "secret",
        "client_secret",
        "password",
        "session",
        "session_id",
        "Authorization",
        "auth",
        "key",
        "jwt",
    ] {
        assert!(is_secret_key(k), "{k}");
        assert_eq!(storable_value(k, "value-1"), "[REDACTED]", "{k}");
    }
    for k in [
        "id",
        "uuid",
        "item_id",
        "order_id",
        "author_id",
        "title",
        "name",
    ] {
        assert!(!is_secret_key(k), "{k}");
    }
    assert_eq!(storable_value("id", "item_9"), "item_9");
    // even under an innocent key, secret-looking content is scrubbed
    assert!(!storable_value("note", "password=hunter2hunter2").contains("hunter2"));
}

#[test]
fn test_violation_condition_evaluation() {
    assert!(evaluate_violation("status == 200", 200, ""));
    assert!(!evaluate_violation("status == 200", 403, ""));

    assert!(evaluate_violation(
        "status == 200 || status == 204",
        204,
        ""
    ));
    assert!(evaluate_violation(
        "status != 403 && status != 404",
        200,
        ""
    ));
    assert!(!evaluate_violation(
        "status != 403 && status != 404",
        403,
        ""
    ));

    assert!(evaluate_violation("bola", 200, ""));
    assert!(!evaluate_violation("bola", 403, ""));

    let (tag, expr) = extract_violation_tag("stored_xss:unescaped:<img src=x onerror=");
    assert_eq!(tag, "stored_xss");
    assert!(evaluate_violation(
        expr,
        200,
        "<ul><li><img src=x onerror=\"alert(1)\"></li></ul>"
    ));
    assert!(!evaluate_violation(
        expr,
        200,
        "<ul><li>&lt;img src=x onerror=&quot;alert(1)&quot;&gt;</li></ul>"
    ));
}

#[test]
fn preflight_decides_everything_that_needs_no_request() {
    assert!(preflight(&chain(), &creds()).is_ok());
    // credentials of every actor
    let e = preflight(&chain(), &Credentials::none().with("alice", "a")).unwrap_err();
    assert!(
        e.contains("missing credential") && e.contains("'bob'") && e.contains("RH_BOB_TOKEN"),
        "{e}"
    );
    assert!(
        preflight(&chain(), &Credentials::none())
            .unwrap_err()
            .contains("'alice'")
    );
    // an anonymous second actor needs no token
    let mut anon = chain();
    anon[1].actor = "anon".into();
    assert!(preflight(&anon, &Credentials::none().with("alice", "a")).is_ok());
    // unknown verbs are rejected, never turned into GET
    let mut bad = chain();
    bad[1].method = "TRACE".into();
    assert!(
        preflight(&bad, &creds())
            .unwrap_err()
            .contains("not allowed")
    );
    // lower-case verbs are fine (normalised)
    let mut low = chain();
    low[0].method = "post".into();
    assert!(preflight(&low, &creds()).is_ok());
    // placeholders must be producible by an earlier step
    let mut ph = chain();
    ph[1].path = "/api/items/{{nope}}".into();
    assert!(preflight(&ph, &creds()).unwrap_err().contains("{{nope}}"));
    let mut first = chain();
    first[0].path = "/api/items/{{id}}".into();
    assert!(
        preflight(&first, &creds())
            .unwrap_err()
            .contains("unresolved placeholder"),
        "no step before the first can fill it"
    );
    // one resource: POST /api/items pairs with GET /api/items/{{id}} only
    let mut other = chain();
    other[1].path = "/api/orders/{{id}}".into();
    assert!(
        preflight(&other, &creds())
            .unwrap_err()
            .contains("not the same resource")
    );
    let mut nested = chain();
    nested[1].path = "/api/items/{{id}}/history".into();
    assert!(preflight(&nested, &creds()).is_err());
    let mut slash = chain();
    slash[0].path = "/api/items/".into();
    assert!(
        preflight(&slash, &creds()).is_ok(),
        "a trailing slash is the same resource"
    );
    let mut noph = chain();
    noph[1].path = "/api/items".into();
    assert!(
        preflight(&noph, &creds())
            .unwrap_err()
            .contains("does not address the created resource")
    );
    // same actor, anonymous creator, missing creating step
    let mut same = chain();
    same[1].actor = "Alice".into();
    assert!(
        preflight(&same, &creds())
            .unwrap_err()
            .contains("same actor")
    );
    let mut anon_creator = chain();
    anon_creator[0].actor = "anon".into();
    assert!(preflight(&anon_creator, &creds()).is_err());
    assert!(preflight(&chain()[1..], &creds()).is_err());
    assert!(preflight(&[], &creds()).is_err());
}

#[test]
fn actor_bearer_resolves_roles_and_never_invents_a_token() {
    let c = creds();
    assert_eq!(actor_bearer("alice", &c).as_deref(), Some("Bearer a"));
    assert_eq!(actor_bearer("ALICE", &c).as_deref(), Some("Bearer a"));
    assert_eq!(actor_bearer("anon", &c), None);
    assert_eq!(actor_bearer("carol", &c), None);
    assert!(
        actor_bearer("forged", &c)
            .unwrap()
            .starts_with("Bearer forged.")
    );
}
