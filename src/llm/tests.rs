use super::budget::{Shape, downgrade, raw_chat, raw_once};
use super::catalog::provider_ids;
use super::client::key_with;
use super::*;
use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::sync::atomic::Ordering;
use std::time::Duration;

#[test]
fn one_call_gets_only_a_share_of_the_run_budget() {
    let b = Budget::new(20, Duration::from_secs(300));
    let left = b
        .call_deadline()
        .saturating_duration_since(std::time::Instant::now());
    assert!(
        left <= Duration::from_secs(181) && left >= Duration::from_secs(170),
        "{left:?}"
    );
    // a 34k-token Max Pro call would get 300 s alone; under the deadline it gets the share
    let mut c = LlmConfig::resolve(Some("vllm"), None, false).unwrap();
    assert_eq!(c.call_timeout(34_816), Duration::from_secs(300));
    c.call_deadline = Some(b.call_deadline());
    assert!(c.call_timeout(34_816) <= Duration::from_secs(181));
    // an exhausted budget still allows the minimum, never zero
    c.call_deadline = Some(std::time::Instant::now());
    assert_eq!(c.call_timeout(34_816), Duration::from_secs(MIN_CALL_SECS));
    assert!(c.past_call_deadline());
}

#[test]
fn container_rewrites_loopback_llm_url() {
    assert_eq!(
        container_loopback_to_host("http://localhost:6130/v1"),
        "http://host.docker.internal:6130/v1"
    );
    assert_eq!(
        container_loopback_to_host("http://127.0.0.1:8000"),
        "http://host.docker.internal:8000"
    );
    assert_eq!(
        container_loopback_to_host("http://vllm.lan:8000/v1"),
        "http://vllm.lan:8000/v1"
    );
    let get = |inside: bool| {
        move |k: &str| match k {
            "READYHAI_LLM_URL" => Some("http://localhost:6130/v1".to_string()),
            "READYHAI_IN_CONTAINER" if inside => Some("1".to_string()),
            _ => None,
        }
    };
    let c = LlmConfig::from_vars(get(true)).unwrap();
    assert_eq!(c.base_url().unwrap(), "http://host.docker.internal:6130/v1");
    let h = LlmConfig::from_vars(get(false)).unwrap();
    assert_eq!(h.base_url().unwrap(), "http://localhost:6130/v1");
}

#[test]
fn cloud_guard() {
    assert!(LlmConfig::resolve(Some("anthropic"), None, false).is_err());
    let c = LlmConfig::resolve(Some("anthropic"), None, true).unwrap();
    assert_eq!(c.model, "claude-sonnet-5-5");
    let o = LlmConfig::resolve(Some("ollama"), Some("x"), false).unwrap();
    assert_eq!(o.model, "x");
    assert!(LlmConfig::resolve(Some("nope"), None, true).is_err());
    assert!(LlmConfig::resolve(None, None, true).is_err());
}

#[test]
fn no_hardcoded_lan_address_in_catalog() {
    for p in CATALOG {
        assert!(
            !p.base_url.contains("10.10."),
            "{} bakes in a LAN address",
            p.id
        );
        // a built-in base is loopback or a public name, never a private LAN address
        if let Some(h) = reqwest::Url::parse(p.base_url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
        {
            assert!(
                !h.starts_with("192.168.") && !h.starts_with("10.") && !h.starts_with("172."),
                "{} bakes in a private address {h}",
                p.id
            );
        }
    }
    let g = provider("vllm").unwrap();
    assert_eq!(g.base_url, "");
    assert_eq!(g.legacy_url_env, Some("READYHAI_VLLM_URL"));
    // the generic provider is the only one without an address; only it has a legacy URL variable
    assert!(
        CATALOG
            .iter()
            .all(|p| (p.base_url.is_empty() && p.legacy_url_env.is_some()) == (p.id == "vllm"))
    );
}

fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let m: std::collections::HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |k| m.get(k).cloned()
}

fn model_of(body: &str) -> String {
    serde_json::from_str::<Value>(body).unwrap()["model"]
        .as_str()
        .unwrap()
        .to_string()
}

fn models_seen(m: &mock::Mock) -> Vec<String> {
    m.requests
        .lock()
        .unwrap()
        .iter()
        .map(|r| model_of(r.split("\r\n\r\n").nth(1).unwrap()))
        .collect()
}

#[test]
fn provider_aliases_select_the_generic_descriptor() {
    let g = provider("vllm").unwrap();
    for a in [
        "openai-compatible",
        "custom",
        "CUSTOM",
        " Openai-Compatible ",
    ] {
        assert!(std::ptr::eq(provider(a).unwrap(), g), "{a}");
    }
    let c = LlmConfig::resolve(Some("custom"), None, false).unwrap();
    assert_eq!(c.provider.id, "vllm");
    assert_eq!(c.describe(), "vllm/qwen3.8-flash-next");
    let mut seen = std::collections::HashSet::new();
    for p in CATALOG {
        for id in std::iter::once(p.id).chain(p.aliases.iter().copied()) {
            assert!(seen.insert(id), "duplicate provider id/alias {id}");
        }
    }
    assert!(provider("nope").is_none());
    let e = LlmConfig::resolve(Some("nope"), None, true)
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("custom") && e.contains("openai-compatible"),
        "{e}"
    );
}

#[test]
fn llm_url_overrides_the_base_of_every_provider() {
    let c = LlmConfig::from_vars(vars(&[
        ("READYHAI_LLM_PROVIDER", "ollama"),
        ("READYHAI_LLM_URL", "http://gpu-box:8080/v1"),
    ]))
    .unwrap();
    assert_eq!(c.provider.id, "ollama");
    assert_eq!(c.base_url().unwrap(), "http://gpu-box:8080/v1");
    for id in ["openai", "anthropic", "openrouter"] {
        let with = LlmConfig::from_vars(vars(&[
            ("READYHAI_LLM_PROVIDER", id),
            ("READYHAI_LLM_ALLOW_CLOUD", "1"),
            ("READYHAI_LLM_URL", "https://llm-proxy.example.com/gw"),
        ]))
        .unwrap();
        assert_eq!(with.base_url().unwrap(), "https://llm-proxy.example.com/gw");
        let without = LlmConfig::from_vars(vars(&[
            ("READYHAI_LLM_PROVIDER", id),
            ("READYHAI_LLM_ALLOW_CLOUD", "1"),
        ]))
        .unwrap();
        assert_eq!(without.base_url().unwrap(), without.provider.base_url);
    }
}

#[test]
fn llm_url_is_what_the_call_really_hits() {
    let m = mock::start(|_| "{\"ok\": true}".into());
    let mut c = LlmConfig::from_vars(vars(&[
        ("READYHAI_LLM_PROVIDER", "ollama"),
        ("READYHAI_LLM_URL", m.base.as_str()),
    ]))
    .unwrap();
    c.cache_dir = Some(tmpdir("url-wire"));
    assert_eq!(
        ask_json(&c, &mut Budget::per_run(), "s", "p").unwrap()["ok"],
        true
    );
    assert_eq!(m.chat_hits.load(Ordering::SeqCst), 1);
    assert!(probe(&c));
}

#[test]
fn llm_url_alone_selects_the_generic_provider() {
    let c =
        LlmConfig::from_vars(vars(&[("READYHAI_LLM_URL", "http://localhost:8000/v1")])).unwrap();
    assert_eq!(c.provider.id, "vllm");
    assert_eq!(c.model, "qwen3.8-flash-next");
    assert_eq!(c.base_url().unwrap(), "http://localhost:8000/v1");
    // no URL at all: configured, but with nowhere to send, and the error says what to export
    let c = LlmConfig::from_vars(vars(&[])).unwrap();
    assert_eq!(c.provider.id, "vllm");
    let e = c.base_url().unwrap_err().to_string();
    assert!(e.contains("READYHAI_LLM_URL"), "{e}");
    // the alias ids select the same generic provider
    for id in ["openai-compatible", "custom"] {
        let c = LlmConfig::from_vars(vars(&[
            ("READYHAI_LLM_PROVIDER", id),
            ("READYHAI_LLM_URL", "http://localhost:8000/v1"),
        ]))
        .unwrap();
        assert_eq!(c.provider.id, "vllm");
    }
}

#[test]
fn vllm_url_is_a_deprecated_fallback_alias() {
    let old = "http://old-box:8000/v1";
    let c = LlmConfig::from_vars(vars(&[("READYHAI_VLLM_URL", old)])).unwrap();
    assert_eq!((c.provider.id, c.base_url().unwrap()), ("vllm", old.into()));
    // READYHAI_LLM_URL wins when both are set
    let c = LlmConfig::from_vars(vars(&[
        ("READYHAI_VLLM_URL", old),
        ("READYHAI_LLM_URL", "http://new-box:8000/v1"),
    ]))
    .unwrap();
    assert_eq!(c.base_url().unwrap(), "http://new-box:8000/v1");
    // the alias belongs to the generic provider only: it never redirects another one
    let c = LlmConfig::from_vars(vars(&[
        ("READYHAI_LLM_PROVIDER", "ollama"),
        ("READYHAI_VLLM_URL", old),
    ]))
    .unwrap();
    assert_eq!(c.base_url().unwrap(), "http://localhost:11434/v1");
}

#[test]
fn empty_variables_count_as_unset() {
    let c = LlmConfig::from_vars(vars(&[
        ("READYHAI_LLM_PROVIDER", ""),
        ("READYHAI_LLM_URL", "  "),
        ("READYHAI_VLLM_URL", ""),
        ("READYHAI_LLM_API_KEY", ""),
        ("READYHAI_LLM_MODEL", ""),
        ("READYHAI_LLM_MODELS", " "),
    ]))
    .unwrap();
    assert_eq!(c.provider.id, "vllm");
    assert!(c.base_override.is_none() && c.api_key.is_none());
    assert_eq!(c.models, [c.provider.default_model]);
}

#[test]
fn base_url_validation_rejects_secrets_and_never_echoes_them() {
    for bad in [
        "not a url",
        "ftp://host/v1",
        "file:///etc/passwd",
        "http://",
        "http://svc:s3cretpw@host:8000/v1",
        "http://host:8000/v1?api_key=tok-9f8e7d",
        "http://host:8000/v1#tok-9f8e7d",
    ] {
        let e = validate_base_url(bad).unwrap_err().to_string();
        assert!(
            !e.contains("s3cretpw") && !e.contains("tok-9f8e7d"),
            "{bad}: {e}"
        );
        assert!(
            LlmConfig::from_vars(vars(&[("READYHAI_LLM_URL", bad)])).is_err(),
            "{bad}"
        );
    }
    assert_eq!(
        validate_base_url("  http://host:8000/v1/ ").unwrap(),
        "http://host:8000/v1/"
    );
}

#[test]
fn public_host_classification() {
    for h in [
        "localhost",
        "127.0.0.1",
        "127.5.5.5",
        "[::1]",
        "::1",
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.5",
        "169.254.1.1",
        "100.64.0.1",
        "100.127.255.255",
        "0.0.0.0",
        "fd00::1",
        "fe80::1",
        "::ffff:192.168.1.1",
        "gpu-box",
        "ollama",
        "vllm.lan",
        "gpu.local",
        "host.docker.internal",
        "svc.ns.svc.cluster.local",
        "box.corp.internal",
        "GPU.LAN.",
        "app.localhost",
        "nas.home.arpa",
    ] {
        assert!(!is_public_host(h), "{h} must not count as public");
    }
    for h in [
        "api.openai.com",
        "llm.example.com",
        "8.8.8.8",
        "1.1.1.1",
        "172.32.0.1",
        "172.15.255.255",
        "100.128.0.1",
        "100.63.255.255",
        "2606:4700::1111",
        "::ffff:8.8.8.8",
        "example.lan.com",
        "internal.example.com",
    ] {
        assert!(is_public_host(h), "{h} must count as public");
    }
    assert_eq!(
        public_host_of("https://llm.example.com/v1").as_deref(),
        Some("llm.example.com")
    );
    assert_eq!(public_host_of("http://10.0.0.5:8000/v1"), None);
    assert!(public_host_of("garbage").is_some(), "fails closed");
}

#[test]
fn public_url_with_a_local_provider_needs_allow_cloud() {
    let public = "https://llm.example.com/v1";
    let e = LlmConfig::from_vars(vars(&[("READYHAI_LLM_URL", public)]))
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("READYHAI_LLM_ALLOW_CLOUD")
            && e.contains("llm.example.com")
            && e.contains("refused"),
        "{e}"
    );
    // the deprecated variable and other local providers are guarded the same way
    assert!(LlmConfig::from_vars(vars(&[("READYHAI_VLLM_URL", public)])).is_err());
    assert!(
        LlmConfig::from_vars(vars(&[
            ("READYHAI_LLM_PROVIDER", "ollama"),
            ("READYHAI_LLM_URL", public)
        ]))
        .is_err()
    );
    for flag in ["1", "true"] {
        assert!(
            LlmConfig::from_vars(vars(&[
                ("READYHAI_LLM_URL", public),
                ("READYHAI_LLM_ALLOW_CLOUD", flag)
            ]))
            .is_ok(),
            "{flag}"
        );
    }
    for private in [
        "http://127.0.0.1:8000/v1",
        "http://10.0.0.5:8000/v1",
        "http://gpu-box:8000/v1",
        "http://vllm.lan/v1",
        "http://host.docker.internal:11434/v1",
        "http://[::1]:8000/v1",
    ] {
        assert!(
            LlmConfig::from_vars(vars(&[("READYHAI_LLM_URL", private)])).is_ok(),
            "{private}"
        );
    }
    // a cloud provider stays refused without the flag, whatever the URL
    assert!(
        LlmConfig::from_vars(vars(&[
            ("READYHAI_LLM_PROVIDER", "openai"),
            ("READYHAI_LLM_URL", "http://10.0.0.5/v1")
        ]))
        .is_err()
    );
    // a config assembled by hand cannot get around it: nothing is sent, nothing is probed
    let mut c = LlmConfig::resolve(Some("vllm"), None, false).unwrap();
    c.base_override = Some(public.into());
    assert!(c.guard().is_err());
    assert!(
        ask_json(&c, &mut Budget::per_run(), "s", "p")
            .unwrap_err()
            .to_string()
            .contains("refused")
    );
    assert!(!probe(&c) && probe_status(&c).is_none());
    assert!(query_models(&c).is_err());
    assert!(client(c).chat("s", &[], &[]).is_err());
}

#[test]
fn generic_api_key_wins_over_the_provider_key() {
    let provider_env = |k: &str| (k == "OPENAI_API_KEY").then(|| "provider-key".to_string());
    let own = LlmConfig::resolve(Some("openai"), None, true).unwrap();
    assert_eq!(
        key_with(&own, provider_env).unwrap().as_deref(),
        Some("provider-key")
    );
    let generic = LlmConfig::from_vars(vars(&[
        ("READYHAI_LLM_PROVIDER", "openai"),
        ("READYHAI_LLM_ALLOW_CLOUD", "1"),
        ("READYHAI_LLM_API_KEY", " generic-key\n"),
    ]))
    .unwrap();
    assert_eq!(
        key_with(&generic, provider_env).unwrap().as_deref(),
        Some("generic-key")
    );
    assert_eq!(
        key_with(&generic, |_| None).unwrap().as_deref(),
        Some("generic-key"),
        "the provider variable is not needed"
    );
    // neither set: the error names the variables, never a value
    let e = key_with(&own, |_| None).unwrap_err().to_string();
    assert!(
        e.contains("OPENAI_API_KEY") && e.contains("READYHAI_LLM_API_KEY"),
        "{e}"
    );
    assert!(key_with(&own, |_| Some("  ".into())).is_err());
    // local providers need no key, but accept the generic one
    let local = LlmConfig::resolve(Some("ollama"), None, false).unwrap();
    assert_eq!(key_with(&local, |_| Some("x".into())).unwrap(), None);
    let local_keyed = LlmConfig::from_vars(vars(&[
        ("READYHAI_LLM_PROVIDER", "ollama"),
        ("READYHAI_LLM_API_KEY", "local-key"),
    ]))
    .unwrap();
    assert_eq!(
        key_with(&local_keyed, |_| None).unwrap().as_deref(),
        Some("local-key")
    );
    // a key that cannot be a header value is an error, not a silently dropped header
    let bad = LlmConfig::from_vars(vars(&[("READYHAI_LLM_API_KEY", "a\nb")])).unwrap();
    let e = key_with(&bad, |_| None).unwrap_err().to_string();
    assert!(
        e.contains("control character") && !e.contains("a\nb"),
        "{e}"
    );
}

#[test]
fn key_goes_out_as_bearer_or_x_api_key_and_is_never_shown() {
    const K: &str = "generic-test-key-0123456789abcdef";
    let wire = |m: &mock::Mock| m.requests.lock().unwrap()[0].to_ascii_lowercase();
    let secret = K.to_ascii_lowercase();

    // OpenAI-compatible: bearer
    let m = mock::start(|_| "{\"ok\": true}".into());
    let mut c = mock::cfg(&m.base, &tmpdir("key-openai"));
    c.api_key = Some(ApiKey::new(K));
    ask_json(&c, &mut Budget::per_run(), "s", "p").unwrap();
    let raw = wire(&m);
    assert!(
        raw.contains(&format!("authorization: bearer {secret}")),
        "{raw}"
    );
    assert!(!raw.contains("x-api-key"));

    // Anthropic transport: x-api-key plus the version header, no bearer
    let m = mock::start_status(|_, _| {
        (
            200,
            json!({"content": [{"type": "text", "text": "{\"ok\": true}"}]}).to_string(),
        )
    });
    let mut a = LlmConfig::resolve(Some("anthropic"), None, true).unwrap();
    a.base_override = Some(m.base.clone());
    a.cache_dir = Some(tmpdir("key-anthropic"));
    a.retry_base_ms = 1;
    a.api_key = Some(ApiKey::new(K));
    ask_json(&a, &mut Budget::per_run(), "s", "p").unwrap();
    let raw = wire(&m);
    assert!(raw.contains(&format!("x-api-key: {secret}")), "{raw}");
    assert!(raw.contains("anthropic-version: 2023-06-01"));
    assert!(!raw.contains("authorization"));
    // the status probe authenticates the same way
    assert_eq!(probe_status(&a), Some(200));

    // nothing a human or a log can see carries it
    for s in [
        format!("{a:?}"),
        a.describe(),
        a.thinking_summary(),
        format!("{:?}", ApiKey::new(K)),
    ] {
        assert!(!s.contains(K), "{s}");
    }
    assert!(format!("{a:?}").contains("<redacted>"));
    let bad = mock::start_status(|_, _| (401, "{}".into()));
    let mut c = mock::cfg(&bad.base, &tmpdir("key-err"));
    c.api_key = Some(ApiKey::new(K));
    let e = format!(
        "{:#}",
        ask_json(&c, &mut Budget::per_run(), "s", "p").unwrap_err()
    );
    assert!(e.contains("401") && !e.contains(K), "{e}");
}

#[test]
fn model_list_parsing() {
    assert_eq!(parse_model_list("a, b ,,a,c"), ["a", "b", "c"]);
    assert!(parse_model_list(" , ").is_empty());
    let c = LlmConfig::from_vars(vars(&[("READYHAI_LLM_MODEL", "m1, m2,m3")])).unwrap();
    assert_eq!(c.model, "m1");
    assert_eq!(c.models, ["m1", "m2", "m3"]);
    assert_eq!(c.describe(), "vllm/m1 (+2 fallbacks)");
    // READYHAI_LLM_MODELS is an alias, used only when READYHAI_LLM_MODEL is unset
    let c = LlmConfig::from_vars(vars(&[("READYHAI_LLM_MODELS", "x,y")])).unwrap();
    assert_eq!(
        (c.model.as_str(), c.describe()),
        ("x", "vllm/x (+1 fallback)".into())
    );
    let c = LlmConfig::from_vars(vars(&[
        ("READYHAI_LLM_MODEL", "only"),
        ("READYHAI_LLM_MODELS", "x,y"),
    ]))
    .unwrap();
    assert_eq!(c.models, ["only"]);
    assert_eq!(c.describe(), "vllm/only");
    // nothing (or only separators): the provider default
    for v in [vars(&[]), vars(&[("READYHAI_LLM_MODEL", ",")])] {
        let c = LlmConfig::from_vars(v).unwrap();
        assert_eq!(c.models, ["qwen3.8-flash-next"]);
    }
    let o = LlmConfig::resolve(Some("ollama"), Some("p,q"), false).unwrap();
    assert_eq!((o.model.as_str(), o.models.len()), ("p", 2));
    // `model` stays the source of truth for the primary even when a caller reassigns it
    let mut c = LlmConfig::resolve(Some("ollama"), Some("m1,m2,m3"), false).unwrap();
    c.model = "other".into();
    assert_eq!(c.model_chain(), ["other", "m1", "m2", "m3"]);
    c.model = "m2".into();
    assert_eq!(c.model_chain(), ["m2", "m1", "m3"]);
}

fn fallback_cfg(m: &mock::Mock, name: &str, models: &str) -> LlmConfig {
    let mut c = mock::cfg(&m.base, &tmpdir(name));
    c.models = parse_model_list(models);
    c.model = c.models[0].clone();
    c
}

#[test]
fn failed_calls_fall_back_to_the_next_model_in_order() {
    // m1: 500 (retried once), m2: 404 (not retried), m3: answers
    let m = mock::start_status(|_, body| match model_of(body).as_str() {
        "m1" => (500, "{}".into()),
        "m2" => (404, "{}".into()),
        _ => (200, ok_body("{\"ok\": true}")),
    });
    let c = fallback_cfg(&m, "fallback", "m1,m2,m3");
    let mut b = Budget::per_run();
    assert_eq!(ask_json(&c, &mut b, "s", "p").unwrap()["ok"], true);
    assert_eq!(models_seen(&m), ["m1", "m1", "m2", "m3"]);
    assert_eq!(b.calls, 1, "fallbacks are part of one logical call");

    // an unusable answer (reasoning only / empty) is a failure too
    let m = mock::start_status(|_, body| {
        if model_of(body) == "m1" {
            (200, ok_body(""))
        } else {
            (200, ok_body("{\"ok\": true}"))
        }
    });
    let c = fallback_cfg(&m, "fallback-empty", "m1,m2");
    assert_eq!(
        ask_json(&c, &mut Budget::per_run(), "s", "p").unwrap()["ok"],
        true
    );
    assert_eq!(models_seen(&m), ["m1", "m2"]);

    // a healthy primary never touches the fallbacks
    let m = mock::start(|_| "{\"ok\": true}".into());
    let c = fallback_cfg(&m, "fallback-unused", "m1,m2");
    ask_json(&c, &mut Budget::per_run(), "s", "p").unwrap();
    assert_eq!(models_seen(&m), ["m1"]);
}

#[test]
fn when_every_model_fails_the_error_names_them_all() {
    let m = mock::start_status(|_, _| (401, "{}".into()));
    let c = fallback_cfg(&m, "fallback-all", "m1,m2");
    let e = ask_json(&c, &mut Budget::per_run(), "s", "p")
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("all 2 configured models failed") && e.contains("'m1'") && e.contains("'m2'"),
        "{e}"
    );
    assert_eq!(models_seen(&m), ["m1", "m2"], "401 is not retried");
    // one model: its own error, unchanged
    let m = mock::start_status(|_, _| (401, "{}".into()));
    let c = fallback_cfg(&m, "fallback-one", "m1");
    let e = ask_json(&c, &mut Budget::per_run(), "s", "p")
        .unwrap_err()
        .to_string();
    assert!(!e.contains("configured models") && e.contains("401"), "{e}");
}

#[test]
fn chat_clients_fall_back_too() {
    let msgs = [Msg {
        role: "user".into(),
        content: "hi".into(),
    }];
    // OpenAI-compatible
    let m = mock::start_status(|_, body| match model_of(body).as_str() {
        "m1" => (400, "{}".into()),
        _ => (200, ok_body("hello")),
    });
    let c = fallback_cfg(&m, "chat-openai", "m1,m2");
    assert_eq!(client(c).chat("sys", &msgs, &[]).unwrap().text, "hello");
    assert_eq!(models_seen(&m), ["m1", "m2"]);

    // Anthropic Messages, through both chat() and the single-shot path
    let answer = |body: &str| match model_of(body).as_str() {
        "m1" => (400, "{}".to_string()),
        _ => (
            200,
            json!({"content": [{"type": "text", "text": "{\"ok\": true}"}]}).to_string(),
        ),
    };
    let m = mock::start_status(move |_, body| answer(body));
    let mut a = LlmConfig::resolve(Some("anthropic"), Some("m1,m2"), true).unwrap();
    a.base_override = Some(m.base.clone());
    a.cache_dir = Some(tmpdir("chat-anthropic"));
    a.retry_base_ms = 1;
    a.api_key = Some(ApiKey::new("k"));
    assert_eq!(
        client(a.clone()).chat("sys", &msgs, &[]).unwrap().text,
        "{\"ok\": true}"
    );
    assert_eq!(models_seen(&m), ["m1", "m2"]);
    assert_eq!(
        ask_json(&a, &mut Budget::per_run(), "s", "p").unwrap()["ok"],
        true
    );
    assert_eq!(models_seen(&m), ["m1", "m2", "m1", "m2"]);
}

fn tool() -> ToolDef {
    ToolDef {
        name: "t".into(),
        description: "d".into(),
        schema: json!({"type": "object"}),
    }
}

#[test]
fn body_shapes() {
    let msgs = [Msg {
        role: "user".into(),
        content: "hi".into(),
    }];
    let o = OpenAiClient {
        cfg: LlmConfig::resolve(Some("ollama"), None, false).unwrap(),
    };
    let b = o.body("sys", &msgs, &[tool()]);
    assert_eq!(b["messages"][0]["role"], "system");
    assert_eq!(b["tools"][0]["function"]["name"], "t");
    let a = AnthropicClient {
        cfg: LlmConfig::resolve(Some("anthropic"), None, true).unwrap(),
    };
    let b = a.body("sys", &msgs, &[tool()]);
    assert_eq!(b["system"], "sys");
    assert_eq!(b["tools"][0]["input_schema"]["type"], "object");
    assert_eq!(b["messages"][0]["content"], "hi");
}

#[test]
fn think_and_json() {
    let v = parse_json_object("<think>hmm {x}</think>\n```json\n{\"a\": 1}\n```").unwrap();
    assert_eq!(v["a"], 1);
    assert!(parse_json_object("not json").is_err());
    assert!(parse_json_object("{broken").is_err());
    assert_eq!(strip_think("a<think>b"), "a");
}

#[test]
fn probe_and_cloud() {
    let d = std::env::temp_dir().join("rh-llm-probe");
    let m = mock::start(|_| "{}".into());
    assert!(probe(&mock::cfg(&m.base, &d)));
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = format!("http://{}/v1", l.local_addr().unwrap());
    drop(l);
    let t = std::time::Instant::now();
    assert!(!probe(&mock::cfg(&dead, &d)));
    assert!(t.elapsed().as_secs() < 3);
    let mut c = LlmConfig::resolve(Some("anthropic"), None, true).unwrap();
    c.allow_cloud = false;
    let mut b = Budget::per_run();
    assert!(
        ask_json(&c, &mut b, "s", "p")
            .unwrap_err()
            .to_string()
            .contains("refused")
    );
}

#[test]
fn cache_and_budget() {
    let d = std::env::temp_dir().join(format!("rh-llm-cache-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let m = mock::start(|_| "<think>x</think>{\"ok\": true}".into());
    let c = mock::cfg(&m.base, &d);
    let mut b = Budget::new(2, Duration::from_secs(60));
    assert_eq!(ask_json(&c, &mut b, "s", "p1").unwrap()["ok"], true);
    assert_eq!(ask_json(&c, &mut b, "s", "p1").unwrap()["ok"], true);
    assert_eq!(m.chat_hits.load(Ordering::SeqCst), 1);
    assert!(ask_json(&c, &mut b, "s", "p2").is_ok());
    assert!(
        ask_json(&c, &mut b, "s", "p3")
            .unwrap_err()
            .to_string()
            .contains("budget")
    );
    assert_eq!(m.chat_hits.load(Ordering::SeqCst), 2);
}

fn tmpdir(n: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("rh-llm-{n}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn ok_body(content: &str) -> String {
    json!({"choices": [{"message": {"role": "assistant", "content": content}}]}).to_string()
}

#[test]
fn retries_429_and_5xx_with_backoff_then_succeeds() {
    let m = mock::start_status(|hit, _| match hit {
        0 => (429, "{\"error\":\"slow down\"}".into()),
        1 => (503, "{\"error\":\"busy\"}".into()),
        _ => (200, ok_body("{\"ok\": true}")),
    });
    let c = mock::cfg(&m.base, &tmpdir("retry"));
    let mut b = Budget::per_run();
    assert_eq!(ask_json(&c, &mut b, "s", "p").unwrap()["ok"], true);
    assert_eq!(
        m.chat_hits.load(Ordering::SeqCst),
        3,
        "two transient failures then success"
    );
    assert_eq!(b.calls, 1, "retries are one logical call");
}

#[test]
fn gives_up_after_max_attempts_and_does_not_retry_client_errors() {
    let m = mock::start_status(|_, _| (500, "{\"error\":\"boom\"}".into()));
    let c = mock::cfg(&m.base, &tmpdir("giveup"));
    assert!(ask_json(&c, &mut Budget::per_run(), "s", "p").is_err());
    assert_eq!(
        m.chat_hits.load(Ordering::SeqCst),
        2,
        "a 5xx is retried once, not max_attempts times"
    );

    // 429 keeps the full retry budget (Retry-After is honoured by the mock as 0)
    let m = mock::start_status(|_, _| (429, "{\"error\":\"slow\"}".into()));
    let c = mock::cfg(&m.base, &tmpdir("giveup-429"));
    assert!(ask_json(&c, &mut Budget::per_run(), "s", "p").is_err());
    assert_eq!(m.chat_hits.load(Ordering::SeqCst) as u32, c.max_attempts);

    let m = mock::start_status(|_, _| (401, "{\"error\":\"nope\"}".into()));
    let c = mock::cfg(&m.base, &tmpdir("noretry"));
    assert!(ask_json(&c, &mut Budget::per_run(), "s", "p").is_err());
    assert_eq!(m.chat_hits.load(Ordering::SeqCst), 1, "401 is not retried");
}

/// A server that accepts connections and never answers; the counter is how many arrived.
fn silent_server() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}/v1", l.local_addr().unwrap());
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let a2 = accepted.clone();
    std::thread::spawn(move || {
        let mut held = vec![];
        for s in l.incoming().flatten() {
            a2.fetch_add(1, Ordering::SeqCst);
            held.push(s); // accept and never answer
        }
    });
    (base, accepted)
}

fn body_of(req: &str) -> Value {
    serde_json::from_str(req.split("\r\n\r\n").nth(1).unwrap()).unwrap()
}

fn sent_bodies(m: &mock::Mock) -> Vec<Value> {
    m.requests
        .lock()
        .unwrap()
        .iter()
        .map(|r| body_of(r))
        .collect()
}

#[test]
fn a_timeout_is_not_retried_identically() {
    let (base, accepted) = silent_server();
    let mut c = mock::cfg(&base, &tmpdir("timeout"));
    c.timeout_override = Some(Duration::from_millis(200));
    let t = std::time::Instant::now();
    // 2048 tokens -> one smaller request (1024); then nothing would change, so it stops
    let e = ask_json(&c, &mut Budget::per_run(), "s", "p").unwrap_err();
    assert!(is_timeout_error(&e), "{e:#}");
    assert!(e.to_string().contains("timed out"), "{e:#}");
    assert!(e.to_string().contains("max_tokens"), "{e:#}");
    assert_eq!(accepted.load(Ordering::SeqCst), 2, "{e:#}");
    assert!(t.elapsed() < Duration::from_secs(5));

    // the chat clients send once per model and do not repeat a timed-out request
    let before = accepted.load(Ordering::SeqCst);
    let msgs = [Msg {
        role: "user".into(),
        content: "hi".into(),
    }];
    let e = client(c).chat("sys", &msgs, &[]).unwrap_err();
    assert!(is_timeout_error(&e), "{e:#}");
    assert_eq!(accepted.load(Ordering::SeqCst), before + 1);
}

#[test]
fn call_timeout_scales_with_the_answer_size() {
    // 20 s + max_tokens / 40, clamped to 30..=300
    assert_eq!(call_timeout_secs(1), 30);
    assert_eq!(call_timeout_secs(400), 30);
    assert_eq!(call_timeout_secs(2048), 71);
    assert_eq!(call_timeout_secs(10_240), 276);
    assert_eq!(call_timeout_secs(34_816), 300);
    assert_eq!(call_timeout_secs(u32::MAX), 300);
    let mut c = LlmConfig::resolve(Some("vllm"), None, false).unwrap();
    assert_eq!(c.call_timeout(10_240), Duration::from_secs(276));
    c.timeout_override = Some(Duration::from_secs(45));
    assert_eq!(c.call_timeout(10_240), Duration::from_secs(45));
    assert_eq!(c.call_timeout(1), Duration::from_secs(45));
}

#[test]
fn timeout_env_override() {
    let base = ("READYHAI_LLM_URL", "http://localhost:8000/v1");
    let get = |v: &str| LlmConfig::from_vars(vars(&[base, ("READYHAI_LLM_TIMEOUT_SECS", v)]));
    assert_eq!(
        get("45").unwrap().timeout_override,
        Some(Duration::from_secs(45))
    );
    assert_eq!(
        get(" 7 ").unwrap().timeout_override,
        Some(Duration::from_secs(7))
    );
    assert_eq!(get("").unwrap().timeout_override, None, "empty is unset");
    assert!(
        LlmConfig::from_vars(vars(&[base]))
            .unwrap()
            .timeout_override
            .is_none()
    );
    for bad in ["abc", "0", "-3", "3601", "1.5"] {
        let e = get(bad).unwrap_err().to_string();
        assert!(e.contains("READYHAI_LLM_TIMEOUT_SECS"), "{bad}: {e}");
    }
}

#[test]
fn downgrade_halves_tokens_to_a_floor_and_stops_when_nothing_changes() {
    assert_eq!(downgrade(34_816, true), Some(17_408));
    assert_eq!(downgrade(2048, false), Some(1024));
    assert_eq!(downgrade(1500, false), Some(1024));
    assert_eq!(
        downgrade(1024, true),
        Some(1024),
        "dropping the effort is a change"
    );
    assert_eq!(downgrade(1024, false), None);
    assert_eq!(downgrade(512, false), None, "never grows");
}

fn thinking_cfg(m: &mock::Mock, name: &str, models: &str) -> LlmConfig {
    let mut c = fallback_cfg(m, name, models);
    c.thinking = true;
    c.thinking_budget_tokens = 8192;
    c.model_tier = "high".into();
    c.timeout_override = Some(Duration::from_millis(500));
    c
}

fn max_tokens_of(b: &Value) -> u64 {
    b["max_tokens"].as_u64().unwrap()
}

#[test]
fn a_timed_out_call_is_retried_smaller_and_without_reasoning() {
    // answers fast once the request is under 6000 tokens; a bigger one outlasts the 500 ms timeout
    let m = mock::start_status(|_, body| {
        let big = serde_json::from_str::<Value>(body).unwrap()["max_tokens"]
            .as_u64()
            .unwrap()
            > 6000;
        if big {
            std::thread::sleep(Duration::from_millis(650));
        }
        (200, ok_body("{\"ok\": true}"))
    });
    let c = thinking_cfg(&m, "downgrade-ok", "m1");
    let mut b = Budget::per_run();
    assert_eq!(ask_json(&c, &mut b, "s", "p").unwrap()["ok"], true);
    let bodies = sent_bodies(&m);
    assert_eq!(bodies.len(), 2, "{bodies:?}");
    assert_eq!(max_tokens_of(&bodies[0]), 10_240);
    assert_eq!(bodies[0]["reasoning_effort"], "high");
    assert_eq!(max_tokens_of(&bodies[1]), 5120);
    assert!(bodies[1].get("reasoning_effort").is_none(), "{}", bodies[1]);
    assert_eq!(b.calls, 1, "the retry is part of one logical call");
    let note = b.notes.join(" | ");
    assert!(
        note.contains("timed out") && note.contains("succeeded") && note.contains("5120"),
        "{note}"
    );
    assert!(!note.contains("Bearer"), "{note}");
}

#[test]
fn at_most_two_downgrades_then_the_next_model() {
    // m1 never answers in time; m2 answers
    let m = mock::start_status(|_, body| {
        if model_of(body) == "m1" {
            std::thread::sleep(Duration::from_millis(550));
        }
        (200, ok_body("{\"ok\": true}"))
    });
    let c = thinking_cfg(&m, "downgrade-chain", "m1,m2");
    let mut b = Budget::per_run();
    assert_eq!(ask_json(&c, &mut b, "s", "p").unwrap()["ok"], true);
    assert_eq!(models_seen(&m), ["m1", "m1", "m1", "m2"]);
    let sizes: Vec<u64> = sent_bodies(&m).iter().map(max_tokens_of).collect();
    // the next model starts again from the full request
    assert_eq!(sizes, [10_240, 5120, 2560, 10_240]);
    assert!(
        b.notes.iter().any(|n| n.contains("gave up")),
        "{:?}",
        b.notes
    );

    // with no model left the error says what was tried
    let m = mock::start_status(|_, _| {
        std::thread::sleep(Duration::from_millis(550));
        (200, ok_body("{}"))
    });
    let c = thinking_cfg(&m, "downgrade-exhausted", "m1");
    let e = ask_json(&c, &mut Budget::per_run(), "s", "p").unwrap_err();
    assert!(is_timeout_error(&e), "{e:#}");
    let msg = e.to_string();
    assert!(
        msg.contains("3 time(s)")
            && msg.contains("max_tokens 10240")
            && msg.contains("max_tokens 2560"),
        "{msg}"
    );
}

#[test]
fn a_server_error_is_retried_once_then_the_next_model_is_tried() {
    let m = mock::start_status(|_, body| {
        if model_of(body) == "m1" {
            (500, "{}".into())
        } else {
            (200, ok_body("{\"ok\": true}"))
        }
    });
    let c = fallback_cfg(&m, "five-hundred", "m1,m2");
    assert_eq!(
        ask_json(&c, &mut Budget::per_run(), "s", "p").unwrap()["ok"],
        true
    );
    assert_eq!(models_seen(&m), ["m1", "m1", "m2"]);
    // a 500 that heals on the retry stays on the same model
    let m = mock::start_status(|hit, _| {
        if hit == 0 {
            (500, "{}".into())
        } else {
            (200, ok_body("{\"ok\": true}"))
        }
    });
    let c = fallback_cfg(&m, "five-hundred-heals", "m1,m2");
    ask_json(&c, &mut Budget::per_run(), "s", "p").unwrap();
    assert_eq!(models_seen(&m), ["m1", "m1"]);
}

#[test]
fn probe_latency_sends_a_one_token_completion() {
    let m = mock::start(|_| {
        std::thread::sleep(Duration::from_millis(120));
        "x".into()
    });
    let c = mock::cfg(&m.base, &tmpdir("latency"));
    let d = probe_latency(&c).unwrap();
    assert!(
        d >= Duration::from_millis(120) && d < Duration::from_secs(5),
        "{d:?}"
    );
    let bodies = sent_bodies(&m);
    assert_eq!(bodies.len(), 1);
    assert_eq!(max_tokens_of(&bodies[0]), 1);
    assert!(bodies[0].get("reasoning_effort").is_none());
    assert!(
        bodies[0].to_string().len() < 200,
        "tiny prompt: {}",
        bodies[0]
    );
    let r = latency_report(&Ok(d));
    assert!(
        r.summary.starts_with("latency ") && r.summary.ends_with(" ms"),
        "{r:?}"
    );
    assert!(!r.slow);
}

#[test]
fn probe_latency_times_out_although_models_answers() {
    let m = mock::start_status(|_, _| {
        std::thread::sleep(Duration::from_millis(700));
        (200, ok_body("x"))
    });
    let mut c = mock::cfg(&m.base, &tmpdir("latency-slow"));
    c.timeout_override = Some(Duration::from_millis(300));
    let e = probe_latency(&c).unwrap_err();
    assert!(is_timeout_error(&e), "{e:#}");
    assert!(probe(&c), "/models answers: the server is up");
    let r = latency_report(&Err(e));
    assert!(r.slow && r.summary.contains("timed out"), "{r:?}");
    // an HTTP error is a failed probe, not a slow endpoint
    let bad = mock::start_status(|_, _| (401, "{}".into()));
    let c = mock::cfg(&bad.base, &tmpdir("latency-401"));
    let r = latency_report(&probe_latency(&c));
    assert!(!r.slow && r.summary.contains("401"), "{r:?}");
    // unreachable
    let mut c = LlmConfig::resolve(Some("vllm"), None, false).unwrap();
    c.base_override = Some("http://127.0.0.1:1/v1".into());
    assert!(probe_latency(&c).is_err());
}

#[test]
fn latency_above_ten_seconds_is_slow() {
    assert!(!latency_report(&Ok(Duration::from_millis(840))).slow);
    assert!(!latency_report(&Ok(SLOW_LATENCY)).slow);
    assert!(latency_report(&Ok(Duration::from_millis(10_001))).slow);
    assert_eq!(
        latency_report(&Ok(Duration::from_millis(840))).summary,
        "latency 840 ms"
    );
}

#[test]
fn a_slow_endpoint_caps_thinking_at_the_high_tier() {
    let base = LlmConfig::resolve(Some("vllm"), None, false).unwrap();
    let think = |on: bool, tier: &str, budget: u32| base.clone().with_thinking(on, tier, budget);
    let c = think(true, "max_pro", 32_768);
    let capped = c.capped_to_high_tier().unwrap();
    assert_eq!(capped.model_tier, "high");
    assert_eq!(capped.thinking_budget_tokens, 8192);
    assert_eq!(call_params(&capped).max_tokens, 10_240);
    assert!(think(true, "high", 8192).capped_to_high_tier().is_none());
    assert!(think(true, "medium", 2048).capped_to_high_tier().is_none());
    assert!(think(false, "max", 32_768).capped_to_high_tier().is_none());
    // a big budget under a lower tier name is held to the High budget, the name is kept
    let k = think(true, "medium", 20_000).capped_to_high_tier().unwrap();
    assert_eq!(
        (k.model_tier.as_str(), k.thinking_budget_tokens),
        ("medium", 8192)
    );
}

#[test]
fn gate_and_triage_calls_never_think() {
    let m = mock::start(|_| "{\"ok\": true}".into());
    let mut c = mock::cfg(&m.base, &tmpdir("light"));
    c = c.with_thinking(true, "max_pro", 32_768);
    // the planner's config reasons ...
    ask_json(&c, &mut Budget::per_run(), "s", "planner").unwrap();
    // ... the gate's and the triager's do not
    ask_json(&c.without_thinking(), &mut Budget::per_run(), "s", "gate").unwrap();
    let bodies = sent_bodies(&m);
    assert_eq!(max_tokens_of(&bodies[0]), 34_816);
    assert_eq!(bodies[0]["reasoning_effort"], "high");
    assert_eq!(max_tokens_of(&bodies[1]), 2048);
    assert!(bodies[1].get("reasoning_effort").is_none(), "{}", bodies[1]);
}

#[test]
fn reasoning_field_is_never_the_answer() {
    let m = mock::start_status(|_, _| {
        (200, json!({"choices": [{"finish_reason": "length", "message": {"role": "assistant", "content": "", "reasoning": "thinking... {\"ok\": true}"}}]}).to_string())
    });
    let d = tmpdir("reasoning");
    let c = mock::cfg(&m.base, &d);
    let e = ask_json(&c, &mut Budget::per_run(), "s", "p")
        .unwrap_err()
        .to_string();
    assert!(e.contains("reasoning"), "{e}");
    assert!(
        !d.exists() || std::fs::read_dir(&d).map(|r| r.count()).unwrap_or(0) == 0,
        "nothing cached"
    );
}

#[test]
fn schema_invalid_output_is_not_cached_and_valid_is() {
    let m = mock::start_status(|hit, _| {
        if hit == 0 {
            (200, ok_body("{\"wrong\": 1}"))
        } else {
            (200, ok_body("{\"summary\": \"fine\"}"))
        }
    });
    let d = tmpdir("schema");
    let c = mock::cfg(&m.base, &d);
    let need_summary = |v: &Value| {
        if v["summary"].is_string() {
            Ok(())
        } else {
            bail!("summary missing")
        }
    };
    let mut b = Budget::per_run();
    let e = ask_json_with(&c, &mut b, "s", "p", need_summary)
        .unwrap_err()
        .to_string();
    assert!(e.contains("schema"), "{e}");
    assert!(
        !d.exists() || std::fs::read_dir(&d).unwrap().count() == 0,
        "invalid output must not be cached"
    );
    // same prompt again: asks the model again (nothing was cached), now valid, now cached
    assert_eq!(
        ask_json_with(&c, &mut b, "s", "p", need_summary).unwrap()["summary"],
        "fine"
    );
    assert_eq!(m.chat_hits.load(Ordering::SeqCst), 2);
    assert_eq!(
        ask_json_with(&c, &mut b, "s", "p", need_summary).unwrap()["summary"],
        "fine"
    );
    assert_eq!(
        m.chat_hits.load(Ordering::SeqCst),
        2,
        "valid output served from cache"
    );
    // a cached entry that fails a stricter validator is ignored and re-asked
    let strict = |v: &Value| {
        if v["other"].is_string() {
            Ok(())
        } else {
            bail!("other missing")
        }
    };
    assert!(ask_json_with(&c, &mut b, "s", "p", strict).is_err());
    assert_eq!(m.chat_hits.load(Ordering::SeqCst), 3);
}

#[derive(serde::Deserialize, Debug)]
struct Out {
    items: Vec<String>,
}

#[test]
fn ask_typed_validates_with_serde() {
    let m = mock::start(|_| "{\"items\": \"not-a-list\"}".into());
    let c = mock::cfg(&m.base, &tmpdir("typed"));
    assert!(ask_typed::<Out>(&c, &mut Budget::per_run(), "s", "p", |_| Ok(())).is_err());
    let m = mock::start(|_| "{\"items\": [\"a\"]}".into());
    let c = mock::cfg(&m.base, &tmpdir("typed2"));
    let o = ask_typed::<Out>(&c, &mut Budget::per_run(), "s", "p", |o| {
        if o.items.is_empty() {
            bail!("empty")
        } else {
            Ok(())
        }
    })
    .unwrap();
    assert_eq!(o.items, ["a"]);
}

#[test]
fn redaction() {
    let t = "key sk-abcdef0123456789ABCD jwt eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.abcdefgh12345 password=hunter22x hash 0123456789abcdef0123456789abcdef ok";
    let r = redact_for_llm(t);
    assert!(
        !r.contains("sk-abc")
            && !r.contains("eyJ")
            && !r.contains("hunter22")
            && !r.contains("0123456789abcdef0123")
    );
    assert!(r.contains("ok"));
}

#[test]
fn redaction_by_key_name_suffix_in_text() {
    let t = "DB_PASSWORD=s3cr3tvalue\nSTRIPE_SECRET: abc123\nAPP_KEY=base64:zzzz\n{\"admin_password\": \"p@ss\", \"user\": \"bob\"}\nAuthorization: Bearer abcdef.ghijkl.mnopqr\npostgres://svc:pw1234@db.internal/x\nplain: value";
    let r = redact_for_llm(t);
    for leak in [
        "s3cr3tvalue",
        "abc123",
        "base64:zzzz",
        "p@ss",
        "abcdef.ghijkl",
        "pw1234",
    ] {
        assert!(!r.contains(leak), "leaked {leak} in {r}");
    }
    assert!(
        r.contains("\"user\": \"bob\"") && r.contains("plain: value") && r.contains("db.internal"),
        "{r}"
    );
}

#[test]
fn redact_value_is_structural() {
    let tok_secret = format!("abcdef{}", "123456");
    let tok_val = format!("token={tok_secret}");
    let v = json!({"PASSWORD": "x", "db": {"user_secret": ["a", "b"], "host": "h"}, "arr": [{"api_key": 1}, tok_val], "n": 5, "nul": null});
    let r = redact_value(&v);
    assert_eq!(r["PASSWORD"], "[REDACTED]");
    assert_eq!(r["db"]["user_secret"], "[REDACTED]");
    assert_eq!(r["db"]["host"], "h");
    assert_eq!(r["arr"][0]["api_key"], "[REDACTED]");
    assert!(!r["arr"][1].as_str().unwrap().contains(&tok_secret));
    assert_eq!(r["n"], 5);
    assert!(
        is_sensitive_key("x-api-key")
            && is_sensitive_key("stripeKey")
            && is_sensitive_key("MY_SECRET")
            && !is_sensitive_key("monkey")
            && !is_sensitive_key("title")
    );
}

#[test]
fn atomic_write_replaces_whole_file() {
    let d = tmpdir("atomic");
    let p = d.join("sub").join("f.json");
    write_atomic(&p, b"one").unwrap();
    write_atomic(&p, b"two-two").unwrap();
    assert_eq!(std::fs::read_to_string(&p).unwrap(), "two-two");
    assert!(
        std::fs::read_dir(p.parent().unwrap()).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp"))
    );
}

#[test]
fn thinking_budget_arithmetic_cannot_overflow_and_is_clamped() {
    // `budget + 2048` used to overflow u32 for a hostile budget
    for hostile in [
        0,
        1,
        1023,
        8192,
        32768,
        32769,
        u32::MAX - 2047,
        u32::MAX - 1,
        u32::MAX,
    ] {
        let m = max_tokens_with_thinking(hostile);
        assert!(
            m <= MAX_OUTPUT_TOKENS && m > MIN_THINKING_BUDGET,
            "{hostile} -> {m}"
        );
        let c = clamp_thinking_budget(hostile);
        assert!(
            (MIN_THINKING_BUDGET..=MAX_THINKING_BUDGET).contains(&c),
            "{hostile} -> {c}"
        );
    }
    assert_eq!(
        max_tokens_with_thinking(u32::MAX),
        MAX_THINKING_BUDGET + 2048
    );
    assert_eq!(clamp_thinking_budget(0), MIN_THINKING_BUDGET);
    let cfg = LlmConfig::resolve(Some("ollama"), None, false)
        .unwrap()
        .with_thinking(true, "high", u32::MAX);
    assert_eq!(cfg.thinking_budget_tokens, MAX_THINKING_BUDGET);
    // even a config that bypassed `with_thinking` (pub field) cannot overflow the request
    for provider in ["ollama", "anthropic"] {
        let mut c = LlmConfig::resolve(Some(provider), None, true).unwrap();
        c.thinking = true;
        c.thinking_budget_tokens = u32::MAX;
        let p = call_params(&c);
        assert!(p.max_tokens <= MAX_OUTPUT_TOKENS, "{provider}: {p:?}");
        assert_eq!(p.temperature, Some(STRUCTURED_TEMPERATURE), "{provider}");
    }
}

#[test]
fn thinking_never_forces_temperature_one_on_structured_calls() {
    // OpenAI-compatible: reasoning effort rides along, temperature stays low
    let mut o = LlmConfig::resolve(Some("ollama"), None, false)
        .unwrap()
        .with_thinking(true, "max", 8192);
    let p = call_params(&o);
    assert_eq!(
        (p.temperature, p.reasoning_effort, p.anthropic_thinking),
        (Some(0.1), Some("high"), None)
    );
    o.thinking = false;
    assert_eq!(call_params(&o).reasoning_effort, None);
    // Anthropic: a thinking block would force temperature 1.0, so none is attached
    let a = LlmConfig::resolve(Some("anthropic"), None, true)
        .unwrap()
        .with_thinking(true, "high", 16000);
    let p = call_params(&a);
    assert_eq!(
        (p.temperature, p.anthropic_thinking, p.max_tokens),
        (Some(0.1), None, 2048)
    );
    // the log says what was sent, not that the budget was "forwarded"
    let s = a.thinking_summary();
    assert!(
        s.contains("NOT sent") && s.contains("temperature 1.0"),
        "{s}"
    );
    let s = o.with_thinking(true, "medium", 4096).thinking_summary();
    assert!(
        s.contains("reasoning_effort=medium")
            && s.contains("cap, not a reasoning allocation")
            && !s.contains("forwarded"),
        "{s}"
    );
}

#[test]
fn structured_call_carries_a_low_temperature_and_a_bounded_max_tokens_on_the_wire() {
    let m = mock::start(|_| "{\"ok\": true}".into());
    let mut c = mock::cfg(&m.base, &tmpdir("wire-temp"));
    c.thinking = true;
    c.thinking_budget_tokens = u32::MAX;
    c.model_tier = "high".into();
    assert_eq!(
        ask_json(&c, &mut Budget::per_run(), "s", "p").unwrap()["ok"],
        true
    );
    let raw = m.requests.lock().unwrap()[0].clone();
    let body: Value = serde_json::from_str(raw.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(body["temperature"], 0.1, "{body}");
    assert_eq!(body["reasoning_effort"], "high");
    let max = body["max_tokens"].as_u64().unwrap();
    assert!(max <= MAX_OUTPUT_TOKENS as u64 && max >= 4096, "{max}");
}

#[test]
fn calls_and_time_are_recorded_on_the_budget() {
    let m = mock::start(|_| {
        std::thread::sleep(Duration::from_millis(20));
        "{\"ok\": true}".into()
    });
    let c = mock::cfg(&m.base, &tmpdir("budget-time"));
    let mut b = Budget::per_run();
    ask_json(&c, &mut b, "s", "p").unwrap();
    ask_json(&c, &mut b, "s", "p").unwrap(); // cached: free
    assert_eq!(b.calls, 1);
    assert!(b.elapsed_ms() >= 20, "{}", b.elapsed_ms());
    // a failed call is still a call and its time still counts
    let bad = mock::start_status(|_, _| (401, "{}".into()));
    let c = mock::cfg(&bad.base, &tmpdir("budget-time-bad"));
    let mut b2 = Budget::per_run();
    assert!(ask_json(&c, &mut b2, "s", "p").is_err());
    assert_eq!(b2.calls, 1);
}

#[test]
fn connect_from_env_reports_a_reason() {
    let mut c = LlmConfig::resolve(Some("vllm"), None, false).unwrap();
    c.base_override = Some("http://127.0.0.1:1/v1".into());
    assert!(!probe(&c));
    assert_eq!(c.describe(), "vllm/qwen3.8-flash-next");
}
