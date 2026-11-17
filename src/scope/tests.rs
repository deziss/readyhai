//! Comprehensive unit tests for target scoping and egress gating.

use std::path::Path;

use super::config::{load_configured, Scope};
use super::decision::{check, check_host, egress_guard};
use super::dns::test_dns;
use super::git_guard::check_git_host;
use super::ip::{classify_host, is_internal_ip, HostClass};
use super::url::url_host;

fn scope(toml_text: &str) -> Scope {
    toml::from_str(toml_text).unwrap()
}

#[test]
fn hosts() {
    assert_eq!(
        url_host("https://user:pw@App.Example.com:8443/x?y").unwrap(),
        "app.example.com"
    );
    let s = scope(
        "[[hosts]]\nhost='*.nonprod.example'\nenv='nonprod'\n[[hosts]]\nhost='app.example'\nenv='prod'",
    );
    // listed entries use their env
    assert!(check("https://a.nonprod.example/", Some(&s)).unwrap());
    assert!(!check("https://app.example/", Some(&s)).unwrap());
    // an unlisted public host is allowed for full testing by default (nonprod = true)
    assert!(check("https://evil.example/", Some(&s)).unwrap());
    assert!(check("https://x.unlisted.example/", None).unwrap());
    assert!(check("https://nonprod.example/", Some(&s)).unwrap());
    assert!(check("https://anonprod.example/", Some(&s)).unwrap());
}

#[test]
fn internal_hosts_need_an_entry() {
    assert!(is_internal_ip("127.0.0.1".parse().unwrap()));
    assert!(is_internal_ip("10.1.2.3".parse().unwrap()));
    assert!(is_internal_ip("192.168.0.9".parse().unwrap()));
    assert!(is_internal_ip("169.254.169.254".parse().unwrap())); // cloud metadata
    assert!(is_internal_ip("100.100.0.1".parse().unwrap())); // CGNAT
    assert!(is_internal_ip("::1".parse().unwrap()));
    assert!(is_internal_ip("fd00:ec2::254".parse().unwrap())); // unique-local metadata
    assert!(!is_internal_ip("8.8.8.8".parse().unwrap()));
    assert!(!is_internal_ip("1.1.1.1".parse().unwrap()));
    // an unlisted internal IP target is refused
    assert!(check("http://169.254.169.254/latest/meta-data/", None).is_err());
    assert!(check("http://10.0.0.5:8080/", None).is_err());
    // but a listed internal host is allowed with its env
    let s = scope(
        "[[hosts]]\nhost='10.0.0.5'\nenv='nonprod'\n[[hosts]]\nhost='127.0.0.1'\nenv='prod'",
    );
    assert!(check("http://10.0.0.5:8080/", Some(&s)).unwrap());
    assert!(!check("http://127.0.0.1/", Some(&s)).unwrap()); // listed prod → read-only
}

#[test]
fn git_host_allowlist() {
    assert!(check_git_host("github.com", None).is_ok());
    assert!(check_git_host("gist.github.com", None).is_ok());
    assert!(check_git_host("gitlab.com", None).is_ok());
    // an unknown public host is allowed to clone (public code can live anywhere)
    assert!(check_git_host("git.example.com", None).is_ok());
    // an internal git host is refused unless listed under [git] hosts
    assert!(check_git_host("10.0.0.9", None).is_err());
    let s = scope("[git]\nhosts=['git.internal', '10.0.0.9']");
    assert!(check_git_host("10.0.0.9", Some(&s)).is_ok());
    assert!(check_git_host("git.internal", Some(&s)).is_ok());
}

#[test]
fn host_normalisation() {
    assert_eq!(url_host("http://[::1]:8080/x").unwrap(), "::1");
    assert_eq!(url_host("http://App.Example./").unwrap(), "app.example");
    let s = scope(
        "[[hosts]]\nhost='APP.example.'\nenv='nonprod'\n[[hosts]]\nhost='[::1]'\nenv='nonprod'",
    );
    assert!(check("http://app.example/", Some(&s)).unwrap());
    assert!(check("http://[::1]:9/", Some(&s)).unwrap());
}

#[test]
fn only_http_and_https() {
    for u in [
        "ftp://app.example/",
        "file:///etc/passwd",
        "ssh://app.example",
        "javascript:alert(1)",
        "app.example",
        "",
    ] {
        assert!(url_host(u).is_err(), "{u}");
    }
    assert!(url_host("HTTPS://app.example").is_ok());
}

#[test]
fn backslash_in_authority_uses_the_real_host() {
    let s = scope("[[hosts]]\nhost='allowed.internal'\nenv='nonprod'");
    assert_eq!(
        url_host("http://10.9.9.9\\@allowed.internal/").unwrap(),
        "10.9.9.9"
    );
    assert!(check("http://10.9.9.9\\@allowed.internal/", Some(&s)).is_err());
    assert!(egress_guard("http://10.9.9.9\\@allowed.internal/", Some(&s), false).is_err());

    let s = scope("[[hosts]]\nhost='app.example'\nenv='nonprod'");
    assert_eq!(
        url_host("http://app.example\\@evil.example/").unwrap(),
        "app.example"
    );
    let e = egress_guard("http://app.example\\@evil.example/x", Some(&s), false).unwrap();
    assert_eq!(e.host, "app.example");
    assert!(!e.url.contains('\\'), "{}", e.url);
    assert_eq!(url_host(&e.url).unwrap(), "app.example");

    for u in [
        "http://evil.example#@app.example/",
        "http://evil.example?@app.example/",
        "http://app.example@evil.example/",
        "http://app.example:80@evil.example/",
    ] {
        assert_eq!(url_host(u).unwrap(), "evil.example", "{u}");
    }
}

#[test]
fn overlapping_entries_exact_beats_wildcard() {
    for order in [
        "[[hosts]]\nhost='*.example'\nenv='prod'\n[[hosts]]\nhost='qa.example'\nenv='nonprod'",
        "[[hosts]]\nhost='qa.example'\nenv='nonprod'\n[[hosts]]\nhost='*.example'\nenv='prod'",
    ] {
        let s = scope(order);
        assert!(check("https://qa.example/", Some(&s)).unwrap(), "{order}");
        assert!(
            !check("https://other.example/", Some(&s)).unwrap(),
            "{order}"
        );
    }
    let s = scope(
        "[[hosts]]\nhost='*.example'\nenv='nonprod'\n[[hosts]]\nhost='www.example'\nenv='prod'",
    );
    assert!(!check("https://www.example/", Some(&s)).unwrap());
    assert!(check("https://dev.example/", Some(&s)).unwrap());
}

#[test]
fn overlapping_entries_prod_beats_nonprod() {
    for order in [
        "[[hosts]]\nhost='a.example'\nenv='nonprod'\n[[hosts]]\nhost='a.example'\nenv='prod'",
        "[[hosts]]\nhost='a.example'\nenv='prod'\n[[hosts]]\nhost='a.example'\nenv='nonprod'",
    ] {
        assert!(
            !check("https://a.example/", Some(&scope(order))).unwrap(),
            "{order}"
        );
    }
    for order in [
        "[[hosts]]\nhost='*.example'\nenv='prod'\n[[hosts]]\nhost='*.stage.example'\nenv='nonprod'",
        "[[hosts]]\nhost='*.stage.example'\nenv='nonprod'\n[[hosts]]\nhost='*.example'\nenv='prod'",
    ] {
        assert!(
            !check("https://x.stage.example/", Some(&scope(order))).unwrap(),
            "{order}"
        );
    }
    let s = scope("[[hosts]]\nhost='a.example'\nenv='non-prod'");
    assert!(!check("https://a.example/", Some(&s)).unwrap());
}

#[test]
fn overlapping_equal_wildcards_are_order_independent() {
    let a = scope(
        "[[hosts]]\nhost='*.example'\nenv='nonprod'\n[[hosts]]\nhost='*.b.example'\nenv='nonprod'",
    );
    let b = scope(
        "[[hosts]]\nhost='*.b.example'\nenv='nonprod'\n[[hosts]]\nhost='*.example'\nenv='nonprod'",
    );
    assert_eq!(a.find("x.b.example").unwrap().host, "*.b.example");
    assert_eq!(b.find("x.b.example").unwrap().host, "*.b.example");
}

#[test]
fn egress_guard_gates_intrusive_actions() {
    let s = scope(
        "[[hosts]]\nhost='qa.example'\nenv='nonprod'\n[[hosts]]\nhost='www.example'\nenv='prod'",
    );
    assert!(egress_guard("https://www.example/", Some(&s), false).is_ok());
    assert!(
        !egress_guard("https://www.example/", Some(&s), false)
            .unwrap()
            .nonprod
    );
    let e = egress_guard("https://www.example/", Some(&s), true)
        .unwrap_err()
        .to_string();
    assert!(e.contains("prod") && e.contains("refused"), "{e}");
    assert!(
        egress_guard("https://qa.example/x", Some(&s), true)
            .unwrap()
            .nonprod
    );
    assert!(egress_guard("https://other.example/", Some(&s), false).is_ok());
    assert!(egress_guard("https://other.example/", Some(&s), true).is_ok());
    assert!(egress_guard("https://other.example/", None, true).is_ok());
    assert!(egress_guard("https://qa.example/", None, false).is_ok());
    assert!(egress_guard("http://127.0.0.1:8080/", None, true).is_err());
    assert!(egress_guard("ftp://qa.example/", Some(&s), false).is_err());

    let any_scope = scope("[[hosts]]\nhost='*'\nenv='nonprod'");
    assert!(egress_guard("https://deziss.com/", Some(&any_scope), true).is_ok());
    assert!(egress_guard("http://127.0.0.1:8080/", Some(&any_scope), true).is_ok());
}

#[test]
fn perf_resilience_fields() {
    let s: Scope = toml::from_str(
        "[[hosts]]\nhost='app.test'\nenv='nonprod'\n[hosts.perf]\nvus=50\nallow_heavy=true\n[hosts.resilience]\ncompose_project='shop'\nservices=['postgres','redis']",
    )
    .unwrap();
    let h = s.find("app.test").unwrap();
    assert_eq!(h.perf.as_ref().unwrap().vus, Some(50));
    assert!(h.perf.as_ref().unwrap().allow_heavy);
    assert_eq!(
        h.resilience.as_ref().unwrap().services,
        vec!["postgres", "redis"]
    );
    let s: Scope = toml::from_str("[[hosts]]\nhost='a'\nenv='prod'").unwrap();
    assert!(s.hosts[0].perf.is_none() && s.hosts[0].resilience.is_none());
}

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("readyhai-scope-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn an_unloadable_scope_is_refused_never_treated_as_no_scope() {
    let d = tmp_dir("unloadable");
    let missing = d.join("scope.toml");
    let e = format!("{:#}", Scope::load(&missing).unwrap_err());
    assert!(
        e.contains("cannot be read") && e.contains("scope.example.toml"),
        "{e}"
    );

    let dir = d.join("adir");
    std::fs::create_dir_all(&dir).unwrap();
    let e = format!("{:#}", Scope::load(&dir).unwrap_err());
    assert!(
        e.contains("is a directory") && e.contains("cp scope.example.toml scope.toml"),
        "{e}"
    );

    let bad = d.join("bad.toml");
    std::fs::write(&bad, "[[hosts]\nhost = ").unwrap();
    let e = format!("{:#}", Scope::load(&bad).unwrap_err());
    assert!(e.contains("not valid"), "{e}");
    std::fs::write(&bad, "[[hosts]]\nhost = 'a'\n").unwrap();
    assert!(Scope::load(&bad).is_err());

    for p in [&missing, &dir, &bad] {
        let r = load_configured(Some(p.to_str().unwrap()));
        assert!(r.is_err(), "{}", p.display());
        assert!(
            format!("{:#}", r.unwrap_err()).contains("refusing"),
            "{}",
            p.display()
        );
    }

    assert!(load_configured(None).unwrap().is_none());
    assert!(load_configured(Some("")).unwrap().is_none());
    assert!(load_configured(Some("   ")).unwrap().is_none());

    let ok = d.join("ok.toml");
    std::fs::write(&ok, "[[hosts]]\nhost='a.example'\nenv='prod'\n").unwrap();
    let s = load_configured(Some(ok.to_str().unwrap()))
        .unwrap()
        .unwrap();
    assert_eq!(s.hosts.len(), 1);
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn shipped_scope_files_parse() {
    let root = env!("CARGO_MANIFEST_DIR");
    let ex = Scope::load(&Path::new(root).join("scope.example.toml"))
        .expect("scope.example.toml must parse");
    assert!(!ex.hosts.is_empty());

    let own = Path::new(root).join("scope.toml");
    let mut files = vec![("scope.example.toml", ex)];
    if own.is_file() {
        files.push((
            "scope.toml",
            Scope::load(&own).expect("scope.toml must parse"),
        ));
    }
    for (name, s) in files {
        for h in &s.hosts {
            assert!(!h.host.trim().is_empty(), "{name}: empty host");
            assert!(
                h.env == "prod" || h.env == "nonprod",
                "{name}: {} has env {:?} (expected prod|nonprod)",
                h.host,
                h.env
            );
        }
    }
}

#[test]
fn a_prod_listed_host_stays_read_only_next_to_the_wildcard() {
    let s = scope(
        "[[hosts]]\nhost='app.shop.example'\nenv='prod'\n[[hosts]]\nhost='*.shop.example'\nenv='prod'\n[[hosts]]\nhost='*'\nenv='nonprod'\n[git]\nhosts=['*']\n",
    );
    for url in ["https://app.shop.example/", "https://www.shop.example/x"] {
        assert!(
            !egress_guard(url, Some(&s), false).unwrap().nonprod,
            "{url}"
        );
        let e = egress_guard(url, Some(&s), true).unwrap_err().to_string();
        assert!(e.contains("prod") && e.contains("refused"), "{url}: {e}");
    }

    assert!(
        egress_guard("https://other.example/", Some(&s), true)
            .unwrap()
            .nonprod
    );
    assert!(
        egress_guard("http://127.0.0.1:8080/", Some(&s), true)
            .unwrap()
            .nonprod
    );

    let s = scope(
        "[[hosts]]\nhost='*'\nenv='nonprod'\n[[hosts]]\nhost='app.shop.example'\nenv='prod'\n",
    );
    assert!(egress_guard("https://app.shop.example/", Some(&s), true).is_err());
    assert!(egress_guard("https://app.shop.example/", Some(&s), false).is_ok());

    let ex = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("scope.example.toml"))
        .unwrap();
    let s = scope(&format!(
        "{ex}\n[[hosts]]\nhost='app.example.com'\nenv='prod'\n"
    ));
    assert!(egress_guard("https://app.example.com/", Some(&s), true).is_err());
    assert!(egress_guard("https://app.example.com/", Some(&s), false).is_ok());
}

#[test]
fn internal_names_are_internal_whatever_dns_says() {
    test_dns::set("localhost", &["8.8.8.8"]);
    test_dns::set("host.docker.internal", &["8.8.8.8"]);
    test_dns::set("api.localhost", &["8.8.8.8"]);
    for h in [
        "localhost",
        "LOCALHOST.",
        "api.localhost",
        "a.b.localhost",
        "host.docker.internal",
        "metadata.google.internal",
    ] {
        assert_eq!(classify_host(h), HostClass::Internal, "{h}");
        assert!(check_host(h, None).is_err(), "{h} must need an entry");
        assert!(
            egress_guard(&format!("http://{h}/"), None, false).is_err(),
            "{h}"
        );
    }

    assert_eq!(classify_host("notlocalhost.example"), HostClass::Public);
    assert_eq!(classify_host("localhost.example"), HostClass::Public);

    let s = scope(
        "[[hosts]]\nhost='*.localhost'\nenv='nonprod'\n[[hosts]]\nhost='localhost'\nenv='nonprod'",
    );
    assert!(egress_guard("http://api.localhost:3000/", Some(&s), true).is_ok());
    assert!(egress_guard("http://localhost:3000/", Some(&s), true).is_ok());
}

#[test]
fn a_public_name_with_an_internal_address_is_internal() {
    test_dns::set("rebind.example", &["10.1.2.3"]);
    test_dns::set("mixed.example", &["93.184.216.34", "192.168.1.5"]);
    test_dns::set("v6.example", &["fd00::1"]);
    test_dns::set("fine.example", &["93.184.216.34", "2606:2800:220:1::1"]);
    for h in ["rebind.example", "mixed.example", "v6.example"] {
        assert_eq!(classify_host(h), HostClass::Internal, "{h}");
        assert!(
            egress_guard(&format!("https://{h}/"), None, false).is_err(),
            "{h}"
        );
    }
    assert_eq!(classify_host("fine.example"), HostClass::Public);
    assert!(egress_guard("https://fine.example/", None, true).is_ok());
}

#[test]
fn unresolvable_names_are_refused_for_intrusive_actions_only() {
    assert_eq!(classify_host("nx.invalid"), HostClass::Unresolvable);
    assert!(egress_guard("https://nx.invalid/", None, false).is_ok());
    let e = egress_guard("https://nx.invalid/", None, true)
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("does not resolve") && e.contains("intrusive"),
        "{e}"
    );

    let s = scope("[[hosts]]\nhost='nx.invalid'\nenv='nonprod'");
    assert!(egress_guard("https://nx.invalid/", Some(&s), true).is_ok());
    let s = scope("[[hosts]]\nhost='*'\nenv='nonprod'");
    assert!(egress_guard("https://other.invalid/", Some(&s), true).is_ok());

    assert!(egress_guard("https://app.example/", None, true).is_ok());
}

#[test]
fn more_internal_ranges() {
    for ip in [
        "0.1.2.3",
        "224.0.0.1",
        "240.0.0.1",
        "198.18.0.1",
        "ff02::1",
        "fec0::1",
        "::ffff:10.0.0.1",
        "64:ff9b::a00:1",
        "64:ff9b::7f00:1",
    ] {
        assert!(is_internal_ip(ip.parse().unwrap()), "{ip}");
    }
    for ip in [
        "8.8.8.8",
        "93.184.216.34",
        "2606:4700:4700::1111",
        "64:ff9b::808:808",
        "100.63.255.255",
        "100.128.0.1",
    ] {
        assert!(!is_internal_ip(ip.parse().unwrap()), "{ip}");
    }
}
