use super::*;
use super::coverage::*;
use super::eol::*;
use super::licenses::*;
use super::migrations::*;
use super::routes::*;
use super::smells::*;
use crate::ctx::Ctx;
use crate::model::{CheckOutput, CheckStatus, Finding, Profile, Severity, Target, TargetKind};
use crate::qa::model::{Cell, ResultStatus};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/qa-repo")
    }

    fn ctx_for(tag: &str, qa: bool) -> Ctx {
        let src = fixture();
        let tmp = std::env::temp_dir().join(format!("readyhai-suite-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let snap = crate::snapshot::take(&src, &tmp.join("src"), &[], &[]).unwrap();
        Ctx {
            run_id: "t".into(),
            target: Target {
                kind: TargetKind::Repo,
                raw: src.display().to_string(),
                path: Some(src.clone()),
                image: None,
                url: None,
                openapi: None,
                host: None,
                apk: None,
                device: None,
            },
            profile: Profile::Quick,
            run_dir: tmp.clone(),
            facts: crate::rules::detect_facts(&snap),
            snapshot: Some(snap),
            docker: crate::tools::Docker::detect(&tmp),
            cfg: Default::default(),
            error_lines: Default::default(),
            nonprod: false,
            qa: if qa {
                Some(crate::qa::QaCtx::new(
                    crate::qa::roles::Roles::default(),
                    None,
                    None,
                    false,
                ))
            } else {
                None
            },
        }
    }

    fn run_one(ctx: &Ctx, id: &str) -> CheckOutput {
        let c = checks().into_iter().find(|c| c.id == id).unwrap();
        (c.run)(ctx).unwrap()
    }

    #[test]
    fn cobertura_lcov_jacoco() {
        let t = fs::read_to_string(fixture().join("coverage.xml")).unwrap();
        let c = parse_cobertura(&t).unwrap();
        assert!((c.overall - 0.42).abs() < 1e-9);
        assert!(c.files.contains(&("app/auth.py".to_string(), 0.0)));

        let l = parse_lcov(
            "SF:src/a.js\nLF:10\nLH:5\nend_of_record\nSF:src/auth.js\nLF:4\nLH:0\nend_of_record\n",
        )
        .unwrap();
        assert!((l.overall - 5.0 / 14.0).abs() < 1e-9);
        assert_eq!(l.files[1], ("src/auth.js".to_string(), 0.0));

        let j = r#"<report><package name="com/x"><sourcefile name="A.java"><counter type="LINE" missed="3" covered="7"/></sourcefile>
<sourcefile name="Pay.java"><counter type="LINE" missed="5" covered="0"/></sourcefile></package></report>"#;
        let j = parse_jacoco(j).unwrap();
        assert!((j.overall - 7.0 / 15.0).abs() < 1e-9);
        assert_eq!(j.files[1], ("com/x/Pay.java".to_string(), 0.0));
    }

    #[test]
    fn route_extraction_all_frameworks() {
        let py = "@app.get(\"/health\")\n@router.post('/orders')\n@bp.route(\"/u\", methods=[\"GET\", \"POST\"])\n@bp.route('/x')\n";
        let r = extract_routes("a.py", py);
        let l: Vec<String> = r.iter().map(|r| r.label()).collect();
        assert_eq!(
            l,
            ["GET /health", "POST /orders", "GET /u", "POST /u", "GET /x"]
        );
        let js = "app.get('/a/:id', h)\nrouter.post(\"/b\", h)\n";
        assert_eq!(extract_routes("a.js", js).len(), 2);
        let java = "@GetMapping(\"/items/{id}\")\n@RequestMapping(value = \"/r\", method = RequestMethod.PUT)\n";
        let r = extract_routes("A.java", java);
        assert_eq!(
            (r[0].label().as_str(), r[1].label().as_str()),
            ("GET /items/{id}", "PUT /r")
        );
        let dj = "urlpatterns = [path('users/<int:pk>/', v)]";
        assert_eq!(
            extract_routes("proj/urls.py", dj)[0].path,
            "users/<int:pk>/"
        );
        assert!(extract_routes("views.py", dj).is_empty());
    }

    #[test]
    fn route_segments_read_every_framework_syntax_the_same_way() {
        let want = ["orders", "{}"];
        for p in [
            "/orders/{id}",
            "/Orders/{order_id}/",
            "orders/<int:pk>",
            "/orders/:id?x=1",
            "/orders/*",
            "/orders/(?P<pk>[0-9]+)",
        ] {
            assert_eq!(route_segments(p), want, "{p}");
        }
        assert!(route_segments("/").is_empty());
        assert_eq!(route_segments("/api/v1/health"), ["api", "v1", "health"]);
    }

    #[test]
    fn route_normalization_matching() {
        let rx = route_regex("/orders/{id}").unwrap();
        assert!(rx.is_match("client.get(\"/orders/42\")"));
        assert!(rx.is_match("f\"/api/orders/{oid}/\""));
        assert!(!rx.is_match("client.get(\"/orders\")"));
        assert!(
            route_regex("/users/:id")
                .unwrap()
                .is_match("get('/users/7?x=1')")
        );
        assert!(
            route_regex("users/<int:pk>/")
                .unwrap()
                .is_match("\"/users/3/\"")
        );
        let o = route_regex("/orders").unwrap();
        assert!(o.is_match("get(\"/orders\")"));
        assert!(!o.is_match("get(\"/orders/5\")"));
        assert!(!o.is_match("get(\"/orders_old\")"));
        assert!(route_regex("/").unwrap().is_match("get(\"/\")"));
    }

    #[test]
    fn smells_in_fixture_and_js() {
        let t = fs::read_to_string(fixture().join("tests/test_orders.py")).unwrap();
        let mut s = Smells::default();
        scan_smells("tests/test_orders.py", &t, &mut s);
        assert_eq!(s.no_assert.len(), 1, "{:?}", s.no_assert);
        assert!(s.no_assert[0].contains("test_orders_no_assert"));
        assert_eq!(s.skipped.len(), 1);
        assert_eq!(s.sleeps.len(), 1);
        let js = "it('a', () => {\n  expect(1).toBe(1);\n});\nit('b', () => {\n  run();\n});\nit.skip('c', () => {});\nsetTimeout(f, 2000);\nsetTimeout(f, 50);\n";
        let mut s = Smells::default();
        scan_smells("a.test.js", js, &mut s);
        assert_eq!(s.no_assert.len(), 1, "{:?}", s.no_assert);
        assert_eq!(s.skipped.len(), 1);
        assert_eq!(s.sleeps.len(), 1);
    }

    fn table() -> Value {
        serde_json::json!({
            "python": [{"cycle":"3.8","eol":"2024-10-07"},{"cycle":"3.12","eol":"2028-10-31"},{"cycle":"3.9","eol":"2026-01-10"}],
            "nodejs": [{"cycle":"16","eol":"2023-09-11"},{"cycle":"22","eol":"2027-04-30"}],
            "debian": [{"cycle":"10","eol":"2022-09-10"}],
            "alpine": [{"cycle":"3.14","eol":"2023-05-01"}],
            "ubuntu": [{"cycle":"20.04","eol":"2025-05-31"}]
        })
    }

    #[test]
    fn dockerfile_from_and_eol_dates() {
        let rts = from_images(
            "FROM python:3.8-slim AS base\nFROM base\nFROM --platform=linux/amd64 docker.io/library/node:16\nFROM debian:buster-slim\nFROM alpine:3.14.2\nFROM ubuntu:focal\nFROM python:latest\nFROM scratch\n",
            "Dockerfile",
        );
        let got: Vec<(&str, &str)> = rts
            .iter()
            .map(|r| (r.product, r.version.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("python", "3.8"),
                ("nodejs", "16"),
                ("debian", "10"),
                ("alpine", "3.14.2"),
                ("ubuntu", "20.04")
            ]
        );
        let t = table();
        // fixed "today"
        assert_eq!(
            eol_state(&t, &rts[0], "2026-10-25").unwrap().1,
            EolState::Eol("2024-10-07".into())
        );
        assert_eq!(eol_state(&t, &rts[3], "2026-10-25").unwrap().0, "3.14");
        let py39 = Runtime {
            product: "python",
            version: "3.9.7".into(),
            source: "x".into(),
            exact: true,
        };
        assert!(matches!(
            eol_state(&t, &py39, "2025-09-01").unwrap().1,
            EolState::Soon(_, 131)
        ));
        assert!(eol_state(&t, &py39, "2025-01-01").is_none());
        let py312 = Runtime {
            product: "python",
            version: "3.12".into(),
            source: "x".into(),
            exact: true,
        };
        assert!(eol_state(&t, &py312, "2026-10-25").is_none());
        assert_eq!(day_num("1970-01-02"), Some(1));
        assert_eq!(range_min(">=3.8,<4").unwrap(), ("3.8".to_string(), false));
        assert_eq!(
            range_min("16.x".trim_end_matches(".x")).unwrap(),
            ("16".to_string(), true)
        );
    }

    #[test]
    fn fixture_eol_and_hints() {
        let ctx = ctx_for("eol", true);
        let r = run_one(&ctx, "qa.release.eol");
        assert!(
            r.findings.iter().any(|f| f.rule == "qa.release.eol_runtime"
                && f.severity == Severity::High
                && f.title.contains("python 3.8")),
            "{:?}",
            r.findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
        let n = ctx.qa.as_ref().unwrap().with(|c| c.defects.len());
        assert!(n >= 1);
    }

    #[test]
    fn fixture_coverage_routes_smells() {
        let ctx = ctx_for("all", true);
        let cov = run_one(&ctx, "qa.suite.coverage");
        let rules: Vec<&str> = cov.findings.iter().map(|f| f.rule.as_str()).collect();
        assert!(rules.contains(&"qa.suite.low_coverage"), "{rules:?}");
        assert!(
            cov.findings
                .iter()
                .any(|f| f.rule == "qa.suite.critical_uncovered" && f.location == "app/auth.py")
        );
        let r = run_one(&ctx, "qa.suite.routes");
        let fs: Vec<&Finding> = r
            .findings
            .iter()
            .filter(|f| f.rule == "qa.suite.untested_routes")
            .collect();
        // one finding PER untested route, each with its own fingerprint
        assert_eq!(
            fs.len(),
            3,
            "{:?}",
            fs.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
        for want in ["GET /health", "GET /orders/{id}", "/admin/stats"] {
            assert!(fs.iter().any(|f| f.title.contains(want)), "missing {want}");
        }
        assert!(
            !fs.iter()
                .any(|f| f.title.contains("Route GET /orders is never"))
        );
        let mut f2: Vec<Finding> = fs.iter().map(|f| (*f).clone()).collect();
        f2.iter_mut().for_each(|f| f.finalize());
        assert_eq!(
            f2.iter()
                .map(|f| f.fingerprint.clone())
                .collect::<BTreeSet<_>>()
                .len(),
            3
        );
        let m = ctx.qa.as_ref().unwrap().with(|c| c.coverage.clone());
        assert_eq!(m.rows.len(), 4);
        assert_eq!(m.cells.iter().filter(|c| c.2 == Cell::Pass).count(), 1);
        let s = run_one(&ctx, "qa.suite.smells");
        let sm: Vec<&Finding> = s
            .findings
            .iter()
            .filter(|f| f.rule == "qa.suite.test_smells")
            .collect();
        assert_eq!(
            sm.len(),
            3,
            "{:?}",
            sm.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
        assert!(sm.iter().any(
            |f| f.title.contains("test_orders_no_assert") && f.title.contains("no assertions")
        ));
        assert!(sm.iter().any(|f| f.title.starts_with("Skipped test")));
        assert!(sm.iter().any(|f| f.title.starts_with("Sleep of 1s")));
    }

    #[test]
    fn smell_identity_has_no_line_numbers_and_new_items_are_new() {
        let one = Smells {
            no_assert: vec!["t/a.py:10 test_x".into()],
            skipped: vec!["t/a.py:3".into()],
            sleeps: vec![],
        };
        let moved = Smells {
            no_assert: vec!["t/a.py:99 test_x".into()],
            skipped: vec!["t/a.py:40".into()],
            sleeps: vec![],
        };
        let keys = |s: &Smells| {
            smell_defs(s)
                .into_iter()
                .map(|d| d.fp_key)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            keys(&one),
            keys(&moved),
            "moving code must not change fingerprints"
        );
        // a second skipped test in the same file is a new item
        let two = Smells {
            skipped: vec!["t/a.py:3".into(), "t/a.py:50".into()],
            ..Default::default()
        };
        assert_eq!(
            keys(&two),
            vec!["smell:skipped:t/a.py:1", "smell:skipped:t/a.py:2"]
        );
        assert!(keys(&one).contains(&"smell:skipped:t/a.py:1".to_string()));
    }

    #[test]
    fn coverage_fingerprint_follows_the_band() {
        assert_eq!(cov_band(55.0), cov_band(51.0));
        assert_ne!(cov_band(55.0), cov_band(35.0));
        assert_eq!(
            (cov_band(0.0), cov_band(59.9), cov_band(100.0)),
            (0, 50, 100)
        );
        // the fixture (42%) yields the band-40 key
        let ctx = ctx_for("covband", true);
        let f = run_one(&ctx, "qa.suite.coverage");
        let mut low = f
            .findings
            .into_iter()
            .find(|f| f.rule == "qa.suite.low_coverage")
            .unwrap();
        low.finalize();
        let want =
            crate::qa::recommend::fingerprint("qa.suite.low_coverage", "overall:coverage.xml:40");
        assert_eq!(low.fingerprint, want);
    }

    #[test]
    fn missing_coverage_is_blocked() {
        let mut ctx = ctx_for("nocov", true);
        let snap = ctx.snapshot.as_mut().unwrap();
        snap.files.retain(|f| f != "coverage.xml");
        let r = run_one(&ctx, "qa.suite.coverage");
        assert!(matches!(r.status, Some(CheckStatus::Skipped(_))));
        let c = ctx.qa.as_ref().unwrap();
        assert_eq!(c.with(|c| c.results[0].status), ResultStatus::Blocked);
        assert!(c.with(|c| c.untested[0].contains("no coverage report")));
    }

    #[test]
    fn migrations_detect_and_commands() {
        let ctx = ctx_for("mig", true);
        let t = detect_migrations(&ctx.snapshot.as_ref().unwrap().files);
        assert_eq!(t, vec![MigTool::Alembic(String::new())]);
        let r = run_one(&ctx, "qa.release.migrations");
        assert!(
            matches!(r.status, Some(CheckStatus::Skipped(ref m)) if m.contains("[test] image"))
        );

        let a = app_args(
            "r1",
            "app",
            "readyhai-r1-mig",
            Path::new("/snap"),
            "svc",
            "img:1",
        );
        let j = a.join(" ");
        for need in [
            "--cap-drop ALL",
            "no-new-privileges",
            "--read-only",
            "--pids-limit",
            "--memory 1g",
            "readyhai.run=r1",
            "--network readyhai-r1-mig",
            "/snap:/src:ro",
            "-w /src/svc",
            "-e DATABASE_URL ",
            "img:1",
        ] {
            assert!(j.contains(need), "missing {need} in {j}");
        }
        assert!(!j.contains("postgresql://"));
        let p = pg_args("r1", "pg", "n").join(" ");
        assert!(
            p.contains("-e POSTGRES_PASSWORD ")
                && p.contains("--cap-drop ALL")
                && p.contains("postgres:16-alpine")
        );
        assert_eq!(step_for_exit(12), "alembic downgrade base");
        assert!(crate::tools::validate_create_policy(&a[1..a.len() - 4]).is_ok());
    }

    #[test]
    fn licenses_policy() {
        let ctx = ctx_for("lic", true);
        let sbom = serde_json::json!({"components":[
            {"name":"a","version":"1","licenses":[{"license":{"id":"MIT"}}]},
            {"name":"b","version":"2","licenses":[{"license":{"id":"AGPL-3.0-only"}}]},
            {"name":"c"}]});
        let none = licenses_eval(&ctx, &sbom, &[]);
        assert!(none.is_empty());
        let bad = licenses_eval(&ctx, &sbom, &parse_deny("AGPL-3.0*, GPL-3.0*"));
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].rule, "qa.release.license");
        assert!(bad[0].detail.contains("b@2"));
    }

    #[test]
    fn license_denials_are_per_package() {
        let ctx = ctx_for("lic2", true);
        let deny = parse_deny("AGPL-3.0*");
        let mk = |pkgs: &[(&str, &str)]| serde_json::json!({"components": pkgs.iter().map(|(n, v)| serde_json::json!({"name": n, "version": v, "licenses":[{"license":{"id":"AGPL-3.0-only"}}]})).collect::<Vec<_>>()});
        let fp = |fs: Vec<Finding>| {
            fs.into_iter()
                .map(|mut f| {
                    f.finalize();
                    f.fingerprint
                })
                .collect::<BTreeSet<_>>()
        };
        let a = fp(licenses_eval(&ctx, &mk(&[("b", "2")]), &deny));
        let bumped = fp(licenses_eval(&ctx, &mk(&[("b", "3")]), &deny));
        assert_eq!(a, bumped, "a version bump is the same item");
        let more = fp(licenses_eval(&ctx, &mk(&[("b", "2"), ("c", "1")]), &deny));
        assert_eq!(more.len(), 2);
        assert!(
            a.is_subset(&more) && more.len() > a.len(),
            "a NEW denied package is a new fingerprint"
        );
    }

    #[test]
    fn infra_exit_codes_are_not_migration_failures() {
        for c in [125, 126, 127, 137, 143] {
            assert!(infra_exit(c).is_some(), "{c}");
        }
        for c in [11, 12, 13, 124, 1] {
            assert!(infra_exit(c).is_none(), "{c}");
        }
        assert_eq!(step_for_exit(11), "alembic upgrade head");
    }

    #[test]
    fn lcov_without_line_data_is_no_data_not_full_coverage() {
        // LF:0 everywhere: nothing instrumented
        assert!(parse_lcov("SF:src/a.js\nLF:0\nLH:0\nend_of_record\n").is_none());
        assert!(parse_lcov("").is_none());
        // a file with LF:0 says nothing about itself and does not dilute the others to 100%
        let l = parse_lcov(
            "SF:src/empty.js\nLF:0\nLH:0\nend_of_record\nSF:src/b.js\nLF:10\nLH:5\nend_of_record\n",
        )
        .unwrap();
        assert_eq!(l.files, vec![("src/b.js".to_string(), 0.5)]);
        assert!((l.overall - 0.5).abs() < 1e-9);
        // jacoco: only sourcefiles without any counted line
        let j = r#"<report><package name="p"><sourcefile name="A.java"><counter type="LINE" missed="0" covered="0"/></sourcefile></package></report>"#;
        assert!(parse_jacoco(j).is_none());
        // cobertura: nothing instrumented
        let c =
            r#"<coverage line-rate="1" lines-valid="0" lines-covered="0"><packages/></coverage>"#;
        assert!(parse_cobertura(c).is_none());
        let ok = r#"<coverage line-rate="0.5" lines-valid="10" lines-covered="5"><packages/></coverage>"#;
        assert!((parse_cobertura(ok).unwrap().overall - 0.5).abs() < 1e-9);
    }

    #[test]
    fn a_coverage_report_with_no_line_data_is_skipped_and_untested() {
        let mut ctx = ctx_for("nolines", true);
        let snap = ctx.snapshot.as_mut().unwrap();
        snap.files.retain(|f| f != "coverage.xml");
        fs::write(
            snap.root.join("lcov.info"),
            "SF:src/a.js\nLF:0\nLH:0\nend_of_record\n",
        )
        .unwrap();
        snap.files.push("lcov.info".into());
        let r = run_one(&ctx, "qa.suite.coverage");
        assert!(
            matches!(&r.status, Some(CheckStatus::Skipped(m)) if m.contains("no line data")),
            "{:?}",
            r.status
        );
        assert!(
            r.findings.is_empty(),
            "no low-coverage finding, and certainly no 100% pass"
        );
        let c = ctx.qa.as_ref().unwrap();
        assert_eq!(c.with(|c| c.results[0].status), ResultStatus::Blocked);
        assert!(c.with(
            |c| c.untested[0].contains("lcov.info") && c.untested[0].contains("no line data")
        ));
    }

    #[test]
    fn licences_without_a_deny_policy_are_skipped_not_pass() {
        let ctx = ctx_for("lic-none", true);
        let sbom = serde_json::json!({"components":[
            {"name":"a","version":"1","licenses":[{"license":{"id":"MIT"}}]},
            {"name":"b","version":"2","licenses":[{"license":{"id":"AGPL-3.0-only"}}]}]});
        assert!(licenses_eval(&ctx, &sbom, &[]).is_empty());
        let q = ctx.qa.as_ref().unwrap();
        let (res, untested, notes) =
            q.with(|c| (c.results.clone(), c.untested.clone(), c.notes.clone()));
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].status, ResultStatus::Skipped, "{res:?}");
        assert!(
            untested
                .iter()
                .any(|u| u.contains("not evaluated") && u.contains("no deny policy")),
            "{untested:?}"
        );
        assert!(notes.iter().any(|n| n.contains("not evaluated")));

        // check level: the CheckOutput is Skipped too (needs READYHAI_LICENSE_DENY unset)
        if std::env::var("READYHAI_LICENSE_DENY").is_ok() {
            return;
        }
        let ctx = ctx_for("lic-none2", true);
        fs::create_dir_all(ctx.out_dir()).unwrap();
        fs::write(ctx.out_dir().join("sbom.cdx.json"), sbom.to_string()).unwrap();
        let r = run_one(&ctx, "qa.release.licenses");
        assert!(
            matches!(&r.status, Some(CheckStatus::Skipped(m)) if m.contains("not judged")),
            "{:?}",
            r.status
        );
        // with a policy it is judged (and fails on the AGPL package)
        let mut ctx = ctx_for("lic-pol", true);
        ctx.cfg.license.deny = vec!["AGPL-3.0*".into()];
        fs::create_dir_all(ctx.out_dir()).unwrap();
        fs::write(ctx.out_dir().join("sbom.cdx.json"), sbom.to_string()).unwrap();
        let r = run_one(&ctx, "qa.release.licenses");
        assert!(
            r.status.is_none() && r.findings.len() == 1,
            "{:?}",
            r.status
        );
    }
