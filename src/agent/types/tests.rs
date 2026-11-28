//! Unit tests for agent types, ledger, priority ordering, and lifecycle tokens.

#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use super::super::created_ledger::*;
    use super::super::execution::*;
    use super::super::fixtures::*;
    use super::super::lifecycle::*;
    use super::super::planning::*;

    #[test]
    fn created_ledger_records_validates_and_deduplicates() {
        let l = CreatedLedger::new();
        assert!(l.record("/api/items", "42"));
        assert!(!l.record("/api/items", "42"), "same resource twice");
        assert!(l.record_with("put", "/api/items/7", "7", Some("user"), Some("TC-002")));
        // path or id that cannot be put in a URL safely are refused
        for (p, i) in [
            ("api/items", "1"),
            ("//evil.example/x", "1"),
            ("/a/../b", "1"),
            ("/a b", "1"),
            ("/a?x=1", "1"),
            ("/a", "1/2"),
            ("/a", ""),
            ("/a", "x y"),
            ("/a", "1;DROP"),
        ] {
            assert!(!l.record(p, i), "{p} {i}");
        }
        let e = l.entries();
        assert_eq!(l.len(), 2);
        assert_eq!(e[0].teardown_path(), "/api/items/42");
        assert_eq!(
            (e[1].method.as_str(), e[1].role.as_deref()),
            ("PUT", Some("user"))
        );
        assert_eq!(
            e[1].teardown_path(),
            "/api/items/7",
            "a path already ending in the id is not extended"
        );
        let mut with_loc = e[0].clone();
        with_loc.delete_path = Some("/v2/things/abc".into());
        assert_eq!(with_loc.teardown_path(), "/v2/things/abc");
        assert!(!l.record_resource(CreatedResource {
            delete_path: Some("/x?y".into()),
            ..e[0].clone()
        }));
    }

    #[test]
    fn record_created_writes_to_the_installed_ledger_and_restores_the_previous() {
        assert!(
            !record_created("/a", "1"),
            "no ledger installed: nothing recorded"
        );
        let outer = CreatedLedger::new();
        let inner = CreatedLedger::new();
        {
            let _o = outer.install();
            assert!(record_created("/a", "1"));
            {
                let _i = inner.install();
                assert!(record_created_with("POST", "/b", "2", None, Some("TC-1")));
            }
            assert!(record_created("/c", "3"), "outer ledger is current again");
        }
        assert!(!record_created("/d", "4"));
        assert_eq!(outer.len(), 2);
        assert_eq!(inner.len(), 1);
        assert_eq!(inner.entries()[0].case_id.as_deref(), Some("TC-1"));
        // another thread sees no ledger
        let _g = outer.install();
        assert!(
            !std::thread::spawn(|| record_created("/e", "5"))
                .join()
                .unwrap()
        );
    }

    #[test]
    fn evidence_share_counts_stored_request_response_pairs_not_constants() {
        let ok = result("TC-001", "boundary", "PASS");
        let mut blocked = result("TC-002", "boundary", "BLOCKED");
        blocked.status_code = None; // transport error: request recorded, no response
        let mut no_file = result("TC-003", "authz", "PASS");
        no_file.evidence_file = None;
        let skipped =
            CaseExecutionResult::not_run(&planned("TC-004", "authz", "POST", "/y"), "dry-run");
        assert!(
            ok.has_stored_evidence()
                && !blocked.has_stored_evidence()
                && !no_file.has_stored_evidence()
        );
        assert_eq!(
            evidence_share(&[ok.clone(), blocked, no_file, skipped]),
            (1, 3),
            "skipped cases are not executed"
        );
        assert_eq!(evidence_share(&[]), (0, 0));
        assert_eq!(evidence_share(&[ok]), (1, 1));
    }

    #[test]
    fn priority_puts_auth_stateful_and_openapi_before_generic_probes() {
        let mut stateful = planned("a", "authz_chain", "POST", "/items");
        stateful.stateful_steps = Some(vec![StatefulStep {
            step_number: 1,
            actor: "alice".into(),
            method: "POST".into(),
            path: "/items".into(),
            payload: None,
            extract_vars: None,
            expected_status: None,
            violation_condition: None,
        }]);
        let mut openapi = planned("b", "boundary", "POST", "/orders");
        openapi.source = Some("openapi".into());
        let auth = planned("c", "authz", "GET", "/admin");
        let root = planned("d", "state_transition", "GET", "/");
        let mut llm = planned("e", "boundary", "GET", "/z");
        llm.source = Some("llm".into());
        let generic = planned("f", "boundary", "GET", "/about");
        let key = |c: &PlannedCase| case_priority(c).0;
        assert!(key(&auth) == 0 && key(&root) == 0 && key(&stateful) == 1 && key(&openapi) == 2);
        assert!(key(&openapi) < key(&generic) && key(&generic) < key(&llm));
        assert_eq!(profile_case_cap("QUICK"), Some(20));
        assert_eq!(
            (
                profile_case_cap("standard"),
                profile_case_cap("deep"),
                profile_case_cap("discovery-scan")
            ),
            (None, None, None)
        );
    }

    #[test]
    fn cancel_token_honours_the_flag_and_a_marker_file() {
        let t = CancelToken::new();
        assert!(!t.is_cancelled());
        t.clone().cancel();
        assert!(t.is_cancelled(), "clones share the flag");
        let dir = std::env::temp_dir().join(format!("rh-cancel-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("CANCEL");
        let _ = std::fs::remove_file(&marker);
        let t = CancelToken::new().with_file(marker.clone());
        assert!(!t.is_cancelled());
        std::fs::write(&marker, b"x").unwrap();
        assert!(
            t.is_cancelled(),
            "another process asked through the marker file"
        );
        let _ = std::fs::remove_dir_all(&dir);
        // registry: an id is cancellable only while its registration is alive
        let tok = CancelToken::new();
        let reg = register_run("run-unit-cancel", &tok);
        assert!(running_run_ids().contains(&"run-unit-cancel".to_string()));
        assert!(request_cancel("run-unit-cancel") && tok.is_cancelled());
        drop(reg);
        assert!(!running_run_ids().contains(&"run-unit-cancel".to_string()));
        assert!(!request_cancel("../etc/passwd"));
    }
}
