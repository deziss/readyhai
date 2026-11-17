//! Comprehensive unit tests for engine storage, git operations, targets, and deadlines.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::Path;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use super::super::deadline::{deadline_passed, run_deadline, DeadlineGuard};
    use super::super::git::{clone_url, git_clone, git_clone_command, redact_url_credentials, remote_repo_host};
    use super::super::orchestrator::scan;
    use super::super::storage::{new_run_id, run_dir, valid_run_id, write_atomic};
    use super::super::target_parser::parse_target;
    use super::super::types::ScanOpts;
    use super::super::ENV_LOCK;

    #[test]
    fn run_ids_carry_64_random_bits() {
        let id = new_run_id();
        let (ts, rand_part) = id.rsplit_once('-').unwrap();
        assert_eq!(rand_part.len(), 16, "{id}");
        assert!(rand_part.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(ts.len(), "20260101-000000".len());
        assert!(valid_run_id(&id));
        let ids: std::collections::HashSet<String> = (0..2000).map(|_| new_run_id()).collect();
        assert_eq!(ids.len(), 2000);
        // ids from older versions (16 random bits) stay valid for lookups
        assert!(valid_run_id("20261027-053327-57e2"));
        assert!(!valid_run_id("../etc") && !valid_run_id("") && !valid_run_id(&"a".repeat(64)));
    }

    #[test]
    fn write_atomic_replaces_whole_files_and_never_creates_dirs() {
        let d = std::env::temp_dir().join(format!("rh-atomic-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("status.json");
        write_atomic(&f, b"one").unwrap();
        write_atomic(&f, b"two-longer").unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "two-longer");
        let names: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["status.json".to_string()],
            "no temp file may survive"
        );
        // parent gone (run deleted underneath a worker): fails, does not resurrect
        let gone = d.join("deleted-run");
        assert!(write_atomic(&gone.join("status.json"), b"x").is_err());
        assert!(!gone.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn remote_repo_hosts_in_every_spelling() {
        let host = |s: &str| remote_repo_host(s).unwrap();
        assert_eq!(host("https://GitHub.com/org/x"), "github.com");
        assert_eq!(
            host("git:https://git.example.com:8443/org/x.git"),
            "git.example.com"
        );
        assert_eq!(host("git@git.example.com:org/x.git"), "git.example.com");
        assert_eq!(host("git:git@git.example.com:org/x.git"), "git.example.com");
        assert_eq!(host("deploy@git.example.com:org/x.git"), "git.example.com");
        assert_eq!(
            host("ssh://git@git.example.com:2222/org/x.git"),
            "git.example.com"
        );
        assert_eq!(
            host("git:ssh://git@git.example.com/org/x.git"),
            "git.example.com"
        );
        // the real host of a backslash URL is the part before the backslash
        assert_eq!(
            host("https://evil.example\\@git.example.com/x.git"),
            "evil.example"
        );
        for bad in [
            "git:ext::sh -c id",
            "file:///srv/x.git",
            "git@-oProxyCommand=x:org/x.git",
            "x.git",
            "git@host",
            "git@:path",
            "ftp://h/x.git",
            "git@ho st:x",
            "git@[::1]:x.git",
        ] {
            assert!(remote_repo_host(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn clone_url_is_the_normalised_form_of_what_was_checked() {
        assert_eq!(
            clone_url("git:https://evil.example\\@git.example.com/x.git").unwrap(),
            "https://evil.example/@git.example.com/x.git"
        );
        assert_eq!(
            clone_url("git@host:org/x.git").unwrap(),
            "git@host:org/x.git"
        );
    }

    #[test]
    fn web_targets_are_normalised_at_parse_time() {
        let t = parse_target("https://app.example\\@evil.example/x", None).unwrap();
        assert_eq!(
            t.url.as_deref(),
            Some("https://app.example/@evil.example/x")
        );
        assert!(parse_target("http://", None).is_err());
    }

    #[test]
    fn git_command_is_non_interactive() {
        let cmd = git_clone_command("git@h:o/r.git", Path::new("/tmp/x"));
        let env: HashMap<String, String> = cmd
            .get_envs()
            .filter_map(|(k, v)| {
                Some((
                    k.to_string_lossy().into_owned(),
                    v?.to_string_lossy().into_owned(),
                ))
            })
            .collect();
        assert_eq!(
            env.get("GIT_SSH_COMMAND").map(String::as_str),
            Some("ssh -o BatchMode=yes")
        );
        assert_eq!(
            env.get("GIT_TERMINAL_PROMPT").map(String::as_str),
            Some("0")
        );
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.windows(2).any(|w| w == ["-c", "credential.helper="]));
        assert!(args.iter().any(|a| a == "--"));
        assert_eq!(args[args.len() - 2], "git@h:o/r.git");
    }

    #[test]
    fn git_clone_times_out_and_does_not_leak_credentials() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        // a server that accepts and never answers: git hangs in the TLS handshake
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut held = vec![];
            for c in l.incoming().flatten() {
                held.push(c);
            }
        });
        let dest = std::env::temp_dir().join(format!("rh-clone-{}", std::process::id()));
        let t0 = Instant::now();
        let e = git_clone(
            &format!("https://127.0.0.1:{port}/x.git"),
            &dest,
            Duration::from_secs(2),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("timed out"), "{e}");
        assert!(t0.elapsed() < Duration::from_secs(10), "{:?}", t0.elapsed());
        assert!(!dest.exists());

        // refused connection: fails fast, credentials redacted from the message
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let e = git_clone(
            &format!("https://user:s3cr3tpass@127.0.0.1:{closed}/x.git"),
            &dest,
            Duration::from_secs(20),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("git clone failed"), "{e}");
        assert!(!e.contains("s3cr3tpass"), "{e}");
        assert!(git_clone("file:///etc", &dest, Duration::from_secs(1)).is_err());
        assert_eq!(
            redact_url_credentials("fatal: https://u:p@h/x and ssh://k@h/y"),
            "fatal: https://***@h/x and ssh://***@h/y"
        );
    }

    #[test]
    fn deadline_registry_follows_the_guard() {
        let id = "20990101-000000-00000000000000ff";
        assert!(run_deadline(id).is_none() && !deadline_passed(id));
        {
            let _g = DeadlineGuard::new(id, Some(Instant::now() - Duration::from_secs(1)));
            assert!(deadline_passed(id));
        }
        assert!(run_deadline(id).is_none(), "guard must unregister on drop");
        let _g = DeadlineGuard::new(id, Some(Instant::now() + Duration::from_secs(60)));
        assert!(!deadline_passed(id) && run_deadline(id).is_some());
    }

    #[test]
    fn a_scan_past_its_deadline_fails_instead_of_returning_a_partial_verdict() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let d = std::env::temp_dir().join(format!("rh-deadline-{}", std::process::id()));
        let target = d.join("repo");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("README.md"), "hi").unwrap();
        unsafe { std::env::set_var("READYHAI_DATA", d.join("data")) };
        let opts = ScanOpts {
            target: target.to_string_lossy().into_owned(),
            no_tools: true,
            deadline: Some(Instant::now() - Duration::from_secs(1)),
            ..Default::default()
        };
        let id = new_run_id();
        let e = scan(&opts, &id).unwrap_err().to_string();
        assert!(e.contains("deadline"), "{e}");
        assert!(
            !run_dir(&id).join("run.json").exists(),
            "no run.json for a run that missed its deadline"
        );
        assert!(run_deadline(&id).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }
}
