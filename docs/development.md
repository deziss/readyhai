# Development

## Repo layout

```
readyhai/
  Cargo.toml  Cargo.lock  Dockerfile  docker-compose.yml  .env.example  .dockerignore  README.md
  tools.lock.toml          pinned scanner images (embedded at build time; override with READYHAI_TOOLS_LOCK)
  scope.example.toml       sample rules of engagement
  policies/default.toml    default gate policy (embedded)
  templates/report.html.j2 HTML report (auto-escaped, CSP)
  src/                     the crate (below)
  probe/                   linux.sh  macos.sh  windows.ps1   (embedded with include_str!, piped over ssh)
  runners/playwright/      Dockerfile  package.json  crawl.mjs   (built locally, not a registry image)
  ci/                      Jenkinsfile.stage  github-action.yml  gitlab-ci.yml  argocd-postsync-job.yaml
  tests/fixtures/          host-probe/ logs/ android/ tool-outputs/ mcp/ vuln-app/
  docs/                    this documentation
```

## Module ownership map

| Module | Lines | Owns |
|---|---|---|
| `main.rs` | 244 | CLI, exit codes, summary printing |
| `model.rs` | 382 | Shared types: `Finding`, `CheckStatus`, `Target`, `Run`, `Profile`, `Verdict`, `ErrorCluster` |
| `engine.rs` | 366 | Orchestration, target parsing, run ids, data dir, git clone |
| `checks.rs` | 60 | `Check` struct and the registry `all()` |
| `ctx.rs` | 42 | Per-run context handed to checks (`error_line`, `out_dir`, `src_dir`) |
| `facts.rs` | 27 | `Facts` struct (filled by `rules::detect_facts`) |
| `snapshot.rs` | 210 | Denylist and filtered copy |
| `config.rs` | 58 | `readyhai.toml` types |
| `policy.rs` | 180 | Suppressions, summary, verdict |
| `baseline.rs` | 60 | Baseline file and diff |
| `scope.rs` | 80 | `scope.toml` |
| `rules.rs` | 784 | Native readiness checks, fact detection, Dockerfile/compose/k8s parsing |
| `tools.rs` | 1453 | Docker runner, create-policy, lock file, parsers, scrubbers, `tests.own`, plugins, `tools pull/update` |
| `web.rs` | 532 | `web.smoke`, Schemathesis, ZAP, Playwright |
| `host.rs` | 718 | SSH, probes, Lynis, host CVE |
| `android.rs` | 752 | MobSF client, adb runtime, logcat parser |
| `logs.rs` | 168 | Error clustering and redaction |
| `report.rs` | 278 | HTML, JSON, SARIF, JUnit |
| `serve.rs` | 326 | REST API, background worker, Web UI endpoints |
| `mcp.rs` | 295 | MCP stdio server and `precheck` |
| `llm.rs` | 544 | Provider catalog (vLLM, Ollama, cloud), reasoning token parser, token budget |
| `agent.rs` | 639 | Autonomous multi-agent QA loop, Evidence Ledger calculation, defect triage |
| `web_ui.rs` | 1168 | Cyber-dark Web Studio SPA (HTML, CSS, JS) with live pipeline telemetry |

## Adding a check

1. Pick the module (`rules.rs` for native repo rules, `tools.rs` for containers, `web.rs`, `host.rs`, `android.rs`) or a new module added to `main.rs` and to `checks::all()`.
2. Register it:

```rust
Check::new("readiness.foo", "Foo hardening", &[TargetKind::Repo], Profile::Quick, |ctx| {
    // ctx.facts, ctx.snapshot, ctx.cfg, ctx.error_line(source, line)
    Ok(CheckOutput::findings(vec![ /* Finding::new(check, rule, Category, Severity, title, location) */ ]))
})
// .tool("grype")   // set when it needs a container: gives --no-tools / no-docker skipping and shows in `checks`
// .intrusive()     // only runs with --profile deep on a nonprod host; no check uses this yet
```

3. Return `CheckOutput::status(CheckStatus::NotApplicable(..)/Skipped(..)/Partial(..))` for the non-pass cases; never emit an empty pass when you could not look. `Err(..)` becomes `errored`.
4. Choose a stable `rule` id (`<check>.<name>`). Set `.fp_key(..)` to something that survives unrelated edits (no line numbers, no versions). The engine fills `check` if empty and calls `finalize()` on each finding.
5. If the rule should always fail, add its prefix to `policies/default.toml` `hard_fail`.
6. Add a unit test that feeds a fixture (see testing) and update [checks.md](checks.md).

Read files only through `rules::read(snap, rel)`, which refuses denied placeholders and files over 2 MB. Never put secret text in a `Finding`.

## Adding a container tool (data-like)

1. Add `[tools.<name>]` to `tools.lock.toml`.
2. In `tools.rs::checks()` build a `ToolSpec::new("<name>", &[args...])`; set `entrypoint`, `network`, `memory`, `timeout_secs`, `tmpfs` as needed; args must write results under `/out`. Call `ctx.docker.run(ctx, &spec)`.
3. Write `parse_<tool>(json) -> Result<Vec<Finding>>`, keeping only rule and location (no matched text), and a `scrub_<tool>` if the raw file can contain matched text; call `rewrite_scrubbed` after parsing.
4. Record a real output as `tests/fixtures/tool-outputs/<tool>.json` and add a golden test.

## Adding a plugin

No code needed: create `<plugin-dir>/<name>/plugin.toml` (schema in [configuration.md](configuration.md#plugins)), run `readyhai checks --plugins ...` (set `READYHAI_PLUGINS`) to confirm it loads, then scan. Output must be SARIF, JUnit or a `Finding[]` JSON. Pin the image by digest.

## Adding a target kind

1. Add a variant to `TargetKind` and a field on `Target` in `model.rs`.
2. Parse the syntax in `engine::parse_target` (validate strictly: charset, no leading `-`, canonicalize paths).
3. Handle it in `engine::scan` (snapshot or staging, allowed-root and scope checks, server-mode restrictions) and in `mcp::precheck` if it carries a path or URL.
4. Register checks whose `kinds` include it. Update the profile table in [usage.md](usage.md) and [checks.md](checks.md).

## Adding a parser

Write `parse_x(text) -> Result<Vec<Finding>>` as a pure function, with `Severity::parse` for lenient severities. Keep it free of IO so it can be tested from a recorded file under `tests/fixtures/tool-outputs/`. For a new log source, call `ctx.error_line("<source>", &redacted_line)` and the engine clusters it.

## Testing

Run only dev builds and tests on the author's machine (see constraints). With cargo on PATH:

```bash
export PATH=$PATH:$HOME/.cargo/bin
cargo check
cargo test                       # about 50 unit tests; no Docker needed
cargo test nuhire -- --ignored   # NuHire dump (needs the nuhire checkout)
```

Test layers:

| Layer | Where | What |
|---|---|---|
| Parser golden tests | `tools.rs`, `web.rs`, `host.rs`, `android.rs` tests | Recorded tool outputs in `tests/fixtures/tool-outputs/` (gitleaks, grype, semgrep, hadolint, checkov, dockle, JUnit, SARIF), `tests/fixtures/host-probe/{linux,macos,windows}.json`, `tests/fixtures/android/{logcat.txt,mobsf_report.json}`. The plan said `insta`; the tests use plain asserts. |
| Policy/security units | `policy.rs`, `scope.rs`, `snapshot.rs`, `tools.rs` (`policy_rejects_bad_args`), `report.rs` (XSS), `mcp.rs` (scripted session), `llm.rs` (cloud guard, redaction), `logs.rs` (clustering, redaction), `serve.rs` | |
| Rules on the fixture | `rules.rs::fixture_findings` | Runs all native checks over `tests/fixtures/vuln-app` and asserts the expected rule ids; asserts a comment does not trigger `readiness.k8s.privileged` |
| Live | manual, via a Sonnet verification agent | Scans against Docker, the fixture end to end |

### The vuln-app fixture

`tests/fixtures/vuln-app` is intentionally vulnerable; never deploy it. It seeds:

- `Dockerfile` on `python:3.11-slim`, no `USER`, no `HEALTHCHECK`, no `.dockerignore`
- `requirements.txt` with pinned vulnerable `requests==2.19.1`, `PyYAML==5.3`, `Jinja2==2.10` and an unpinned `fastapi`; no lockfile
- `docker-compose.yml` with `privileged: true`, a `curl` healthcheck on `/`, no limits
- `k8s/deployment.yaml` (no probes/limits) and `k8s/secret.yaml` (a Secret manifest)
- `Jenkinsfile` with `if command -v trivy; then trivy image ... || true; fi` (never fails, optional, no SAST/secret stage)
- `.env` (fake test-only secret) and `.env.example`, a fake secret in `app/config.py` (the plan also called for a symlink to `.env`; the fixture has none, so symlink dropping is not covered by it)
- `tests/test_app.py` with one passing and one deliberately failing test; `app/main.py` exposing `/health`

Do not open or print `.env` files. The in-code fake token is 36 characters so gitleaks recognizes it; a `ghp_`-style token may trip GitHub push protection when you publish.

### NuHire acceptance test

`cargo test nuhire -- --ignored` runs `rules.rs::nuhire_user_service`, which takes snapshots of `nuhire/services/user-service` and `nuhire/argocd` (hard-coded absolute paths) and **prints** the facts and every native finding. It has **no assertions**: compare the output with the expectations in [usage.md](usage.md#nuhire) by eye. Turning it into an asserting test is an open item.

## Build constraints

- On the author's machine only dev builds (`cargo check`, `cargo test`, `cargo build`) are run. No `--release`, no `docker build`, no heavy tests. `[profile.dev] debug = 0` to keep builds light. The user builds and runs images.
- `~/.cargo/bin` is not on PATH.
- Release profile: `strip`, `lto = "thin"`.

## Coding conventions

- Edition 2024, `anyhow` for errors, `serde` for IO types, blocking `reqwest` with rustls; `tokio` only for the server.
- Secrets: never read a denylisted path, never put secret text in a `Finding`, redact before clustering, logging or LLM use.
- Findings need a stable rule id, the right category and severity, a remediation, and a fingerprint key without line numbers or versions.
- Check status must be honest: use `partial`, `skipped`, `not_applicable` and `errored` rather than a silent pass.
- Shell out with an argv list (`Command::arg`), never through a shell string, except where a fixed remote script is the point (`host.rs`, ZAP's `sh -c` with a URL that is first checked for metacharacters).
- User-controlled strings that reach a command line (image, user, host) are validated: strict charset, no leading `-`, `--` before positional arguments.
- Keep parsers pure and tested from recorded outputs.
- Dead code (the LLM module) carries `#![allow(dead_code)]` until the agent phase wires it in.
