# Development

## Repo layout

```
readyhai/
  Cargo.toml  Cargo.lock  Dockerfile  docker-compose.yml  .env.example  .dockerignore  README.md  CHANGELOG.md  VERSION  Makefile
  tools.lock.toml          pinned scanner images (embedded at build time; override with READYHAI_TOOLS_LOCK)
  scope.example.toml       sample rules of engagement (copy to scope.toml, which is git-ignored)
  readyhai.toml            the self-scan config (suppresses the deliberately vulnerable fixtures)
  policies/default.toml    default gate policy (embedded)
  templates/               report.html.j2, qa-report.html.j2, dashboard.html.j2 (auto-escaped, CSP)
  data/endoflife.json      end-of-life snapshot (embedded)
  src/                     the crate (below)
  probe/                   linux.sh  macos.sh  windows.ps1   (embedded with include_str!, piped over ssh)
  runners/playwright/      Dockerfile  package.json  crawl.mjs qa.mjs pdf.mjs   (UI QA and PDF; image published to GHCR)
  runners/context_retriever/  Python (LangGraph, BGE-M3) retriever the agent can query for change notes
  frontend/                the Next.js Agent Studio (own README, own package.json)
  ci/                      Jenkinsfile.stage  github-action.yml  gitlab-ci.yml  argocd-postsync-job.yaml
  .github/workflows/       ci.yml  image.yml  release.yml  scorecard.yml
  scripts/version.sh       single-source versioning
  tests/eval/              eval suites (*.toml)
  tests/fixtures/          vuln-app, qa-api, qa-api-src, qa-repo, qa-ui, qa-perf, resilience, host-probe, android, logs, tool-outputs, mcp
  docs/                    this documentation
```

## Module ownership map

Lines include the unit tests that live in the same file.

| Module | Lines | Owns |
|---|---|---|
| `main.rs` | 750 | CLI (clap), exit codes, summary printing, the `agent` and `agent-memory` commands |
| `model.rs` | 390 | Shared types: `Finding`, `CheckStatus`, `Target`, `Run`, `Profile`, `Verdict`, `ErrorCluster` |
| `engine.rs` | 990 | Orchestration, target parsing, run ids, data dir, git clone, deadlines |
| `checks.rs`, `ctx.rs`, `facts.rs`, `config.rs` | 70, 50, 30, 70 | `Check` struct and registry `all()`, per-run context, `Facts`, `readyhai.toml` types |
| `snapshot.rs` | 300 | Denylist and filtered copy |
| `policy.rs`, `baseline.rs` | 310, 145 | Suppressions, summary, verdict; baseline file and diff |
| `scope.rs` | 980 | `scope.toml`, host classification, egress guard, fail-closed loading |
| `rules.rs` | 2,050 | Native readiness checks, fact detection, Dockerfile/compose/k8s parsing |
| `tools.rs` | 2,800 | Docker runner, create-policy, lock file, parsers, scrubbers, `tests.own`, plugins, `tools pull/update` |
| `supply.rs` | 1,180 | OSV reachability, Scorecard, Spectral, oasdiff |
| `web.rs`, `host.rs`, `android.rs` | 980, 1,130, 1,180 | `web.smoke`, Schemathesis, ZAP, Playwright; SSH, probes, Lynis, host CVE; MobSF client, adb runtime, logcat |
| `logs.rs`, `report.rs` | 190, 600 | Error clustering and redaction; HTML, JSON, SARIF, JUnit |
| `network.rs` | 3,900 | Network lab: regress, curl, deep audit, multi-region, HAR, requester IP |
| `serve.rs` | 3,620 | REST API, scan worker, egress guard, agent and network routes, auth middleware |
| `mcp.rs` | 1,720 | MCP stdio server, `precheck`, async agent swarm |
| `llm.rs`, `llm/untrusted.rs` | 1,550, 180 | Provider catalog, call parameters, cache; untrusted-text helpers |
| `qa/` (mod, model, plan, triage, recommend, report, roles, ai, perf, resilience, suite, ui) and `qa/api/` (spec, synth, exec, authz, stateful, contract, latency, mod) | 9,800 + 6,700 | The senior-QA engine, see the module map in [architecture.md](architecture.md) |
| `agent/` (mod, pipeline, discover, plan, change, lead, budget, exec, oracle, verify, mutation, stateful, triage, ledger, memory, remediation, report, store, types, tests) | 32,800 | The agent, see the module map in [architecture.md](architecture.md#agent-architecture-srcagent) |
| `eval.rs` | 2,680 | `readyhai eval`: suite files, fixture launcher, scoring, reports |
| `bundle.rs`, `dashboard.rs` | 870, 340 | Offline bundle, `doctor`; static dashboard |

## Adding a check

1. Pick the module (`rules.rs` for native repo rules, `tools.rs` for containers, `web.rs`, `host.rs`, `android.rs`) or a new module added to `main.rs` and to `checks::all()`.
2. Register it:

```rust
Check::new("readiness.foo", "Foo hardening", &[TargetKind::Repo], Profile::Quick, |ctx| {
    // ctx.facts, ctx.snapshot, ctx.cfg, ctx.error_line(source, line)
    Ok(CheckOutput::findings(vec![ /* Finding::new(check, rule, Category, Severity, title, location) */ ]))
})
// .tool("grype")   // set when it needs a container: gives --no-tools / no-docker skipping and shows in `checks`
// .intrusive()     // only runs with --profile deep on a nonprod host; `qa.resilience` is the only built-in user
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
cargo test -j 2                  # about 640 unit tests; no Docker needed (-j 2 keeps the build light)
cargo test nuhire -- --ignored   # NuHire dump (needs the nuhire checkout)
cargo run -- eval                # detection quality vs seeded bugs (python3 + git; see eval.md)
EVAL_SUITES=qa-repo EVAL_K=1 cargo test -j 2 eval::tests::live_eval -- --ignored --nocapture
```

Test layers:

| Layer | Where | What |
|---|---|---|
| Parser golden tests | `tools.rs`, `web.rs`, `host.rs`, `android.rs` tests | Recorded tool outputs in `tests/fixtures/tool-outputs/` (gitleaks, grype, semgrep, hadolint, checkov, dockle, JUnit, SARIF), `tests/fixtures/host-probe/{linux,macos,windows}.json`, `tests/fixtures/android/{logcat.txt,mobsf_report.json}`. The plan said `insta`; the tests use plain asserts. |
| Policy/security units | `policy.rs`, `scope.rs` (host classification with a fake DNS table), `snapshot.rs`, `tools.rs` (`policy_rejects_bad_args`), `report.rs` (XSS), `mcp.rs` (scripted session, stdio isolation subprocess), `llm.rs` (cloud guard, redaction), `logs.rs` (clustering, redaction), `serve.rs` (every route returns 401 without a token, guard behaviour) | |
| Agent units | `agent/tests.rs` and the modules' own tests: oracle, planner, verifier, lead (one worker and four give the same plan, results, defects and ledger), memory, change, ledger, teardown. They run against in-process fixture servers on loopback | |
| Eval | `eval.rs` unit tests for the harness; the suites in `tests/eval` run in CI as the `eval` job | |
| Frontend | `frontend/src/**/*.test.{ts,tsx}` (vitest, jsdom); node 24 | |
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
- `src/agent/mod.rs` carries `#![allow(dead_code, unused_imports)]` for the public surface it re-exports; new agent code should not rely on it.
- Verdicts are deterministic: nothing an LLM says may change a verdict, a severity or a gate. Target-derived text that reaches a prompt goes through `llm::untrusted`.
- CI runs `cargo fmt -- --check` and `cargo clippy -- -D warnings`; run both before pushing. `main.rs` allows only style lints.
