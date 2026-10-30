# Architecture

Single Rust crate (`readyhai`, edition 2024, ~16,300 lines in `src/` after increment 2; the table below describes the v1 components, the QA module map follows at the end). One binary provides the CLI, the REST server, the MCP stdio server and a health probe.

## Components

| Component | Code | Role |
|---|---|---|
| CLI | `src/main.rs` | clap derive. Subcommands `scan`, `baseline accept`, `checks`, `tools pull|update`, `serve`, `mcp`, `ping`. Maps verdict to exit code. |
| Engine | `src/engine.rs` | Parses target, takes snapshot, detects facts, loops over the check registry, dedups, applies suppressions and baseline, runs the gate, writes `run.json`. |
| Check registry ("mods") | `src/checks.rs` | `Check { id, title, kinds, min_profile, tool, intrusive, run }`. `checks::all()` concatenates built-in modules plus optional plugins. |
| Native rules | `src/rules.rs` | `readiness.*` checks (Dockerfile, deps, compose, k8s, CI, repo hygiene) and fact detection. In-process, no containers. |
| Tool runners and parsers | `src/tools.rs` | Docker sandbox runner, create-policy, lock file, gitleaks/grype/semgrep/hadolint/checkov/dockle/image-inspect/JUnit/SARIF parsers, `tests.own`, plugins, `tools pull|update`. |
| Web checks | `src/web.rs` | Native `web.smoke`, plus Schemathesis, ZAP baseline, Playwright runner containers. |
| Host checks | `src/host.rs` | SSH probe (Linux/macOS/Windows), host package CVEs through grype, Lynis. |
| Android checks | `src/android.rs` | MobSF per-scan container, adb runtime check. |
| Snapshot | `src/snapshot.rs` | Filtered copy of the repo. Secret-bearing files become empty placeholders. |
| Facts | `src/facts.rs`, `rules::detect_facts` | What is in the snapshot (Dockerfiles, compose, k8s, manifests, CI files, README, tests, framework, dep counts). |
| Policy gate | `src/policy.rs` | Suppressions, per-category summary, verdict. Default policy embedded from `policies/default.toml`. |
| Baseline | `src/baseline.rs` | Accepted fingerprint set, portable JSON. |
| Scope | `src/scope.rs` | `scope.toml` rules of engagement for web targets. |
| Reports | `src/report.rs`, `templates/report.html.j2` | HTML, JSON, SARIF 2.1.0, JUnit. |
| Log clustering | `src/logs.rs` | Normalizes error lines into signatures, groups, redacts examples. |
| REST server | `src/serve.rs` | axum 0.8, bearer token, one in-process worker. |
| MCP server | `src/mcp.rs` | Hand-written JSON-RPC 2.0 over stdio. No `rmcp` crate. |
| LLM abstraction | `src/llm.rs` | Provider catalog (vLLM, Ollama, cloud), reasoning token extraction, token budgeting. |
| Agentic AI Engine | `src/agent/` | Autonomous 4-agent loop (Planner -> Explorer -> Triager -> Readiness Gate), 4-pillar Evidence Ledger scoring. |
| Web Studio SPA | `src/web_ui.rs` | Cyber-dark single-page web app with real-time pipeline status, terminal trace, scenario inspector, and runs history. |

## Agentic AI Architecture & Evidence Ledger (Increment 3)

The Agentic AI subsystem in `src/agent/` introduces an autonomous multi-agent testing architecture governed by an LLM-as-a-Judge supervisor:

```
[Target URL / Spec]
        │
        ▼
1. Planner Agent ────────► Synthesizes boundary, negative, RBAC, and injection scenarios
        │
        ▼
2. Explorer Agent ───────► Executes probes, measures latency, captures reproduction cURL
        │
        ▼
3. Triager Agent ────────► Clusters defects by root cause, tags OWASP Top 10 vulnerabilities
        │
        ▼
4. Readiness Gate ───────► Evaluates exit criteria, assesses residual risk, computes Evidence Ledger
        │
        ▼
[Evidence Ledger] ───────► GO / CONDITIONAL_GO / NO_GO Verdict
```

### Global History Archive & Persistence Engine

All scans and test runs are persisted in the local data directory under `~/.local/share/readyhai/agent-runs/`:
- **Unified `AgentRunReport` Schema:** Standardized JSON persistence containing discovered routes, synthesized test vectors, response payloads, reproduction cURL snippets, defect clusters, and 4-pillar Evidence Ledgers.
- **Reconnaissance Discovery Persistence:** When `/api/agent/discover` executes, a full report profile `"discovery-scan"` is stored, making active discovery history visible across browser sessions and CLI runs.
- **In-Place Retest Mutation:** When `/api/agent/retest` is invoked, the engine updates the test case result in-memory and atomically rewrites the JSON file on disk, maintaining an accurate audit ledger.
- **Strict Domain Exclusions:** Enforced server-side filtering (`out.retain(...)`) guarantees that sensitive or excluded domains (such as `agent-prod.nuhire.in`) never appear in query listings or disk-backed reports.

### The 4 Pillars of the 2026 Evidence Ledger

1. **Value Pillar (Weight: 25%):**
   - Verifies core functional journeys, payload structure tolerances, and boundary values.
2. **Authority Pillar (Weight: 25%):**
   - Tests horizontal/vertical access boundaries, IDOR manipulation, and tenancy separation.
3. **Safety Pillar (Weight: 25%):**
   - Probes SQL/NoSQL injections, stored/reflected XSS, path traversal, prompt shielding, and credential masking.
4. **Evidence Pillar (Weight: 25%):**
   - Ensures all identified defects include reproducible, self-contained cURL commands and verifiable audit trails.

### Web Studio SPA Integration

Implemented directly in `src/web_ui.rs` as an embedded single-page application served via axum (`GET /` and `GET /ui`). It provides real-time model telemetry, interactive agent pipeline state tracking, copyable reproduction commands, and historical run comparison without external CDN dependencies.

## Executors

The plan named three executors. In code they are not a trait; each check owns its execution path.

| Executor | Used by | Mechanism |
|---|---|---|
| Sandbox container | `tool.*`, `tests.own`, `host.cve`, plugins | `docker run` through the **docker CLI** (`std::process::Command`), with a fixed hardened flag set. |
| Remote (SSH) | `host.probe`, `host.lynis` | The system **OpenSSH client** (`ssh`), script piped on stdin. |
| In-process | `readiness.*`, `web.smoke`, `image.inspect` (calls `docker image inspect`) | Plain Rust (and `reqwest` for HTTP). |
| Per-scan service container | `android.mobsf` | `docker run -d` MobSF, REST on a loopback port, removed after the scan. |
| Local adb | `android.runtime` | `adb` binary on the machine running readyhai. |

## Data flow

```
 CLI: readyhai scan ...      REST: POST /runs (axum)       MCP: readyhai_scan (stdio JSON-RPC)
        \                          |  queue (mpsc, 1 worker)        /
         '------------------- engine::scan(opts, run_id) ----------'
                                   |
   parse_target ──► scope check (web) ──► allowed-roots check (server/MCP)
                                   |
   Repo:  snapshot::take(src → runs/<id>/src)   Image: docker save → runs/<id>/src/image.tar
                                   |
                       rules::detect_facts(snapshot) ─► Facts
                                   |
   for check in checks::all(plugins):          (kind match, profile >= min_profile)
        skip?  --no-tools | docker missing | intrusive without deep+nonprod
        run:   native fn  |  docker run (net none, /src ro, /out rw)  |  ssh  |  http
        parse /out file ─► Vec<Finding>        status = passed|failed|partial|skipped|n/a|errored
                                   |
   finalize fingerprints ─► dedup ─► suppressions (readyhai.toml) ─► baseline diff (new/existing)
                                   |
   sort ─► policy::verdict (PASS/WARN/FAIL + reasons) ─► run.json
                                   |
   report::write ─► html | json | sarif | junit          exit code 0/1/2 (3 on error)
```

Error lines (web 4xx/5xx, console errors, journald, logcat) are pushed into `Ctx::error_lines` by checks and clustered by `logs::cluster` into `Run.errors` ("Top errors", max 50 clusters).

## Data model

All in `src/model.rs`; serialized with serde.

**Target**: `kind` (`repo|image|web|host|android`), `raw` (as typed), plus `path`, `image`, `url`, `openapi`, `host` (`HostSpec{user,host,port,os,key}` - key is never serialized), `apk`, `device`.

**Check** (registry entry): `id`, `title`, `kinds[]`, `min_profile`, `tool` (container tool name or none), `intrusive`, `run(&Ctx) -> Result<CheckOutput>`.

**CheckStatus** (JSON: `{"state": "...", "reason": "..."}`): `passed`, `failed`, `partial(reason)`, `skipped(reason)`, `not_applicable(reason)`, `errored(reason)`. A check that returns findings and no explicit status is `failed` if it has any findings, else `passed`. `Err` or panic becomes `errored`. See [checks.md](checks.md) for when each occurs.

**Finding**

| Field | Notes |
|---|---|
| `fingerprint` | 24 hex chars, `sha256(rule \0 key)[..12]`. Key is `fp_key` if set, else `location`. |
| `check`, `rule` | Producing check id and stable rule id (`readiness.dockerfile.no_user`, `CVE-2024-1234`, `secrets.aws-access-token`). |
| `category` | `security`, `supply_chain`, `reliability`, `observability`, `quality`, `operability`, `performance`. |
| `severity` | `info < low < medium < high < critical`. |
| `title`, `detail`, `remediation` | Free text. Attacker-controlled for scanned content; escaped in HTML, labelled untrusted over MCP. |
| `location` | `path:line`, `path`, URL, `user@host:section`, image ref, or package. |
| `ids`, `package`, `version`, `fix_version`, `epss`, `kev` | Vulnerability data from Grype. |
| `status` | `new`, `existing`, `suppressed`. Plus `suppressed_reason`. |

Fingerprint keys are chosen so unrelated edits do not change identity: vulnerabilities use `canonical-id|package|manifest-path` (no version, so a bump is not "fixed + new"); SAST uses `path|hash-of-matched-snippet` (no line number); gitleaks uses `file|rule`; compose/k8s findings use `file:service-or-object`.

**Run**: `id`, `version`, `target`, `profile`, `started`, `finished`, `verdict`, `reasons[]`, `categories[]` (counts by severity and new/existing/suppressed), `checks[]` (`CheckResult{id,title,tool,status,findings,duration_ms}`), `findings[]`, `fixed` (baseline fingerprints no longer seen), `notes[]`, `errors[]`.

**ErrorCluster**: `signature` (ids, numbers, timestamps stripped), `example` (redacted, max 300 chars), `count`, `source` (`web.console`, `web.http`, `host.journal`, `host.oslog`, `host.eventlog`, `android.logcat`), `first_seen`.

## Run directory

`<READYHAI_DATA>/runs/<run-id>/` (default data dir: `$XDG_DATA_HOME/readyhai` or `~/.local/share/readyhai`). Run id: `YYYYMMDD-HHMMSS-xxxx` (UTC + 4 hex).

```
runs/<id>/
  src/             snapshot (repo), image.tar (image), app.apk (android) - mounted read-only at /src
  out/             tool outputs (mounted rw at /out): gitleaks.json, sbom.cdx.json, grype.json, semgrep.json,
                   results_json.json (checkov), dockle.json, junit.xml, zap.json, playwright.json + screenshots,
                   host-probe.json, host-sbom.cdx.json, host-grype.json, mobsf.json
  artifacts/       created, currently unused by checks
  report/          server mode only: readyhai-report.{html,json,sarif,junit.xml}
  run.json         full Run, written at the end of engine::scan
  status.json      server mode only: {"id","state","error"}; state queued|running|done|error
<data>/baselines/<sha256(target)[..16]>.json   default per-target baseline
<data>/cache/{grype,semgrep,lynis}/            vuln DB, rule pack, Lynis tarball (shared tool cache)
```

CLI reports go to `--out` (default `./readyhai-report/`), not into the run directory. `tool` outputs of gitleaks, semgrep and checkov are rewritten after parsing with match text removed (see [security-model.md](security-model.md)).

## Why Rust

- One static-ish binary and a small image. The same binary is CLI, server and MCP server.
- The tool is an orchestrator of containerized scanners, so Python's library advantage is small.
- Memory safety for a program that parses attacker-controlled scanner output, YAML and HTTP responses.
- Cost: no Playwright for Rust (the runner is a Node container), dev builds only on the author's machine, cargo is not on PATH (`~/.cargo/bin`).

## Why the docker CLI instead of bollard

The plan used `bollard`. The build uses `Command::new("docker")`:
- Fewer dependencies (no hyper/tokio-docker stack; `Cargo.toml` has 17 direct dependencies, tokio only for the server).
- Volume subpath mounts, `--tmpfs`, `--log-driver none` and `--read-only` are one-flag each and easy to review as an argv list. `validate_create_policy` inspects that list before the run.
- Works unchanged against a remote `DOCKER_HOST` (socket proxy) and rootless Docker or Podman.
- Cost: shells out (the image bundles the `docker` CLI from `docker:29-cli`), exit-code and stderr parsing, a 150 ms polling loop for timeouts, no streaming API. The create-policy is a string check over argv, not a check of the final container config.

## Why the OpenSSH client instead of russh

The plan used `russh` + `russh-sftp`. The build pipes the probe script to `ssh` on stdin:
- Reuses the user's `known_hosts`, ssh-agent and `~/.ssh/config` (ProxyJump etc.) with the real, battle-tested host-key verification: `-o StrictHostKeyChecking=yes -o BatchMode=yes`.
- No SSH implementation or key handling in this process; no SFTP and no files written on the target (the Linux probe runs as `exec sh -c "$script"` from stdin).
- Cost: requires `ssh` on the machine running readyhai. The Docker image does **not** install it, so host scans work from the CLI but not from the shipped container (see [deployment.md](deployment.md)). The Windows path relies on `powershell ... -Command -` reading the script from stdin.

## Design trade-offs and deviations from the plan

| Topic | Plan | Code today | Consequence |
|---|---|---|---|
| Storage | SQLite (`sqlx`) | Files only (`run.json`, `status.json`, baseline JSON) | Simple, greppable. No query across runs; list endpoint scans directories (last 50). |
| Job queue | SQLite-persisted | In-memory `tokio::mpsc` (cap 64), one worker | Restart loses queued jobs; `status.json` stays `queued`. |
| Git index | `gix` | `git ls-files` via the host `git` binary, also in parents and nested repos | Needs `git` on PATH (the image installs it). |
| Git clone | pinned `alpine/git` container | host `git clone --depth 1` with hooks off, `protocol.file.allow=never`, `core.symlinks=false`, no submodules | Clone runs outside the sandbox. |
| Probe delivery | SFTP upload | stdin pipe over ssh | Nothing is written to the target. |
| Concurrency | memory-budget scheduler | sequential checks; one server worker | Predictable memory. Slow on big targets. |
| Executors | trait + enum | per-check code | Less abstraction, easy to read. |
| `schemars` / JSON schemas | per-check schemas | not present | MCP tool schemas are hand-written. |
| Deep profile | intrusive checks | no check is marked intrusive yet | `deep` currently only enables `deep`-profile plugins and the Android monkey run. |
| Required check errored | hard FAIL | WARN | See [checks.md](checks.md#verdict-rules). |
| TLS expiry / protocols | native check | not implemented | Documented gap in `web.rs`. |

## Senior-QA module map (increment 2)

QA checks are ordinary registry checks flagged `.qa()`; they run only for `readyhai qa`. A composite `Target` carries both `url` and `path` (`--repo`), so repo/image checks and QA checks produce one `Run` with `qa: Option<QaReport>`.

| Module | Role |
|---|---|
| `src/qa/mod.rs` | `QaCtx` (roles, spec, journeys, `nonprod`, collector, 5 rps throttle, 2000-request cap), `checks()`, `build_report()` |
| `src/qa/model.rs` | Data model (below) |
| `src/qa/plan.rs` | Risk-based plan: spec operations x roles, impact x likelihood, budget |
| `src/qa/api/{spec,synth,exec,authz,stateful,contract,mod}.rs` | OpenAPI loader, case synthesis (renamed from `gen.rs`, `gen` is a reserved keyword in edition 2024), HTTP executor with redaction, auth matrix, CRUD/BOLA, contract + breaking change |
| `src/qa/ui.rs` + `runners/playwright/{qa,pdf}.mjs` | Playwright runner modes (crawl, responsive, a11y, vitals, forms, journeys, visual), PDF rendering |
| `src/qa/perf.rs` | k6 script generation, limits, baseline store/compare |
| `src/qa/resilience.rs` | compose pause/unpause fault injection with Drop guard |
| `src/qa/suite.rs` | coverage, routes, smells, EOL, migrations, licences |
| `src/qa/triage.rs` | dedupe, 5xx root-cause grouping, severity/priority |
| `src/qa/recommend.rs` | exit criteria, Go / Conditional Go / No-Go, executive summary |
| `src/qa/ai.rs` + `src/llm.rs` | optional LAN-LLM enrichment (`ask_json`: single-shot strict JSON, cache, budget) |
| `src/qa/report.rs` + `templates/qa-report.html.j2` | HTML, PDF, Markdown, Jira/GitLab/TestRail/Xray exports |
| `src/qa/roles.rs` | roles.toml loader and credential resolution |
| `src/bundle.rs` | offline export/import, `doctor`, endoflife snapshot |
| `src/dashboard.rs` | `index.jsonl` append (engine) and static dashboard |

Flow: engine runs all checks -> findings -> baseline + policy gate -> verdict -> `qa::build_report` (triage, coverage, exit criteria, recommendation) -> optional `ai::enrich` -> `run.json` -> `dashboard::append_index` -> report writers.

## QA data model (`src/qa/model.rs`)

| Type | Fields (main) |
|---|---|
| `TestCase` | `id` (stable, e.g. `api.GET./orders/{id}.authz.user`), `area` (api, ui, perf, resilience, suite, release), `technique` (positive, boundary, equivalence, negative, auth_matrix, state_transition, contract, exploratory, regression, perf_baseline, resilience, static), `title`, `priority` P1-P4, `component`, `role`, `steps`, `expected`, `source` (deterministic, llm, user) |
| `TestResult` | `case_id`, `status` (pass, fail, blocked, skipped, flaky), `actual`, `duration_ms`, `attempts`, `evidence[]`, `defect_id` |
| `Evidence` | `kind` (http exchange, screenshot, trace, k6 summary...), `path` relative to the artifacts dir; always redacted |
| `Defect` | `id`, `rule`, `category`, `severity`, `priority`, `area`, `title`, `component`, `environment`, `steps_to_reproduce` (curl / Playwright, tokens as `$RH_<ROLE>_TOKEN`), `expected`, `actual`, `evidence`, `reproduced (N, M)`, `cases`, `remediation`, `fp_key`, `fingerprint`, `status`, `regression`, `ai_note` |
| `CoverageMatrix` | rows endpoints/pages/journeys x columns techniques/roles; cell = pass, fail, untested, n/a |
| `QaReport` | plan, environment, `cases`, `results`, `counts`, `coverage`, `defects`, `risks`, `exit_criteria[{name, met, blocking, detail}]`, `recommendation`, `executive_summary`, `ai_summary`, `notes` (mode, LLM note, untested reasons) |

**Defect -> Finding twin:** `Defect::to_finding(check)` yields exactly one `Finding` (rule `qa.<area>.<kind>`, same fingerprint), so the gate, baseline suppressions, SARIF and JUnit need no changes. The fingerprint uses `rule` + `fp_key`, so QA defects are baselined like any other finding.
