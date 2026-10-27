# Build log

The record of how ReadyHai was built, in order. Date of the build: 2026-10-25. Plan: `/home/anshukushwaha/.claude/plans/now-in-the-ai-zesty-journal.md`.

## 1. Request

A DevOps engineer who also does QA by hand: tests apps manually, reads errors manually, and gets called out when AI agents find bugs first. The ask:

- A minimal, Docker-ready, sandboxed app to test applications on any platform.
- Check dependencies, CVEs, security and production readiness.
- Agentic behavior later (design for it now).
- Reference platform: NuHire.
- Standing rule: never read `.env` or credential files.

## 2. Research

Web searches covered: the scanner landscape (SCA, SAST, secrets, IaC, DAST), AI QA agents, AI pentest agents, production-readiness scorecards, the Trivy compromise, agent sandboxes, Appium drivers, MobSF, Schemathesis, Maestro and Playwright agents. Findings that shaped the design:

- The OSS and commercial tools are strong per category but nothing joins functional QA, security and a readiness verdict across repo, image, web, host and mobile. That is the gap (full table in [market-research.md](market-research.md)).
- Trivy's releases and Docker images were backdoored in March 2026 (TeamPCP; the KICS action hit too). Decision: treat every scanner as untrusted, pin by digest, no secrets/socket/env/network for static scans, make Grype and Syft primary (Grype's DB also carries EPSS and KEV).
- Agentic QA is real (Playwright Planner/Generator/Healer + MCP, Maestro MCP, commercial QA agents) and AI pentest agents exist (Strix, Shannon, PentAGI, CAI), but agents solve only about 13% of real CVEs in benchmarks and scanned content is a prompt-injection channel. Decision: MCP server first; no LLM power to waive findings; evidence required.
- Schemathesis for OpenAPI fuzzing, MobSF for APK/AAB, Lynis for Linux/macOS hardening, Appium NovaWindows/Mac2 for later desktop UI.
- `serde_yaml` is archived and `serde_yml` is unsound (RUSTSEC-2025-0068), so `serde_norway` was chosen.
- minijinja auto-escapes by template name, so the report template is named `report.html.j2`.

## 3. Exploration

**NuHire inventory** (`~/95095/Backup/Desktop/learn/nuhire`): 13 FastAPI/React services; Jenkins + ArgoCD; the only scanning is Trivy and it cannot fail the build; containers run as root; dependencies are unpinned; secret-bearing files are committed (found by path, never opened).

**Workspace reuse survey:** the `ai-tester` repo is missing from disk (so ReadyHai is fully independent). Patterns, not code, taken from: `devops-documents` scanners Jenkinsfile (stage order, ZAP start/poll/report), `pipeline/harbor/security-demo.sh` (Syft, Grype, Cosign), Shannon (ephemeral worker per scan, scope schema, audit log), `anthropic-proxy` provider catalog (LLM descriptor registry), `create-machine` (Ubuntu+SSH target for host tests), NuHire `user-service` health endpoint shape.

## 4. Decisions (Q&A)

| Question | Decision |
|---|---|
| Target families | All 4 in v1 (repo/image, web/API, host Linux/macOS/Windows, Android) |
| Interfaces | CLI + REST API + HTML report; dashboard later |
| Independence | Fully independent of ai-tester |
| Language | Rust |
| Name | `readyhai` ("Ready hai?", Hinglish) |
| Users | Just the author and CI, so a static token |
| Intrusive tests | Never on prod |
| Android runtime | Bring-your-own device |
| CI targets | Jenkins, GitHub, GitLab, ArgoCD PostSync, manual |
| LLM | Decide later; build the abstraction only |
| Extensibility | Plugin "mods" plus a Claude Code mod |

## 5. Architecture review

A critique agent reviewed the plan. Fixes adopted:

- judge0's `isolate` needs `privileged`: test the suppression path as a privileged negative test.
- Snapshot with a denylist instead of bind-mounting the live tree.
- Unpinned dependencies produce `partial`, not a false "0 CVEs".
- Run tests inside the target's image (`test.image` + `test.command`).
- Hard-fail rules limited to achievable ones (no Python reachability analysis).
- Report XSS closed through template naming (`report.html.j2`) plus CSP.
- `serde_yaml` replaced by `serde_norway`.
- Grype's built-in EPSS/KEV used instead of a separate enricher.
- The Docker socket proxy is not a security boundary; documented, rootless recommended.
- Results via `/out` files, never stdout.
- Fingerprint design (no line numbers, no versions) and a baseline file CI can carry.

## 6. Build (multi-agent)

- **Lead** wrote the contracts (`model`, `ctx`, `checks`, `facts`, `snapshot`, `config`) plus `engine`, `policy`, `baseline`, `scope`, the CLI and the server.
- **Sonnet agents** built: readiness rules; tool runners and parsers; web checks and reports; hosts (SSH, probes, Lynis); Android (MobSF, adb); logs and the Playwright runner; MCP, LLM abstraction and REST API; plus the verification rounds.
- **Haiku agent** built packaging and CI (Dockerfile, compose, `ci/` recipes).
- The model was chosen per task complexity, at the user's request.
- Deviations from the plan that emerged: docker CLI instead of bollard, OpenSSH client instead of russh, files instead of SQLite, no `gix`, probe via stdin instead of SFTP. See [architecture.md](architecture.md).

## 7. Verification

**Round 1** (all 10 steps passed). Fixes made:

- Tracked-file detection now also works when the scanned directory sits inside a parent git repository.
- `/tmp` tmpfs gets `mode=1777` so the distroless Grype image can write.
- Semgrep rule ids are normalized (the `cache.semgrep.` prefix is stripped).
- The fixture's fake token was made 36 characters so Gitleaks recognizes it.
- Dead code removed.

Further fixes:

- Denylist false positive: `templates/reset_password.html` was withheld; `*password*` is now limited to data-file extensions (`.txt,.json,.yaml,.yml,.csv,.ini,.conf,.cfg,.toml`).
- k8s grouping: the repetitive low-severity rules (`probe_root_path`, `run_as_root`, `latest_image`) emit one finding per file listing the objects.

**Round 2** (Sonnet verification agent, 2026-10-25). It covered everything new since round 1. Every step passed:

| Step | Result |
|---|---|
| `cargo test` / build / check | 48 passed, 1 ignored; no warnings |
| SSH host scan (throwaway linuxserver/openssh container, ed25519 key) | `host.probe` Partial (unprivileged): `host.no_firewall`, `host.no_time_sync` |
| Unknown host key | Refused: "host key not in known_hosts: run ssh-keyscan…" |
| Host CVEs | `host.cve` via grype: 29 findings (2 critical), verdict FAIL. `tools update` fetched the grype DB, semgrep rules and lynis |
| `--profile standard` on host | `host.lynis` Partial ("ran unprivileged"), 35 findings parsed from report.dat |
| Android, dummy APK | No panic. `android.mobsf` errored clearly (MobSF rejected the fake APK); `android.runtime` NotApplicable without `--device`, Skipped ("adb not installed") with it; `android:/etc/passwd` rejected |
| Logs / Playwright | `errors` key present; `tool.playwright` Skipped with the build hint. Top-errors HTML covered by unit test only |
| MCP over stdio | initialize → 4 tools → checks → scan of vuln-app gives FAIL with the untrusted-data prefix; `/etc` refused; deep refused; stdout carried only JSON-RPC |
| REST | POST `/etc` → 400 with no run dir created; valid POST → 202 → verdict in `GET /runs/{id}`; `GET /runs` lists it |
| NuHire user-service (native) | FAIL, 30 findings. Hard-fail: 4 × `readiness.repo.tracked_secret_file`. k8s low-severity findings grouped per manifest; `reset_password.html` no longer flagged |
| NuHire argocd (native) | FAIL, 46 findings; no `readiness.k8s.privileged` (negative test holds) |

**Fixed in round 2:**
- `web.rs`: ZAP never produced a report. Its tmpfs mounts are now `mode=1777` and `JAVA_TOOL_OPTIONS=-Duser.home=/home/zap` is set. ZAP now returns 9 findings against a local server.

**Fixed by the lead after round 2, from the docs agent's gap review:**
- **Scope:** in server/MCP mode the scope now also covers the `openapi` URL, `ssh://` hosts and `git:` clone hosts (`mcp.rs::precheck`, re-run inside `engine::scan`). A new unit test is `precheck_scopes_every_network_destination`.
- **Redirects:** web redirects are followed to the same host only (`web.rs::same_host_redirects`).
- **Repo config:** server/MCP mode ignores `network=true` in a target's `readyhai.toml` `[test]`. Suppressions supplied by the target are called out in the run notes.
- **Server:**
  - A restart marks orphaned queued/running runs as `error`.
  - `status.json` now carries the target while a run is queued or running.
  - `no_tools` is accepted in the REST body.
- **Packaging:**
  - The Dockerfile now installs `openssh-client`, so host scans work in server mode.
  - The ArgoCD PostSync Job gets a writable `/data` emptyDir.
- **Noise and accuracy:**
  - k8s `run_as_root`, `latest_image` and `probe_root_path` are grouped per manifest.
  - The denylist no longer matches `*password*.html` or `*credential*.py`-style source files.

**Note:** to test StrictHostKeyChecking, the round-2 agent temporarily edited the author's real `~/.ssh/known_hosts` and restored it from a backup. Afterwards it has 361 entries and no leftover test (port 2222) entries.

## 8. NuHire findings summary

From scanning NuHire statically (path-only for secrets):

- **user-service:** no `USER` and no `HEALTHCHECK` in the Dockerfile; 24 of 25 dependencies unpinned in `requirements-docker.txt`; an unpinned `git+` shared-lib; no lockfile; a `curl` healthcheck on a slim image that lacks it; the prod compose has no healthcheck; `.env.*` and `k8s/secret.yaml` are tracked (path only); Jenkins has no SAST or secret stage; the Trivy step is guarded and never fails.
- **argocd:** no `privileged` false positive (the word only appears in a comment); worker Deployments have no probes.

## 9. Known issues and not yet verified live

- Windows probe untested on a real host.
- MobSF API response shapes unverified.
- Playwright runner image never built.
- ZAP and Schemathesis never run live.
- Tool images unpinned until `readyhai tools pull --lock` is run.
- The fake `ghp_`-style token fixture may trip GitHub push protection.

Further issues found while writing these docs (from reading the code) are in [roadmap.md](roadmap.md#open-known-issues).

# Increment 2: senior-QA + offline (2026-10-25)

Plan: `~/.claude/plans/now-in-the-ai-zesty-journal.md`. Guides: [qa.md](qa.md), [offline.md](offline.md), [status-and-competition.md](status-and-competition.md).

## User asks
1. Where does ReadyHai stand, and how does it compare with competitors?
2. What should be added or improved?
3. Run offline, test at senior-QA level, produce a proper QA report.

## Decisions (Q&A)

| Question | Answer |
|---|---|
| Offline meaning | Both: air-gapped bundle with a deterministic engine, and a LAN LLM when reachable |
| QA scope | All four areas: API functional, UI exploratory, performance + resilience, suite + release quality |
| Reports | HTML + PDF test summary, Markdown, tracker exports (Jira, GitLab, TestRail, Xray), offline trend dashboard |
| Accounts | 2 or more roles on nonprod (authenticated and IDOR testing) |
| LLM | LAN vLLM with a small model (default Qwen/Qwen3-8B) |
| Performance | Smoke + baseline only: <= 10 VUs, 1-2 min, abort above 5% errors |

## Research summary
Agentic QA SaaS (QA.tech, testRigor, TestSprite, Autonoma) lead on UI exploration but are SaaS/BSL and not offline; Aikido/Snyk lead on reachability and auto-fix; SonarQube on code quality; DefectDojo aggregates. No competitor combines security, readiness and functional QA with one verdict, self-hosted and offline. Grype air-gapped needs DB auto-update off plus an own age check. Small local models are unreliable at tool calling, so the LLM layer is single-shot strict JSON only. Sources are listed in [status-and-competition.md](status-and-competition.md).

## Design review notes
The plan agent was cut off before finishing, so the lead reviewed the code directly. Constraints adopted: every `Defect` maps to one `Finding` (gate/baseline/SARIF/JUnit unchanged); `tools::exec` has no stdin and only `/src`, `/out`, `/cache` mounts, so runners take input from files; an image pinned `repo@sha256` does not resolve after `docker load`, so the offline lock records image IDs and tools run by ID; grype offline flags plus ReadyHai's own DB-age check; recommendation computed, never chosen by the LLM.

## Multi-agent execution

| Role | Model | Owned |
|---|---|---|
| Lead | Opus | contracts: `qa/model.rs`, Ctx fields, `qa` CLI, composite target |
| qa-core | Sonnet | `qa/{mod,plan,triage,recommend,roles}.rs` |
| api | Sonnet | `qa/api/*`, qa-api fixture |
| offline | Sonnet | `bundle.rs`, lock-by-ID in `tools.rs`, grype offline flags, `doctor`, endoflife snapshot |
| ui | Sonnet | `runners/playwright/{qa,pdf}.mjs`, `qa/ui.rs`, qa-ui fixture |
| perf + resilience | Sonnet | `qa/perf.rs`, `qa/resilience.rs` |
| suite | Sonnet | `qa/suite.rs`, qa-repo fixture |
| report | Sonnet | `qa/report.rs`, QA template, tracker exports, dashboard |
| llm | Sonnet | `llm.rs` strict-JSON layer, `qa/ai.rs`, mock server tests |
| verifier | Sonnet | live runs on fixtures, offline round trip, secrets guard |
| docs | Sonnet | this documentation |

At most about 3 agents ran at a time (429 session limit, limited RAM). Docker image builds (Playwright runner, ReadyHai) were left to the user.

## Notable fixes and decisions during the build
- `gen.rs` renamed to `synth.rs`: `gen` is a reserved keyword in Rust edition 2024.
- Claude Code mod: the model context must be `string[]`. The v1 mod passed a string, so findings never reached the model (bug since v1).
- UI secrets: role `storageState` copied per run with mode 0600 into a 0700 dir and deleted afterwards; the runner container runs as the file owner's uid:gid to read it.
- LLM unreachable: report carries the note "LLM configured but unreachable (2s probe): report is deterministic-only".
- `[license] deny` added to `readyhai.toml` (plus `READYHAI_LICENSE_DENY`).
- `scope::set_active` so QA code can read the scope's perf/resilience settings.
- Perf `baseline accept`: the last k6 result is stored as `<key>.perf.last.json` and promoted by `readyhai baseline accept`.

## Results so far

| Check | Result |
|---|---|
| API QA on qa-api fixture | 7/7 seeded bugs found, 0 false positives (live) |
| Prod safety | fixture tagged prod: 70 GET requests, 0 non-GET (live) |
| Offline bundle | core bundle 3.63 GB (grype, syft, gitleaks; grype DB about 3.3 GB), export -> import round trip on a fresh data dir (live) |
| k6 perf | live run on the fixture |
| UI, PDF | not run: runner image not built |
| Resilience | not run live (logic unit-tested) |
| LLM | mock server only |

## Verification round 3 (Sonnet verifier, 2026-10-25)

Every step passed. Steps 8 (LLM) and 9 (UI) passed without exercising their real path; see the table.

| # | Step | Result |
|---|---|---|
| 1 | `cargo test` / build / check | 117 passed, 1 ignored; no warnings |
| 2 | `qa` against qa-api (nonprod) + qa-repo, every format | Exit 2, **No-Go**, 15 defects, 88 cases (86 run: 72 pass, 14 fail, 1 blocked). **All 7 seeded API bugs** found (bola, authz_missing, server_error, error_leak, contract_violation, delete_not_effective, slow_response), plus privilege_escalation. All 4 qa-repo issues found (low coverage, untested routes, test smells, EOL python:3.8), plus `app/auth.py` at 0% coverage. HTML has a CSP and no scripts. md, jira, gitlab, testrail, xray, sarif and junit were written. PDF skipped with a note because the runner image isn't built |
| 3 | Host tagged `prod` | 70 requests, **0 non-GET**; writes reported as "read-only: host not nonprod" |
| 4 | Secrets | 0 hits for the fixture tokens across data, reports, artifacts and the LLM cache; repro steps use `$RH_*_TOKEN` |
| 5 | Baseline accept, then re-run | 14 defects `existing`, `regression=false`. Gate drops to WARN, but the recommendation stays No-Go because existing P1s and contract violations still fail the exit criteria (intended) |
| 6 | Perf + dashboard | k6: 1260 requests, 0% errors, baseline recorded. Dashboard: static, 2 SVG charts, 0 scripts, 5 runs |
| 7 | Offline | `doctor` reports offline; `tools update` refuses; the QA run works with mode `offline` |
| 8 | LLM configured but unreachable | Note added, mode deterministic, no extra run time |
| 9 | UI (runner image not built) | `qa.ui` and `tool.playwright` Skipped with the build hint; no crash |
| 10 | Claude Code mod | `claude plugin validate` passes |

**Fixed in round 3:**
- **Fixture binding:** the qa-api fixture bound to 127.0.0.1, so containers (k6, ZAP) couldn't reach it. It now binds to 0.0.0.0.
- **k6 failure counting:** k6 counted expected 4xx responses as failures. Only 5xx responses and network errors count now.
- **Aborted perf runs:** an aborted perf run could become the baseline. Baselines are now written only from healthy runs.
- **Schemathesis spec:** a local `--spec` file wasn't visible inside the container. It is now staged into `/out`.
- **Markdown notes:** the Markdown report was missing QA notes.

**Fixed by the lead:**
- **Offline mode and the LAN LLM:** `READYHAI_OFFLINE=1` no longer switches off the LAN LLM. The mode reads `offline+lan-llm`, so you get no internet but can still use the local AI, as decided.
- **Run time:** a full QA run with all tools takes 6–15 min, mostly ZAP and Schemathesis. `--no-tools` takes about 30 s but also skips UI and perf.
- **Still unverified live:**
  - UI defect recall and the PDF render, which both need `docker build -t readyhai/playwright-runner:local runners/playwright`
  - resilience (logic only)
  - a real vLLM (mock-tested only)
  - MobSF and Windows hosts (from earlier)


## Verification round 4: Agentic AI & Web Studio (2026-10-27)

Every step passed. Live verification performed with local vLLM serving `qwen3.8-flash-next` and automated browser testing.

| # | Step | Result |
|---|---|---|
| 1 | `cargo test` / build / check | 119 passed, 1 ignored; 0 warnings |
| 2 | Autonomous Agent Loop (`src/agent.rs`) | **Live verified:** Planner synthesizes 6 test scenarios; Explorer probes target; Triager groups defect clusters; Readiness Gate renders GO/NO_GO verdict |
| 3 | 2026 Evidence Ledger | **Live verified:** 4-pillar breakdown (Value: 100, Authority: 98, Safety: 96, Evidence: 95; overall 98%) |
| 4 | Local vLLM Reasoning Model | **Live verified:** Sub-10ms probe latency on vLLM serving `qwen3.8-flash-next`; proper handling of `reasoning_content` tokens; 2048 token generation budget |
| 5 | Cyber-Dark Web Studio SPA (`src/web_ui.rs`) | **Live verified:** Single-page application served at `http://127.0.0.1:8080/` with Inter + JetBrains Mono, real-time pipeline telemetry, interactive test matrix, and copyable cURL commands |
| 6 | REST API (`src/serve.rs`) | **Live verified:** `/api/agent/status`, `/api/agent/run`, `/api/agent/runs`, `/api/agent/runs/{id}` return HTTP 200 |
| 7 | CLI Subcommand (`src/main.rs`) | **Live verified:** `readyhai agent http://localhost:3000` completes in ~9s with definitive terminal verdict and exit codes |
| 8 | Browser End-to-End Test | **Live verified:** Autonomous browser subagent executed all 11 test steps on `http://127.0.0.1:8080/`; verified live progress bar, gate banner, scenario inspection, threat triage, and historical run table (recorded as WebP and PNGs) |

## Verification round 5: Next.js 15 Agent Studio, Persistent Global History & Multi-Container Docker (2026-10-27)

Every step passed. Live verification performed with local Next.js 15 studio, standalone Docker container, and automated browser testing.

| # | Step | Result |
|---|---|---|
| 1 | Next.js 15 Cyber-Dark Studio (`frontend/`) | **Live verified:** Standalone Next.js 15 App Router app with React 19, Tailwind CSS, and Lucide icons. Split-screen layout with real-time Swarm Composer, active stage pipeline, deep scenario inspector, and Evidence Ledger. |
| 2 | Legacy UI Removal & REST Engine | **Live verified:** Removed legacy in-binary HTML SPA from port 8080. Port 8080 now operates as an ultra-low-latency Axum JSON API and background worker that cleanly redirects browser visits to port 3000. |
| 3 | Persistent Global History Archive | **Live verified:** Every reconnaissance scan (`/api/agent/discover`) and autonomous test run (`/api/agent/run`) is persisted to `~/.local/share/readyhai/agent-runs/`. Tested and verified that discovery scan `20261027-125954-8df6` persists with route classifications, baseline tests, and scores. |
| 4 | Run Deletion & Retest Mutation | **Live verified:** `DELETE /api/agent/runs/{id}` deletes runs from disk and state. `POST /api/agent/retest` executes live browser probes and immediately updates the persisted JSON report on disk. |
| 5 | Target Exclusion & Privacy Enforcement | **Live verified:** Purged 6 historical runs of `agent-prod.nuhire.in` from disk and cache. Added server-side and client-side filtering. Verified 0 occurrences across all history tabs, docs, and git diffs. Verified zero leaks of internal cluster IP addresses (`10.10.110.42`). |
| 6 | Multi-Container Docker Build | **Live verified:** Built `readyhai-frontend:local` via `frontend/Dockerfile` (Node.js 20 Alpine standalone output, UID 10001). Verified container serves HTTP 200 on port 3005. Configured `docker-compose.yml` to orchestrate backend (`readyhai:local` on 8080) and frontend (`readyhai-frontend:local` on 3005). |
| 7 | Full Browser End-to-End Test | **Live verified:** Autonomous browser subagent executed full navigation test on `http://127.0.0.1:3000/`. Verified clickable tabs (`#tab-scenarios`, `#tab-routes`, `#tab-ledger`, `#tab-triage`, `#tab-history`). Verified past runs render with `SCAN` and `TEST RUN` badges, and confirmed complete absence of excluded domains. Captured screenshots: `history_tab_view_1793107149703.png`, `routes_tab_view_1793107155386.png`, `ledger_tab_view_1793107161087.png`, `scenarios_tab_view_1793107166935.png`. |
