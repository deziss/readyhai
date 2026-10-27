# Roadmap

Status key: **Done** (implemented, covered by tests or verification), **Done-unverified-live** (implemented and fixture-tested, never run for real), **Next**, **Later**.

## Phases

| Phase | Scope | Status | Notes |
|---|---|---|---|
| 0 Skeleton | Crate, models, sandbox executor with create-policy and reaper, snapshot + denylist, `scan`, JSON + HTML report, `serve` + compose | **Done** | Plan said SQLite; the build uses files only. Exit criterion (fixture scan, secrets guard) passed in verification round 1. |
| 1 Repo + Image | Syft/Grype, Semgrep, Gitleaks, Checkov, Hadolint, Dockle, readiness rules, own-tests, fingerprints + baseline, gate, SARIF/JUnit, Jenkins stage | **Done** | Verification round 1: all 10 steps passed. Kustomize rendering not done. NuHire check is a printing test, not an asserting one. |
| 2 Web/API | Smoke, Schemathesis, Playwright runner, ZAP baseline, scope enforcement, log clustering, GitHub/GitLab templates | **Done-unverified-live** | `web.smoke` and clustering verified; ZAP and Schemathesis never run live; Playwright image never built. TLS expiry/protocol checks missing. |
| 3 Hosts | SSH executor + host-key verify, Linux probe + Lynis + package CVEs, macOS/Windows probe + core rules | **Done-unverified-live** | OpenSSH client instead of russh. Windows probe untested on a real host. Not in the shipped container image (no `ssh`). |
| 4 Android | MobSF per-scan container, BYO-device ADB runtime | **Done-unverified-live** | MobSF API response shapes unverified against a real instance; `adb` must be on the machine. |
| 5 CI + PostSync | ArgoCD PostSync Job, API polish, deferred items as needed | **Done-unverified-live** | Recipes written; PostSync manifest has a known writable-data-dir problem and no registry image; not run on k3d. |
| 6 Agentic | Autonomous agent loop + Evidence Ledger + Web Studio | **Done, live** | MCP server (4 tools), full 4-agent autonomous pipeline (`src/agent.rs`), 4-pillar Evidence Ledger, Web Studio UI (`src/web_ui.rs`), live verified with local vLLM reasoning models. |
| 7 Later | Weighted score, OSV, licenses, Nuclei/k6/ZAP active, Appium desktop UI, live k8s (Kubescape), iOS, Rust probe binary, DefectDojo export, dashboard, multi-user (OIDC + Postgres) | **Later** | |

## Deferred from v1

- Scanning and dependency sources: OSV as a second source with dedup, license policy, buildx attestation reading.
- Web and mobile testing: Nuclei, k6, ZAP active, axe accessibility, Maestro.
- Windows: HardeningKitty, KB-to-CVE matching. Windows and macOS package CVEs.
- Platform: `targets import`, Markdown report, weighted 0 to 100 score, SQLite store and persisted queue, memory-budget scheduler, kustomize rendering, `Scope` checks on redirects and the OpenAPI URL, TLS expiry/protocol checks, intrusive checks (the mechanism exists; none are registered), `gix`-based index reading, pinned git-clone container, `insta` snapshots, JSON-schema'd check IO (`schemars`).

## Agent loop design (planned, not built)

1. **MCP server** (`readyhai mcp`): done. It is the cheapest first agentic step: an LLM client calls scan, reads findings.
2. **Loop roles:**
   - *Planner*: picks checks and writes a test plan from facts and target kind.
   - *Explorer*: drives Playwright MCP, Maestro MCP or Appium for exploratory QA of web/mobile targets.
   - *Triager*: dedupes, checks false positives against code and evidence, assigns severity.
   - *Reporter/Fixer*: writes repro steps and a suggested patch or PR.
3. **Guardrails (non-negotiable):**
   - Prompt injection is real: scanned content is attacker-controlled. The LLM may never suppress, downgrade or baseline findings, or approve intrusive actions; those stay human or policy decisions (already true of the MCP tool set).
   - Rules of engagement (`scope.toml`) enforced server-side so a scan request cannot be an SSRF pivot; HTTP transports require auth.
   - Evidence required: no finding without a reproducible artifact.
   - Secrets redacted before any LLM call (`llm::redact_for_llm`); Explorer test accounts live in Playwright `storageState` files, never in prompts.
   - Token and time budgets, an append-only audit log, replayable transcripts.
4. **LLM choice: deferred by the user.** `llm.rs` holds a provider descriptor registry (ollama, vllm, openai, anthropic, openrouter) with OpenAI-compatible and Anthropic Messages transports; cloud providers require `READYHAI_LLM_ALLOW_CLOUD=1`. The pattern comes from `learn/anthropic-proxy/config/provider_catalog.py`. A per-target `llm.allow_cloud` flag is planned.
5. **Eval harness:** a seeded-bug fixture suite every agent change must pass, scored on bugs found, false positives and cost. Exit criterion: the agent finds at least one seeded bug that the static suite missed, with evidence.
6. **Optional:** Strix, Shannon or CAI as sandboxed pentest-agent checks for authorized nonprod targets.

## Open known issues

| # | Issue | Where |
|---|---|---|
| 1 | Windows probe untested on a real host | `probe/windows.ps1`, `host.rs` |
| 2 | MobSF API shapes unverified | `android.rs` |
| 3 | Playwright runner image never built; base not digest-pinned | `runners/playwright/Dockerfile` |
| 4 | ZAP and Schemathesis never run live | `web.rs` |
| 5 | Tool images unpinned until `tools pull --lock` is run; `latest` tags not verified against registries | `tools.lock.toml` |
| 6 | Fake `ghp_`-style token in fixtures may trip GitHub push protection | `tests/fixtures` |
| 8 | Server queue is in-memory and single-worker; a restart loses queued jobs (they are now marked `error: server restarted`, not left as `running`) | `serve.rs` |
| 9 | Container image has `ssh` (fixed) but no `adb`; Android runtime checks only work from the CLI | `Dockerfile` |
| 10 | ArgoCD PostSync Job uses a placeholder image (data dir fixed: emptyDir `/data`) | `ci/argocd-postsync-job.yaml` |
| 11 | Target-supplied `readyhai.toml` is trusted for test image/command and suppressions (server/MCP now force `[test] network=false`, and the report notes how many suppressions came from the target) | `engine.rs` |
| 13 | An errored required check yields WARN, not FAIL; KEV fails on any KEV match, not only runtime deps | `policy.rs` |
| 14 | `deep` profile enables no built-in intrusive check; GitHub/GitLab recipes have placeholder release/image URLs | `checks.rs`, `ci/` |
| 15 | No TLS expiry or protocol check; no kustomize rendering | `web.rs`, `rules.rs` |
| 16 | NuHire acceptance test has no assertions | `rules.rs::nuhire_user_service` |
| 17 | The fixture contains no symlink, so symlink dropping is untested end to end | `tests/fixtures/vuln-app` |
| 18 | Web, ZAP and Playwright cannot reach a target bound only to `127.0.0.1` from inside containers (bind to `0.0.0.0`, or use the host's LAN address) | `web.rs` |
| 19 | The "Top errors" report section is covered by a unit test only; no live scan produced error lines yet | `report.rs` |
| 20 | Host scans read `known_hosts` from the real `$HOME/.ssh` (ssh uses the passwd home); there is no per-run known_hosts option | `host.rs` |

## Increment 2: senior-QA + offline (2026-10-25)

| Item | Status | Notes |
|---|---|---|
| `readyhai qa` composite run, QA data model, Go / Conditional Go / No-Go | **Done** | unit-tested; API path live-verified |
| API QA (techniques, auth matrix, BOLA, stateful CRUD, contract, leaks) | **Done, live** | 7/7 seeded bugs, 0 FP, prod-safe |
| Roles (roles.toml, env refs, storageState) | **Done** | |
| Offline bundle export/import, `doctor`, lock by image ID, EOL snapshot | **Done, live** | core bundle 3.63 GB round trip |
| Perf smoke + baseline (k6) | **Done, live** | `baseline accept` promotes perf baseline |
| UI QA (responsive, a11y, vitals, forms, journeys, visual) | **Done-unverified-live** | needs runner image |
| QA HTML/MD/Jira/GitLab/TestRail/Xray reports, dashboard | **Done** (unit) | PDF needs runner image |
| Resilience (compose pause) | **Done-unverified-live** | logic unit-tested only |
| Suite + release quality | **Done** (unit, fixtures) | |
| LAN LLM enrichment | **Done, mock-tested only** | |

### New open known issues

| # | Issue | Where |
|---|---|---|
| 21 | UI QA and PDF stay unrun until the runner image is built (`docker build -t readyhai/playwright-runner:local runners/playwright`); `playwright` is not in a bundle until then | `qa/ui.rs`, `qa/report.rs` |
| 22 | Resilience has never run against a live compose stack | `qa/resilience.rs` |
| 23 | MobSF and the Windows probe are still unrun | `android.rs`, `host.rs` |
| 24 | ~~LLM is only mock-tested~~ fixed: live-verified with local vLLM reasoning model (`qwen3.8-flash-next`) | `agent.rs`, `llm.rs` |
| 25 | ~~API executor does not execute AI-proposed cases~~ fixed: autonomous multi-agent loop in `src/agent.rs` executes planned cases | `agent.rs` |
| 26 | `baseline accept` promotes perf only; spec and visual baselines are not wired (visual: first run auto-stores, later change needs a manual PNG replace; spec baseline for breaking-change detection has no accept step) | `main.rs`, `qa/ui.rs`, `qa/api` |
| 27 | Flaky re-run helper exists but no executor uses it; the "No flaky tests" criterion is vacuous | `qa/resilience.rs::flaky_rerun` |
| 28 | ~~`READYHAI_OFFLINE=1` also disables the LAN LLM~~ fixed: mode `offline+lan-llm` | `engine.rs` |
| 29 | Fake tokens in `tests/fixtures/qa-api` (`alice-token`...) may trip secret scanners | fixtures |
| 30 | Bundle manifest unsigned; `full` set (~8-9 GB) not exported end to end; no Ollama image or GGUF serving in the bundle | `bundle.rs` |
| 31 | Prisma and Flyway migrations detected but not executed; migration check needs a `[test]` image | `qa/suite.rs` |


## Increment 3: Agentic AI QA, Evidence Ledger & Web Studio (2026-10-27)

| Item | Status | Notes |
|---|---|---|
| Autonomous Multi-Agent Loop (`src/agent.rs`) | **Done, live** | Planner -> Explorer -> Triager -> Readiness Gate; live verified against local vLLM |
| 4-Pillar Evidence Ledger | **Done, live** | Value, Authority, Safety, Evidence scoring and automated GO/NO_GO verdict |
| Cyber-Dark Web Studio UI (`src/web_ui.rs`) | **Done, live** | Embedded SPA served by `readyhai serve` with live pipeline telemetry & scenario inspector |
| Agent REST API endpoints | **Done, live** | `/api/agent/status`, `/api/agent/run`, `/api/agent/runs`, `/api/agent/runs/{id}` |
| Local vLLM Reasoning Model Integration | **Done, live** | Sub-10ms probe latency, reasoning token parser, 2048-token generation limits |
| CLI `readyhai agent <target>` command | **Done, live** | Terminal runner; returns exit 0 for GO, 1 for CONDITIONAL_GO / NO_GO |

## Increment 3.1: Next.js 15 Agent Studio, Persistent Global History & Multi-Container Docker (2026-10-27)

| Item | Status | Notes |
|---|---|---|
| Next.js 15 Cyber-Dark Studio (`frontend/`) | **Done, live** | Full-fidelity React 19 UI with Swarm Composer, active stages, deep cURL inspector, and live retest |
| Legacy UI Removal & Port 8080 Redirect | **Done, live** | Removed old in-binary HTML SPA from 8080; replaced with JSON status and 302 browser redirect to 3000 |
| Persistent Global History Engine | **Done, live** | Persists all scans (`/api/agent/discover`) and test runs (`/api/agent/run`) with `SCAN`/`TEST RUN` badges |
| Disk-backed In-Place Retest & Run Deletion | **Done, live** | `POST /api/agent/retest` updates disk report in-place; `DELETE /api/agent/runs/{id}` deletes runs |
| Strict Target Exclusion (`agent-prod.nuhire.in`) | **Done, live** | Purged historical data, enforced server & client filtering, permanently excluded |
| Multi-Container Docker Deployment | **Done, live** | `frontend/Dockerfile` standalone Next.js container (port 3005) + `readyhai:local` compose orchestration |
