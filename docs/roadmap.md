# Roadmap

Status key: **Done** (implemented, covered by tests or verification), **Done, live** (also run against real containers or servers), **Done-unverified-live** (implemented and fixture-tested, never run for real), **Next**, **Later**. Release notes are in [../CHANGELOG.md](../CHANGELOG.md).

## Phases

| Phase | Scope | Status | Notes |
|---|---|---|---|
| 0 Skeleton | Crate, models, sandbox executor with create-policy and reaper, snapshot + denylist, `scan`, JSON + HTML report, `serve` + compose | **Done** | Plan said SQLite; the build uses files only. Exit criterion (fixture scan, secrets guard) passed in verification round 1. |
| 1 Repo + Image | Syft/Grype, Semgrep, Gitleaks, Checkov, Hadolint, Dockle, readiness rules, own-tests, fingerprints + baseline, gate, SARIF/JUnit, Jenkins stage | **Done** | Verification round 1: all 10 steps passed. Kustomize rendering not done. NuHire check is a printing test, not an asserting one. |
| 2 Web/API | Smoke, Schemathesis, Playwright runner, ZAP baseline, scope enforcement, log clustering, GitHub/GitLab templates | **Done, live** | ZAP (2 findings) and Schemathesis (6) ran against the fixture API and the Playwright runner was built on 2026-10-30. TLS expiry/protocol checks missing. |
| 3 Hosts | SSH executor + host-key verify, Linux probe + Lynis + package CVEs, macOS/Windows probe + core rules | **Done-unverified-live** | Linux verified live (round 2). OpenSSH client instead of russh. Windows probe untested on a real host. The container image ships `ssh`. |
| 4 Android | MobSF per-scan container, BYO-device ADB runtime | **Done, live** (MobSF) | MobSF verified on InsecureBankv2 on 2026-10-30 (11 normalized findings, secrets count-only). The adb runtime check needs `adb` on the machine (not in the image). |
| 5 CI + PostSync | ArgoCD PostSync Job, API polish, deferred items as needed | **Done-unverified-live** | Recipes written; the PostSync manifest has not run on a cluster. |
| 6 Agentic | Autonomous agent loop + Evidence Ledger + Studio | **Done, live** | 4-agent pipeline (`src/agent/`), four-pillar Evidence Ledger, live-verified with a local vLLM reasoning model. The in-binary SPA (`src/web_ui.rs`) was removed in favour of the Next.js Studio. |
| 7 Super agent | Shared QA checks, verifier, code-aware planning, lead and area sub-agents, per-target memory, eval harness | **Done** | Landed in 0.2.0 and 0.3.0 (2026-11-05). Detection is gated by the eval suites (7/7 seeded bugs). Not yet run against a real, non-fixture application. |
| 8 Studio revamp | Design system, command center, release gate in the workspace, six-stage stepper, cancel, sandboxed reports, token settings | **Done** | 0.4.0. UI behaviour is covered by vitest; no browser end-to-end test runs in CI. |
| 9 Later | See "Next" and "Later" below | **Next** / **Later** | |

## Next

Ordered by value, each one built on a mechanism that already exists:

1. **Browser-UI agent area (Playwright).** A fifth area in the lead that drives the existing Playwright runner (`runners/playwright`, the engine behind `qa.ui`): follow the crawled journeys with a role's `storageState`, fill and submit forms with boundary inputs, check console errors and broken navigation. Findings go through the same oracle, the same verifier replay (a UI failure must reproduce k times) and the same cleanup ledger; the area gets its own budget slice. Exit criterion: an eval suite with a UI fixture (`tests/fixtures/qa-ui`) where the agent finds the seeded UI bugs, with no false positives.
2. **LLM-guided exploration under the verifier.** Let the model propose the next probes from what it has observed (new parameters, state sequences, unusual headers). Every proposal is validated against the discovered routes and spec before it is planned, runs through the deterministic oracle, is replayed by the verifier, and stays `exploratory` (not scored) unless a deterministic check fails it, as today's LLM extras already are. The budget caps calls and requests. Exit criterion: an eval suite with a bug that only a guided sequence reaches, and a measured false-positive rate of 0 on the existing suites with guidance on.
3. **Multi-target dashboards.** Trends and comparisons across targets and services (for a fleet such as NuHire's 13 services): the static dashboard (`readyhai dashboard`, `<data>/index.jsonl`) and the agent memory aggregates feed a Studio view and a REST listing per target, showing verdict history, open and regressed defects, flaky case classes and coverage per operation. Exit criterion: one page that answers "which service got worse since last week".

## Later

- GitHub App / PR status check (today `POST /api/github/pr-comment` only renders markdown; upload SARIF with the `upload-sarif` action).
- Remote probe nodes for multi-region probing (`/api/network/multi-region` measures one vantage point and says so).
- A Reporter/Fixer agent that validates a suggested patch against the source before proposing it (today's remediation is generic, labelled example guidance).
- Persisted job queue and multi-user auth (OIDC); SQLite or Postgres store instead of files.
- Weighted 0 to 100 score, OSV as a second CVE source with dedup, buildx attestation reading, Nuclei, Maestro, HardeningKitty, KB-to-CVE matching for Windows, kustomize rendering, TLS expiry and protocol checks, DefectDojo export, Appium desktop UI, live k8s (Kubescape), iOS.
- More eval suites: a UI suite, a multi-file change suite, more seeded bug classes (mass assignment, path traversal, CORS), and a baseline run against a real open-source API.
- Optional sandboxed pentest agents (Strix, Shannon, CAI) as checks for authorized nonprod targets.

## Deferred from v1 (still open)

- Scanning and dependency sources: OSV as a second source with dedup, buildx attestation reading.
- Web and mobile testing: Nuclei, ZAP active scan, Maestro.
- Windows: HardeningKitty, KB-to-CVE matching. Windows and macOS package CVEs.
- Platform: `targets import`, weighted score, SQLite store and persisted queue, memory-budget scheduler, kustomize rendering, TLS expiry/protocol checks, `gix`-based index reading, pinned git-clone container, `insta` snapshots, JSON-schema'd check IO (`schemars`). (Done since v1: Markdown report in `qa`, k6, axe-core, licence policy, scope checks on redirects and the OpenAPI URL, the first intrusive check.)

## Agent design: what exists and what does not

1. **MCP server** (`readyhai mcp`): done. Scan tools plus the async agent tools (`readyhai_agent_swarm` returns a run id, `readyhai_agent_status`, `readyhai_agent_cancel`, `readyhai_agent_discover`).
2. **Loop roles:**
   - *Planner*: done, deterministic, grounded in the crawl and the spec; the LLM may only add validated cases.
   - *Explorer*: done as the lead agent with `auth`, `contract`, `state` and `ui` (crawl-grounded HTTP) areas. Driving a browser is the first "Next" item.
   - *Verifier*: done (`verify.rs`).
   - *Triager*: done (`triage.rs`).
   - *Reporter*: done for reports and example guidance; a *Fixer* that proposes validated patches is "Later".
3. **Guardrails (non-negotiable, all in place):**
   - Prompt injection is real: scanned content is attacker-controlled. The LLM may never suppress, downgrade or baseline findings, or approve intrusive actions; those stay human or policy decisions. The only waiver is an operator's expiring `agent-memory accept`.
   - Rules of engagement (`scope.toml`) enforced server-side by one egress guard; HTTP transports require auth.
   - Evidence required: no defect without a stored request/response, and a failure must reproduce under the verifier.
   - Secrets redacted before any LLM call (`llm::redact_for_llm`, `llm::untrusted`); test credentials only from `RH_<ROLE>_TOKEN`, bound to the target host.
   - Token, time and request budgets, cooperative cancellation, replayable evidence, an eval gate in CI.
4. **LLM choice:** `llm.rs` holds a provider catalog (ollama, vllm, openai, anthropic, openrouter) with OpenAI-compatible and Anthropic Messages transports; cloud providers require `READYHAI_LLM_ALLOW_CLOUD=1`. The agent works without any LLM.
5. **Eval harness:** done (`readyhai eval`, [eval.md](eval.md)). The original exit criterion (the agent finds a seeded bug that the static suite missed, with evidence) is met: the agent finds all 7 seeded bugs of the `qa-api` fixture, and `agent-diff` finds the one bug on the route a PR changed.

## Open known issues

| # | Issue | Where |
|---|---|---|
| 1 | Windows probe untested on a real host | `probe/windows.ps1`, `host.rs` |
| 6 | Fake `ghp_`-style token in fixtures may trip GitHub push protection | `tests/fixtures` |
| 8 | Server queue is in-memory and single-worker; a restart loses queued jobs (they are marked `error: server restarted`, not left as `running`) | `serve.rs` |
| 9 | The container image has `ssh` but no `adb`; Android runtime checks only work from the CLI | `Dockerfile` |
| 10 | ArgoCD PostSync Job: pin the image tag or digest instead of `latest`; not run on a cluster | `ci/argocd-postsync-job.yaml` |
| 11 | Target-supplied `readyhai.toml` is trusted for test image/command and suppressions (server/MCP force `[test] network=false`, and the report notes how many suppressions came from the target) | `engine.rs` |
| 13 | KEV fails on any KEV match, not only runtime dependencies | `policy.rs` |
| 15 | No TLS expiry or protocol check; no kustomize rendering | `web.rs`, `rules.rs` |
| 16 | NuHire acceptance test has no assertions | `rules.rs::nuhire_user_service` |
| 17 | The fixture contains no symlink, so symlink dropping is untested end to end | `tests/fixtures/vuln-app` |
| 18 | Web, ZAP and Playwright cannot reach a target bound only to `127.0.0.1` from inside containers (bind to `0.0.0.0`, or use the host's LAN address) | `web.rs` |
| 19 | The "Top errors" report section is covered by a unit test only | `report.rs` |
| 20 | Host scans read `known_hosts` from the real `$HOME/.ssh`; there is no per-run known_hosts option | `host.rs` |
| 22 | Resilience ran only against the compose fixture, never a real application stack | `qa/resilience.rs` |
| 27 | Flaky re-runs cover read-only API cases only (writes and the stateful lifecycle are never repeated) | `qa/api` |
| 30 | Bundle manifest unsigned; `full` set (~8-9 GB) not exported end to end; no Ollama image or GGUF serving in the bundle | `bundle.rs` |
| 31 | Prisma and Flyway migrations detected but not executed; the migration check needs a `[test]` image | `qa/suite.rs` |
| 32 | The REST `POST /api/agent/run` is synchronous (the HTTP call returns when the run ends; the id of a run in progress comes from `GET /api/agent/runs`); only MCP returns the id at once | `serve.rs` |
| 33 | `agent --diff-base` needs a spec; without one the change impact is `skipped` | `agent/change.rs` |
| 34 | The agent covers HTTP APIs and crawled pages, not browser behaviour | "Next" item 1 |
| 35 | Version files still read 0.1.0 while the changelog describes 0.2.0 to 0.4.0 | `VERSION`, `Cargo.toml`, `scripts/version.sh set` |

Fixed since the last roadmap: tool images unpinned (16 of 17 digests pinned), Playwright runner never built, ZAP and Schemathesis never run live, MobSF API shapes unverified, the errored-check-is-only-WARN deviation (`errored_fails`), `baseline accept` promoting perf only (spec, visual and perf are all promoted), LLM only mock-tested (live-verified with local vLLM), the API executor not executing AI-proposed cases (the agent does), `READYHAI_OFFLINE` disabling the LAN LLM (mode `offline+lan-llm`), the agent's own HTTP client following redirects (it never does), the hard-coded agent-prod host exclusion (removed: scope.toml is the only host policy), the GitLab and GitHub recipe placeholders.

## History of increments

| Increment | Date | Scope |
|---|---|---|
| 1 | 2026-10-25 | Scan engine, sandbox, readiness rules, tools, gate, REST, MCP, CI recipes |
| 2 | 2026-10-25 | `readyhai qa`, offline bundle, perf, resilience, suite quality, LAN LLM, reports, dashboard |
| 3 | 2026-10-27 | Agentic AI engine, Evidence Ledger, first Web Studio |
| 3.1 | 2026-10-27 | Next.js 16 Agent Studio, persistent history, retest and delete, multi-container Docker |
| 3.2 | 2026-10-28 to 2026-11-04 | Network Lab, extended thinking and tiers, crawl-grounded planning, reports, mutation, stateful chains, TOCTOU bursts, MCP swarm, UI design pass |
| hardening | 2026-10-29 to 2026-11-03 | Bearer auth on all routes, scope relaxation to public hosts, evidence-based verdicts, live verification of UI/DAST/resilience/MobSF, supply-chain checks, signed images |
| 0.2.0 | 2026-11-05 | Review fixes, verifier, cleanup confirmation, eval harness, CI gates |
| 0.3.0 | 2026-11-05 | Shared QA checks, code-aware planning, lead and sub-agents, memory |
| 0.4.0 | 2026-11-05 | UI revamp, docs refresh |
