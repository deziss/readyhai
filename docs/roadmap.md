# Roadmap

Status key: **Done** (implemented, covered by tests or verification), **Done, live** (also run against real containers or servers), **Done-unverified-live** (implemented and fixture-tested, never run for real), **Next**, **Later**. Release notes are in [../CHANGELOG.md](../CHANGELOG.md).

## Phases

| Phase | Scope | Status | Notes |
|---|---|---|---|
| 0 Skeleton | Crate, models, sandbox executor with create-policy and reaper, snapshot + denylist, `scan`, JSON + HTML report, `serve` + compose | **Done** | Plan said SQLite; the build uses files only. Exit criterion (fixture scan, secrets guard) passed in verification round 1. |
| 1 Repo + Image | Syft/Grype, Semgrep, Gitleaks, Checkov, Hadolint, Dockle, readiness rules, own-tests, fingerprints + baseline, gate, SARIF/JUnit, Jenkins stage | **Done** | Verification round 1: all 10 steps passed. Kustomize rendering not done. NuHire check is a printing test, not an asserting one. |
| 2 Web/API | Smoke (weak CSP, TLS expiry/protocol/chain), Schemathesis, Playwright runner, Nuclei, ZAP baseline & active (`nonprod` + `deep`), scope enforcement, log clustering, GitHub/GitLab templates | **Done, live** | ZAP (2 findings) and Schemathesis (6) ran against the fixture API and Playwright runner was built on 2026-10-30; weak CSP, TLS, Nuclei, and active ZAP added in `0.7.0`. |
| 3 Hosts | SSH executor + host-key verify, Linux probe + Lynis + package CVEs, macOS/Windows probe + core rules | **Done-unverified-live** | Linux verified live (round 2). OpenSSH client instead of russh. Windows probe untested on a real host. The container image ships `ssh`. |
| 4 Android | MobSF per-scan container, BYO-device ADB runtime | **Done, live** (MobSF) | MobSF verified on InsecureBankv2 on 2026-10-30 (11 normalized findings, secrets count-only). The adb runtime check needs `adb` on the machine (not in the image). |
| 5 CI + PostSync | ArgoCD PostSync Job, API polish, deferred items as needed | **Done-unverified-live** | Recipes written; the PostSync manifest has not run on a cluster. |
| 6 Agentic | Autonomous agent loop + Evidence Ledger + Studio | **Done, live** | 4-agent pipeline (`src/agent/`), four-pillar Evidence Ledger, live-verified with a local vLLM reasoning model. The in-binary SPA (`src/web_ui.rs`) was removed in favour of the Next.js Studio. |
| 7 Super agent | Shared QA checks, verifier, code-aware planning, lead and area sub-agents, per-target memory, eval harness | **Done** | Landed in 0.2.0 and 0.3.0 (2026-11-05). Detection is gated by the eval suites (7/7 seeded bugs). Not yet run against a real, non-fixture application. |
| 8 Studio revamp | Design system, command center, release gate in the workspace, six-stage stepper, cancel, sandboxed reports, token settings | **Done** | `0.4.0`–`0.6.2`. UI behaviour is covered by vitest (127 cases); no browser end-to-end test runs in CI. |
| 9 Deep security | Native Tree-sitter cross-file taint/auth audit (`security.code_audit`), Opengrep, Nuclei, active ZAP, TLS/CSP checks, modular `attacks/*`, in-process OAST, Playwright `BrowserSecurity`, white-box `--repo` AST bridge, ReAct follow-up waves, `security-deep` + `whitebox-exploit` evals | **Done** | Landed in `0.7.0`. Gated across 10 deterministic CI eval suites with 0 false positives. |
| 10 Modern Toolchain & Dep Upgrade | Node 24 LTS, TypeScript 7, React 19, Next.js 16.4, MiniJinja 3, Sha2 0.11, Rand 0.10, Reqwest 0.13, Playwright 1.65.1 | **Done, live** | Landed in `0.9.0`. Full suite passed: 813 Rust tests, 141 Vitest tests, Docker stack running healthy. |
| 11 World-Class Evaluator & QA Engine | 7-pillar master plan (Multi-protocol APIs, Autonomous State-Graph Journeys, GenAI Evaluator, OTel trace correlation, Agentic Fixer, Mutation testing, Enterprise mesh) | **In Progress** | Master blueprint: [docs/plans/2026-11-14-world-class-evaluator-and-qa-master-plan.md](plans/2026-11-14-world-class-evaluator-and-qa-master-plan.md) |

## Evolutionary Horizons (World-Class Evaluator & QA Engine)

See [plans/2026-11-14-world-class-evaluator-and-qa-master-plan.md](plans/2026-11-14-world-class-evaluator-and-qa-master-plan.md) for full architectural specifications.

1. **Horizon 1 (v1.0.0) — Protocol Breadth & Enterprise Queue**: **Done**
   - OpenAPI 3.1 & JSON Schema Draft 2020-12 full support (`prefixItems`, polymorphic schemas).
   - GraphQL schema introspection, circular DoS, and authorization fuzzer (`qa.graphql.*`).
   - Self-healing resilient locator tree in Playwright runner (`qa.mjs`).
   - Persistent task queue recovery (`opts.json`) with multi-worker concurrent execution (`READYHAI_WORKERS`) in `src/serve.rs`.
2. **Horizon 2 (v1.2.0) — Autonomous Exploration & Deep Observability**: **Done**
   - Dynamic Markov state-graph explorer for single-page web applications and dead-end detection (`qa.ui.dead_end`).
   - Multi-persona collaborative browser journeys with concurrent sessions (`sync_personas: [...]`).
   - W3C distributed trace context injection (`traceparent`, `tracestate`, `baggage`) & OTel APM correlation (`READYHAI_APM_URL`).
   - Structural visual regression with resilient fallback locator trees.
3. **Horizon 3 (v1.5.0) — Universal GenAI & Agent Evaluator (`readyhai eval-ai`)**: **Done**
   - CLI command `readyhai eval-ai` & REST endpoint `POST /api/eval-ai`.
   - Dedicated GenAI evaluation engine: RAG Quality Triad (Context Relevance, Faithfulness / Hallucination detection, Answer Relevance).
   - Agent trajectory & tool-calling validation: schema conformance, cyclic loop detection, efficiency scoring.
   - Adversarial AI red-teaming: indirect prompt injection detection, token leakage scanning, and canary exfiltration auditing.
4. **Horizon 4 (v2.0.0) — The Agentic Fixer (`readyhai fix`)**: **Done**
   - AST-grounded code remediation across Rust, TypeScript/JavaScript, Python, and Go for missing auth guards, SQL injection, path traversal, command execution, CORS wildcards, and hardcoded secrets.
   - Sibling guard mining: examines repository endpoints to automatically discover and reuse standard authentication middleware identifiers.
   - Deterministic test-before-PR verification sandbox (`cargo test`, `npm test`, `pytest`, `go test`) with automatic safe rollback on regression.
   - Automated GitHub/GitLab Pull Request authoring with before/after unified diffs, Evidence Ledger reproduction curl commands, and local git branch committing (strictly obeying local-only Push Policy).
   - REST endpoint `POST /api/fix` for Web UI & Agent Studio integration.
5. **Horizon 5 (v2.5.0) — Mutation Testing & Global Fleet Mesh (`readyhai mutate`)**: **Next**
   - Source code mutation engine with mutation score calculation.
   - Autonomous negative test generator killing survived mutants.
   - Multi-region distributed probe nodes for global edge latency and geo-fence testing.
   - Multi-target enterprise fleet dashboard and cross-service drift intelligence.

## Next

Ordered by value, each one built on mechanisms already in place:

1. **Multi-target dashboards.** Trends and comparisons across targets and services (for a fleet such as NuHire's 13 services): the static dashboard (`readyhai dashboard`, `<data>/index.jsonl`) and the agent memory aggregates feed a Studio view and a REST listing per target, showing verdict history, open and regressed defects, flaky case classes and coverage per operation. Exit criterion: one page that answers "which service got worse since last week".
2. **Verified PR patch synthesis (Fixer).** Validate proposed patches against the repo AST and unit tests before opening a fix PR or diff (today remediation is generic, labelled example guidance).
3. **Full-stack multi-hop runtime/service correlation.** Extend AST taint/auth linking across microservice boundaries and live distributed traces.

*(Completed from prior "Next": Playwright browser-UI security agent area (`BrowserSecurity` / `agent_browser.mjs`) and bounded adaptive ReAct follow-up exploration under the verifier (`react.rs`) landed in `0.7.0`.)*

## Later

- GitHub App / PR status check (today `POST /api/github/pr-comment` only renders markdown; upload SARIF with the `upload-sarif` action).
- Remote probe nodes for multi-region probing (`/api/network/multi-region` measures one vantage point and says so).
- A Reporter/Fixer agent that validates a suggested patch against the source before proposing it (today's remediation is generic, labelled example guidance).
- Persisted job queue and multi-user auth (OIDC); SQLite or Postgres store instead of files.
- Weighted 0 to 100 score, OSV as a second CVE source with dedup, buildx attestation reading, Nuclei, Maestro, HardeningKitty, KB-to-CVE matching for Windows, kustomize rendering, TLS expiry and protocol checks, DefectDojo export, Appium desktop UI, live k8s (Kubescape), iOS.
- More eval suites: a UI suite, a multi-file change suite, more seeded bug classes (mass assignment, path traversal, CORS), and a baseline run against a real open-source API.
- Optional sandboxed pentest agents (Strix, Shannon, CAI) as checks for authorized nonprod targets.

## Deferred from v1 (still open)

- Scanning and dependency sources: buildx attestation reading; full semantic taint rulesets across compiled languages beyond Python/JS/TS/Go/PHP.
- Mobile testing: Maestro, iOS.
- Windows: HardeningKitty, KB-to-CVE matching. Windows and macOS package CVEs.
- Platform: `targets import`, weighted score, SQLite store and persisted queue, memory-budget scheduler, kustomize rendering, `gix`-based index reading, pinned git-clone container, `insta` snapshots, JSON-schema'd check IO (`schemars`). *(Done since v1: Markdown report in `qa`, k6, axe-core, licence policy, scope checks on redirects and the OpenAPI URL, `qa.resilience`, Nuclei, `tool.zap_active`, TLS weak-protocol/expiry/chain checks, weak CSP checks, `security.code_audit`, `tool.opengrep`, OSV AST import check.)*

## Agent design: what exists and what does not

1. **MCP server** (`readyhai mcp`): done. Scan tools plus the async agent tools (`readyhai_agent_swarm` returns a run id, `readyhai_agent_status`, `readyhai_agent_cancel`, `readyhai_agent_discover`).
2. **Loop roles:**
   - *Planner*: done, deterministic, grounded in the crawl, the spec, modular deep-security generators (`attacks/*`), and white-box AST handlers (`--repo`); the LLM may only add validated cases.
   - *Explorer*: done as the lead agent with `auth`, `contract`, `state` and `ui` areas, in-process OAST collector (`oast.rs`), bounded adaptive ReAct follow-up waves (`react.rs`), and interactive Playwright DOM security (`browser_sec.rs`).
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
| 9 | The container image has `ssh` but no `adb`; Android runtime checks only work from the CLI | `Dockerfile` |
| 10 | ArgoCD PostSync Job: pin the image tag or digest instead of `latest`; not run on a cluster | `ci/argocd-postsync-job.yaml` |
| 11 | Target-supplied `readyhai.toml` is trusted for test image/command and suppressions (server/MCP force `[test] network=false`, and the report notes how many suppressions came from the target) | `engine.rs` |
| 13 | KEV fails on any KEV match, not only runtime dependencies | `policy.rs` |
| 15 | No kustomize rendering *(TLS expiry/protocol checks fixed in `0.7.0`)* | `rules.rs` |
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
| 33 | `agent --diff-base` needs a spec for diff-based operation mapping (though `--repo` white-box AST discovery in `0.7.0` still finds hidden routes and sinks) | `agent/change.rs`, `agent/whitebox.rs` |

Fixed since earlier roadmaps: Server queue persistent task recovery & multi-worker concurrency (`1.0.0`), TLS expiry/protocol checks (`0.7.0`), Playwright `BrowserSecurity` and adaptive ReAct exploration (`0.7.0`), `Nuclei` and `tool.zap_active` (`0.7.0`), OSV AST import reachability (`0.7.0`), native cross-file AST taint/auth audit (`0.7.0`), single-source versioning (`0.2.0` -> `0.7.0`, `18` of `19` container digests pinned in `tools.lock.toml`).

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
| 0.5.0 | 2026-11-05 | Multi-provider LLM, enterprise OpenAPI scaling, RBAC bootstrap, PR bot |
| 0.6.0–0.6.2 | 2026-11-06–2026-11-07 | SPA/XHR discovery, ledger confidence & blockers, proxy timeout & model tier fixes |
| 0.7.0 | 2026-11-12 | Deep security scanning (Tree-sitter AST audit, Opengrep/Nuclei/active ZAP, TLS/CSP checks, modular attacks, OAST, `BrowserSecurity`, white-box bridge, ReAct, 10 eval suites) |
| 0.8.0 | 2026-11-12 | Enterprise reliability & evidence calibration (fast DNS preflight reachability guard, differential injection oracle, boundary query tolerance, plan priority ordering, scaled probe queue, dual-stack binding) |
| 0.8.1 | 2026-11-14 | Tri-state exit criteria & directives scaling (warning status for unevaluated/advisory conditions, pillar warning indicators, 32KB configurable custom instructions, 8000-char planner context, live byte counter) |
| 0.9.0 | 2026-11-14 | Full-stack library & toolchain modernization (Rust MiniJinja 3, Sha2 0.11, Rand 0.10, Reqwest 0.13; Frontend Node 24, TypeScript 7, Next.js 16.4.6, React 19.3.1, Tailwind 4.3.5, Vitest 5.1; Playwright 1.65.1 & LangChain 0.3.19 runners) |
