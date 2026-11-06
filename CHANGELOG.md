# Changelog

All notable changes to ReadyHai are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.6.0] - 2026-11-06

Agent reliability and accuracy: verdicts reflect the app, not the agent's blind spots. On the NuHire SPA, inconclusive results dropped from 15 of 18 to 1 of 8, and a false NO_GO became NOT_EVALUATED with the exact next step.

### Added

- **SPA discovery.** Soft-404 calibration (three random paths; status, length and normalised-text fingerprint) flags catch-all routes. Next.js routes are taken from `_buildManifest.js`, app-router chunk paths and the RSC payload. API paths are extracted from up to 30 same-origin JS chunks. `robots.txt` and `sitemap.xml` are read. More OpenAPI locations are tried (`/api-docs`, `/openapi.yaml`, `/swagger/v1/swagger.json`, `/api/v1/openapi.json`, `/.well-known/openapi`, `/docs` spec links). API hosts outside scope are reported ("add to scope.toml"), never called.
- **Headless XHR discovery** (standard/deep, SPA, Docker): the Playwright runner's new `discover` mode navigates without clicking or submitting and records the API calls the app makes (templated paths, key names only, no values or auth headers). `READYHAI_AGENT_XHR=off` disables it. Rebuild the runner image (`docker build -t readyhai/playwright-runner:local runners/playwright`).
- **Auth-wall detection.** A 401, a redirect to a login/SSO page or a password form marks the route `auth_wall`. Cases there without a credential are BLOCKED (auth wall) with the next step (`readyhai roles init`, `RH_<ROLE>_TOKEN`, storageState), not INCONCLUSIVE.
- **Blockers and confidence.** The evidence ledger has `confidence` (conclusive share of applicable cases, overall and per pillar) and `blockers[]` (auth wall, no input surface, transport, out of scope) with a next step each; a new exit criterion requires 80% conclusive coverage.
- **LLM reliability.** Per-call timeout scales with the request (`clamp(20 + max_tokens/40, 30, 300)` s, `READYHAI_LLM_TIMEOUT_SECS` overrides). A timed-out call is retried smaller (half `max_tokens`, no reasoning effort) instead of identically; a 5xx is retried once, then the next fallback model. A 1-token probe measures latency at run start; a slow endpoint caps planner thinking at the High tier. Gate and triage calls never use thinking.
- **Eval.** New metrics: precision, inconclusive rate, confidence, blockers; new gates `max_inconclusive_rate`, `forbid_verdict`, `expect_blocker`. New Next.js-like fixture `tests/fixtures/spa-next` with suites `agent-spa` (seeded IDOR, SQL error leak, boundary 500), `agent-spa-clean` (must not be NO_GO) and `agent-spa-noauth` (must be NOT_EVALUATED with an auth-wall blocker).
- **UI.** Pillar cards show the backend pillar name, claim and a confidence chip; a "What to provide next" card lists blockers; NOT_EVALUATED shows as a neutral "Not evaluated" (never red); scenarios show NOT_APPLICABLE and BLOCKED reasons and the redirect chain.

### Changed

- **Redirects.** Discovery records the first-hop status, redirect chain and final URL. The executor follows same-origin redirects (up to 5) for liveness, content and robustness cases and judges the final response; authz and sensitive-file probes keep the raw status. Verifier replays follow redirects too.
- **Planner.** Injection, boundary and negative cases target only routes with an input surface (query, form, JSON/API, spec). SPA shells, catch-all routes, login forms and routes that refuse GET (405) get NOT_APPLICABLE rows instead of doomed cases; with credentials, API routes are preferred over the HTML entry page.
- **Wave-2 re-probes** run only for transient causes (transport error, timeout, 5xx, 429, 408), not for redirects, missing evidence or CORS 405.
- **Scoring.** Pillar score is `(pass + 0.5·warn) / conclusive`; a pillar is scored only at 50% confidence or more. NOT_EVALUATED when overall confidence is below 50%, or when an auth wall hides the app and only hygiene checks concluded. NO_GO stays for proven failures. The pass-rate criterion counts conclusive applicable cases only.

### Fixed

- Pillar claims and exit-criteria details started with ": 2 passed" (missing technique label).
- UI pillar cards always said "No evidence text was reported" and used wrong labels ("API Contract" for functional correctness).
- "a injection" wording.

## [0.5.0] - 2026-11-05

LLM provider freedom, enterprise-scale specs, RBAC bootstrap and a PR bot.

### Added

- **Pull-request bot.** `--format pr` writes `readyhai-pr-comment.md` (verdict, reasons, category counts, top 15 open findings, escaped). The repo root is now a composite GitHub Action (`uses: deziss/readyhai@v0.5.0`) that installs the checksummed release binary, scans, keeps one PR comment up to date and gates (`fail-on: fail|warn|never`, `no-tools`). `ci/gitlab-ci.yml` posts/updates one MR note with `READYHAI_GITLAB_TOKEN`. The image now ships `jq`.
- **Enterprise-size specs.** The operation cap is `READYHAI_MAX_OPS` (default 2000, ceiling 10000, was a fixed 500). Operations past it show as untested in coverage with a roll-up note. `$ref` expansion and spec size are bounded, and the quadratic hot spots in planning, coverage, evidence and role matching are gone (1500 operations parse, plan and generate in about 1 s in a debug build).
- **`readyhai roles init --spec <openapi>`** derives a `roles.toml` skeleton from `securitySchemes`, per-operation `security`, OAuth2 scopes and `x-roles`. It uses `RH_<ROLE>_TOKEN` placeholders and never values, writes mode 0600 into the secrets directory, and will not overwrite without `--force`.
- **Generic LLM endpoint and key.** `READYHAI_LLM_URL` sets the base URL for any provider (OpenAI-compatible or Anthropic transport) and `READYHAI_LLM_API_KEY` the key for any provider (bearer or `x-api-key`; wins over `OPENAI_API_KEY` and friends; never logged). The provider ids `openai-compatible` and `custom` select the generic `vllm` provider.
- **Fallback models.** `READYHAI_LLM_MODEL` (or `READYHAI_LLM_MODELS`) takes a comma-separated list; a failed call moves on to the next model in order. `GET /api/agent/status` lists `configured_models` and `api_key_configured`.
- **Off-box guard for URLs.** A local provider pointed at a public host (not loopback, private, `.local`/`.lan`/`.internal`, single-label) now needs `READYHAI_LLM_ALLOW_CLOUD=1`, with an error that says so. A refused LLM config is noted in the QA report instead of silently running deterministic.

### Changed

- UI: **Run regressive test** moved from the header into the Environment and target panel; the sticky Adversarial scenarios toolbar is now opaque and stacks above the rows, so scenarios no longer show through it.

- Inside the Docker image (`READYHAI_IN_CONTAINER=1`) a `localhost` / loopback `READYHAI_LLM_URL` is rewritten to `host.docker.internal`, so the same `.env` works on the host and in compose.

### Deprecated

- `READYHAI_VLLM_URL`: still read when `READYHAI_LLM_URL` is unset. Empty values of every `READYHAI_LLM_*` variable now count as unset.

## [0.4.0] - 2026-11-05

Documentation refresh.

### Added

- `CHANGELOG.md` (this file).

### Fixed

- Docs that contradicted the code were corrected: the scope policy (public hosts get full testing by default, internal hosts must be listed or matched by `*`, `prod` entries are read-only), exit codes of `qa` and `agent` (0/1/2), the agent's pillar weights (30/30/25/15, not 25 each), the `errored_fails` policy key (a required check that errors fails the gate), the removal of `src/web_ui.rs` and of the hard-coded host exclusion, the live-verification status of UI, PDF, ZAP, Schemathesis, resilience and MobSF (verified 2026-10-30), 41 built-in checks, digests pinned for 16 of 17 tools, the Docker image shipping `ssh`, and the `qa.resilience` check being the one intrusive check.

## [0.3.0] - 2026-11-05

UI revamp.

### Added

- **Design system.** IBM Plex Sans for the UI and IBM Plex Mono for real code (URLs, curl commands, ids), loaded with `next/font`. Colour, radius, type-scale and shadow tokens (`rh-bg`, `rh-surface`, `rh-raised`, `rh-line`, `rh-text`, `rh-muted`, `rh-primary`, `rh-go`, `rh-cond`, `rh-nogo`, `rh-info`) defined once in `frontend/src/app/globals.css`; panels use a 1px border, the only shadow is for popovers and dialogs. Reduced-motion and focus-ring rules are global.
- **Command center layout.** The mode switch and header are pinned at the top, the **Run agent** button is pinned at the bottom, and only the controls in between scroll, so the run controls can never be pushed out of reach. Result tabs (Scenarios and inspector, Discovered routes, Evidence ledger, Threat triage, Runs history) stay pinned above their scrolling panels.
- **Release gate in the workspace.** The sign-off card moved from the command center to the workspace column and collapses to a one-line header. "Approve for deployment" is offered only for `GO` / `CONDITIONAL_GO`.
- **Pipeline stepper.** A six-stage stepper (Recon, Discovery, Plan, Execute, Verify, Gate). Every stage has a fixed size in every state; details open on click or keyboard into a fixed-height area, nothing reacts to hover except colour, so the layout never shifts. The Gate stage shows the verdict exactly as the backend reported it.
- **Cancel button and status chips.** Running runs in Runs history have a Cancel button (`POST /api/agent/runs/{id}/cancel`); running, cancelled and failed runs carry a lifecycle chip. A cancelled run shows its partial results and never a gate decision.
- **Token settings.** A key button in the header opens the API-token dialog. The token is kept in `localStorage` (`readyhai_api_token`, in memory when storage is blocked) and attached to every request; a `401` raises a banner until a valid token is saved.
- **Sandboxed reports.** HTML reports are fetched with the token and shown in an iframe sandboxed without `allow-scripts` and `allow-same-origin`; other formats are downloaded as blobs.
- Frontend tests for the new behaviour (`AgentHistoryView`, `Composer`, `FloatingTaskWidget`, `RunStatusBadge`, `ToolCallList`, clipboard and deep-audit cache helpers).

### Changed

- The UI renders only what the backend reported: a missing verdict, score, pillar, requester IP or latency is shown as "not evaluated" or "unknown" in a neutral style, and a green GO appears only for a `GO` verdict. Sign-off state changes only after the backend confirms it.

## [0.2.0] - 2026-11-05

Backend: review fixes, verifier, eval harness, CI, and the super agent (shared QA checks, code-aware planning, lead and sub-agents, memory across runs). These ship together because the super-agent modules are wired into the same core files.

### Security

- **Tokens never reach curls or reports.** Test credentials come only from `RH_<ROLE>_TOKEN` variables; reproduction commands carry the placeholder `${RH_<ROLE>_TOKEN}`, evidence is redacted, and the server's own secrets are never attached to requests sent to a target.
- **Credentials are bound to the target host.** A token is attached only when scheme, host and port equal the run's target, only through the client that validates TLS certificates, and redirects are never followed, so a credential cannot follow a `Location` header elsewhere.
- **Fail-closed scope loading.** A scope file that is configured (`--scope`, `READYHAI_SCOPE`) but missing, a directory, unreadable or invalid is an error everywhere: scans, `agent`, MCP tools and every REST guard (500) refuse to run, and `readyhai serve` checks it at startup (with a hint for the empty directory Docker creates when `scope.toml` is missing).
- **MCP agent tools are safe by default.** `readyhai_agent_swarm` is a dry run unless the caller says otherwise *and* the operator set `READYHAI_MCP_ALLOW_WRITES=1` (the target must also be nonprod in scope); unknown arguments are rejected; at most 2 swarms run at once.
- **Compose network isolation.** The Docker socket proxy sits on an `internal: true` network shared only with `readyhai`; the frontend is on the `edge` network only and cannot reach it. The proxy image is pinned (`v0.5.0`), the backend and the proxy have healthchecks and start in dependency order, and services run with `init: true` and a stop grace period (20 s for the backend).

### Fixed (accuracy)

- **One oracle path.** Every outcome (base request, mutation probe, burst, stateful chain, verifier replay) is judged by `agent::oracle`, with severities from a single table (`triage::severity_for`).
- **Deterministic verdicts.** The LLM may add planned cases, prose and an advisory opinion stored beside the verdict; `gate_verdict` is always the computed one. LLM-proposed cases whose expectations no deterministic oracle failed are run but not scored.
- **Inconclusive is a first-class outcome.** A failure that does not reproduce becomes `INCONCLUSIVE` (not a defect); a ledger with no conclusive result is `NOT_EVALUATED`; `readyhai qa` reports **Inconclusive** when nothing is known to be wrong but too little ran.
- **No fabricated results.** Pillars without conclusive evidence are "not evaluated" (no default scores); the Evidence pillar is the share of executed cases with a stored request/response file; remediation output is generic guidance labelled "example - adapt to your code" (the invented unified diffs are gone); network-lab fields that cannot be measured are `null` or listed in `not_measured`; PR comments and badges say "not evaluated" / `n/a` instead of defaulting to PASS.
- QA engine: a response that says nothing about a case is Blocked, never Pass; check status follows the evidence (Errored / Partial / Skipped); writes never touch harvested records.

### Added

- **The agent reuses the QA engine's API checks.** With an OpenAPI spec the planner uses `qa::api::synth` (case generator), `contract` (response validator and error-leak catalog) and `latency` (p95 over 1000 ms) instead of its own copies. It reads the ids of existing records from collection endpoints (read-only GETs) and plans a contract read per record. Every case carries its response contract, so the oracle and each verifier replay judge it the same way. The eval fixture's 7 seeded bugs are now all found by the agent (7/7).
- **Code-aware planning.** `readyhai agent --repo DIR --diff-base REF` (and `repo` / `diff_base` over REST and MCP) plan around `git diff REF...HEAD`: the QA engine's route extractors map changed files to OpenAPI operations, changed operations get the full case set (even at `quick`), are planned first and cut last, and the report gets a **Change impact** section with per-operation coverage. A diff that cannot be read is a note, never a failed run. An optional context retriever (`runners/context_retriever`, only when an index exists) adds untrusted, redacted, advisory notes and never a case. New settings: `READYHAI_CONTEXT_INDEX`, `READYHAI_CONTEXT_RETRIEVER`, `READYHAI_CONTEXT_TIMEOUT_SECS`, `READYHAI_HOME`.
- **Lead agent and area sub-agents** (`src/agent/lead.rs`). The planner tags every case with an area (`auth`, `contract`, `state`, `ui`); the lead gives each area a slice of the run budget (weighted by risk, three times for a changed operation), runs the areas on `READYHAI_AGENT_WORKERS` threads (default 4, at most 8; `1` gives the same results one after another), merges results by case id, and plans at most one deterministic wave 2 (`auth-to-contract`, `budget-resume`, `inconclusive-reprobe`, never a new write). One per-host rate limiter and one cancel flag are shared by all workers. Reports gain an "Agents" section; `readyhai_agent_status` shows per-area progress.
- **Memory across runs** (`src/agent/memory.rs`). Each target gets `<data>/memory/<target_key>.json` with known defects (by fingerprint), flaky history per case class, per-operation coverage and run aggregates. Known defects are re-tested first, runs report "Since last run" (new, still open, fixed, regressed, not re-tested, known flaky, accepted, acceptance expired), and known-flaky failures are replayed with the maximum k. Memory is written only from deterministic results, never from LLM text, and only reorders a plan. `readyhai agent-memory show|accept|forget`, `GET/DELETE /api/agent/memory`, `POST /api/agent/memory/accept`, and `READYHAI_AGENT_MEMORY=off`. An explicit, expiring acceptance is the only thing that lets a known defect through the gate; it is listed in every report (SARIF `suppression`, JUnit `skipped`).
- Triage folds failures of one check on one endpoint (`/orders/4`, `/orders/5`, ...) into one defect, and the same server error on three or more endpoints into one.
- **Verifier replay.** Every FAIL is replayed `READYHAI_VERIFY_K` times (default 2, at most 5, `0` = off) through the same oracle before triage: all reproduce = confirmed, some = flaky (kept as FAIL for high/critical, WARN otherwise), none = INCONCLUSIVE. Write-method failures are replayed only when the case created its own resource or targets an id no record has. The ledger reports pass^k.
- **Cleanup ledger and confirmation.** Every 2xx creation the run causes is recorded as it happens; on a confirmed-nonprod target the run deletes them newest first, confirms each 2xx DELETE with a GET (`confirmed_gone`, `still_present` = `delete_not_effective`, `unconfirmed`) and writes `cleanup.json` with the leftovers.
- **Eval harness.** `readyhai eval [--suite a,b] [--k N] [--out DIR] [--dir DIR]` scores the QA engine and the agent against fixtures with seeded defects (recall, false positives, pass^k, verdict stability, request and time budgets). Suites in `tests/eval/*.toml`: `qa-api`, `qa-repo`, `agent-api`, `agent-diff`, `agent-memory`. Writes `eval-report.json` and `eval-report.md`. See `docs/eval.md`.
- **CI gates.** New `eval` job (loopback only, no docker, no LLM) and `docker` job (PR builds of the three images, no push); `ci.yml` is reusable (`workflow_call`) and `image.yml` publishes only for the tag `v<VERSION>` after the full CI passed.

### Changed

- `readyhai_agent_status` reports `since_last_run` and per-area progress; `report.json` is checkpointed while the workers run.
- **Exit codes.** `readyhai qa` and `readyhai agent` exit `0` / `1` / `2` (Go / Conditional Go / No-Go or not evaluated); `qa` takes the worse of the recommendation and the gate verdict. Errors still exit `3`; `eval` exits `0` or `1`.
- **MCP.** `readyhai_agent_swarm` returns a run id at once and runs on a worker thread; `readyhai_agent_status` and `readyhai_agent_cancel` poll and stop it; on client disconnect every run the server started is cancelled.
- Reliability: reads are capped (tool stdout 32 MiB, tool output files 50 MB and never through symlinks, response bodies 1 MiB, memory file 8 MiB), state files are written atomically (temp file + rename), and agent runs can be cancelled (`POST /api/agent/runs/{id}/cancel`, `status: cancelled`, partial results kept).

## [0.1.0] - 2026-10-27

Baseline: the repository as committed at `ed4215b` (first commit 2026-10-25; the tag `v0.1.0` marks `8bf9bd5` on 2026-10-27, and development continued under the same version until 2026-11-05).

### Added

- **Scan engine.** `readyhai scan` for repositories, container images, web apps and APIs, SSH hosts (Linux, macOS, Windows) and Android APKs; a check registry with native readiness rules, container checks and plugins; a filtered snapshot with a secrets denylist; a policy gate (PASS / WARN / FAIL), baselines, suppressions with expiry; HTML, JSON, SARIF and JUnit reports; log clustering. Scanners (Syft, Grype, Gitleaks, Semgrep, Hadolint, Checkov, Dockle, ZAP, Schemathesis, MobSF) run in throwaway sandboxed containers pinned by digest in `tools.lock.toml`.
- **Interfaces.** CLI, REST API (`readyhai serve`, bearer token on every route but `/health`), MCP server over stdio, the `/readyhai` Claude Code mod, Docker image and compose stack with a socket proxy, CI recipes for Jenkins, GitHub Actions, GitLab and ArgoCD PostSync.
- **Senior-QA engine** (`readyhai qa`): API tests (positive, boundary, negative, auth matrix, stateful CRUD, BOLA, contract, error leaks), UI tests with Playwright (responsive, a11y, vitals, forms, journeys, visual), k6 performance baseline, compose fault injection, suite and release quality (coverage, untested routes, test smells, end-of-life, migrations, licences), `roles.toml`, a computed Go / Conditional Go / No-Go recommendation, and HTML, PDF, Markdown, Jira, GitLab, TestRail and Xray reports.
- **Offline mode.** `bundle export` / `bundle import`, `doctor`, an embedded end-of-life snapshot, optional LAN LLM enrichment, a static trend dashboard.
- **Agentic AI QA** (`readyhai agent`): Planner, Explorer, Triager and a readiness gate with a four-pillar Evidence Ledger (Value, Authority, Safety, Evidence); extended thinking with model tiers; adaptive schema mutation; stateful multi-actor chains and BOLA audits; TOCTOU concurrency bursts; example remediation guidance; MCP swarm tools; a persistent run history with retest, delete and sign-off.
- **Agent Studio** (`frontend/`, Next.js 16 and React 19): swarm composer, scenario inspector, evidence ledger, threat triage, scans history, and the **Regressive Network Lab** (regress, curl, six-pillar deep audit, multi-region single vantage point, HAR export, PR comment and badges).
- **Supply-chain checks** (`src/supply.rs`): OSV-Scanner reachability, OpenSSF Scorecard, Spectral, oasdiff, mutation-report parsing.
- **Scope policy.** `scope.toml` rules of engagement: public hosts get full testing by default, internal hosts must be listed, `prod` entries are read-only, `*` wildcard, `[git]` host allowlist.
- **Release engineering.** Single-source versioning (`VERSION`, `scripts/version.sh`), multi-arch GHCR images with SBOM and SLSA provenance, release tarball attestation, OpenSSF Scorecard workflow, all actions pinned by commit SHA.
- Live verification on 2026-10-30: UI QA (6/6 seeded UI bugs) and PDF, ZAP baseline and Schemathesis on the fixture API, resilience pause/unpause on a compose fixture, MobSF on InsecureBankv2. See `docs/build-log.md`.
- Licensed under AGPL-3.0.
