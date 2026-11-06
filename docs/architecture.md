# Architecture

Single Rust crate (`readyhai`, edition 2024, about 78,000 lines in `src/` including unit tests; 17 direct dependencies). One binary provides the CLI, the REST server, the MCP stdio server, the eval harness and a health probe. The Agent Studio is a separate Next.js app in `frontend/`.

## Components

| Component | Code | Role |
|---|---|---|
| CLI | `src/main.rs` | clap derive. Subcommands `scan`, `qa`, `agent`, `agent-memory show\|accept\|forget`, `eval`, `bundle export\|import`, `doctor`, `baseline accept`, `checks`, `tools pull\|update`, `serve`, `dashboard`, `mcp`, `ping`. Maps verdicts to exit codes (scan 0/1/2, qa and agent 0/1/2, error 3). |
| Engine | `src/engine.rs` | Parses target, takes snapshot, detects facts, loops over the check registry, dedups, applies suppressions and baseline, runs the gate, writes `run.json`. |
| Check registry ("mods") | `src/checks.rs` | `Check { id, title, kinds, min_profile, tool, intrusive, run }`. `checks::all()` concatenates the 41 built-in checks plus optional plugins. |
| Native rules | `src/rules.rs` | `readiness.*` checks (Dockerfile, deps, compose, k8s, CI, repo hygiene) and fact detection. In-process, no containers. |
| Tool runners and parsers | `src/tools.rs` | Docker sandbox runner, create-policy, lock file, gitleaks/grype/semgrep/hadolint/checkov/dockle/image-inspect/JUnit/SARIF parsers, `tests.own`, plugins, `tools pull|update`. |
| Supply-chain checks | `src/supply.rs` | OSV-Scanner reachability, OpenSSF Scorecard, Spectral, oasdiff. |
| Web checks | `src/web.rs` | Native `web.smoke`, plus Schemathesis, ZAP baseline, Playwright runner containers. |
| Host checks | `src/host.rs` | SSH probe (Linux/macOS/Windows), host package CVEs through grype, Lynis. |
| Android checks | `src/android.rs` | MobSF per-scan container, adb runtime check. |
| Snapshot | `src/snapshot.rs` | Filtered copy of the repo. Secret-bearing files become empty placeholders. |
| Facts | `src/facts.rs`, `rules::detect_facts` | What is in the snapshot (Dockerfiles, compose, k8s, manifests, CI files, README, tests, framework, dep counts). |
| Policy gate | `src/policy.rs` | Suppressions, per-category summary, verdict. Default policy embedded from `policies/default.toml`. |
| Baseline | `src/baseline.rs` | Accepted fingerprint set, portable JSON. |
| Scope | `src/scope.rs` | `scope.toml` rules of engagement: host classification (public / internal / unresolvable), the egress guard, the git host allowlist, fail-closed loading. |
| Reports | `src/report.rs`, `templates/report.html.j2` | HTML, JSON, SARIF 2.1.0, JUnit. |
| Log clustering | `src/logs.rs` | Normalizes error lines into signatures, groups, redacts examples. |
| Senior-QA engine | `src/qa/` | `readyhai qa`: API, UI, perf, resilience, suite and release checks, triage, recommendation, reports. Module map below. |
| Agent engine | `src/agent/` | The autonomous agent: discovery, planner, explorer (lead and area workers), verifier, cleanup, triager, readiness ledger, memory, change-aware planning, persistence. Module map below. |
| Eval harness | `src/eval.rs`, `tests/eval/*.toml` | `readyhai eval`: runs the QA engine and the agent against seeded-defect fixtures and scores recall, false positives, pass^k, verdict stability and budgets. See [eval.md](eval.md). |
| Network lab | `src/network.rs` | Regress, curl, six-pillar deep audit, multi-region (single vantage point), HAR export, requester IP. |
| REST server | `src/serve.rs` | axum 0.8, bearer token on every route but `/health`, one in-process scan worker, the egress guard, agent and network routes. |
| MCP server | `src/mcp.rs` | Hand-written JSON-RPC 2.0 over stdio. No `rmcp` crate. Scan tools plus the async agent swarm tools. |
| LLM abstraction | `src/llm.rs`, `src/llm/untrusted.rs` | Provider catalog (vLLM, Ollama, cloud), reasoning-parameter handling, token budgeting, response cache, and the untrusted-text helpers (preamble, redaction, fencing, output cleaning) every prompt goes through. |
| Offline | `src/bundle.rs`, `src/dashboard.rs` | Air-gapped bundle export/import, `doctor`, the static trend dashboard. |
| Agent Studio | `frontend/` | Next.js 16 / React 19 UI with an `/api/*` proxy to the backend. See [../frontend/README.md](../frontend/README.md). The old in-binary `src/web_ui.rs` SPA no longer exists; `GET /` on the backend returns a JSON endpoint index. |
| Context retriever | `runners/context_retriever/` | Optional Python runner (LangGraph, BGE-M3) the agent can query for advisory notes about changed operations. |

## Agent architecture (`src/agent/`)

The agent is a deterministic pipeline with an optional LLM on the side:

```
[target URL, optional spec, optional repo + diff_base]
        |
        v
1. Discovery ----------> crawl (same-host redirects only), route classification, SPA detection, spec read, ids of existing records
        |
        v
2. Planner ------------> baseline from the crawl + spec-driven cases (shared QA generators); changed operations first
        |                 (change.rs); known defects first (memory.rs); every case tagged with an area; optional validated LLM extras
        v
3. Explorer = Lead ----> allocates a budget slice per area, runs auth | contract | state | ui workers, merges by case id,
        |                 plans at most one wave of deterministic follow-ups (lead.rs); every response judged by the oracle
        v
4. Verifier -----------> replays every FAIL k times through the same oracle; not reproduced = INCONCLUSIVE (verify.rs)
        |
        v
5. Cleanup ------------> deletes what the run created (newest first, nonprod only), reads each 2xx DELETE back (pipeline.rs::teardown)
        |
        v
6. Triager ------------> clusters failures into defects, OWASP labels, severities from one table (triage.rs)
        |
        v
7. Readiness gate -----> technique-coverage matrix -> four pillars -> GO | CONDITIONAL_GO | NO_GO | NOT_EVALUATED (ledger.rs)
        |
        v
[AgentRunReport: <data>/agent-runs/<run id>/report.json + evidence/ + cleanup.json + report/*]
```

`report.json` is checkpointed after every stage with `status: "running"` and ends as `completed`, `failed` or `cancelled`. Cancellation (`request_cancel`, the REST route, MCP `readyhai_agent_cancel`, client disconnect) is honoured between steps; the run still triages and tears down what it did.

**Rules every module follows.** Verdicts are deterministic. The oracle judges each observation, triage derives defects and severities from failed assertions, and the ledger computes pillars and the gate from a technique-coverage matrix. The LLM can add planned cases (validated against the discovered routes and the spec, never remapped), prose notes and an advisory opinion; the opinion is stored beside the verdict (`llm_advisory`) and never changes `gate_verdict`. Everything that reaches an LLM and came from the target goes through `llm::untrusted`. Test credentials come only from `RH_<ROLE>_TOKEN` variables; the server's own secrets are never attached to requests sent to a target. A run has a `RunBudget` (steps, requests, wall clock, per-host rate, LLM calls) and honours `dry_run`. Nothing is invented: a pillar with no conclusive evidence is "not evaluated", an unreachable target is BLOCKED, never PASS.

### Module map

| Module | Role |
|---|---|
| `mod.rs` | Module wiring and the design rules above |
| `pipeline.rs` | The run: stage order, checkpoints, LLM resolution, `RunOptions`, cancellation, cleanup/teardown, memory hooks, `run_agentic_loop_with`, `run_discovery_scan` |
| `discover.rs` | Crawl and route discovery, tech detection, `SpecDoc`, id harvesting |
| `plan.rs` | The planner: baseline, spec-driven cases (`qa::api::synth`, `qa::plan`), depth by profile, `plan_cases_changed`, `plan_cases_remembered`, LLM extras validation |
| `change.rs` | Change-aware planning: `git diff`, route extraction (`qa::suite::extract_routes`), operation mapping, optional context retriever |
| `lead.rs` | The lead: areas, budget allocation, workers, write ordering, merge, wave 2, the "Agents" report |
| `budget.rs` | `RunBudget`, per-host `HostLimiter`, slices, environment overrides |
| `exec.rs` | The explorer: builds and sends requests (`Clients::send` is the only place a request leaves), credentials, reproduction curls, evidence files, flaky re-runs, teardown confirmation reads |
| `oracle.rs` | The typed assertion oracle: one observation plus its case in, PASS / FAIL / INCONCLUSIVE checks out |
| `verify.rs` | The independent verifier: replay, pass^k, `apply` policy |
| `mutation.rs` | Adaptive schema mutation from validation-error reflection |
| `stateful.rs` | Multi-actor chains (BOLA) and concurrency bursts (TOCTOU) |
| `triage.rs` | Defects, OWASP classes, `severity_for`, folding of repeated failures, LLM notes |
| `ledger.rs` | Coverage matrix, pillars, gate verdict, exit checklist, claims, verification summary |
| `memory.rs` | Per-target memory, "Since last run", acceptance |
| `remediation.rs` | Generic example guidance per defect class (never a patch) |
| `report.rs` | HTML, Markdown, SARIF, JSON and JUnit renderings of a run |
| `store.rs` | Persistence under `<data>/agent-runs/`, per-run locks, sign-off, retest, delete |
| `types.rs` | Shared types: request, report, planned case, result, defect, ledger, cleanup, verification, cancel token |

### Oracle (`oracle.rs`)

One path judges everything: the base request, an adaptive-mutation probe, a concurrency burst, a stateful chain and every verifier replay all go through `oracle::judge`, `judge_burst` or `judge_stateful`. A check code (`authz`, `server_error`, `error_disclosure`, `contract_fields`, `expected_status`, `content_type`, `cors`, `injection_reflection`, `sensitive_exposure`, `path_traversal`, `race_condition`, `mass_assignment`, `slow_response`, `undocumented_status`, `delete_not_effective`, ...) carries a verdict and a severity from the single table `triage::severity_for` (critical: `authz`, `sensitive_exposure`, `path_traversal`; high: `race_condition`, `mass_assignment`, `error_disclosure`, `injection_reflection`, `cors_credentialed`, and `server_error` on injection and authz cases; medium: other `server_error`, `cors`, `expected_status`, `contract_fields`, `delete_not_effective`; low: `expected_redirect`, `content_type`, `slow_response`, `undocumented_status`). No LLM input is consulted. A case proposed by the LLM is `exploratory`: its own expectations are not evidence, so only deterministic invariant checks can fail it, and a passing exploratory case is not scored.

With an OpenAPI spec the agent does not re-implement the QA engine's API checks; it reuses the context-free parts of `src/qa/api`: the case generator (`synth::generate`: a string one character over `maxLength`, a number past `minimum`/`maximum`, a missing required field), the response validator (`contract`: documented statuses, 2xx body schema subset), the error-leak catalog (`contract::leak_kind`) and the latency limit (`latency`: p95 over 1000 ms). The planner reads the ids of existing records from the collection endpoints (read-only GETs), plans a contract read per record and the probes per operation; every case carries its response contract (`PlannedCase.contract`), so the oracle and each verifier replay judge it the same way.

### Credentials (`exec.rs`)

All enforced in `Clients::send`, the only place a request leaves the process: `RH_<ROLE>_TOKEN` is attached only when the request's scheme, host and port equal the run's target (exact match); only through a client that validates TLS certificates (requests that carry a real credential never go through the client that accepts invalid certificates); a redirect is followed only for a safe GET/HEAD liveness, content or robustness case, only to the same origin (exact scheme, host and port, at most 5 hops, each hop through `Clients::send` again), so a credential cannot follow a `Location` to another host; authorization cases, sensitive-file probes and forged-token requests are never redirected (the raw status is their evidence). Reproduction commands carry `${RH_<ROLE>_TOKEN}`, never the value; stored evidence is redacted and capped (64 KiB bodies).

### Verifier (`verify.rs`)

Before a FAIL reaches triage and the ledger it is replayed `k` times (`READYHAI_VERIFY_K`, default 2, at most 5, `0` = off). The request is rebuilt from the stored case and the credential attached afresh; each replay is judged by the same oracle and *reproduces* the failure when it fails again with at least one of the original failing checks. Outcomes: `Confirmed` (all k reproduce), `Flaky` (some), `NotReproduced` (none), `Unverified` (not replayable, or a budget or cancellation stop). Policy (`verify::apply`): not reproduced becomes INCONCLUSIVE and is not a defect; flaky stays FAIL, flagged, for critical and high failures and becomes WARN otherwise; confirmed and unverified keep FAIL (an unverified high/critical defect still blocks the gate, because a failure that could not be examined is not evidence that it is gone). Only safe methods are repeated freely; a write-method FAIL is replayed only when the original case created its own resource (a 2xx creation, a stateful chain that builds its own object) or targets an id no record has (`999999`, `readyhai-nonexistent`). Replays are charged to the budget and rate limit, and what they create is recorded for teardown. Cases that memory knows as flaky get k = 5. The ledger carries the summary (`pass^k`).

### Cleanup (`pipeline.rs::teardown`)

Every 2xx creation the run causes (normal cases, mutation probes, stateful-chain POSTs, every request of a burst, verifier replays) is recorded in a `CreatedLedger` as it happens. At the end of a non-dry-run run against a target the scope file confirms as nonprod, the run DELETEs them newest first (the budget is deliberately not consulted) and reads each one back: `confirmed_gone` (404/410), `still_present` (a 2xx DELETE that left the resource: a `delete_not_effective` defect and a leftover), `unconfirmed` (401/403/5xx/transport error). Whatever cannot be removed, including creations whose response named no id, is listed in the report notes and in `cleanup.json`. On a target not confirmed nonprod nothing is sent and every resource is listed as a leftover.

### Change-aware planning (`src/agent/change.rs`)

With `repo` and `diff_base` on the run request (`readyhai agent --repo DIR --diff-base REF`, REST, MCP) the agent plans around the code diff, deterministically and without an LLM:

```
git diff --name-only <base>...HEAD  (no hooks, no prompts, null stdin, time and output capped, inside the repo)
        │  changed files
        ▼
qa::suite::extract_routes (the QA engine's own extractors)  ──►  routes of each changed file
        │  qa::suite::route_segments: one path-template normalisation for routes and spec paths
        ▼
spec operations: exact template match, prefix-mounted match, else "file changed, routes unknown"
        │  ChangeSet
        ▼
plan::plan_cases_changed: changed operations planned in full, first (PlannedCase.changed_ops),
plan_order() cuts unchanged cases first  ──►  report.change_impact (+ per-operation coverage)
```

Git and file reads never fail the run: a diff that cannot be read ends as `change_impact.status = failed` with the reason in its notes and the plan the profile alone gives. Files are read without following symlinks. An optional context retriever (`runners/context_retriever query --json`, only when an index exists) adds untrusted, redacted, advisory `context_notes`; it never adds a case. The triager also folds failures of one check on one endpoint (`DELETE /orders/4`, `/orders/5`, ...) into one defect that lists all its cases, and the same server error on three or more endpoints into one, as the QA engine's triage does.

### Lead and area workers (`src/agent/lead.rs`)

The Explorer stage is an orchestrator-worker structure (a lead agent and specialised sub-agents), kept deterministic and safe:

```
plan (every case tagged with an area by the planner)
        │
        ▼
Lead: partition by area ──► allocate a RunBudget slice per area (steps, requests, wall clock, LLM calls)
        │                    weight = risk of the cases x 3 for a changed operation; capped at what the area can use;
        │                    ~15% of the requests stay in the lead's pool
        ▼
wave 1:  auth worker | contract worker | state worker | ui worker      (READYHAI_AGENT_WORKERS threads, default 4, max 8)
         each runs the ordinary exec path on its slice; one shared per-host rate limiter and one cancel flag
        │
        ▼  merge by case id (natural order, never by completion time)
wave 2 (at most one): deterministic follow-ups, no LLM, from the pool (unused slices + the reserve)
        │
        ▼
verify -> cleanup -> triage -> ledger          (unchanged, on the merged results)
```

| Area | Cases |
|---|---|
| `auth` | authz technique: unauthenticated / forged-token access, BOLA chains, sensitive-file probes, CORS |
| `contract` | contract, boundary, negative, injection and latency cases from the spec (and non-mutating LLM extras) |
| `state` | stateful chains that are not authz, concurrency bursts, state-changing lifecycle cases |
| `ui` | the crawl-grounded baseline: page liveness and the probes of discovered pages, SPA checks |

What keeps it deterministic and safe:

- **One politeness limit.** `budget::HostLimiter` hands out request slots per host; every slice of the run shares it, so N workers together never exceed `READYHAI_AGENT_RATE_PER_HOST`. Parallelism hides response latency, it does not raise the request rate: a run that is paced by the limiter (the eval fixture) takes as long with 4 workers as with 1.
- **One cancellation flag.** Slices share the run's cancel token (and marker file). A worker that waits for a request slot or for its turn wakes up and stops; every unrun case is SKIPPED with `run cancelled`.
- **Writes take turns.** A case that can change the target (write method, chain with a write step, burst) runs in one fixed order: area order, then plan order. Reads run in parallel. So the ids a target hands out and the order of the created-resource ledger are the same with 1 worker as with 8. Areas are claimed in that same order, so a worker only ever waits for an area that is already running.
- **Fixed slices, a pool after the wave.** Nothing is borrowed between areas inside a wave. What an area leaves unused is reclaimed when the wave ends; wave 2 spends it (and the reserve) and nothing else.
- **Wave 2 rules** (`lead::plan_follow_ups`, at most 12 cases, never a new write): `auth-to-contract` (a read that failed an access check gets a contract check on the same endpoint as the identity that was let in, with the contract of the plan's own case for that operation), `budget-resume` (a case an area budget cut off is run from the pool), `inconclusive-reprobe` (a safe read that ended on a transient cause, a timeout or network error, a 5xx, a 429 or 408, is sent once more; a deterministic INCONCLUSIVE such as a redirect, no class evidence, a CORS 405 or an auth wall never is). Follow-ups get the id `<origin>-F1`, join the plan, and are replayed by the verifier like any case.
- **Stable merge.** Results are merged in case-id order; `READYHAI_AGENT_WORKERS=1` runs the areas one after another and gives the same plan, results, defects and ledger as 8 (checked by `one_worker_and_four_give_the_same_plan_results_defects_and_ledger` and by the eval's verdict stability and pass^k).

Known limits: a read that observes records another area is creating at that moment can see a different list from run to run (no fixture verdict depends on one); a wall-clock limit that binds cuts the run where the machine happens to be.

The report has an "Agents" section (markdown, HTML; `agents` in the JSON) with one row per area: status, cases, sent, pass/fail, steps, requests, wall clock and LLM calls used/allocated, defects, and the wave-2 additions with their rule. The run's `report.json` is checkpointed while the workers run, and `readyhai_agent_status` shows the same per-area progress (cases sent, failures, budget used/allocated, wave-2 additions).

### Per-target memory (`src/agent/memory.rs`)

The agent remembers what it learned about a target, so the next run starts from it. It is deterministic, written only from deterministic results, and never changes a verdict by itself.

```
run N-1 ──► memory file <data>/memory/<target_key>.json ──► run N
              known defects (fingerprint, first/last seen, open|fixed|regressed, runs seen, acceptance)
              flaky history per case class (pass/fail/flaky over the last 20 runs that ran it)
              per-operation last coverage and last result, baselines in effect, last 50 run aggregates
```

* **Key.** `sha256(canonical target URL)[..16]` (scheme, host, port and path; no userinfo, query, fragment or trailing slash), the same construction as `engine::target_key` for a web target.
* **Identity of a defect.** `sha256(failing check, endpoint template)[..24]` (`TriagedDefect.fingerprint`; record ids collapse to `{id}`, so `/orders/4` and `/orders/7` are one defect; a merged "same server error on N endpoints" defect is identified by the error). A case class is `technique|METHOD|endpoint|role`; the reproduction of a defect is the case classes whose failure defines it.
* **Written from** the oracle, verifier and triage output of a finished run: statuses, failing check codes, fingerprints, sanitized endpoint templates. Never from LLM text (`ai_note`, summaries), response bodies, titles, evidence or reproduction commands. What comes from the target (a path) is reduced to `[A-Za-z0-9 /_.\-{}~:@+,;=*%()\[\]]`, 200 characters at most; operator text (accepted by, reason) loses control characters and is capped. A run that was cancelled does not update the memory.
* **Transitions.** Found now and unknown: **new**. Known open (or regressed) and found again: **still open**. Known fixed and found again: **regressed**. Known open, not found, and *every* reproduction case class ran and passed: **fixed**. Not found but the cases were skipped, blocked, inconclusive or not planned: **not re-tested**, the defect stays open (absence is not a fix).
* **What the planner does with it** (`plan::plan_cases_remembered`, `memory::PlanHints`): it reorders and tags, nothing else. The cases of a case class that failed for an open, regressed or recently fixed (30 days) defect come first (`PlannedCase.regression_of` holds the defect fingerprints), then the changed operations of change-aware planning, then the operations that failed last time they ran or have flaky history (`history_priority`), then the rest, every tier in the planner's order. No case is added, dropped or rewritten, so an operation that passed before keeps its baseline coverage; the planner never builds a request from memory. (Only when a plan is cut to a step cap or the `quick` profile cap does the order decide what is dropped: the cut then falls on operations that never failed first, exactly as it falls on unchanged operations in a change-aware run, and the dropped cases are listed as SKIPPED.) The verifier replays failures of known-flaky cases with the maximum k (5) instead of `READYHAI_VERIFY_K`. Follow-up cases of the lead are not probes. With the same memory the plan is the same for any `READYHAI_AGENT_WORKERS` (the plan does not depend on it).
* **Acceptance.** `readyhai agent-memory accept <target> <fingerprint> --reason ... --expires YYYY-MM-DD` (or REST) is the one operator decision that touches the gate. While it holds (through the expiry date), the defect is listed but does not block: `TriagedDefect.accepted` is set, `ledger::is_blocking` is false, its failing cases are run and listed but not scored (like unconfirmed exploratory cases), and the ledger's verdict basis says what the computed verdict would be without it. After the date the defect blocks again and is listed as expired. A defect that gets fixed loses its acceptance. SARIF carries it as a `suppression`, JUnit as `skipped`.
* **Report.** A "Since last run" section (`AgentRunReport.since_last_run`, also in the JSON report, the markdown and HTML renderings, and `readyhai_agent_status`): New, Still open, Fixed, Regressed, Not re-tested, Known flaky, Accepted (with who, why and expiry), Acceptance expired, and the regression probes at the head of the plan.
* **File.** Schema-versioned (`schema: 1`), written atomically (temp file + rename) under the per-target lock `<memory>/.locks/<key>.lock` (the lock the run store uses; held only while a run, `accept` or `forget` reads the current state and writes the new one). A run folds itself into the memory it read without the lock when its gate stage starts and, if the file changed by the time it writes (another run, an operator), folds itself in again, so no update is lost and no lock is held while an LLM is slow. The file carries a SHA-256 digest of its content. A file that does not parse, has another schema or target, is over 8 MiB or fails the digest is moved to `<key>.json.corrupt-<run id>` and ignored: the run says so in its notes and plans from the profile alone. The digest catches accidental and naive edits, not an attacker who can write the data directory (they can also edit the run store): hand edits go through `agent-memory accept|forget`.
* **Retention.** The last 50 run aggregates; a defect, flaky entry or operation not seen for 90 days is dropped; flaky history keeps the last 20 outcomes per case class; caps of 500 defects, 1000 operations and 2000 case classes.

### Persistence (`store.rs`)

Every agent run, discovery scan and retest is persisted under `<data>/agent-runs/<run id>/`:

```
report.json          the AgentRunReport, replaced atomically (temp file + rename); a checkpoint while running
evidence/<case>.json the stored request/response of each executed case (redacted, capped)
cleanup.json         what the teardown created, deleted, confirmed and left behind
CANCEL               marker written by a cancel request for a run in another process
report/              readyhai-report.{html,json,md,sarif,junit.xml}, rendered when the run ends or on first GET
```

A lock file `<data>/agent-runs/.locks/<run id>.lock` (created exclusively, removed on drop, stale after 60 s) serialises load-modify-save (retest, sign-off, delete) so two writers cannot lose an update.

- **Unified `AgentRunReport` schema:** discovered routes, planned cases, executed results with reproduction curls, defects, the Evidence Ledger, the verification summary, the cleanup report, agents, change impact, since-last-run and sign-off state.
- **Discovery scans:** `/api/agent/discover` stores a report with the profile `discovery-scan` and no score, so reconnaissance is visible in the history.
- **In-place retest:** `/api/agent/retest` re-runs one case, updates the stored result atomically and resets an earlier sign-off when the retest changes the gate verdict.
- **Sign-off:** approve or reject records the authenticated principal; a running run cannot be signed off and a cancelled or failed run can only be rejected.
- There is no hard-coded host exclusion anywhere: which hosts may be tested is decided only by `scope.toml`.

### The four pillars of the Evidence Ledger (`ledger.rs`)

A technique-coverage matrix (`authz`, `boundary`, `negative`, `injection`, `state_transition`; cells count pass, warn, fail, inconclusive, blocked, skipped, not applicable) feeds four pillars. *Conclusive* = pass + warn + fail; *applicable* = planned minus not applicable minus not executed (SKIPPED); a NOT_APPLICABLE case is in no denominator. A pillar's **confidence** is conclusive / applicable (percent); a pillar is scored only at 50% or more, otherwise it is "not evaluated" (no score), never a default. An inconclusive or blocked case is missing evidence, not a failure: it lowers confidence, never the score.

| Pillar | Weight | Techniques | Score |
|---|---|---|---|
| `value`: functional correctness and input handling | 30 | boundary, negative, state_transition | (pass + 0.5 warn) / conclusive cases; capped at 65 by a high failure and 40 by a critical one |
| `authority`: authorization and least privilege | 30 | authz | same |
| `safety`: injection resistance and data safety | 25 | injection | same |
| `evidence`: reproducible evidence | 15 | none | share of executed cases that have a stored request/response evidence file (the target answered and the file exists). A transport error or a missing file is not evidence, and a reproduction curl alone does not count |

Gate (`ledger::compute_scored`): the ledger carries an overall `confidence` (conclusive / applicable over the whole run) and `blockers` (an auth wall, no input surface, a transport error, an out-of-scope host), each with a detail and the next step. `NO_GO` when a blocking critical defect exists (a proven failure is never hidden behind low coverage); `NOT_EVALUATED` when overall confidence is below 50% or no functional pillar has a score, with the blockers and next steps in the executive summary; `NO_GO` when the weighted overall (over the scored pillars) is below 70; otherwise `CONDITIONAL_GO` when anything is left to say (blocking high defects, failed, flaky or blocked cases, an unevaluated pillar, fewer than 80% of applicable cases conclusive, overall below 85, dry-run skips) and `GO` when nothing is. A defect blocks (`ledger::is_blocking`) unless an unexpired memory acceptance covers it, or it is flaky or unverified and not high/critical. LLM-proposed cases that no deterministic oracle failed are listed but not scored. The ledger also carries claims that cite case ids and evidence files, an exit checklist (zero critical, no high, pass rate at least 85% of conclusive applicable cases, conclusive coverage at least 80% of applicable cases, authorization exercised and held, injection exercised and held, no blocked or flaky cases, evidence for every executed case) and `verdict_basis`. CLI and REST both surface it; the CLI exit code is 0 for `GO`, 1 for `CONDITIONAL_GO`, 2 for anything else.

### Frontend (`frontend/`)

The Agent Studio is a Next.js 16 app (React 19, Tailwind v4) served on port 3000. Its `/api/*` route handler proxies to `READYHAI_BACKEND_URL` and, when the UI container has `READYHAI_TOKEN`, attaches it server-side when the browser sent no `Authorization` header. Design system, scripts and token handling: [../frontend/README.md](../frontend/README.md).

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

The agent has its own flow, entered from `readyhai agent`, `POST /api/agent/run` (synchronous: the HTTP call returns the finished report) or MCP `readyhai_agent_swarm` (asynchronous: returns the run id at once and runs on a worker thread; at most 2 at a time):

```
 egress guard (scope: public ok, internal must be listed, prod refused for intrusive) ──► guard repo/diff_base (allowed roots)
        |
 discovery ─► plan (+change, +memory) ─► lead: auth|contract|state|ui workers ─► merge ─► wave 2
        |                                                                                    |
        └──────────── checkpoint report.json after every stage (status running) ◄───────────┘
        |
 verify (replay FAILs k times) ─► cleanup (DELETE + read back) ─► triage ─► ledger (gate) ─► memory update ─► save + reports
```

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

`<READYHAI_DATA>/runs/<run-id>/` (default data dir: `$XDG_DATA_HOME/readyhai` or `~/.local/share/readyhai`). Run id: `YYYYMMDD-HHMMSS-<16 hex digits>` (UTC + 64 random bits; ids from older builds with 4 hex digits stay valid).

```
runs/<id>/
  src/             snapshot (repo), image.tar (image), app.apk (android) - mounted read-only at /src
  out/             tool outputs (mounted rw at /out): gitleaks.json, sbom.cdx.json, grype.json, semgrep.json,
                   results_json.json (checkov), dockle.json, junit.xml, zap.json, playwright.json + screenshots,
                   host-probe.json, host-sbom.cdx.json, host-grype.json, mobsf.json
  artifacts/       QA artifacts: qa-baseline staging (spec, perf), UI screenshots and traces
  report/          server mode only: readyhai-report.{html,json,sarif,junit.xml}
  run.json         full Run, written at the end of engine::scan
  status.json      server mode only: {"id","state","error"}; state queued|running|done|error
<data>/baselines/<sha256(target)[..16]>.json   default per-target baseline
<data>/memory/<key>.json                       the agent's memory of one web target (see "Per-target memory")
<data>/agent-runs/<run-id>/                    agent runs: report.json, evidence/, cleanup.json, report/ (see "Persistence")
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
| Deep profile | intrusive checks | one built-in check is intrusive: `qa.resilience` (compose fault injection, `readyhai qa` only) | `deep` also enables `deep`-profile plugins and the Android monkey run. |
| Required check errored | hard FAIL | FAIL by default (`errored_fails = true` in the policy); WARN when the policy sets it false or the check's tool image is missing | See [checks.md](checks.md#verdict-rules). |
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

## Super Agent feature map

| Feature | Code | Notes |
|---|---|---|
| Extended Thinking | `src/llm.rs` | Reasoning budget 1k to 32k tokens (clamped), tiers Low, Medium, High, Max, Max Pro; what is sent depends on the provider and the run log says which |
| Adaptive schema mutation | `src/agent/mutation.rs` | Parses validation errors from FastAPI/Pydantic, Django REST Framework, Express/Zod and synthesizes targeted boundary and type probes (`<id>-M1`) |
| Stateful chains and BOLA | `src/agent/stateful.rs` | Alice creates, Bob reads; a prerequisite setup failure is not a breach |
| TOCTOU bursts | `src/agent/stateful.rs` | `std::sync::Barrier` synchronized bursts, planned only for spec-declared create operations |
| Verifier | `src/agent/verify.rs` | Replays failures k times; pass^k |
| Lead and area workers | `src/agent/lead.rs` | `auth`, `contract`, `state`, `ui`; wave 2 |
| Change-aware planning | `src/agent/change.rs` | `--repo` and `--diff-base` |
| Memory | `src/agent/memory.rs` | "Since last run", acceptance |
| Example remediation | `src/agent/remediation.rs` | Generic guidance labelled "example - adapt to your code"; never applied or tested; the invented diffs of earlier builds are gone |
| MCP swarm tools | `src/mcp.rs` | `readyhai_agent_swarm`, `readyhai_agent_status`, `readyhai_agent_cancel`, `readyhai_agent_discover` |
| Eval | `src/eval.rs` | The regression gate for all of the above |

## License

ReadyHai is distributed under the GNU Affero General Public License v3.0 (AGPL-3.0). See [`LICENSE`](../LICENSE) for complete terms.
