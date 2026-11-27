# Agent, QA & security intelligence

ReadyHai is both a deterministic security scanner and an autonomous QA/pentest agent. This
document covers the **agentic and intelligence side** of the product (v3.8.0): the senior-QA
engine, the 6-station Super Agent, the opt-in exploitation-verification engine, the cross-target
vulnerability database, the network lab, the evaluation harnesses, the agentic fixer and mutation
tester, the MCP server, and the operator settings/RBAC system that governs all of it. The scanner
core — target syntaxes, the check catalog, profiles, baselines and reports — is documented in the
sibling feature guide, [Scanning and targets](./scanning-and-targets.md).

One invariant runs through everything below: **Deterministic Primacy**. All verdicts and defect
classifications are computed by deterministic code; LLM output is strictly advisory — it can add
validated cases, prose and prioritisation, but it never mints or changes a verdict. Where a
feature sends traffic at a target, it is separately gated by the scope rules of engagement
(`scope.toml`, prod refusal) and, for the newest classes (exploit re-verification, intrusive
checks, MCP writes), by explicit operator opt-in in `settings.toml`.

## In this section

- [QA test suite (`readyhai qa`)](#qa-test-suite-readyhai-qa)
- [Super Agent (`readyhai agent`)](#super-agent-readyhai-agent)
- [Exploitation verification (`readyhai exploits`)](#exploitation-verification-readyhai-exploits)
- [Vulnerability database (`readyhai vulns`)](#vulnerability-database-readyhai-vulns)
- [Network lab & WireGuard audit](#network-lab--wireguard-audit)
- [Eval harness (`readyhai eval`)](#eval-harness-readyhai-eval)
- [GenAI evaluator (`readyhai eval-ai`)](#genai-evaluator-readyhai-eval-ai)
- [Agentic fixer (`readyhai fix`) and mutation testing (`readyhai mutate`)](#agentic-fixer-readyhai-fix-and-mutation-testing-readyhai-mutate)
- [MCP server & integrations](#mcp-server--integrations)
- [Settings system & RBAC](#settings-system--rbac)
- [Safety model](#safety-model)

Related deep dives: [docs/qa.md](../qa.md), [docs/eval.md](../eval.md),
[docs/api.md](../api.md), [docs/architecture.md](../architecture.md),
[docs/security-model.md](../security-model.md), [docs/configuration.md](../configuration.md).

---

## QA test suite (`readyhai qa`)

**What it does.** `readyhai qa` is a spec-driven, senior-QA engine (`src/qa/`) that runs
functional-verification campaigns against a live app and closes with a release recommendation.
Its areas:

- **API tests from OpenAPI** (`src/qa/api/`): positive, boundary (min/max ±1, enum and format
  edges), negative (missing required, wrong type, 1 MB string), inert-marker reflection probes,
  contract validation against a JSON-schema subset, error-leak detection (traceback signatures,
  SQLSTATE, `ORA-nnnnn`), pagination/idempotency probes and p95 latency limits — rules
  `qa.api.*` (`server_error`, `contract_violation`, `bola`, `error_leak`, `crash_on_input`, …).
  Writes use resources the run created itself or the synthetic id `999999`; harvested real ids
  are read-only. Everything the run creates is registered for cleanup the moment it exists, and
  leftovers are reported as LEAKED.
- **GraphQL fuzzer** (`src/qa/graphql.rs`): endpoint discovery, introspection availability,
  10-level circular/nested query DoS (`qa.graphql.deep_nesting_dos`, `qa.graphql.circular_dos`),
  field-level authorization audit (`qa.graphql.authz_missing` / `unauthorized_field`) and
  malformed-query robustness.
- **RBAC auth matrix** (roles in `roles.toml` with `allow`/`deny` globs): every operation replayed
  with no auth, an invalid token and each configured role (`qa.api.authz_missing`,
  `qa.api.privilege_escalation`), plus stateful BOLA chains where a second role replays reads and
  updates against the first role's resource (`qa.api.bola`, Critical).
- **k6 performance** (`src/qa/perf.rs`): 5 VUs / 60 s by default (hard cap 10 VUs / 120 s unless
  `allow_heavy`), aborts when `http_req_failed` exceeds `max_error_rate` (default 5 %); p95
  regression > 20 % against the stored baseline is `qa.perf.regression`.
- **Resilience / chaos** (`src/qa/resilience.rs`, Deep profile only): `docker pause` of
  allow-listed compose services for 30 s while health and API paths are probed; hang, missing
  degraded status, no recovery and lying health checks are rules `qa.resilience.*`. Unpause is
  guaranteed by a Drop guard and signal handlers.
- **UI QA & a11y** (`src/qa/ui.rs` + the Playwright runner): crawl with responsive viewports,
  axe-core a11y (`qa.ui.a11y`), Core Web Vitals, form-validation gaps, YAML journeys with
  self-healing locators, visual baselines and multi-persona synchronized sessions.
- **WSTG pentest probes** (`src/qa/pentest/`): benign-marker checks for sensitive files,
  dangerous methods, JWT tampering, injection/SSRF/redirect reflection, session hygiene, headers
  and cookies, CORS, rate limiting and API-logic swaps (`qa.pentest.*`). Safe by construction —
  no exploitation, no data access — and every rule maps to OWASP WSTG v4.1, API Top 10 2023 and
  ASVS v4.2 ids (`src/qa/wstg.rs`).
- **Test-design generation** (`src/qa/design/`): boundary-value analysis, equivalence
  partitions, greedy all-pairs covering arrays and decision tables (`qa.design.boundary`,
  `equivalence`, `pairwise`, `decision-table`) plus an operation × technique **coverage matrix**
  (`qa.design.matrix`). Generated cases are planned, not executed: their matrix cells stay
  `Untested` until run elsewhere, so design gaps show up without fabricated evidence.
- **Repo/release quality** (with `--repo`): coverage thresholds, untested route detection, test
  smells, runtime EOL, alembic migration up/down/up, licence deny list (`qa.suite.*`,
  `qa.release.*`).
- **Recommendation** (`src/qa/recommend/`): **Go / Conditional Go / No-Go / Inconclusive**
  computed from blocking exit criteria (open P1s, new critical/high security findings, gate
  verdict, every failed case traced to a defect, sufficient executed evidence) — never chosen by
  an LLM. Exit codes: Go 0, Conditional Go 1, No-Go/Inconclusive 2.

**Why it matters.** It replaces the manual "someone writes Postman collections before release"
step with a reproducible, spec-driven campaign whose output is an auditable test summary: per-case
status, coverage matrix, defects with reproduction curls, exit criteria and a go/no-go a release
manager can sign. "Blocked is not Pass" and the executed-evidence criterion mean the report
distinguishes *verified good* from *never looked at*.

**How to use it.**

```bash
readyhai qa https://staging.example.com \
  --repo ./svc \
  --spec https://staging.example.com/openapi.json \
  --roles roles.toml --scope scope.toml \
  --profile standard \
  --format html,json,pdf,jira --out qa-report
echo $?   # 0 Go, 1 Conditional Go, 2 No-Go / Inconclusive, 3 error

readyhai roles init --spec openapi.json      # derive a roles.toml skeleton (no network)
readyhai baseline accept <run-id>            # promote spec/visual/perf baselines
```

Roles file (keep outside the repo, `chmod 600`; secrets are env-var *names* resolved at request
time): `[[role]]` entries with `auth = bearer|basic|header|cookie|none`, `token_env`,
`allow`/`deny` globs, optional Playwright `storage_state`. Profiles: `quick` (read-only),
`standard` (adds writes, forms, journeys, k6 — nonprod only), `deep` (adds resilience — nonprod
plus a `[hosts.resilience]` allow-list in `scope.toml`). Report formats include HTML, PDF,
Markdown, SARIF/JUnit/JSON and tracker exports (`jira`, `gitlab`, `testrail`, `xray`).

**Configuration.** No dedicated settings section; QA rides on the shared files: `scope.toml`
(`--scope` / `READYHAI_SCOPE`, per-host `[hosts.perf]` and `[hosts.resilience]` blocks),
`roles.toml` (`--roles` / `READYHAI_ROLES`), a journeys YAML/JSON (`--journeys`), `readyhai.toml`
(`--config`, licence deny list `[license] deny`), a policy (`--policy`) and operator
`settings.toml` (`--settings` / `READYHAI_SETTINGS`) for tool/plugin toggles. Full detail:
[docs/qa.md](../qa.md).

**Safety notes.** Writes, form submits, mutating journeys, k6 and fault injection only run on a
host the scope file treats as nonprod; a host listed `env = "prod"` gets read-only tests. Global
5 req/s throttle and a 2 000-request run cap. Created data is tagged and cleaned up; leftovers
are reported, never hidden. Evidence is redacted (tokens, `set-cookie`) and capped at 8 KB;
reproduction curls reference credentials only as `$RH_<ROLE>_TOKEN`. Tracker exports escape
markup and neutralise CSV formula injection.

---

## Super Agent (`readyhai agent`)

**What it does.** The agent is an autonomous **6-station Software Factory StateGraph**
(`src/agent/`, `src/agent/pipeline/`) over an HTTP target, combining LLM reasoning with
deterministic verification guardrails:

1. **Recon & Dynamic Directives** (`recon/`): TLS/header/cookie fingerprinting; the LLM
   synthesises Rules of Engagement, canary tokens and focus areas (BOLA, IDOR, prompt injection)
   — `SynthesizedDirectives`.
2. **Surface Discovery** (`discover/`): same-host crawl, SPA/XHR detection, OpenAPI parse, record
   id harvesting, LLM semantic shadow-route inference (`discover/semantic.rs`).
3. **Intel (new in v3.8.0)** (`pipeline/intel.rs`): see below — sits between memory recall and
   planning.
4. **Planning & Attack DAG** (`plan/`): baseline + spec-driven cases (reusing the QA engine's
   `qa::api::synth`), deep-security attack generators (JWT tampering, BFLA, header ACL bypass,
   BOPLA/mass assignment, SSTI, blind SQLi, OAST-backed SSRF, TOCTOU bursts, GraphQL), and an
   Attack DAG with topological ordering and prerequisite guards (`plan/dag.rs`).
5. **Execution & ReAct** (`lead/`, `react.rs`): the plan is split into `auth`, `contract`,
   `state`, `ui` areas, each run by an area worker (`READYHAI_AGENT_WORKERS`, default 4) in
   concurrent waves under one shared budget, rate limit and cancel flag, then a deterministic
   wave 2 follows up. The closed-loop OODA ReAct controller watches responses for anomalies
   (500 stack traces, 403 leaks, 422 schema errors), formulates mutation hypotheses and triggers
   bounded branching probe waves with oscillation damping.
6. **Verification** (`verify/`): every FAIL is independently replayed up to *k* times
   (`READYHAI_VERIFY_K`, default 2, max 5, `0` disables) — pass^k. A Contextual Taint Juror
   inspects source-to-sink reflection to drop false positives and attaches unified-diff
   remediation patches to confirmed defects. A failure that does not reproduce becomes
   INCONCLUSIVE, not a defect.
7. **Triage → Evidence Ledger → Gate** (`triage/`, `ledger/`, `pipeline/gate.rs`): one typed
   oracle (`oracle/`) judges every observation — no LLM input is consulted. The **Evidence
   Ledger** scores four weighted pillars (`value` 30, `authority` 30, `safety` 25, `evidence` 15)
   over a technique-coverage matrix, each pillar only scored at ≥ 50 % confidence, and emits the
   gate verdict `GO | CONDITIONAL_GO | NO_GO | NOT_EVALUATED` plus a `SoftwareFactoryAttestation`
   (release-readiness score 0–100, OWASP ASVS V2–V14 breakdown, SHA-256 seal). Everything the run
   created is torn down and read back on confirmed-nonprod targets (`cleanup.json`, leftovers
   listed).

### The v3.8.0 Intel stage

`pipeline/intel.rs` runs after memory recall and before the planner so the agent no longer plans
blind on a target it has already probed. It gathers four cheap sources into one **advisory**
bundle:

1. **Vulns DB history** — the host's `open` rows with their `verification` stamps, read only when
   `[vulndb] enabled` (capped at 25 rows).
2. **Up-front safe re-verification** — when `[exploits] enabled` **and** the run is not a
   dry-run, the v3.7 verification templates replay over the host's open rows within the
   `max_probes` budget, every URL through the ordinary scope egress guard with `intrusive = true`.
3. **Passive posture** — URL/host facts from the scope and `src/network` helpers; no active
   probing of its own.
4. **Tooling availability** — Docker daemon, tool-lock entries and plugged packs present, so the
   planner does not schedule what the machine cannot run today.

The result lands in the agent memory's `PlanHints` as `known_open` + `reproduced`, so the planner
re-tests verified/open weaknesses first (**reproduced > open > regression** order). After Defect
Triage the run **records its own triaged findings back** into the same Vulns DB via
`vulndb::record_run` (again gated on `[vulndb] enabled`). Invariants: intel only *reorders* the
plan — it never creates, upgrades or changes a verdict; a dry run sends **zero probes** and
**records nothing**; a guard refusal becomes an honest `inconclusive`, never a bypassed probe;
a broken settings file hard-errors the run.

**Memory across runs.** `<data>/memory/<target-key>.json` remembers known defects by fingerprint,
flaky case classes and coverage — written only from deterministic results, never from LLM text.
Each report carries "Since last run": new / still open / fixed / regressed / not re-tested /
known flaky / accepted. `readyhai agent-memory accept <target> <fp> --reason … --expires …` is
the one memory input that can move a gate, and only because an operator asked; it is listed in
every report until the expiry. A corrupt or hand-edited memory file is moved aside
(`<key>.json.corrupt-<run>`), never trusted.

**White-box mode.** `--repo DIR --diff-base REF` maps `git diff REF...HEAD` to changed operations
(that diff's operations get the full case set, planned first), and the Tree-sitter AST bridge
(`whitebox.rs`, `src/code_audit.rs`) inventories hidden handlers and annotates live defects with
`file:line handler` source linkage.

**Why it matters.** It compresses a manual adversarial QA cycle — recon, enumeration, attack
Ideas, exploitation attempts, re-verification, triage, evidence collection, release sign-off —
into one auditable run whose every claim cites a stored request/response evidence file. The
verifier + ledger design is what makes autonomous findings trustworthy enough to gate a release.

**How to use it.**

```bash
readyhai agent https://staging.example.com --spec https://staging.example.com/openapi.json \
  --scope scope.toml --max-steps 25                    # exit 0 GO / 1 COND_GO / 2 NO_GO
readyhai agent https://staging.example.com --dry-run   # plan only: zero packets
readyhai agent https://staging.example.com --spec $SPEC --repo ./svc --diff-base origin/main
readyhai agent-memory show https://staging.example.com
```

Over REST (`readyhai serve`, full details in [docs/api.md](../api.md)):

```bash
H="Authorization: Bearer $READYHAI_TOKEN"
curl -s -H "$H" -X POST http://127.0.0.1:8080/api/agent/run \
  -H 'Content-Type: application/json' \
  -d '{"target":"https://staging.example.com","profile":"standard","max_steps":25,
       "custom_instructions":"focus on authz and boundary validation"}'
curl -s -H "$H" "http://127.0.0.1:8080/api/agent/runs"                     # history, incl. running
curl -s -H "$H" -X POST "http://127.0.0.1:8080/api/agent/runs/<id>/cancel" # stop at next step
curl -s -H "$H" -X POST "http://127.0.0.1:8080/api/agent/runs/<id>/approve" \
  -H 'Content-Type: application/json' -d '{"notes":"release 24.11"}'
curl -s -H "$H" "http://127.0.0.1:8080/api/agent/runs/<id>/report/html"
```

`POST /api/agent/run` is synchronous and returns the finished `AgentRunReport`; a run in progress
is visible in `GET /api/agent/runs` with `status: "running"` — its checkpoint is rewritten after
every stage, which is where UI progress and a cancel id come from (polling, not WebSocket). Other
routes: `/api/agent/discover`, `/api/agent/crawl`, `/api/agent/directives/synthesize`,
`/api/agent/status`, `/api/agent/retest`, `/api/agent/memory` (GET/DELETE) and
`/api/agent/memory/accept`.

**Agent Studio** (the Next.js UI on port 3000, API on 8080) is the same surface: a command center
(target, spec, directives, profile, steps, model tier, reasoning budget), the six-stage pipeline
stepper, and a workspace with Scenarios/inspector (reproduction cURL with in-place retest),
Discovered routes, Evidence ledger, Threat triage, Runs history and the Release-gate sign-off
card. It shows only what the backend reported — a missing verdict renders "not evaluated", never
a default. Launch both with `docker compose up -d` or
`readyhai serve --bind 127.0.0.1:8080` + `cd frontend && npm run dev`.

**Configuration.** The LLM is optional (`READYHAI_LLM_URL`, `READYHAI_LLM_API_KEY`,
`READYHAI_LLM_MODEL`; without it the run is deterministic and says so). Run budget (`budget.rs`):
600 requests, 900 s wall clock, 10 req/s per host, 20 LLM calls, steps clamped 1..=50 —
override via `READYHAI_AGENT_MAX_STEPS` / `_MAX_REQUESTS` / `_MAX_SECONDS` / `_RATE_PER_HOST` /
`_MAX_LLM_CALLS`. Kill switches and toggles: `READYHAI_AGENT_WORKERS` (default 4, max 8),
`READYHAI_VERIFY_K`, `READYHAI_AGENT_MEMORY=off` (stateless CI), `READYHAI_OAST_BIND` /
`READYHAI_OAST_URL`. Reports land under `<data>/agent-runs/<run-id>/`
(`report.json`, `evidence/`, `cleanup.json`, HTML/MD/SARIF/JUnit). The Intel stage reads operator
`READYHAI_SETTINGS` (else `<data>/settings.toml`); it adds no new keys of its own.

**Safety notes.** A host listed `env = "prod"` is refused outright (intrusive egress guard, even
for a dry run); internal hosts must be listed in `scope.toml`. Test credentials come only from
`RH_<ROLE>_TOKEN` env vars, are attached only to the exact target origin over a
certificate-validating client, and never follow redirects; they appear in reproduction commands
only as `${RH_<ROLE>_TOKEN}`. Target text is fenced and neutralised before any prompt
(`<target_untrusted_content>`), and memory never enters a prompt. Cancel is honoured between
steps and the run still triages and tears down. MCP swarms are dry runs unless the operator sets
`READYHAI_MCP_ALLOW_WRITES=1` and the target is nonprod.

---

## Exploitation verification (`readyhai exploits`)

**What it does.** Shipped in v3.7.0 (`src/exploits/`), this engine turns a *reported* Vulns DB
finding into a *reproduced* one with safe, deterministic re-checks. A hand-reviewed catalogue of
six templates (families `exposure`, `crypto`, `config`) auto-selects by keyword from a row's own
kind + rule + title:

| Template | Family | Oracle |
|---|---|---|
| `http.env-file-read` | exposure | `GET {origin}/.env` — `verified` only on a 200 with a real `KEY=value` secret shape; an HTML rewrite is `not_reproducible` |
| `http.git-dir-listing` | exposure | `GET {origin}/.git/HEAD` — the exact git ref line is the proof; no other repo files fetched |
| `http.backup-file-read` | exposure | GETs the single artifact URL the finding itself names, inspects in memory |
| `http.admin-panel-open` | exposure | the reported path answers an admin-shaped 200 — two markers required, one is coincidence |
| `http.weak-tls-live` | crypto | confirms the host is alive, then honestly reports `inconclusive`: the local rustls floor is TLS 1.2, so a deprecated handshake cannot be proven in-process and no fake `verified` is minted |
| `http.server-status-probe` | config | baseline reachability; never auto-matched, `inconclusive` by construction |

Verdicts stamped on the vulndb row: `verified` (the oracle passed just now),
`not_reproducible`, `inconclusive` (couldn't prove either way), `skipped` (budget, no match,
not a URL) — plus `unverified` as the absence of a probe. Each stamp carries `verified_by`
(template id) and `verified_at`. **A verification never changes the triage `status`** — that is
the operator's decision.

**Why it matters.** Scanners over- and under-report with time; before acting on (or accepting) a
recorded finding you want to know whether the exposure still exists *right now*, with evidence.
The honest four-way verdict design means "we couldn't prove it" is never laundered into a green
or red stamp, which keeps the stamp trustworthy enough to feed the agent's Intel stage.

**How to use it.**

```bash
readyhai exploits list            # the catalogue: zero settings reads, zero network
readyhai exploits run 4f2a91c7d3 b10c99aa22          # refuses until [exploits] enabled=true
readyhai exploits run <fp> --json
```

```bash
H="Authorization: Bearer $READYHAI_TOKEN"
curl -s -H "$H" http://127.0.0.1:8080/api/exploits/templates
# {"count":6,"templates":[{id,family,applies_keywords,description,…}]}
curl -s -H "$H" -X POST http://127.0.0.1:8080/api/exploits/run \
  -H 'Content-Type: application/json' -d '{"fingerprints":["4f2a91c7d3"]}'
# {"executed":n,"results":[{fingerprint,template,verdict,reason,evidence,verified_at}]}
# 400 empty or >50 fingerprints; 409 while [exploits] enabled = false
```

In the UI, the **Vulns** view shows a per-row verification badge and a **Verify** button; the
**Settings** view has an Exploitation card (enable toggle + `max_probes`).

**Configuration.** `settings.toml` (verified against `src/settings.rs`):

```toml
[exploits]
enabled = false     # default; never defaults true. CLI refuses, REST answers 409 while false
max_probes = 25     # template executions per run, validated 1..=100
```

Rows past the probe budget are reported `skipped` with that reason — never silently dropped. At
most 50 fingerprints per run. The CLI, the pipeline Intel stage and `serve` all resolve the same
file: `READYHAI_SETTINGS`, else `<data>/settings.toml` (the copy the Settings UI writes).

**Safety notes.** Strictly opt-in at three layers: operator settings (`409`/refusal until
enabled), RBAC (`POST /api/exploits/run` is fail-closed **Admin**), and scope — every URL a run
would request passes `scope::egress_guard` with `intrusive = true` in a pre-flight, so prod-tagged
and unresolvable hosts are refused and one refusal fails the whole run. The safe-template policy:
one or two read-only GETs per template, only the finding's own resource or its canonical origin's
`/.env` / `/.git/HEAD`, zero payloads and write verbs, zero-redirect client with a hard timeout,
64 KiB body cap inspected in memory, evidence a ≤ 120-char excerpt with control characters
crushed and every assignment-shaped token masked to `KEY=[redacted]`.

---

## Vulnerability database (`readyhai vulns`)

**What it does.** Shipped in v3.6.0 (`src/vulndb/`), one local JSONL file
(`<data>/vulns/vulns.jsonl`, or `[vulndb] path`) remembers every warn/fail finding from every
scan — CLI or `serve`, static or agent — across all targets. One row per
(`target`, `kind`, `rule`, `resource`), keyed by a 24-hex-char **fingerprint** (SHA-256 over the
null-separated identity parts); re-observation bumps `occurrences` and `last_seen` instead of
duplicating. Rows carry `status` (`open | accepted | forgotten`) and since v3.7 the verification
stamp described above. Triage is durable: `accepted`/`forgotten` survive re-scans, and an
**acceptance resets to `open` when the severity changes** — a High you accepted that came back
Critical is a new decision. Suppressed findings are never recorded. Writes come from the scan
finalize path and from agent runs (v3.8.0); they are advisory — a DB problem is a report note,
never a failed scan. Reads are tolerant: one bad line is skipped with a warning.

**Why it matters.** It answers the operator question no per-run report can: *what has ReadyHai
seen on this machine, how often does it come back, and what did we already decide?* It is also
the backbone of the Intel stage — the agent plans against this history and feeds it back, so
scan, CLI, UI and agent share one triaged picture.

**How to use it.**

```bash
readyhai vulns                                  # open findings across all targets (table)
readyhai vulns --json
readyhai vulns --status accepted --target https://staging.example.com
readyhai vulns --all                            # include accepted + forgotten
readyhai vulns accept 4f2a91c7d3                # unique 6+ char prefix is enough
readyhai vulns forget 4f2a91c7d3
```

```bash
H="Authorization: Bearer $READYHAI_TOKEN"
curl -s -H "$H" 'http://127.0.0.1:8080/api/vulns?status=open&severity=critical&verification=unverified'
# {"count":n,"vulns":[{fingerprint,target,target_key,kind,rule,title,severity,resource,
#                     first_seen,last_seen,occurrences,status,message,
#                     verification,verified_by,verified_at}]}
curl -s -H "$H" -X POST http://127.0.0.1:8080/api/vulns/4f2a91c7d3 \
  -H 'Content-Type: application/json' -d '{"status":"accepted"}'   # Admin role when RBAC is on
```

The **Vulns** view (fifth top-level tab in the UI) renders the same rows with severity/target/
status filters, per-row Accept/Forget, the verification badge and Verify button. `readyhai vulns`
is read-only: no scan, no Docker, no network.

**Configuration.**

```toml
[vulndb]
enabled = true    # default true; false stops recording, existing rows keep working
# path = "/var/lib/readyhai/vulns.jsonl"   # default <data>/vulns/vulns.jsonl; empty is rejected
```

Both fields are editable through `PUT /api/settings` (an absent `vulndb` keeps stored values;
`path: null` clears the override) and shown on the Settings UI's database card.

**Safety notes.** File is capped at 10 MB — a rewrite beyond the cap is refused rather than
performed behind the operator's back. Recording never changes a verdict or exit code. The file
lives in the data dir (treat it like the rest of `<data>`); row text is capped at 300 chars.
Triage writes over REST need the admin role when RBAC is on (fail-closed classification).
JSONL files written before v3.7 load unchanged (rows read as `unverified`).

---

## Network lab & WireGuard audit

**What it does.** Two related but separate capabilities:

- **Network lab** (`src/network/`, REST `/api/network/*`, UI tab): flakiness and
  intermittent-failure diagnostics. `POST /api/network/regress` runs N iterations (default 10,
  clamped 1–100) in separate private sessions with throttling presets (`unthrottled`, `fast_3g`,
  `slow_3g`, `flaky`, `custom`) and classifies the outcome (`STABLE`, `TIMEOUT`,
  `5XX_FLAPPING`, `CONNECTION_RESET`, `HTTP_ERRORS`, `HIGH_JITTER`) with a reproduction cURL.
  `POST /api/network/curl` runs hardened curl (`-q --proto =http,https`, `--` before the URL,
  capped output) with stage timings. `POST /api/network/deep-audit` walks six pillars:
  dual-stack, same-host sub-resources, protocol matrix, TLS (real `openssl s_client` handshake),
  CORS preflight and an MTU black-hole sweep. `POST /api/network/multi-region` measures one
  vantage point and says so (`not_measured_regions` lists what it did not probe — there are no
  remote probe nodes). `POST /api/network/export-har` converts a regress report to HAR 1.2
  (no egress). `GET /api/network/requester-ip` reports the server's egress IP for allow-lists.
  A **PR-gate** helper (`POST /api/github/pr-comment`) builds a PR comment from data you supply;
  anything missing renders "not evaluated", never a default. **There is no `readyhai network`
  CLI subcommand** — the lab is served by `readyhai serve` and driven from the UI or curl.
- **WireGuard config audit** (v3.6.0): built-in repo check `wireguard` (the 46th check, quick
  profile, `src/rules/wireguard.rs`) audits wg-quick `*.conf` / `*.wgconfig` files during
  `readyhai scan` — committed `PrivateKey`/`PresharedKey` values (high, length-reported, never
  echoed), the same key reused across peers/files, `AllowedIPs = 0.0.0.0/0|::/0` default-route
  overreach, non-32-byte/placeholder key material, duplicate `ListenPort`s, `[Interface]` without
  `Address=`, and NAT peers (`Endpoint=`) without `PersistentKeepalive`. Non-WireGuard `.conf`
  files (nginx et al.) are detected by content and ignored; findings flow through baselines,
  suppressions and SARIF like any other check.

**Why it matters.** "It works sometimes" is a class of production defect no scanner sees; the lab
turns it into a root-cause category with evidence. WireGuard configs are routinely committed with
live private keys, and one reused key collapses per-peer isolation — both are exactly the kind of
repo-resident risk a built-in, dependency-free check should catch.

**How to use it.**

```bash
curl -s -H "$H" -X POST http://127.0.0.1:8080/api/network/regress \
  -H 'Content-Type: application/json' \
  -d '{"target":"https://staging.example.com/health","iterations":20,"timeout_ms":5000,
       "separate_sessions":true,"throttle_profile":"flaky","delay_between_ms":50}'

readyhai scan ./infra                          # runs the wireguard check over the repo
```

**Configuration.** `READYHAI_SCOPE` governs every lab request through the egress guard. Numeric
fields are clamped, never trusted: `iterations` 1–100 (>25 counts as load → nonprod only),
`timeout_ms` 100–15 000, payload ≤ 256 KiB, a 120 s regress run budget. No dedicated settings
keys. Rule severities: [docs/configuration.md](../configuration.md#wireguard-config-audit-wireguard).

**Safety notes.** Read-only methods (GET/HEAD/OPTIONS) ≤ 25 iterations are the non-intrusive
default; anything else routes through the intrusive guard, so `env = "prod"` hosts are refused.
curl subprocesses pin `--proto =http,https`, run under hard timeouts, and everything unmeasurable
is reported as not measured rather than guessed. Certificate verification is deliberately off for
the HTTP probes (staging diagnosis) — the TLS pillar judges certificates separately.

---

## Eval harness (`readyhai eval`)

**What it does.** `readyhai eval` (`src/eval/`) scores ReadyHai's own QA engine and agent against
fixtures with **known, seeded defects** (`tests/fixtures/**`, suite definitions in
`tests/eval/*.toml`, 10 suites: `qa-api`, `qa-repo`, `agent-api`, `agent-diff`, `agent-memory`,
`agent-spa`, `agent-spa-clean`, `agent-spa-noauth`, `security-deep`, `whitebox-exploit`). Per
suite, over *k* runs, it measures **recall** (mean + worst run), precision, **false positives**,
**pass^k** (every run must reach the recall threshold — one lucky run does not count), verdict
stability, inconclusive rate and confidence (agent), request and time budgets, and optional
expected/forbidden verdicts and expected blockers (`auth_wall`, `out_of_scope`, …).

**Why it matters.** It is the regression gate for *detection logic*: a change that makes the
engine miss a seeded bug, invent a defect, or flip its verdict between runs fails CI. `known_gap`
expectations keep honest gaps on the page (and demand removal when closed) instead of hiding
them; `agent-spa-clean`/`-noauth` explicitly test that the agent does **not** invent failures and
reports missing evidence as NOT_EVALUATED with a named blocker.

**How to use it.** Needs `python3` (stdlib fixture servers) and `git` (the `agent-diff` suite);
no docker, no network, no LLM:

```bash
readyhai eval                        # all suites, k=2 → eval-report/{eval-report.json,md}
readyhai eval --suite qa-api --k 3   # exit 0 all thresholds met, 1 a miss, 3 harness error
READYHAI_EVAL_KEEP=1 readyhai eval --suite agent-spa   # keep per-run data dirs for diagnosis
```

CI: the `eval` job in `.github/workflows/ci.yml` runs
`cargo run --quiet -- eval --suite all --k 2 --out eval-report` after `test`, appends the markdown
to the job summary and uploads `eval-report/` as an artifact even on red runs.

**Configuration.** Suite files (`tests/eval/<suite>.toml`, unknown keys rejected): `[target]`
(server/spec/roles/repo + tokens), `[thresholds]` (`min_recall = 0.85`, `max_false_positives = 2`,
`pass_k`, `stable_verdict`, `max_requests`, `max_seconds`, `max_inconclusive_rate`), one
`[[expect]]` per seeded defect and `[[allow]]` for explainable extras. CLI flags: `--suite`,
`--k`, `--out`, `--dir`.

**Safety notes.** Each run is isolated: its own `READYHAI_DATA`, a generated loopback-only
`scope.toml`, a fresh fixture server, `READYHAI_OFFLINE=1`, LLM/agent env unset, fake tokens only.
Do not loosen a threshold to make a run green — fix the detection or update the expectation with
a stated reason.

---

## GenAI evaluator (`readyhai eval-ai`)

**What it does.** `readyhai eval-ai` (`src/eval_ai/`) evaluates **GenAI applications** — RAG
pipelines, LLM outputs and agent tool trajectories — fully offline and deterministically
(tokenizer/NLP heuristics, no cloud LLM):

- **RAG triad**: *context relevance* (query coverage in retrieved chunks), *faithfulness /
  hallucination detection* (atomic-proposition extraction; unsupported entities and numbers are
  itemised with explanations), *answer relevance* (intent fulfilment; evasive answers penalised).
- **Trajectory evaluation**: tool-call JSON-schema conformance, cyclic-loop detection (repeated
  identical calls), and efficiency (minimal vs executed steps).
- **Red-teaming** (`--red-team`): prompt-injection/jailbreak signature scanning, credential-leak
  detection (`sk-`, `ghp_`, `AKIA`, private keys) and canary-token exfiltration checks.

**Why it matters.** Teams deploying LLM features have no cheap way to gate regressions in answer
grounding or tool behaviour. Running the same deterministic checks ReadyHai applies to APIs gives
AI features the same kind of CI gate, air-gap-safe.

**How to use it.**

```bash
readyhai eval-ai --query "What is the capital of France?" \
  --context "Paris is the capital and largest city of France." \
  --response "Paris is the capital of France." --threshold 0.70

readyhai eval-ai --dataset dataset.json --red-team --trajectory trace.json --format markdown

curl -s -H "$H" -X POST http://127.0.0.1:8080/api/eval-ai -H 'Content-Type: application/json' \
  -d '{"query":"…","context":"…","response":"…","threshold":0.70,"red_team":true}'
# → {total_cases, passed_cases, composite_score, verdict PASS|WARN|FAIL, results[…]}
```

**Configuration.** `--dataset` (JSON array or JSONL of query/context/response/expected),
`--trajectory` (JSON steps file), `--expected` ground truth, `--threshold` (default 0.70),
`--format table|json|markdown`, `--out FILE`, `--red-team`. No `settings.toml` section.

**Safety notes.** Fully offline by design (`READYHAI_OFFLINE=1` compatible); it sends no network
traffic and stores only the report you request. Its verdicts are heuristic and deterministic —
they gate *regressions* against your own baselines, not absolute quality claims.

---

## Agentic fixer (`readyhai fix`) and mutation testing (`readyhai mutate`)

### `readyhai fix` — Agentic Fixer (`src/fix/`)

**What it does.** AST-grounded remediation for defects from a previous run or a live code audit:
pattern + Tree-sitter synthesis for auth guards, SQLi, path traversal, command injection, CORS
and secret handling; **sibling guard mining** (`mine_sibling_guards`) learns the repo's own
middleware convention so patches match the codebase; a **sandbox** auto-detects the test runner
(`cargo test`, `npm test`, `pytest`, `go test`) and rolls back if a patch breaks anything; output
includes a unified diff, rationale, and completed PR-description markdown (`--format markdown`).

**How to use it.**

```bash
readyhai fix --repo ./svc --run 20261126-1015-0f3a --dry-run     # preview only
readyhai fix --repo ./svc --defect security.taint.sql_injection --branch fix/sqli-42
# REST: curl -H "$H" -X POST http://127.0.0.1:8080/api/fix -d '{"repo":".","defect":"…","dry_run":true}'
```

**Configuration.** `--repo` (serve/MCP: confined to `READYHAI_ALLOWED_ROOTS`), `--defect`,
`--run` (loads `run.json` / `evidence_ledger.json`), `--dry-run`, `--verify` (default `true`;
`--verify false` skips test verification), `--branch NAME`, `--format text|json|markdown`.

**Safety notes.** Local-only git policy: `--branch` creates a branch and commit **and never
pushes**; PR output is markdown for you to review. Patches are `VerificationFailed`/`RolledBack`
statuses if the suite disagrees — an unverified patch is never reported as applied.

### `readyhai mutate` — mutation testing (`src/mutate.rs`)

**What it does.** "Tests the tests": injects targeted semantic mutants (comparison inversion,
boolean flip, **auth-guard bypass** `is_admin = true`, return inversion, arithmetic swap), runs
the project's tests per mutant, and reports Killed / Survived / Timed-out with a
mutation score, an oracle-quality grade and, for every survived mutant, the concrete assertion
suggested to kill it.

**How to use it.**

```bash
readyhai mutate --repo . --max-mutants 20 --timeout-secs 30
readyhai mutate --repo . --target src/auth --format markdown
# REST: curl -H "$H" -X POST http://127.0.0.1:8080/api/mutate -d '{"repo":".","max_mutants":10}'
```

**Configuration.** `--repo`, `--target`, `--max-mutants` (default 20), `--timeout-secs` (per
mutant, default 30), `--format text|json|markdown`.

**Safety notes.** Mutants are applied and reverted under bounded, timed test runs; a surviving
mutant is a report finding, not a code change.

---

## MCP server & integrations

**What it does.** `readyhai mcp` serves the **Model Context Protocol** over stdio (newline
JSON-RPC 2.0, `src/mcp/`), giving Claude Code or any MCP client eight tools: `readyhai_scan`,
`readyhai_checks`, `readyhai_run`, `readyhai_findings`, plus the async swarm trio
`readyhai_agent_swarm` (returns a `run_id` immediately; at most 2 concurrent swarms),
`readyhai_agent_status` and `readyhai_agent_cancel`, and `readyhai_agent_discover`. Client
disconnect cancels every run it started. Integration surface beyond MCP: the REST API (all of the
above), SVG badges (`/api/badges/{gate,ledger,network}`), the PR-comment route, and the
`[integrations]` settings layer (next section) that gates pinned container tools and plugin
packs — including the 19 digest-pinned official packs (`plugins/official/`: reconnaissance
`httpx`/`dnsx`/`subfinder`/`gau`/`katana`/`naabu`/`nmap`/`rustscan`/`feroxbuster`, active checks
`nikto`/`sqlmap`/`testssl`/`tlsx`, supply-chain `grype`/`osv-scanner`/`conftest`, and Kubernetes
`kube-linter`/`kubescape`/`kube-score`) whose images are auto-provisioned on the go.

**Why it matters.** It lets a coding agent point a governed scanner and a verified QA swarm at a
codebase or URL and read back structured findings — with the human's safety policy (roots, scope,
dry-run) enforced server-side rather than trusted to the model.

**How to use it.**

```bash
claude mcp add readyhai -e READYHAI_ALLOWED_ROOTS=/path/to/code -- readyhai mcp
# or {"mcpServers":{"readyhai":{"command":"readyhai","args":["mcp"],
#     "env":{"READYHAI_ALLOWED_ROOTS":"/path/to/code","READYHAI_SCOPE":"/cfg/scope.toml"}}}}
```

**Configuration.** `READYHAI_ALLOWED_ROOTS` (repo/APK/openapi paths must be under it; MCP
defaults to the process CWD), `READYHAI_SCOPE`, `READYHAI_DATA`, `READYHAI_PLUGINS`,
`READYHAI_MCP_ALLOW_DEEP=1` (permit `readyhai_scan profile:"deep"`),
`READYHAI_MCP_ALLOW_WRITES=1` (permit `dry_run:false` swarms; target must still be nonprod).
Full tool schemas: [docs/api.md](../api.md#mcp-server).

**Safety notes.** Swarms are **dry runs by default** and a model cannot opt itself into writes
(unknown arguments are errors). There are deliberately **no write tools for judgment** — no
baseline-accept, suppression or policy tool: a prompt-injected model can scan and read, never
waive. Every result is prefixed with the untrusted-data banner and truncated. The protocol stream
is private (fd 0 → `/dev/null`, fd 1 → stderr) so no child process can corrupt or swallow
JSON-RPC. Agent tools use the intrusive guard even for dry runs, so `env = "prod"` hosts are
refused outright.

---

## Settings system & RBAC

**What it does.** The operator settings layer (`src/settings.rs`, operator-owned TOML) decides
what may run, per check and per feature — and **a scanned repo's own settings file is never
read**. Precedence: `--settings <file>` > `READYHAI_SETTINGS` > defaults (all `auto`); for
`exploits run`, the agent pipeline and `serve` the fallback is also `<data>/settings.toml`, the
copy the Settings UI writes. A file that fails to parse or validate is a **hard error** — a
silently-ignored settings file must never flip an integration the operator meant to keep off.

Verified keys (against `settings.example.toml` / `src/settings.rs`):

```toml
[integrations]
tools = "auto"      # pinned-container tool checks — auto | on | off
plugins = "auto"    # plugin.* checks from the plugins dir — auto | on | off
intrusive = "auto"  # kill switch for the intrusive class: auto | off ONLY ("on" is rejected)

[[toggle]]          # per-check rules, file order; exact id > LAST matching glob > category > auto
id = "plugin.crowdstrike.*"
enabled = "off"

[vulndb]
enabled = true      # default true — scans record warn/fail findings
# path = "…"        # default <data>/vulns/vulns.jsonl

[exploits]
enabled = false     # default false — safe re-verification (CLI + REST + Intel stage)
max_probes = 25     # validated 1..=100
```

`off` renders as a visible `Skipped` with a reason — a toggle never hides coverage. `on` protects
a check only from *settings*; the profile, scope-nonprod, `--no-tools` and Docker gates keep
their authority. `integrations.intrusive` can only narrow, never force.

**REST & UI.** `GET /api/settings` returns `{path, exists, editable, version, effective,
override_count, shadowing_env}` where `effective` carries `integrations`, `toggle`, `vulndb` and
`exploits`; any authenticated role may read. `PUT /api/settings` (Admin when RBAC is on) saves
atomically to `<data>/settings.toml` with an optimistic-concurrency `version` (`409` stale,
`400` invalid e.g. `intrusive:"on"` or empty `vulndb.path`; absent/partial `vulndb`/`exploits`
objects carry stored values over). `DELETE /api/settings` resets the data-dir overrides.
`GET /api/settings/checks` lists every check with its effective decision and
`decided_by: default|settings|integration`. The **Settings** view exposes all of it: tri-state
Tools/Plugins/Intrusive controls, a searchable per-check toggle table, the Vulnerability-database
card, the Exploitation card and a read-only RBAC keyring panel.

**RBAC (togglable, `serve`).** Point `READYHAI_RBAC_FILE` at an `rbac.toml`
(template `rbac.example.toml`); the toggle resolves `READYHAI_RBAC=on|off|auto` >
`[rbac] enabled` > auto (ON when the file exists with keys). Each bearer token maps to a keyring
entry (`key` or `key_sha256`, hashed and compared in constant time) and a role: `viewer`
(reads) ⊂ `operator` (+ trigger scans/agent runs/network lab/evals) ⊂ `admin` (+ approve/reject,
memory-accept, fix, deletes, settings, vuln triage, exploit runs). **Unclassified write routes
fail closed as Admin-only.** Wrong role → `403` naming the required role (distinct from `401`).
`READYHAI_TOKEN` stays break-glass admin unless `READYHAI_RBAC_BOOT_ADMIN=0`.

**How to use it.**

```bash
READYHAI_SETTINGS=settings.toml readyhai scan ./svc
READYHAI_RBAC_FILE=rbac.toml readyhai serve --bind 127.0.0.1:8080
curl -s -H "$H" http://127.0.0.1:8080/api/settings/checks | jq '.[].decided_by' | sort -u
```

**Safety notes.** Settings are operator-side only; untrusted targets can never relax them. Every
gate layer keeps its own authority (settings `on` cannot bypass profile/scope/Docker). RBAC boot
refuses `READYHAI_RBAC=on` with no usable keys, and key material is never echoed by
`GET /api/rbac` (names, roles and fingerprint prefixes only).

---

## Safety model

Three principles bind the whole agent/QA/intelligence stack together, and each feature above
inherits rather than reinvents them. **Deterministic primacy:** one typed oracle plus the
verifier's pass^k replay compute every verdict; LLM output only adds validated cases, prose and
advisory intel (the Intel stage reorders the plan — `verified`/`open` first — and never creates
or changes a finding); memory is written only from deterministic results; the Evidence Ledger's
gate and the QA recommendation are computed, never chosen by a model. **Opt-in intrusive
capability:** everything that sends more traffic than a read is separately authorised —
`integrations.intrusive` accepts only `auto|off` (settings can silence intrusive checks but can
never force one), `[exploits] enabled` defaults to `false` (CLI refuses, REST answers 409, the
agent's Intel stage skips its probe pass), resilience/fault injection needs the deep profile plus
a per-host allow-list, MCP swarms are dry runs until `READYHAI_MCP_ALLOW_WRITES=1`, and probe
budgets (`max_probes`, run request caps, k6 VU ceilings) bound every campaign. **Prod refusal
& redaction:** one egress guard (`scope::egress_guard`) puts every target URL through the rules
of engagement — internal hosts must be listed, a host tagged `env = "prod"` is read-only for QA
and outright refused for agent runs, exploit verification and network-lab load (`intrusive =
true`), and a configured-but-unusable scope file fails closed everywhere; credentials exist only
as `RH_*` env references bound to the exact target origin and never enter reports, evidence,
memory or prompts; evidence excerpts mask assignment-shaped tokens (`KEY=[redacted]`), WireGuard
key material is length-reported only, and all target-derived text is redacted, fenced and treated
as untrusted before any renderer or LLM sees it.
