# Senior-QA guide (`readyhai qa`)

Increment 2 (2026-10-25), accuracy pass 2026-10-29. Describes what the code in `src/qa/**` does today. Live-verified vs unit-only status is in [status-and-competition.md](status-and-competition.md).

```
readyhai qa <url> [--repo ./svc] [--spec openapi.json|URL] [--roles roles.toml] [--journeys journeys.yaml]
                  [--scope scope.toml] [--profile quick|standard|deep] [--policy P] [--config C] [--baseline B]
                  [--format html,json,pdf,md,jira,gitlab,testrail,xray] [--out DIR] [--no-tools] [--plugins DIR]
```

`--roles` also reads `READYHAI_ROLES`; `--scope` reads `READYHAI_SCOPE`. The URL must be listed in `scope.toml`. With `--repo`, the normal repo/image/readiness checks run in the same run, so one verdict covers security, readiness and functional QA.

## Pipeline

Plan (`plan.rs`: spec operations x roles, risk = impact x likelihood, request budget) -> Generate (`api/synth.rs`) -> Execute (API executor, Playwright runner, k6, compose fault injection, repo checks) -> Verify (contract, status, leak, persistence checks) -> Triage (`triage.rs`: dedupe by component and kind, group 5xx root causes by status + error-body fingerprint, severity = impact, priority = severity x exposure) -> Report (`recommend.rs`, `report.rs`).

Every `Defect` becomes exactly one `Finding` with rule `qa.<area>.<kind>`, so the gate, baseline, SARIF and JUnit work unchanged.

## Profiles

| Profile | QA content | Host requirement |
|---|---|---|
| `quick` | Read-only API tests (GET/HEAD/OPTIONS), contract, auth matrix reads, UI crawl + responsive + a11y + vitals, repo suite/release checks | any host in scope |
| `standard` | Adds API writes (stateful CRUD), UI forms, journeys, visual baselines, k6 smoke + baseline, migrations up/down/up | writes/forms/load only when the host is `env = "nonprod"` |
| `deep` | Adds resilience fault injection | nonprod + `[hosts.resilience]` allow-list |

## API testing (`src/qa/api/`, native Rust over reqwest)

Spec: OpenAPI 3.x JSON or YAML; local `$ref` only, ref depth <= 4, <= 500 operations. Unsupported operations are listed `untested`, never silently passed.

| Technique | What is sent | Rule(s) |
|---|---|---|
| positive | valid request from examples/defaults/synthesized values | `qa.api.server_error`, `qa.api.undocumented_status`, `qa.api.contract_violation` |
| boundary | min/max length and value +-1, enum edges, format edges (email, uuid, date) | `qa.api.validation_missing`, `qa.api.server_error` |
| negative | missing required, wrong type, null, extra property, 1 MB string, unicode | same |
| inert markers | harmless marker strings in body/query; detect reflection or 5xx, never exploit | `qa.api.reflection` |
| auth matrix | every operation with no auth, invalid token, each role; expectations from spec `security` + `allow`/`deny` globs in roles.toml | `qa.api.authz_missing`, `qa.api.privilege_escalation` |
| stateful CRUD | create -> read -> update -> delete -> read=404 by path templates; IDs from `Location`, `id` field; replay with another role | `qa.api.persistence_failure`, `qa.api.delete_not_effective`, `qa.api.bola`, `qa.api.idempotency` |
| contract | response status documented + body checked against JSON-schema subset (types, required, enum, formats); spec compared with the baseline spec for removed endpoints/fields and new required fields | `qa.api.contract_violation`, `qa.api.breaking_change` |
| error leak | error responses (status >= 400 only) whose body shows a stack-trace signature: Python `Traceback`, Java/Node/.NET frames with a source file, SQLSTATE, `ORA-nnnnn`, `Exception in thread`, a `stackTrace` key, server source paths with a file extension. HTML attribute values (`href="/home/..."`) and prose are ignored, so nav links on a 404 page are not a leak | `qa.api.error_leak` |
| malformed input vs crash | a timeout or connection reset on a non-positive case while the target answered before is a possible crash/hang (High; Critical when the target no longer answers afterwards). A target that never answered is Blocked, not a crash | `qa.api.crash_on_input` |
| pagination / idempotency | page values 0, -1, huge; PUT twice | `qa.api.validation_missing`, `qa.api.idempotency` |
| latency | p95 per operation (needs >= 2 samples) | `qa.api.slow_response` |

Rules (severity as coded): `authz_missing` High P1, `privilege_escalation` High P1, `bola` Critical P1, `server_error` High P2, `crash_on_input` High P2 (Critical P1 when the target stops answering), `delete_not_effective` High P2, `access_denied` Medium P2 (a role that roles.toml allows gets 401/403), `error_leak` Medium P2, `persistence_failure` Medium P2, `contract_violation` Medium P3, `validation_missing` Medium P3, `breaking_change` Medium P3, `reflection` Low P3, `slow_response` Low P3 (p95 > 1000 ms), `idempotency` Low P3, `positive_failed` Low P4 (generated valid input rejected), `undocumented_status` Low P4.

### Execution order, budget and coverage

- **Order.** The checks run `qa.api.authz` (P1 cases), then `qa.api.functional`, then `qa.api.stateful`, so the shared request budget (2000) cannot starve the auth matrix. Inside each check operations run by plan risk (`qa.plan`: impact x likelihood), highest first; the plan budget of an operation caps its generated cases (the cases beyond it are listed under *untested*). The auth matrix stops at 60% of the budget and the functional check keeps 10% (max 200) for the stateful lifecycle on nonprod standard+ runs.
- **Budget exhaustion.** An operation the budget did not reach is still planned: its cases are recorded as Skipped ("request budget exhausted"), its coverage cell is Untested and it is listed under *untested*. The "cases executed" criterion therefore drops instead of the run looking complete. Cleanup DELETEs of data this run created may exceed the cap.
- **Blocked is not Pass.** A response that says nothing about the case is Blocked: 401/403 (no authorized role), 404 on a path parameter without a harvested id, 429, an unfollowed redirect, a transport error. This applies to boundary/negative/marker cases too, so a 401 is never a "validation pass". The `functional` cell of an operation is Pass only when at least one case passed; with every case skipped or blocked it is Untested.
- **Failures have defects.** A failed case always carries a defect: `positive_failed` for a rejected valid request, `access_denied` for an allowed role that is denied, plus the specific rules above. The recommendation additionally blocks on any failed case without a defect (see exit criteria).
- **Flaky detection.** A failed read-only case (GET functional cases, pagination probes, GET auth-matrix cases) is re-run up to 2 times. The result records `attempts` (1 + re-runs); the defect records `reproduced` N of M. All attempts failing = Fail, otherwise Flaky (an intermittent failure is still a defect). Writes and the stateful lifecycle are never repeated.
- **Response bodies.** Up to 1 MiB of each response is read and JSON is parsed from the whole body (schema validation, id harvesting); only the stored/evidence copy is cut to 8 KB. Larger bodies are not parsed. `{data:{...}}`-style wrappers (and JSON:API `attributes`) are looked through for ids and the stateful echo/persistence checks.
- **Generated values** are capped at 64 KB per string whatever `minLength`/`maxLength` the spec claims.
- **Spec baselines.** The spec snapshot (`<key>.spec-full.json`, breaking changes) and operation list (`<key>.spec.json`, "new since baseline" risk) are seeded on the first run; every run also stages its own copy under `<run>/artifacts/qa-baseline/`, and `baseline accept <run>` promotes it.

Each defect carries steps to reproduce as a curl command; tokens appear only as `$RH_<ROLE>_TOKEN`. Evidence bodies are redacted and capped at 8 KB.

Note on AI execution: In `readyhai qa`, AI-proposed cases are recorded as advisory report notes. For fully autonomous end-to-end synthesis, execution, triage, and Evidence Ledger gating of AI test scenarios, use `readyhai agent <target>` (see [usage.md](usage.md)). Schemathesis remains an optional separate fuzzer (see [checks.md](checks.md)).

## UI testing (`src/qa/ui.rs` + `runners/playwright/qa.mjs`)

Needs the runner image (not built by CI; build it yourself): `docker build -t readyhai/playwright-runner:local runners/playwright`. Without Docker or the image the check is skipped with that hint.

| Mode | Profile | Behaviour | Rule |
|---|---|---|---|
| crawl | quick | same-origin crawl, max 20 pages | web.* findings |
| responsive | quick | viewports 375x812, 768x1024, 1366x768: horizontal overflow, clipped elements, small tap targets | `qa.ui.responsive_overflow` (Low) |
| a11y | quick | axe-core bundled in the image (offline). critical/serious -> Medium, others Low | `qa.ui.a11y` |
| vitals | quick | LCP, CLS, long tasks, page weight, request count | `qa.ui.slow_page` (LCP Medium, CLS Low) |
| forms | standard + nonprod | fills each field with boundary/invalid values and submits; skips cross-origin and destructive-looking actions (logout, delete, pay, checkout...). Accepting invalid input without a validation message is a gap | `qa.ui.validation_gap` (Medium) |
| journeys | standard | steps per role using `storageState`; read-only journeys run anywhere, mutating ones are skipped unless nonprod. Trace/video on failure | `qa.ui.journey_failed` (High) |
| visual | standard | screenshots per page and viewport vs stored PNGs (pixelmatch); > 0.5% pixels changed needs review | `qa.ui.visual_change` (Low) |

Visual baselines live in `<data>/baselines/<target-key>/visual/`. The first run stores the screenshots as the baseline (and records the visual case as Skipped / coverage Untested: nothing was compared); the next run compares. `baseline accept <run>` promotes that run's screenshots (`<run>/artifacts/ui/shots`, diff images excluded) to the new baseline.

a11y defects are one per (axe rule, page) and visual defects one per (page, viewport): a new violation on a new page, or a new viewport regression, is a new fingerprint and gates even when the rule already had an accepted finding elsewhere.

### Journeys file (YAML or JSON; a list, or `{journeys: [...]}`)

```yaml
- name: checkout-smoke
  roles: [alice]            # optional; default = all roles in roles.toml (or "anon")
  steps:
    - goto: /login
    - fill: "#email"
      value: "alice@example.test"
    - fill: "#password"
      value: "from-your-test-account"
    - click: "button[type=submit]"
    - expect_url: /dashboard
    - expect_text: "Welcome"
    - select: "#country"
      value: "IN"
    - press: Enter
    - wait: 500              # ms (max 10 s), or a selector
```

Step keys: `goto` (same-origin only), `click`, `fill`, `select`, `press`, `expect_text`, `expect_url`, `wait`; `selector` and `value` are alternatives to the inline form. Do not put real secrets in the journeys file; prefer `storageState` from the role.

## Performance (`src/qa/perf.rs`, k6 container)

Standard profile, nonprod only. Hits up to 8 GET endpoints without path parameters or required query/header inputs (health endpoints included) per role-persona. Spec paths are prefixed with the `servers[0].url` base path. Only 2xx/3xx count as success: a 401/403/404 (broken credentials, wrong base path) is a failed request. The anonymous persona only requests endpoints the spec declares public; secured endpoints need a role credential, and a run where nothing is reachable is skipped with a note instead of reporting 100% errors.

| Limit | Value |
|---|---|
| Default | 5 VUs, 60 s |
| Hard cap | 10 VUs, 120 s (unless `allow_heavy = true` in scope) |
| Abort | `http_req_failed` rate over 5% (`max_error_rate`, configurable) |

Override per host in `scope.toml`:

```toml
[[hosts]]
host = "app.nonprod.example"
env  = "nonprod"
[hosts.perf]
vus = 8
duration_secs = 90
max_error_rate = 0.05
allow_heavy = false
```

First run stores `<data>/baselines/<key>.perf.json`. Later runs compare p95 against it. The latest healthy result is kept as `<key>.perf.last.json`; `readyhai baseline accept <run-id>` promotes it to the new baseline.

| Rule | Severity | Trigger |
|---|---|---|
| `qa.perf.regression` | Medium | p95 more than 20% worse than baseline (ignores deltas under 20 ms) |
| `qa.perf.errors` | High | error rate over 1% (run aborted above the limit) |
| `qa.perf.slow` | Low | p95 above 1000 ms |

Credentials reach k6 only as container env, never in the script file.

## Resilience (`src/qa/resilience.rs`, deep profile)

Only for docker-compose targets on a nonprod host with an allow-list:

```toml
[hosts.resilience]
compose_project = "shop"
services = ["postgres", "redis"]      # max 4 used
```

A container is touched only if it carries both the compose project label and an allow-listed service label, and the lookup must match exactly one container. It is `docker pause`d for 30 s while the health endpoint (`/health`, `/healthz`, `/api/health`, `/ready`) and an API path are probed every 3 s; it is unpaused by a Drop guard even on panic or early return, and by a signal thread on SIGINT/SIGTERM/SIGHUP (verified live), then recovery is awaited up to 60 s.

| Rule | Severity |
|---|---|
| `qa.resilience.hang` (requests hang instead of failing fast) | High |
| `qa.resilience.no_degraded_status` (no 503/degraded response) | Medium |
| `qa.resilience.no_recovery` (does not recover within 60 s) | Critical |
| `qa.resilience.health_lies` (health stays 2xx while dependency is down) | Medium |

Status: decision logic is unit-tested; it has never been run against a live compose stack.

## Suite and release quality (`src/qa/suite.rs`, needs `--repo`)

| Check | What | Rule (severity) |
|---|---|---|
| `qa.suite.coverage` | reads Cobertura `coverage.xml`/`cobertura.xml`, `lcov.info`, `jacoco.xml` from the repo or from the `[test]` run; below 60% | `qa.suite.low_coverage` (Medium), `qa.suite.critical_uncovered` (Medium) |
| `qa.suite.routes` | regex-extracts FastAPI/Flask/Express/Spring routes and looks for tests referencing them; one defect per untested route | `qa.suite.untested_routes` (Medium) |
| `qa.suite.smells` | tests without asserts, skipped tests, sleeps; one defect per smell | `qa.suite.test_smells` (Low) |
| `qa.release.eol` | Dockerfile FROM + SBOM versions vs the endoflife snapshot (see [offline.md](offline.md)) | `qa.release.eol_runtime` (High past EOL, Medium within 180 days, Low when only the declared minimum) |
| `qa.release.migrations` | alembic up -> down -> up against an ephemeral Postgres 16 on a per-run network; needs a `[test]` image in readyhai.toml. Prisma and Flyway are detected but reported untested. Exit codes 125/126/127/137/143 (docker error, command not found in the image, OOM/kill) are tooling failures: the case is Blocked and the check Errored, never a migration defect | `qa.release.migration_failure` (High) |
| `qa.release.licenses` | SBOM licences vs deny list; one defect per denied package | `qa.release.license` (High) |

**Per-item fingerprints.** Every suite defect has its own fingerprint so that a NEW item in an already-accepted bucket is new and gates: untested route (`route:<METHOD path>`), test smell (no-assert test: file + test name; skipped/sleep: file + ordinal, never a line number), denied licence (`license:<package>:<licence>`, version excluded), critical-uncovered file, low overall coverage (`overall:<report>:<10-point band>`, so a drop into a lower band is new). More than 100 items of a kind collapse into one roll-up defect.

Licence deny list: `[license] deny = ["AGPL-3.0*", "GPL-3.0*"]` in `readyhai.toml`, or `READYHAI_LICENSE_DENY` (comma separated) in the environment. Needs `sbom.cdx.json`, i.e. the syft tool must have run (not with `--no-tools`); otherwise the check records "not evaluated".

## roles.toml

Keep it outside the target repo, `chmod 600` (a looser mode logs a warning). Secrets are env-var references, resolved at request time, never stored in run.json.

```toml
[[role]]
name = "alice"                 # [A-Za-z0-9_-], unique
auth = "bearer"                # bearer | basic | header | cookie | none
token_env = "RH_ALICE_TOKEN"   # bearer/header
allow = ["/orders", "/orders/**", "/health"]
deny  = ["/admin/**"]

[[role]]
name = "svc"
auth = "header"
header_name = "X-API-Key"      # default X-API-Key
token_env = "RH_SVC_KEY"

[[role]]
name = "legacy"
auth = "basic"
username_env = "RH_LEGACY_USER"
password_env = "RH_LEGACY_PASS"

[[role]]
name = "webuser"
auth = "cookie"
storage_state = "webuser.state.json"   # Playwright storageState, relative to roles.toml
```

`allow`/`deny` are glob patterns that define the expected-access matrix. At least two roles are needed for BOLA and the "Authorization tested with >= 2 roles" exit criterion. Fixture example: `tests/fixtures/qa-api/roles.toml` (fake tokens `alice-token` etc.).

## Safety model

| Rule | Enforcement |
|---|---|
| Writes only on nonprod | POST/PUT/PATCH/DELETE, UI form submits, mutating journeys, k6 and fault injection need the host tagged `env = "nonprod"` in scope.toml; prod/untagged = read-only |
| Rate limit | 5 requests/s global (`QaCtx::throttle`) |
| Request cap | 2000 requests per run; then remaining cases are blocked |
| Tagged data + cleanup | created records are tagged and deleted at the end; leftovers reported |
| Scope | every URL is checked against scope.toml (SSRF/rules-of-engagement guard) |
| Evidence | redacted (set-cookie, tokens) |

Live check: a prod-tagged run of the qa-api fixture issued 70 GET requests and no writes.

## Recommendation and exit criteria

Computed in `recommend.rs`, never chosen by the LLM.

| Exit criterion | Blocking |
|---|---|
| No open P1 defects | yes |
| No new critical/high security findings | yes |
| Gate verdict not FAIL | yes |
| Every failed case is traced to a defect | yes |
| >= 90% of planned cases executed | no |
| No failed test cases (open ones; a failure behind a suppressed defect is accepted) | no |
| No flaky tests | no |
| Authorization tested with >= 2 roles: distinct configured roles that executed role-specific auth-matrix (or BOLA) cases; anonymous/invalid-token cases, blocked/skipped cases and roles with no credential do not count | no |
| API contract violations = 0 | no |

**No-Go** if the verdict is FAIL or any blocking criterion is unmet. **Conditional Go** (conditions listed: unmet criteria, open defects, WARN reasons) if any non-blocking criterion is unmet or the verdict is WARN. **Go** otherwise. Note that running without roles (fewer than 2) alone yields Conditional Go.

## Reports (`--format`, `--out`)

| Format | File | Notes |
|---|---|---|
| `html` (or `qa`) | `qa-report.html` | test summary: cover, executive summary + badge, scope, results, coverage matrix, defects (steps, expected/actual, evidence), risks, exit criteria, security summary, appendix. Auto-escaped |
| `pdf` | `qa-report.pdf` | renders the HTML with the Playwright runner image (`pdf.mjs`, network none, read-only). If the image is missing: note printed, HTML still written |
| `md` | `qa-report.md` | summary + defects |
| `jira` | `defects.jira.csv` | Summary, Issue Type=Bug, Priority, Labels, Component, Description (Jira markup) |
| `gitlab` | `defects.gitlab.json` | issue objects |
| `testrail` | `testcases.testrail.csv` | cases |
| `xray` | `testcases.xray.csv` | cases |
| `json`, `sarif`, `junit` | as for `scan` | `run.json` contains `qa`. JUnit: findings are grouped under their check id; every new QA defect (any severity) is a `<failure>`, baselined ones are not; a failing finding whose check names no registered check goes to an `unattributed` suite instead of vanishing |

Tracker exports are files only; no API calls are made. QA formats on a non-QA run are skipped with a note.

Defect text comes from specs and pages the tool does not control, so exports neutralise it: Markdown/GitLab text is escaped (no emphasis, links, images, raw HTML, headings, list markers or @mentions) and curl/code steps sit in a fence longer than any backtick run inside them; Jira text escapes wiki markup and neutralises `{code` inside `{code}` blocks; every CSV cell starting with `=`, `+`, `-`, `@`, TAB or CR gets a leading apostrophe (formula injection).

**Dashboard:** every run appends one line to `<data>/index.jsonl` (target, date, verdict, recommendation, severity counts, pass rate, coverage, p95). `readyhai dashboard --out DIR` (default `readyhai-dashboard`) renders static HTML with inline SVG sparklines, no JavaScript, no network.

## Fixtures (acceptance set)

| Fixture | Seeded bugs | Result |
|---|---|---|
| `tests/fixtures/qa-api/` | IDOR on `/orders/{id}`, unauthenticated `/admin/stats`, 500 on `note` > 100 chars, traceback leak on `/search?q='`, missing required `total` on `/orders/2`, no-op DELETE, slow `/reports/slow` | 7/7 found, 0 false positives (live) |
| `tests/fixtures/qa-ui/` | no form validation, overflow at 375 px, a11y errors, console error, broken link, v1 -> v2 visual change | expected defects in `EXPECTED.md`; needs runner image; unrun live |
| `tests/fixtures/qa-repo/` | 42% coverage, untested routes, test smells, `python:3.8`, alembic down-migration raising | expected in `EXPECTED.md`; unit-tested |
| `tests/fixtures/qa-perf/k6-summary.json` | recorded k6 summary for parser tests | unit |

The fixtures contain fake tokens (`alice-token`, ...) that may trip secret scanners.

## Known gaps in this guide's features

- Flaky re-runs cover read-only API cases only (writes and the stateful lifecycle are never repeated); UI journeys are not re-run.
- AI-proposed API cases are only listed as report notes.
- `baseline accept <run>` promotes the spec, visual and perf baselines through `qa::accept_baselines` (spec/visual need that call in `main.rs`; perf is already wired).
- The default policy's `hard_fail` list has `api.server_error`, which never matches the QA rule `qa.api.server_error`; add the `qa.api.` names to `policies/default.toml` to hard-fail on them.
- UI and PDF have not been run live (resilience has: `tests/fixtures/resilience`); see [status-and-competition.md](status-and-competition.md).

Runner image: `READYHAI_PLAYWRIGHT_IMAGE`, else local `readyhai/playwright-runner:local`, else `ghcr.io/deziss/readyhai-playwright-runner:latest`. Targets on `host.docker.internal` get the Docker host-gateway mapping. The PDF is rendered as the output dir owner (a fixed uid 65534 could not write it).
