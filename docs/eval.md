# Evaluation harness (`readyhai eval`)

`readyhai eval` scores ReadyHai's own QA engine and agent. It runs them against fixtures with
**known, seeded defects** and measures how many they find, how much noise they add, and whether the
answer is the same every time. It is the regression gate for the detection logic: a change to
`src/qa/**` or `src/agent/**` that makes ReadyHai miss a seeded bug, invent a defect, or flip its
verdict between runs fails the `eval` CI job.

```bash
export PATH=$PATH:$HOME/.cargo/bin
cargo run -- eval                       # all suites, k = 2, report in ./eval-report/
cargo run -- eval --suite qa-api --k 3  # one suite, three runs
echo "exit=$?"                          # 0 every threshold met, 1 a threshold missed, 3 harness error
```

Needs `python3` (the fixture servers are stdlib scripts) and, for `agent-diff`, `git` (it builds a throwaway repository). No network, no docker, no LLM, no scanner
images: everything runs on `127.0.0.1`.

| Flag | Default | Meaning |
|---|---|---|
| `--suite a,b` / `all` | `all` | Suites to run (file names in `--dir` without `.toml`) |
| `--k N` | `2` | Runs per suite. pass^k needs all `N` to meet the recall threshold |
| `--out DIR` | `eval-report` | Directory for `eval-report.json` and `eval-report.md` |
| `--dir DIR` | `tests/eval` | Directory holding the suite files |

## What is measured

Per suite, over `k` independent runs:

| Metric | Definition | Default threshold |
|---|---|---|
| **recall** | expected defects found / expected defects (required ones only). Reported as the mean over runs plus the worst run | mean >= 0.85 |
| **precision** | reported defects that were expected / (expected + false positives), per run. A defect that matches an `[[allow]]` is in neither count; a run that reported nothing scores 1.0. Reported as the mean over runs plus the worst run | reported, no gate (the false-positive limit gates) |
| **false positives** | defects the run reported that match no `[[expect]]` and no `[[allow]]`. Reported for the worst run | <= 2 |
| **inconclusive rate** | agent only. INCONCLUSIVE cases / executed applicable cases (PASS + WARN + FAIL + INCONCLUSIVE; NOT_APPLICABLE, SKIPPED and BLOCKED are not in it, so a run that never got past a login wall has no rate). Worst run. A run that executed nothing cannot pass this gate | `max_inconclusive_rate`, unset = unchecked (the new SPA suites set 0.25) |
| **confidence** | agent only. The ledger's `confidence`: conclusive cases / applicable cases, in percent. Worst run. Reported, not gated | reported |
| **pass^k** | every one of the `k` runs reached the recall threshold. One lucky run does not count | true |
| **verdict stability** | all `k` runs ended with the same verdict (a deterministic engine must not flip) | stable |
| **requests** | requests the target saw, counted by the fixture server's own log (readiness probe excluded). Worst run | `max_requests` |
| **wall time** | seconds per run, fixture start excluded. Worst run | `max_seconds` |
| **expected verdict** | optional: every run must end with `expect_verdict` (exact, case-insensitive). `verdict_match` in the JSON | unset |
| **forbidden verdict** | optional: no run may end with a verdict in `forbid_verdict`, e.g. `["NO_GO"]` for a target with nothing wrong | unset |
| **expected blocker** | optional, agent only: every run's `evidence_ledger.blockers` must list the reason `expect_blocker` (`auth_wall`, `out_of_scope`, `no_surface`, `transport`). The reasons seen are reported as `blockers` | unset |

A suite passes when every check above passes. The process exits `1` if any suite fails.

Two kinds of expectation are reported but kept out of recall, so they cannot hide a regression
silently and cannot turn the job red for something that is not a regression:

- `optional = true`: needs something the CI runner may lack (docker). Listed as "optional not found".
- `known_gap = true`: the tool is known not to detect this seeded bug **yet**. Listed on every run
  as "known gaps still open". The day a run finds it, the report says "known gaps now found in every
  run, remove `known_gap` so they gate". Remove the flag then: the bug is now part of recall and a
  later regression fails the build. Never add a `known_gap` to hide a bug the tool used to find.

### Suites

| Suite | Kind | What runs | Seeded defects |
|---|---|---|---|
| `qa-api` | `qa` | `engine::scan` with QA options (what `readyhai qa` calls), profile `standard`, no tools, the spec and roles of `tests/fixtures/qa-api` | the 7 bugs listed in `tests/fixtures/qa-api/server.py` |
| `agent-api` | `agent` | `agent::run_agentic_loop_with` against the same fixture: spec given, `dry_run` false, nonprod scope, deterministic (no LLM) | the same 7 bugs, matched through the failing oracle checks. All 7 gate recall; the agent reuses the QA engine's case generator, response validator, leak catalog and latency limit (`src/qa/api`), so a bug it cannot find yet would be flagged `known_gap` in its file |
| `agent-diff` | `agent` | the agent with a source repo and a base ref (change-aware planning), profile `quick`: the harness builds a git repository from `tests/fixtures/qa-api-src` (commit 1 the service, commit 2 a PR that touches `app/search.py` and the changelog) | bug 4 of the qa-api server (`GET /search`, the one route the PR changed). The other six bugs are on untouched routes and are not expected: any other defect is a false positive (`max_false_positives = 0`). Also checks the change impact: the diff maps to exactly `GET /search`, its cases lead the plan, and all were sent |
| `agent-memory` | `agent` | the agent **twice in the same data directory** against the same fixture (`[memory] runs = 2`), as `agent-api`; the last run is scored | the same 7 bugs. On top of recall and false positives, four checks over the series: the first run remembered what it found (every defect new); the second reports every seeded defect as **still open** (and none as new again); its plan **starts with the regression probes** (the reproduction case of each known defect that a planned case can re-test; a defect found by the teardown has none); and no case the first run planned is missing from the second (memory only reorders; the second plan may hold *more* reads, because the fixture's no-op DELETE leaves orders behind that the target now lists) |
| `agent-spa` | `agent` | the agent against `tests/fixtures/spa-next` (a fake Next.js app behind a login wall: `/` is a 307 to `/login`, every unknown path is the same 200 HTML shell, the API lives only in the JS chunks the shell loads), **no spec**, test accounts `alice` and `bob`, deterministic, no LLM | the 3 bugs listed in `tests/fixtures/spa-next/server.py`: an IDOR on `GET /api/orders/{id}`, a SQL error and stack trace leaked by `?q='` (500), a 500 on out-of-range `limit` / `offset`. Recall >= 0.85, inconclusive rate <= 25%, verdict `NO_GO` |
| `agent-spa-clean` | `agent` | the same app started with `--clean` (`target.server_args`), the same accounts | none: every bug is fixed. The false-positive guard: the verdict must **not** be `NO_GO`, at most 1 reported defect, inconclusive rate <= 25% |
| `agent-spa-noauth` | `agent` | the same buggy app with **no credentials** | none can be seen. The agent cannot get past the wall and must say so: verdict `NOT_EVALUATED`, an `auth_wall` blocker in the ledger, no defect reported |
| `security-deep` | `agent` | the agent (`profile = "deep"`, `max_steps = 120`, `alice` + `admin` JWTs) against `tests/fixtures/security-deep/server.py` + `openapi.json`, deterministic, no LLM | 12 seeded security loopholes (boolean & time-delay blind SQLi, SSTI, blind OAST SSRF, open redirect, JWT `alg:none`, BFLA, mass assignment, negative quantity, TOCTOU race, DOM XSS, stored XSS) plus clean negative controls; `max_false_positives = 0`, `min_recall = 0.85`, verdict `NO_GO` |
| `whitebox-exploit` | `agent` | the agent (`profile = "standard"`, `max_steps = 40`) with `[target.repo]` (`diff_base = false`, `require_source_context = true`) against `tests/fixtures/whitebox-exploit` | discovers undocumented `/internal/debug-export` via Tree-sitter AST analysis, exploits its SQLi, and attaches `file:line` source linkage (`app.py:9 handler debug_export`); `min_recall = 1.0`, `max_false_positives = 0`, verdict `NO_GO` |
| `qa-repo` | `repo` | static `engine::scan` (QA checks on) of `tests/fixtures/qa-repo`, findings with the `qa.` prefix | the suite/release defects in `tests/fixtures/qa-repo/EXPECTED.md` |

Expected verdicts (`expect_verdict`, every run must end with it): `qa-api` `NoGo/Fail`, `qa-repo` none, `agent-api`, `agent-memory`, `agent-spa`, `security-deep` and `whitebox-exploit` `NO_GO`, `agent-diff` `CONDITIONAL_GO`, `agent-spa-noauth` `NOT_EVALUATED`. `agent-spa-clean` forbids `NO_GO` instead of naming one.

The three SPA suites exist because the first real run against a thin, login-walled SPA (NuHire) ended `NO_GO` at 55 with 15 of 18 cases INCONCLUSIVE, none of them a defect of the app: the agent's own blind spots (a 307 it did not follow, input tests aimed at an HTML shell, no route or API call found in the JS). They measure that directly: `agent-spa` that the agent gets through the wall and finds the API and the bugs behind it with few inconclusive cases, `agent-spa-clean` that it does not invent a failing verdict, `agent-spa-noauth` that missing evidence is reported as "not evaluated" with its reason and not as a failure.

### Isolation

Every run gets:

- its own `READYHAI_DATA` directory (so no baseline, no carried-over state; the agent's memory of the target lives in it, so it starts empty, and only a `[memory]` suite runs the agent twice in one);
- a generated `scope.toml` that lists only `127.0.0.1` and `localhost` as `env = "nonprod"`
  (`READYHAI_SCOPE` points at it; your own scope file is never read);
- a fresh fixture server on a free loopback port (fixture state, such as the order list, starts clean);
- `READYHAI_OFFLINE=1`, the LLM and agent-budget variables (`READYHAI_AGENT_WORKERS` included, so the agent runs with its default 4 workers) unset, `--no-tools`, no public-IP lookup;
- the FAKE fixture tokens from the suite file, exported as `RH_<ROLE>_TOKEN` for the run and restored
  afterwards.

The harness changes process environment, so it holds a lock and restores everything it touched.
It is run through the binary (or the `live_eval` test below), never from a unit test that shares a
process with other tests.

## Reading the results

`eval-report/eval-report.md` is the human summary (also appended to the GitHub job summary in CI):

```
| suite | kind | recall | min run | precision | FP | inconclusive | confidence | pass^k | verdict | requests | time | open gaps | result |
```

(`inconclusive` and `confidence` are `-` for the `qa` and `repo` suites, which have no cases.) It is
followed by one section per suite listing every check (`PASS`/`FAIL` with the numbers), the blockers
the agent reported and, for each run, its case counts by status, the missed expectations and the
false positives.

`eval-report/eval-report.json` is the same data for machines. Top level: `version`, `started`, `k`,
`passed`, `suites[]`. Each suite has `description`, `notes` (expectation id to what the seeded defect
is), `recall`, `recall_min`, `precision`, `precision_min`, `false_positives`, `inconclusive_rate`
(worst run, null when none), `confidence` (worst run), `blockers` (union over runs), `verdict_match`
(null without `expect_verdict`), `pass_k`, `verdict_stable`, `verdicts`,
`known_gaps_open`, `known_gaps_closed`, `requests`, `seconds`, `thresholds`, `checks[]`, `passed`,
`error` and `runs[]`. Each run has `recall`, `found`, `missed`, `optional_found`, `optional_missed`,
`gap_found`, `gap_missed`, `false_positives`, `true_positives`, `precision`, `cases` (agent: status
-> count), `inconclusive_rate`, `confidence`, `blockers`, `allowed_seen` (extras that matched an `[[allow]]`, with
its reason), `observed` (every `rule @ component` the run reported that was scored; an agent defect
with several failing checks shows them joined with `+`), `verdict`, `requests`, `seconds`.

Diagnosing a failure:

| Symptom | Look at | Usual cause |
|---|---|---|
| `inconclusive rate` over the limit | `cases` of the run (counts by status), then the report's INCONCLUSIVE results | the planner aims cases at something that cannot answer them (an HTML shell, a redirect), or the executor does not follow a redirect |
| `inconclusive rate` "executed no applicable case" | `cases`, `blockers` | everything was BLOCKED / NOT_APPLICABLE: the credentials did not reach the agent, or discovery found no surface |
| `forbidden verdict` | `verdicts`, the run's ledger `reasons` | a false alarm: a proven-looking failure on a target with no bug (check `false_positives` and the FAIL cases), or inconclusive cases counted as failures |
| `expected blocker` | `blockers` of the run | the agent did not name the wall (login redirect / 401) as the reason it had no evidence |
| `recall` low, `missed` lists an id | that `[[expect]]` in the suite file, then `observed` of the run | the check stopped detecting the bug, or its rule id / component text changed (update the suite file if the change is intended) |
| `false positives` > limit | the `false_positives` list of the run | a new rule fires on the fixture. If it is a real extra view of a seeded bug add an `[[allow]]`, otherwise fix the rule |
| `pass^k` false, mean recall fine | per-run `recall` | detection depends on timing or ordering (flaky check) |
| `verdict stable` fails | `verdicts` | non-deterministic gate: a flaky case, a rate/timing threshold |
| `request budget` / `time budget` | `requests`, `seconds` | the run now sends more traffic than before; raise the budget only if intended |
| `runs completed` fails | `error` | fixture did not start (is `python3` on PATH? set `READYHAI_EVAL_PYTHON`), or the engine returned an error |

To look at the raw run (reports, evidence, agent `report.json`) behind a result, set
`READYHAI_EVAL_KEEP=1`: the per-run data directories are then kept and their parent is printed
(under `$TMPDIR`) instead of being deleted.

Do not loosen a threshold to make a red run green. Fix the detection, or, when the fixture or the
rule legitimately changed, update the expectation and say why in the commit.

## Suite file format

`tests/eval/<suite>.toml`. The file name must equal `name`. Unknown keys are rejected.

```toml
name = "qa-api"
kind = "qa"                      # qa | agent | repo
description = "what this suite proves"
observe_prefix = "qa."           # optional: only score observations whose rule starts with this
expect_verdict = "NoGo/Fail"     # optional: every run must end with this verdict (exact, case-insensitive)
forbid_verdict = ["NO_GO"]       # optional: no run may end with any of these (a target with nothing wrong)
expect_blocker = "auth_wall"     # optional, agent only: every run's ledger must list this blocker reason

[target]
server  = "tests/fixtures/qa-api/server.py"    # qa, agent: python3 script, started as `server.py PORT LOGFILE [server_args...]`
server_args = ["--clean"]                      # optional: extra arguments after PORT LOGFILE (e.g. a fixture's bug-free mode)
spec    = "tests/fixtures/qa-api/openapi.json" # qa, agent (optional for agent: leave it out to make the agent find the API itself)
roles   = "tests/fixtures/qa-api/roles.toml"   # qa
path    = "tests/fixtures/qa-repo"             # repo: directory to scan
profile = "standard"                           # quick | standard | deep
max_steps = 50                                 # agent only
[target.tokens]                                # FAKE fixture tokens only
alice = "alice-token"
[target.repo]                                  # agent only: a repo copied per run for white-box AST and/or diff planning
commits = ["tests/fixtures/qa-api-src/base", "tests/fixtures/qa-api-src/change"]   # 1 or more commits copied over each other; when diff_base = true (default), commit 1 is tagged `base` as --diff-base
diff_base = true                               # set false for pure white-box AST repo analysis without a git diff
require_source_context = false                 # when true, every matched defect must carry file:line handler source linkage

[memory]                                       # agent only: run the agent N times in the same data directory
runs = 2                                       # 2..=5; the last run is scored, the series must remember (see above)

[change]                                       # agent only, needs target.repo
operations = ["GET /search"]                   # the change impact must name exactly these operations
planned_first = true                           # their cases come before every other case (the root probe aside)
min_sent = 1.0                                 # share of their planned cases that must have been sent

[thresholds]                     # every key optional; these are the defaults
min_recall = 0.85
max_false_positives = 2
pass_k = true
stable_verdict = true
max_requests = 300               # per run; unset = unchecked
max_seconds = 150                # per run; unset = unchecked
max_inconclusive_rate = 0.25     # agent only, 0..=1: INCONCLUSIVE / executed applicable cases, worst run; unset = unchecked

[[expect]]                       # one per seeded defect
id = "idor"                      # unique within the file
rule = "qa.api.bola"             # rule id, `*` is the only wildcard
component = "GET /orders/{id}"   # optional, same wildcard rules
title = "BOLA"                   # optional, case-insensitive substring of the defect title
optional = false                 # true: needs something this machine may lack (docker); reported, never counted in recall
known_gap = false                # true: the tool cannot find it yet; reported, never counted in recall (exclusive with optional)
note = "bug 1"                   # shown next to a missed id in the report

[[allow]]                        # an extra that is real or harmless: not a false positive
rule = "qa.api.privilege_escalation"
component = "GET /admin/stats"
reason = "bug 2 seen through the role matrix"
```

What a "defect" is, per kind:

- `qa`: `run.qa.defects` (the QA report); `rule` is the defect rule, `component` is `METHOD /path`.
- `agent`: `triaged_defects`; `rule` matches any **failing oracle check code** of the defect's cases
  (a defect can carry several), `component` is the defect component (path only, ids resolved:
  `/orders/4`, so use `/orders/*`).
- `repo`: `run.findings`; `rule` is the finding rule, `component` is its location.

`[memory]` (agent only, `runs = 2` by default, 2 to 5, not with `target.repo`) runs the agent `runs` times against one fixture instance in one data directory and scores the last run. It adds four checks that must hold in every run of the suite: `memory: first run remembered`, `memory: seeded defects still open`, `memory: regression probes lead the plan` and `memory: no case dropped`. `requests` counts every agent run of the series, and `max_requests` / `max_seconds` are also each agent run's own budget, so set them for the whole series.

`[change]` adds up to three checks to the suite (`changed operations`, `changed operations planned first`, `changed operations covered`); each must hold in every run, like `pass^k`.

A suite with no seeded defect (a clean target, or a target the agent cannot see into) has no `[[expect]]`:
it then needs at least one of `expect_verdict`, `forbid_verdict` or `expect_blocker`, and its recall is
vacuously 1.0 (every reported defect is a false positive, bounded by `max_false_positives`).

A defect is expected if it matches any `[[expect]]` (one defect may satisfy several), allowed if it
matches an `[[allow]]`, and otherwise counts as a false positive.

## Adding a suite

1. Put a fixture with **documented** seeded defects under `tests/fixtures/<name>/`. For a server,
   a stdlib-only `python3` script taking `PORT [REQUEST_LOG]` and writing one `METHOD /path` line per
   request to the log (the harness counts requests from it). It must answer `GET /health` with a 200
   (the harness waits for it). Extra arguments come from `target.server_args`: give a fixture a
   `--clean` mode and add a second suite over it, so a regression that invents a failure shows up too.
   Use fake credentials only.
2. Run the tool once by hand and look at what it reports (`readyhai qa ... --format json`).
3. Create `tests/eval/<name>.toml` with one `[[expect]]` per seeded defect, taken from the *intended*
   behaviour, not copied from whatever the tool happens to print. If it misses a bug today, keep the
   expectation: that is the gap the eval exists to show (mark `optional = true` only when the
   detection genuinely needs docker or another thing the CI runner lacks).
4. Add `[[allow]]` entries only for extras you can explain.
   If the tool cannot detect a seeded bug yet, keep the expectation and flag it `known_gap = true`
   so the gap stays on the page and closes visibly.
5. Set budgets about 2x what you measured, `cargo run -- eval --suite <name> --k 3`, and check the
   three runs agree.
6. Add the suite to the table above. CI picks it up automatically (`--suite all`).

A new suite *kind* means a new executor in `src/eval.rs` (`exec_*`): return the verdict string and
the list of `Observed { rules, component, title }`, and add the kind to `SuiteKind` and `run_once`.

## GenAI & Agent Application Evaluation (`readyhai eval-ai`)

`readyhai eval-ai` evaluates GenAI applications, LLM pipelines, RAG systems, and AI agents. It operates completely offline (`READYHAI_OFFLINE=1`) without external cloud LLM dependencies, using deterministic semantic tokenization, atomic proposition decomposition, entity graph comparison, and adversarial signature scanning.

```bash
# Evaluate a single RAG query-context-response exchange
readyhai eval-ai \
  --query "What is the capital of France?" \
  --context "Paris is the capital and largest city of France." \
  --response "Paris is the capital of France." \
  --threshold 0.70

# Evaluate a JSON/JSONL dataset of test cases with red-teaming enabled
readyhai eval-ai --dataset dataset.json --red-team --format table
```

### Metrics Evaluated

1. **RAG Quality Triad:**
   - **Context Relevance:** Lexical and semantic token coverage of user query terms within the retrieved context chunks.
   - **Faithfulness / Hallucination Detection:** Atomic proposition extraction verifying whether every entity, proper noun, and numeric claim in the generated answer exists in the retrieved context. Hallucinated entities and figures are itemized with exact explanations.
   - **Answer Relevance:** Evaluates query intent fulfillment and penalizes evasive responses (*"I don't know"*, *"As an AI..."*).
2. **Agent Trajectory & Tool Execution:**
   - **JSON Schema Conformance:** Validates tool input parameters against declared tool definitions.
   - **Cyclic Loop Detection:** Detects repeated, oscillating tool calls with identical arguments.
   - **Trajectory Efficiency:** Ratio of minimal required steps to total steps executed.
3. **Adversarial AI Red-Teaming Scanner:**
   - **Prompt Injection:** Identifies jailbreak signatures, DAN jailbreaks, instruction overrides.
   - **Sensitive Credential Leakage:** Scans outputs for leaked API keys (`sk-`, `ghp_`, `rh_`, `AKIA`) and private keys.
   - **Canary Exfiltration:** Detects canary token leakage in responses.

---

## Mutation Testing & Test Oracle Calibration (`readyhai mutate`)

`readyhai mutate` evaluates the effectiveness of your repository's test suite ("testing the tests") by injecting targeted semantic defects (mutants) into your source code and executing the test harness.

```bash
# Run mutation testing across the repository (evaluating up to 20 mutants)
readyhai mutate --repo . --max-mutants 20 --timeout-secs 30

# Target a specific module or package
readyhai mutate --repo . --target "src/auth" --format markdown
```

### Mutation Operators

- **Comparison Inversion:** Inverts relational operators (`==` <-> `!=`, `<` <-> `>=`, `>` <-> `<=`).
- **Boolean Literal Flip:** Inverts boolean constants (`true` <-> `false`).
- **Auth Guard Bypass:** Mutates security conditions (`is_admin` -> `true`, `is_authorized` -> `true`).
- **Return Value Inversion:** Replaces `return Ok(...)` with `return Err(...)`, or `return true` with `return false`.
- **Arithmetic Inversion:** Swaps binary arithmetic operators (`+` <-> `-`, `*` <-> `/`).

### Test Oracle Calibration & Verdicts

- **Killed (Pass):** The test suite fails when the mutant is active (proves the test suite actively catches the bug).
- **Survived (Gap):** The test suite passes despite the injected bug (proves assertions are missing or superficial).
- **Timed Out (Pass):** The mutant causes a timeout or infinite loop (counted as killed).
- **Mutation Score:** $\frac{\text{Killed} + \text{TimedOut}}{\text{Total Mutants}} \times 100\%$.
- **Negative Test Generation:** For every survived mutant, ReadyHai synthesizes the exact assertion needed to kill the mutant and eliminate the coverage blind spot.

---

## CI

The `eval` job in `.github/workflows/ci.yml` runs after `test`: `cargo run -- eval --suite all --k 2
--out eval-report` with `python3` available (the agent suite also enforces `max_requests` and
`max_seconds` as the run's own budget; for the qa suites they are measured after the run), appends the markdown to the job summary and uploads
`eval-report/` as the `eval-report` artifact (always, so a red run keeps its evidence). It uses no
network beyond what the build itself needs and starts no containers.

## Developing the harness

The pure logic (matching, scoring, thresholds, report rendering, suite parsing, the fixture launcher)
has unit tests: `cargo test -j 2 eval`. The end-to-end run is an ignored test that executes in its
own process:

```bash
EVAL_SUITES=qa-repo EVAL_K=1 cargo test -j 2 eval::tests::live_eval -- --ignored --nocapture
```
