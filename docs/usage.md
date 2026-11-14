# Usage

Binary: `readyhai` (dev build: `target/debug/readyhai`; `cargo` lives in `~/.cargo/bin`, add it to PATH). Version: `readyhai --version`.

## Commands

| Command | Purpose |
|---|---|
| `readyhai scan <target> [flags]` | Scan a target, write reports, exit with the verdict code (0 PASS, 1 WARN, 2 FAIL) |
| `readyhai qa <url> [flags]` | Senior-QA run (API, UI, perf, resilience, suite and release quality) with a Go / Conditional Go / No-Go / Inconclusive recommendation. See [qa.md](qa.md) and the table at the end of this page |
| `readyhai roles init --spec FILE [--out FILE\|-] [--force]` | Derive a `roles.toml` skeleton from an OpenAPI spec (roles, `RH_<ROLE>_TOKEN` env var names, allow/deny globs inferred from scopes). See [Generating roles.toml](#generating-rolestoml-from-the-spec) |
| `readyhai agent <url> [--spec URL] [--scope FILE] [--max-steps N] [--dry-run] [--repo DIR --diff-base REF]` | Autonomous Agentic AI QA run; exit 0 `GO`, 1 `CONDITIONAL_GO`, 2 `NO_GO` or not evaluated. See below |
| `readyhai agent-memory show <target> [--json]` | What the agent remembers about a target: known defects (with the fingerprint `accept` takes), flaky case classes, operations, baselines |
| `readyhai agent-memory accept <target> <fingerprint> --reason TEXT --expires YYYY-MM-DD [--by NAME]` | Accept a known open defect until a date: listed in every report, not blocking |
| `readyhai agent-memory forget <target>` | Delete the memory of a target |
| `readyhai eval [--suite a,b] [--k N] [--out DIR] [--dir DIR]` | Score the QA engine and the agent against seeded-defect fixtures. Exit 0 every threshold met, 1 a threshold missed, 3 harness error. See [eval.md](eval.md) |
| `readyhai eval-ai [--query Q --context C --response R \| --dataset FILE] [--red-team] [--format table\|json\|markdown]` | Universal GenAI & Agent Evaluator: RAG Quality Triad (Context Relevance, Faithfulness/Hallucinations, Answer Relevance), tool trajectory loops, and prompt injection red-teaming |
| `readyhai baseline accept <run> [--out FILE]` | Accept a run's findings as the baseline |
| `readyhai checks` | List registered checks (reads `READYHAI_PLUGINS` for plugins) |
| `readyhai tools pull [--lock FILE]` | `docker pull` every image in `tools.lock.toml`; optionally write resolved digests |
| `readyhai tools update` | Refresh grype DB, semgrep rules, Lynis tarball (the only networked step) |
| `readyhai bundle export [--out FILE] [--set core\|full] [--with-model FILE.gguf]` / `bundle import <bundle.tar>` | Offline bundle. See [offline.md](offline.md) |
| `readyhai doctor` | Mode (offline / lan-llm / deterministic), tool presence, grype DB age, LLM reachability, disk |
| `readyhai dashboard [--out DIR]` | Static offline trend dashboard from `<data>/index.jsonl` (default `readyhai-dashboard`) |
| `readyhai serve [--bind ADDR]` | REST API and scan worker (default `127.0.0.1:8080`); needs `READYHAI_TOKEN`. `GET /` returns a JSON endpoint index, the UI is the separate Next.js app on port 3000 |
| `readyhai mcp` | MCP server on stdio. Tools: `readyhai_scan`, `readyhai_checks`, `readyhai_run`, `readyhai_findings`, `readyhai_agent_swarm`, `readyhai_agent_status`, `readyhai_agent_cancel`, `readyhai_agent_discover` |
| `readyhai ping [--url URL]` | Container HEALTHCHECK probe (default `http://127.0.0.1:8080/health`), exit 0 healthy / 1 not |

### `scan` flags

| Flag | Default | Notes |
|---|---|---|
| `<target>` | required | See target syntaxes below |
| `--profile quick\|standard\|deep` | `quick` | See profiles |
| `--openapi URL` | none | OpenAPI spec for web targets. Else `/openapi.json`, `/docs/openapi.json`, `/api/openapi.json`, `/swagger.json` are probed |
| `--policy FILE` | embedded `policies/default.toml` | Gate policy; see [configuration.md](configuration.md) |
| `--scope FILE` (env `READYHAI_SCOPE`) | none | `scope.toml` rules of engagement for web targets (template: `scope.example.toml`). With no file, public hosts get full testing and internal hosts are refused. A file that is given but missing, a directory or invalid is an error (exit 3), never "no scope" |
| `--config FILE` | `<repo>/readyhai.toml` | If given, the target's own `readyhai.toml` is ignored |
| `--baseline FILE` | `<data>/baselines/<hash>.json` | Baseline to diff against |
| `--format a,b` | `html,json` | Any of `html`, `json`, `sarif`, `junit`; unknown names are ignored |
| `--out DIR` | `readyhai-report` | Report directory |
| `--no-tools` | off | Skip every check that needs a container (`.tool` set) |
| `--os linux\|macos\|windows` | `linux` | Host OS for `ssh://` targets |
| `--key FILE` | ssh-agent / `~/.ssh/config` | Private key for `ssh://` (adds `IdentitiesOnly=yes`) |
| `--device SERIAL\|HOST:PORT` | none | adb device/emulator for `android:` runtime check |
| `--plugins DIR` (env `READYHAI_PLUGINS`) | none | Plugin directory |

Progress, the per-check table and the verdict go to **stderr**; reports are files. On start it prints `readyhai <ver> · run <id> · <target> · profile <p>`: note the run id, you need it for `baseline accept`.

Example summary line: `[part] tool.sbom_cve  12 finding(s) — 25 of 26 deps unpinned; ...` with markers `ok`, `FAIL`, `part`, `skip`, `n/a`, `ERR`.

## Persistent Global History & Live Retesting

Every agent run and discovery scan is archived on disk under `<data>/agent-runs/<run id>/` (default data directory `~/.local/share/readyhai`, or `READYHAI_DATA`):
- **Reconnaissance scans (`/api/agent/discover`):** route classifications (API vs SPA fallback), probe latencies; stored with the profile `discovery-scan` and no score.
- **Agent runs (`/api/agent/run`, `readyhai agent`, MCP):** the full trace, executed cases with reproduction curls, evidence files, defects, the Evidence Ledger, the verification and cleanup summaries, and the sign-off state.
- **Live re-testing:** `POST /api/agent/retest` (or the retest button in the UI) re-executes one case and updates the stored report in place.
- **Run management:** the UI "Runs history" lists runs with their lifecycle chip, a Cancel button for running runs, report downloads and a delete action (`DELETE /api/agent/runs/{id}`).

## Autonomous Agentic AI (`readyhai agent`)

Runs the autonomous testing pipeline against an HTTP target: **Discovery -> Planner -> Explorer -> Verifier -> Cleanup -> Triager -> Readiness gate**. Verdicts are computed by deterministic code. An LLM (a local vLLM / Ollama, or any OpenAI-compatible endpoint: `READYHAI_LLM_URL`, optional `READYHAI_LLM_API_KEY`, `READYHAI_LLM_MODEL` as one model or a fallback list) is optional; when it is unreachable the run is deterministic and says so.

```bash
readyhai agent https://staging.example.com --spec https://staging.example.com/openapi.json --max-steps 25
```

### The pipeline
1. **Discovery:** crawls the target (same-host redirects only), classifies routes (API vs SPA shell), discovers XHR calls via Playwright when enabled (`READYHAI_AGENT_XHR`), reads the OpenAPI spec when given, harvests existing resource ids, and—when `--repo` is supplied—runs Tree-sitter AST source/sink/guard discovery (`whitebox.rs`) to surface hidden routes and handlers.
2. **Planner:** boundary, negative, authorization, injection and state cases from the crawl and spec (reusing `qa::api`), plus modular deep-security attack suites (`attacks/auth.rs` JWT tampering/BFLA/proxy ACL bypass, `attacks/bopla.rs` excessive data exposure & mass assignment, `attacks/injection.rs` open redirect, OAST SSRF, multi-encoding path traversal, SSTI, boolean/time blind SQLi, time-delay CMDi, and `attacks/logic.rs` TOCTOU races, workflow step-skip, HPP, GraphQL) and white-box AST probes. Depth follows the run request's `profile` (`quick` baseline only, `standard` top 15 operations, `deep` top 30); the CLI always runs `standard`, REST and MCP accept all three. Changed operations and known defects go first.
3. **Explorer (lead agent), OAST, ReAct & BrowserSecurity:** the plan is split into `auth`, `contract`, `state` and `ui`; each runs on its own worker with a slice of the budget (`READYHAI_AGENT_WORKERS`, default 4) and an in-process loopback OAST collector (`oast.rs`). One per-host rate limit (`READYHAI_AGENT_RATE_PER_HOST`, default 10/s) is shared; writes run in a fixed order. Deterministic wave 2 follow-ups (`lead.rs`), bounded adaptive ReAct exploration (`react.rs`), and interactive Playwright DOM/storage/cookie checks (`browser_sec.rs`, `standard`/`deep`, disable with `READYHAI_AGENT_BROWSER=off`) follow under the remaining budget.
4. **Verifier:** every failure is replayed `READYHAI_VERIFY_K` times (default 2, max 5, `0` off) including blind timing/OAST/redirect probes. Reproduced failures are defects; failures that do not reproduce are INCONCLUSIVE.
5. **Cleanup:** what the run created is deleted newest first on a nonprod target and read back; leftovers are listed in the report and `cleanup.json`.
6. **Triager:** clusters failures into defects with OWASP labels, severities, and white-box `file:line handler` source linkage when `--repo` is present.
7. **Readiness gate:** four-pillar **Evidence Ledger** (`Value` 30, `Authority` 30, `Safety` 25, `Evidence` 15) and the verdict `GO`, `CONDITIONAL_GO`, `NO_GO`, or `NOT_EVALUATED` when nothing conclusive ran.

### Flags
- `<target>`: an `http://` or `https://` URL (required). The agent probes over HTTP only.
- `--spec URL`: OpenAPI spec URL. Without it the agent probes a few common paths and plans little; the console warns "low coverage" below 5 executed cases.
- `--scope FILE` (env `READYHAI_SCOPE`): `scope.toml`. The agent sends writes and attack payloads, so a host listed `env = "prod"` is refused; a public host needs no entry; an internal host (localhost, RFC1918) must be listed or matched by a `*` entry. A scope file that cannot be used is an error.
- `--max-steps N`: executed test cases (default 5, clamped to 1..=50). The MCP tool defaults to 15 and the Studio to 15; the run budget also bounds requests (600), wall clock (900 s) and LLM calls (20), see [configuration.md](configuration.md#agent-run-budget).
- `--dry-run`: validate the scope and print what would run (target, spec, steps, change plan); no request is sent.
- `--repo DIR --diff-base REF` (together, `clap` enforces it): the service's checkout and the git ref the change is measured from, for a PR run that tests what changed. See below.

The console summary prints run id, model and provider, gate verdict, readiness, the one-line summary, defect and case counts, "Since last" (memory) and "Change" (diff) lines.

### Testing what a PR changed
```bash
readyhai agent https://staging.example.com --spec https://staging.example.com/openapi.json \
  --repo . --diff-base origin/main
```
The agent runs `git diff --name-only origin/main...HEAD` in the checkout (no hooks, no prompts, a time limit), reads the routes the changed files declare with the QA engine's route extractors (Flask/FastAPI decorators, Express, Spring, Django `urls.py`) and matches them to the spec's operations by path template. A changed source file whose routes cannot be read (a language the extractors do not know, a deleted handler) still marks the operations whose `operationId` appears in it or whose path is the file's resource name, as "file changed, routes unknown". Those **changed operations get the full case set** (authz, injection, contract read, boundary and negative probes, the tenant chain and a burst for creates) **even at the `quick` profile**, are **planned first and cut last**; every other operation keeps what the profile alone gives. The report has a **Change impact** section: changed files, the operations they map to (and how), unmapped files, and per changed operation how many cases were planned and sent. A diff that cannot be read (unknown ref, not a repository) is a note, never a failed run. **A spec is needed**: without `--spec` the changed files cannot be mapped to operations, the change impact is `skipped` and the plan is what the profile gives. `READYHAI_GIT_TIMEOUT_SECS` bounds the `git diff` (default 60 s, 5 to 3600).

If an index of the checkout exists (`$READYHAI_CONTEXT_INDEX`, or `<repo>/.readyhai/context-index`, built with `runners/context_retriever`), the agent asks the retriever about the changed operations (one subprocess, 60 s by default, `READYHAI_CONTEXT_TIMEOUT_SECS`). What it prints is untrusted text: it is redacted, bounded and shown as advisory notes, and adds no case. With no index the step is skipped with a note.

### What the agent remembers between runs

Every run against the same URL (scheme, host, port and path) reads what the earlier runs found and writes what this one found, in `<data_dir>/memory/<target_key>.json`. It is deterministic and written only from the run's test results (never from LLM text or response bodies), and it never changes a verdict by itself:

- **Regression probes first.** For every known open, regressed or recently fixed (30 days) defect the plan puts its reproduction cases first, then changed operations, then operations that failed or were flaky before, then the rest. Nothing is skipped because it passed before: memory only reorders. Failures of cases that were flaky before are verified with the maximum k (5).
- **"Since last run"** in the console summary, the markdown and HTML reports, `report.json` (`since_last_run`) and `readyhai_agent_status`:
  - **New**: found now, never seen. **Still open**: known, found again. **Fixed**: known, not found, and every reproduction case ran and passed. **Regressed**: known as fixed, found again. **Not re-tested**: known, not found, but its reproduction cases did not run cleanly (skipped, blocked, inconclusive): it is *not* called fixed.
  - **Known flaky**: case classes that failed on some attempts in the last 20 runs that ran them.
  - **Accepted** and **Acceptance expired**: see below.
- **Accepting a defect.** `readyhai agent-memory show <target>` lists the defects with their fingerprints (they are in the report too). `readyhai agent-memory accept <target> <fingerprint> --reason "tracked in OPS-1" --expires 2026-12-31` lets that defect through the gate until the end of that day: it stays listed (with who, why and the expiry) in every report, SARIF marks it suppressed and JUnit marks its cases skipped, its failing cases are not scored, and the verdict basis states what the verdict would be without the acceptance. After the date it blocks again and the report lists it as expired. A defect that gets fixed loses its acceptance. The acceptance is the only memory input that can move a verdict, and only because an operator asked.
- **Corrupt or edited memory** (not valid JSON, another schema, another target, over 8 MiB, content that does not match its digest) is moved aside as `<key>.json.corrupt-<run id>`; the run says so in its notes and plans from the profile alone. Never edit the file by hand: use `accept` and `forget`.
- `READYHAI_AGENT_MEMORY=off` switches it off for a run (CI that must not carry state); `readyhai agent-memory forget <target>` clears one target.

### Exit codes of `readyhai agent`
- `0`: gate verdict `GO`.
- `1`: `CONDITIONAL_GO` (conditions are listed in the summary).
- `2`: `NO_GO`, or `NOT_EVALUATED` (nothing conclusive ran, for example the target was unreachable).
- `3`: error (bad target, unusable scope file, I/O).

Reports and execution traces are persisted under `<data>/agent-runs/<run id>/` (`report.json`, `evidence/`, `cleanup.json`, `report/readyhai-report.{html,json,md,sarif,junit.xml}`).

---

## Target syntaxes

| Target | Example | Notes |
|---|---|---|
| Local path | `./my-service` | Must be an existing directory. Never scanned directly: a filtered snapshot is. |
| Git | `git:https://github.com/org/repo` | `https://`, `ssh://` or `git@` URLs only. Shallow clone with hooks disabled, then snapshotted; the clone is deleted. Uses host `git`. |
| Image | `image:myapp:1.4` | Must exist **locally** (`docker save` does not pull). Rejects empty, leading `-`, or whitespace refs. |
| Web | `https://staging.example.com` | `http://` or `https://`. A public host needs no `scope.toml` entry (it gets full testing unless listed `prod`); an internal host (localhost, RFC1918, metadata) must be listed or matched by a `*` entry. |
| Host | `ssh://deploy@10.0.0.5:2222 --os linux --key ~/.ssh/id_ed25519` | `user@host[:port]`, charset `[A-Za-z0-9._-]`. Host key must already be in `known_hosts`. |
| Android | `android:./app.apk --device emulator-5554` | `.apk` or `.aab` file. `--device` enables the runtime check; adb install needs an `.apk`. |

## Profiles

A check runs when its target kind matches and `profile >= check.min_profile` (`quick < standard < deep`).

| Profile | Adds |
|---|---|
| `quick` | Native readiness rules, native Tree-sitter AST audit (`security.code_audit`), gitleaks, SBOM+CVE, semgrep, hadolint, checkov, dockle, image inspect, `web.smoke` (headers, weak CSP, TLS cert/protocol), `host.probe`, `host.cve`, `android.mobsf` |
| `standard` | `tests.own`, `tool.opengrep`, `tool.osv_reachability`, `tool.scorecard`, Schemathesis, ZAP baseline, `tool.nuclei`, Playwright crawl, `host.lynis`, `android.runtime` |
| `deep` | Intrusive checks, which run only on a nonprod host (a public host not listed `prod` in `scope.toml`, or an entry with `env = "nonprod"`): `tool.zap_active` and `qa.resilience` (`readyhai qa` only, needs a `[hosts.resilience]` allow-list). `deep` also enables a monkey stress run on Android emulators and any plugin with `profile = "deep"`. |

The MCP server refuses `deep` unless `READYHAI_MCP_ALLOW_DEEP=1`.

## Reports

Written to `--out`:

| Format | File | Notes |
|---|---|---|
| html | `readyhai-report.html` | Single file, auto-escaped, CSP `default-src 'none'; style-src 'unsafe-inline'; img-src data:`, no JavaScript |
| json | `readyhai-report.json` | The full `Run` |
| sarif | `readyhai-report.sarif` | SARIF 2.1.0; `partialFingerprints["readyhai/v1"]`; suppressed findings carry `suppressions` |
| junit | `readyhai-report.junit.xml` | One `testsuite` per check; `failure` per new finding at or above medium; `error` for errored checks; `skipped` for skipped/n-a |

SARIF levels: critical/high -> `error`, medium -> `warning`, low/info -> `note`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | PASS (`scan`) / Go (`qa`) / `GO` (`agent`) |
| 1 | WARN / Conditional Go / `CONDITIONAL_GO` |
| 2 | FAIL / No-Go or Inconclusive / `NO_GO` or `NOT_EVALUATED` |
| 3 | Tool error (bad target, unreadable policy or scope file, IO error, ...); message on stderr as `readyhai: error: ...` |

`readyhai qa` exits with the worse of the recommendation and the gate verdict. A check that errors does not produce exit 3: it is reported as `errored` and, by default (`errored_fails = true` in the policy), fails the gate when the check is required (native, or its tool image is present); otherwise it raises the verdict to WARN. `readyhai eval` exits 0 or 1 (3 for a harness error), `readyhai ping` 0 or 1.

## Baseline workflow

By default the gate only counts **new** findings (`only_new = true`), so legacy debt does not block deploys.

```bash
readyhai scan .                                   # first run: no baseline, everything is "new"
readyhai baseline accept 20261025-101500-a1b2 --out .readyhai/baseline.json
git add .readyhai/baseline.json                   # commit it; CI agents have no local state
readyhai scan . --baseline .readyhai/baseline.json   # now only new findings gate
```

- Without `--out`, the baseline is stored at `<data>/baselines/<sha256(path or raw)[..16]>.json` and picked up automatically for the same target path.
- A baseline holds every non-suppressed fingerprint of the accepted run. Findings in it become `existing`; baseline entries not seen again are counted as `fixed` ("N fixed since baseline").
- The snapshot skips `.readyhai/`, so the committed baseline is not scanned.
- Suppressions are separate (target `readyhai.toml`) and need a reason and expiry.

## Worked examples

```bash
# 1. Fixture, no Docker
readyhai scan tests/fixtures/vuln-app --no-tools --format html,json

# 2. Repo with all scanners, SARIF for code scanning
readyhai scan . --profile quick --format html,sarif,junit --out readyhai-report

# 3. Repo including its own tests (readyhai.toml needs [test])
readyhai scan . --profile standard

# 4. Image
readyhai scan image:nginx:1.27

# 5. Web app with OpenAPI, scoped
readyhai scan https://staging.example.com --profile standard \
  --openapi https://staging.example.com/openapi.json --scope scope.toml

# 6. Linux host over SSH (host key must be in known_hosts: ssh-keyscan -p 22 host >> ~/.ssh/known_hosts after verifying)
readyhai scan ssh://ops@10.0.0.5 --os linux --profile standard

# 7. Android app with a connected emulator
readyhai scan android:./app.apk --device emulator-5554 --profile standard

# 8. With a plugin directory
readyhai scan . --plugins ./plugins

# 9. Autonomous Agentic AI QA with Evidence Ledger (localhost is internal: list it in scope.toml)
readyhai agent http://localhost:3000 --scope scope.toml --max-steps 5

# 9b. Local OWASP benchmark harness (deterministic suites, or live nonprod OWASP Juice Shop / VAmPI)
./scripts/bench_owasp.sh --suite
READYHAI_ALLOW_NONPROD=1 ./scripts/bench_owasp.sh --target http://127.0.0.1:3000 --profile deep

# 10. Web Studio UI (SPA) + REST API
# Start ReadyHai Backend API Engine (default port 8080)
readyhai serve --bind 127.0.0.1:8080

# 11. Universal GenAI & Agent Evaluator (RAG Quality Triad, Hallucinations, Trajectory, Red-Teaming)
# Single query evaluation with RAG context
readyhai eval-ai --query "What is the capital of France?" \
                 --context "Paris is the capital and most populous city of France." \
                 --response "The capital of France is Paris."

# Batch evaluation over JSON or JSONL dataset with adversarial red-teaming checks
readyhai eval-ai --dataset tests/eval/rag_bench.jsonl --red-team --format markdown --out eval-ai-report.json

# Agent tool trajectory efficiency and cyclic loop evaluation
readyhai eval-ai --trajectory agent_trace.json --threshold 0.80

# In a separate terminal or service, launch the Next.js 16 Agent Studio (port 3000):
cd frontend && npm run dev -- -p 3000
# Open http://127.0.0.1:3000, click the key icon and paste READYHAI_TOKEN (or run it under compose, which attaches it server-side).
# The backend's own `GET /` is a JSON endpoint index and needs the bearer token like every other route.
```

### NuHire

NuHire (`~/95095/Backup/Desktop/learn/nuhire`, 13 FastAPI/React services) is the reference platform. Services are separate git repos, so scan one service at a time:

```bash
readyhai scan ~/95095/Backup/Desktop/learn/nuhire/services/user-service --no-tools
readyhai scan ~/95095/Backup/Desktop/learn/nuhire/argocd --no-tools
```

Expected native findings for `user-service` (from the audit): no `USER` and no `HEALTHCHECK` in the Dockerfile, 24 of 25 dependencies unpinned in `requirements-docker.txt`, an unpinned `git+` shared-lib, no lockfile, a `curl` healthcheck on a slim image, prod compose without a healthcheck, tracked `.env.*` and `k8s/secret.yaml` (reported by path, never read), and Jenkins lacking SAST and secret stages. For `argocd/` there must be no `privileged` finding (it only appears in a comment) and worker Deployments without probes are flagged. The in-repo test `cargo test nuhire -- --ignored` prints these findings; see [development.md](development.md) for its limits.

## Senior-QA and offline workflow

```
readyhai qa <url> [--repo DIR] [--spec FILE|URL] [--roles roles.toml] [--journeys FILE] [--scope scope.toml]
                  [--profile quick|standard|deep] [--policy P] [--config C] [--baseline B]
                  [--format LIST] [--out DIR] [--no-tools] [--plugins DIR]
```

`--roles` also reads `READYHAI_ROLES`, `--scope` reads `READYHAI_SCOPE`. The same scope policy applies as for `scan`: a public host needs no entry, an internal host must be listed, a host listed `prod` gets read-only tests. Full guide: [qa.md](qa.md).

`qa` extra formats for `--format`: `html` (QA test summary `qa-report.html`), `pdf`, `md`, `jira`, `gitlab`, `testrail`, `xray` (plus `json`, `sarif`, `junit`). Default is `html,json`. Exit codes: the worse of the recommendation (Go 0, Conditional Go 1, No-Go and Inconclusive 2) and the gate verdict (PASS 0, WARN 1, FAIL 2); errors exit 3.

`baseline accept <run>` on a QA run also promotes the spec snapshot, the visual screenshots and the last perf result that run staged to the new baselines (one `baseline:` line each).

```bash
export RH_ALICE_TOKEN=... RH_BOB_TOKEN=...       # values referenced by roles.toml
readyhai qa https://app.nonprod.example --repo ./svc --spec openapi.json \
    --roles ~/.config/readyhai/secrets/app/roles.toml --scope scope.toml \
    --profile standard --format html,pdf,md,jira --out qa-out
readyhai dashboard --out dash/
```

### Large specs (1,000+ operations)

`qa` plans and tests the first **2000** operations of the spec (document order); the agent's spec-driven cases come from the same parser and share the cap (the agent also applies its own per-profile operation limits). `READYHAI_MAX_OPS` changes the number; it is clamped to a ceiling of **10000**, and a value that is not a positive integer falls back to 2000 with a note in the report.

```bash
READYHAI_MAX_OPS=5000 readyhai qa https://app.nonprod.example --spec openapi.json --roles roles.toml
```

- **Nothing over the cap is passed silently.** Each operation beyond it appears as `Untested` in the `functional` column of the coverage matrix, the first 25 are named in the report's out-of-scope list, and one roll-up line says how many there are (`N of M operation(s) are over the K-operation cap`) and how to raise the cap.
- **The request budget still bounds execution** (`max_requests`, 2000 per run). Operations the budget did not reach have their cases recorded as planned and skipped, and an `Untested` cell. Operations are tried highest plan risk first, so a small budget spends itself on the risky ones.
- **Memory is bounded.** A spec file or HTTP body over 64 MiB is refused. `$ref` expansion copies at most 50,000 nodes per path item and 6 million per spec; past that a ref collapses to `{}` ("any") and the report says that some schemas were truncated, so cases for those operations are weaker, not wrong.
- Building the spec, the plan, the cases and the coverage matrix is linear in the number of operations (a synthetic 1500-operation spec with nested `$ref` schemas parses, plans and generates cases in about a second in a debug build; the test asserts under 5 s).

The cap is an environment variable only: `ScanOpts` and the engine are shared, so there is no `--max-ops` flag.

### Generating roles.toml from the spec

```
readyhai roles init --spec openapi.json [--out roles.toml | --out -] [--force]
```

Reads a local OpenAPI 3.x file (JSON or YAML; a URL is refused, the command makes no requests) and writes a `roles.toml` skeleton in the format of [qa.md](qa.md#rolestoml):

| The spec says | The file gets |
|---|---|
| `components.securitySchemes`: `http` `bearer`, `oauth2`, `openIdConnect` | `auth = "bearer"`, `token_env = "RH_<ROLE>_TOKEN"` |
| `http` `basic` | `auth = "basic"`, `username_env = "RH_<ROLE>_USER"`, `password_env = "RH_<ROLE>_PASS"` |
| `apiKey` in a header | `auth = "header"`, `header_name` = the key name, `token_env` |
| `apiKey` in a cookie | `auth = "cookie"`, `storage_state = "<role>.state.json"` (record it with a logged-in test account) |
| `apiKey` in a query string, `mutualTLS` | not expressible in roles.toml: no role, a `# NOTE:` line |
| global `security` and per-operation `security` (an empty list = public) | which operations each role can reach; a role for a second scheme that only some operations accept is allowed those and denied the rest |
| OAuth2 scope names, `x-roles` / `x-required-roles` (operation, document or scheme level) | privileged names (`admin`, `root`, `superuser`, `internal`, `staff`, `sudo`) make an `admin` role plus ordinary `user` / `user2` (a second account of the same level, for BOLA); `x-roles` make one role per name |
| paths only a privileged scope or role reaches (or, with no scopes at all, a path with an `admin` or `internal` segment) | `deny` globs for the ordinary roles, `allow = ["/**"]` for admin |

The secret values never touch the file: only env var names. The header comment lists what to `export` (with `...` as the value). `allow` and `deny` are globs over the full request path, so the `servers[0].url` base path is part of them (`/api/v1/admin/**`); a subtree whose operations all agree becomes one `<prefix>/**` entry (plus the bare prefix when it is an operation itself), so 1000 admin paths are one glob. Globs match paths, not methods: when the methods of one path disagree, or neighbouring wildcards overlap (deny wins), no glob is written and a `# NOTE:` line in the header says which. The result is a starting point, so review it.

Without `--out` the file goes to `$XDG_CONFIG_HOME/readyhai/secrets/roles.toml` (default `~/.config/readyhai/secrets/roles.toml`), outside any repo; a missing directory is created mode 0700. The file is written mode **0600**, an existing file is refused unless `--force`, and a symlink at the target is always refused. `--out -` prints to stdout instead.

```bash
readyhai roles init --spec openapi.json --out ~/.config/readyhai/secrets/app/roles.toml
export RH_USER_TOKEN=... RH_USER2_TOKEN=... RH_ADMIN_TOKEN=...     # test accounts, never real users
readyhai qa https://app.nonprod.example --spec openapi.json --roles ~/.config/readyhai/secrets/app/roles.toml
```
