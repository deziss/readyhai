# Usage

Binary: `readyhai` (dev build: `target/debug/readyhai`; `cargo` lives in `~/.cargo/bin`, add it to PATH). Version: `readyhai --version`.

## Commands

| Command | Purpose |
|---|---|
| `readyhai scan <target> [flags]` | Scan a target, write reports, exit with the verdict code |
| `readyhai baseline accept <run> [--out FILE]` | Accept a run's findings as the baseline |
| `readyhai checks` | List registered checks (reads `READYHAI_PLUGINS` for plugins) |
| `readyhai tools pull [--lock FILE]` | `docker pull` every image in `tools.lock.toml`; optionally write resolved digests |
| `readyhai tools update` | Refresh grype DB, semgrep rules, Lynis tarball (the only networked step) |
| `readyhai agent <target> [--max-steps N]` | Autonomous Agentic AI QA run (Planner -> Explorer -> Triager -> Readiness Gate) |
| `readyhai serve [--bind ADDR]` | High-performance REST API + async engine; auto-redirects to Next.js Agent Studio (default `127.0.0.1:8080`) |
| `readyhai mcp` | MCP server on stdio (tools: scan, checks, run, findings) |
| `readyhai ping [--url URL]` | Container HEALTHCHECK probe (default `http://127.0.0.1:8080/health`), exit 0 healthy / 1 not |

### `scan` flags

| Flag | Default | Notes |
|---|---|---|
| `<target>` | required | See target syntaxes below |
| `--profile quick\|standard\|deep` | `quick` | See profiles |
| `--openapi URL` | none | OpenAPI spec for web targets. Else `/openapi.json`, `/docs/openapi.json`, `/api/openapi.json`, `/swagger.json` are probed |
| `--policy FILE` | embedded `policies/default.toml` | Gate policy; see [configuration.md](configuration.md) |
| `--scope FILE` (env `READYHAI_SCOPE`) | none | `scope.toml` rules of engagement for web targets |
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

Every scan and test run in ReadyHai is persistently archived on disk in `~/.local/share/readyhai/agent-runs/`:
- **Active URL Reconnaissance Scans (`/api/agent/discover`):** Automatically saves route classifications (API vs SPA fallback), synthesized baseline test vectors, probe latencies, and initial evidence ledger.
- **Autonomous Swarm Test Runs (`/api/agent/run`):** Archives full 4-agent trace logs, adversarial payloads, live response bodies, reproduction cURL commands, OWASP threat clusters, and signed governance gate verdicts.
- **Live Re-Testing in Browser:** Retesting any individual scenario via the UI or `POST /api/agent/retest` executes a live browser probe and mutates the persisted run record on disk with updated latencies and assertion proofs.
- **Run Management & Deletion:** The UI "Runs History" tab renders distinct `SCAN` vs `TEST RUN` badges, test case counts, defect metrics, and an instant deletion action via `DELETE /api/agent/runs/{id}`.

## Autonomous Agentic AI (`readyhai agent`)

Executes an autonomous multi-agent QA testing loop powered by local reasoning models (vLLM / Ollama):

```bash
readyhai agent http://localhost:3000 --max-steps 5
```

### The 4-Agent Pipeline:
1. **Planner Agent:** Synthesizes boundary cases, negative inputs, RBAC abuse vectors, and OWASP Top 10 exploits based on target facts and endpoints.
2. **Explorer Agent:** Dispatches tests, records sub-millisecond latencies, collects HTTP responses, and captures exact `reproduction_curl` commands.
3. **Triager Agent:** Groups failed probes into deduplicated defect clusters and calculates OWASP blast radius.
4. **Production Readiness Gate:** Scores the 4-pillar **Evidence Ledger** (`Value`, `Authority`, `Safety`, `Evidence`) and issues an automated deployment verdict (`GO`, `CONDITIONAL_GO`, `NO_GO`).

### Flags:
- `<target>`: Target URL or codebase path (required).
- `--max-steps <N>`: Maximum autonomous exploration iterations (default: 5).

### Exit Codes:
- `0`: Gate verdict `GO` (production-ready).
- `1`: Gate verdict `CONDITIONAL_GO` or `NO_GO` (readiness criteria violated).

Reports and execution traces are persisted under `<data_dir>/agent-runs/<run_id>/report.json`.

---

## Target syntaxes

| Target | Example | Notes |
|---|---|---|
| Local path | `./my-service` | Must be an existing directory. Never scanned directly: a filtered snapshot is. |
| Git | `git:https://github.com/org/repo` | `https://`, `ssh://` or `git@` URLs only. Shallow clone with hooks disabled, then snapshotted; the clone is deleted. Uses host `git`. |
| Image | `image:myapp:1.4` | Must exist **locally** (`docker save` does not pull). Rejects empty, leading `-`, or whitespace refs. |
| Web | `https://staging.example.com` | `http://` or `https://`. Server mode requires the host in `scope.toml`. |
| Host | `ssh://deploy@10.0.0.5:2222 --os linux --key ~/.ssh/id_ed25519` | `user@host[:port]`, charset `[A-Za-z0-9._-]`. Host key must already be in `known_hosts`. |
| Android | `android:./app.apk --device emulator-5554` | `.apk` or `.aab` file. `--device` enables the runtime check; adb install needs an `.apk`. |

## Profiles

A check runs when its target kind matches and `profile >= check.min_profile` (`quick < standard < deep`).

| Profile | Adds |
|---|---|
| `quick` | Native readiness rules, gitleaks, SBOM+CVE, semgrep, hadolint, checkov, dockle, image inspect, `web.smoke`, `host.probe`, `host.cve`, `android.mobsf` |
| `standard` | `tests.own`, Schemathesis, ZAP baseline, Playwright crawl, `host.lynis`, `android.runtime` |
| `deep` | Intrusive checks, which run only on a `nonprod` host from `scope.toml`. **No built-in check is intrusive yet.** Today `deep` additionally enables a monkey stress run on Android emulators and any plugin with `profile = "deep"`. |

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
| 0 | PASS |
| 1 | WARN |
| 2 | FAIL |
| 3 | Tool error (bad target, unreadable policy, IO error, ...); message on stderr as `readyhai: error: ...` |

A check that errors does not produce exit 3: it is reported as `errored` and raises the verdict to at least WARN.

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

# 9. Autonomous Agentic AI QA with Evidence Ledger
readyhai agent http://localhost:3000 --max-steps 5

# 10. Web Studio UI (SPA) + REST API
# Start ReadyHai Backend API Engine (default port 8080)
readyhai serve --bind 127.0.0.1:8080

# In a separate terminal or service, launch the Next.js 16 Agent Studio (port 3000):
cd frontend && npm run dev -- -p 3000
# Open http://127.0.0.1:3000 in your browser for the full cyber-dark studio interface.
# (Visiting http://127.0.0.1:8080 in a browser automatically redirects you to port 3000)
```

### NuHire

NuHire (`~/95095/Backup/Desktop/learn/nuhire`, 13 FastAPI/React services) is the reference platform. Services are separate git repos, so scan one service at a time:

```bash
readyhai scan ~/95095/Backup/Desktop/learn/nuhire/services/user-service --no-tools
readyhai scan ~/95095/Backup/Desktop/learn/nuhire/argocd --no-tools
```

Expected native findings for `user-service` (from the audit): no `USER` and no `HEALTHCHECK` in the Dockerfile, 24 of 25 dependencies unpinned in `requirements-docker.txt`, an unpinned `git+` shared-lib, no lockfile, a `curl` healthcheck on a slim image, prod compose without a healthcheck, tracked `.env.*` and `k8s/secret.yaml` (reported by path, never read), and Jenkins lacking SAST and secret stages. For `argocd/` there must be no `privileged` finding (it only appears in a comment) and worker Deployments without probes are flagged. The in-repo test `cargo test nuhire -- --ignored` prints these findings; see [development.md](development.md) for its limits.

## Senior-QA and offline commands (increment 2)

| Command | Purpose |
|---|---|
| `readyhai qa <url> [--repo DIR] [--spec FILE\|URL] [--roles roles.toml] [--journeys FILE] [--scope scope.toml] [--profile quick\|standard\|deep] [--policy P] [--config C] [--baseline B] [--format LIST] [--out DIR] [--no-tools] [--plugins DIR]` | Senior-QA run: API/UI tests, auth matrix, perf, suite/release quality, QA test summary report with Go / Conditional Go / No-Go. `--roles` = `READYHAI_ROLES`, `--scope` = `READYHAI_SCOPE`. Full guide: [qa.md](qa.md) |
| `readyhai bundle export [--out FILE] [--set core\|full] [--with-model FILE.gguf]` | Build an offline bundle (defaults: `readyhai-bundle.tar`, `core`). See [offline.md](offline.md) |
| `readyhai bundle import <bundle.tar>` | Verify and install a bundle into the data dir |
| `readyhai doctor` | Mode (offline / lan-llm / deterministic), tool presence, grype DB age, LLM reachability, disk |
| `readyhai dashboard [--out DIR]` | Static offline trend dashboard from `<data>/index.jsonl` (default `readyhai-dashboard`) |

`qa` extra formats for `--format`: `html` (QA test summary `qa-report.html`), `pdf`, `md`, `jira`, `gitlab`, `testrail`, `xray` (plus `json`, `sarif`, `junit`). Default is `html,json`. Exit codes are the same as `scan`.

`baseline accept <run>` on a QA run also promotes the last perf result to the perf baseline.

```bash
export RH_ALICE_TOKEN=... RH_BOB_TOKEN=...       # values referenced by roles.toml
readyhai qa https://app.nonprod.example --repo ./svc --spec openapi.json \
    --roles ~/.config/readyhai/secrets/app/roles.toml --scope scope.toml \
    --profile standard --format html,pdf,md,jira --out qa-out
readyhai dashboard --out dash/
```
