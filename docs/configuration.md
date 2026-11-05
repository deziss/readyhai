# Configuration

## Where things are read from

| File | Selected by | Default |
|---|---|---|
| `readyhai.toml` (per target) | `--config FILE` | `<repo>/readyhai.toml` in the scanned directory |
| `policy.toml` | `--policy FILE` | embedded copy of `policies/default.toml` |
| `scope.toml` | `--scope FILE` or `READYHAI_SCOPE` | none (public hosts get full testing, internal hosts are refused) |
| baseline JSON | `--baseline FILE` | `<data>/baselines/<hash>.json` |
| `tools.lock.toml` | `READYHAI_TOOLS_LOCK` | copy embedded in the binary at build time |
| plugins | `--plugins DIR` or `READYHAI_PLUGINS` | none |

Unknown keys in `readyhai.toml` are ignored (serde defaults), but a TOML syntax error aborts the scan with exit 3. In server mode (REST/MCP) `--policy` and `--config` cannot be passed: the default policy is used, and the target's own `readyhai.toml` is read.

## readyhai.toml

Per-target settings, normally committed in the repo root.

```toml
[[suppress]]
rule = "readiness.compose.privileged"   # rule id, prefix, or glob (e.g. "CVE-2024-*")
path = "services/coding-platform/**"    # optional glob against the finding's path
reason = "judge0 isolate needs privileged"
expires = "2027-03-31"                  # YYYY-MM-DD, required

[snapshot]
deny = ["**/judge0*.conf"]              # extra secret-bearing globs (withheld as empty placeholders)
skip_dirs = ["vendor", "third_party"]   # extra directory names to skip entirely

[test]
image = "myapp:dev"                     # image to run tests in (the built app image)
command = "pytest -q --junitxml=/out/junit.xml -p no:cacheprovider"
network = false                         # default false
timeout_secs = 900                      # default 900
```

| Section | Behavior |
|---|---|
| `[[suppress]]` | `reason` and `expires` are mandatory (parse error otherwise). A rule matches if the glob matches the finding's rule or the rule starts with the string. Expired entries are ignored and a note is printed: `suppression for 'X' expired on D - ignored`. Matched findings get `status = suppressed` and `suppressed_reason = "<reason> (until <expires>)"`. Suppressed findings stay in reports and never gate. |
| `[snapshot] deny` | Added to the built-in denylist. Matched case-insensitively against the relative path. |
| `[snapshot] skip_dirs` | Matched against directory base names. Built-in skips: `.git`, `node_modules`, `.venv`, `venv`, `__pycache__`, `target`, `.tox`, `.mypy_cache`, `.pytest_cache`, `dist`, `.next`, `.cache`, `.gradle`, `.idea`, `.readyhai`. |
| `[test]` | Required for `tests.own`. `/src` is read-only inside the container: write caches to `/tmp`. The command must write `/out/junit.xml`. |

Built-in denylist (never opened, replaced by empty placeholders): `.env`, `.env.*`, `*.env`, `*secret*.yaml|yml`, `*secrets*.json`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `*.csr`, `id_rsa*`, `id_ed25519*`, `id_ecdsa*`, `id_dsa*`, `creds*.{md,txt,json,yaml,yml,csv,ini,conf,cfg,toml,xml}`, `creds`, `*credential*.{...}`, `.npmrc`, `.pypirc`, `.netrc`, `.htpasswd`, `.dockercfg`, `.docker/config.json`, `*password*.{txt,json,yaml,yml,csv,ini,conf,cfg,toml}`, `*token*.json`, `robot$*.json`, `*.tfstate*`, `*.kdbx`, `backups/env_backup*`. Allowed even if matched: `*.example`, `*.sample`, `*.template`, `*.dist`, `*_example`, `*.example.*`, `.env.example*`, `.env.sample*`, `.env.template*`. Files over 20 MB are skipped. `reset_password.html` and `credentials_service.py` are intentionally **not** denied (earlier false positive, fixed).

## policy.toml

Embedded default (`policies/default.toml`):

```toml
fail_severity = "critical"    # FAIL at or above this
warn_severity = "medium"      # WARN at or above this
only_new = true               # gate only on findings new versus the baseline
kev_fails = true              # any KEV-listed vuln fails
hard_fail = [                 # rule-id prefixes that fail regardless of severity
  "secrets.",
  "readiness.repo.tracked_secret_file",
  "readiness.compose.privileged",
  "readiness.k8s.privileged",
  "tests.failed",
  "web.5xx",
  "api.server_error",
  "qa.api.server_error",
  "qa.api.crash_on_input",
]
errored_fails = true          # a required check that ends errored fails the gate (false: WARN)
```

The first five keys are required in a custom file (no per-key defaults); `errored_fails` is optional and defaults to `true`. Severities: `info`, `low`, `medium`, `high`, `critical`. Hard-fail matching is `rule.starts_with(prefix)`. A check is *required* when it is native or its tool image is present; an error caused by a missing image ("no such image", "pull access denied", ...) is only a WARN. Checks that were skipped because docker is not available add a WARN reason; `partial` checks raise the verdict to at least WARN.

## scope.toml

The operator's local copy lives next to `docker-compose.yml` and is git-ignored (it holds real hosts). Start from the template: `cp scope.example.toml scope.toml`. The template lists `host.docker.internal`, `localhost` and `127.0.0.1` as `nonprod`, ends with the global `*` / `nonprod` entry (so every host is testable unless you list it `prod` above it; order does not matter) and `[git] hosts = ["*"]`. Delete the `*` entry to test only the hosts you list plus public ones.

```toml
[[hosts]]
host = "app.nonprod.example"   # exact host, "*.suffix", or "*" for every host
env = "nonprod"                # "prod" | "nonprod"

[[hosts]]
host = "app.example.com"
env = "prod"

[[hosts]]
host = "*"                     # the shipped default: all other hosts are fully testable
env = "nonprod"

[git]
hosts = ["*"]                  # allowed git clone hosts; public code hosts are built in
```

Matching is case-insensitive on the URL host (userinfo and port stripped; `*.x` matches `a.x` but not `x`; `*` matches everything, internal hosts included). When several entries match, an exact entry beats a wildcard and `prod` beats `nonprod`; an `env` that is not literally `nonprod` counts as prod. The file order never matters. Behavior for web targets:

| Situation | Result |
|---|---|
| Public host, not listed | **Allowed, full testing**: it counts as `nonprod`, so non-intrusive scans, probes, discover, crawl, git clone and intrusive actions (writes, attack payloads, load, fault injection, agent swarm) all run. List it with `env = "prod"` to make it read-only |
| Internal host, not listed and no matching `*` entry | **Rejected**: `host 'h' is internal and not listed in scope.toml`. Internal = loopback, RFC1918, 169.254 metadata, CGNAT (100.64/10), unique-local/link-local v6, reserved/multicast, plus the names `localhost`, `*.localhost`, `host.docker.internal`, `gateway.docker.internal`, `metadata.google.internal`, whatever DNS returns for them. A name with any internal address counts as internal |
| Internal host, listed (or matched by `*`) | Allowed with its `env` (you vouch it is yours) |
| Host listed `prod` | Allowed; intrusive actions (writes, attacks, load) refused. Stays read-only even when a `*` `nonprod` entry also exists |
| Host listed `nonprod` | Allowed; intrusive checks may run with `--profile deep` |
| Unlisted name that does not resolve | Allowed for read-only actions; **intrusive actions are refused** (it cannot be classified) |
| Remote git clone, public code host | Allowed (github/gitlab/bitbucket/codeberg/sr.ht by default) |
| Remote git clone, internal host | Rejected unless listed under `[git] hosts = [...]` (or `*`) |
| Non-http(s) scheme, or git `ext::`/option-injection | Always rejected |

**A scope file that is configured but unusable is an error, never "no scope".** If `--scope` or `READYHAI_SCOPE` points at a path that is missing, is a directory, is unreadable or is not valid TOML, scans, the agent commands and the MCP tools fail with that reason, and `readyhai serve` refuses to start. A blank `READYHAI_SCOPE` counts as not set. With no scope file at all, public hosts are fully testable and internal hosts are refused. Under Docker, a missing `scope.toml` makes `docker compose up` create an empty *directory* of that name: remove it, run `cp scope.example.toml scope.toml` and recreate the container (`serve` says exactly this).

Scope applies to the target URL, an absolute `--openapi` URL, the `ssh://` host and the clone host. It does not cover redirects the target issues to other hosts (the HTTP client stays on the same host) or plugin network traffic (see [security-model.md](security-model.md)).

## Baseline JSON

```json
{
  "version": 1,
  "run_id": "20261025-101500-a1b2",
  "target": "./my-service",
  "accepted": "2026-10-25T10:20:00Z",
  "fingerprints": ["0123456789abcdef01234567", "..."]
}
```

Written by `baseline accept`, sorted set, safe to commit and diff. Only `fingerprints` is used when comparing.

## tools.lock.toml

```toml
[tools.grype]
image = "anchore/grype:latest"
digest = ""            # sha256:... once pinned
version = "latest"
```

Keys under `[tools]` (17): `syft`, `grype`, `gitleaks`, `semgrep`, `hadolint`, `checkov`, `dockle`, `zap`, `schemathesis`, `git`, `mobsf`, `k6`, `osv-scanner`, `scorecard`, `spectral`, `oasdiff`, `playwright`. 16 carry a `sha256` digest; `playwright` is built locally as `readyhai/playwright-runner:local` (or pulled from `ghcr.io/deziss/readyhai-playwright-runner`), so no registry digest exists. `git` is listed but not used by the code (git clones run on the host).

Resolution (`tools::image_for`): if `digest` starts with `sha256:` the image runs as `repo@sha256:...` (tag dropped), else as the tag. Unpinned images run, and the run adds a note per image: `tool image X unpinned (...) - run readyhai tools pull --lock`.

`readyhai tools pull --lock tools.lock.toml` runs `docker pull <image>` for every entry (pull failures, e.g. the `:local` playwright image, are printed and skipped), reads `RepoDigests[0]`, and rewrites the file with digests. This is trust-on-first-use: it pins whatever the registry served at that moment, so verify signatures yourself where the vendor publishes them, and review the diff. Commit the resulting file and set `READYHAI_TOOLS_LOCK` to it; otherwise the binary uses the lock embedded at its build time.

`readyhai tools update` is the only step that uses the network: `grype db update` in a network-enabled container into `<data>/cache/grype`; semgrep rules from `https://semgrep.dev/c/p/default` into `<data>/cache/semgrep/default.yml`; the Lynis 3.1.6 tarball from `downloads.cisofy.com` into `<data>/cache/lynis/` (checked against a published `.sha256` if one exists, else the hash is recorded as unverified).

## Plugins

A plugin is a directory `<plugin-dir>/<name>/plugin.toml`. Directories are loaded in name order; an unreadable or invalid `plugin.toml`, or one with no valid `kinds`, is silently skipped (check `readyhai checks` to confirm it loaded).

```toml
id = "bandit"                      # check id becomes plugin.bandit
title = "Bandit Python SAST"       # default: id
kinds = ["repo"]                   # any of repo, image, web (host/android are not supported)
profile = "quick"                  # quick | standard (default) | deep
image = "ghcr.io/pycqa/bandit@sha256:..."
args = ["-r", "{src}", "-f", "sarif", "-o", "/out/bandit.sarif"]
output = "/out/bandit.sarif"       # file inside /out the plugin writes
format = "sarif"                   # sarif | junit | readyhai-json
network = false                    # default false
entrypoint = "bandit"              # optional
```

| Field | Notes |
|---|---|
| Placeholders in `args` | `{src}` -> `/src`, `{out}` -> `/out`, `{url}` -> target URL (empty for non-web), `{image_tar}` -> `/src/image.tar` |
| Sandbox | Same hardening as built-in tools (net none unless `network = true`, caps dropped, read-only rootfs, non-root, `/src` ro, `/out` rw). Container-create policy applies. |
| `sarif` | `runs[].results[]` mapped: `ruleId`, `level` (error high, warning medium, note low, none info), first physical location, message first line. Category `security`. fp = `uri|rule|hash(message)` |
| `junit` | Failed cases become `tests.failed` findings (same rules as `tests.own`); errors-only is `errored` |
| `readyhai-json` | A JSON array of `Finding` objects (see [architecture.md](architecture.md#data-model)); `check` is overwritten with `plugin.<id>` |
| Unpinned image | Status `partial("plugin image unpinned")` and a pin warning. Use `@sha256:` |
| Failure | Missing output file -> `errored` with the container exit code and stderr tail |

Plugins cannot be marked intrusive.

## Environment variables

**Server and data**

| Variable | Used by | Meaning |
|---|---|---|
| `READYHAI_DATA` | all | Data directory (runs, baselines, cache, agent runs, memory). Default `$XDG_DATA_HOME/readyhai`, else `~/.local/share/readyhai`. The image sets `/data`. |
| `READYHAI_DATA_VOLUME` | container mode | Name of the Docker volume mounted at the data dir. When set, tool containers mount `/src`, `/out`, `/cache` by **volume subpath** instead of bind mounts. Compose sets `readyhai_data`. |
| `READYHAI_TOKEN` | `serve`, frontend container | Bearer token for the REST API; at least 16 printable ASCII characters or `serve` refuses to start (exit 3). The frontend container attaches it server-side when the browser sent no `Authorization` header. |
| `READYHAI_PRINCIPAL` | `serve` | Name recorded on sign-offs (`[A-Za-z0-9._@:-]`, at most 64, default `api-token`). |
| `READYHAI_ALLOWED_ROOTS` | `serve`, `mcp` | Colon-separated directories that repo paths, APKs and the agent's `repo` must be under. MCP defaults to the current directory if unset; REST with none configured refuses paths. Compose sets `/targets`. |
| `READYHAI_RUN_TIMEOUT_SECS` | `serve` | Wall-clock deadline of one scan run (default 3600, clamped to 60 to 86400). Late checks are skipped and the run ends as `error`. |
| `READYHAI_PLUGINS` | `scan`, `qa`, `checks`, `serve`, `mcp` | Plugin directory. |
| `READYHAI_TOOLS_LOCK` | all tool runs | Path to a lock file overriding the embedded one. |
| `READYHAI_GIT_TIMEOUT_SECS` | git clones, `agent --diff-base` | Wall-clock limit of a `git clone` (default 300, 10 to 3600, never longer than the run deadline) and of the agent's `git diff` (default 60, 5 to 3600). |
| `READYHAI_PUBLIC_IP`, `READYHAI_EGRESS_IP` | network lab, agent | Egress IP to report instead of asking public IP-echo services (api.ipify.org, checkip.amazonaws.com, icanhazip.com, ifconfig.me). |

**Scope and MCP**

| Variable | Used by | Meaning |
|---|---|---|
| `READYHAI_SCOPE` | `scan`, `qa`, `agent`, `serve`, `mcp` | Path to `scope.toml` (also the `--scope` fallback). Set but missing, a directory, unreadable or invalid is an error (`serve` will not start); blank counts as unset. Compose sets `/config/scope.toml` and mounts your `./scope.toml` there. |
| `READYHAI_MCP_ALLOW_DEEP` | `mcp` | `1` allows `profile: deep` for `readyhai_scan` over MCP. |
| `READYHAI_MCP_ALLOW_WRITES` | `mcp` | `1` allows `readyhai_agent_swarm` to run with `dry_run: false` (state-changing requests). Without it MCP swarms are dry runs; with it the target must still not be listed `prod`. |

**Agent**

| Variable | Used by | Meaning |
|---|---|---|
| `READYHAI_VERIFY_K` | `agent`, REST, MCP, `eval` | Replays of every failed case before it becomes a defect. Default 2, at most 5, `0` turns the verifier off (failures then count as found; the ledger says so). |
| `READYHAI_AGENT_WORKERS` | `agent`, REST, MCP | Area worker threads of the lead (`auth`, `contract`, `state`, `ui`). Default 4, at most 8, `1` runs the areas one after another with the same results. The per-host rate is shared by all workers. See [architecture.md](architecture.md#lead-and-area-workers-srcagentleadrs). |
| `READYHAI_AGENT_MEMORY` | `agent`, REST, MCP | `off` (also `0`, `false`, `no`, `none`) turns the per-target memory off for the process: runs plan from the profile alone, read no memory and write none, and the report has no "Since last run". Anything else: on. `readyhai agent-memory ...` and `/api/agent/memory` work either way. See [architecture.md](architecture.md#per-target-memory-srcagentmemoryrs). |
| `READYHAI_AGENT_MAX_STEPS`, `_MAX_REQUESTS`, `_MAX_SECONDS`, `_RATE_PER_HOST`, `_MAX_LLM_CALLS` | `agent`, REST, MCP | Run budget defaults, see "Agent run budget" below. `--max-steps` and the request's `max_steps` override the first. |
| `RH_<ROLE>_TOKEN` | `agent`, `qa` | Test credentials: the token of role `<ROLE>` (the role name upper-cased, non-alphanumerics become `_`). The agent acts as `RH_USER_TOKEN`, else `RH_ALICE_TOKEN`, else the first role whose name does not look privileged; stateful chains use alice and bob; an admin token is never picked to probe with. Read only from the environment, attached only to requests for the run's own target (scheme, host and port equal), never written to reports, curls or memory. Without a credential, secured operations are probed without one and a note says so. |
| `READYHAI_CONTEXT_INDEX` | `agent --diff-base` | Directory of a context-retriever index (`manifest.json` + `chunks.jsonl`). Default `<repo>/.readyhai/context-index`. |
| `READYHAI_CONTEXT_RETRIEVER` | `agent --diff-base` | Command to run instead of `python3 -m runners.context_retriever.main`. |
| `READYHAI_CONTEXT_TIMEOUT_SECS` | `agent --diff-base` | Retriever timeout (default 60, 5 to 300). |
| `READYHAI_HOME` | `agent --diff-base` | Checkout that holds `runners/context_retriever` when readyhai is not run from it. |

**LLM** (optional; used by `qa` enrichment and the agent; without a reachable endpoint everything runs deterministically)

| Variable | Used by | Meaning |
|---|---|---|
| `READYHAI_LLM_PROVIDER` | `qa`, `agent` | `vllm` (default), `ollama`, or cloud `openai`, `anthropic`, `openrouter`. |
| `READYHAI_LLM_MODEL` | `qa`, `agent` | Model override; defaults per provider: `qwen3.8-flash-next` (vllm), `qwen2.5-coder` (ollama), `gpt-4.1`, `claude-sonnet-5-5`, `anthropic/claude-sonnet-5-5`. |
| `READYHAI_VLLM_URL` | `qa`, `agent` | OpenAI-compatible base URL of the `vllm` provider (no built-in address). |
| `READYHAI_LLM_ALLOW_CLOUD` | `qa`, `agent` | `1` / `true` required for cloud providers; otherwise the config is refused. |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY` | `qa`, `agent` | Provider keys, read only when that provider is selected. |

See [offline.md](offline.md#lan-llm-mode).

**QA, scanners and offline**

| Variable | Used by | Meaning |
|---|---|---|
| `READYHAI_ROLES` | `qa` | roles.toml path (fallback for `--roles`). |
| `READYHAI_LICENSE_DENY` | `qa.release.licenses` | Extra denied licences, comma separated (added to `[license] deny`). |
| `READYHAI_PLAYWRIGHT_IMAGE` | `qa.ui`, `tool.playwright`, PDF | Runner image. Else the local `readyhai/playwright-runner:local`, else `ghcr.io/deziss/readyhai-playwright-runner:latest`. |
| `READYHAI_GITHUB_TOKEN` | `tool.scorecard` | GitHub token for OpenSSF Scorecard (passed to the container by name as `GITHUB_AUTH_TOKEN`). Without it the check is skipped. |
| `READYHAI_OFFLINE` | all | `1`/`true`: no pulls, no DB updates, no `bundle export`; the LAN LLM still works (mode `offline+lan-llm`). |
| `READYHAI_BUNDLE_TOOLS` | `bundle export` | Comma-separated tool names to restrict the bundle. |

**Eval**

| Variable | Used by | Meaning |
|---|---|---|
| `READYHAI_EVAL_PYTHON` | `eval` | Python used for the fixture servers (default `python3`). |
| `READYHAI_EVAL_KEEP` | `eval` | Set to keep the per-run data directories (their parent is printed). |
| `EVAL_SUITES`, `EVAL_K`, `EVAL_OUT` | the ignored `live_eval` test | Suites, k and output directory of `cargo test eval::tests::live_eval -- --ignored`. |

`eval` sets `READYHAI_DATA`, `READYHAI_SCOPE`, `READYHAI_OFFLINE=1` for each run and unsets the LLM, plugin, roles and agent-budget variables (`READYHAI_AGENT_WORKERS` and `READYHAI_AGENT_MEMORY` included) so the host's setup cannot change a score.

**Compose, frontend and system**

| Variable | Used by | Meaning |
|---|---|---|
| `READYHAI_IMAGE`, `READYHAI_FRONTEND_IMAGE` | compose | Image overrides (`ghcr.io/deziss/readyhai:latest`, `ghcr.io/deziss/readyhai-frontend:latest`). |
| `READYHAI_PORT`, `FRONTEND_PORT` | compose | Loopback ports (default 8080 and 3000). |
| `TARGETS_DIR`, `SCOPE_FILE` | compose | Host directory mounted at `/targets` (default `./targets`) and the scope file mounted at `/config/scope.toml` (default `./scope.toml`). |
| `READYHAI_BACKEND_URL`, `PORT` | frontend | Backend URL (default `http://127.0.0.1:8080`, compose sets `http://readyhai:8080`) and the UI port (3000). |
| `DOCKER_HOST` | docker CLI | Standard docker CLI variable; compose points it at the socket proxy. |
| `SSH_AUTH_SOCK` | host scans | ssh-agent socket. Server mode requires either it or `--key` for `ssh://` targets. |
| `XDG_DATA_HOME`, `HOME` | data dir | Default data location. |

Tool containers receive **no** environment from the host. The runner passes only `HOME=/tmp` plus tool-specific variables it sets itself (for example `GRYPE_DB_AUTO_UPDATE=false`, `GRYPE_DB_CACHE_DIR=/cache/grype`, `SYFT_CHECK_FOR_APP_UPDATE=false`, `CKV_IGNORE_HIDDEN_DIRECTORIES=true`, `PLAYWRIGHT_BROWSERS_PATH`); a secret such as the GitHub token is passed by name so its value never appears in `ps`.

The context-retriever runner (`runners/context_retriever`, Python) has its own variables: `READYHAI_EMBEDDING_BACKEND` (`ollama` default, `vllm`, `huggingface`), `READYHAI_EMBEDDING_MODEL`, `READYHAI_EMBEDDING_API_KEY`, `READYHAI_LLM_API_KEY`, `READYHAI_DEVICE` (`cpu` default), plus `READYHAI_VLLM_URL` and `READYHAI_LLM_MODEL` for synthesis. See its README.

### Agent run budget

A run is bounded by a `RunBudget`: steps (executed cases), requests (every HTTP request including discovery, replays and cleanup), wall clock, per-host rate and LLM calls. Defaults come from code and the variables above:

| Limit | Default | Variable |
|---|---|---|
| steps | 60 (the CLI passes `--max-steps`, default 5; MCP 15; REST and the Studio as requested, clamped to 1..=50) | `READYHAI_AGENT_MAX_STEPS` |
| requests | 600 | `READYHAI_AGENT_MAX_REQUESTS` |
| wall clock | 900 s | `READYHAI_AGENT_MAX_SECONDS` |
| requests per second per host | 10 | `READYHAI_AGENT_RATE_PER_HOST` (`0` disables pacing) |
| LLM calls | 20 | `READYHAI_AGENT_MAX_LLM_CALLS` |

The lead divides these into per-area slices; the rate limit stays global. A limit that binds ends the run early, records why (`stopped`) and marks the unrun cases SKIPPED, which lowers coverage.

## QA configuration

### roles.toml
Test accounts for `readyhai qa --roles` (or `READYHAI_ROLES`). Keep it outside the target repo, `chmod 600`. Per `[[role]]`: `name` (`[A-Za-z0-9_-]`, unique), `auth` (`bearer|basic|header|cookie|none`), `token_env`, `header_name` (default `X-API-Key`), `username_env`/`password_env`, `storage_state` (path relative to roles.toml), `allow`/`deny` glob lists. Values are env-var **names**; secrets are read at request time. Schema and example: [qa.md](qa.md#rolestoml).

### `[license]` in readyhai.toml
```toml
[license]
deny = ["AGPL-3.0*", "GPL-3.0*"]
```
`READYHAI_LICENSE_DENY` (comma separated) is added to the list. Used by `qa.release.licenses`.

### scope.toml perf and resilience
```toml
[[hosts]]
host = "app.nonprod.example"
env  = "nonprod"
[hosts.perf]                 # k6 limits; hard caps 10 VUs / 120 s unless allow_heavy
vus = 8
duration_secs = 90
max_error_rate = 0.05
allow_heavy = false
[hosts.resilience]           # deep profile; only these compose services are paused
compose_project = "shop"
services = ["postgres", "redis"]
```
Defaults without `[hosts.perf]`: 5 VUs, 60 s, abort above 5% errors. Writes, load and fault injection run only on a nonprod host (a public host that is not listed `prod`, or an entry with `env = "nonprod"`); fault injection additionally needs the `[hosts.resilience]` allow-list.

Lock precedence: `READYHAI_TOOLS_LOCK` > `<data>/tools.lock.toml` > embedded. Lock entries may carry an image `id`, which is run by ID.

Data dir additions: `<data>/baselines/<key>.perf.json`, `<key>.perf.last.json`, `<data>/baselines/<key>/visual/*.png`, `<data>/index.jsonl`, `<data>/llm-cache/`, `<data>/bundles/`, `<data>/cache/endoflife.json`, `<data>/agent-runs/<run_id>/{report.json,evidence/,cleanup.json,report/}` (plus `<data>/agent-runs/.locks/`), `<data>/memory/<target_key>.json` (the agent's memory of a target; `<key>.json.corrupt-<run id>` is a file that failed its checks and was set aside).

### Agent memory

Nothing needs configuring: `readyhai agent`, `POST /api/agent/run` and `readyhai_agent_swarm` keep a memory per target under `<data>/memory/` unless `READYHAI_AGENT_MEMORY=off`. The target is the URL as given, reduced to scheme, host, port and path (`http://h:8080` and `http://h:8080/` are one target; a different path or port is another). Fixed limits (no setting): the last 50 runs, 90 days for a defect that is not seen again, 20 flaky outcomes per case class, 30 days of re-testing a fixed defect first, 8 MiB per file. Delete one target with `readyhai agent-memory forget <target>` or `DELETE /api/agent/memory?target=`; delete them all by removing `<data>/memory/`. Back up or move the directory like the rest of `<data>`; it holds endpoint templates and defect fingerprints, no response bodies, no credentials, no LLM text.
