# Configuration

## Where things are read from

| File | Selected by | Default |
|---|---|---|
| `readyhai.toml` (per target) | `--config FILE` | `<repo>/readyhai.toml` in the scanned directory |
| `policy.toml` | `--policy FILE` | embedded copy of `policies/default.toml` |
| `scope.toml` | `--scope FILE` or `READYHAI_SCOPE` | none |
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
]
```

All five keys are required in a custom file (no per-key defaults). Severities: `info`, `low`, `medium`, `high`, `critical`. Hard-fail matching is `rule.starts_with(prefix)`.

## scope.toml

```toml
[[hosts]]
host = "app.nonprod.example"   # exact host or "*.suffix"
env = "nonprod"                # "prod" | "nonprod"

[[hosts]]
host = "app.example.com"
env = "prod"
```

Matching is case-insensitive on the URL host (userinfo and port stripped; `*.x` matches `a.x` but not `x`). Behavior for web targets:

| Situation | Result |
|---|---|
| Server/MCP, no scope file | Rejected: `web targets must be listed in scope.toml` |
| Scope file given, host not listed | Rejected: `host 'h' is not in scope.toml` (CLI too) |
| CLI, no scope file | Allowed, treated as non-nonprod |
| Host listed `prod` | Allowed; intrusive checks skipped |
| Host listed `nonprod` | Allowed; intrusive checks may run with `--profile deep` |

Scope applies only to the target URL. It does not cover redirects, the `--openapi` URL, or plugin network traffic (see [security-model.md](security-model.md)).

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

Keys under `[tools]`: `syft`, `grype`, `gitleaks`, `semgrep`, `hadolint`, `checkov`, `dockle`, `zap`, `schemathesis`, `git`, `mobsf`, `playwright` (the last is built locally as `readyhai/playwright-runner:local`, so no registry digest exists). `git` is listed but not used by the code (git clones run on the host).

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

| Variable | Used by | Meaning |
|---|---|---|
| `READYHAI_DATA` | all | Data directory (runs, baselines, cache). Default `$XDG_DATA_HOME/readyhai`, else `~/.local/share/readyhai`. Image sets `/data`. |
| `READYHAI_DATA_VOLUME` | container mode | Name of the Docker volume mounted at the data dir. When set, tool containers mount `/src`, `/out`, `/cache` by **volume subpath** instead of bind mounts. Compose sets `readyhai_data`. |
| `READYHAI_TOKEN` | `serve` | Bearer token for the REST API; at least 16 characters or `serve` refuses to start. |
| `READYHAI_ALLOWED_ROOTS` | `serve`, `mcp` | Colon-separated directories that repo paths and APKs must be under. MCP defaults to the current directory if unset. Compose sets `/targets`. |
| `READYHAI_SCOPE` | `scan`, `serve`, `mcp` | Path to `scope.toml`. Also a `--scope` fallback. |
| `READYHAI_PLUGINS` | `scan`, `checks`, `serve`, `mcp` | Plugin directory. |
| `READYHAI_TOOLS_LOCK` | all tool runs | Path to a lock file overriding the embedded one. |
| `READYHAI_MCP_ALLOW_DEEP` | `mcp` | `1` allows `profile: deep` over MCP. |
| `READYHAI_LLM_PROVIDER` | `llm.rs` (unused) | `ollama`, `vllm`, `openai`, `anthropic`, `openrouter`. |
| `READYHAI_LLM_MODEL` | `llm.rs` (unused) | Model override; default per provider (`qwen2.5-coder`, `default`, `gpt-4.1`, `claude-sonnet-5-5`, `anthropic/claude-sonnet-5-5`). |
| `READYHAI_LLM_ALLOW_CLOUD` | `llm.rs` (unused) | `1`/`true` required for cloud providers. |
| `READYHAI_VLLM_URL` | `llm.rs` (unused) | Base URL for the `vllm` provider. |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY` | `llm.rs` (unused) | Provider keys, read only when an LLM client is used. |
| `DOCKER_HOST` | docker CLI | Standard docker CLI variable; compose points it at the socket proxy. |
| `SSH_AUTH_SOCK` | host scans | ssh-agent socket. Server mode requires either it or `--key` for `ssh://` targets. |
| `XDG_DATA_HOME`, `HOME` | data dir | Default data location. |
| `TARGETS_DIR`, `READYHAI_PORT` | compose only | Host directory mounted at `/targets` (default `./targets`) and the loopback port (default 8080). |

Tool containers receive **no** environment from the host. The runner passes only `HOME=/tmp` plus tool-specific variables it sets itself (for example `GRYPE_DB_AUTO_UPDATE=false`, `GRYPE_DB_CACHE_DIR=/cache/grype`, `SYFT_CHECK_FOR_APP_UPDATE=false`, `CKV_IGNORE_HIDDEN_DIRECTORIES=true`, `PLAYWRIGHT_BROWSERS_PATH`).

## QA configuration (increment 2)

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
Defaults without `[hosts.perf]`: 5 VUs, 60 s, abort above 5% errors. Writes, load and fault injection need `env = "nonprod"`.

### Environment variables added
| Variable | Used by | Meaning |
|---|---|---|
| `READYHAI_ROLES` | `qa` | roles.toml path (fallback for `--roles`) |
| `READYHAI_LICENSE_DENY` | `qa.release.licenses` | extra denied licences, comma separated |
| `READYHAI_OFFLINE` | all | `1`/`true`: no pulls, no DB updates, no `bundle export`; disables the LLM in `qa` |
| `READYHAI_BUNDLE_TOOLS` | `bundle export` | comma-separated tool names to restrict the bundle |
| `READYHAI_LLM_PROVIDER`, `READYHAI_LLM_MODEL`, `READYHAI_LLM_ALLOW_CLOUD`, `READYHAI_VLLM_URL` | `qa` | LAN LLM enrichment, now used (no longer "unused"). Setting only `READYHAI_VLLM_URL` selects `vllm` with default model `Qwen/Qwen3-8B`. See [offline.md](offline.md#lan-llm-mode) |

Lock precedence (increment 2): `READYHAI_TOOLS_LOCK` > `<data>/tools.lock.toml` > embedded. Lock entries may carry an image `id`, which is run by ID.

Data dir additions: `<data>/baselines/<key>.perf.json`, `<key>.perf.last.json`, `<data>/baselines/<key>/visual/*.png`, `<data>/index.jsonl`, `<data>/llm-cache/`, `<data>/bundles/`, `<data>/cache/endoflife.json`.
