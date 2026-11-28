# Configuration

## Where things are read from

| File | Selected by | Default |
|---|---|---|
| `readyhai.toml` (per target) | `--config FILE` | `<repo>/readyhai.toml` in the scanned directory |
| `policy.toml` | `--policy FILE` | embedded copy of `policies/default.toml` |
| `scope.toml` | `--scope FILE` or `READYHAI_SCOPE` | none (public hosts get full testing, internal hosts are refused) |
| baseline JSON | `--baseline FILE` | `<data>/baselines/<hash>.json` |
| `settings.toml` | `--settings FILE` or `READYHAI_SETTINGS` | none (every integration `auto`) |
| `rbac.toml` | `READYHAI_RBAC_FILE` (serve) | none = RBAC off |
| `tools.lock.toml` | `READYHAI_TOOLS_LOCK` | copy embedded in the binary at build time |
| plugins | `--plugins DIR` or `READYHAI_PLUGINS` | none |
| vuln database | `[vulndb] path` in `settings.toml` | `<data>/vulns/vulns.jsonl` (written on the first recorded finding) |

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

Keys under `[tools]` (19): `syft`, `grype`, `gitleaks`, `semgrep`, `opengrep`, `hadolint`, `checkov`, `dockle`, `zap`, `nuclei`, `schemathesis`, `git`, `mobsf`, `k6`, `osv-scanner`, `scorecard`, `spectral`, `oasdiff`, `playwright`. 18 carry a `sha256` digest; `playwright` is built locally as `readyhai/playwright-runner:local` (or pulled from `ghcr.io/deziss/readyhai-playwright-runner`), so no registry digest exists. `git` is listed but not used by the code (git clones run on the host).

Resolution (`tools::image_for`): if `digest` starts with `sha256:` the image runs as `repo@sha256:...` (tag dropped), else as the tag. Unpinned images run, and the run adds a note per image: `tool image X unpinned (...) - run readyhai tools pull --lock`.

`readyhai tools pull --lock tools.lock.toml` runs `docker pull <image>` for every entry (pull failures, e.g. the `:local` playwright image, are printed and skipped), reads `RepoDigests[0]`, and rewrites the file with digests. This is trust-on-first-use: it pins whatever the registry served at that moment, so verify signatures yourself where the vendor publishes them, and review the diff. Commit the resulting file and set `READYHAI_TOOLS_LOCK` to it; otherwise the binary uses the lock embedded at its build time.

`readyhai tools update` is the only step that uses the network: `grype db update` into `<data>/cache/grype`; OSV-Scanner offline ecosystem databases into `<data>/cache/osv-scanner`; Nuclei templates into `<data>/cache/nuclei`; rules from `https://semgrep.dev/c/p/default` into `<data>/cache/semgrep/default.yml` and `<data>/cache/opengrep/default.yml`; and the Lynis 3.1.6 tarball from `downloads.cisofy.com` into `<data>/cache/lynis/` (checked against a published `.sha256` if one exists, else the hash is recorded as unverified).

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
format = "sarif"                   # sarif | junit | readyhai-json | lines
network = false                    # default false
entrypoint = "bandit"              # optional, single string (--entrypoint override)
# Optional runner-v2 fields:
cache_rw = false                   # writable /cache mount (scanner DBs, templates, wordlists)
env = ["BANDIT_TOKEN"]             # env NAME passthrough (values come from ReadyHai's env, never argv)
stdout = false                     # capture stdout as the report (then `output` is not needed)
host_gateway = false               # --add-host host.docker.internal (auto-on for loopback targets)
user = "10001"                     # numeric uid[:gid] override for the container
intrusive = false                  # respect the scope prod guard (deep scans too)
# For format = "lines" only:
rule = "recon.httpx.probe"         # rule id on every finding
severity = "info"                  # info | low | medium | high | critical
title_prefix = "HTTP surface"      # finding title becomes "<prefix>: <value>"
```

| Field | Notes |
|---|---|
| Placeholders in `args` | `{src}` -> `/src`, `{out}` -> `/out`, `{url}` -> target URL (loopback hosts rewritten to `host.docker.internal`, empty for non-web), `{domain}` -> bare hostname of the target, `{image_tar}` -> `/src/image.tar` |
| Sandbox | Same hardening as built-in tools (net none unless `network = true`, caps dropped, read-only rootfs, non-root, `/src` ro, `/out` rw, `/tmp` tmpfs; `/cache` ro unless `cache_rw`). Container-create policy applies. Loopback targets auto-enable the host gateway so `network = true` plugins can reach a localhost dev server. |
| `sarif` | `runs[].results[]` mapped: `ruleId`, `level` (error high, warning medium, note low, none info), first physical location, message first line. Category `security`. fp = `uri|rule|hash(message)` |
| `junit` | Failed cases become `tests.failed` findings (same rules as `tests.own`); errors-only is `errored`. The container exit code is only trusted when `stdout = true`. |
| `readyhai-json` | A JSON array of `Finding` objects (see [architecture.md](architecture.md#data-model)); `check` is overwritten with `plugin.<id>` |
| `lines` | JSONL (one object per line), for recon CLIs (`httpx -json`, `katana -json -silent`, `subfinder -json`...). URL/host taken from common keys (`url`, `host`, `input`, ...); one deduped finding per value with `rule`/`severity`/`title_prefix`. Empty output with exit 0 = zero findings. |
| Unpinned image | Status `partial("plugin image unpinned")` and a pin warning. Use `@sha256:` |
| `env` names not set | Status `partial("env not set, ...")` — the plugin ran, coverage may be lower |
| Failure | Missing/empty output (except exit-0 `lines`) -> `errored` with the container exit code and stderr tail. Invalid `plugin.toml` (unknown format, `user` not numeric, `env` entry not an identifier, missing `output` without `stdout`) -> skipped at load with a warning. |

Plugins marked `intrusive = true` (or `profile = "deep"`) run only on targets the scope file does not mark `prod`, like built-in intrusive checks. ReadyHai's own verified plugin pack lives in [`../plugins/official/`](../plugins/README.md).

**On-the-go setup** (v3.6.0): `readyhai tools pull --plugins DIR` is optional. At scan start the engine provisions the packs it is about to run — digest-pinned images that aren't in the local Docker store are pulled, pack cache dirs are created — and every action is reported as a `setup:` note in the run notes. Offline bundle mode skips provisioning. A failed pre-pull is never fatal: the plugin run still pulls on demand, and a missing image degrades to the usual `tool_failed`/partial status instead of failing the run.

## Settings (tool/plugin toggles)

`--settings <file>` (or `READYHAI_SETTINGS`) points at an operator-owned TOML file that switches integrations on or off per check, per glob, or per category. Start from [`../settings.example.toml`](../settings.example.toml). A file that fails to parse or validate is a hard error — a silently-ignored settings file must never flip an integration the operator meant to keep off. A scanned repo's own files are **never** consulted for settings.

```toml
[integrations]
tools = "auto"      # pinned-container tool checks (tri-state: auto | on | off)
plugins = "auto"    # plugin.* checks
intrusive = "auto"  # kill switch: auto | off only ("on" is rejected at load)

[[toggle]]
id = "plugin.crowdstrike.*"   # check id or glob; last matching glob wins
enabled = "off"
```

Resolution per check: exact `[[toggle]]` id > last matching glob > category switch > `auto`. `off` produces a normal `Skipped` status with a visible reason in the report — a toggle never hides coverage. `on` only protects a check from *settings*; the profile, scope-nonprod, `--no-tools` and Docker gates keep their authority. The precedence mirrors how tools like Trivy and Nuclei layer config (flag > env > file > defaults), same as the rest of ReadyHai: `--settings` > `READYHAI_SETTINGS` > none. Design choices follow verified OSS precedents: tri-state mirrors Wazuh's `<disabled>` wodle switch (auto answers "why didn't it run"); the kill-switch-that-can-only-narrow mirrors github-mcp-server's `--read-only` beating explicit `--tools`; per-file-not-per-flag selectors with hard-fail on an unparseable file follow Trivy's `trivy.yaml`; opaque plugin option pass-through follows DefectDojo's `Tool_Configuration.extras`.

The same file carries the vulnerability-database section:

```toml
[vulndb]
enabled = true    # scans record warn/fail findings into the DB (default true)
# path = "/var/lib/readyhai/vulns/vulns.jsonl"   # default <data>/vulns/vulns.jsonl
```

`enabled = false` stops recording; existing rows and `readyhai vulns` keep working. An empty/whitespace `path` is rejected at load like any other bad setting. `GET`/`PUT /api/settings` expose the same two fields (`effective.vulndb`); an absent `vulndb` in a `PUT` body carries the stored values over, `path: null` clears the override.

## Vulnerability database (vulndb)

One local JSONL file — `<data>/vulns/vulns.jsonl`, or `[vulndb] path` — holds every warn/fail finding ReadyHai has recorded across all targets, so triage isn't redone scan after scan. After a scan (any target kind) finishes, findings with status warn/fail are appended: one row per `target + kind + rule + resource`, keyed by a 24-hex-char **fingerprint** (SHA-256 prefix). Re-observing a finding bumps `occurrences` and `last_seen` instead of duplicating the row. The run notes say what happened: `vulndb: N finding(s) recorded in <path> (X new, Y seen again)`. Recording is on by default and never changes a verdict or exit code; the file lives in the data dir, is capped at 10 MB (a rewrite beyond the cap is refused with a note), and needs no database server.

Each row carries `fingerprint, target, target_key, kind, rule, title, severity, resource, first_seen, last_seen, occurrences, status, message`. Statuses are `open`, `accepted`, `forgotten`:

- `accepted` and `forgotten` survive re-observation — the counters move, the decision stands. An `accepted` finding re-recorded at a *different severity* falls back to `open` (a High that became Critical is a new decision).
- Setting `open` again is allowed (re-open) from CLI, API or UI.

```bash
readyhai vulns                                  # open findings (table)
readyhai vulns --json                           # machine-readable
readyhai vulns --status accepted --target https://staging.example.com
readyhai vulns --all                            # no status filter
readyhai vulns accept 4f2a91c7d3                # 6+ chars, unique prefix is enough
readyhai vulns forget 4f2a91c7d3
```

`readyhai vulns` reads only the file — no scan, no Docker, no network. The columns are `FINGERPRINT SEVERITY CHECK TARGET SEEN STATUS RULE/RESOURCE`. The same rows are served by `GET /api/vulns` and triaged by `POST /api/vulns/{fingerprint}` ([api.md](api.md)), and the web **Vulns** view renders them.

## WireGuard config audit (`wireguard`)

A built-in repo check (v3.6.0) that reads `*.conf` / `*.wgconfig` files in the repo — no container. A file is only parsed as WireGuard when it has an `[Interface]` or `[Peer]` section *and* a WireGuard directive (`PrivateKey`, `AllowedIPs`, `Endpoint`, …), so an unrelated `nginx.conf` is left alone. Findings never echo key material: values are redacted to length/shape, and keys are compared by value, not printed.

| Rule | Severity | Detection |
|---|---|---|
| `wireguard.private-key-committed` | high | `PrivateKey=` / `PresharedKey=` value committed to the repo (redacted in the finding) |
| `wireguard.key-reuse` | medium | the same key value used by more than one peer or file (identity collision / blast radius) |
| `wireguard.allowed-ips-overreach` | medium | `AllowedIPs = 0.0.0.0/0` or `::/0` — full-tunnel default route on a peer |
| `wireguard.weak-key-material` | medium | key material that isn't 32 bytes of base64, or all-zero |
| `wireguard.listen-port-conflict` | medium | the same `ListenPort` on more than one `[Interface]` in the tree |
| `wireguard.missing-address` | medium | `[Interface]` without `Address=` (tunnel comes up unroutable) |
| `wireguard.no-keepalive` | low | a peer with `Endpoint=` and no `PersistentKeepalive` (NAT drops the mapping) |

It runs as a quick-profile repo check, so it's part of a plain `readyhai scan .`; it appears as the `wireguard` check and is togglable like any other check.

## RBAC (rbac.toml)

`readyhai serve` runs with role-based access control when a key file exists. Start from [`../rbac.example.toml`](../rbac.example.toml) and point `READYHAI_RBAC_FILE` at it. The toggle is tri-state: `READYHAI_RBAC=on|off|auto` (env wins), then `[rbac] enabled` in the file, then `auto` = ON when the file exists, OFF otherwise. With RBAC **off** the server behaves exactly as it always has: one `READYHAI_TOKEN` bearer, full access. With RBAC **on**, every bearer token is resolved against `[[key]]` entries (plaintext `key` or `key_sha256 = "sha256:<64 hex>"`; keys are hashed in memory and compared in constant time) and authorized per route:

| Role | May |
|---|---|
| `viewer` | `GET`/`HEAD` anywhere (dashboards, read-only integrations) |
| `operator` | + trigger scans and agent runs, cancel, network lab, evals |
| `admin` | + approve/reject, `fix`, memory-accept, delete runs — governance |

Any write route not explicitly classified is treated Admin-only (fail closed). The legacy `READYHAI_TOKEN` remains a break-glass `admin` unless `READYHAI_RBAC_BOOT_ADMIN=0` — set that in real deployments once your first named key works. `READYHAI_RBAC=on` without a key file, or with a key file that has no entries, is a boot error: the server refuses to start a lockbox nobody can open. `GET /api/whoami` reports the caller's name, role and resolved permissions. The role model is deliberately minimal (DefectDojo/Opsgenie-style tiered roles rather than per-permission strings) because every ReadyHai action already falls into read / operate / govern.


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
| `READYHAI_SETTINGS` | `scan`, `qa` | Operator settings file (tool/plugin toggles); `--settings` wins. See "Settings" above. |
| `READYHAI_RBAC` | `serve` | RBAC toggle `on\|off\|auto`; auto = on when a key file exists. See "RBAC" above. |
| `READYHAI_RBAC_FILE` | `serve` | Path to `rbac.toml` (per-key roles). Existence under `auto` decides the default toggle. |
| `READYHAI_RBAC_BOOT_ADMIN` | `serve` | `0` removes the legacy token's break-glass admin while RBAC is on. |
| `READYHAI_TOOLS_LOCK` | all tool runs | Path to a lock file overriding the embedded one. |
| `READYHAI_GIT_TIMEOUT_SECS` | git clones, `agent --diff-base` | Wall-clock limit of a `git clone` (default 300, 10 to 3600, never longer than the run deadline) and of the agent's `git diff` (default 60, 5 to 3600). |
| `READYHAI_CONNECT_TIMEOUT_MS` | scan-side HTTP (web fetch, discovery, QA API, agent, LLM) | How long a request waits for a connection (TCP connect **and** TLS handshake) before it is called unreachable (default 5000, 100 to 30000). It never shortens how long an already-connected server may take to answer, so timing-based checks (`qa.api.slow_response`, time-delay blind SQLi) are unaffected. A target that accepts the socket and then goes silent is given up on in this window instead of holding the run open to its deadline. |
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
| `READYHAI_OAST_BIND` | `agent` (`oast.rs`) | Loopback address:port for the in-process OAST callback collector (default `127.0.0.1:0`). |
| `READYHAI_OAST_URL` | `agent` (`oast.rs`) | Optional external callback base URL advertised in `__OAST_URL__` probes when the target runs in another network namespace (for example `http://host.docker.internal:<port>`). |
| `READYHAI_AGENT_BROWSER` | `agent` (`browser_sec.rs`) | Set to `off` (also `0`, `false`, `no`, `none`) to disable Playwright `BrowserSecurity` DOM/client-side checks in `standard`/`deep` runs. |
| `READYHAI_AGENT_XHR` | `agent` (`discover/xhr.rs`) | Set to `off` to disable headless Playwright XHR discovery on SPAs. |
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
| `READYHAI_LLM_URL` | `qa`, `agent` | Base URL of the endpoint, for **any** provider: an OpenAI-compatible server (vLLM, Ollama, LiteLLM, llama.cpp, a gateway; `.../v1`) or, with `READYHAI_LLM_PROVIDER=anthropic`, an Anthropic-compatible one. It replaces the provider's built-in base. Plain `scheme://host[:port]/path`: credentials in the URL, a query string or a fragment are refused (use the key variable). With no provider set, the URL alone selects the generic OpenAI-compatible provider (`vllm`). No built-in address. |
| `READYHAI_VLLM_URL` | `qa`, `agent` | **Deprecated** alias of `READYHAI_LLM_URL`, read only when that is unset and only for the generic provider. |
| `READYHAI_MAX_OPS` | `qa`, `agent` | Most OpenAPI operations planned per run (default `2000`, ceiling `10000`). Operations past it are reported as untested in coverage, never passed. |
| `READYHAI_MAX_CUSTOM_INSTRUCTIONS_BYTES` | `serve`, `agent` | Maximum bytes for custom operator instructions/directives (default `32768` [32 KB], clamped between `4096` and `131072`). |
| `READYHAI_LLM_PROVIDER` | `qa`, `agent` | `vllm` (default; also spelled `openai-compatible` or `custom`), `ollama`, or cloud `openai`, `anthropic`, `openrouter`. |
| `READYHAI_LLM_API_KEY` | `qa`, `agent` | Key for any provider; wins over the provider's own variable below, and is optional for local servers. Sent as `Authorization: Bearer` (OpenAI-compatible) or `x-api-key` (Anthropic). Never logged, printed, put in a report or an error. |
| `READYHAI_LLM_MODEL` | `qa`, `agent` | Model, or a comma-separated list (`READYHAI_LLM_MODELS` is an alias, read when this is unset). The first is primary; when a call to it fails (an error after its retries, a non-success status, an empty answer) the next one is tried, in order, within the same call. If every model fails the error names them all. Defaults per provider: `qwen3.8-flash-next` (vllm), `qwen2.5-coder` (ollama), `gpt-4.1`, `claude-sonnet-5-5`, `anthropic/claude-sonnet-5-5`. |
| `READYHAI_LLM_ALLOW_CLOUD` | `qa`, `agent` | `1` / `true` required to send findings off-box: for cloud providers, **and** when `READYHAI_LLM_URL` points a local provider at a public host. Otherwise the config is refused with a message saying so. Not public: loopback, private (RFC 1918), link-local, unique-local and `100.64.0.0/10` addresses; `.local`, `.lan`, `.internal` (so `host.docker.internal`), `.localhost` and `.home.arpa` names; single-label names (`localhost`, `gpu-box`). Names are judged by spelling, never resolved. |
| `READYHAI_LLM_TIMEOUT_SECS` | `qa`, `agent` | One fixed per-call timeout in whole seconds (1 to 3600). Unset or empty: each call gets `clamp(20 + max_tokens / 40, 30, 300)` seconds, so a 2k-token summary gets about 70 s and a 35k-token reasoning call 300 s. A call that times out is **not** repeated as it was: it is sent again with half the `max_tokens` (floor 1024) and no `reasoning_effort`, at most twice, and then the next model in `READYHAI_LLM_MODEL` is tried; a 5xx is retried once, then the next model; 429 honours `Retry-After`. The agent also sends one 1-token completion at the start of a run: its latency is shown in the run's LLM status, and an answer slower than 10 s (or none in time) caps the planner's thinking at the High tier (8192 tokens) with a run note. Gate and triage calls never reason (2048 tokens). |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY` | `qa`, `agent` | Provider keys, read only when that provider is selected and `READYHAI_LLM_API_KEY` is unset. |

Empty values count as unset, so an `.env` file can list every name. `GET /api/agent/status` shows the primary `model`, the full `configured_models` list and whether a key is set (`api_key_configured`), never the key.

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

The context-retriever runner (`runners/context_retriever`, Python) has its own variables: `READYHAI_EMBEDDING_BACKEND` (`ollama` default, `vllm`, `huggingface`), `READYHAI_EMBEDDING_MODEL`, `READYHAI_EMBEDDING_API_KEY`, `READYHAI_DEVICE` (`cpu` default), plus `READYHAI_LLM_URL` (the deprecated `READYHAI_VLLM_URL` still works), `READYHAI_LLM_API_KEY` and `READYHAI_LLM_MODEL` (a comma list: the first is used, the rest are fallbacks) for synthesis and the `vllm` embedding backend. See its README.

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
