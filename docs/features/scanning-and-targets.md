# Scanning & targets

ReadyHai's scanner is a single Rust binary that takes one target — a repository, a container
image, a web app or API, a host reachable over SSH, or an Android package — and returns one
verdict with reasons. It runs its own native rules plus pinned third-party scanners inside
hardened throwaway containers, normalises every result into one `Finding` schema, dedupes it
against a baseline, and turns the whole thing into an exit code suitable for CI.

The scan surface and the QA/agent surface share the same engine, checks registry, policy and
reports; this page covers the scanning side (`readyhai scan`). For the senior-QA engine and the
autonomous agent, see [Agent, QA & security intelligence](./agent-qa-security.md).

**In this section**

- [Scanning & targets](./scanning-and-targets.md) — this page
- [Agent, QA & security intelligence](./agent-qa-security.md) — `readyhai qa`, `readyhai agent`, vulndb, exploits, RBAC

Reference pages: [usage](../usage.md) (every flag), [checks](../checks.md) (every rule id and
severity), [configuration](../configuration.md) (every file key and environment variable),
[security-model](../security-model.md) (sandbox controls).

## The verdict model

A scan ends in exactly one of three verdicts, and the process exit code is the verdict:

| Exit | Verdict | Meaning |
|---|---|---|
| `0` | `PASS` | Nothing at or above the warn threshold was considered |
| `1` | `WARN` | Findings at or above `warn_severity` (default `medium`), or a check was `partial` or `errored` |
| `2` | `FAIL` | A finding at or above `fail_severity` (default `critical`), a hard-fail rule, a KEV-listed CVE, or a required check that `errored` |
| `3` | error | Not a verdict: bad target, unusable scope/policy/settings file, I/O failure. Message on stderr as `readyhai: error: …` |

The rules live in `policy::verdict` and are driven by the policy file (embedded
`policies/default.toml` by default, `--policy FILE` to replace it). Suppressed findings never
gate, and with the default `only_new = true` neither do `existing` findings — see
[Baselines & noise control](#baselines--noise-control).

Statuses other than pass/fail carry weight on purpose: a `partial` check raises the verdict to at
least `WARN`, and an `errored` *required* check fails the gate while `errored_fails = true`
(the default). A check is *required* when it is native or when its tool image is present, so a
missing image is a `WARN`, not a `FAIL`.

### Deterministic and honest

Three properties hold across every feature on this page:

1. **Verdicts come from code, never from an LLM.** An optional LAN model may add prose, notes and
   advisory test ideas; it cannot change a verdict, a severity or the gate.
2. **Nothing is silently green.** Coverage gaps surface as `partial`, `skipped`, `not_applicable`
   or `errored` with a reason, visible in the summary, the HTML report and SARIF. A scanner whose
   output says it did not finish cannot return the gate to `PASS`.
3. **Unmeasured is reported as unmeasured.** Findings are only emitted for what a check actually
   inspected; `null` and `not_applicable` are preferred to a default score.

Progress, the per-check table and the verdict go to **stderr**; the reports are files. Every run
prints `readyhai <ver> · run <id> · <target> · profile <p>` — note the run id, `baseline accept`
takes it.

### Profiles

A check runs when the target kind matches *and* `profile >= check.min_profile`
(`quick < standard < deep`). The same profile gate applies to every feature below.

| Profile | Adds |
|---|---|
| `quick` (default) | Native readiness rules, native Tree-sitter audit, gitleaks, SBOM+CVE, semgrep, hadolint, checkov, dockle, image inspect, web smoke, host probe/CVE, MobSF |
| `standard` | `tests.own`, `tool.opengrep`, `tool.osv_reachability`, `tool.scorecard`, Schemathesis, ZAP baseline, Nuclei, Playwright crawl, `host.lynis`, `android.runtime` |
| `deep` | Intrusive checks — only against a host that `scope.toml` does not mark `prod`: `tool.zap_active`, Android monkey stress, plugins declaring `profile = "deep"` |

`--no-tools` skips every check that needs a container. Note that `host.probe` and `host.lynis`
have no `tool` set, so `--no-tools` does **not** skip them; `host.cve` and `image.inspect` do and
are skipped.

---

## Repository scanning

`readyhai scan <path>` — the default and widest target kind.

```bash
readyhai scan ./services/user-api                       # native rules + quick tools
readyhai scan . --profile standard --format html,json,sarif --out readyhai-report
readyhai scan tests/fixtures/vuln-app --no-tools        # native rules only, no Docker needed
readyhai scan git:https://github.com/org/repo           # shallow clone, then snapshotted
```

**What it does.** The repo is never scanned in place: a filtered snapshot is copied into the run
directory and mounted read-only as `/src`. Secret-denylisted paths are recreated as empty
placeholders and never opened; `.git`, `node_modules`, `.venv`, `target` and friends are skipped;
symlinks are dropped; files over 20 MB are skipped. Twenty-six checks are registered for the repo
kind: fifteen run at `quick`, five more from `standard` up, and the six coverage /
release-quality checks listed further down run only under `readyhai qa`.

**Why it matters.** Most of what blocks a release is visible statically: an unpinned dependency, a
committed key, a `privileged: true` service, a build stage running as root, a route with no auth
guard. Those answers do not need a running system, and they can gate a PR in seconds.

### Dependency inventory and CVEs

| Check | Tool | Profile | Detects |
|---|---|---|---|
| `tool.sbom_cve` | syft + grype | quick | CycloneDX SBOM, package CVEs with EPSS and KEV |
| `tool.osv_reachability` | osv-scanner | standard | OSV CVEs annotated reachable / unreachable / unknown |
| `readiness.deps` | native | quick | Unpinned deps, unpinned `git+` deps, missing lockfile |

`tool.sbom_cve` runs syft (`dir:/src`) and then grype in `sbom:` mode with DB auto-update off and
no network. Findings use the vulnerability id as the rule (`CVE-…`, `GHSA-…`), carry `epss`,
`kev` and `fix_version`, and are fingerprinted by `canonical-id|package|manifest path` so a rerun
does not create a new finding. Any unpinned dependency, or a grype DB older than 7 days, makes
the check `partial` — CVE coverage is honestly labelled incomplete.

`tool.osv_reachability` is the noise-control answer to "we have 4,000 CVEs". OSV-Scanner v2 runs
offline (`--offline-vulnerabilities --call-analysis=go`) against the DB in `<cache>/osv-scanner`;
each finding carries `Reachability: reachable|unreachable|unknown`. `unreachable` (call analysis
ran and found no path) lowers severity one level; `unknown` never lowers. When call analysis is
`unknown`, ReadyHai adds a Tree-sitter import check across Python, JS/TS, Go and PHP and notes
that the package is imported, without changing the severity.

### Native code audit (`security.code_audit`)

Native, no container, `quick` profile — so it runs on a laptop with no Docker and inside a
container host. ReadyHai parses Python, JS/TS, Go and PHP with Tree-sitter and performs cross-file
taint tracking (source → up to three hops → sink) plus auth-guard consistency checks against
sibling routes.

Rule ids: `security.taint.sql_injection`, `security.taint.command_exec`, `security.taint.ssrf`,
`security.taint.path_traversal`, `security.taint.ssti` (High) and `security.auth.missing_guard`
(Medium, a sibling route missing a decorator/middleware its neighbours all have). Parsing is
in-memory — target code is never executed — bounded to 2,500 source files and 1 MiB per file, and
secret-denylisted paths are skipped.

`tool.opengrep` (`standard`) adds Opengrep intra-file static taint analysis (`--taint-intrafile`)
using the cached rule pack, reading `/cache/opengrep` and falling back to `/cache/semgrep`.

### SAST, secrets, IaC and Dockerfile lint

| Check | Tool | Rule ids / severity |
|---|---|---|
| `tool.semgrep` | semgrep | Semgrep `check_id`; ERROR high, WARNING medium, else low |
| `tool.opengrep` | opengrep | Same mapping as semgrep |
| `tool.gitleaks` | gitleaks | `secrets.<RuleID>`, high, **hard-fail**; values redacted, never recorded |
| `tool.checkov` | checkov | `CKV_*` ids (secrets framework skipped) |
| `tool.hadolint` | hadolint | `DL…`/`SC…` codes; error high, warning medium, else low |

The native readiness rules duplicate the important parts of those scanners without needing a
container, so a `--no-tools` run still catches the structural problems: `readiness.dockerfile`
(no `USER`, no `HEALTHCHECK`, `:latest` base, remote `ADD`, no `.dockerignore`),
`readiness.compose` (`privileged`, `docker.sock` mount, host network, healthcheck problems, no
limits, no restart policy), `readiness.k8s` (plaintext `Secret`, `privileged`, `hostNetwork`,
missing probes/limits, run-as-root, `:latest`), `readiness.ci` (no CI, a scanner that can never
fail, missing SAST/secret/dependency stages) and `readiness.repo` (tracked secret-bearing files
reported **by path only**, no README, no tests, no `/health` route, no OpenTelemetry). Compose
files are parsed natively — `docker compose config` auto-loads `.env` and is never called.

### WireGuard config audit (`wireguard`)

A built-in `quick` repo check, no container (`src/rules/wireguard.rs`). It reads `*.conf` and
`*.wgconfig` files and only treats a file as WireGuard when it has an `[Interface]` or `[Peer]`
section *and* a WireGuard directive, so an unrelated `nginx.conf` is left alone. Key values are
never printed: they are redacted to length/shape, and reuse is detected by comparing values.

| Rule | Severity | Detection |
|---|---|---|
| `wireguard.private-key-committed` | high | `PrivateKey=` / `PresharedKey=` committed to the repo |
| `wireguard.key-reuse` | medium | same key value used by more than one peer or file |
| `wireguard.allowed-ips-overreach` | medium | `AllowedIPs = 0.0.0.0/0` or `::/0` on a peer |
| `wireguard.weak-key-material` | medium | not 32 bytes of base64, or all-zero |
| `wireguard.listen-port-conflict` | medium | same `ListenPort` on more than one `[Interface]` |
| `wireguard.missing-address` | medium | `[Interface]` without `Address=` |
| `wireguard.no-keepalive` | low | peer with `Endpoint=` and no `PersistentKeepalive` |

It is togglable like any other check (`[[toggle]] id = "wireguard"`).

### API contract, coverage and migration safety

On a repo target you also get `tool.spectral` (OpenAPI lint with `spectral:oas`), `tool.oasdiff`
(breaking changes versus an accepted `<spec>.baseline.<ext>` file), `tool.scorecard` (OpenSSF
Scorecard for a `github.com` origin, needs `READYHAI_GITHUB_TOKEN`, `standard`), and
`qa.suite.mutation` (`standard`), which reads *existing* mutation reports (cargo-mutants, Stryker,
mutmut 3) rather than running mutation tests — a score below 60% is a Medium finding
(`qa.suite.low_mutation_score`).

Test-coverage and migration-safety checks (`qa.suite.coverage`, `qa.suite.routes`,
`qa.suite.smells`, `qa.release.eol`, `qa.release.migrations`, `qa.release.licenses`) are
registered as QA checks: they run under `readyhai qa --repo <dir>`, not under `readyhai scan`.
The migration check is the only repo-side one that starts containers — it runs an alembic
up/down/up cycle against a throwaway `postgres:16-alpine` and needs `[test] image` in
`readyhai.toml`; Prisma and Flyway are detected and reported as *untested*, never as passed.
They appear in `readyhai checks` alongside the others and are detailed in
[Agent, QA & security intelligence](./agent-qa-security.md).

**Configuration**

| Key / flag | Effect |
|---|---|
| `--config FILE` | Use this `readyhai.toml` instead of `<repo>/readyhai.toml` |
| `[[suppress]]` `rule`/`path`/`reason`/`expires` | Silence a rule, prefix or glob; reason and expiry are mandatory |
| `[snapshot] deny` / `skip_dirs` | Extra secret-bearing globs / directory names to skip |
| `[test]` `image`/`command`/`network`/`timeout_secs` | Required for `tests.own`; command must write `/out/junit.xml` |
| `--plugins DIR` (env `READYHAI_PLUGINS`) | Extra `plugin.*` checks |

**Notes & limits.** A repo path given to the server or MCP must sit under
`READYHAI_ALLOWED_ROOTS`. `tool.scorecard` is the only repo check with network access and is
`skipped` when `READYHAI_OFFLINE=1`. `tool.scorecard` passes the token to the container as an
environment variable, so it is visible in the local `docker` process list while the check runs.
OSV reachability only enables Go call analysis (Rust analysis runs build scripts). Kustomize
overlays are not rendered, so a patch-only overlay directory is analysed as written.

---

## Container image scanning

```bash
readyhai scan image:nginx:1.27
readyhai scan image:myapp:1.4 --profile quick --format html,sarif
```

**What it does.** The image must exist **locally** — `docker save` does not pull, and an absent
ref is an error rather than a pull. ReadyHai builds a distro+language SBOM with syft
(`docker-archive:/src/image.tar`), matches it against the local grype DB, runs Dockle's
CIS-style image checks, and inspects the image config for the readiness properties that matter:
user, healthcheck, tag, size.

| Check | Tool | Detects |
|---|---|---|
| `tool.sbom_cve` | syft + grype | Package CVEs with EPSS/KEV, same mapping as the repo scan |
| `tool.dockle` | dockle | `CIS-DI-*` / `DKL-*`: FATAL high, WARN medium, INFO low; PASS/SKIP dropped |
| `image.inspect` | docker | `image.root_user` (high), `image.no_healthcheck` (medium), `image.large` (> 1 GB, low), `image.latest_tag` (low) |

**Why it matters.** The image is the artefact that actually ships. Running as root, having no
`HEALTHCHECK`, and carrying a `:latest` base are properties of the artefact — checking them at the
artefact catches the cases where a Dockerfile was bypassed or built from a different commit.

**How to use it.** Build first, then scan in the same job so nothing moves under you:

```bash
docker build -t myapp:${SHA} .
readyhai scan image:myapp:${SHA} --profile quick --format json,sarif --out readyhai-report
```

**Configuration.** Images come from `tools.lock.toml` (keys `syft`, `grype`, `dockle`); the
`[test] image` in `readyhai.toml` is for a repo target's own test suite, not for `image:` targets.
Suppressions apply by rule id, e.g. `rule = "image.no_healthcheck"` with a reason and expiry.

**Notes & limits.** ReadyHai does not pull the target image, and refuses empty refs, refs with a
leading `-`, and refs containing whitespace. `image.inspect` has a `tool` set, so `--no-tools`
skips it and the accompanying `WARN` reason for unavailable docker applies. The grype DB is
checked for age: over 7 days old the scan is `partial`, over 30 days it is flagged stale.

---

## Web & API scanning

```bash
readyhai scan https://staging.example.com --profile standard \
  --openapi https://staging.example.com/openapi.json --scope scope.toml
readyhai scan https://app.internal --profile deep --scope scope.toml   # + ZAP active scan
```

**What it does.** One native HTTP check plus five container checks (`tool.zap_baseline` and
`tool.zap_active` share the ZAP image) cover the request surface. Rules of
engagement come from `scope.toml`: a public host needs no entry and gets full testing unless
listed `env = "prod"`; an internal host (loopback, RFC1918, link-local, CGNAT, `*.localhost`,
`host.docker.internal`, metadata, or any name resolving to those) **must** be listed or matched by
a `*` entry, otherwise the scan is refused. A configured-but-unusable scope file is an error
(exit 3), never "no scope".

| Check | Profile | Tool | Detects |
|---|---|---|---|
| `web.smoke` | quick | native | Status, latency, TLS, headers, CSP, cookies, CORS, health endpoint |
| `tool.schemathesis` | standard | schemathesis | OpenAPI-negative testing (property-based API fuzzing) |
| `tool.zap_baseline` | standard | zap | Passive DAST baseline |
| `tool.nuclei` | standard | nuclei | Template scans (CVE, misconfig, exposure, takeover) |
| `tool.zap_active` | deep `[intrusive]` | zap | Full active scan |
| `tool.playwright` | standard | playwright | Browser crawl with client-side security checks |

`web.smoke` is one native check with a lot of rules — it issues the start URL, a CORS probe, the
health paths, and an OpenSSL handshake for TLS inspection, following up to 5 redirects:
`web.5xx` (high, also used for "target unreachable"), `web.4xx`, `web.slow` (> 2 s),
`web.no_tls`, `web.tls_weak_protocol` (SSLv*/TLS 1.0/1.1), `web.tls_expiring` (high at ≤ 0 days,
medium at ≤ 14), `web.tls_untrusted`, `web.missing_headers` (HSTS on HTTPS, CSP,
`X-Content-Type-Options`, `X-Frame-Options`/`frame-ancestors`, `Referrer-Policy`),
`web.weak_csp` (`'unsafe-inline'`, `'unsafe-eval'`, wildcard `*`, `http:` script sources),
`web.version_disclosure`, `web.insecure_cookie` (missing Secure/HttpOnly/SameSite),
`web.cors_permissive` (reflected arbitrary Origin, or `*` with credentials), `web.no_health`.

Tool checks map as follows: Schemathesis → `api.server_error` (high, **hard-fail**),
`api.auth_not_enforced`, `api.undeclared_method`, `api.invalid_input_accepted`, `api.schema`,
`api.content_type`, `api.status_code`, `api.check`; ZAP → `zap.<pluginid>` by risk; Nuclei →
`nuclei.<template-id>` with CVE/CWE attached, tags `cve,misconfig,exposure,takeover`, DoS and fuzz
templates excluded (`-etags dos,fuzz`), rate limited to 20/s; Playwright → `web.page_error`,
`web.console_error`, `web.broken_link`, `web.5xx`, `web.4xx`, `web.storage_secret`,
`web.cookie_httponly`, `web.sourcemap_exposed`, `web.postmessage_no_origin`.

**Why it matters.** `web.smoke` alone catches the majority of production header/TLS/cookie
misconfigurations, costs a handful of requests (start URL, a CORS probe, four health paths, one
TLS handshake), and is safe enough to run against almost anything. The
active layers then answer the questions passive scanning cannot: does the API reject malformed
input, do known templates fire, does the SPA leak tokens into client storage.

**Configuration**

| Key / flag | Effect |
|---|---|
| `--openapi URL` | Spec for `tool.schemathesis` (else `/openapi.json`, `/docs/openapi.json`, `/api/openapi.json`, `/swagger.json` are probed) |
| `--scope FILE` (env `READYHAI_SCOPE`) | Rules of engagement; template in `scope.example.toml` |
| `[hosts]` `host` + `env = "prod"/"nonprod"` | Per host: `prod` is read-only, `nonprod` permits intrusive checks |
| `READYHAI_PLAYWRIGHT_IMAGE` | Runner image override |
| `READYHAI_SCOPE` + `[[hosts]]` for the DAST tools | The active scanners inherit the same guard as everything else |

**Notes & limits.** `tool.zap_active` requires `--profile deep` **and** a host the scope file does
not mark `prod`; otherwise it reports `skipped(intrusive: needs --profile deep and a nonprod
host)`. Loopback targets are rewritten to `host.docker.internal` for the containers, so a local dev
server is reachable from inside them. The `tool.playwright` check needs the locally built runner
image (`docker build -t readyhai/playwright-runner:local runners/playwright`) and crawls up to 20
same-origin pages with GET/HEAD only. Schemathesis is `not_applicable` without a spec. Scope
covers the target URL, an absolute `--openapi` URL and the git host — it does not cover redirects
the target issues to other hosts, and the HTTP client stays on the original host.

---

## Host scanning over SSH

```bash
ssh-keyscan -p 22 10.0.0.5 >> ~/.ssh/known_hosts   # after verifying the fingerprint
readyhai scan ssh://ops@10.0.0.5 --os linux --profile standard
readyhai scan ssh://deploy@10.0.0.5:2222 --os linux --key ~/.ssh/id_ed25519
```

**What it does.** One read-only probe script (embedded: `probe/linux.sh`, `macos.sh`,
`windows.ps1`) is streamed over SSH and produces a JSON document; ReadyHai parses it into findings
and keeps the raw document at `<run>/out/host-probe.json`. The Linux probe collects OS and kernel
version (`uname -r`), listening sockets (`ss -tlnp`), systemd state and failed units, disks, sshd
settings, sudo configuration, firewall status, time sync, docker container states, error lines from
the journal, and a package inventory. On Linux that inventory is turned into a CycloneDX 1.5 SBOM
and scanned with grype. `standard` adds a full Lynis hardening audit.

| Check | Profile | Runs in | Detects |
|---|---|---|---|
| `host.probe` | quick | remote host (ssh) | OS/ssh/firewall/updates/accounts/disk/units/containers |
| `host.cve` | quick | grype container | Package CVEs from the probe inventory (Linux only) |
| `host.lynis` | standard | remote host (ssh) | Lynis 3.1.6 warnings, suggestions, hardening index |

Linux rules include `host.ssh_root_login` (high), `host.ssh_password_auth`,
`host.pending_updates` (high when security updates are pending — "reboot if a kernel/libc update
is included"), `host.failed_units`, `host.no_firewall`, `host.uid0_extra` (high),
`host.nopasswd_sudo`, `host.no_time_sync`, `host.container_restarting` and `host.disk_full`
(medium > 85%, high > 95%). macOS adds `host.sip_disabled`, `host.gatekeeper_off`,
`host.filevault_off`, `host.mac_firewall_off`; Windows adds `host.defender_off`,
`host.defender_stale`, `host.firewall_off`, `host.smb1`, `host.rdp_no_nla`. Journal/oslog/event-log
error lines are redacted and clustered under `host.journal` / `host.oslog` / `host.eventlog`.

**Why it matters.** The host is the layer nobody's SAST sees: a stray UID-0 account, a disabled
firewall, a five-month-old kernel, a container in a restart loop. Because the finding set is the
same schema, a host finding gates and suppresses exactly like a code finding.

**Configuration**

| Key / flag | Effect |
|---|---|
| `--os linux\|macos\|windows` | Probe script selection; default `linux` |
| `--key FILE` | Private key (adds `IdentitiesOnly=yes`); else `ssh-agent` / `~/.ssh/config` |
| `SSH_AUTH_SOCK` | Required in server mode unless `--key` is available |
| `<data>/cache/lynis/` | Lynis tarball, populated by `readyhai tools update` |

**Notes & limits.** The host key must already be in `known_hosts` — ReadyHai will not accept an
unknown key on your behalf. The target syntax is `user@host[:port]` with charset
`[A-Za-z0-9._-]`, and the SSH host goes through the same scope guard as web targets. `host.cve` is
`not_applicable` on non-Linux hosts or when the probe returned no package inventory; Lynis on
Windows is `not_applicable`. A probe that ran without root reports reduced coverage (non-root,
TCC-blocked reads, PowerShell not in FullLanguage, not elevated) as `partial`, and an unprivileged
Lynis run is likewise `partial`. Listening ports and the kernel release are recorded in
`out/host-probe.json` and reported through the update and sshd rules; ReadyHai does not enumerate
extra ports with a scanner unless you add `nmap`/`rustscan`/`naabu` as plugins
([plugins/official/](../../plugins/official/)).

---

## Android APK / AAB

```bash
readyhai scan android:./app-release.apk
readyhai scan android:./app-release.apk --device emulator-5554 --profile standard
```

**What it does.** `android.mobsf` (`quick`, MobSF container) statically analyses the package:
manifest flags (`debuggable` high, `allow_backup` medium, `cleartext_traffic` medium), code,
binary, network-security-config and certificate analysis, dangerous permissions
(`mobsf.permissions.dangerous`, low), trackers, hardcoded secrets (`mobsf.secrets.hardcoded`,
medium, **values withheld — a count only**) and `mobsf.target_sdk.outdated` (targetSdk < 33).
`android.runtime` (`standard`, adb) installs the APK, launches it with `monkey`, waits 20 s and
reads `logcat -d *:E` for crashes and ANRs (`android.crash`, `android.anr`, high, reliability),
uninstalling the app if ReadyHai installed it.

**Why it matters.** Mobile findings live in a build artefact nobody diffs: an accidentally
debuggable release build, `allowBackup`, cleartext traffic, a pinned SDK from four versions ago,
and a crash that only appears once the app is actually launched on a device.

**Configuration.** `--device SERIAL|HOST:PORT` enables the runtime check (adb install needs an
`.apk`; an `.aab` with `--device` is `skipped`). MobSF runs as a per-scan container with a random
API key passed by environment variable and a port bound to `127.0.0.1` only; the report is
scrubbed before saving.

**Notes & limits.** The stock MobSF image ships no `semgrep`, so `mobsf.code_analysis.*` findings
are absent even though JADX decompiles — and JADX itself is downloaded from GitHub at scan time,
so the MobSF scan needs internet and degrades to `skipped`/`errored` in a fully air-gapped lane.
On an emulator under `--profile deep`, `android.runtime` additionally runs a 1500-event monkey
stress. The MobSF container is the one documented exception to the standard sandbox: it is not
read-only, not `--user`-restricted and needs a bridge network
([security-model](../security-model.md)).

---

## Baselines & noise control

Four mechanisms, each with a different job. Using only one of them is usually why a scan is noisy.

### 1. Baseline: gate on new findings only

```bash
readyhai scan .
readyhai baseline accept 20261025-101500-a1b2 --out .readyhai/baseline.json
git add .readyhai/baseline.json          # CI agents have no local state
readyhai scan . --baseline .readyhai/baseline.json
```

A baseline is a sorted set of fingerprints — commit it. Findings present in it become `existing`
and are excluded from the verdict (default `only_new = true`); baseline entries that stop
appearing are counted as `fixed` ("N fixed since baseline"). Without `--out`, the baseline is
stored per target at `<data>/baselines/<hash>.json` and picked up automatically for the same
target path. The snapshot skips `.readyhai/`, so committing the baseline does not make it a
finding. On a QA run, `baseline accept` also promotes the spec snapshot, visual screenshots and
the last perf result.

### 2. Suppressions: accepted risk with an owner and an expiry

```toml
# <repo>/readyhai.toml
[[suppress]]
rule = "readiness.compose.privileged"    # rule id, prefix, or glob ("CVE-2024-*")
path = "services/isolate/**"             # optional glob on the finding path
reason = "judge0 isolate needs privileged"
expires = "2027-03-31"                   # required
```

`reason` and `expires` are mandatory — a suppression that cannot fail is not a control. Expired
entries are ignored with a note. Suppressed findings stay in every report (`status = suppressed`,
`suppressed_reason = "<reason> (until <expires>)"`), are marked `suppressions` in SARIF, and never
gate.

### 3. Settings: operator-level tool/plugin toggles

`--settings FILE` (env `READYHAI_SETTINGS`, flag wins) points at an **operator-owned** file; a
scanned repo's own settings file is never read. Tri-state values are `auto` (default), `on`,
`off`, resolved per check as *exact `[[toggle]]` id > last matching glob > category switch > auto*.

```toml
[integrations]
tools = "auto"       # pinned-container tool checks
plugins = "auto"     # plugin.* checks
intrusive = "auto"   # kill switch: auto | off only — "on" is rejected at load

[[toggle]]
id = "plugin.crowdstrike.*"
enabled = "off"
```

`off` produces a normal `Skipped` with a visible reason — a toggle never hides coverage. `on`
protects a check from *settings* only; the profile, scope-nonprod, `--no-tools` and Docker-
availability gates keep their authority. A file that fails to parse or validate is a hard error.
Full file: [`settings.example.toml`](../../settings.example.toml).

### 4. vulndb: cross-target memory

Every warn/fail finding from any scan is appended to one local JSONL
(`<data>/vulns/vulns.jsonl`, or `[vulndb] path`), one row per target × kind × rule × resource
keyed by a 24-hex fingerprint. Re-observing bumps `occurrences`/`last_seen` instead of
duplicating.

```bash
readyhai vulns                                  # open findings
readyhai vulns --json --target https://staging.example.com
readyhai vulns accept 4f2a91c7d3                # 6+ chars, unique prefix
readyhai vulns forget 4f2a91c7d3
```

`accepted` and `forgotten` survive re-scans; an acceptance resets to `open` if the severity moved.
Recording never changes a verdict or exit code, the file is capped at 10 MB, and it needs no
database server. Safe re-verification of recorded findings is separately opt-in via
`[exploits] enabled = true` (`readyhai exploits run <fp>`) — off by default, and every probe URL
re-enters through the scope guard in intrusive mode, so a `prod` host is refused.

---

## Reports

Reports are written to `--out` (default `readyhai-report`). Choose with `--format a,b` (default
`html,json`; unknown names are ignored).

| Format | File | Notes |
|---|---|---|
| `html` | `readyhai-report.html` | Single file, auto-escaped, CSP `default-src 'none'; style-src 'unsafe-inline'; img-src data:`, no JavaScript |
| `json` | `readyhai-report.json` | The full `Run` — checks, findings, verdict basis, categories |
| `sarif` | `readyhai-report.sarif` | SARIF 2.1.0, `partialFingerprints["readyhai/v1"]`, suppressed findings carry `suppressions` |
| `junit` | `readyhai-report.junit.xml` | One `testsuite` per check; `failure` per new finding ≥ medium |

```bash
readyhai scan . --format html,json,sarif,junit --out readyhai-report
readyhai scan https://staging.example.com --format sarif --out sarif-out   # GitHub code scanning
```

SARIF levels: critical/high → `error`, medium → `warning`, low/info → `note`. `readyhai dashboard
--out DIR` builds a static offline trend view of all runs from `<data>/index.jsonl`, and
`readyhai serve` exposes the same results over REST
([api](../api.md)). CI recipes — GitHub Actions, GitLab, Jenkins, ArgoCD PostSync, SARIF upload,
baseline in CI — are in [ci](../ci.md).

**Notes & limits.** `pdf`, `md`, `jira`, `gitlab`, `testrail` and `xray` are QA-run formats, not
`scan` formats: an unknown name in `--format` is simply ignored, so check the files land. The
report directory is a plain directory the caller chooses; nothing prunes it.

---

## Tool orchestrator & plugged OSS scanner packs

ReadyHai ships 19 scanner images in its lock (18 of them digest-pinned) and, since v3.6, a plugin
system for everything else. Both paths are the same machinery: a pinned container, a declarative
config, one of four output formats, and the same Finding schema.

### The lock: `tools.lock.toml`

```toml
[tools.grype]
image = "anchore/grype:v0.121.3"
digest = "sha256:13113eec…"
version = "v0.121.3"
```

Keys: `syft`, `grype`, `gitleaks`, `semgrep`, `opengrep`, `hadolint`, `checkov`, `dockle`, `zap`,
`nuclei`, `schemathesis`, `git`, `mobsf`, `k6`, `osv-scanner`, `scorecard`, `spectral`, `oasdiff`,
`playwright`. When `digest` starts with `sha256:` the image runs as `repo@sha256:…` (tag dropped);
otherwise the tag runs and every check adds a note (`tool image X unpinned - run readyhai tools
pull --lock`). Precedence: `READYHAI_TOOLS_LOCK` > `<data>/tools.lock.toml` (installed by
`bundle import`) > the lock embedded in the binary.

```bash
readyhai tools pull --lock tools.lock.toml      # docker pull each entry, rewrite with digests
readyhai tools pull --plugins ./plugins         # also pull valid plugin images, warn on drift
readyhai tools update                           # grype DB, OSV DBs, nuclei templates,
                                                # semgrep/opengrep rules, lynis tarball
readyhai doctor                                 # mode, tool presence, DB age, LLM, disk
```

`tools pull --lock` is **trust-on-first-use**: it pins whatever the registry served at that
moment. Review the diff and verify cosign signatures where the vendor publishes them.
`tools update` is the only step that uses the network at normal run time.

### Container sandbox

Every built-in tool and every plugin runs with `--network none` unless the check genuinely needs
network — in code that is Schemathesis, ZAP, Nuclei, Playwright, `tests.own` with
`network = true`, plugin `network = true`, and `tools update` — plus `--cap-drop ALL`,
`no-new-privileges`,
`--read-only`, `--user 65534:65534`, `--tmpfs /tmp`, pids/memory/CPU limits, `--log-driver none`,
`HOME=/tmp` only (no host environment passthrough), and a hard per-check timeout. Mounts are
`/src` read-only, `/out` writable, `/cache` read-only. A create-policy check rejects
`--privileged`, host namespaces, `--cap-add`, mounts outside `/src` `/out` `/cache`, and any
argument mentioning `docker.sock` — ReadyHai never gives a scanner the Docker socket.

In the shipped Compose stack, ReadyHai itself reaches Docker through
[`tecnativa/docker-socket-proxy:v0.5.0`](../../docker-compose.yml) on an internal network with
`EXEC=0`, `BUILD=0`, `SWARM=0`, `SECRETS=0`. The proxy filters Docker API *paths*, not request
bodies: it is defence in depth, not a security boundary. Prefer rootless Docker or Podman on
shared hosts.

### Plugging in OSS scanners

A plugin is `plugins/<name>/plugin.toml`: a pinned image, `args` with `{src}` `{out}` `{url}`
`{domain}` `{image_tar}` placeholders, and `format = "sarif" | "junit" | "readyhai-json" | "lines"`
(JSONL, for recon CLIs like `httpx -json`). Optional runner-v2 fields cover real scanner needs:
`cache_rw` (writable `/cache` for self-updating DBs), `env` (variable **names**, values never in
argv), `stdout`, `host_gateway`, `user`, `network`, `entrypoint`, and `intrusive` to respect the
scope `prod` guard. An unpinned plugin image reports `partial`.

```bash
cp -r plugins/official ./plugins && export READYHAI_PLUGINS=./plugins
readyhai tools pull --plugins ./plugins
readyhai scan . --profile standard
readyhai checks        # confirm plugin.<id> rows loaded
```

Verified packs in [`plugins/official/`](../../plugins/official/): recon (`subfinder`, `httpx`,
`katana`, `dnsx`, `naabu`, `tlsx`, `gau`, `feroxbuster`), posture (`kube-linter`, `kube-score`,
`conftest`, `kubescape`), supply chain (`grype`, `osv-scanner`), and network attack (`nmap`,
`rustscan`, `testssl`, `sqlmap`, `nikto`). Vendor tools are bring-your-own-license templates only
(`plugins/_example/`: trivy, OWASP dependency-check, npm-audit, CrowdStrike Falcon) — ReadyHai
never redistributes licensed content. Since v3.6.0 the engine also provisions packs it is about
to run at scan start (pulling a missing digest-pinned image, creating its cache dir) and records
each action as a `setup:` note; a failed pre-pull degrades to the usual skipped/partial status
instead of failing the run.

### Feeds & offline

```bash
scripts/fetch-feeds.sh            # core: wordlists + KEV + EPSS + nuclei templates
scripts/fetch-feeds.sh recon      # wordlists for ferox/ffuf/katana pipelines
scripts/fetch-feeds.sh vulndata   # CISA KEV, FIRST EPSS, GHSA dump
scripts/fetch-feeds.sh rego       # ReadyHai rego pack for conftest
```

Everything is fetched from primary upstreams with a recorded sha256 into the same cache
(`$READYHAI_DATA_DIR/cache`, else `~/.local/share/readyhai/cache`) that plugins see as `/cache`;
a corrupt entry is re-downloaded, never trusted. EPSS and KEV aggregators are cached locally only
— not redistributed inside bundles. Full license/cadence table:
[data sources](../data-sources.md).

For air-gapped hosts, `readyhai bundle export` / `bundle import` move the binary, images, DBs,
rules and the end-of-life snapshot as a hashed tarball, and `READYHAI_OFFLINE=1` hard-fails every
pull and DB update:

```bash
readyhai bundle export --set core --out readyhai-bundle.tar   # connected machine
readyhai bundle import readyhai-bundle.tar                    # air-gapped machine
```

**Notes & limits.** `playwright` is intentionally unpinned — it is built locally
(`readyhai/playwright-runner:local`), so no registry digest exists. The `git` entry in the lock is
unused by the code: git clones run on the host, hardened (`core.hooksPath=/dev/null`,
`--depth 1`, no submodules, no credential helper, `BatchMode=yes`) and limited by
`READYHAI_GIT_TIMEOUT_SECS`. Plugin `plugin.toml` files that are invalid or have no valid `kinds`
are silently skipped at load — confirm with `readyhai checks` or `readyhai doctor`, which prints a
per-pack loaded/skipped reason. `host` and `android` target kinds are not supported by plugins
(`repo`, `image`, `web` only).

---

## Where to look next

- Every flag, target syntax and worked example: [usage](../usage.md)
- Every check id, rule id, severity and hard-fail prefix: [checks](../checks.md)
- Every config file key and environment variable: [configuration](../configuration.md)
- Sandbox controls, threat model, residual risks: [security-model](../security-model.md)
- Offline bundles, `doctor`, LAN-LLM mode: [offline](../offline.md)
- Orchestrator direction, verified packs, BYO-license policy: [superapp-orchestrator](../superapp-orchestrator.md)
- QA engine and autonomous agent: [Agent, QA & security intelligence](./agent-qa-security.md)
