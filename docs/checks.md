# Check catalog

List the live registry with `readyhai checks` (columns: id, kinds, min profile, tool or `native`, title, `[intrusive]`). 28 built-in checks; plugins add more. Columns below: **Tool** is the container image key in `tools.lock.toml`, or `native`.

## Check index

| Check id | Kinds | Min profile | Tool | Detects |
|---|---|---|---|---|
| `readiness.dockerfile` | repo | quick | native | Root user, missing HEALTHCHECK, `:latest` bases, remote `ADD`, no `.dockerignore` |
| `readiness.deps` | repo | quick | native | Unpinned deps, unpinned `git+` deps, missing lockfile |
| `readiness.compose` | repo | quick | native | `privileged`, docker.sock mount, host network, healthcheck problems, no limits, no restart policy |
| `readiness.k8s` | repo | quick | native | Plaintext Secret manifests, privileged, host network, missing probes/limits, run-as-root, `:latest` images |
| `readiness.ci` | repo | quick | native | Missing CI, scanners that can never fail or are skipped, missing SAST/secret/dependency scan stages |
| `readiness.repo` | repo | quick | native | Tracked secret-bearing files, no README, no tests, no `/health`, no OpenTelemetry |
| `tool.gitleaks` | repo | quick | gitleaks | Secrets in the snapshot (redacted) |
| `tool.sbom_cve` | repo, image | quick | syft + grype | SBOM, known CVEs with EPSS and KEV |
| `tool.semgrep` | repo | quick | semgrep | SAST with the cached rule pack |
| `tool.hadolint` | repo | quick | hadolint | Dockerfile lint |
| `tool.checkov` | repo | quick | checkov | IaC misconfiguration (k8s, compose, Dockerfile, terraform) |
| `tool.osv_reachability` | repo | standard | osv-scanner | Known CVEs annotated reachable / unreachable / unknown (Go call analysis); unreachable lowers severity one level, unknown never lowers |
| `tool.scorecard` | repo | standard | scorecard | OpenSSF Scorecard for a github.com `origin` (checks scoring < 5) |
| `tool.spectral` | repo | quick | spectral | OpenAPI lint (`spectral:oas` ruleset) |
| `tool.oasdiff` | repo | quick | oasdiff | OpenAPI breaking changes vs the accepted spec baseline |
| `qa.suite.mutation` | repo | quick | native | Mutation score from existing reports (qa only) |
| `tool.dockle` | image | quick | dockle | CIS-style image checks |
| `image.inspect` | image | quick | docker | Root user, no healthcheck, size, `:latest` tag |
| `tests.own` | repo | standard | target image | The project's own tests (JUnit) |
| `web.smoke` | web | quick | native | Status, latency, TLS use, headers, cookies, CORS, health endpoint |
| `tool.schemathesis` | web | standard | schemathesis | API fuzzing against OpenAPI |
| `tool.zap_baseline` | web | standard | zap | Passive ZAP baseline |
| `tool.playwright` | web | standard | playwright | Browser crawl: JS errors, failed requests, broken links |
| `host.probe` | host | quick | native (ssh) | OS/ssh/firewall/updates/accounts/logs |
| `host.cve` | host | quick | grype | Package CVEs (Linux only) |
| `host.lynis` | host | standard | native (ssh) | Lynis hardening audit |
| `android.mobsf` | android | quick | mobsf | Static APK/AAB analysis |
| `android.runtime` | android | standard | native (adb) | Install, launch, logcat crashes/ANRs |
| `plugin.<id>` | as declared | as declared | as declared | See [configuration.md](configuration.md#plugins) |

Note: `host.probe` and `host.lynis` have no `tool` set, so `--no-tools` does not skip them. `host.cve` and `image.inspect` do have one and are skipped.

## Supply-chain and API-contract checks

**`tool.osv_reachability`** runs OSV-Scanner v2 (`scan source --offline-vulnerabilities --call-analysis=go`) with the network off. It reads the DB from `<cache>/osv-scanner`, populated by `readyhai tools update`; without it the check is `skipped(osv vuln DB missing)`. Each finding carries `Reachability: reachable|unreachable|unknown` in the title and detail. `unreachable` (call analysis ran and no path exists) lowers severity one level with a note; `unknown` (no analysis: non-Go ecosystem, or no Go modules available in the sandbox) never lowers. Severity comes from the CVSS score, else the advisory rating. Only Go call analysis is enabled (Rust analysis runs build scripts). Exit 128 (nothing to scan) is `not_applicable`.

**`tool.scorecard`** needs a `github.com` remote in `.git/config` (else `not_applicable`) and `READYHAI_GITHUB_TOKEN` (else `skipped`); the token is passed to the container as `GITHUB_AUTH_TOKEN`, so it is visible in the local docker process list while the check runs. It is the only one of the five with network access (`skipped` when `READYHAI_OFFLINE=1`). One finding per Scorecard check scoring 0-4 (inconclusive `-1` is ignored). Severity is Scorecard's risk level one notch down: Dangerous-Workflow High; Binary-Artifacts, Branch-Protection, Code-Review, Dependency-Update-Tool, Maintained, Signed-Releases, Token-Permissions, Vulnerabilities Medium; Pinned-Dependencies, SAST, Security-Policy, Fuzzing, Packaging Low.

**`tool.spectral`** lints every OpenAPI 3 / Swagger 2 file found in the snapshot (up to 20; `*.baseline.*` files are skipped) with the built-in `spectral:oas` ruleset. Spectral error -> Medium, warn -> Low, info/hint -> Info. `not_applicable` when the repo has no spec.

**`tool.oasdiff`** runs `oasdiff breaking` between each spec and its accepted baseline, a file next to it named `<spec>.baseline.<yaml|yml|json>` (for example `openapi.yaml` and `openapi.baseline.yaml`). Breaking error -> High, warn -> Medium. No baseline -> `not_applicable`. A failed diff for one spec makes the check `partial`.

**`qa.suite.mutation`** never runs mutation tests. It reads existing reports: cargo-mutants `mutants.out/outcomes.json`, Stryker `reports/mutation/mutation.json`, mutmut 3 `mutants/**/*.meta`. Score = detected / (detected + survived); unviable, compile-error and unchecked mutants are excluded, timeouts count as detected. A score below 60% is a Medium finding (`qa.suite.low_mutation_score`). With only a config, or nothing, the check is `not_applicable` with a hint; the mutmut 2 SQLite `.mutmut-cache` is detected but not parsed. The mutation goldens in `tests/fixtures/tool-outputs/mutation-*.json` are format-faithful hand-built files, not captured runs.

## Status semantics

| Status | When |
|---|---|
| `passed` | Check ran and returned no findings |
| `failed` | Check ran and returned at least one finding (any severity, including suppressed ones; status is about the check, not the gate) |
| `partial(reason)` | Ran but coverage is incomplete (see below) |
| `skipped(reason)` | Did not run: `--no-tools`; `docker not available`; `vuln DB missing`; `rules missing`; `intrusive: needs --profile deep and a nonprod host`; Playwright runner image not built; ZAP URL with unsafe characters; `lynis tarball missing`; `adb not installed`; AAB with adb; no package inventory |
| `not_applicable(reason)` | Nothing to check: no Dockerfile, no manifests, no k8s/compose, no `[test]` in `readyhai.toml`, no OpenAPI spec, host is not Linux (`host.cve`), Lynis on Windows, no `--device`, no APK |
| `errored(reason)` | Tool failed or produced no output, SSH/adb failure, timeout, JUnit missing or only collection errors, panic |

Partial causes: `tool.sbom_cve` when any dependency is unpinned (`N of M deps unpinned; CVE coverage incomplete`) or when the grype DB is older than 7 days; `host.probe` when the probe reports reduced coverage (not root, TCC-blocked reads, PowerShell not in FullLanguage mode, not elevated); `host.lynis` when it ran unprivileged; plugins whose image is not digest-pinned.

Nothing is silently green: partial, errored and skipped are visible in the summary and HTML report. Partial and errored raise the verdict to at least WARN; skipped and not_applicable do not.

## Verdict rules

Implemented in `policy::verdict` using the policy (default in [configuration.md](configuration.md#policytoml)). Suppressed findings are ignored; with `only_new = true` (default) so are `existing` findings.

1. FAIL if any considered finding is at or above `fail_severity` (default `critical`).
2. FAIL if any considered finding's `rule` starts with a `hard_fail` prefix.
3. FAIL if `kev_fails` and any considered finding has `kev = true`. This is any KEV match in anything grype scanned (no runtime-vs-dev split; the plan wanted runtime-only).
4. WARN if any considered finding is at or above `warn_severity` (default `medium`), or any check is `errored` or `partial`.
5. Otherwise PASS.

Deviation: the plan made "a required check errored" a hard fail. In code an errored check is WARN only.

Default hard-fail prefixes: `secrets.`, `readiness.repo.tracked_secret_file`, `readiness.compose.privileged`, `readiness.k8s.privileged`, `tests.failed`, `web.5xx`, `api.server_error`.

## Rules by check

Severity and category are as emitted. "fp" = what identifies the finding across runs.

### readiness.dockerfile (parses the last stage of each Dockerfile found)

| Rule | Sev | Cat | Trigger |
|---|---|---|---|
| `readiness.dockerfile.no_user` | high | security | Final stage has no `USER`, or `USER root/0` |
| `readiness.dockerfile.no_healthcheck` | medium | reliability | No `HEALTHCHECK` (other than `NONE`) in the final stage |
| `readiness.dockerfile.latest_base` | low | supply_chain | A `FROM` image is untagged or `:latest` (build args and `scratch` skipped) |
| `readiness.dockerfile.add_remote` | low | supply_chain | `ADD` of an `http(s)://` URL |
| `readiness.dockerfile.no_dockerignore` | low | operability | No `.dockerignore` next to the Dockerfile |

### readiness.deps

Reads `requirements*.txt` and `package.json` (dependencies, devDependencies, optionalDependencies). Pinned means `==` for Python, exact semver for npm. Notes which requirements file a Dockerfile installs (`pip install -r`).

| Rule | Sev | Cat | Trigger |
|---|---|---|---|
| `readiness.deps.unpinned` | medium if under 80% pinned, else low | supply_chain | One finding per manifest with any unpinned dependency; detail lists up to 10 |
| `readiness.deps.git_unpinned` | medium | supply_chain | `git+` dependency without `@ref` |
| `readiness.deps.no_lockfile` | medium | supply_chain | No lockfile in the same directory as a manifest (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `Cargo.lock`, `go.sum`, `composer.lock`, `Gemfile.lock`) |

### readiness.compose (files named `docker-compose*.yml|yaml` or `compose*.yml|yaml`, parsed natively with merge keys; `docker compose config` is never used)

| Rule | Sev | Cat | Trigger |
|---|---|---|---|
| `readiness.compose.privileged` | high | security | `privileged: true` (hard-fail) |
| `readiness.compose.docker_sock` | high | security | Volume mounts `docker.sock` |
| `readiness.compose.host_network` | medium | security | `network_mode: host` |
| `readiness.compose.no_healthcheck` | medium | reliability | No healthcheck, `disable: true`, or `NONE` |
| `readiness.compose.healthcheck_root_path` | low | reliability | All URLs in the healthcheck probe `/` |
| `readiness.compose.healthcheck_missing_binary` | medium | reliability | Healthcheck uses `curl`/`wget` but the built image (slim/alpine/distroless, from the service's Dockerfile) never installs it |
| `readiness.compose.no_limits` | low | reliability | No `deploy.resources.limits`, `mem_limit` or `cpus` |
| `readiness.compose.no_restart` | low | reliability | No `restart` and no `deploy.restart_policy` |

### readiness.k8s (YAML files containing at least one object with `apiVersion` and `kind`; multi-document supported)

| Rule | Sev | Cat | Trigger |
|---|---|---|---|
| `readiness.k8s.plaintext_secret` | high | security | `Secret` manifest with non-empty `data`/`stringData` |
| `readiness.k8s.host_network` | medium | security | `hostNetwork: true` in a pod spec |
| `readiness.k8s.privileged` | high | security | Container `securityContext.privileged: true` (hard-fail) |
| `readiness.k8s.no_probes` | medium | reliability | Deployment/StatefulSet container missing readiness or liveness probe |
| `readiness.k8s.no_limits` | medium | reliability | Container without `resources.limits` |
| `readiness.k8s.probe_root_path` | low | reliability | One finding per file: probes only `/` |
| `readiness.k8s.run_as_root` | low | security | One finding per file: no `runAsNonRoot` / non-zero `runAsUser` |
| `readiness.k8s.latest_image` | low | supply_chain | One finding per file: image untagged or `:latest` |

Workload kinds read: Deployment, StatefulSet, DaemonSet, Job, CronJob. Comments never trigger rules (verified by the NuHire `argocd/` negative case). Kustomize overlays are not rendered (plan item not implemented).

### readiness.ci (Jenkinsfile*, `.github/workflows/*.y*ml`, `.gitlab-ci.yml`)

| Rule | Sev | Cat | Trigger |
|---|---|---|---|
| `readiness.ci.no_ci` | medium | operability | No CI file found |
| `readiness.ci.scanner_never_fails` | medium | security | A line naming a known scanner also has `--exit-code 0`, `|| true`, `--soft-fail` or `continue-on-error: true` |
| `readiness.ci.scanner_optional` | medium | security | Scanner guarded by `command -v`/`which`/`type -p`/`hash` |
| `readiness.ci.no_sast` | medium | security | No semgrep/sonar/bandit/codeql/snyk code/checkmarx/opengrep/readyhai anywhere in CI |
| `readiness.ci.no_secret_scan` | medium | security | No gitleaks/trufflehog/detect-secrets/ggshield/readyhai |
| `readiness.ci.no_dep_scan` | medium | security | No trivy/grype/snyk/osv-scanner/dependency-check/pip-audit/npm audit/readyhai |

Comment lines (`#`, `//`) are ignored. The stage checks are repo-wide (all CI files joined), the "never fails" checks are per line. Note this means a Jenkinsfile containing `readyhai` satisfies all three stage rules.

### readiness.repo

| Rule | Sev | Cat | Trigger |
|---|---|---|---|
| `readiness.repo.tracked_secret_file` | high | security | A denylisted (secret-bearing) file is tracked by git; path only, never read (hard-fail). Tracked state comes from `git ls-files` for every repo in the tree, including a parent repo |
| `readiness.repo.no_readme` | low | operability | No `README*` at the root |
| `readiness.repo.no_tests` | medium | quality | No test dir or `test_*.py`, `*_test.py`, `*_test.go`, `*.spec.*`, `*.test.*` |
| `readiness.repo.no_health_route` | low | reliability | Web framework detected (fastapi, flask, django, express, nestjs) and no `/health`, `/healthz`, `/ready` in sources |
| `readiness.repo.no_otel` | low | observability | Web framework detected and no `opentelemetry` in deps or sources |

### Container tools

| Check | Rule ids | Severity / category |
|---|---|---|
| `tool.gitleaks` | `secrets.<RuleID>` (e.g. `secrets.aws-access-token`) | high, security. Hard-fail. fp = `file|rule`. Secret value never recorded (`--redact`, plus scrubbed output) |
| `tool.sbom_cve` | The vulnerability id itself (`CVE-...`, `GHSA-...`); `ids` merges related ids | grype severity (Negligible/Unknown -> info). Category `security` if KEV else `supply_chain`. Carries `epss`, `kev`, `fix_version`. fp = `canonical-id|package|manifest path` |
| `tool.semgrep` | Semgrep `check_id` (prefix `cache.semgrep.` stripped) | ERROR high, WARNING medium, else low; security. fp = `path|hash(snippet)` |
| `tool.hadolint` | `DLnnnn` / `SCnnnn` codes | error high, warning medium, else low. Security for DL3002/DL3004/DL3020, else quality |
| `tool.checkov` | `CKV_*` ids (secrets framework skipped) | Checkov severity, default medium; security |
| `tool.dockle` | dockle codes (`CIS-DI-*`, `DKL-*`) | FATAL high, WARN medium, INFO low; PASS/SKIP dropped; security |
| `image.inspect` | `image.root_user` (high, security), `image.no_healthcheck` (medium, reliability), `image.large` (low, performance, over 1 GB), `image.latest_tag` (low, supply_chain) | Based on `docker image inspect` |
| `tests.own` | `tests.failed` | high, quality, hard-fail. One per failed case; location `suite::name` |

`tool.sbom_cve` runs syft (`dir:/src` or `docker-archive:/src/image.tar`) writing CycloneDX, then grype `sbom:` with DB auto-update off and no network. Skipped if `<cache>/grype` is missing.

`tests.own`: runs `sh -c <command>` in `test.image` with `/src` read-only as workdir. Needs `[test]` in the target's `readyhai.toml`; the command must write JUnit to `/out/junit.xml`. Only failed cases produce findings; if there are only errors (collection/environment) the check is `errored`. No auto-detection is done.

### Web

| Check | Rule ids | Severity / category |
|---|---|---|
| `web.smoke` | `web.5xx` (high, reliability; also used for "target unreachable"), `web.4xx` (medium, reliability), `web.slow` (low, performance, over 2 s), `web.no_tls` (medium, security, plain HTTP on a non-local host), `web.missing_headers` (medium, security: HSTS on https, CSP, X-Content-Type-Options, X-Frame-Options or `frame-ancestors`, Referrer-Policy), `web.version_disclosure` (low, security: `Server`/`X-Powered-By` with digits), `web.insecure_cookie` (medium, security: missing Secure/HttpOnly/SameSite), `web.cors_permissive` (medium, security: reflected arbitrary Origin or `*` with credentials), `web.no_health` (low, reliability: none of `/health`, `/healthz`, `/api/health`, `/ready` returns 2xx) | Only the start URL is requested (plus the CORS probe and health paths). Follows up to 5 redirects. **TLS certificate expiry and protocol versions are not checked.** |
| `tool.schemathesis` | `api.server_error` (high, reliability, hard-fail), `api.auth_not_enforced` (high, security; ST401/ST203), `api.undeclared_method` (low; ST204, e.g. TRACE -> 501), `api.invalid_input_accepted`, `api.schema`, `api.content_type`, `api.status_code`, `api.check` (medium, quality) | Verified live against Schemathesis v4 (`run --report junit --report-dir /out`, file `junit-<ts>.xml`). The JUnit `message` carries only check codes (`ST101, ST204`); classification uses those codes and the failure body text. `not_applicable` without a spec |
| `tool.zap_baseline` | `zap.<pluginid>` | ZAP risk: 3 high, 2 medium, 1 low, else info; security. Passive baseline only, `-I` so ZAP warnings do not fail the run |
| `tool.playwright` | `web.page_error` (high, quality), `web.console_error` (medium, quality), `web.broken_link` (medium, quality), `web.5xx` (high, reliability), `web.4xx` (low, reliability) | Same-origin crawl, up to 20 pages, GET/HEAD only. Needs the locally built runner image |

`web.5xx` from Playwright and `api.server_error` from Schemathesis are hard-fail. Loopback targets (`localhost`, `127.0.0.1`, ...) are rewritten to `host.docker.internal` for containers.

### Host

| Check | Rule ids | Severity / category |
|---|---|---|
| `host.probe` (Linux) | `host.ssh_root_login` (high), `host.ssh_password_auth` (medium), `host.disk_full` (medium over 85%, high over 95%, reliability), `host.pending_updates` (high if security updates, else medium), `host.failed_units` (medium, reliability), `host.no_firewall` (medium), `host.uid0_extra` (high), `host.nopasswd_sudo` (medium), `host.no_time_sync` (low, reliability), `host.container_restarting` (medium, reliability; over 3 restarts or `Restarting`) | security unless noted |
| `host.probe` (macOS) | `host.ssh_root_login`, `host.ssh_password_auth`, `host.disk_full`, `host.sip_disabled` (high), `host.gatekeeper_off` (medium), `host.filevault_off` (medium), `host.mac_firewall_off` (medium) | security unless noted |
| `host.probe` (Windows) | `host.defender_off` (high), `host.defender_stale` (medium, over 3 days), `host.firewall_off` (high, per profile), `host.smb1` (high), `host.rdp_no_nla` (high), `host.pending_updates` (high/medium) | security |
| `host.cve` | CVE ids as in `tool.sbom_cve`, `check` = `host.cve`, location `user@host:package` | Linux only; needs a package inventory from the probe; scanned with grype in a container |
| `host.lynis` | `lynis.<TEST-ID>` (warnings medium, suggestions low), `lynis.hardening_index` (low, index under 65) | security. Lynis 3.1.6 tarball from `tools update`, streamed over ssh and run from a temp dir |

Journal/oslog/event-log error lines go to the error clusters (`host.journal`, `host.oslog`, `host.eventlog`) after redaction. Probe output is stored as `out/host-probe.json`.

### Android

| Check | Rule ids | Severity / category |
|---|---|---|
| `android.mobsf` | `mobsf.manifest_analysis.<key>` (special keys `debuggable` high, `allow_backup` medium, `cleartext_traffic` medium), `mobsf.code_analysis.<id>` (carries CWE ids), `mobsf.binary_analysis.*`, `mobsf.network_security.*`, `mobsf.certificate.*`, `mobsf.permissions.dangerous` (low), `mobsf.trackers.detected` (low), `mobsf.secrets.hardcoded` (medium, values withheld), `mobsf.target_sdk.outdated` (medium, supply_chain, targetSdk below 33) | Severity from MobSF; security unless noted. Report scrubbed into `out/mobsf.json`. Verified live (MobSF v4.6.3, InsecureBankv2.apk: 11 findings, secrets count-only). The stock image ships no `semgrep`, so `code_analysis` is empty (no `mobsf.code_analysis.*`) even though JADX decompiles; JADX itself is downloaded from GitHub at scan time, so the scan needs internet. |
| `android.runtime` | `android.crash`, `android.anr` | high, reliability. Installs the APK, launches it with `monkey`, waits 20 s, reads `logcat -d *:E`. In `deep` on an emulator only, 1500 monkey events. Uninstalls if it installed the app |

### Plugins

`plugin.<id>` findings use the rule ids from the plugin's output (SARIF `ruleId`, JUnit `tests.failed`, or `rule` in `readyhai-json`). SARIF levels map error high, warning medium, note low, none info; category `security`.

## Fixture expectations (`tests/fixtures/vuln-app`)

Native rules must produce at least: `readiness.dockerfile.no_user`, `.no_healthcheck`, `.no_dockerignore`, `readiness.deps.unpinned`, `.no_lockfile`, `readiness.compose.privileged`, `.healthcheck_root_path`, `.healthcheck_missing_binary`, `.no_limits`, `readiness.k8s.no_probes`, `.no_limits`, `readiness.ci.no_sast`, `.no_secret_scan`, `.scanner_never_fails`, `.scanner_optional`, `readiness.repo.tracked_secret_file`, `.no_otel`. See [development.md](development.md).

## QA checks (`readyhai qa` only, increment 2)

Registered with `.qa()`: they run only under `readyhai qa`, not `scan`. Details and severities are in [qa.md](qa.md). Each defect becomes one finding with the rule id below.

| Check id | Min profile | Tool | Rules |
|---|---|---|---|
| `qa.plan` | quick | native | risk-based plan, no findings |
| `qa.api.functional` | quick | native | `qa.api.server_error` (High), `qa.api.error_leak` (Medium), `qa.api.undocumented_status` (Low), `qa.api.contract_violation` (Medium), `qa.api.validation_missing` (Medium), `qa.api.reflection` (Low), `qa.api.breaking_change` (Medium), `qa.api.slow_response` (Low) |
| `qa.api.authz` | quick | native | `qa.api.authz_missing` (High), `qa.api.privilege_escalation` (High) |
| `qa.api.stateful` | standard | native | `qa.api.bola` (Critical), `qa.api.persistence_failure` (Medium), `qa.api.delete_not_effective` (High), `qa.api.idempotency` (Low) |
| `qa.ui` | quick (forms/journeys/visual need standard) | playwright | `qa.ui.responsive_overflow` (Low), `qa.ui.a11y` (Medium for critical/serious, else Low), `qa.ui.slow_page` (Medium LCP / Low CLS), `qa.ui.validation_gap` (Medium), `qa.ui.journey_failed` (High), `qa.ui.visual_change` (Low) |
| `qa.perf` | standard | k6 | `qa.perf.regression` (Medium), `qa.perf.errors` (High), `qa.perf.slow` (Low) |
| `qa.resilience` | deep | native (docker); verified live with `tests/fixtures/resilience` (SIGINT/SIGTERM/SIGHUP also unpause) | `qa.resilience.hang` (High), `.no_degraded_status` (Medium), `.no_recovery` (Critical), `.health_lies` (Medium) |
| `qa.suite.coverage` | quick | native | `qa.suite.low_coverage` (Medium), `qa.suite.critical_uncovered` (Medium) |
| `qa.suite.routes` | quick | native | `qa.suite.untested_routes` (Medium) |
| `qa.suite.smells` | quick | native | `qa.suite.test_smells` (Low) |
| `qa.release.eol` | quick | native | `qa.release.eol_runtime` (High / Medium / Low) |
| `qa.release.migrations` | standard | docker | `qa.release.migration_failure` (High) |
| `qa.release.licenses` | quick | native | `qa.release.license` (High) |

Status rules: a QA check that cannot run (no Docker, no runner image, no coverage file, nonprod-only work on a non-nonprod host) is `Skipped` or records its cases as `untested`/`blocked`, never as passed. These checks are listed by `readyhai checks` together with the other built-in checks.
