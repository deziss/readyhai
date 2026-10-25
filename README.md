# ReadyHai

**Ready hai?** A self-hosted QA tester and production-readiness gate. Point it at a code repo, a container image or a web app/API. It runs the right checks in hardened throwaway containers and gives one verdict, **PASS / WARN / FAIL**, with the reasons.

```
readyhai scan ./my-service                 # repo: deps/SBOM, CVEs, SAST, secrets, IaC, Dockerfile, readiness rules
readyhai scan image:nginx:1.27             # image: SBOM, CVEs, CIS (dockle), root/healthcheck/size
readyhai scan https://staging.app --profile standard   # web: smoke, headers, cookies, CORS, Schemathesis, ZAP baseline, Playwright crawl
readyhai scan ssh://ops@10.0.0.5 --os linux --key ~/.ssh/id_ed25519   # host: hardening, patches, ports, failed units, journal errors, package CVEs, Lynis
readyhai scan android:./app-release.apk --device emulator-5554         # Android: MobSF static + crash/ANR capture on your device
readyhai mcp                                # MCP server over stdio: lets Claude Code / other agents run scans
readyhai qa https://app.nonprod.example --repo ./svc --spec openapi.json --roles roles.toml --profile standard --format html,pdf,md,jira   # senior QA: API/UI/perf tests, auth matrix, Go/No-Go test summary
readyhai bundle export --set core && readyhai bundle import readyhai-bundle.tar   # air-gapped bundle (export online, import offline)
```

Exit codes for CI: `0` PASS · `1` WARN · `2` FAIL · `3` tool error. Reports go to `readyhai-report/` (`--format html,json,sarif,junit`).

## Quick start

```
cargo build                      # dev build; release: cargo build --release
readyhai tools pull --lock tools.lock.toml   # pull scanner images, pin digests
readyhai tools update            # vuln DB + rule packs (the only networked step)
readyhai scan . --no-tools       # native readiness rules only, no containers
readyhai scan .                  # everything
readyhai baseline accept <run-id> [--out .readyhai/baseline.json]
```

The gate only counts **new** findings compared with the baseline, so known debt doesn't block every deploy. Accept a baseline once, then commit `.readyhai/baseline.json` (pass it with `--baseline`) so CI agents keep it.

## Profiles

| Profile | Runs |
|---|---|
| `quick` | static checks: native rules, gitleaks, syft+grype, semgrep, hadolint, checkov, dockle, web smoke |
| `standard` | adds the project's own tests (`[test]` in readyhai.toml), Schemathesis, ZAP baseline |
| `deep` | adds intrusive checks, only on hosts tagged `nonprod` in `scope.toml` |

## Per-target config: `readyhai.toml`

```toml
[[suppress]]
rule = "readiness.compose.privileged"
path = "services/coding-platform/**"
reason = "judge0 isolate needs privileged"
expires = "2027-03-31"

[snapshot]
deny = ["**/judge0*.conf"]        # extra secret-bearing files to withhold

[test]
image = "myapp:dev"
command = "pytest -q --junitxml=/out/junit.xml -p no:cacheprovider"
```

## Secrets: what ReadyHai never does

- Scanners only see a **filtered snapshot** of the repo. `.env*` (except `*.example`), `*secret*.yaml`, keys, certificates and `creds*` files become empty placeholders, and their content is never opened. If one of them is tracked in git, ReadyHai reports it by path only.
- `.git` is not copied (history can hold old secrets), and symlinks are dropped.
- Gitleaks runs with `--redact`. Snippet fields are removed from the raw tool outputs.
- Tool containers run with no network (static scans), `--cap-drop ALL`, a read-only rootfs, a non-root user, logging off, and no env passthrough.

## Supply chain

The scanners are third-party code. Trivy's images were backdoored in March 2026, so ReadyHai treats every scanner as untrusted:
- **Pin by digest:** pin every image with `tools pull --lock`. Unpinned images run, but the report flags them.
- **No escalation:** tool containers never get privileged mode, host networking, the Docker socket or host binds. This is enforced in code.

## Server mode (Docker)

```
cp .env.example .env    # set READYHAI_TOKEN
docker compose up -d
curl -H "Authorization: Bearer $TOKEN" -X POST localhost:8080/runs -d '{"target":"/targets/app"}' -H 'content-type: application/json'
curl -H "Authorization: Bearer $TOKEN" localhost:8080/runs/<id>
curl -H "Authorization: Bearer $TOKEN" localhost:8080/runs/<id>/report/html > report.html
```

- **Repo targets** must sit under `/targets` (mount them read-only with `TARGETS_DIR`).
- **Web targets** must be listed in `scope.toml` (`READYHAI_SCOPE`).
- **Docker access:** `docker-socket-proxy` only limits Docker API *paths*, so anything that can reach it effectively has root on the host. On shared hosts, use rootless Docker or Podman.

## CI

Recipes are in `ci/`:
- **Jenkins:** a stage, which replaces `if command -v trivy … || true` steps that can never fail.
- **GitHub Actions:** SARIF upload.
- **GitLab:** a CI job.
- **ArgoCD:** a PostSync hook that checks the live nonprod environment.

## Plugins ("mods")

Add your own checks without recompiling. Put `plugins/<name>/plugin.toml` in the plugin directory (`--plugins DIR`): a container image plus args, with output in SARIF, JUnit or ReadyHai JSON.

```toml
id = "plugin.bandit"
title = "Bandit Python SAST"
kinds = ["repo"]
profile = "quick"
image = "ghcr.io/pycqa/bandit@sha256:…"
args = ["-r", "{src}", "-f", "sarif", "-o", "/out/bandit.sarif"]
output = "/out/bandit.sarif"
format = "sarif"
```

## Docs

Senior-QA guide: [docs/qa.md](docs/qa.md). Offline and LAN-LLM modes: [docs/offline.md](docs/offline.md). Status vs competitors: [docs/status-and-competition.md](docs/status-and-competition.md).

Full documentation is in [`docs/`](docs/README.md). It covers architecture, the check catalog, configuration, the security model, the API and MCP server, deployment, CI and the build log.

## Roadmap

- **Now:**
  - **Targets:** repo, image, web, hosts over SSH (Linux, macOS and Windows) and Android (MobSF plus an attached device).
  - **Runtime errors:** clustered into a "Top errors" report section.
  - **Integrations:** an MCP server, plus the LLM provider layer, which isn't wired to anything yet.
- **Next:**
  - **Agent loop:** Planner → Explorer → Triager, with a seeded-bug eval harness.
  - **Testing coverage:** desktop UI testing (Appium) and a live Kubernetes cluster audit.
  - **Platform:** a dashboard and multi-user access.
