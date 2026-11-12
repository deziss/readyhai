# ReadyHai documentation

ReadyHai ("Ready hai?" = "is it ready?") is a self-hosted security scanner, autonomous pentest & QA agent, and production-readiness gate written in Rust. You point it at a repo, a container image, a web app/API, a host (SSH) or an Android app. It runs native readiness rules plus pinned scanners in hardened throwaway containers, a senior-QA engine and an autonomous testing agent, and returns one verdict with reasons: `PASS` / `WARN` / `FAIL` for scans, Go / Conditional Go / No-Go / Inconclusive for `qa`, `GO` / `CONDITIONAL_GO` / `NO_GO` for the agent.

These docs describe what the code in `src/`, `frontend/`, `tests/eval/` and `.github/workflows/` does (current version: `VERSION` / `0.8.0`; changelog: [../CHANGELOG.md](../CHANGELOG.md)). Where the code differs from the original plan, the docs say so. If you find a mismatch, trust the code and check [build-log.md](build-log.md) for older context.

## Index

| Doc | What it covers |
|---|---|
| [architecture.md](architecture.md) | Components, data flow, the agent module map (pipeline, oracle, verifier, lead, memory, change, ledger), data model, run directory, design choices and trade-offs |
| [usage.md](usage.md) | Every CLI command and flag, target syntaxes, profiles, reports, exit codes, baseline workflow, agent workflows, examples |
| [configuration.md](configuration.md) | `readyhai.toml`, `policy.toml`, `scope.toml`, baseline JSON, `tools.lock.toml`, plugins, every environment variable |
| [api.md](api.md) | REST endpoints, the egress guard, the agent API, the network lab API, and the MCP stdio server |
| [security-model.md](security-model.md) | Threat model, controls with code locations, known residual risks |
| [qa.md](qa.md) | Senior-QA guide: `readyhai qa`, API/UI/perf/resilience/suite checks, roles.toml, safety model, recommendation logic, reports |
| [eval.md](eval.md) | `readyhai eval`: scores the QA engine and agent against seeded-defect fixtures (recall, false positives, pass^k), suite file format, how to add a suite, CI job |
| [checks.md](checks.md) | Full check catalog (45 built-in checks), every rule id, severities, hard-fail rules, status semantics |
| [offline.md](offline.md) | Air-gapped bundle, `READYHAI_OFFLINE`, `doctor`, LAN-LLM mode |
| [deployment.md](deployment.md) | Docker compose, networks, published images, offline operation, sizing |
| [ci.md](ci.md) | ReadyHai's own workflows and the recipes for Jenkins, GitHub Actions, GitLab CI, ArgoCD PostSync, SARIF, baseline in CI |
| [claude-code-mod.md](claude-code-mod.md) | The `/readyhai` Claude Code mod |
| [development.md](development.md) | Repo layout, module map, adding checks/plugins/targets/parsers, tests, conventions |
| [status-and-competition.md](status-and-competition.md) | Where ReadyHai stands (live vs unit-only vs eval-gated), competitor table, sources |
| [roadmap.md](roadmap.md) | Phase status, what is done, what is next, known issues |
| [market-research.md](market-research.md) | OSS vs commercial landscape, the gap, sources |
| [build-log.md](build-log.md) | What was done in this build, in order, round by round |
| [../frontend/README.md](../frontend/README.md) | The Next.js Agent Studio: design system, scripts, token handling, node version |
| [../CHANGELOG.md](../CHANGELOG.md) | Release notes (Keep a Changelog) |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Contributor setup, CI verification gates, PR guidelines, AGPL-3.0 licensing |
| [../SECURITY.md](../SECURITY.md) | Supported versions, vulnerability disclosure policy, authorized testing scope |

## 60-second quick start

```bash
git clone https://github.com/deziss/readyhai.git
cd readyhai
export PATH=$PATH:$HOME/.cargo/bin          # if cargo is not yet on PATH
cargo build                                 # dev build; binary at target/debug/readyhai
R=target/debug/readyhai

$R scan tests/fixtures/vuln-app --no-tools  # native rules only, no Docker needed
echo "exit=$?"                              # 0 PASS, 1 WARN, 2 FAIL, 3 error
xdg-open readyhai-report/readyhai-report.html

# with scanners (needs Docker):
$R tools pull --lock tools.lock.toml        # pull scanner images and pin digests
$R tools update                             # grype DB + semgrep rules + lynis (only networked step)
$R scan ./my-service --profile quick

# accept today's findings so only NEW ones gate from now on
$R baseline accept <run-id> --out .readyhai/baseline.json
$R scan ./my-service --baseline .readyhai/baseline.json
```

Autonomous agent run (exit 0 GO, 1 CONDITIONAL_GO, 2 NO_GO or not evaluated):

```bash
$R agent https://staging.example.com --spec https://staging.example.com/openapi.json --dry-run   # plan only
$R agent https://staging.example.com --spec https://staging.example.com/openapi.json --max-steps 25
$R agent-memory show https://staging.example.com                                                # what it remembers
```

Score the detection logic against seeded bugs (needs `python3` and `git`; no docker, network or LLM):

```bash
$R eval                                     # report in ./eval-report/, exit 0 / 1 / 3
```

Server and Studio:

```bash
cp .env.example .env                        # set READYHAI_TOKEN (16+ chars)
cp scope.example.toml scope.toml            # must exist before `up` (it is bind-mounted)
docker compose up -d                        # API on 127.0.0.1:8080, Studio on 127.0.0.1:3000
```

Or without Docker: `export READYHAI_TOKEN=$(openssl rand -hex 24); $R serve --bind 127.0.0.1:8080`, then `cd frontend && npm run dev` (node 24; see [../frontend/README.md](../frontend/README.md)) and paste the same token under the key icon. See [api.md](api.md) and [deployment.md](deployment.md).

## Status at a glance

- Repo, image, web, host and Android scans: 45 built-in checks (including native Tree-sitter AST cross-file taint & auth-guard auditing `security.code_audit`, `tool.opengrep`, `tool.nuclei`, `tool.zap_active`, and OSV AST import enrichment); the web, UI, PDF, resilience and MobSF paths were run live on 2026-10-30. The Windows probe is the one path never run on a real host. Details: [status-and-competition.md](status-and-competition.md).
- Senior-QA engine (`readyhai qa`): API path live-verified (7/7 seeded bugs, 0 false positives), UI QA found 6/6 seeded UI bugs, see [qa.md](qa.md).
- Agent (`readyhai agent`): modular deep-security attack probes (JWT tampering, BFLA, reverse-proxy/ACL bypasses, BOPLA, blind SQLi/CMDi, SSTI, path traversal, open redirect, OAST SSRF, TOCTOU race conditions, GraphQL/HPP), interactive Playwright DOM/storage/cookie security (`BrowserSecurity`), white-box `--repo` AST source-sink linking, adaptive ReAct follow-up waves, independent k-replay verifier, lead and area sub-agents, per-target memory, and four-pillar Evidence Ledger. Gated across 10 eval suites (`readyhai eval`): `agent-api` (7/7), `security-deep`, `whitebox-exploit`, and 7 additional suites ([eval.md](eval.md)).
- Next: cross-service distributed tracing / multi-target dashboards and PR auto-fix patch synthesis ([roadmap.md](roadmap.md)).
