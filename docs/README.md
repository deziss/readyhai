# ReadyHai documentation

ReadyHai ("Ready hai?" = "is it ready?") is a self-hosted QA tester and production-readiness gate written in Rust. You point it at a repo, a container image, a web app/API, a host (SSH) or an Android app. It runs native readiness rules plus pinned scanners in hardened throwaway containers, and returns one verdict (`PASS` / `WARN` / `FAIL`) with reasons.

These docs describe what the code in `src/` does as of 2026-10-25 (v0.1.0). Where the code differs from the original plan, the docs say so. A verification agent was fixing bugs in `src/` while these were written; if you see a mismatch, trust the code and check `build-log.md` for the latest status.

## Index

| Doc | What it covers |
|---|---|
| [architecture.md](architecture.md) | Components, data flow, data model, run directory, design choices and trade-offs |
| [qa.md](qa.md) | Senior-QA guide: `readyhai qa`, API/UI/perf/resilience/suite checks, roles.toml, safety model, recommendation logic, reports |
| [offline.md](offline.md) | Air-gapped bundle, `READYHAI_OFFLINE`, `doctor`, LAN-LLM mode |
| [status-and-competition.md](status-and-competition.md) | Where ReadyHai stands after increment 2 (live vs unit-only), competitor table, sources |
| [usage.md](usage.md) | Every CLI command and flag, target syntaxes, profiles, reports, exit codes, baseline workflow, examples |
| [checks.md](checks.md) | Full check catalog, every rule id, severities, hard-fail rules, status semantics |
| [configuration.md](configuration.md) | `readyhai.toml`, `policy.toml`, `scope.toml`, baseline JSON, `tools.lock.toml`, plugins, env vars |
| [security-model.md](security-model.md) | Threat model, controls with code locations, known residual risks |
| [api.md](api.md) | REST endpoints and the MCP stdio server |
| [deployment.md](deployment.md) | Docker compose, images to build, offline operation, sizing |
| [ci.md](ci.md) | Jenkins, GitHub Actions, GitLab CI, ArgoCD PostSync, SARIF, baseline in CI |
| [claude-code-mod.md](claude-code-mod.md) | The `/readyhai` Claude Code mod |
| [development.md](development.md) | Repo layout, module map, adding checks/plugins/targets/parsers, tests, conventions |
| [market-research.md](market-research.md) | OSS vs commercial landscape, the gap, sources |
| [roadmap.md](roadmap.md) | Phase status, deferred items, agent loop design, known issues |
| [build-log.md](build-log.md) | What was done in this build, in order |

## 60-second quick start

```bash
cd ~/95095/Backup/Desktop/learn/readyhai
export PATH=$PATH:$HOME/.cargo/bin          # cargo is not on PATH by default here
cargo build                                 # dev build; binary at target/debug/readyhai
R=target/debug/readyhai

$R scan tests/fixtures/vuln-app --no-tools  # native rules only, no Docker needed
echo "exit=$?"                              # 0 PASS, 1 WARN, 2 FAIL, 3 tool error
xdg-open readyhai-report/readyhai-report.html

# with scanners (needs Docker):
$R tools pull --lock tools.lock.toml        # pull scanner images and pin digests
$R tools update                             # grype DB + semgrep rules + lynis (only networked step)
$R scan ./my-service --profile quick

# accept today's findings so only NEW ones gate from now on
$R baseline accept <run-id> --out .readyhai/baseline.json
$R scan ./my-service --baseline .readyhai/baseline.json
```

# autonomous multi-agent QA run:
$R agent http://localhost:3000 --max-steps 5

# launch backend REST API & Execution Engine (port 8080):
$R serve --bind 127.0.0.1:8080

# launch Next.js Agent Studio UI (port 3000):
cd frontend && npm run dev                  # visit http://127.0.0.1:3000

Server mode: `cp .env.example .env`, set `READYHAI_TOKEN` (16+ chars), `docker compose up -d`, then see [api.md](api.md) and [deployment.md](deployment.md).

## Status at a glance

- Repo and image targets: implemented, unit-tested and passed verification round 1. Web: native smoke checked; ZAP, Schemathesis and the Playwright runner were never run live.
- Host (SSH), Android, MCP: implemented, tested against recorded fixtures; Windows probe and MobSF API shapes not verified live.
- LLM & Agentic AI: implemented and live-verified with local vLLM reasoning models (`qwen3.8-flash-next`).
- Increment 2 added `readyhai qa`, offline bundles, and static trend dashboard ([qa.md](qa.md)).
- Increment 3 completed the autonomous **Agentic AI QA engine** (`readyhai agent <target>`), the 4-pillar **Evidence Ledger** (`Value`, `Authority`, `Safety`, `Evidence`), and the cyber-dark **Agent Studio** Next.js interface at `http://127.0.0.1:3000` with the backend REST API on port `8080`. See [roadmap.md](roadmap.md) and [architecture.md](architecture.md).
