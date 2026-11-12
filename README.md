<div align="center">

# ReadyHai 🛡️

**Ready hai?** *(रेड्डी है? / "Is it ready?")* — Self-hosted security scanner, autonomous pentest & QA agent, and production-readiness gate.

[![License](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.7.0-brightgreen.svg)](VERSION)
[![Rust](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](Cargo.toml)
[![Tests](https://img.shields.io/badge/tests-814%20Rust-informational.svg)](#testing)
[![Author](https://img.shields.io/badge/maintainer-Anshu%20Kushawaha-blueviolet.svg)](mailto:kushwahaanshu8858@gmail.com)

Point ReadyHai at a codebase, a container image, an API/web app, an SSH host, or an Android APK.  
It executes hardened, sandboxed checks and outputs a definitive verdict: **PASS**, **WARN**, or **FAIL**.

[Quick Start](#quick-start) • [Features](#key-capabilities) • [CLI Commands](#command-reference) • [Eval](#evaluation-harness) • [Version Management](#single-source-of-truth-versioning) • [Security & Secrets](#secrets-and-sensitive-data-policy) • [Documentation](docs/README.md) • [Changelog](CHANGELOG.md)

---

</div>

## Overview

Modern deployments often rely on dozens of disparate tools (`trivy`, `semgrep`, `gitleaks`, `hadolint`, `zap`, `playwright`, `k6`) glued together with shell scripts that mask errors or produce overwhelming, unprioritized alerts. 

**ReadyHai** unifies static analysis, dynamic security, end-to-end QA, and host hardening into a single high-performance binary:
- **One Clear Verdict:** Returns exit codes designed for CI pipelines: `readyhai scan` exits `0` PASS, `1` WARN, `2` FAIL; `readyhai qa` and `readyhai agent` exit `0` Go, `1` Conditional Go, `2` No-Go or not evaluated; `3` is always an error (bad input, unreadable scope file, I/O).
- **Zero-Noise Baselines:** Accept existing technical debt once (`.readyhai/baseline.json`). The gate strictly evaluates **new** defects introduced in PRs.
- **Throwaway Container Sandboxes:** Scanners run non-root, read-only, network-isolated, and capability-dropped (`--cap-drop ALL`).
- **Deterministic and honest:** verdicts come from code, never from an LLM. Anything that could not be measured is "not evaluated" or `null`, never a default score. A failure must reproduce under the verifier before it counts as a defect.
- **Measured against seeded bugs:** `readyhai eval` scores the QA engine and the agent on fixtures with known defects (recall, false positives, pass^k) and gates CI on it.
- **AI Agent Native:** Built-in Model Context Protocol (MCP) server over stdio for Claude Code and autonomous agents.

---

## Key Capabilities

| Target | What ReadyHai Checks |
|---|---|
| **Repository (`repo`)** | Dependencies/SBOM, CVEs with OSV call-graph + AST import reachability, native Tree-sitter AST & cross-file taint/auth-guard audit (`security.code_audit`), Opengrep intra-file taint (`tool.opengrep`), Semgrep SAST, secret leak detection, IaC misconfigurations, Dockerfile anti-patterns, test coverage, migration safety, native readiness rules. |
| **Container Image (`image`)** | Distro SBOM, package CVEs, CIS benchmarks via Dockle, non-root execution, healthchecks, layer sizes. |
| **Web & APIs (`web`)** | Smoke status, TLS chain/expiry/protocol inspection, security headers & weak CSP, cookie security, CORS policy, Schemathesis fuzzing, Nuclei template scanner, OWASP ZAP baseline & active nonprod scan, Playwright crawler (including client storage secrets, HttpOnly cookies, source maps, postMessage handlers). |
| **Host over SSH (`ssh://`)** | OS hardening, Lynis audit, kernel patches, listening ports, failed systemd units, journal errors, package CVEs (Linux, macOS, Windows). |
| **Android APK (`android:`)** | MobSF static analysis, dangerous permissions, hardcoded secrets, crash and ANR extraction from connected ADB devices/emulators. |
| **QA Test Suite (`qa`)** | Synthetic OpenAPI test generation, RBAC authorization matrix, k6 load testing, resilience & chaos testing, axe-core a11y, visual diffs, suite and release quality, a computed Go / Conditional Go / No-Go / Inconclusive recommendation. |
| **Super Agent (`agent`)** | Autonomous adversarial security & QA of an HTTP target: shared QA API checks, deep-security attack probes (JWT tampering, BFLA, ACL/path bypass, BOPLA, blind SQLi/CMDi, SSTI, OAST SSRF, TOCTOU, GraphQL/HPP), Playwright `BrowserSecurity` (DOM XSS, sinks, storage leaks), white-box `--repo` AST source-sink correlation, adaptive ReAct follow-up waves, independent verifier, per-target memory, and a deterministic four-pillar Evidence Ledger with a GO / CONDITIONAL_GO / NO_GO gate. |
| **Eval (`eval`)** | Scores the QA engine and the agent across 10 fixtures with seeded defects (`security-deep`, `whitebox-exploit`, `agent-api`, `agent-spa*`, `qa-api`, `qa-repo`, etc.): recall, false positives, pass^k, verdict stability, request and time budgets. |

---

## Super Agent Suite

The agent (`readyhai agent`, `POST /api/agent/run`, MCP `readyhai_agent_swarm`) is an orchestrator-worker structure around a deterministic core. The LLM is optional: when one is configured and reachable it can add validated test cases, prose notes and an advisory opinion, and it never changes a verdict.

- **Shared QA checks.** With an OpenAPI spec the agent reuses the QA engine's case generator, response validator, error-leak catalog and latency limit (`src/qa/api`), reads the ids of existing records from collection endpoints and validates each one against the spec. On the eval fixture it finds 7 of 7 seeded bugs.
- **Modular deep-security attacks (`src/agent/attacks/`).** Dedicated probe generators for JWT tampering (`alg:none`, stripped signatures, claim escalation, `kid` traversal), BFLA, reverse-proxy/header ACL bypasses (`/.`, `..;/`, `X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`), BOPLA excessive exposure & mass assignment, parameter-targeted Open Redirect / SSTI / multi-encoded path traversal / blind boolean & time-delay SQLi / command injection, OAST-backed blind SSRF, TOCTOU concurrency races, HTTP parameter pollution, and GraphQL introspection.
- **In-process OAST & BrowserSecurity.** An ephemeral loopback HTTP listener (`src/agent/oast.rs`) correlates out-of-band `__OAST_URL__` SSRF callbacks during execution and verification, while interactive Playwright (`src/agent/browser_sec.rs`, `runners/playwright/agent_browser.mjs`) verifies DOM XSS, DOM sinks, storage/cookie hygiene, exposed source maps, and clickjacking without storing raw secret values.
- **White-box AST bridge & ReAct follow-up.** `--repo DIR --diff-base REF` not only maps `git diff REF...HEAD` to changed operations, it also runs native Tree-sitter AST source/sink/guard analysis (`src/agent/whitebox.rs`, `src/code_audit.rs`) to target hidden handlers and annotate live defects with exact source locations (`file:line handler symbol`), followed by bounded adaptive ReAct exploration (`src/agent/react.rs`) under the run budget. An optional context retriever adds advisory notes.
- **Lead agent and area sub-agents.** The plan is split into `auth`, `contract`, `state` and `ui` areas; each area runs on its own worker (`READYHAI_AGENT_WORKERS`, default 4) with a slice of the run budget, then one deterministic wave 2 follows up. Results merge by case id, so one worker and eight give the same plan, defects and ledger. One per-host rate limit and one cancel flag are shared.
- **Independent verifier.** Every FAIL is replayed `READYHAI_VERIFY_K` times (default 2, max 5, `0` off) through the same oracle before it becomes a defect: reproduced = confirmed, partly = flaky, never = INCONCLUSIVE. The ledger reports pass^k.
- **Memory across runs.** The agent remembers each target (known defects by fingerprint, flaky cases, coverage) in `<data>/memory/`, tests the reproduction of known defects first, and reports "Since last run": new, still open, fixed, regressed, not re-tested, known flaky, accepted. Deterministic, never written from LLM text, and it only reorders the plan. `readyhai agent-memory accept ... --expires` lets a known defect through the gate until a date, listed in every report.
- **Extended Thinking.** A reasoning budget (1k to 32k tokens, clamped) and model tiers (`Low`, `Medium`, `High`, `Max`, `Max Pro`) when an LLM is configured. What is actually sent depends on the provider (OpenAI-compatible servers get `reasoning_effort` and a `max_tokens` cap; structured planning and verdict calls stay at a low temperature) and the run log says which.
- **Adaptive schema mutation, stateful chains, TOCTOU bursts.** Validation errors from FastAPI (Pydantic), Django REST Framework and Express (Zod) steer boundary mutations; multi-actor chains (Alice creates, Bob reads) audit BOLA/IDOR without counting prerequisite setup failures as breaches; barrier-synchronised bursts probe race conditions on spec-declared create operations.
- **Cleanup and example remediation.** Everything the run creates is recorded, deleted at the end on a confirmed nonprod target and read back; leftovers are listed. Remediation output is generic guidance labelled "example - adapt to your code", not a verified fix.
- **Model Context Protocol (MCP) Server.** `readyhai_agent_swarm` returns a run id at once; `readyhai_agent_status` and `readyhai_agent_cancel` poll and stop it; `readyhai_agent_discover` maps a target. Swarms are dry runs unless the caller asks and the operator sets `READYHAI_MCP_ALLOW_WRITES=1` (and the target is nonprod).

---

## Quick Start

### 0. Pre-built binary or image

```bash
# Container images (multi-arch, with SBOM + provenance)
docker pull ghcr.io/deziss/readyhai:latest

# Verify provenance of an image or a release tarball
gh attestation verify oci://ghcr.io/deziss/readyhai:latest --repo deziss/readyhai
gh attestation verify readyhai-linux-x86_64.tar.gz --repo deziss/readyhai
```

### 1. Build from Source

ReadyHai is written in high-performance Rust (2024 edition):

```bash
# Clone the repository
git clone https://github.com/deziss/readyhai.git
cd readyhai

# Build debug binary (or make release)
make build

# Build optimized, stripped release binary
make release
sudo cp target/release/readyhai /usr/local/bin/
```

### 2. Pull & Pin Tool Scanners

ReadyHai uses pinned container images for external scanners (Syft, Grype, Semgrep, Hadolint, Gitleaks, Checkov, Dockle):

```bash
# Pull scanner images and pin cryptographic sha256 digests
readyhai tools pull --lock tools.lock.toml

# Update local vulnerability databases & rule packs
readyhai tools update
```

### 3. Run Your First Scan

```bash
# Fast scan: native readiness rules only (zero container overhead)
readyhai scan . --no-tools

# Full static scan using sandboxed tools
readyhai scan .

# Run with custom profile and export multi-format reports
readyhai scan . --profile quick --format html,sarif,junit,json --out readyhai-report
```

### 4. Establish a Baseline

Prevent legacy debt from blocking active development:

```bash
# Accept baseline from a run id
readyhai baseline accept <run-id> --out .readyhai/baseline.json

# Commit .readyhai/baseline.json so CI checks only gate newly introduced findings
readyhai scan . --baseline .readyhai/baseline.json
```

### 5. Run the Server and the Studio with Docker

```bash
cp .env.example .env                # set READYHAI_TOKEN (16+ characters); never commit .env
cp scope.example.toml scope.toml    # rules of engagement; compose bind-mounts it, so it must exist BEFORE `up`
docker compose pull                 # ghcr.io/deziss/readyhai, readyhai-frontend (or: docker compose build)
docker compose up -d
curl http://127.0.0.1:8080/health   # {"status":"ok","version":"..."}
# Studio: http://127.0.0.1:3000 (compose attaches the token server-side; the backend API stays on 127.0.0.1:8080)
```

If `scope.toml` does not exist when you run `docker compose up`, Docker creates an empty directory of that name and `readyhai serve` refuses to start with a message that says how to fix it. Scan targets are mounted read-only from `./targets` (override with `TARGETS_DIR`) at `/targets`. See [docs/deployment.md](docs/deployment.md).

### 6. Test a Running App with the Agent

```bash
# Public hosts need no scope entry; internal hosts (localhost, RFC1918, host.docker.internal) must be listed in scope.toml
readyhai agent https://staging.example.com --spec https://staging.example.com/openapi.json --dry-run   # plan only, nothing is sent
export RH_ALICE_TOKEN=... RH_BOB_TOKEN=...      # test credentials, read only from the environment
readyhai agent https://staging.example.com --spec https://staging.example.com/openapi.json --max-steps 25
```

`--spec` takes an http(s) URL. Reports and the run's evidence are written under `<data>/agent-runs/<run id>/` (default data directory `~/.local/share/readyhai`).

### 7. Score ReadyHai Itself

```bash
cargo run -- eval                  # needs python3 and git; no docker, network or LLM
```

---

## Command Reference

### Scanning Targets

```bash
# 1. Codebase / Repository
readyhai scan ./services/user-api

# 2. Container Image
readyhai scan image:nginx:1.27

# 3. Web Service or API
readyhai scan https://staging.example.com --profile standard

# 4. Remote Host over SSH (Linux, macOS, Windows)
readyhai scan ssh://ops@10.0.0.5 --os linux --key ~/.ssh/id_ed25519

# 5. Android APK
readyhai scan android:./app-release.apk --device emulator-5554
```

### Senior QA Engine

Run automated contract testing, RBAC verification, load testing, and visual QA. The output is a QA test summary with a computed recommendation (Go, Conditional Go, No-Go or Inconclusive) next to the gate verdict:

```bash
readyhai qa https://api.staging.example \
  --repo ./services/api \
  --spec openapi.json \
  --roles roles.toml \
  --profile standard \
  --format html,pdf,md,jira \
  --out readyhai-qa-report
```

### AI Agent Integration (MCP)

Run ReadyHai as an MCP server over stdio for Claude Code or other autonomous agents:

```bash
readyhai mcp
```

Tools: `readyhai_scan`, `readyhai_checks`, `readyhai_run`, `readyhai_findings`, and the agent tools `readyhai_agent_swarm`, `readyhai_agent_status`, `readyhai_agent_cancel`, `readyhai_agent_discover`. There is deliberately no baseline, suppression or config tool. See [docs/api.md](docs/api.md#mcp-server).

### Autonomous Agentic AI QA & Production Gate

The agent runs a fixed pipeline: **Discovery -> Planner -> Explorer -> Verifier -> Cleanup -> Triager -> Readiness gate**. The Explorer stage is a lead agent that runs four area workers (`auth`, `contract`, `state`, `ui`). Verdicts are computed by deterministic code; an optional local reasoning model (vLLM / Ollama) only adds validated test cases and prose.

- **Planner:** boundary, negative, authorization, injection and state cases from the crawl and the OpenAPI spec; changed operations first when `--repo` / `--diff-base` are given; known defects first when memory exists.
- **Explorer:** sends the cases (one per-host rate limit, writes take turns), judges each response with the oracle, captures the reproduction curl (credentials as `${RH_<ROLE>_TOKEN}` placeholders) and a stored request/response evidence file.
- **Verifier:** replays every failure `READYHAI_VERIFY_K` times; only reproduced failures stay defects.
- **Triager:** clusters failures into defects with OWASP labels and severities from one table.
- **Readiness gate:** a four-pillar **Evidence Ledger** (*Value* 30, *Authority* 30, *Safety* 25, *Evidence* 15) and a deterministic **GO / CONDITIONAL_GO / NO_GO** verdict, or `NOT_EVALUATED` when nothing conclusive ran.

```bash
# Plan only: validate the scope and print what would run, send nothing
readyhai agent https://api.example.com --spec https://api.example.com/openapi.json --dry-run

# Run multi-agent QA via CLI (exit 0 GO, 1 CONDITIONAL_GO, 2 NO_GO or not evaluated)
readyhai agent https://api.example.com --spec https://api.example.com/openapi.json --max-steps 25

# Test what a PR changed
readyhai agent https://staging.example.com --spec https://staging.example.com/openapi.json \
  --repo . --diff-base origin/main

# What the agent remembers about a target; let a known defect through until a date
readyhai agent-memory show https://api.example.com
readyhai agent-memory accept https://api.example.com <fingerprint> --reason "tracked in OPS-1" --expires 2026-12-31

# 1. Start the ReadyHai backend engine (port 8080). READYHAI_TOKEN is required (16+ characters);
#    there is no fallback token, and every route except /health needs it.
export READYHAI_TOKEN=$(openssl rand -hex 24)
readyhai serve --bind 127.0.0.1:8080

# 2. Start the dedicated Next.js 16 frontend (port 3000; node 24, see frontend/README.md)
cd frontend && npm run dev -- -p 3000
# Open http://127.0.0.1:3000, click the key icon and paste the same token

# Or launch both together via Docker Compose (one-time setup: .env AND scope.toml must exist
# before the first `docker compose up`):
cp .env.example .env && cp scope.example.toml scope.toml
docker compose up -d
```

The agent sends write requests and attack payloads. A host listed `env = "prod"` in `scope.toml` is refused; public hosts and listed nonprod hosts are tested in full. See [Scope](#scopetoml-network--host-boundaries).

### Evaluation Harness

`readyhai eval` scores the QA engine and the agent against fixtures with **known, seeded defects**: recall, false positives, pass^k, verdict stability, and request and time budgets. It needs only `python3` (the fixture servers are stdlib scripts) and `git`; no network, no docker, no LLM. CI runs it as the `eval` job.

```bash
readyhai eval                      # all suites in tests/eval, k = 2, report in ./eval-report/
readyhai eval --suite qa-api --k 3 # one suite, three runs
echo $?                            # 0 every threshold met, 1 a threshold missed, 3 harness error
```

Suites: `qa-api`, `qa-repo`, `agent-api`, `agent-diff`, `agent-memory`. Details and the suite file format: [docs/eval.md](docs/eval.md).

### Web Interface (Port 3000)

The Next.js interface (IBM Plex, dark theme, `rh-*` design tokens) has three top-level views:

1. **Agent studio**
   - *Command center* (left): mode switch and header pinned at the top, **Run agent** pinned at the bottom, controls (target, OpenAPI spec, directives, profile, steps, model tier, reasoning budget, discovery and crawl) scroll in between. The token key button sits in the header.
   - *Six-stage pipeline stepper* (Recon, Discovery, Plan, Execute, Verify, Gate): click or keyboard a stage for its details; the layout never shifts. The Gate stage shows the backend's verdict.
   - *Workspace* (right): tabs for Scenarios and inspector (cURL, response, in-place retest), Discovered routes, Evidence ledger, Threat triage and Runs history, with the **Release gate** sign-off card (approve or block, recorded as the authenticated principal).
   - *Runs history*: every past agent run with its lifecycle chip (running, cancelled, failed), a **Cancel** button for running runs, report downloads (HTML in a sandboxed iframe, Markdown, SARIF, JSON, JUnit), and "load into studio".
2. **Scans**: master-detail archive of static scans (repositories, images, hosts) with verdict, kind and severity filters, a check execution grid, and report downloads (HTML, SARIF 2.1.0, JSON, JUnit).
3. **Network lab** (flakiness and intermittent-failure diagnostics):
   - **Regressive testing**: N iterations with separate private sessions (no connection pooling) to catch flapping endpoints, socket leaks and proxy drops, with throttling presets (Unthrottled, Fast 3G, Slow 3G, flaky jitter, custom latency).
   - **Root-cause diagnosis**: DNS, TCP, TLS, TTFB and gateway status stages; classification into `STABLE`, `TIMEOUT`, `5XX_FLAPPING`, `CONNECTION_RESET`, `HTTP_ERRORS`, `HIGH_JITTER`; copyable reproduction cURLs. Anything that cannot be measured is shown as not measured.
   - **Deep audit** (six pillars: dual-stack, sub-resources, protocol matrix, TLS, CORS preflight, MTU) and a **cURL runner** with stage timings.

The UI shows only what the backend reported; a missing verdict, score or measurement is "not evaluated", never a default.

### REST API & Web Dashboard

Launch the persistent ReadyHai daemon:

```bash
cp .env.example .env
# Edit READYHAI_TOKEN in .env (minimum 16 characters)
cp scope.example.toml scope.toml   # rules of engagement; compose bind-mounts it, so it must exist first
docker compose up -d

# Trigger scans via REST API
curl -H "Authorization: Bearer $READYHAI_TOKEN" \
     -X POST http://127.0.0.1:8080/runs \
     -H 'Content-Type: application/json' \
     -d '{"target":"/targets/my-app"}'
```

### Air-Gapped Environments

Export scanner tools and rule packs into an offline tarball:

```bash
# On an internet-connected machine:
readyhai bundle export --set core --out readyhai-bundle.tar

# On the air-gapped machine:
readyhai bundle import readyhai-bundle.tar
```

---

## Execution Profiles

| Profile | Checks Executed | Intended Environment |
|---|---|---|
| `quick` | Native readiness rules, Gitleaks, Syft + Grype, Semgrep, Hadolint, Checkov, Dockle, HTTP smoke. | PR checks, local pre-commit |
| `standard` | Everything in `quick` + target project test suite (`readyhai.toml`), Schemathesis API tests, OWASP ZAP baseline. | Staging CI/CD pipelines |
| `deep` | Everything in `standard` + intrusive checks: dependency fault injection (`qa.resilience`, `readyhai qa` only, compose services you allow-list), the Android monkey run, and plugins with `profile = "deep"`. Intrusive checks run only on hosts that `scope.toml` does not mark `prod` (a public host by default, or an entry with `env = "nonprod"`). | Nightly / Pre-release soak |

---

## Configuration

### `readyhai.toml` (Per-Project Rules)

Place `readyhai.toml` in your repository root to configure suppressions, test execution, or secret snapshots:

```toml
# Suppress a known accepted risk with an audit reason and expiration
[[suppress]]
rule = "readiness.compose.privileged"
path = "services/worker/**"
reason = "Sandbox worker requires isolated container execution"
expires = "2027-12-31"

# Withhold proprietary or sensitive files from snapshot copies
[snapshot]
deny = ["**/internal-certs/**", "**/*.pfx"]

# Custom test stage executed in standard profile
[test]
image = "python:3.12-slim"
command = "pytest -q --junitxml=/out/junit.xml"
```

### `scope.toml` (Network & Host Boundaries)

Rules of engagement for network targets. Copy `scope.example.toml` to `scope.toml` and edit it:

```toml
[[hosts]]
host = "staging.internal.net"   # exact host or "*.suffix"; "*" matches every host
env  = "nonprod"                # "nonprod" = full testing; "prod" = read-only

[[hosts]]
host = "app.example.com"
env  = "prod"                   # writes, attack payloads, load and fault injection are refused

[[hosts]]
host = "*"                      # the shipped default: everything not listed above is fully testable
env  = "nonprod"

[git]
hosts = ["*"]                   # git hosts allowed for clones (github/gitlab/etc. are built in)
```

How a target is decided:

- A **public** host needs no entry and gets **full testing** (it counts as `nonprod`): non-intrusive probes *and* intrusive actions (writes, attack payloads, load, fault injection, the agent swarm). Mark a host `env = "prod"` to keep it read-only.
- An **internal** host (loopback, RFC1918, link-local/metadata, CGNAT, unique-local v6, and the names `localhost`, `*.localhost`, `host.docker.internal`, `gateway.docker.internal`, `metadata.google.internal`, whatever DNS says) is **refused unless it is listed**, or matched by a `*` entry, which is you vouching that it is yours. A public name that resolves to any internal address counts as internal.
- An exact entry beats a wildcard, and `prod` beats `nonprod`, so a `prod` entry keeps its host read-only even next to `host = "*"`.
- Intrusive actions on an unlisted name that does not resolve are refused (it cannot be told apart from an internal host).
- A scope file that is configured (`--scope` / `READYHAI_SCOPE`) but missing, a directory or invalid is an **error**: the CLI and the server refuse to run rather than carry on without it. `readyhai serve` checks it at startup.

See [docs/configuration.md](docs/configuration.md#scopetoml).

---

## Secrets and Sensitive Data Policy

ReadyHai was designed from the ground up to **never leak credentials**:

1. **Filtered Snapshots:** Scanner containers never inspect raw repos directly. Sensitive files (`.env*` except `.example`, `*secret*.yaml`, `*.pem`, `*.key`, `id_rsa`, certificates) are stripped or replaced with 0-byte placeholders before tool execution.
2. **Path-Only Reporting:** If a secret file is tracked in git, ReadyHai reports the path and remediation instructions, but **never reads or displays its contents**.
3. **Redacted Findings:** Gitleaks runs with mandatory `--redact`. Snippet fields are scrubbed from raw SARIF and tool output JSONs.
4. **Placeholder Tokens:** QA and agent reproduction commands carry placeholders (`$RH_<ROLE>_TOKEN`, `${RH_<ROLE>_TOKEN}`), never real authorization headers. Test credentials are read only from `RH_<ROLE>_TOKEN` environment variables and are attached only to requests for the run's own target (same scheme, host and port), over a certificate-validating client, without following redirects.
5. **No Network Passthrough:** Static scan containers run without network connectivity, preventing exfiltration.
6. **Strict `.gitignore`:** The repository maintains comprehensive ignore rules preventing `.env*`, keys, certificates, build caches, and test artifacts from ever being committed or pushed.

---

## Single Source of Truth Versioning

Project versioning is governed strictly by the root `VERSION` file as the single source of truth:

```bash
# View current version
make version
# or: ./scripts/version.sh get

# Verify synchronization across Cargo.toml, Cargo.lock, and package.json
make version-check
# or: ./scripts/version.sh check

# Bump version semantically
make bump-patch     # 0.1.0 -> 0.1.1
make bump-minor     # 0.1.0 -> 0.2.0
make bump-major     # 0.1.0 -> 1.0.0

# Set explicit version
./scripts/version.sh set 0.2.0

# Create an annotated release tag
make tag
# or: ./scripts/version.sh tag
```

Release notes are in [CHANGELOG.md](CHANGELOG.md). Images are published only for the tag `v<VERSION>`.

The `./scripts/version.sh` utility guarantees atomic version propagation across:
- `VERSION` (single source of truth)
- `Cargo.toml`
- `Cargo.lock`
- `runners/playwright/package.json`
- `runners/playwright/package-lock.json`

---

## CI/CD Integration

### GitHub Actions

Add `.github/workflows/readyhai.yml` to your repositories:

```yaml
name: ReadyHai Production Gate

on:
  push:
    branches: [ main, master ]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install ReadyHai
        run: |
          curl -sSfL https://github.com/deziss/readyhai/releases/latest/download/readyhai-linux-x86_64.tar.gz | sudo tar xz -C /usr/local/bin

      - name: Run ReadyHai Gate
        run: |
          readyhai scan . --profile quick --format sarif,html,junit --out readyhai-report

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: readyhai-report/readyhai-report.sarif

      - name: Archive HTML Readiness Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: readiness-report
          path: readyhai-report/
```

*Pre-built recipes for GitLab CI, Jenkins, and ArgoCD are located in the [`ci/`](ci/) directory.*

---

## Testing

ReadyHai has a large automated test suite: 814 Rust `#[test]` functions in `src/` (3 are `#[ignore]`d), 127 frontend test cases (vitest), and 18 Python tests for the context retriever (`1` skipped if `numpy` is absent). On top of unit tests, `readyhai eval` scores detection against seeded defects across 10 suites (`agent-*`, `qa-*`, `security-deep`, `whitebox-exploit`). They cover golden fixtures, snapshotting, AST taint/auth auditing, OAST & browser security, policy evaluation, redaction, the scope guard, the oracle, verifier, lead and memory, contract testing, and tool parsers.

```bash
export PATH=$PATH:$HOME/.cargo/bin
cargo test -j 2                    # unit and integration tests; no Docker needed
cargo run -- eval                  # detection quality vs seeded bugs (python3 + git)

# frontend (node 24 is needed by vitest 5 and eslint 9; see frontend/README.md)
cd frontend && npm ci && npm run lint && npx tsc --noEmit && npm test

# context retriever
python3 -m unittest discover -s runners/context_retriever/tests -t . -v
```

CI (`.github/workflows/ci.yml`) runs version sync, `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, a release build, the `eval` job, the frontend job, the Python job and, on pull requests, no-push builds of the three images. See [docs/ci.md](docs/ci.md).

---

## Roadmap & Enterprise Evolution

The full status is in [docs/roadmap.md](docs/roadmap.md). In short:

- **Done:** scan engine (45 built-in checks incl. Tree-sitter cross-file AST audit, Opengrep, Nuclei, active ZAP), senior-QA engine, offline bundle, deep-security agent (modular attacks, in-process OAST, Playwright `BrowserSecurity`, white-box AST bridge, ReAct adaptive waves, independent verifier, lead and sub-agents, per-target memory), 10-suite eval harness and CI gate, Agent Studio and Network Lab, MCP swarm tools, signed multi-arch images.
- **Next:** multi-target trend dashboards, cross-service distributed taint/auth correlation, and verified PR patch synthesis.
- **Not implemented, and documented as such:**
  - A GitHub App / PR status check: `POST /api/github/pr-comment` only renders PR-comment markdown from data you supply; ReadyHai does not post to GitHub. Upload SARIF with the `upload-sarif` action instead.
  - Remote probe nodes for multi-region probing: `/api/network/multi-region` measures a single vantage point ("This host") and says so.

---

## Contributing & Security

- **Contributing:** See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, CI verification gates, and pull request requirements.
- **Security Policy:** See [SECURITY.md](SECURITY.md) for supported versions, private vulnerability disclosure, and authorized testing scope boundaries.

---

## Author & Maintainer

**Anshu Kushawaha**  
Email: [kushwahaanshu8858@gmail.com](mailto:kushwahaanshu8858@gmail.com)  
GitHub: [@AnshuKushwaha](https://github.com/AnshuKushwaha)

---

## License

ReadyHai is licensed under the **GNU Affero General Public License v3.0 only (`AGPL-3.0-only`)**.

- If you modify ReadyHai and run it over a network (including hosted API/SaaS/UI deployments), Section 13 of AGPL-3.0 requires making the Corresponding Source of your modified version available to network users.
- See [`LICENSE`](LICENSE) (and [`frontend/LICENSE`](frontend/LICENSE)) for the complete license text.
