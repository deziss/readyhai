<div align="center">

# ReadyHai 🛡️

**Ready hai?** *(रेड्डी है? / "Is it ready?")* — Self-hosted QA tester and production-readiness gate.

[![License](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-brightgreen.svg)](VERSION)
[![Rust](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](Cargo.toml)
[![Tests](https://img.shields.io/badge/tests-117%20passed-success.svg)](tests/)
[![Author](https://img.shields.io/badge/maintainer-Anshu%20Kushawaha-blueviolet.svg)](mailto:kushwahaanshu8858@gmail.com)

Point ReadyHai at a codebase, a container image, an API/web app, an SSH host, or an Android APK.  
It executes hardened, sandboxed checks and outputs a definitive verdict: **PASS**, **WARN**, or **FAIL**.

[Quick Start](#quick-start) • [Features](#key-capabilities) • [CLI Commands](#command-reference) • [Version Management](#single-source-of-truth-versioning) • [Security & Secrets](#secrets-and-sensitive-data-policy) • [Documentation](docs/README.md)

---

</div>

## Overview

Modern deployments often rely on dozens of disparate tools (`trivy`, `semgrep`, `gitleaks`, `hadolint`, `zap`, `playwright`, `k6`) glued together with shell scripts that mask errors or produce overwhelming, unprioritized alerts. 

**ReadyHai** unifies static analysis, dynamic security, end-to-end QA, and host hardening into a single high-performance binary:
- **One Clear Verdict:** Returns exit codes designed for CI pipelines (`0` PASS, `1` WARN, `2` FAIL, `3` Error).
- **Zero-Noise Baselines:** Accept existing technical debt once (`.readyhai/baseline.json`). The gate strictly evaluates **new** defects introduced in PRs.
- **Throwaway Container Sandboxes:** Scanners run non-root, read-only, network-isolated, and capability-dropped (`--cap-drop ALL`).
- **AI Agent Native:** Built-in Model Context Protocol (MCP) server over stdio for Claude Code and autonomous agents.

---

## Key Capabilities

| Target | What ReadyHai Checks |
|---|---|
| **Repository (`repo`)** | Dependencies/SBOM, CVEs, SAST, secret leak detection, IaC misconfigurations, Dockerfile anti-patterns, test coverage, migration safety, native readiness rules. |
| **Container Image (`image`)** | Distro SBOM, package CVEs, CIS benchmarks via Dockle, non-root execution, healthchecks, layer sizes. |
| **Web & APIs (`web`)** | Smoke status, TLS/security headers, CSP, cookie security, CORS policy, Schemathesis fuzzing, OWASP ZAP baseline, Playwright crawler. |
| **Host over SSH (`ssh://`)** | OS hardening, Lynis audit, kernel patches, listening ports, failed systemd units, journal errors, package CVEs (Linux, macOS, Windows). |
| **Android APK (`android:`)** | MobSF static analysis, dangerous permissions, hardcoded secrets, crash and ANR extraction from connected ADB devices/emulators. |
| **QA Test Suite (`qa`)** | Synthetic OpenAPI test generation, RBAC authorization matrix, k6 load testing, resilience & chaos testing, axe-core a11y, visual diffs. |

---

## Quick Start

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

Run automated contract testing, RBAC verification, load testing, and visual QA:

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

### Autonomous Agentic AI QA & Production Gate (2026)

ReadyHai includes a state-of-the-art multi-agent testing engine powered by local reasoning models (vLLM / Ollama):

- **Planner Agent:** Synthesizes boundary tests, negative inputs, RBAC abuse vectors, and OWASP Top 10 exploits.
- **Explorer Agent:** Dispatches tests, measures latency, captures live reproduction curl commands and raw evidence.
- **Triager Agent:** Clusters failures, dedupes defect instances, and evaluates OWASP blast radius.
- **Production Gate (LLM-as-a-Judge):** Computes a 4-pillar **Evidence Ledger** (*Value*, *Authority*, *Safety*, *Evidence*) and delivers an automated **GO / NO_GO** deployment verdict.

```bash
# Run multi-agent QA via CLI
readyhai agent http://localhost:3000 --max-steps 5

# Launch the cyber-dark Web Studio SPA on port 8080
readyhai serve --bind 127.0.0.1:8080
# Open http://127.0.0.1:8080 in your browser to access the live Agent Studio
```


### REST API & Web Dashboard

Launch the persistent ReadyHai daemon:

```bash
cp .env.example .env
# Edit READYHAI_TOKEN in .env (minimum 16 characters)
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
| `deep` | Everything in `standard` + intrusive chaos tests, aggressive fuzzing, and stress runs (only targets tagged `nonprod` in `scope.toml`). | Nightly / Pre-release soak |

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

Safeguards against scanning unauthorized endpoints:

```toml
allowed_hosts = ["staging.internal.net", "10.0.0.0/8"]
nonprod_hosts = ["staging.internal.net"]
```

---

## Secrets and Sensitive Data Policy

ReadyHai was designed from the ground up to **never leak credentials**:

1. **Filtered Snapshots:** Scanner containers never inspect raw repos directly. Sensitive files (`.env*` except `.example`, `*secret*.yaml`, `*.pem`, `*.key`, `id_rsa`, certificates) are stripped or replaced with 0-byte placeholders before tool execution.
2. **Path-Only Reporting:** If a secret file is tracked in git, ReadyHai reports the path and remediation instructions, but **never reads or displays its contents**.
3. **Redacted Findings:** Gitleaks runs with mandatory `--redact`. Snippet fields are scrubbed from raw SARIF and tool output JSONs.
4. **Placeholder Tokens:** QA and curl steps output mock placeholders (e.g., `$RH_ADMIN_TOKEN`), never real authorization headers.
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

ReadyHai features a comprehensive automated test suite (117+ tests covering golden fixtures, snapshotting, policy evaluation, redaction, contract testing, and tool integrations):

```bash
# Run unit & integration tests
cargo test

# Run tests with output
cargo test -- --nocapture
```

---

## Author & Maintainer

**Anshu Kushawaha**  
Email: [kushwahaanshu8858@gmail.com](mailto:kushwahaanshu8858@gmail.com)  
GitHub: [@AnshuKushwaha](https://github.com/AnshuKushwaha)

---

## License

ReadyHai is distributed under the [GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE).  
See [`LICENSE`](LICENSE) for full details.
