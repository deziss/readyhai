# Where ReadyHai stands (2026-11-14, after 0.9.0)

Size: about 101,300 lines of Rust in `src/` (unit tests included; the QA engine is `18,824` lines, the agent `47,960` lines), a Next.js Studio in `frontend/`, 814 Rust `#[test]` functions (3 `#[ignore]`d), 127 frontend and 18 Python tests. This replaces the table from 0.4.0.

## How to read the evidence column

- **live**: run against real containers or servers (the date is given where the record is a commit or the build log).
- **eval-gated**: scored on every CI run by `readyhai eval` against fixtures with seeded defects (recall, false positives, pass^k). It is a regression gate, not proof about a real application.
- **unit**: only tests with recorded fixtures or mocks.

## Status by area

| Area | State | Evidence | Gap |
|---|---|---|---|
| Repo + image security and readiness | Strong | live, NuHire acceptance passed; `security.code_audit` (Tree-sitter cross-file taint & sibling auth guard audit) + `tool.opengrep` unit & `whitebox-exploit` eval-gated | NuHire check prints, it does not assert |
| Gate, baseline, suppressions | Solid | unit + live; a required check that errors fails the gate by default | - |
| Secret safety, sandbox, scope/SSRF | Solid | live secrets-guard test; scope fails closed; one egress guard for every server-initiated request | DNS is resolved at guard time, not pinned |
| **API QA** (`readyhai qa`, `qa.api.*`) | Strong | **live and eval-gated: 7/7 seeded bugs, 0 false positives; a prod-listed run sent 70 GET requests and no writes** | AI-proposed cases are notes only |
| **UI QA and PDF** (`qa.ui.*`) | Built | **live (2026-10-30): 6/6 seeded UI bugs, valid PDF**; unit for the parsers | UI QA still uses `qa-ui` fixture manually |
| **Perf (k6)** | Built | live on the fixture; baseline and regression logic unit-tested | fixture scale only |
| **Resilience** | Built | live against the compose fixture (2026-10-30): pause, detect, unpause, signal-safe | no real application stack |
| Web (ZAP, Schemathesis, Nuclei, `web.smoke`) | Built | live against the fixture API (2026-10-30: ZAP & Schemathesis); weak CSP + TLS protocol/expiry/chain checks, Nuclei, and active ZAP (`deep`+`nonprod`) unit-tested in `0.7.0` | Nuclei & active ZAP not run live in CI without containers |
| Hosts (SSH) | Linux verified live | round 2 | Windows untested, macOS partial |
| Android | MobSF live | InsecureBankv2 (2026-10-30) | adb runtime check unrun without a device; not in the container image |
| Supply chain (`tool.osv_reachability`, scorecard, spectral, oasdiff, mutation) | Built | OSV Go call-graph + AST import enrichment (`enrich_osv_with_ast`), unit on recorded outputs | not exercised live against external GitHub API in CI |
| Offline bundle | Built | **live round trip: core bundle 3.63 GB, export -> import into a fresh data dir** | `full` set not exported end to end; manifest unsigned |
| Reports: HTML, MD, Jira/GitLab/TestRail/Xray, SARIF, JUnit, dashboard | Built | unit (shape, escaping, no secrets) | tracker imports not tried in real tools |
| **Agent** (`readyhai agent`) | **Strong on fixtures** | **eval-gated across 10 suites (`security-deep` 12 loopholes, `whitebox-exploit` AST linkage, `agent-api` 7/7, `agent-diff`, `agent-memory`, `agent-spa*`)**; includes Playwright `BrowserSecurity`, in-process OAST collector, white-box AST bridge, and adaptive ReAct waves | opt-in `bench_owasp.{sh,ps1}` harness for live Juice Shop / VAmPI not run in CI |
| Agent verifier and cleanup | Built | unit + eval (pass^k, verdict stability, timing/OAST/redirect replay); cleanup reads every 2xx DELETE back | write-method failures on real records stay `unverified` by design |
| Agent lead, change-aware planning, memory | Built | unit + eval; white-box `--repo` works with or without diff | context retriever advisory only, unrun in CI |
| MCP | Built | scripted-session tests, stdio isolation subprocess test; async swarm | no live Claude Code session |
| **Eval harness and CI gates** | **Done** | the `eval` job, fmt, clippy `-D warnings`, tests, frontend, Python, PR image builds | 10 suites gated on every CI run |
| Agent Studio | Built | vitest (127 cases: run status, cancel, composer, ledger panels, verdict badge, network lab, stepper, API helpers) | no browser end-to-end test in CI |
| Ops | One scan worker, file store, bearer token, static dashboard | - | no multi-user mode, no persisted queue |

Verdict: a security and readiness scanner with a gate, a senior-QA layer whose API and UI paths are proven live, and a deep-security autonomous agent (AST white-box + OAST + Playwright browser checks + modular exploits) whose detection is measured across 10 eval suites gating CI. What is still unproven in CI: large real-world targets (outside opt-in `bench_owasp.*` runs) and the Windows SSH probe.

## Competitor comparison

| | ReadyHai (after) | Trivy / Grype | Snyk | Aikido | SonarQube | DefectDojo | QA.tech / testRigor / TestSprite | Autonoma | MobSF | Cortex / Port |
|---|---|---|---|---|---|---|---|---|---|---|
| Functional QA (API/UI flows) | **API yes (live); UI yes (live, fixture)** | - | - | - | - | - | **yes (AI, UI-first)** | **yes** | - | - |
| Security scanning breadth | **high** (orchestrates OSS) | high (SCA/IaC) | high | **highest** (CSPM, runtime) | SAST/quality | aggregates | - | - | mobile only | - |
| Readiness gate / scorecard | **yes** | partial (exit code) | partial | partial | quality gate | - | - | - | - | **yes** (metadata only) |
| Targets: repo/image/web/host/android | **all 5** | repo, image, k8s | repo, image, IaC | repo, image, cloud, web | repo | n/a | web (+mobile some) | web + mobile | android/iOS | n/a |
| Offline / air-gapped | **bundle (verified)** | yes (DB mirror) | limited | no (SaaS) | yes (self-host) | yes | **no** (SaaS) | self-host (BSL) | yes | no |
| Self-hosted, own data | **yes** | yes | partial | no | yes | yes | no | yes | yes | no |
| AI agent | **Autonomous agent with verifier, lead and sub-agents, per-target memory, PR-aware planning, MCP, Studio; detection eval-gated** | no | AI fix | AutoTriage | AI CodeFix | no | **core** | core | no | AI assist |
| QA test summary report (Go/No-Go) | **yes** | no | no | no | no | partial | partial | partial | PDF (security) | scorecards |
| Licence / cost | open source, free | AGPL-3.0 | from $25/dev/mo | from ~$350/mo | CE free, paid editions | OSS / Pro | paid SaaS | BSL 1.1 | GPL-3.0 | paid |

**Ahead:** the only tool here combining cross-file static AST + SAST + DAST (Opengrep/Nuclei/ZAP/Schemathesis) + autonomous deep-security agent (modular attacks, OAST, Playwright `BrowserSecurity`, white-box repo linkage) + functional QA across repo, image, web, host and Android with one computed verdict; offline and self-hosted with secret-safe sandboxing; evidence-first findings with prompt-injection handling; an agent whose failures must reproduce before they count, which remembers a target between runs, and which is scored across 10 seeded-bug eval suites on every CI run.

**Behind:** AI-first functional QA SaaS platforms still offer richer multi-step visual flow scripting; Aikido/Snyk offer managed cloud CSPM and auto-fix PR bots; SonarQube has deeper language-specific code-quality rules; no multi-user mode; live runs against large production-scale apps and the Windows probe remain unverified in CI.

Pricing and capability figures come from the third-party pages below (several vendor-authored, hence biased); re-check before quoting.

## Sources

- [Agentic QA tools 2026](https://www.shiplight.ai/api/blog/best-agentic-qa-tools-2026/raw)
- [Open-source AI test tools (Autonoma)](https://getautonoma.com/blog/open-source-ai-test-generation-tools-2026)
- [Self-hosted AI QA cost](https://www.spheron.network/blog/self-host-ai-qa-testing-agent-gpu-cloud/)
- [Aikido vs Snyk](https://thectoclub.com/tools/aikido-security-vs-snyk/)
- [Aikido alternatives](https://appsecsanta.com/aikido-alternatives)
- [Trivy alternatives (Aikido, biased)](https://www.aikido.dev/blog/trivy-alternatives)
- [Test summary report structure](https://testdino.com/blog/software-testing-report)
- [Test summary and Go/No-Go](https://yrkan.com/blog/test-summary-report)
- [Grype air-gapped setup](https://developer.harness.io/docs/security-testing-orchestration/sto-techref-category/grype/grype-setup-in-airgapped)
- [CPU-only local LLMs 2026](https://www.popularai.org/p/best-cpu-only-local-llm-2026)
- [Local LLM tool-calling caveat](https://docs.conduction.nl/claude/local-llm/)

See also [market-research.md](market-research.md) (v1 landscape) and [roadmap.md](roadmap.md).
