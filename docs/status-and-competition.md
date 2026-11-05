# Where ReadyHai stands (2026-11-05, after 0.4.0)

Size: about 78,000 lines of Rust in `src/` (unit tests included; the QA engine is about 16,500, the agent about 32,800 of them), a Next.js Studio in `frontend/`, 639 Rust test functions, 86 frontend and 15 Python tests (counted from source). This replaces the table from increment 2.

## How to read the evidence column

- **live**: run against real containers or servers (the date is given where the record is a commit or the build log).
- **eval-gated**: scored on every CI run by `readyhai eval` against fixtures with seeded defects (recall, false positives, pass^k). It is a regression gate, not proof about a real application.
- **unit**: only tests with recorded fixtures or mocks.

## Status by area

| Area | State | Evidence | Gap |
|---|---|---|---|
| Repo + image security and readiness | Strong | live, NuHire acceptance passed | NuHire check prints, it does not assert |
| Gate, baseline, suppressions | Solid | unit + live; a required check that errors fails the gate by default | - |
| Secret safety, sandbox, scope/SSRF | Solid | live secrets-guard test; scope fails closed; one egress guard for every server-initiated request | DNS is resolved at guard time, not pinned |
| **API QA** (`readyhai qa`, `qa.api.*`) | Strong | **live and eval-gated: 7/7 seeded bugs, 0 false positives; a prod-listed run sent 70 GET requests and no writes** | AI-proposed cases are notes only |
| **UI QA and PDF** (`qa.ui.*`) | Built | **live (2026-10-30): 6/6 seeded UI bugs, valid PDF**; unit for the parsers | not in the eval suites yet |
| **Perf (k6)** | Built | live on the fixture; baseline and regression logic unit-tested | fixture scale only |
| **Resilience** | Built | live against the compose fixture (2026-10-30): pause, detect, unpause, signal-safe | no real application stack |
| Web (ZAP, Schemathesis) | Built | live against the fixture API (2026-10-30: 2 and 6 findings) | no TLS expiry or protocol check |
| Hosts (SSH) | Linux verified live | round 2 | Windows untested, macOS partial |
| Android | MobSF live | InsecureBankv2 (2026-10-30) | adb runtime check unrun without a device; not in the container image |
| Supply chain (`tool.osv_reachability`, scorecard, spectral, oasdiff, mutation) | Built | unit on recorded outputs | not exercised live |
| Offline bundle | Built | **live round trip: core bundle 3.63 GB, export -> import into a fresh data dir** | `full` set not exported end to end; manifest unsigned |
| Reports: HTML, MD, Jira/GitLab/TestRail/Xray, SARIF, JUnit, dashboard | Built | unit (shape, escaping, no secrets) | tracker imports not tried in real tools |
| **Agent** (`readyhai agent`) | **Strong on fixtures** | **eval-gated: 7/7 seeded bugs (`agent-api`), the one bug on a PR's changed route (`agent-diff`), memory carries over (`agent-memory`)**; live with a local vLLM model | not yet run against a real application; HTTP only, no browser |
| Agent verifier and cleanup | Built | unit + eval (pass^k, verdict stability); cleanup reads every 2xx DELETE back | write-method failures on real records stay `unverified` by design |
| Agent lead, change-aware planning, memory | Built | unit + eval; `agent-diff` needs a spec | context retriever advisory only, unrun in CI |
| MCP | Built | scripted-session tests, stdio isolation subprocess test; async swarm | no live Claude Code session |
| **Eval harness and CI gates** | **Done** | the `eval` job, fmt, clippy `-D warnings`, tests, frontend, Python, PR image builds | five suites; no UI suite |
| Agent Studio | Built | vitest (86 cases: run status, cancel, composer, stepper, API helpers) | no browser end-to-end test in CI |
| Ops | One scan worker, file store, bearer token, static dashboard | - | no multi-user mode, no persisted queue |

Verdict: a security and readiness scanner with a gate, a senior-QA layer whose API and UI paths are proven live, and an autonomous agent whose detection is measured by an eval harness that gates CI. What is still unproven: behaviour on real, non-fixture applications, the Windows probe, and browser-level testing by the agent.

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

**Ahead:** the only tool here combining security, readiness and functional QA across repo, image, web, host and Android with one computed verdict; offline and self-hosted with secret-safe sandboxing; evidence-first findings with prompt-injection handling; an agent whose failures must reproduce before they count, which remembers a target between runs, and which is scored against seeded bugs on every CI run.

**Behind:** AI-first QA SaaS explore UIs better today (the agent has no browser area yet, see [roadmap.md](roadmap.md)); Aikido/Snyk have reachability, auto-fix PRs and cloud posture; SonarQube has code-quality depth; no multi-user mode; a few paths unrun live (Windows probe, a real application stack for resilience, a real application for the agent).

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
