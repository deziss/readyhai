# Where ReadyHai stands (after increment 2, 2026-10-25)

Size: about 16k lines of Rust in `src/` (the QA engine, bundle, dashboard and LLM layer add about 9k). This replaces the "v0.1" table from the planning phase.

## Status by area

"Live" means run against real containers/servers; "unit" means only tests with recorded fixtures or mocks. Honest column on the right.

| Area | State | Evidence | Gap |
|---|---|---|---|
| Repo + image security and readiness | Strong | live, NuHire acceptance passed | - |
| Gate, baseline, suppressions | Solid | unit + live | - |
| Secret safety, sandbox, scope/SSRF | Solid | live secrets-guard test | - |
| **API QA** (`qa.api.*`) | Built | **live: 7/7 seeded bugs found, 0 false positives; prod-tagged run sent 70 GET requests and no writes** | AI-proposed cases not executed; OpenAPI `oneOf`/`allOf` partial; Schemathesis still never run |
| **Offline bundle** | Built | **live round trip: core bundle 3.63 GB (grype, syft, gitleaks), export -> import into a fresh data dir** | `full` set not exported end to end; manifest unsigned |
| **Perf (k6)** | Built | **live k6 run; baseline store/compare and regression logic unit-tested** | only against the fixture, smoke scale |
| **UI QA** (`qa.ui.*`) | Built | unit (runner output parsed from recorded JSON) | **runner image not built, so Playwright and PDF never run live** |
| **PDF report** | Built | unit (HTML) | needs the runner image; unrun |
| Reports: HTML, MD, Jira/GitLab/TestRail/Xray, dashboard | Built | unit (shape, escaping, no secrets) | tracker imports not tried in real tools |
| **Resilience** | Built | unit (decision logic only) | **never run against a live compose stack** |
| Suite + release quality | Built | unit on fixtures | migrations run needs a `[test]` image; Prisma/Flyway not run; not live |
| **LLM (LAN vLLM)** | Built | **mock server only** | no real vLLM run; quality of a small model unknown |
| Web (ZAP, Schemathesis) | Basic | smoke verified | ZAP/Schemathesis never run live |
| Hosts (SSH) | Linux verified live | round 2 | Windows untested, macOS partial |
| Android | Code only | - | MobSF happy path and device runtime never run |
| Ops | One worker, file store, token auth, static dashboard | - | no multi-user mode |

Verdict: a security and readiness scanner with a gate, now with a senior-QA layer (API functional/auth/stateful testing proven live; UI, PDF, resilience and LLM implemented but not yet exercised for real) and a verified offline bundle path.

## Competitor comparison

| | ReadyHai (after) | Trivy / Grype | Snyk | Aikido | SonarQube | DefectDojo | QA.tech / testRigor / TestSprite | Autonoma | MobSF | Cortex / Port |
|---|---|---|---|---|---|---|---|---|---|---|
| Functional QA (API/UI flows) | **API yes (live); UI built, unrun** | - | - | - | - | - | **yes (AI, UI-first)** | **yes** | - | - |
| Security scanning breadth | **high** (orchestrates OSS) | high (SCA/IaC) | high | **highest** (CSPM, runtime) | SAST/quality | aggregates | - | - | mobile only | - |
| Readiness gate / scorecard | **yes** | partial (exit code) | partial | partial | quality gate | - | - | - | - | **yes** (metadata only) |
| Targets: repo/image/web/host/android | **all 5** | repo, image, k8s | repo, image, IaC | repo, image, cloud, web | repo | n/a | web (+mobile some) | web + mobile | android/iOS | n/a |
| Offline / air-gapped | **bundle (verified)** | yes (DB mirror) | limited | no (SaaS) | yes (self-host) | yes | **no** (SaaS) | self-host (BSL) | yes | no |
| Self-hosted, own data | **yes** | yes | partial | no | yes | yes | no | yes | yes | no |
| AI agent | **LAN-LLM advisory (mock-tested) + MCP** | no | AI fix | AutoTriage | AI CodeFix | no | **core** | core | no | AI assist |
| QA test summary report (Go/No-Go) | **yes** | no | no | no | no | partial | partial | partial | PDF (security) | scorecards |
| Licence / cost | open source, free | AGPL-3.0 | from $25/dev/mo | from ~$350/mo | CE free, paid editions | OSS / Pro | paid SaaS | BSL 1.1 | GPL-3.0 | paid |

**Ahead:** the only tool here combining security, readiness and functional QA across repo, image, web, host and Android with one computed verdict; offline and self-hosted with secret-safe sandboxing; evidence-first findings with prompt-injection handling.

**Behind:** AI-first QA SaaS explore UIs better today; Aikido/Snyk have reachability, auto-fix PRs and cloud posture; SonarQube has code-quality depth; no multi-user mode; several paths unrun live (Windows, MobSF, Playwright runner, resilience, real LLM).

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
