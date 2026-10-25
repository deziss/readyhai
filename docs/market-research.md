# Market research

Done at the start of the build (October 2026) to decide what to build and what to reuse.

## OSS vs commercial landscape

| Category | Open source | Commercial |
|---|---|---|
| SCA / CVE / SBOM | Grype+Syft, OSV-Scanner, Dependency-Track, Trivy | Snyk, Black Duck, Mend, Sonatype |
| SAST | Semgrep CE / Opengrep, SonarQube CE, Bandit | Checkmarx, Veracode, Semgrep Pro, Snyk Code |
| Secrets | Gitleaks, TruffleHog | GitGuardian |
| IaC / container config | Checkov, Hadolint, Dockle, Kubescape | Wiz, Prisma Cloud, Aqua |
| DAST / API fuzz | OWASP ZAP, Nuclei, Schemathesis, RESTler | Invicti, Burp Enterprise, StackHawk |
| Web / mobile QA | Playwright (Planner/Generator/Healer agents, MCP), Maestro, Appium (NovaWindows, Mac2), MobSF | QA.tech, testRigor, TestSprite, Quash, BrowserStack |
| Host hardening | Lynis, OpenSCAP, Wazuh SCA, HardeningKitty | Tenable, Qualys, CIS-CAT Pro |
| Vuln mgmt / ASPM | DefectDojo, SecObserve | ArmorCode, Invicti ASPM, Aikido |
| Readiness scorecards | Backstage (DIY), OpenSSF Scorecard | Cortex, Port, OpsLevel, DX |
| AI pentest agents | Strix, Shannon, PentAGI, CAI, PentestGPT | XBOW, Horizon3 |

## The gap ReadyHai fills

No open-source tool combines functional QA, security and a readiness gate across repo, image, web, host and mobile, with one findings model and one verdict. ReadyHai orchestrates the best existing scanners and does not re-implement them. It adds:

- Native readiness rules (Dockerfile, deps, compose, k8s, CI, repo hygiene) that scanners do not cover.
- Error/log clustering into a "Top errors" section ("stop reading logs manually").
- A baseline diff ("what is new since the last deploy") and a gate with exit codes for CI.
- Honest check statuses (`partial`, `skipped`, `errored`), so a scanner that cannot fail, is optional, or covers 1 of 26 dependencies is visible instead of a green tick.

Not a replacement for: DefectDojo-style vulnerability management, Dependency-Track portfolios, or a human pentest.

## Agentic QA and pentest landscape

- Agentic QA products (QA.tech, testRigor, TestSprite, Quash) drive browsers with LLMs; Playwright now ships Planner/Generator/Healer agents and an MCP server; Maestro and Appium cover mobile and desktop UI.
- AI pentest agents (Strix, Shannon, PentAGI, CAI, PentestGPT; commercial XBOW, Horizon3) chain recon, exploitation and reporting. They need evidence-based findings and tight scope control because scanned content is hostile (prompt injection) and agents solve only about 13% of real CVEs in benchmarks.
- Takeaway used in the design: start with an MCP server over deterministic checks (cheap, safe), then add a Planner/Explorer/Triager/Reporter loop with server-side scope enforcement, evidence-required findings, and no LLM power to suppress or waive. See [roadmap.md](roadmap.md).

## Supply-chain lesson

Trivy's releases and Docker images were backdoored in March 2026 (TeamPCP; the KICS action was hit too). ReadyHai therefore treats every scanner as untrusted: digest pinning in `tools.lock.toml`, no secrets/socket/env/network for static scans, Grype/Syft as primary and Trivy not used. See [security-model.md](security-model.md).

## Sandbox options considered

| Option | Verdict |
|---|---|
| Plain hardened `docker run` (cap-drop, read-only, no network, no log driver) | **Chosen**: simple, auditable, works with rootless Docker/Podman |
| gVisor (`runsc` runtime) | Optional hardening if installed; not wired into the code |
| Firecracker/microVM sandboxes (agent sandbox products) | Heavier; revisit for the agent phase running untrusted code |
| Docker socket proxy | Reduces accidental surface only; **not a security boundary** |
| Rootless Docker / Podman | Recommended on shared hosts |

## Key tool notes

- Grype carries EPSS and KEV in its DB, so no separate enricher.
- Schemathesis: property-based API fuzzing from OpenAPI (5xx and schema violations).
- MobSF: static APK/AAB analysis over REST; run as a short-lived per-scan container.
- Appium drivers (NovaWindows, Mac2) and Maestro: later, for desktop/mobile UI exploration.
- Lynis: Linux/macOS hardening audit; HardeningKitty for Windows is deferred.

## Sources

- [DefectDojo alternatives](https://appsecsanta.com/defectdojo-alternatives) · [Top OSS vuln mgmt 2026](https://defectdojo.com/blog/top-11-open-source-vulnerability-management-tools-for-2026)
- [Trivy vs Grype](https://appsecsanta.com/trivy-vs-grype) · [Trivy attack (Aqua)](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know) · [CSA SG advisory](https://www.csa.gov.sg/alerts-and-advisories/advisories/ad-2026-001/) · [Wiz](https://wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack)
- [Agentic QA tools 2026](https://qa.tech/blog/best-agentic-qa-tools-in-2026) · [New AI testing tools](https://quashbugs.com/blog/new-ai-testing-tools-emerging) · [Playwright agents](https://currents.dev/posts/state-of-playwright-ai-ecosystem-in-2026)
- [AI pentesting agents 2026](https://appsecsanta.com/research/ai-pentesting-agents-2026) · [awesome-ai-pentesting](https://github.com/skyvanguard/awesome-ai-pentesting)
- [Schemathesis](https://qaskills.sh/blog/schemathesis-api-fuzzing-guide) · [Maestro MCP](https://maestro.dev/mcp) · [MobSF (MASTG)](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0035) · [Appium drivers](https://appium.io/docs/en/3.0/ecosystem/drivers)
- [Agent sandboxes](https://www.tembo.io/blog/ai-agent-sandbox) · [Lynis](https://dev.co/devops/open-source/lynis) · [Wazuh SCA](https://wazuh.com/blog/automating-linux-endpoint-hardening-with-wazuh/)
- [Port readiness scorecard](https://docs.port.io/guides/all/setup-production-readiness-scorecard) · [Cortex alternatives](https://getdx.com/blog/cortex-and-alternatives) · [Snyk vs Veracode](https://www.pixee.ai/blog/snyk-vs-veracode)
- [RUSTSEC-2025-0068 serde_yml](https://rustsec.org/advisories/RUSTSEC-2025-0068) · [OSV offline](https://google.github.io/osv-scanner-v1/experimental/offline-mode/) · [minijinja auto-escape](https://docs.rs/minijinja/latest/minijinja/fn.default_auto_escape_callback.html)
