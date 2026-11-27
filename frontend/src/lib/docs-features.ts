/**
 * ReadyHai feature registry backing the in-app `/docs` route.
 *
 * Content mirrors ../README.md, settings.example.toml and docs/ as of v3.8.0.
 * Every command shown here exists in the CLI; do not invent flags. When a
 * feature changes, update this registry alongside docs/ in the same PR.
 */

export interface DocFeature {
  /** URL-safe identifier; used for the in-page anchor. */
  id: string;
  title: string;
  tagline: string;
  category: DocCategory;
  /** What the feature actually does, one bullet per entry. */
  whatItDoes: string[];
  whyItMatters: string;
  /** Ordered usage steps; `code` renders as a monospace block. */
  howToUse: { description: string; code?: string }[];
  /** Config files / sections relevant to the feature. */
  config?: string[];
  /** Relative path to the repo markdown doc with the full reference. */
  docs?: string;
}

export const DOC_CATEGORIES = [
  "Scanning",
  "QA & agent",
  "Findings & reporting",
  "Network & tooling",
  "Platform",
] as const;

export type DocCategory = (typeof DOC_CATEGORIES)[number];

/** Docs-page version badge. Kept in sync with the root VERSION file at release. */
export const DOCS_VERSION = "3.8.1";

/** Repo-wide documentation index (external). */
export const REPO_DOCS_URL = "https://github.com/deziss/readyhai/blob/main/docs/README.md";

/** Base URL for linking a DocFeature.docs path to GitHub. */
export const REPO_FILE_BASE = "https://github.com/deziss/readyhai/blob/main";

export const DOC_FEATURES: DocFeature[] = [
  // ---------------------------------------------------------------- Scanning
  {
    id: "repo-scanning",
    title: "Repository scanning",
    tagline: "Static readiness, SAST, secrets, SBOM and IaC gate for any codebase.",
    category: "Scanning",
    whatItDoes: [
      "Runs 46 built-in native readiness rules, including a Tree-sitter cross-file AST audit for taint flows and missing auth guards (security.code_audit).",
      "Builds a dependency SBOM and maps CVEs with OSV call-graph plus AST-import reachability, so unreachable CVEs do not noise the verdict.",
      "Detects secret leaks with Gitleaks running --redact in a network-isolated sandbox; findings report the file path and remediation, never the file contents.",
      "Adds Opengrep intra-file taint rules and Semgrep SAST through pinned, non-root, read-only containers.",
      "Flags IaC misconfigurations (Checkov), Dockerfile anti-patterns (Hadolint, Dockle), migration-safety issues and thin test coverage.",
      "Includes the WireGuard configuration audit (wireguard check) for committed keys, key reuse and default-route overreach.",
      "Exits with CI-ready codes: 0 PASS, 1 WARN, 2 FAIL; 3 always means an operational error.",
    ],
    whyItMatters:
      "Most repos are glued together from scanner scripts that mask failures or bury real risk in noise. One scan produces one deterministic verdict that a pipeline can trust.",
    howToUse: [
      { description: "Fast native-only scan, zero container overhead:", code: "readyhai scan . --no-tools" },
      { description: "Full static scan with the pinned sandbox tools:", code: "readyhai scan ." },
      {
        description: "PR-style gate with multi-format exports:",
        code: "readyhai scan . --profile quick --format html,sarif,junit,json --out readyhai-report",
      },
    ],
    config: ["readyhai.toml ([[suppress]], [snapshot], [test])", ".readyhai/baseline.json", "settings.toml ([[toggle]])"],
    docs: "docs/checks.md",
  },
  {
    id: "image-scanning",
    title: "Container image scanning",
    tagline: "SBOM, package CVEs and CIS-style hygiene for shipped images.",
    category: "Scanning",
    whatItDoes: [
      "Extracts the distribution SBOM and reports package CVEs for any image reference.",
      "Runs Dockle CIS benchmarks against the image configuration.",
      "Checks non-root execution, healthcheck presence and layer bloat.",
      "Feeds warn/fail findings into the vulnerability database like every other scan.",
    ],
    whyItMatters:
      "The image is what production actually runs. Checking the source tree alone misses base-layer CVEs and unsafe image configuration introduced after the last commit.",
    howToUse: [
      { description: "Scan an image by reference:", code: "readyhai scan image:nginx:1.27" },
    ],
    docs: "docs/checks.md",
  },
  {
    id: "web-api-scanning",
    title: "Web & API scanning",
    tagline: "Passive posture plus spec-driven fuzzing and baseline ZAP.",
    category: "Scanning",
    whatItDoes: [
      "Checks smoke status, TLS chain / expiry / protocol support, security headers, weak CSP, cookie flags and CORS policy.",
      "Fuzzes declared endpoints with Schemathesis when an OpenAPI spec is available.",
      "Runs the Nuclei template scanner and the OWASP ZAP baseline scan; the active ZAP scan only runs on scope-allowed nonprod hosts (standard/deep profiles).",
      "Crawls with Playwright to catch client-storage secrets, non-HttpOnly cookies, exposed source maps and postMessage handlers.",
      "Refuses internal hosts that are not listed in scope.toml and keeps env = \"prod\" hosts read-only.",
    ],
    whyItMatters:
      "Staging deployments drift from both the code and the hardening checklist. Continuous external posture checks catch header, TLS and CSP regressions before users do.",
    howToUse: [
      {
        description: "Scan a deployed service:",
        code: "readyhai scan https://staging.example.com --profile standard",
      },
      { description: "Bound what may be touched with scope.toml rules of engagement before intrusive scans." },
    ],
    config: ["scope.toml ([[hosts]], env = nonprod|prod)"],
    docs: "docs/usage.md",
  },
  {
    id: "ssh-host-scanning",
    title: "SSH host scanning",
    tagline: "OS hardening, patch and service audit over SSH for Linux, macOS, Windows.",
    category: "Scanning",
    whatItDoes: [
      "Audits OS hardening posture with a Lynis run over the SSH session.",
      "Reviews kernel patch status and installed package CVEs.",
      "Lists listening ports, failed systemd units and journal errors.",
      "Supports Linux, macOS and Windows hosts with key or agent authentication.",
    ],
    whyItMatters:
      "Hosts drift after provisioning and quietly regress. A read-only audit turns \"we think the box is hardened\" into a dated, evidenced scan result.",
    howToUse: [
      {
        description: "Scan a remote host over SSH:",
        code: "readyhai scan ssh://ops@10.0.0.5 --os linux --key ~/.ssh/id_ed25519",
      },
    ],
    docs: "docs/usage.md",
  },
  {
    id: "android-apk-scanning",
    title: "Android APK scanning",
    tagline: "MobSF static analysis plus live crash and ANR extraction.",
    category: "Scanning",
    whatItDoes: [
      "Runs MobSF static analysis on the APK: manifest review, dangerous permissions, hardcoded secrets.",
      "Extracts crashes and ANRs from a connected ADB device or emulator while the app runs.",
      "Runs the monkey soak only under the deep profile, and only on hosts scope.toml does not mark prod.",
    ],
    whyItMatters:
      "Mobile releases ship permission creep and embedded credentials that server-side scanning never sees. Static plus on-device signals give one verdict for the release artifact.",
    howToUse: [
      {
        description: "Scan an APK with a device attached:",
        code: "readyhai scan android:./app-release.apk --device emulator-5554",
      },
    ],
    docs: "docs/usage.md",
  },

  // ------------------------------------------------------------- QA & agent
  {
    id: "qa-test-suite",
    title: "QA test suite (readyhai qa)",
    tagline: "Senior-QA engine: contracts, RBAC, load, resilience, a11y, WSTG probes.",
    category: "QA & agent",
    whatItDoes: [
      "Generates synthetic OpenAPI 3.1 contract tests and validates every response against the schema.",
      "Fuzzes GraphQL schemas and executes an RBAC authorization matrix from roles.toml.",
      "Runs k6 load tests plus resilience / chaos fault injection (qa.resilience, deep profile, allow-listed compose services only).",
      "Checks accessibility with axe-core, detects state-graph dead ends (Markov), and uses self-healing Playwright locators with multi-persona synchronized sessions and W3C traceparent injection.",
      "Includes safe WSTG pentest probes (qa.pentest.*: headers, JWT, session handling, rate limits, CORS, Set-Cookie audit, injection markers — benign payloads only) and repo-side fixture data-quality checks (qa.data.*).",
      "Generates spec-driven design cases (boundary-value, equivalence-partition, pairwise, decision-tables) with an operation x technique coverage matrix (qa.design.*).",
      "Maps every rule to OWASP WSTG v4.1, API Security Top 10 2023 and ASVS v4.2, with per-group execution coverage in the report.",
      "Computes a Go / Conditional Go / No-Go / Inconclusive recommendation next to the gate verdict; exit 0 / 1 / 2, 3 = error.",
    ],
    whyItMatters:
      "QA suites measure activity, not readiness. ReadyHai derives one honest release recommendation from executed evidence, and anything that could not run shows as not evaluated instead of passing silently.",
    howToUse: [
      {
        description: "Run the QA engine against an API with a spec and role matrix:",
        code:
          "readyhai qa https://api.staging.example \\\n  --spec openapi.json --roles roles.toml \\\n  --profile standard --format html,pdf,md,jira --out readyhai-qa-report",
      },
    ],
    config: ["readyhai.toml ([test] custom stage)", "roles.toml", "scope.toml"],
    docs: "docs/qa.md",
  },
  {
    id: "super-agent",
    title: "Super Agent (readyhai agent)",
    tagline: "Autonomous adversarial QA: 6-station pipeline with deterministic gates.",
    category: "QA & agent",
    whatItDoes: [
      "Runs a 6-station StateGraph: Recon & directives, Surface discovery, Attack-DAG planning, ReAct execution waves, independent verification, and the readiness gate.",
      "The v3.8.0 Intel stage precedes every run: it feeds the planner the Vulns DB open findings and verification stamps for the host, opt-in safe re-verification ([exploits], scope-guarded, never on a dry run) and the available tooling; after triage the run records its own confirmed findings back into the same database.",
      "Executes deep-security attacks: JWT tampering, BFLA, ACL/path bypasses, BOPLA and mass assignment, blind SQLi/CMDi, SSTI, OAST-backed SSRF, TOCTOU races, HPP and GraphQL introspection.",
      "Verifies browser-side risk with Playwright (DOM XSS, DOM sinks, storage leaks, source maps, clickjacking) and correlates white-box AST source/sink data with --repo / --diff-base.",
      "Replays every failure k times; only reproduced failures stay defects. A juror filters false positives and attaches example remediation patches.",
      "Remembers each target across runs (memory): new, still open, fixed and regressed defects, flaky cases, and dated defect acceptances via readyhai agent-memory.",
      "Gates with a deterministic four-pillar Evidence Ledger (Value 30, Authority 30, Safety 25, Evidence 15) to GO / CONDITIONAL_GO / NO_GO, or NOT_EVALUATED when nothing conclusive ran.",
      "Honours an Extended Thinking reasoning budget (1k-32k) and model tiers when an LLM is configured; verdicts always come from code, never from the LLM.",
    ],
    whyItMatters:
      "Manual adversarial QA does not scale per release. The agent applies the probe creativity of a red team under hard scope, budget and verification guardrails, with evidence an auditor can replay.",
    howToUse: [
      {
        description: "Plan only — validate scope, send nothing:",
        code: "readyhai agent https://api.example.com --spec https://api.example.com/openapi.json --dry-run",
      },
      {
        description: "Full run (exit 0 GO, 1 CONDITIONAL_GO, 2 NO_GO / not evaluated):",
        code: "readyhai agent https://api.example.com --spec https://api.example.com/openapi.json --max-steps 25",
      },
      {
        description: "Focus on what a PR changed:",
        code: "readyhai agent https://staging.example.com --spec openapi.json --repo . --diff-base origin/main",
      },
      {
        description: "Inspect memory and accept a known defect until a date:",
        code:
          "readyhai agent-memory show https://api.example.com\nreadyhai agent-memory accept https://api.example.com <fingerprint> --reason \"tracked in OPS-1\" --expires 2026-12-31",
      },
    ],
    config: ["scope.toml", "[exploits] for Intel re-verification", "READYHAI_VERIFY_K", "READYHAI_AGENT_WORKERS"],
    docs: "README.md",
  },
  {
    id: "exploitation-verification",
    title: "Exploitation verification (readyhai exploits)",
    tagline: "Opt-in, safe, read-only re-checks that grade findings as evidence.",
    category: "QA & agent",
    whatItDoes: [
      "Ships deterministic read-only PoC templates (env-file read, .git/HEAD exposure, backup-file read, open admin panel, live TLS posture, reachability probe) auto-matched to a finding by kind, rule and title.",
      "Requests only the finding's own URL (or its origin's /.env or /.git/HEAD); every probe passes the scope egress guard in intrusive mode, so prod hosts stay refused.",
      "Strictly opt-in: while [exploits] enabled = false (the default) the API answers 409 and the CLI refuses before any probe.",
      "Budgets max_probes template executions per run (1-100); rows past the budget are reported as skipped, never silently dropped.",
      "Stamps each Vulns DB row verified / not_reproducible / inconclusive / skipped — never changing triage status; honesty first, so anything it cannot prove stays inconclusive.",
      "Exposed as CLI (readyhai exploits list / run), REST (GET /api/exploits/templates, POST /api/exploits/run) and the Verify button in the Vulns view.",
    ],
    whyItMatters:
      "Scanner findings age badly; half of a triage queue is already fixed or was never real. Evidence-graded verification re-checks safely so decisions ride on proven state, not a dated report.",
    howToUse: [
      { description: "List templates and run verification for recorded findings:", code: "readyhai exploits list\nreadyhai exploits run" },
      { description: "Enable it first in the server's settings.toml:", code: "[exploits]\nenabled = true\nmax_probes = 25" },
      { description: "Or flip the Exploitation card in the Settings view (admin role when RBAC is on)." },
    ],
    config: ["settings.toml [exploits] enabled / max_probes", "scope.toml"],
    docs: "docs/configuration.md",
  },
  {
    id: "vulnerability-database",
    title: "Vulnerability database (readyhai vulns)",
    tagline: "Cross-target JSONL database with fingerprint dedupe and durable triage.",
    category: "Findings & reporting",
    whatItDoes: [
      "Records every warn/fail finding from every scan in one local JSONL, deduplicated by fingerprint across targets and re-runs; re-observation only bumps the count.",
      "Triage states open / accepted / forgotten survive re-scans; an accepted row re-observed at a different severity re-opens automatically.",
      "Rows also carry the exploitation-verification stamp and the template that set it.",
      "CLI (readyhai vulns ...), REST (GET/POST /api/vulns) and the Vulns web view are three views of the same rows, with status/target/severity/verification filters.",
      "Read-only and offline: no scan, no Docker, no network; recording is on by default and never changes a verdict or exit code.",
    ],
    whyItMatters:
      "Without a database every scan re-litigates last month's accepted risks. Durable triage means the gate talks about genuinely new findings and the backlog stops arguing with itself.",
    howToUse: [
      { description: "List open findings across all targets:", code: "readyhai vulns" },
      { description: "Filter or emit machine-readable rows:", code: "readyhai vulns --status accepted --target https://staging.example.com\nreadyhai vulns --json" },
      { description: "Accept or forget by unique 6+ char fingerprint prefix:", code: "readyhai vulns accept 4f2a91c7d3\nreadyhai vulns forget 4f2a91c7d3" },
    ],
    config: ["settings.toml [vulndb] enabled (default true)", "<data>/vulns/vulns.jsonl"],
    docs: "docs/configuration.md",
  },

  // --------------------------------------------------- Findings & reporting
  {
    id: "baselines",
    title: "Baselines",
    tagline: "Accept existing debt once; the gate then blocks only new findings.",
    category: "Findings & reporting",
    whatItDoes: [
      "Snapshots a run's accepted findings into .readyhai/baseline.json.",
      "Subsequent scans with --baseline compare against it and PASS/WARN/FAIL strictly on newly introduced findings.",
      "Committed alongside the code, so every PR gate and every dev machine share one definition of \"pre-existing\".",
    ],
    whyItMatters:
      "Gates fail on day one only when the alternative is switching them off. Baselines convert inherited technical debt into an explicit, reviewed artefact instead of CI noise.",
    howToUse: [
      { description: "Accept a run's findings as the baseline:", code: "readyhai baseline accept <run-id> --out .readyhai/baseline.json" },
      { description: "Commit it, then gate only new defects:", code: "readyhai scan . --baseline .readyhai/baseline.json" },
    ],
    docs: "docs/usage.md",
  },
  {
    id: "reports",
    title: "Reports (HTML / JSON / SARIF / JUnit)",
    tagline: "One run, every format your humans and machines consume.",
    category: "Findings & reporting",
    whatItDoes: [
      "Emits HTML (self-contained, sandbox-iframe friendly), JSON, SARIF 2.1.0 for GitHub Code Scanning and JUnit for CI test reports via --format.",
      "QA runs additionally export Markdown, PDF and Jira-ready output.",
      "Agent runs expose every format over REST (GET /api/agent/runs/{id}/report/{fmt}: html, json, markdown, sarif, junit) and as downloads in the Runs history view.",
      "Findings keep OWASP labels, severities and reproduction evidence; redaction rules apply to every format including raw tool output.",
    ],
    whyItMatters:
      "A gate is only as good as its artifacts. Engineers triage in SARIF, managers read HTML, pipelines parse JUnit — one scan serves all three without reformatting scripts.",
    howToUse: [
      { description: "Choose formats at scan time:", code: "readyhai scan . --format html,sarif,junit,json --out readyhai-report" },
      {
        description: "Fetch an agent run's SARIF from the server:",
        code:
          "curl -H \"Authorization: Bearer $READYHAI_TOKEN\" \\\n  http://127.0.0.1:8080/api/agent/runs/<id>/report/sarif -o run.sarif",
      },
    ],
    docs: "docs/usage.md",
  },
  {
    id: "eval-harness",
    title: "Eval harness (readyhai eval)",
    tagline: "Detection quality scored against seeded bugs, gated in CI.",
    category: "Platform",
    whatItDoes: [
      "Scores the QA engine and the agent against fixtures with known, seeded defects: recall, false positives, pass^k, verdict stability, request and time budgets.",
      "Runs 10 suites including qa-api, qa-repo, agent-api, agent-diff, agent-memory, security-deep and whitebox-exploit.",
      "Needs only python3 and git — fixture servers are stdlib scripts; no network, no Docker, no LLM.",
      "Exit codes gate CI: 0 every threshold met, 1 a threshold missed, 3 harness error; the report lands in ./eval-report/.",
    ],
    whyItMatters:
      "A detector nobody scores is a rumor. ReadyHai's own CI fails when recall or precision regresses, so \"it found it\" is a measured claim, not a vibe.",
    howToUse: [
      { description: "Run all suites (k = 2 by default):", code: "readyhai eval" },
      { description: "One suite, three runs:", code: "readyhai eval --suite qa-api --k 3" },
    ],
    docs: "docs/eval.md",
  },
  {
    id: "genai-evaluator",
    title: "GenAI evaluator (readyhai eval-ai)",
    tagline: "Offline RAG quality, agent trajectory and prompt-injection red-teaming.",
    category: "Platform",
    whatItDoes: [
      "Scores the RAG Quality Triad offline: Context Relevance, Faithfulness (hallucination extraction) and Answer Relevance.",
      "Detects loops in agent tool-call trajectories from a captured trace.",
      "Red-teams prompt injection and sensitive credential leakage in prompts and outputs.",
      "Works from datasets, queries and traces without needing production traffic.",
    ],
    whyItMatters:
      "GenAI features ship into products faster than their quality is measured. The same honest, deterministic gate ReadyHai applies to APIs applies to LLM behavior.",
    howToUse: [
      { description: "Score a RAG dataset:", code: "readyhai eval-ai --dataset tests" },
      { description: "Check an agent trace for loops:", code: "readyhai eval-ai --trajectory agent_trace.json" },
    ],
    docs: "README.md",
  },
  {
    id: "agentic-fixer",
    title: "Agentic fixer (readyhai fix)",
    tagline: "AST-grounded remediation with a test-before-PR sandbox.",
    category: "Platform",
    whatItDoes: [
      "Applies AST-grounded remediations: sibling auth-guard injection, SQL-injection parameterization, path-traversal sanitization, command-execution vectorization, CORS and secret handling.",
      "Verifies each patch in a local test sandbox (cargo test, npm test, pytest, go test) before proposing anything.",
      "Rolls back safely when the sandbox verdict is negative.",
      "Hands finished patches to an automated Pull Request bot flow.",
    ],
    whyItMatters:
      "Findings without fixes rot. A fixer grounded in the AST and verified by your own tests turns a defect into a reviewable PR instead of a ticket.",
    howToUse: [
      { description: "Fix defects in a repository:", code: "readyhai fix --repo ./services/api" },
    ],
    docs: "README.md",
  },
  {
    id: "mutation-testing",
    title: "Mutation testing (readyhai mutate)",
    tagline: "Breaks your code on purpose to grade your test oracle.",
    category: "Platform",
    whatItDoes: [
      "Applies autonomous source mutations: conditional inversion, boolean flips, auth bypass, return flips and arithmetic changes.",
      "Computes the test-oracle Mutation Score from how many mutants your tests kill.",
      "Synthesizes actionable negative-test assertions for every survived mutant.",
    ],
    whyItMatters:
      "Green tests prove nothing about test quality. Mutation score measures whether the suite would actually notice the bug — and the generated assertions close each gap.",
    howToUse: [
      { description: "Mutate a repository and print the score:", code: "readyhai mutate --repo ./services/api" },
    ],
    docs: "README.md",
  },

  // ------------------------------------------------------ Network & tooling
  {
    id: "network-lab",
    title: "Network lab & WireGuard audit",
    tagline: "Flakiness reproduction, root-cause diagnosis and VPN config audit.",
    category: "Network & tooling",
    whatItDoes: [
      "Regressive testing: N iterations from separate private sessions (no connection pooling) with throttling presets (Fast 3G, Slow 3G, flaky jitter, custom) to catch flapping endpoints, socket leaks and proxy drops.",
      "Root-cause diagnosis across DNS, TCP, TLS, TTFB and gateway stages, classified as STABLE, TIMEOUT, 5XX_FLAPPING, CONNECTION_RESET, HTTP_ERRORS or HIGH_JITTER, with copyable reproduction cURLs.",
      "Deep audit over six pillars: dual-stack, sub-resources, protocol matrix, TLS, CORS preflight and MTU; plus a cURL runner with stage timings and HAR export.",
      "Backed by POST /api/network/regress, /api/network/curl, /api/network/deep-audit and /api/network/multi-region; intrusive combinations are refused per scope.toml, and anything unmeasured is shown as not measured.",
      "The WireGuard repository check flags committed PrivateKey/PresharedKey values (redacted), key reuse across peers/files, AllowedIPs = 0.0.0.0/0 overreach, weak key material, [Interface] sections without Address=, duplicate ListenPorts and NAT peers missing PersistentKeepalive.",
    ],
    whyItMatters:
      "\"It's intermittent\" is a bug report nobody can ship on. The lab turns flakiness into a classification with reproduction commands; the WireGuard audit stops VPN mistakes from becoming silent routing or key-exposure incidents.",
    howToUse: [
      { description: "Open the Network lab tab in the Studio UI and pick a mode (Regression / Diagnosis / Deep audit)." },
      {
        description: "Or drive the API directly:",
        code:
          "curl -H \"Authorization: Bearer $READYHAI_TOKEN\" -X POST \\\n  http://127.0.0.1:8080/api/network/regress \\\n  -H 'Content-Type: application/json' -d '{\"url\":\"https://staging.example.com\",\"iterations\":50}'",
      },
      { description: "The WireGuard audit runs inside repository scans automatically:", code: "readyhai scan ." },
    ],
    config: ["scope.toml (intrusive classification of lab calls)"],
    docs: "docs/api.md",
  },
  {
    id: "tool-orchestrator",
    title: "Tool orchestrator & OSS scanner packs",
    tagline: "One hub, many spokes: every external tool becomes one check.",
    category: "Network & tooling",
    whatItDoes: [
      "Treats every tool as a check: external plugin.* checks share the Finding schema, baselines, suppressions, gate and exports with ReadyHai's native checks.",
      "A plugin is a digest-pinned container plus declarative TOML — no shell on the host, secrets passed by env name only, read-only /src, writable /out, network only when declared.",
      "Ships official OSS packs under plugins/official/: recon (subfinder, httpx, katana, feroxbuster), posture (kube-linter, kube-score, conftest) and network/web lanes (nmap, rustscan, testssl, sqlmap, nikto).",
      "Normalises results at the edge in four formats: sarif, junit, lines (JSONL recon output) and readyhai-json.",
      "Caches reference feeds via the checksummed, idempotent scripts/fetch-feeds.sh (SecLists, asset-note, nuclei-templates, CISA KEV, EPSS, GHSA dumps, rego packs) mounted through /cache.",
      "Vendor community editions are bring-your-own: CrowdStrike, Snyk, Qualys, Caido/Burp ship as templates only — you supply the licensed binary or token at runtime.",
      "readyhai doctor prints a plugins: section with per-pack loaded/skipped reasons; readyhai checks --plugins lists what will run.",
    ],
    whyItMatters:
      "Stacking scanners in shell scripts hides failures and multiplies false positives. The orchestrator gives every tool one sandbox, one finding model and one verdict, and keeps the toolset auditable via pinned digests.",
    howToUse: [
      { description: "Pull and pin the scanner images:", code: "readyhai tools pull --lock tools.lock.toml\nreadyhai tools update" },
      { description: "Provision plugin pack images and verify what loaded:", code: "readyhai tools pull --plugins\nreadyhai doctor" },
      { description: "List the resulting checks:", code: "readyhai checks --plugins" },
    ],
    config: ["tools.lock.toml", "plugins/ directory", "scripts/fetch-feeds.sh"],
    docs: "docs/superapp-orchestrator.md",
  },

  // ------------------------------------------------------------ Platform
  {
    id: "mcp-server",
    title: "MCP server (readyhai mcp)",
    tagline: "Run ReadyHai from Claude Code and any MCP-speaking agent.",
    category: "Platform",
    whatItDoes: [
      "Serves ReadyHai over stdio as a Model Context Protocol server.",
      "Exposes readyhai_scan, readyhai_checks, readyhai_run, readyhai_findings plus agent tools readyhai_agent_swarm, readyhai_agent_status, readyhai_agent_cancel and readyhai_agent_discover.",
      "readyhai_agent_swarm returns a run id immediately; status and cancel tools poll and stop it.",
      "Agent swarms are dry runs unless the caller asks for writes and the operator sets READYHAI_MCP_ALLOW_WRITES=1 (and the target is nonprod).",
      "Deliberately ships no baseline, suppression or config tools — an agent may observe and test, never weaken the gate.",
    ],
    whyItMatters:
      "Coding agents are now first-class operators. A scoped MCP surface lets them launch scans and swarms with the same scope guard, budget and redaction rules as any human, without file access to the gate itself.",
    howToUse: [
      { description: "Start the server and register it as an MCP server in your client:", code: "readyhai mcp" },
    ],
    config: ["READYHAI_MCP_ALLOW_WRITES (default off)", "scope.toml"],
    docs: "docs/api.md",
  },
  {
    id: "settings-and-toggles",
    title: "Settings & toggles system",
    tagline: "Operator tri-state controls with a per-check decision trace.",
    category: "Platform",
    whatItDoes: [
      "Tri-state (auto / on / off) switches for the Tools, Plugins and Intrusive classes; intrusive accepts auto or off only — on is rejected, so it can never override profile or scope gates.",
      "Resolves each check in a fixed order: exact [[toggle]] id > last matching glob > category switch > auto. off skips with a visible reason in the report; on never bypasses --no-tools, profile, scope or Docker-availability gates.",
      "The Settings view shows a searchable per-check table with each check's effective decision and why (by auto, by settings, ...), a custom id/glob field, and Save/Discard/Reset with optimistic-concurrency versioning.",
      "Saving writes settings.toml in the server's data directory (admin role required when RBAC is on); the next scan picks it up.",
      "Also surfaces the vulnerability-database status panel (flag + path), the Exploitation opt-in card, and a read-only RBAC keyring panel for admins.",
      "The operator's file is authoritative: a scanned repo's own settings file is never read. readyhai scan --settings settings.toml or READYHAI_SETTINGS selects it explicitly.",
    ],
    whyItMatters:
      "Scanners get ignored when they skip silently. An explicit operator layer with a per-check decision trace makes every skip attributable, reviewable and diffable.",
    howToUse: [
      { description: "Start from the example file:", code: "cp settings.example.toml settings.toml\nreadyhai scan . --settings settings.toml" },
      { description: "Or manage toggles in the Settings tab of the web UI and press Save." },
    ],
    config: ["settings.toml ([integrations], [[toggle]], [exploits], [vulndb])", "READYHAI_SETTINGS"],
    docs: "docs/configuration.md",
  },
  {
    id: "offline-airgapped",
    title: "Offline / air-gapped operation",
    tagline: "Full tool power with no internet: bundles, pinned digests, offline eval.",
    category: "Platform",
    whatItDoes: [
      "Exports scanner images and rule packs into one tarball on a connected machine and imports it on the air-gapped host (readyhai bundle export / import).",
      "All tool images are sha256 digest-pinned (tools.lock.toml), so an offline box verifies exactly what was approved online; images and release tarballs carry provenance.",
      "Static scan containers run without network connectivity by design, and feed caches (feeds + plugin /cache) are plain checksummed files on disk.",
      "readyhai eval, the Vulns database, baselines and report export all work fully offline.",
    ],
    whyItMatters:
      "Regulated and OT environments must gate releases without egress. Air-gap support is a first-class path — pinned supply chain in, verdicts out, no runtime downloads.",
    howToUse: [
      { description: "On an internet-connected machine:", code: "readyhai bundle export --set core --out readyhai-bundle.tar" },
      { description: "On the air-gapped machine:", code: "readyhai bundle import readyhai-bundle.tar" },
    ],
    config: ["tools.lock.toml"],
    docs: "docs/offline.md",
  },
  {
    id: "cicd-release-train",
    title: "CI/CD gating & release train",
    tagline: "Exit-code gates, SARIF upload and a version-disciplined release process.",
    category: "Platform",
    whatItDoes: [
      "Gates on exit codes: scan 0 PASS / 1 WARN / 2 FAIL, qa and agent 0 Go / 1 Conditional Go / 2 No-Go or not evaluated, 3 always operational error — so artifacts still publish under if: always() while failures block the merge.",
      "Ships a GitHub Actions recipe (install, gate, upload-sarif, archive report) plus pre-built GitLab CI, Jenkins and ArgoCD recipes in ci/.",
      "Combines with baselines so PR pipelines judge only newly introduced findings.",
      "ReadyHai's own CI enforces version sync, cargo fmt, clippy -D warnings, the Rust and frontend test suites, the Python retriever tests, the readyhai eval quality gate and signed multi-arch image builds.",
      "The root VERSION file is the single source of truth; scripts/version.sh propagates atomically and images publish only for the matching v<VERSION> tag.",
    ],
    whyItMatters:
      "A security gate earns trust by being boring and consistent. Deterministic codes, standard formats and a versioned release train make the check something the team leaves on.",
    howToUse: [
      {
        description: "Minimal PR gate step:",
        code: "readyhai scan . --profile quick --format sarif,html,junit --out readyhai-report",
      },
      { description: "Copy the workflow from the README CI/CD section or a recipe from ci/." },
      { description: "Check version sync locally before release:", code: "make version-check" },
    ],
    config: [".github/workflows/", "ci/ recipes", "VERSION + scripts/version.sh"],
    docs: "docs/ci.md",
  },
];
