# ReadyHai as the Pentest Super-App (Orchestrator Plan)

Vision: ReadyHai becomes the **control plane** that plans, runs, normalises, dedupes,
gates and exports the work of many security tools — open-source, community-edition,
vendor CLI, *and its own native checks* — under one sandbox, one Finding model, one
gate, one report.

Research basis (Nov 2026): three verified research passes over the OSS scanner
landscape, commercial/community editions, and orchestrator interoperability
standards. Every integration below was license-checked and CLI-flag-checked against
primary sources before being listed.

## Architecture: one hub, many spokes

```mermaid
flowchart LR
  subgraph feeds[Feed cache scripts/fetch-feeds.sh]
    F1[OSV + GHSA] --- F2[CISA KEV, EPSS] --- F3[SecLists, assetnote,\nnuclei-templates, rego packs]
  end
  subgraph hub[ReadyHai core = orchestrator]
    P[Planner / profiles\nquick·standard·deep] --> R[Runner\ndocker sandbox · plugins · native checks]
    R --> N[Normalise\nsarif · junit · lines · readyhai-json]
    N --> D[Dedupe + baseline + VEX-style suppression]
    D --> G[Gate PASS/WARN/FAIL]
  end
  feeds --> R
  subgraph spokes[Tool lanes = plugins]
    A[Recon: subfinder httpx katana\nferoxbuster dnsx naabu]
    B[Web: nuclei zap dalfox sqlmap nikto]
    C[Supply chain: trivy grype\nosv-scanner dependency-check]
    D2[K8s/cloud posture: kube-linter\nkube-score conftest kubescape Prowler]
    E[LLM-app: garak promptfoo]
    F[Vendor BYO: CrowdStrike falcon CLI\nSnyk Qualys Caido/Burp (user-licensed)]
  end
  R --- A & B & C & D2 & E & F
  G --> X[Exports: SARIF · JSON · DefectDojo\nCycloneDX/VEX · MCP · tickets]
```

Principles:

1. **Everything is a check.** Native `tool.*` checks and `plugin.*` checks share the
   same Finding schema, baselines, suppressions, gate and exports. ReadyHai orchestrates
   *itself* the same way it orchestrates Trivy.
2. **Plugin = pinned container + declarative TOML.** No shell on the host, no secrets
   in argv (env is passed by name), read-only `/src`, writable `/out`, optional
   read-write `/cache` for big scanner DBs, network and host-gateway only when the
   plugin declares them.
3. **Normalise at the edge.** Four output formats cover the ecosystem: `sarif`
   (GHAS/defectdojo-world), `junit` (CI), `lines` (JSONL recon tools — native, zero
   jq/python shim needed), `readyhai-json` (exact control).
4. **Feeds are cached, tools stay stateless.** `scripts/fetch-feeds.sh` vendors
   wordlists/templates/feeds onto the host disk; plugins mount them via `/cache`.
   Air-gapped runs keep working (see `docs/offline.md`, `readyhai bundle`).
5. **Community editions are BYO.** Vendor CLI/plugins (CrowdStrike falcon, Snyk token,
   Qualys API, Caido PAT, Burp Pro) ship as *templates only* — the user supplies the
   licensed binary/token at runtime. ReadyHai never redistributes licensed content.

## What shipped this iteration (verified end-to-end)

| Piece | Proof |
|---|---|
| Plugin runner v2: `cache_rw`, `env` (by-name), `stdout`, `host_gateway`, `user`, `intrusive`, `{domain}`, new `lines` JSONL format, empty-output guard, loopback→`host.docker.internal` rewrite shared with core web client | 2 unit tests + live runs: httpx 1 finding on :8099 demo via rewritten URL; subfinder `[part]` w/ key hints on IP target; katana crawl finding; trivy image scan 1 finding |
| `plugins/official/` recon pack (subfinder, httpx, katana, feroxbuster) — digest-pinned, line-format | live E2E against local demo site |
| `plugins/official/` posture pack (kube-linter, kube-score, conftest) — native SARIF + rego | 7+12+1 findings on a deliberately-bad pod yaml |
| `plugins/_example/`: trivy ×3 (image/fs/config), owasp-dependency-check, npm-audit, osv-report, crowdstrike-fcs (+`falcon2readyhai.sh` jq converter, unit-tested) | trivy + falcon converter verified |
| `scripts/fetch-feeds.sh` — SecLists, asset-note, nuclei-templates, CISA KEV, EPSS, GHSA dump, PATT, rego packs; checksummed, idempotent | rego mode tested |
| `policies/rego/readyhai.rego` — ReadyHai's own conftest policy pack (v1 rego) | conftest fires 1 finding on test pod |

## Sprint plan — now → Monday 00:00 (aggressive, each step verifiable)

- **Sat — Recon chain:** `dnsx` + `naabu` + `tlsx` + `gau` plugins (all PD images,
  `lines`); wire katana output to feed nuclei via a shared `/cache` hand-off dir;
  feroxbuster wordlist from `fetch-feeds.sh recon`.
- **Sun AM — Supply-chain lane:** `grype` + `osv-scanner` plugins (`cache_rw` DBs);
  trivy `--skip-db-update` when KEV/EPSS caches are fresh; CVE enrichment from
  `fetch-feeds.sh vulndata` → findings gain `known_exploited`/`epss` evidence notes.
- **Sun PM — Cloud + LLM lanes:** Prowler plugin (BYO creds via `env`), `garak` and
  `promptfoo` plugins (JSONL/JSON report under `/out`).
- **Mon — Glue:** `readyhai tools pull` also pulls plugin images; `readyhai doctor`
  lists plugin load/skip reasons; docs (this file, `docs/data-sources.md`,
  `plugins/README.md`) + `cargo test --all-targets` + clippy clean.

## Orchestrator 0.x backlog (research-validated, effort-sized)

Priority order; S ≤ 2wk, M 2–6wk, L > 6wk solo. Full analysis in the research report.

1. **Finding v2 model** (M): `locations[]`, purl `component`, `ids[]`, `evidence[]`,
   `verification{}`, `confidence`, `suppression{kind,expires}`, `routing`,
   `provenance`, `dedupe{}` — everything below is a projection of this.
2. **DefectDojo exporter** (M): Generic Findings Import per tool,
   `unique_id_from_tool`, reimport + close_old_findings, DD hash_code config guidance.
3. **SARIF conformance overhaul** (M): suppressions/baselineState visible,
   executionSuccessful notifications, GitHub-safe shaping, `security-severity`.
4. **Incomplete-run ⇒ never PASS** (S): parseable-but-error scanner output can't
   green-light the gate. Highest trust-per-line-change. *(Do first — tiny.)*
5. **Standards export layer** (L, split 5a–5d): CycloneDX 1.6/1.7 BOM+VEX+VDR,
   OpenVEX, CSAF VEX, GitLab report, OCSF, SPDX 3.0.
6. **Dependency-Track integration** (M): BOM+VEX round-trip, ReadyHai-authored DT policy bundle.
7. **Evidence ledger as append-only fact DAG** (L) with replayable witnesses.
8. **Two-layer dedupe** (M): deterministic key (rule×purl×location) + advisory
   semantic layer; stable ids surviving DD/GitLab/GitHub identity schemes.
9. **VEX/justification lifecycle** (M): suppression kinds → CISA-VEX justifications,
   expiry on every acceptance, auto-return of findings.
10. **MCP client broker** (L): digest-pinned external MCP servers, all output forced
    through parsers → Finding v2 non-authoritative; tool-list drift = finding.
11. **MCP server 2026-07-28 conformance** (M): `server/discover`, `resultType`, MRTR
    fallback, deterministic tools/list; publish to the MCP registry. Independent —
    can start any time.
12. **Ticket router** (M): Jira via finding-groups (or delegate DD→Jira), Linear
    GraphQL + own uniqueness store, GitHub PR comments for `baselineState=new`,
    CODEOWNERS mapping.
13. **CI/CD packaging** (M): artifact-before-gate job split, GHES/GitLab/ADO targets
    with correct severity arithmetic, Alertmanager metrics (gate verdict + new-finding
    counts; finding ids only in annotations).
14. **Verification-gate policy v2** (M): verdicts only from deterministic methods,
    LLM capped at WARN, computed CVSS with cited evidence, counter-evidence required.
15. **Oracle/eval hardening** (M): anti-memorisation canaries in fixtures, known
    false-accept modes corpus, verifier-error metrics (verdict determinism across
    identical re-runs).

**"Orchestrator 0.1" first release = 2 + 3 + 4 + 11** (mutually independent,
immediately demonstrable), with 1 starting in parallel.

## Vendor / community-edition policy

| Vendor | How it plugs in | License stance |
|---|---|---|
| CrowdStrike | BYO falcon CLI (Falcon SI-EM/Spotlight, your licensed API client) → `plugins/_example/crowdstrike-fcs` + jq converter → readyhai-json | Template only; binary never in ReadyHai repos |
| Snyk | `snyk/snyk` image + user token via `env` (Free tier quotas documented) | BYO token |
| Qualys | CE API (free 16-asset tier) via thin plugin, keys via `env` | BYO keys |
| Caido / Burp | Caido headless + PAT (EULA-clean, do first); Burp **Pro** headless only — Community edition forbids automation | BYO licence |
| Tenable | No verifiablefree CE in 2026 — excluded | n/a |
| Insight/other | Only add a template when public availability + redistribution terms are verified | n/a |

Rule: if we can't verify license *and* public availability from primary sources, it
doesn't ship — not even as an example.

## Image allowlist (digest-pinned, verified live this iteration)

All digests resolved 2026-11-21 and stored in each `plugin.toml`. Re-verify with
`docker inspect --format='{{index .RepoDigests 0}}' <image>` on refresh.
