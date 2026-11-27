# Changelog

All notable changes to ReadyHai are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [3.8.1] - 2026-11-27

### Fixed

- **Agent plan tier order — advisory intel no longer outranks a proven reproduction**: the v3.8.0 Intel stage ranked cases tagged with a merely-*open* Vulns DB finding above the agent's own memory regression probes, so a second run against a known target could start with database context instead of re-running the reproduction it remembered. The plan ladder is now **reproduced live (this run) > memory regression probes > known-open database notes > changed/history operations > rest**, in the planner, the truncation order and the hint merge alike. The `agent-memory` eval suite (`regression probes lead the plan`) passes again; CI is green.

### Docs

- **Comprehensive feature guides**: new `docs/features/` section explains every feature — what it does, why it matters, how to use it, how to configure it — across [Scanning & targets](features/scanning-and-targets.md) (verdict model; repo/image/web/SSH/Android targets; baselines; reports; tool orchestrator and OSS packs) and [Agent, QA & security intelligence](features/agent-qa-security.md) (QA suite, Super Agent incl. the Intel stage, exploits, vulndb, network lab, eval/eval-ai, fix, mutate, MCP, settings/RBAC).
- **In-app Docs route**: the frontend now serves the full feature catalog at `/docs` (`src/app/docs/`, registry in `src/lib/docs-features.ts`) with search, category navigation and deep links back to the repo markdown; a Docs entry joins the header navigation.

## [3.8.0] - 2026-11-26

### Added

- **Intel stage (`src/agent/pipeline/intel.rs`)**: a new pipeline station between memory recall and Planning — the agent no longer plans blind on a target it has already probed. Before the planner runs, the agent gathers four cheap sources into one advisory intel bundle: (1) the target's own **Vulns DB history** for this host — its open findings with their `verification` stamps exactly as triaged, honoured only when `[vulndb] enabled`; (2) **up-front safe re-verification** — when the operator has `[exploits] enabled` and the run is not a dry-run, the v3.7 verification templates replay over the host's currently-open findings within the `max_probes` budget, every URL through the ordinary scope egress guard with `intrusive = true`, so a weakness proven before is proven again before planning starts; (3) **passive network posture** — cheap facts from the existing `src/network` helpers, no active probing of its own; (4) **tooling availability** — which plugged tool images (Docker packs / tool cache) are actually present, so the planner does not schedule what the machine cannot run today.
- **Post-triage recording loop**: after Defect Triage the agent records its own triaged findings into the Vulns DB via `vulndb::record_run` when `[vulndb] enabled` — agent runs now feed the same cross-target database CLI and `serve` scans write to, with the same fingerprint dedupe and triage-status semantics. Dry runs record nothing and probe nothing.

### Changed

- Agent-memory `PlanHints` gained `known_open` (this host's open Vulns DB findings) and `reproduced` (weaknesses the Intel stage re-proved this run), so the planner re-tests verified/open weaknesses first. Deterministic prioritization only: intel reorders the plan, and — per Deterministic Primacy — never changes a verdict.

### Docs

- `src/agent/pipeline/README.md`: Intel stage in the lifecycle and submodule table, with advisory/deterministic invariants; README agent blurb notes the vulndb consume/re-record loop; `docs/build-log.md` Round 12 describes the sources and the safety layers.

### Testing

- The Intel stage ships with unit coverage for the gate semantics (no `[vulndb]` → no intel read or write-back; `[exploits]` off or dry-run → zero probes; dry-run → zero records; plan-hint prioritization stays deterministic and verdict-neutral) — plus plan-hint merge and planner-elevation cases in `memory/tests.rs` and `plan/tests.rs` (reproduced > open > regression ordering, and a byte-identical plan with empty hints). Release run: 1014 `cargo test` passed (+15 over v3.7.0), `cargo clippy -- -D warnings` and `cargo fmt --check` clean.

## [3.7.0] - 2026-11-26

### Added

- **Exploitation verification engine** (`src/exploits/`): safe, deterministic re-checks that turn a *reported* vulndb finding into a *reproduced* one. A hand-reviewed catalogue of six templates (families `exposure|crypto|config`): `http.env-file-read` (GET `{origin}/.env`, `verified` only on a 200 with a real `KEY=value` secret shape — an HTML page rewriting it is `not_reproducible`), `http.git-dir-listing` (GET `{origin}/.git/HEAD`, the exact git ref line is the proof, no further repository files fetched), `http.backup-file-read` (GETs the single artifact URL the finding itself names and inspects it in memory), `http.admin-panel-open` (the reported path answering an admin-shaped 200 — two markers, one is coincidence), `http.weak-tls-live` (confirms the host is alive, then honestly reports `inconclusive`: the local rustls floor is TLS 1.2, so a deprecated handshake cannot be proven in-process and a fake `verified` is never minted) and `http.server-status-probe` (baseline reachability, never auto-matched, `inconclusive` by construction — reachability alone verifies nothing). A row auto-selects its template by keyword on its own kind + rule + title; the only URLs ever requested are the finding's own resource or its canonical origin's `/.env` / `/.git/HEAD`. No enumeration, no payloads, no write verbs — one or two read-only GETs per template, each through the shared zero-redirect client with a hard request timeout, body capped at 64 KiB, inspected in memory and dropped.
- **Strictly opt-in safety layers**: `[exploits] enabled = false` by default — a run refuses and the REST endpoint answers `409` until the operator enables it, exactly like `integrations.intrusive` being opt-in. `[exploits] max_probes` budgets template executions per run (default 25, validated `1..=100`; records past the budget land as `skipped` with that reason). Every URL a run would request passes the ordinary scope egress guard with `intrusive = true` in a pre-flight — prod-tagged and unresolvable hosts are refused and a single refusal fails the whole run — so the blocking probe loop only ever replays pre-approved URLs. RBAC classifies `POST /api/exploits/run` as Admin (fail-closed, like vuln triage); at most 50 fingerprints per run.
- **Evidence-grade verification states on vulndb rows**: each record carries `verification` (`unverified|verified|not_reproducible|inconclusive|skipped`), `verified_by` (template id) and `verified_at`. A verification NEVER changes the triage `status` — that belongs to the operator. Evidence is a bounded ≤120-char excerpt with control characters crushed and every assignment-shaped token (`KEY=value`, `key: "value"`, `password = 'x'`) masked to `KEY=[redacted]`: proof of the exposure's shape without the secret itself.
- **REST**: `GET /api/exploits/templates` (read class; `{count, templates}` with each template's family, keywords and description) and `POST /api/exploits/run` (Admin class; body `{fingerprints:[…]}` with unique 6+-character prefixes → `{executed, results:[{fingerprint, template, verdict, reason, evidence, verified_at}]}`; `400` on an empty list or 51+ fingerprints, `409` while `[exploits] enabled = false`).
- **CLI**: `readyhai exploits list` prints the catalogue (zero settings reads, zero network); `readyhai exploits run <fingerprint>…` (`--json` available) refuses with a clear message while `[exploits] enabled = false` — before any probe — hard-fails on a broken settings file or a configured-but-invalid scope, and routes every probe URL through `scope::egress_guard(…, intrusive = true)` (`READYHAI_SCOPE`).
- **UI**: Settings gained an editable **Exploitation** card (enable toggle + `max_probes`, riding along in every `PUT /api/settings`, with the server's 1–100 bounds mirrored client-side; hidden when an older backend reports no `effective.exploits`). The Vulns view gained a per-row verification badge on stamped rows (tone by verdict; tooltip carries verdict, template, when and why) and a **Verify** button that runs the finding's own template via `POST /api/exploits/run` and restamps the row — `409` disabled answers show the server's own wording, and the buttons hide entirely against a backend without the templates endpoint.

### Changed

- Vulndb rows gained `verification` / `verified_by` / `verified_at`, all `#[serde(default)]`: JSONL files written before v3.7 load unchanged and their rows read as `unverified` (also normalised when an empty string is deserialized). `GET /api/vulns` accepts `?verification=` (any of the five values, same 400-on-bogus rule as `status`/`severity`).

### Docs

- `settings.example.toml`: documented `[exploits]` section (default-off rationale, probe budget semantics). README feature list + Vulnerability Database and both UI sections updated; `docs/README.md` index rows (`api.md`, `configuration.md`) and `docs/build-log.md` Round 11 describe the engine, the safety layers and the endpoints.

### Testing

- 15 new engine tests (`src/exploits/tests.rs`): keyword matching gated to URL resources, unknown template → `skipped` not panic, non-URL resource skip, redaction (`KEY=[redacted]`) and control-char crushing, the `.env` shape needing two real assignments, the admin oracle needing two markers, live stub-server probes (verified-and-redacted; `not_reproducible` on 404; the TLS template's honest `inconclusive`), a guard refusal producing `inconclusive` with zero traffic sent, and the batch runner (stamps rows, never touches `status`, budget skips extras, unknown fingerprints skip). The `serve` route table pins both new endpoints; the Vulns view suite adds badge, Verify-stamps-row, 409-disabled and hide-without-templates cases, and the Settings suite adds the Exploitation card (toggle + `max_probes` riding in every `PUT`, hidden for backends without the section). Release run: 999 `cargo test` passed (15 new), 170 vitest cases (6 new), `cargo clippy -- -D warnings` and frontend lint clean.

## [3.6.0] - 2026-11-23

### Added

- **Five official network packs** (`plugins/official/`, all digest-pinned, researched against live Docker Hub): `nmap` (instrumentisto — `-sV --version-light --top-ports 100` bounded service sweep), `rustscan` (official org image — connect sweep), `sqlmap` (parrotsec — level 2 / risk 1 SQLi confirmation) are `intrusive` ⇒ deep profile + nonprod only, exactly like `naabu`; `testssl` (official drwetter image) is a read-only TLS audit at standard profile next to `tlsx`; `nikto` (frapsoft — the SecureCodebox image is a ruby wrapper that drops an interactive CVE prompt, so it stays out until that changes). Each pack was flag-verified against its image and smoke-run on loopback (`--help` conformance, entrypoint, output shape). New output parsers in `src/tools/plugins.rs` for their native formats: `nmap` (`-oX` XML, risky ports escalate, dangerous services capped medium), `nikto-xml` (medium on named CVE/OSVDB/EDB items), `testssl` (brace-balanced multi-object JSON; OK/INFO skipped, its own grades mapped), `sqlmap` (injectable url/parameter entries only), `portline` (rustscan-style `ip:port` stdout, deduped, empty-output exit 0 stays a note).
- **Vulnerability database** (`src/vulndb.rs`): every warn/fail finding from every scan is recorded across targets in one local JSONL (`<data>/vulns/vulns.jsonl`, created on first finding; `[vulndb] enabled/path` in settings, `[vulndb]` also governable through `PUT /api/settings` with proper `null`-clears-path semantics). Fingerprints dedupe re-observations (occurrences + `last_seen` counted; `target_key` reuses agent-memory canonicalization); triage statuses `open|accepted|forgotten` survive re-scans — an acceptance only re-opens when severity changes. CLI `readyhai vulns [--json] [--status S] [--target T] [--all]` + `readyhai vulns accept|forget <fp>` (prefix-matched ≥6 chars). REST `GET /api/vulns` (count+rows, `status`/`severity`/`target` filters, 400 on bogus values) and `POST /api/vulns/{fp}` (admin-only when RBAC is on — the fail-closed write rule needed no new code). Findings flow in from either CLI or `serve` scans; suppressed findings never record.
- **WireGuard config audit** — built-in `wireguard` check (46th), no sidecar image needed (none exists worth trusting): audits wg-quick `*.conf`/`*.wgconfig` for committed `PrivateKey`/`PresharedKey` values (key material is length-reported, never echoed — covered by test), same key reused across peers/files (fail-open decrypt-once, get-everywhere), `AllowedIPs = 0.0.0.0/0|::/0` default-route overreach, non-32-byte/placeholder base64 keys, two `[Interface]`s claiming one `ListenPort`, `[Interface]` without `Address=`, and peers with `Endpoint` but no `PersistentKeepalive`. Non-WireGuard `.conf` files (nginx et al.) are detected by content and ignored; flows through baselines/suppressions/SARIF like every other check.
- **On-the-go setup** (`ensure_packs` in `src/tools/plugins.rs`, one orchestrator call site): before the first plugin check, a scan pre-provisions what it is actually about to select — pulls missing digest-pinned pack images (never a blind tag), pre-creates the tool-cache dir for `cache_rw` packs, and reports each action as `setup: …` notes. Settings-silenced packs, wrong-kind/profile packs, offline bundles and `--no-tools` are skipped exactly like the dispatch loop decides; a 90 s setup budget hands the rest to on-demand pulls — provisioning can never stall a scan on a registry hiccup.
- **Vulns view** (fifth top-level tab): cross-target table with severity chip, target, rule (mono), first/last seen, occurrence count and status, open/accepted/forgotten + severity filters with debounced target search that also flows to query params, per-row Accept/Forget (server-backed 403s read as "requires admin"), counts header, and an empty state pointing at the first deep scan. Settings gained a "Vulnerability database" card (enabled chip, path or default-data-dir, live open count, and an honest fallback against older backends).

### Changed

- Check count 45 → 46 (`wireguard`); official packs 14 → 19 (19/19 load with `READYHAI_PLUGINS=plugins/official readyhai doctor`).
- `Facts` gained `wg_files`; the snapshot walk content-sniffs WireGuard configs alongside the existing k8s-yaml detection.

### Docs

- `plugins/README.md`: five new pack rows, a considered-&-rejected note (masscan/zmap — raw sockets vs `--cap-drop ALL`; thc-hydra — no maintained image and an out-of-posture class; WiFi suites — monitor mode needs; wireguard — built-in instead), the on-the-go setup guarantee, and the five new formats in the reference. `docs/configuration.md`: `[vulndb]` template, a Vulnerability-database section (fingerprint/status semantics incl. severity re-open) and a WireGuard-rule section. `docs/api.md`, `docs/checks.md`, README feature list, and the Round-10 build-log entry.

### Testing

- Suite: 984 passed / 0 failed / 3 ignored (`cargo test`). New: five parser fixtures, `ensure_packs` provisioning (six tests with an injectable pull — no Docker needed, offline short-circuit, budget), vulndb units (lazy file creation, dedupe/occurrences, status survival incl. severity re-open), six WireGuard rule cases (key redaction proven by test), settings `[vulndb]` validation, `PathPut` absent/null/value round-trip, vulns REST + route-table drift rows. Frontend: vitest 164 passed (12 new: VulnsView suite + Settings vulndb card); `tsc --noEmit` clean. `cargo clippy -- -D warnings` clean; `python3 tomllib` parse 19/19 packs; `readyhai doctor` loads 19/19.
- Live: each new pack was digest-verified (`docker inspect`) and smoke-run on loopback (nmap `-oX` parsed end-to-end, rustscan `Open ip:port` lines, testssl JSON, sqlmap JSON shim, nikto byte-clean XML incl. a query-string URL). WireGuard E2E: a deliberately-bad `wg0.conf` directory produced 8 findings at the right severities, and a second scan recorded "9 new, 2 seen again" — dedupe proven. Docker v3.6.0 stack (`readyhai` + `readyhai-frontend`): `/health` reports 3.6.0; a `POST /api/scans` of the bad-WG target wrote 16 rows into the vuln DB; `GET /api/vulns` through the Next.js proxy returned them, `POST /api/vulns/{fp}` accepted one (`{"ok":true}`), and direct-to-backend unauthenticated calls answer 401 on both routes.

## [3.5.0] - 2026-11-23

### Added

- **Operator settings layer** (`src/settings.rs`, `--settings FILE` / `READYHAI_SETTINGS`, template `settings.example.toml`): tri-state (`auto|on|off`) toggles for every check — exact id, glob (`plugin.crowdstrike.*`), or category (`[integrations] tools / plugins / intrusive`). `off` produces a visible `Skipped` with reason (a toggle never hides coverage); `on` protects a check from *settings only* — profile, scope-nonprod, `--no-tools`, and Docker gates keep full authority; `integrations.intrusive` accepts only `auto|off`, so settings can silence the intrusive class but never force it. Resolution: exact id > last matching glob > category > auto; precedence `--settings` > env > none. A broken settings file is a hard error, and a scanned repo is never consulted. `cargo scan`/`qa` note `settings: N override(s)` in every report.
- **RBAC for `serve`** (`src/serve/rbac.rs`, fully togglable, template `rbac.example.toml`): per-key bearer tokens (`[[key]]` with `key` or `key_sha256`, hashed in memory, constant-time compare) carrying roles `viewer < operator < admin`. Toggle precedence `READYHAI_RBAC=on|off|auto` > `[rbac].enabled` in the file > auto (ON when a key file exists); **off restores the exact legacy single-token mode**. Route matrix enforced in middleware: `GET`/`HEAD` = read; scans/agent/network/eval/cancel = operate; approve/reject/fix/memory-accept/delete = admin; unclassified writes fail closed as admin. `403` bodies name the role and the required role (distinct from `401`). The legacy boot token is break-glass admin unless `READYHAI_RBAC_BOOT_ADMIN=0`. `READYHAI_RBAC=on` without usable keys refuses to boot. `GET /api/whoami` reports the caller's name/role/permissions. Sign-offs and run audit lines record the authenticated key name.
- **Settings UI + REST** (`/api/settings` GET/PUT/DELETE, `/api/settings/checks`, `/api/rbac`; view `SettingsView`): operators flip integrations and per-check toggles in the UI; PUT writes `<data>/settings.toml` atomically, admin-only when RBAC is on (enforced twice: middleware + request classification), with the intrusive-kill-switch rules rejected server-side (`400`), an mtime-based `version` token, `shadowing_env` when an operator `READYHAI_SETTINGS` file outranks the UI-edited file, and the full check catalog with each check's effective decision and decider. The RBAC panel lists key names, roles, and 3-byte digest prefixes — never key material — and answers the admin-only gate with a muted note for lower roles.

### Changed

- `Principal` is now `{name, role}` from the authenticated key (was a bare name); `App` carries the `Rbac` state; `ScanOpts` gained `settings`, which `serve` scans resolve per request (env file wins, else `<data>/settings.toml`) and the orchestrator re-reads per run.
- Frontend: `SaaSViewMode` gained `"settings"`; a Settings nav tab renders the integrations controls, check catalog, and access panel.

### Docs

- `docs/configuration.md`: "Settings (tool/plugin toggles)" and "RBAC (rbac.toml)" sections with design rationale cross-checked against Trivy, Nuclei, Prowler, DefectDojo, super-linter, Wazuh, and github-mcp-server precedents; new env vars in the reference table; `settings.example.toml` and `rbac.example.toml` templates alongside `scope.example.toml`.
- `docs/api.md`: RBAC block in the auth model, role-route matrix, new endpoints.

### Fixed

- **Settings UI "unsaved changes" badge stuck on**: the dirty check compared `JSON.stringify` output, which is sensitive to object key order — the server's wire format orders keys differently from the client's object literals, so the view always looked dirty (Discard could not clear it). The comparison now canonicalizes both sides (sorted key/value pairs); the frontend test stub now re-serializes responses in server wire order so the bug class stays caught.

### Testing

- Suite: 946 passed / 0 failed / 3 ignored (`cargo test`). New: settings units (7), RBAC units (5), full-router RBAC e2e over the real TCP stack incl. the off-toggle restoring legacy mode, settings REST round-trip (GET/PUT/DELETE, validation, catalog decision, RBAC panel). Frontend: vitest suite 152 passed incl. 8 new SettingsView tests; `tsc --noEmit` clean. Live smoke against the release binary verified the RBAC status matrix (200/401/403 per role), `/api/whoami`, and `--settings` skipping in a real scan report. Browser (Next.js dev UI against the v3.5.0 binary): admin save → file written → effective decision "off by settings" on refresh; viewer sees the muted RBAC note and a surfaced `403 role viewer may not govern` on Save; Discard and Reset-to-defaults (DELETE) verified.

## [3.4.0] - 2026-11-22

### Added

- **Recon-chain plugin packs** (`plugins/official/`): `dnsx` (resolvable-host brute — stdin is null in the sandbox so the self-contained `-d {domain} -w` mode is used), `tlsx` (TLS/cert inventory), `naabu` (active TCP port scan, `intrusive`: deep profile + nonprod only), `gau` (archived-URL collector; pinned `sxcurity/gau` because `projectdiscovery/gau` was renamed `urlfinder` and no PD image exists). All `lines`-format, digest-pinned, and every flag set run live in the runner sandbox.
- **Supply-chain plugin packs** (`plugins/official/`): `grype` (image lane, SARIF; reuses the `/cache/grype` DB seeded by `readyhai tools update` via the `GRYPE_DB_CACHE_DIR` env name — without it the first-run DB download overruns the runner's 1 GB tmpfs) and `osv-scanner` (repo lane, `scan source -r /src`, `--allow-no-lockfiles` keeps manifest-free repos reporting an empty SARIF instead of exiting 128 with no file).
- **`readyhai tools pull` also pulls plugin images** (`--plugins DIR` / `READYHAI_PLUGINS`, default `<data>/plugins`): valid plugin images are pulled on top of the lock, deduped against the lock and across packs, sharing the retry/backoff; each pulled image is inspected and a **digest-drift warning** fires when the registry digest differs from the pin in `plugin.toml`. Without `--lock` an unpullable plugin image warns and continues.
- **`readyhai doctor` plugin diagnostics**: a `plugins:` section lists every pack in the plugin directory as loaded/skipped, with the exact rejection reason (missing `output`, bad `user`, invalid `env` name, unrecognized `kinds`, unparseable TOML) plus its image and an `N loaded, M skipped` summary. A single validator (`reject_reason`) is shared by the loader and the diagnostics so the two can never drift.

### Fixed

- **An incomplete run can never yield a PASS verdict** (orchestrator backlog item 4). A plugin whose report parses but records a failed or interrupted run was previously only a warning, so a run with zero findings converged on PASS — "the scan did not happen" was reported as "the scan was clean". Now SARIF `executionSuccessful: false`, error-level or exception-bearing `toolExecutionNotifications`, reports with no runs, and non-zero process exits that still produced parseable output all surface as `CheckStatus::Partial` notes the gate may warn or fail on but can never upgrade to PASS. The `lines` inventory format is exempt from the exit-code rule (recon tools legitimately exit non-zero on partial input). `parse_sarif` became `parse_sarif_report` (findings + incompleteness notes).

### Docs

- `plugins/README.md` official table covers the six new packs; `docs/superapp-orchestrator.md` sprint/backlog status records what shipped (Sat recon chain, Sun-AM supply chain, Mon glue, item 4) and what explicitly did not (katana→nuclei `/cache` hand-off — needs a shared-writable mount the runner does not give; trivy `--skip-db-update` + KEV/EPSS enrichment; the Sun-PM cloud/LLM lanes).

### Testing

- Suite: 932 passed / 0 failed / 3 ignored (`cargo test --locked --bin readyhai`). New coverage: SARIF incompleteness (3), plugin load/skip diagnostics + image-ref enumeration + pull-plan dedup + digest-drift + warn-and-continue/strict (6), pack-loading goldens for all six new packs (2). `readyhai doctor` verified live against `plugins/official`: 14 loaded, 0 skipped.

## [3.3.0] - 2026-11-18

### Added

- **Loop Engineering (OODA Adaptive Control Engine - `src/agent/react.rs`)**:
  - Implemented closed-loop *Observe-Orient-Decide-Act (OODA)* controller for the Explorer stage.
  - Added continuous anomaly detection monitoring runtime errors, HTTP 500 stack traces, and validation schema leaks.
  - Dynamic mutation hypothesis synthesis powered by `ADAPTIVE_MUTATOR_ROLE` system prompts.
  - Integrated `OscillationDamper` with signature-based repetition detection to eliminate infinite mutation cycling.
  - Bounded wave execution strictly respecting global wall-clock, request count, and token budgets.

- **Graph Engineering (StateGraph & Attack DAGs - `src/agent/pipeline/graph.rs`, `src/agent/plan/dag.rs`)**:
  - Formalized typed `StateGraph` finite state machine governing the 6-station lifecycle: `Recon` $\to$ `Discovery` $\to$ `Plan` $\to$ `Execute` $\to$ `Verify` $\to$ `Gate`.
  - Added conditional edge routing (`RoutingCondition::NormalProgression`, `AnomalyDetected`, `ReplayRequired`, `BudgetExhausted`).
  - Added station iteration counters and infinite-loop guards (`MAX_STATION_ITERATIONS = 5`).
  - Extended Attack DAG dependency engine with topological sorting and prerequisite execution guards (`execute_guarded`), preventing cascade false positives.
  - Embedded execution telemetry (`GraphTelemetry`) into every run report.

- **Prompt Engineering (Adversarial Defense & Role Specialization - `src/agent/prompts/`)**:
  - Centralized role-specialized prompt templates across all 6 stations: Recon, Discovery, Plan, Execute, Verify, and Gate.
  - Adversarial XML fencing (`<target_untrusted_content>`) and proactive sanitization (`neutralise_target_tags`) neutralizing prompt breakout and tag forgery.
  - Strict JSON schema constraints and deterministic fallback mechanisms ensuring LLM outputs never corrupt pipeline state.

- **Software Factory Engineering (Station Quality Gates & Signed Attestation - `src/agent/pipeline/gates.rs`)**:
  - Formal station entrance and exit quality gates validating input completeness and verification contracts.
  - Cryptographically signed release attestation (`SoftwareFactoryAttestation`) certifying OWASP ASVS V2–V14 compliance with a deterministic SHA-256 digest seal.
  - Cryptographic evidence provenance in the Evidence Ledger.

- **Autonomous Directives Engine & Command Center UI (`frontend/src/components/Composer.tsx`)**:
  - Removed manual text inputs from Command Center; dynamically synthesizes directives via LLM from target surface.
  - Live threat focus badges, security boundary rules, and unique canary token tracking.

## [3.2.0] - 2026-11-18

Deep Agentic Software Factory Pipeline (Recon, Discovery, Plan, Execute, Verify, Gate), Dynamic Directives Synthesis Engine, Attack DAGs, Contextual Taint Juror, and Command Center Autonomous UI.

### Added

- **6-Station Software Factory StateGraph Pipeline (`src/agent/pipeline/graph.rs`)**:
  - Formalized agent execution into a finite state graph with verified station transitions: `Recon` $\to$ `Discovery` $\to$ `Plan` $\to$ `Execute` [Adaptive ReAct Loop] $\to$ `Verify` [Contextual Taint Juror] $\to$ `Gate` [Software Factory Attestation].
- **Station 1: Target Reconnaissance & Dynamic Directives Engine (`src/agent/recon/`)**:
  - Implemented HTTP security header, cookie, and TLS certificate fingerprinting (`probe_target_recon`).
  - Implemented dynamic agent directives synthesis (`SynthesizedDirectives`): automatically synthesizes rules of engagement, threat vectors (BOLA, IDOR, session leaks, prompt injection), boundary rules, and unique canary tokens via LLM.
  - Exposed endpoint `POST /api/agent/directives/synthesize` in `src/serve/agent_api.rs`.
- **Station 2: Semantic Shadow Route & Parameter Discovery (`src/agent/discover/semantic.rs`)**:
  - Added LLM-assisted semantic route and parameter schema prediction (`discover_semantic_routes`).
  - Predicts hidden shadow endpoints (internal health, admin users, RBAC permissions) and realistic schema shapes for unparameterized API routes.
- **Station 3: Attack DAG & Stateful Workflow Planner (`src/agent/plan/dag.rs`)**:
  - Implemented `AttackDag` and `AttackDagNode` with dependency tracking, cycle detection, and topological sorting.
  - Synthesizes chained multi-step stateful exploit sequences (e.g. setup user $\to$ escalate role $\to$ exfiltrate tenant) guided by dynamic directives.
- **Station 4: Execution & Adaptive ReAct Loop (`src/agent/react.rs`)**:
  - Added real-time anomaly detection (`is_anomaly_candidate`) for HTTP 500 stack traces, 403 authorization leaks, and 422/400 validation schema leaks.
  - Added adaptive branching waves: automatically synthesizes mutation hypotheses and dispatches immediate probe waves to pivot attack paths.
- **Station 5: Verification & Contextual Taint Tracing Juror (`src/agent/verify/juror.rs`)**:
  - Implemented Source-to-Sink taint reflection analysis (`evaluate_with_juror`, `audit_defects_with_juror`) to eliminate automated false positives.
  - Synthesizes concrete unified diff remediation patches (`remediation_patch`) and explanations for verified true positive defects.
- **Station 6: Readiness Gate & Software Factory Attestation (`src/agent/pipeline/gate.rs`)**:
  - Added `software_factory_attestation`: computes release risk scores (0–100), OWASP ASVS breakdown across V2–V14 categories, release directives, and a SHA-256 integrity seal.
- **Frontend Command Center Autonomous Directives Engine (`frontend/src/components/Composer.tsx`)**:
  - Removed manual directives `<textarea>` and static hint buttons.
  - Introduced autonomous directives panel with live threat focus badges, security boundary tags, and 1-click re-synthesis without requiring operator prompt engineering.

## [3.1.0] - 2026-11-17

Full Architectural Modularization (82,460 lines deconstructed across 40 slices), Standalone Single-Binary Engine with Auto-Discovery for Linux & Windows, and Production Docker Hardening.

### Added

- **Architectural Modularization (Slices 1–40)**:
  - Deconstructed over 82,460 lines of monolithic Rust code into clean, modular domain submodules across `src/` (`agent`, `qa`, `serve`, `eval_ai`, `fix`, `bundle`, `report`, `scope`, `code_audit`, `android`, `tools`, `model`, etc.).
  - Standardized module visibilities (`pub(crate)`), eliminated circular dependencies, and isolated test suites across 839 unit & integration tests.
- **Standalone Single-Binary Cross-Platform Engine (Linux & Windows)**:
  - Added zero-dependency `.env` and `scope.toml` auto-discovery (`config::auto_load_env()`) across current directories, `~/.config/readyhai/`, and `%APPDATA%\readyhai\`.
  - Added Win32 stdio handle duplication in `src/mcp/protocol.rs` (`DuplicateHandle` + `GetStdHandle`) enabling `readyhai mcp` on Windows for Claude Code, Cursor, and IDE agents.
  - Cross-platform Tokio signal handling in `src/qa/resilience.rs` (`tokio::signal::ctrl_c()` on Windows, POSIX signals on Unix).
  - Cross-platform data directory resolution in `src/engine/storage.rs` supporting `%LOCALAPPDATA%\readyhai\data`.
  - Official one-line installer scripts: `install.sh` (Linux/macOS) and `install.ps1` (Windows PowerShell).
- **Production Multi-Stage Docker Release**:
  - Validated multi-stage Dockerfile packaging (`rust:1-slim-bookworm` $\to$ `debian:bookworm-slim` + `docker:29-cli`).
  - Container image size optimized to 235 MB with Thin-LTO and symbol stripping.
  - Full cluster integration verified with `readyhai-frontend` (Next.js on port 3000) and `readyhai-socket-proxy`.

## [3.0.0] - 2026-11-17

Full Ecosystem Modernization, Security Tool Refresh, and Reliability Hardening across Rust 2024, Tree-Sitter 0.27, Node 24 Active LTS, and Container Toolchains.

### Added

- **Reliability Hardening & Resilient Tool Pulling:**
  - Added exponential backoff retry loop (up to 3 attempts with dynamic backoff) in `tools_pull_filtered` for container image pulls to gracefully handle transient network spikes and registry rate limits.
  - Hardened HTTP connection pooling in `src/llm.rs` with explicit `pool_idle_timeout` (90s) and `tcp_keepalive` (30s) to prevent socket timeouts and connection churn.
  - Release profile optimization in `Cargo.toml`: configured `panic = "abort"` and `codegen-units = 1` for ultra-lean, fast production binaries with reduced memory fragmentation.

### Changed

- **Crate & Core Engine Upgrades:**
  - Upgraded `tree-sitter` from `0.25` to `0.27.2` (leveraging the pure-Rust runtime architecture for robust multi-language AST auditing).
  - Upgraded `minijinja` to `3.1.0`, `clap` to `4.6.8`, and `rand` to `0.10.4`.
  - Updated frontend Vite/Vitest test runner to native `import.meta.dirname` for 100% deprecation-free ESM runs under Node 24.
- **Security Scanner & Tool Images Refresh (`tools.lock.toml`):**
  - Upgraded Anchore Syft to `v1.57.1` (`sha256:03215d0e98b661d0ecbc8575dbc14d65be1743b5de5df6410aecb7e80f95b060`).
  - Upgraded Anchore Grype to `v0.121.3` (`sha256:13113eeceab017260370cf540e1d25442c59665fd07d1b09b66d63bb0c282887`).
  - Upgraded Semgrep to `1.183.0` (`sha256:2e45517a85e13a9cca14a2a00df6bb48affd66b8ebfae1b0991cd57578362fb0`).
  - Upgraded Bridgecrew Checkov to `3.4.5` (`sha256:122602cf32cc72286155d39f1f234b7b594818f7b8d7fdf490701620e521368b`).
  - Pinned ProjectDiscovery Nuclei to `v3.11.1` (`sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb`).
  - Pinned Grafana k6 to `v2.3.0` (`sha256:3e4186aea62e11a45560bfc51e19eeafe82fc07ce069c78aff44b7ff893d9a5e`).

## [2.5.0] - 2026-11-14

Autonomous Source Code Mutation Testing (`readyhai mutate`), test oracle calibration, negative test synthesis, and multi-region probe mesh.

### Added

- **Autonomous Mutation Testing Engine (`src/mutate.rs`):**
  - CLI command `readyhai mutate [--repo DIR] [--target PATH] [--max-mutants N] [--timeout-secs N]` and REST endpoint `POST /api/mutate`.
  - Injects targeted semantic defects into customer source code across comparison operators, boolean flips, auth guard bypasses, return values, and arithmetic operators.
  - Automatically runs detected repository test harness (`cargo test`, `npm test`, `pytest`, `go test`) against each mutant to evaluate test oracle sensitivity.
  - Computes Mutation Score ($\frac{\text{Killed} + \text{TimedOut}}{\text{Total}} \times 100\%$) and classifies test oracle quality (`EXCELLENT`, `ADEQUATE`, `WEAK`).
  - Synthesizes actionable recommended negative test assertions for every survived mutant to eliminate blind spots.
- **Multi-Region Probe Mesh Coordination:**
  - Route `POST /api/network/multi-region` for geographically distributed vantage latency, SSL certificate propagation, and CDN edge consistency testing.

## [2.0.0] - 2026-11-14

The Agentic Fixer (`readyhai fix`): AST-grounded code remediation, test-before-PR verification loop, and automated Pull Request bot.

### Added

- **The Agentic Fixer Engine (`src/fix.rs`):**
  - CLI command `readyhai fix [--repo DIR] [--defect ID|RULE] [--run ID] [--dry-run] [--verify] [--branch NAME] [--format text|json|markdown]` and REST endpoint `POST /api/fix`.
  - AST-grounded remediation patch synthesis:
    - **Missing Auth Guards:** Injects route middleware based on mined sibling endpoint security conventions across Express, FastAPI, Flask, and Chi.
    - **SQL Injection:** Parameterizes string concatenations and f-strings into bound SQL placeholders (`%s`, `$1`, `?`).
    - **Path Traversal:** Injects safe `basename` and normalization validation before file I/O sinks.
    - **Command Execution:** Eliminates `shell=True` and replaces raw string shell executions with safe argument vectors.
    - **Wildcard CORS:** Replaces wildcard `*` with configurable allowed origins.
    - **Hardcoded Secrets:** Extracts plaintext credentials into environment variable lookups.
  - Sibling Guard Mining: scans existing codebase routes to discover and match standard authentication middleware tokens.
  - Deterministic Test-Before-PR Verification Sandbox: executes project test runner (`cargo test`, `npm test`, `pytest`, `go test`) on candidate patches, rolling back automatically on failure to guarantee zero regressions.
  - Automated PR Bot: creates local git branches, authors structured commits, and synthesizes markdown PR descriptions with unified diffs and Evidence Ledger curl proofs.

## [1.5.0] - 2026-11-14

Universal GenAI & Agent Evaluator (`readyhai eval-ai`): RAG Quality Triad, deterministic hallucination extraction, trajectory efficiency, and adversarial prompt injection red-teaming.

### Added

- **Universal GenAI Evaluator Engine (`src/eval_ai.rs`):**
  - CLI command `readyhai eval-ai [--query Q --context C --response R | --dataset FILE] [--red-team] [--threshold F]` and REST endpoint `POST /api/eval-ai`.
  - **RAG Quality Triad:** Context Relevance, Answer Relevance, and Faithfulness / Groundedness with itemized hallucinated fact and number extraction.
  - **Agent Trajectory & Tool Execution Evaluation:** JSON schema conformance, cyclic repeat loop detection, and trajectory efficiency scoring.
  - **Adversarial Red-Teaming Scanner:** Prompt injection signature detection, credential leak scanning (`sk-`, `ghp_`, `AKIA`), and canary exfiltration auditing.

## [1.2.0] - 2026-11-14

W3C OpenTelemetry distributed trace context propagation, autonomous Markov state-graph dead-end explorer, and multi-persona synchronized testing.

### Added

- **W3C Distributed Tracing Injection (`src/qa/api/exec.rs`):**
  - Injects `traceparent`, `tracestate`, and `baggage` headers into every probe, fuzz payload, and Playwright browser request.
  - Correlates test failures directly to OpenTelemetry APM spans and SQL trace queries via `READYHAI_APM_URL`.
- **Autonomous Markov State-Graph Explorer (`runners/playwright/qa.mjs` & `src/qa/ui.rs`):**
  - Dynamic page state fingerprinting and transition graph construction.
  - Dead-end view detection defect emission (`qa.ui.dead_end`, P2 Medium).
- **Multi-Persona Synchronized Testing:**
  - `sync_personas: [...]` spins up concurrent browser sessions across distinct roles (e.g. admin and regular member) to audit instant session revocation and privilege isolation.

## [1.0.0] - 2026-11-14

Enterprise multi-worker task queue recovery, native GraphQL QA fuzzer, resilient self-healing Playwright locators, and OpenAPI 3.1 polymorphic support.

### Added

- **Native GraphQL QA Fuzzer (`src/qa/graphql.rs`):**
  - Introspection query parsing, circular query DoS attack fuzzing (`qa.graphql.circular_dos`), and field-level authorization auditing (`qa.graphql.unauthorized_field`).
- **Resilient Self-Healing Locators (`runners/playwright/qa.mjs`):**
  - 4-tier fallback selector hierarchy (`data-testid`, semantic role/name, text, and resilient structural CSS) with automatic defect tracking on fallback (`qa.ui.healed_locator`).
- **OpenAPI 3.1 & JSON Schema Draft 2020-12 Support:**
  - `prefixItems` tuple array synthesis, type array validations, and polymorphic schema generation.
- **Persistent Task Queue Recovery (`src/serve.rs` & `src/engine.rs`):**
  - Persists `opts.json` per scan to resume interrupted queue tasks across server restarts.
  - Concurrent multi-worker pool scaling via `READYHAI_WORKERS`.

## [0.9.0] - 2026-11-14

Full-stack library, runner, and container toolchain modernization across Rust, TypeScript, React, Python, and Docker environments.

### Upgraded

- **Rust Backend Ecosystem:**
  - Upgraded template rendering engine to **MiniJinja v3.1.0** (`features = ["serde"]`), adapting template context serialization via `minijinja::value::Serde` across HTML scan, QA, and offline trend dashboard reports (`src/dashboard.rs`, `src/report.rs`, `src/qa/report.rs`).
  - Upgraded cryptographic hashing to **Sha2 v0.11.1** with `digest v0.11.3` across bearer token verification, fingerprinting, and bundle tamper validation (`src/model.rs`, `src/serve.rs`, `src/bundle.rs`).
  - Upgraded random generation to **Rand v0.10.3** and migrated RNG trait imports to `rand::RngExt` (`src/engine.rs`, `src/android.rs`, `src/agent/oast.rs`).
  - Upgraded HTTP client to **Reqwest v0.13.5** with AWS-LC and Rustls cryptographic backends (`features = ["blocking", "rustls", "json"]`) for LLM streaming and agent HTTP executions (`src/llm.rs`, `src/agent/exec.rs`).
  - Advanced 27 compatible in-range transitive crates (`toml 1.2.1`, `cc 1.11.2`, `rustls-pki-types 1.16.0`, `rustls-webpki 0.103.17`, `globset 0.4.21`, `syn 3.0.10`, `smallvec 1.16.5`, etc.).
  - Zero test regressions: all 813 Rust tests pass.
- **Frontend Studio & Node Ecosystem:**
  - Upgraded container base to **Node 24 Active LTS** (`node:24-slim` across `deps`, `builder`, and `runner` multi-stage targets in `frontend/Dockerfile`).
  - Upgraded TypeScript to **v7.0.2** with zero typecheck errors (`npx tsc --noEmit`).
  - Upgraded **Next.js to v16.4.6** and `eslint-config-next` to `v16.4.6` with Turbopack optimizations.
  - Upgraded **React & React-DOM to v19.3.1**.
  - Upgraded **Tailwind CSS & plugins to v4.3.5** (`tailwindcss`, `@tailwindcss/postcss`, `@tailwindcss/turbopack`).
  - Upgraded **Vitest to v5.1.0** and `@vitejs/plugin-react` to `v6.3.0`.
  - Upgraded **Lucide React to v1.73.0** with expanded iconography.
  - Upgraded **Undici HTTP client to v8.12.4** in the frontend proxy handler (`src/app/api/[...path]/route.ts`).
  - Zero test regressions: all 141 frontend Vitest tests pass.
- **Runners Subsystem:**
  - Upgraded Playwright QA & browser security runner: **Playwright v1.65.1**, **Axe-core v4.14.0**, **Pixelmatch v8.0.0**, with base container pinned to `mcr.microsoft.com/playwright:v1.65.1-noble@sha256:1507cbfc550a63a6b7396791ca4f00df17beb56342d2447b3f106c306f525579`.
  - Upgraded Python context retriever: **LangChain v0.3.19**, **LangGraph v0.2.74**, **Pydantic v2.10.6**, **Sentence-Transformers v3.4.1**, **Faiss-CPU v1.10.0**.
  - Pinned `tools.lock.toml` Playwright runner to `v1.65.1`.

## [0.8.1] - 2026-11-14

Tri-state exit criteria classification, warning status indicators, scaled custom directives capacity (32 KB), and live Composer limit monitoring.

### Added

- **Tri-State Exit Criteria (`status: "met" | "warning" | "unmet"` in `src/agent/types.rs` & `src/agent/ledger.rs`):**
  - Unexercised or unevaluated test categories with 0 failures (e.g. injection resistance not evaluated due to no input surface or unexecuted cases) now classify as **`warning`** (amber) instead of a harsh red **`not met`**.
  - Conclusive coverage below the full 80% confidence target but above the 50% conditional threshold (such as 75%) is classified as **`warning`**, aligning with the `Conditional go` release gate verdict.
  - Non-defect execution friction (blocked or flaky cases, missing request/response evidence files) evaluates as **`warning`**.
  - Red **`not met`** is strictly reserved for confirmed defects and violations (critical/high severity findings, actual SQLi/prompt injection breaches, authz boundary failures, or pass rates below 85%).
- **Warning Indicators on Pillar Cards (`frontend/src/components/LedgerPanels.tsx`):** Un-evaluated pillars now render an amber `Warning` badge in Agent Studio instead of hiding status.
- **HTML & Markdown Report Formatting (`src/agent/report.rs`):** HTML reports style warnings with `st-WARN` class; Markdown reports render `[!]` for advisory/warning exit criteria alongside `[x]` (met) and `[ ]` (not met).
- **Expanded Custom Directives Capacity (`src/serve.rs` & `src/mcp.rs`):**
  - Default `custom_instructions` / `directives` limit increased from 4 KB to **32 KB (32,768 bytes)**.
  - Made configurable between 4 KB and 128 KB via `READYHAI_MAX_CUSTOM_INSTRUCTIONS_BYTES`.
  - Planner prompt extraction scaled from 500 characters to **8,000 characters** in `src/agent/plan.rs` so detailed instructions feed into LLM attack synthesis.
- **Frontend Directives Counter & Guard (`frontend/src/components/Composer.tsx` & `frontend/src/app/page.tsx`):** Added live byte counter (`bytes / 32,768 bytes`) with warning colors and client-side limit guard preventing 400 errors.

## [0.8.0] - 2026-11-12

Enterprise reliability, fast DNS preflight guards, differential injection and boundary oracle calibration, and dual-stack network binding.

### Added

- **Brand Identity & Web Assets:** Added official ReadyHai geometric vector logo mark and horizontal lockup (`frontend/public/icon.svg`, `frontend/public/logo.svg`), multi-resolution favicons (`favicon.ico`, `favicon-16x16.png`, `favicon-32x32.png`), mobile touch icon (`apple-touch-icon.png`), PWA icons (`icon-192.png`, `icon-512.png`), PWA `site.webmanifest`, Next.js App Router metadata wiring, Studio header branding (`frontend/src/components/Header.tsx`), standalone documentation assets (`docs/assets/`), and inline CSP-safe SVG emblems in HTML scan, QA, and dashboard reports.
- **Fast DNS Pre-flight Reachability Guard (`preflight_host_dns` in `src/serve.rs`):** Asynchronous DNS resolution check (<1500ms timeout) that immediately returns HTTP 422 NXDOMAIN in <100ms when a domain does not resolve, preventing dead or mistyped domains from blocking worker threads.
- **Differential Injection & Query Tolerance Oracle (`src/agent/oracle.rs`):**
  - Added `boundary_tolerance` decisive check: safe HTTP 200..=299 responses to GET boundary and numeric tolerance tests are recognized as clean passes instead of falling into inconclusive.
  - Added `injection_sanitized` decisive check: safe SQL/NoSQL probe responses that do not disclose database signatures or crash the server record a definitive pass.
  - Handled path traversal probes with explicit sanitization expectations.
- **Scaled Concurrency Pool & Grace Queue (`src/serve.rs`):** Scaled `MAX_CONCURRENT_PROBES` from 4 to 16 and added a 2-second semaphore acquisition timeout before raising HTTP 429.
- **Dual-Stack Docker Compose Binding (`docker-compose.yml`):** Bound frontend (`${FRONTEND_PORT:-3000}:3000`) and backend (`${READYHAI_PORT:-8080}:8080`) to all interfaces, enabling IPv4 and IPv6 loopback connectivity from modern browsers and preventing `ECONNREFUSED` / `Failed to fetch`.

### Fixed

- **Public Surface Calibration (`src/agent/plan.rs`):** Decoupled `fallback_entry` from unrelated internal routes (`!entry_walled` instead of `!any_walled`), ensuring public entry pages (`/`) generate injection, boundary, and robustness test cases even if separate internal endpoints are behind auth walls.
- **Case Priority Ordering (`src/agent/types.rs`):** Moved `is_ledger_row()` placeholder records down to priority class 3 / tier 2, guaranteeing that real executable test cases are never dropped in favor of dummy placeholder rows during `max_steps` plan trimming.
- **Evidence Ledger Exit Criteria:** Injection resistance and data safety now evaluates conclusively on web applications and directives, achieving >= 80% conclusive coverage.

## [0.7.0] - 2026-11-12

Deep security vulnerability scanning across static AST, pinned active scanners, and the autonomous adversarial agent.

### Added

- **Native Tree-sitter AST & cross-file code audit (`security.code_audit`, `src/code_audit.rs`):** Intra-file and cross-file (up to 3 hops) taint tracking across Python, JavaScript/TypeScript/TSX, Go, and PHP for SQL injection (`security.taint.sql_injection`), OS command execution (`security.taint.command_exec`), SSRF (`security.taint.ssrf`), path traversal (`security.taint.path_traversal`), and SSTI (`security.taint.ssti`), plus sibling endpoint auth middleware inconsistency detection (`security.auth.missing_guard`). Also powers AST import reachability enrichment (`enrich_osv_with_ast`) for `tool.osv_reachability` when call-graph reachability is `unknown`.
- **Deep static & DAST scanner integrations:**
  - `tool.opengrep` (`Standard`, `tools.lock.toml`): intra-file taint analysis (`--taint-intrafile`).
  - `tool.nuclei` (`Standard`, `tools.lock.toml`): CVE, misconfiguration, exposure, and takeover templates with cached `/cache/nuclei` support and non-DoS/non-fuzz exclusions.
  - `tool.zap_active` (`Deep`, `[intrusive]`, `tools.lock.toml`): full active ZAP scan (`zap-full-scan.py`) strictly gated on `Deep` profile + `nonprod` target.
- **Expanded `web.smoke` header & TLS checks (`src/web.rs`):** Weak CSP detection (`web.weak_csp` for `'unsafe-inline'`, `'unsafe-eval'`, wildcard `*`, `http:` script sources) and TLS certificate/protocol checks (`web.tls_weak_protocol`, `web.tls_expiring`, `web.tls_untrusted`).
- **Modular adversarial attack generators (`src/agent/attacks/`):**
  - `auth.rs`: JWT tampering (`alg:none`, stripped signature, escalated claims with bogus signature, `kid` traversal), BFLA role cross-calls, and reverse-proxy path normalization / header-override ACL bypasses (`/.`, `..;/`, `X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`).
  - `bopla.rs`: Excessive Data Exposure (`ProbeOracle::ExcessiveDataExposure`) and stateful mass assignment (`role=admin` / `is_admin=true` read-back checks).
  - `injection.rs`: Parameter-name/schema-guided Open Redirect (`ProbeOracle::OpenRedirect`), SSRF (`ProbeOracle::OastCallback`), multi-encoding path traversal, SSTI (`{{1337*79}}` / `${1337*79}`), boolean-differential and time-delay SQLi, and time-delay OS command injection.
  - `logic.rs`: TOCTOU concurrency / single-use replay races, workflow step-skipping, negative quantities/amounts, HTTP Parameter Pollution (HPP), and GraphQL introspection/depth probes.
- **In-process OAST callback collector (`src/agent/oast.rs`):** Zero-dependency loopback HTTP listener (`READYHAI_OAST_BIND` default `127.0.0.1:0`, `READYHAI_OAST_URL`) correlating `__OAST_URL__` blind SSRF/callback probes in `exec` and `verify` (`oast_callback`).
- **Interactive Playwright `BrowserSecurity` (`src/agent/browser_sec.rs`, `runners/playwright/agent_browser.mjs`):** Browser DOM XSS, DOM sink inspection, client storage leak checks (strictly masked previews — never stores raw tokens/JWTs), cookie flags, exposed source maps, and clickjacking verification (`READYHAI_AGENT_BROWSER=off` disables; write probes gated on `nonprod`).
- **White-box AST bridge & ReAct adaptive waves (`src/agent/whitebox.rs`, `src/agent/react.rs`):** Links live agent endpoints and findings back to source handlers, sinks, and missing auth guards when `--repo` is supplied, and runs adaptive ReAct follow-up waves (`react_lead`) under `Budget`.
- **Two new deterministic eval suites & OWASP benchmark harness:** Added `security-deep` and `whitebox-exploit` under `tests/eval/` and `tests/fixtures/` (bringing `readyhai eval --suite all` to 10 suites), plus `scripts/bench_owasp.sh` and `scripts/bench_owasp.ps1`.

### Fixed

- **Toolchain & script fixes:** Scoped test-only parsers (`parse_semgrep`, `parse_opengrep`, `parse_zap`) under `#[cfg(test)]`, fixed `clippy::needless_borrows_for_generic_args` in `src/llm.rs`, and aligned `scripts/bench_owasp.{sh,ps1}` `--target` flags with `readyhai agent` CLI syntax.

## [0.6.2] - 2026-11-07

### Changed

- **Model tier picker.** Descriptions now state the speed trade-off, and High is marked as the recommended tier for small and flash models. Picking Max or Max Pro shows a note: the 16k/32k reasoning budget slows the planner, so with models like qwen3.8-flash use High for faster runs (the planner is also capped at High automatically when the model answers slowly).

## [0.6.1] - 2026-11-07

### Fixed

- **"Agent run failed (HTTP 502): Backend proxy connection failed: fetch failed".** The UI's API proxy used Node's built-in `fetch`, which gives up after 300 s waiting for response headers, while agent runs are synchronous and a deep run often takes longer; the run completed on the backend but the browser got a 502. The proxy now uses an undici dispatcher whose header and body timeouts follow the backend's run limit (`READYHAI_RUN_TIMEOUT_SECS`, default 3600 s, plus 2 min), and a proxy error now includes its cause.
- **One slow LLM call could use the whole LLM budget.** A Max Pro planner call (34k tokens) on a small model ran ~6 minutes, then the gate advisory found the budget exhausted. Each call (with its downgrade retries) is now limited to 60% of the run's remaining LLM time (at least 10 s, never more than its own timeout), and no further downgrade starts past that deadline.

## [0.6.0] - 2026-11-06

Agent reliability and accuracy: verdicts reflect the app, not the agent's blind spots. On the NuHire SPA, inconclusive results dropped from 15 of 18 to 1 of 8, and a false NO_GO became NOT_EVALUATED with the exact next step.

### Added

- **SPA discovery.** Soft-404 calibration (three random paths; status, length and normalised-text fingerprint) flags catch-all routes. Next.js routes are taken from `_buildManifest.js`, app-router chunk paths and the RSC payload. API paths are extracted from up to 30 same-origin JS chunks. `robots.txt` and `sitemap.xml` are read. More OpenAPI locations are tried (`/api-docs`, `/openapi.yaml`, `/swagger/v1/swagger.json`, `/api/v1/openapi.json`, `/.well-known/openapi`, `/docs` spec links). API hosts outside scope are reported ("add to scope.toml"), never called.
- **Headless XHR discovery** (standard/deep, SPA, Docker): the Playwright runner's new `discover` mode navigates without clicking or submitting and records the API calls the app makes (templated paths, key names only, no values or auth headers). `READYHAI_AGENT_XHR=off` disables it. Rebuild the runner image (`docker build -t readyhai/playwright-runner:local runners/playwright`).
- **Auth-wall detection.** A 401, a redirect to a login/SSO page or a password form marks the route `auth_wall`. Cases there without a credential are BLOCKED (auth wall) with the next step (`readyhai roles init`, `RH_<ROLE>_TOKEN`, storageState), not INCONCLUSIVE.
- **Blockers and confidence.** The evidence ledger has `confidence` (conclusive share of applicable cases, overall and per pillar) and `blockers[]` (auth wall, no input surface, transport, out of scope) with a next step each; a new exit criterion requires 80% conclusive coverage.
- **LLM reliability.** Per-call timeout scales with the request (`clamp(20 + max_tokens/40, 30, 300)` s, `READYHAI_LLM_TIMEOUT_SECS` overrides). A timed-out call is retried smaller (half `max_tokens`, no reasoning effort) instead of identically; a 5xx is retried once, then the next fallback model. A 1-token probe measures latency at run start; a slow endpoint caps planner thinking at the High tier. Gate and triage calls never use thinking.
- **Eval.** New metrics: precision, inconclusive rate, confidence, blockers; new gates `max_inconclusive_rate`, `forbid_verdict`, `expect_blocker`. New Next.js-like fixture `tests/fixtures/spa-next` with suites `agent-spa` (seeded IDOR, SQL error leak, boundary 500), `agent-spa-clean` (must not be NO_GO) and `agent-spa-noauth` (must be NOT_EVALUATED with an auth-wall blocker).
- **UI.** Pillar cards show the backend pillar name, claim and a confidence chip; a "What to provide next" card lists blockers; NOT_EVALUATED shows as a neutral "Not evaluated" (never red); scenarios show NOT_APPLICABLE and BLOCKED reasons and the redirect chain.

### Changed

- **Redirects.** Discovery records the first-hop status, redirect chain and final URL. The executor follows same-origin redirects (up to 5) for liveness, content and robustness cases and judges the final response; authz and sensitive-file probes keep the raw status. Verifier replays follow redirects too.
- **Planner.** Injection, boundary and negative cases target only routes with an input surface (query, form, JSON/API, spec). SPA shells, catch-all routes, login forms and routes that refuse GET (405) get NOT_APPLICABLE rows instead of doomed cases; with credentials, API routes are preferred over the HTML entry page.
- **Wave-2 re-probes** run only for transient causes (transport error, timeout, 5xx, 429, 408), not for redirects, missing evidence or CORS 405.
- **Scoring.** Pillar score is `(pass + 0.5·warn) / conclusive`; a pillar is scored only at 50% confidence or more. NOT_EVALUATED when overall confidence is below 50%, or when an auth wall hides the app and only hygiene checks concluded. NO_GO stays for proven failures. The pass-rate criterion counts conclusive applicable cases only.

### Fixed

- Pillar claims and exit-criteria details started with ": 2 passed" (missing technique label).
- UI pillar cards always said "No evidence text was reported" and used wrong labels ("API Contract" for functional correctness).
- "a injection" wording.

## [0.5.0] - 2026-11-05

LLM provider freedom, enterprise-scale specs, RBAC bootstrap and a PR bot.

### Added

- **Pull-request bot.** `--format pr` writes `readyhai-pr-comment.md` (verdict, reasons, category counts, top 15 open findings, escaped). The repo root is now a composite GitHub Action (`uses: deziss/readyhai@v0.5.0`) that installs the checksummed release binary, scans, keeps one PR comment up to date and gates (`fail-on: fail|warn|never`, `no-tools`). `ci/gitlab-ci.yml` posts/updates one MR note with `READYHAI_GITLAB_TOKEN`. The image now ships `jq`.
- **Enterprise-size specs.** The operation cap is `READYHAI_MAX_OPS` (default 2000, ceiling 10000, was a fixed 500). Operations past it show as untested in coverage with a roll-up note. `$ref` expansion and spec size are bounded, and the quadratic hot spots in planning, coverage, evidence and role matching are gone (1500 operations parse, plan and generate in about 1 s in a debug build).
- **`readyhai roles init --spec <openapi>`** derives a `roles.toml` skeleton from `securitySchemes`, per-operation `security`, OAuth2 scopes and `x-roles`. It uses `RH_<ROLE>_TOKEN` placeholders and never values, writes mode 0600 into the secrets directory, and will not overwrite without `--force`.
- **Generic LLM endpoint and key.** `READYHAI_LLM_URL` sets the base URL for any provider (OpenAI-compatible or Anthropic transport) and `READYHAI_LLM_API_KEY` the key for any provider (bearer or `x-api-key`; wins over `OPENAI_API_KEY` and friends; never logged). The provider ids `openai-compatible` and `custom` select the generic `vllm` provider.
- **Fallback models.** `READYHAI_LLM_MODEL` (or `READYHAI_LLM_MODELS`) takes a comma-separated list; a failed call moves on to the next model in order. `GET /api/agent/status` lists `configured_models` and `api_key_configured`.
- **Off-box guard for URLs.** A local provider pointed at a public host (not loopback, private, `.local`/`.lan`/`.internal`, single-label) now needs `READYHAI_LLM_ALLOW_CLOUD=1`, with an error that says so. A refused LLM config is noted in the QA report instead of silently running deterministic.

### Changed

- UI: **Run regressive test** moved from the header into the Environment and target panel; the sticky Adversarial scenarios toolbar is now opaque and stacks above the rows, so scenarios no longer show through it.

- Inside the Docker image (`READYHAI_IN_CONTAINER=1`) a `localhost` / loopback `READYHAI_LLM_URL` is rewritten to `host.docker.internal`, so the same `.env` works on the host and in compose.

### Deprecated

- `READYHAI_VLLM_URL`: still read when `READYHAI_LLM_URL` is unset. Empty values of every `READYHAI_LLM_*` variable now count as unset.

## [0.4.0] - 2026-11-05

Documentation refresh.

### Added

- `CHANGELOG.md` (this file).

### Fixed

- Docs that contradicted the code were corrected: the scope policy (public hosts get full testing by default, internal hosts must be listed or matched by `*`, `prod` entries are read-only), exit codes of `qa` and `agent` (0/1/2), the agent's pillar weights (30/30/25/15, not 25 each), the `errored_fails` policy key (a required check that errors fails the gate), the removal of `src/web_ui.rs` and of the hard-coded host exclusion, the live-verification status of UI, PDF, ZAP, Schemathesis, resilience and MobSF (verified 2026-10-30), 41 built-in checks, digests pinned for 16 of 17 tools, the Docker image shipping `ssh`, and the `qa.resilience` check being the one intrusive check.

## [0.3.0] - 2026-11-05

UI revamp.

### Added

- **Design system.** IBM Plex Sans for the UI and IBM Plex Mono for real code (URLs, curl commands, ids), loaded with `next/font`. Colour, radius, type-scale and shadow tokens (`rh-bg`, `rh-surface`, `rh-raised`, `rh-line`, `rh-text`, `rh-muted`, `rh-primary`, `rh-go`, `rh-cond`, `rh-nogo`, `rh-info`) defined once in `frontend/src/app/globals.css`; panels use a 1px border, the only shadow is for popovers and dialogs. Reduced-motion and focus-ring rules are global.
- **Command center layout.** The mode switch and header are pinned at the top, the **Run agent** button is pinned at the bottom, and only the controls in between scroll, so the run controls can never be pushed out of reach. Result tabs (Scenarios and inspector, Discovered routes, Evidence ledger, Threat triage, Runs history) stay pinned above their scrolling panels.
- **Release gate in the workspace.** The sign-off card moved from the command center to the workspace column and collapses to a one-line header. "Approve for deployment" is offered only for `GO` / `CONDITIONAL_GO`.
- **Pipeline stepper.** A six-stage stepper (Recon, Discovery, Plan, Execute, Verify, Gate). Every stage has a fixed size in every state; details open on click or keyboard into a fixed-height area, nothing reacts to hover except colour, so the layout never shifts. The Gate stage shows the verdict exactly as the backend reported it.
- **Cancel button and status chips.** Running runs in Runs history have a Cancel button (`POST /api/agent/runs/{id}/cancel`); running, cancelled and failed runs carry a lifecycle chip. A cancelled run shows its partial results and never a gate decision.
- **Token settings.** A key button in the header opens the API-token dialog. The token is kept in `localStorage` (`readyhai_api_token`, in memory when storage is blocked) and attached to every request; a `401` raises a banner until a valid token is saved.
- **Sandboxed reports.** HTML reports are fetched with the token and shown in an iframe sandboxed without `allow-scripts` and `allow-same-origin`; other formats are downloaded as blobs.
- Frontend tests for the new behaviour (`AgentHistoryView`, `Composer`, `FloatingTaskWidget`, `RunStatusBadge`, `ToolCallList`, clipboard and deep-audit cache helpers).

### Changed

- The UI renders only what the backend reported: a missing verdict, score, pillar, requester IP or latency is shown as "not evaluated" or "unknown" in a neutral style, and a green GO appears only for a `GO` verdict. Sign-off state changes only after the backend confirms it.

## [0.2.0] - 2026-11-05

Backend: review fixes, verifier, eval harness, CI, and the super agent (shared QA checks, code-aware planning, lead and sub-agents, memory across runs). These ship together because the super-agent modules are wired into the same core files.

### Security

- **Tokens never reach curls or reports.** Test credentials come only from `RH_<ROLE>_TOKEN` variables; reproduction commands carry the placeholder `${RH_<ROLE>_TOKEN}`, evidence is redacted, and the server's own secrets are never attached to requests sent to a target.
- **Credentials are bound to the target host.** A token is attached only when scheme, host and port equal the run's target, only through the client that validates TLS certificates, and redirects are never followed, so a credential cannot follow a `Location` header elsewhere.
- **Fail-closed scope loading.** A scope file that is configured (`--scope`, `READYHAI_SCOPE`) but missing, a directory, unreadable or invalid is an error everywhere: scans, `agent`, MCP tools and every REST guard (500) refuse to run, and `readyhai serve` checks it at startup (with a hint for the empty directory Docker creates when `scope.toml` is missing).
- **MCP agent tools are safe by default.** `readyhai_agent_swarm` is a dry run unless the caller says otherwise *and* the operator set `READYHAI_MCP_ALLOW_WRITES=1` (the target must also be nonprod in scope); unknown arguments are rejected; at most 2 swarms run at once.
- **Compose network isolation.** The Docker socket proxy sits on an `internal: true` network shared only with `readyhai`; the frontend is on the `edge` network only and cannot reach it. The proxy image is pinned (`v0.5.0`), the backend and the proxy have healthchecks and start in dependency order, and services run with `init: true` and a stop grace period (20 s for the backend).

### Fixed (accuracy)

- **One oracle path.** Every outcome (base request, mutation probe, burst, stateful chain, verifier replay) is judged by `agent::oracle`, with severities from a single table (`triage::severity_for`).
- **Deterministic verdicts.** The LLM may add planned cases, prose and an advisory opinion stored beside the verdict; `gate_verdict` is always the computed one. LLM-proposed cases whose expectations no deterministic oracle failed are run but not scored.
- **Inconclusive is a first-class outcome.** A failure that does not reproduce becomes `INCONCLUSIVE` (not a defect); a ledger with no conclusive result is `NOT_EVALUATED`; `readyhai qa` reports **Inconclusive** when nothing is known to be wrong but too little ran.
- **No fabricated results.** Pillars without conclusive evidence are "not evaluated" (no default scores); the Evidence pillar is the share of executed cases with a stored request/response file; remediation output is generic guidance labelled "example - adapt to your code" (the invented unified diffs are gone); network-lab fields that cannot be measured are `null` or listed in `not_measured`; PR comments and badges say "not evaluated" / `n/a` instead of defaulting to PASS.
- QA engine: a response that says nothing about a case is Blocked, never Pass; check status follows the evidence (Errored / Partial / Skipped); writes never touch harvested records.

### Added

- **The agent reuses the QA engine's API checks.** With an OpenAPI spec the planner uses `qa::api::synth` (case generator), `contract` (response validator and error-leak catalog) and `latency` (p95 over 1000 ms) instead of its own copies. It reads the ids of existing records from collection endpoints (read-only GETs) and plans a contract read per record. Every case carries its response contract, so the oracle and each verifier replay judge it the same way. The eval fixture's 7 seeded bugs are now all found by the agent (7/7).
- **Code-aware planning.** `readyhai agent --repo DIR --diff-base REF` (and `repo` / `diff_base` over REST and MCP) plan around `git diff REF...HEAD`: the QA engine's route extractors map changed files to OpenAPI operations, changed operations get the full case set (even at `quick`), are planned first and cut last, and the report gets a **Change impact** section with per-operation coverage. A diff that cannot be read is a note, never a failed run. An optional context retriever (`runners/context_retriever`, only when an index exists) adds untrusted, redacted, advisory notes and never a case. New settings: `READYHAI_CONTEXT_INDEX`, `READYHAI_CONTEXT_RETRIEVER`, `READYHAI_CONTEXT_TIMEOUT_SECS`, `READYHAI_HOME`.
- **Lead agent and area sub-agents** (`src/agent/lead.rs`). The planner tags every case with an area (`auth`, `contract`, `state`, `ui`); the lead gives each area a slice of the run budget (weighted by risk, three times for a changed operation), runs the areas on `READYHAI_AGENT_WORKERS` threads (default 4, at most 8; `1` gives the same results one after another), merges results by case id, and plans at most one deterministic wave 2 (`auth-to-contract`, `budget-resume`, `inconclusive-reprobe`, never a new write). One per-host rate limiter and one cancel flag are shared by all workers. Reports gain an "Agents" section; `readyhai_agent_status` shows per-area progress.
- **Memory across runs** (`src/agent/memory.rs`). Each target gets `<data>/memory/<target_key>.json` with known defects (by fingerprint), flaky history per case class, per-operation coverage and run aggregates. Known defects are re-tested first, runs report "Since last run" (new, still open, fixed, regressed, not re-tested, known flaky, accepted, acceptance expired), and known-flaky failures are replayed with the maximum k. Memory is written only from deterministic results, never from LLM text, and only reorders a plan. `readyhai agent-memory show|accept|forget`, `GET/DELETE /api/agent/memory`, `POST /api/agent/memory/accept`, and `READYHAI_AGENT_MEMORY=off`. An explicit, expiring acceptance is the only thing that lets a known defect through the gate; it is listed in every report (SARIF `suppression`, JUnit `skipped`).
- Triage folds failures of one check on one endpoint (`/orders/4`, `/orders/5`, ...) into one defect, and the same server error on three or more endpoints into one.
- **Verifier replay.** Every FAIL is replayed `READYHAI_VERIFY_K` times (default 2, at most 5, `0` = off) through the same oracle before triage: all reproduce = confirmed, some = flaky (kept as FAIL for high/critical, WARN otherwise), none = INCONCLUSIVE. Write-method failures are replayed only when the case created its own resource or targets an id no record has. The ledger reports pass^k.
- **Cleanup ledger and confirmation.** Every 2xx creation the run causes is recorded as it happens; on a confirmed-nonprod target the run deletes them newest first, confirms each 2xx DELETE with a GET (`confirmed_gone`, `still_present` = `delete_not_effective`, `unconfirmed`) and writes `cleanup.json` with the leftovers.
- **Eval harness.** `readyhai eval [--suite a,b] [--k N] [--out DIR] [--dir DIR]` scores the QA engine and the agent against fixtures with seeded defects (recall, false positives, pass^k, verdict stability, request and time budgets). Suites in `tests/eval/*.toml`: `qa-api`, `qa-repo`, `agent-api`, `agent-diff`, `agent-memory`. Writes `eval-report.json` and `eval-report.md`. See `docs/eval.md`.
- **CI gates.** New `eval` job (loopback only, no docker, no LLM) and `docker` job (PR builds of the three images, no push); `ci.yml` is reusable (`workflow_call`) and `image.yml` publishes only for the tag `v<VERSION>` after the full CI passed.

### Changed

- `readyhai_agent_status` reports `since_last_run` and per-area progress; `report.json` is checkpointed while the workers run.
- **Exit codes.** `readyhai qa` and `readyhai agent` exit `0` / `1` / `2` (Go / Conditional Go / No-Go or not evaluated); `qa` takes the worse of the recommendation and the gate verdict. Errors still exit `3`; `eval` exits `0` or `1`.
- **MCP.** `readyhai_agent_swarm` returns a run id at once and runs on a worker thread; `readyhai_agent_status` and `readyhai_agent_cancel` poll and stop it; on client disconnect every run the server started is cancelled.
- Reliability: reads are capped (tool stdout 32 MiB, tool output files 50 MB and never through symlinks, response bodies 1 MiB, memory file 8 MiB), state files are written atomically (temp file + rename), and agent runs can be cancelled (`POST /api/agent/runs/{id}/cancel`, `status: cancelled`, partial results kept).

## [0.1.0] - 2026-10-27

Baseline: the repository as committed at `ed4215b` (first commit 2026-10-25; the tag `v0.1.0` marks `8bf9bd5` on 2026-10-27, and development continued under the same version until 2026-11-05).

### Added

- **Scan engine.** `readyhai scan` for repositories, container images, web apps and APIs, SSH hosts (Linux, macOS, Windows) and Android APKs; a check registry with native readiness rules, container checks and plugins; a filtered snapshot with a secrets denylist; a policy gate (PASS / WARN / FAIL), baselines, suppressions with expiry; HTML, JSON, SARIF and JUnit reports; log clustering. Scanners (Syft, Grype, Gitleaks, Semgrep, Hadolint, Checkov, Dockle, ZAP, Schemathesis, MobSF) run in throwaway sandboxed containers pinned by digest in `tools.lock.toml`.
- **Interfaces.** CLI, REST API (`readyhai serve`, bearer token on every route but `/health`), MCP server over stdio, the `/readyhai` Claude Code mod, Docker image and compose stack with a socket proxy, CI recipes for Jenkins, GitHub Actions, GitLab and ArgoCD PostSync.
- **Senior-QA engine** (`readyhai qa`): API tests (positive, boundary, negative, auth matrix, stateful CRUD, BOLA, contract, error leaks), UI tests with Playwright (responsive, a11y, vitals, forms, journeys, visual), k6 performance baseline, compose fault injection, suite and release quality (coverage, untested routes, test smells, end-of-life, migrations, licences), `roles.toml`, a computed Go / Conditional Go / No-Go recommendation, and HTML, PDF, Markdown, Jira, GitLab, TestRail and Xray reports.
- **Offline mode.** `bundle export` / `bundle import`, `doctor`, an embedded end-of-life snapshot, optional LAN LLM enrichment, a static trend dashboard.
- **Agentic AI QA** (`readyhai agent`): Planner, Explorer, Triager and a readiness gate with a four-pillar Evidence Ledger (Value, Authority, Safety, Evidence); extended thinking with model tiers; adaptive schema mutation; stateful multi-actor chains and BOLA audits; TOCTOU concurrency bursts; example remediation guidance; MCP swarm tools; a persistent run history with retest, delete and sign-off.
- **Agent Studio** (`frontend/`, Next.js 16 and React 19): swarm composer, scenario inspector, evidence ledger, threat triage, scans history, and the **Regressive Network Lab** (regress, curl, six-pillar deep audit, multi-region single vantage point, HAR export, PR comment and badges).
- **Supply-chain checks** (`src/supply.rs`): OSV-Scanner reachability, OpenSSF Scorecard, Spectral, oasdiff, mutation-report parsing.
- **Scope policy.** `scope.toml` rules of engagement: public hosts get full testing by default, internal hosts must be listed, `prod` entries are read-only, `*` wildcard, `[git]` host allowlist.
- **Release engineering.** Single-source versioning (`VERSION`, `scripts/version.sh`), multi-arch GHCR images with SBOM and SLSA provenance, release tarball attestation, OpenSSF Scorecard workflow, all actions pinned by commit SHA.
- Live verification on 2026-10-30: UI QA (6/6 seeded UI bugs) and PDF, ZAP baseline and Schemathesis on the fixture API, resilience pause/unpause on a compose fixture, MobSF on InsecureBankv2. See `docs/build-log.md`.
- Licensed under AGPL-3.0.
