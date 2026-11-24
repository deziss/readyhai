# ReadyHai optional scanner plugins (runner v2)

Optional community / vendor scanners kept **outside the binary**. The plugin runner
(`src/tools/plugins.rs`) mounts the target read-only at `/src` (image targets also
get `/src/image.tar`), gives a writable `/out`, and for `cache_rw = true` a writable
`/cache` (the tool cache, same dir `readyhai tools pull` uses). Findings appear as
check `plugin.<id>` and flow through baselines, suppressions, SARIF/JUnit export and
the PASS/WARN/FAIL gate for free.

    readyhai scan <target> --profile standard --plugins plugins/official   # or READYHAI_PLUGINS=

The loader reads one level: `<dir>/<pack>/plugin.toml`. Directories without a
`plugin.toml` are ignored, so `official/` and `_example/` roots are inert — point
`--plugins` at your own directory, or at the pack dirs individually
(`--plugins plugins/official`, `_example/` sub-dirs load if you point at
`plugins/_example` — those are working templates, copy them first).

## Bundled packs

**`official/` — verified E2E (Nov 2026), digest-pinned.** Enable with
`--plugins plugins/official` (or copy packs you want). The five v3.6.0 packs
(`nmap`, `rustscan`, `testssl`, `sqlmap`, `nikto`) use the new native formats and the
same sandbox guarantees; each was flag-verified against its live image and smoke-run
on loopback at release time. Digest-pin their images and check them with
`readyhai doctor` (`READYHAI_PLUGINS=plugins/official` prints per-pack load/skip reasons).

| Pack | Lane | Format | Notes |
|---|---|---|---|
| `subfinder` | recon | `lines` (JSONL) | passive subdomain enum; free API keys via `env` names, works without |
| `httpx` | recon | `lines` | surface + tech fingerprint; `host_gateway` for localhost targets |
| `katana` | recon | `lines` | crawler; feeds nuclei/zap next run |
| `feroxbuster` | recon | `lines` | point `-w` at `/cache/wordlists/...` from `scripts/fetch-feeds.sh recon` |
| `dnsx` | recon | `lines` | resolvable-host filter (`-d {domain} -w /cache/wordlists/...`; stdin is null in the sandbox, so no piped `-l`) |
| `tlsx` | recon | `lines` (JSONL) | TLS/cert inventory of the web target |
| `naabu` | recon | `lines` (JSONL) | active TCP port scan ⇒ `intrusive` (deep profile, nonprod only) |
| `gau` | recon | `lines` | archived-URL collector (`lc/gau` lineage — `projectdiscovery/gau` was renamed `urlfinder`, no PD image exists) |
| `nmap` | recon | `nmap` (-oX) | service/version sweep ⇒ `intrusive` (deep, nonprod only); `-top-ports 100 --version-light` bounded for the 600 s budget |
| `rustscan` | recon | `portline` | connect-sweep ⇒ `intrusive`; dedup'd `ip:port` stdout |
| `kube-linter` | posture | `sarif` | manifest/Helm lint of `/src` |
| `kube-score` | posture | `sarif` | real exit-code semantics |
| `conftest` | posture | `sarif` | ships ReadyHai's own rego pack (`policies/rego`) via cache |
| `kubescape` | posture | recipe README | official image is server-only; build a CLI image first |
| `testssl` | posture | `testssl` | TLS/protocol audit of the web target — read-only probe, standard profile (like tlsx) |
| `grype` | supply chain | `sarif` | image lane; shares `cache_rw` `/cache/grype` DB (set `GRYPE_DB_CACHE_DIR`) seeded by `tools update` |
| `osv-scanner` | supply chain | `sarif` | repo lane (`scan source -r /src`); `network` for the OSV API, `--allow-no-lockfiles` keeps clean repos at exit 0 |
| `sqlmap` | web attack | `sqlmap` | SQLi confirmation ⇒ `intrusive`; level 2 / risk 1 bounds |
| `nikto` | web attack | `nikto-xml` | attack-signature inventory ⇒ `intrusive`; XML stdout, medium on known CVE/OSVDB items |

**Considered & rejected** (same vetting as everything above): **masscan / zmap** —
raw-socket senders need `CAP_NET_RAW`, which collides with the `--cap-drop ALL`
sandbox, and neither image is maintained; **thc-hydra** — no reputable maintained
image, and credential brute-forcing is excluded by posture regardless; **WiFi
suites** (aircrack et al.) — monitor mode and host networking are impossible in
the sandbox by design; **WireGuard audit** — no OSS auditor image exists, so it
shipped differently: a built-in repo check (`wireguard`, see
[docs/configuration.md](../docs/configuration.md)).

**`_example/` — templates** (loader ignores them; copy and adapt):

| Example | Tool (license) | Notes |
|---|---|---|
| `trivy/`, `trivy-secrets/`, `trivy-config/` | Trivy (Apache-2.0) | uses `cache_rw` + `--cache-dir /cache/...` (tmpfs `/tmp` is RAM-backed and too small for the DB) |
| `owasp-dependency-check/` | OWASP DC | NVD feed download on first run — needs `network = true` |
| `npm-audit/` | npm | stdout JSON pattern (`stdout = true`, no `sh -c` shim anymore) |
| `osv-report/` | osv-scanner | README explains why HTML report ≠ parseable |
| `crowdstrike-fcs/` | **commercial BYO** | your licensed Falcon CLI in a private image + `falcon2readyhai.sh` jq→readyhai-json converter |

## plugin.toml reference

```toml
id = "toolname"                # check id becomes plugin.<id>
title = "Human title"
kinds = ["web"]                # repo|web|image|host|android (match target kinds)
profile = "standard"           # quick|standard|deep (deep ⇒ intrusive: nonprod only)
image = "org/img:v1@sha256:…"  # digest-pin or you get an "unpinned" note
# network = true               # only if the tool phones home (visible in audit)
# host_gateway = true          # add host-gateway so containers can reach the host
# stdout = true                # capture stdout as the report instead of /out file
# format = "lines"             # sarif | junit | readyhai-json | lines (JSONL recon)
                               # | nmap (nmap -oX XML) | nikto-xml (nikto -Format xml)
                               # | testssl (testssl.sh --jsonfile) | sqlmap (sqlmap JSON report)
                               # | portline (rustscan-style `ip:port` stdout lines)
#   nmap      — one finding per <port> with state="open" on an up <host>; down hosts and
#               <hostport> entries ignored; low, medium for risky ports
#   nikto-xml — each <item> with a <description>; medium when it names OSVDB/CVE/EDB-ID,
#               otherwise low; works with stdout = true
#   testssl   — brace-balanced JSON objects; OK/INFO skipped,
#               LOW→low, MEDIUM→medium, HIGH/CRITICAL→high; rule testssl.<id>
#   sqlmap    — injectable url/parameter entries only (confirmed injection type or
#               "is vulnerable"/"injectable" wording), always high
#   portline  — `ip:port` tokens from any line, deduped on (host, port), low; lines
#               without such a token are ignored; empty output + exit 0 = clean scan
# output = "/out/x.sarif"      # required unless stdout = true
# cache_rw = true              # writable /cache for scanner DBs/templates
# env = ["TOKEN"]              # names only; values copied from ReadyHai's env, never argv
# user = "10001"               # numeric uid[:gid] override
# rule / severity / title_prefix  # required for format = "lines"
args = ["-u", "{url}"]         # placeholders: {src} {out} {url} {domain} {image_tar}
# entrypoint = ["tool"]        # override image entrypoint if it wraps args
```

Behaviour the runner guarantees:

- **Output formats** — `sarif` (levels map error→high, warning→medium, note→low),
  `junit` (a failing suite reports its status; exit code only trusted when
  `stdout = true`), `readyhai-json` (`Vec<Finding>`, exact control), `lines`
  (one JSON object per line from recon CLIs; url/host extracted from common keys,
  deduped; empty output + exit 0 = zero findings, e.g. subfinder on an IP).
- **Loopback targets are rewritten** to `host.docker.internal` (same rule as core
  web checks via `container_url()`) and the host gateway is auto-enabled — localhost
  dev servers are reachable from `network = true` plugins with no extra config.
- **Secrets:** `env` lists *names*; values are resolved from ReadyHai's own
  environment and passed with `docker run -e NAME` — they never appear in the host
  process list. Missing names ⇒ check is `partial` with a note, not a failure.
- **Empty/garbage output** ⇒ `tool_failed` with exit code + stderr excerpt in the
  note (except the exit-0 `lines` case above). A plugin that fails to *load*
  (unknown format, bad `user`, non-numeric env name, no `output` without `stdout`)
  is skipped at load time with a warning.
- Sandboxes stay non-root (unless numeric `user`), read-only rootfs,
  `--cap-drop ALL`, tmpfs `/tmp`. `intrusive` (`profile = "deep"`) plugins run only
  against targets the scope file doesn't mark `prod`.
- **On-the-go setup** (v3.6.0): at scan start ReadyHai pre-pulls the digest-pinned
  plugin images that are not yet local and creates the pack cache dirs, so a fresh
  machine with a plugin dir enabled works without a prep step. What was provisioned
  shows up as `setup:` notes in the report. Offline bundle mode skips it; plugin
  runs still fall back to pulling on demand, and `readyhai tools pull --plugins DIR`
  remains the eager option (pull everything once, before the first scan).

## Feeds & data sources

`scripts/fetch-feeds.sh [recon|vulndata|llm|rego|all]` populates the tool cache
(`$READYHAI_DATA_DIR/cache` → `/cache` in plugins): SecLists + assetnote wordlists,
nuclei-templates, CISA KEV, FIRST EPSS, GHSA, PATT, and the bundled rego pack.
Licenses/cadence: [docs/data-sources.md](../docs/data-sources.md).

## Vendor / community editions (BYO licence)

License stays outside the repo; a thin wrapper converts output to `readyhai-json`.
Pattern: `_example/crowdstrike-fcs/` (Falcon CLI on a private image). Same recipe
for **Snyk** (`snyk/snyk` + token via `env`), **Qualys CE** (free 16-asset tier,
API keys via `env`), **Caido headless** (PAT; prefer over Burp — Burp *Community*
edition's EULA forbids automation, Burp *Pro* headless is fine on a customer
licence). Rule: **public availability + redistribution terms verified from primary
sources, or it doesn't ship — not even as an example.** Policy detail:
[docs/superapp-orchestrator.md](../docs/superapp-orchestrator.md).

## Two enhancement paths

**A. Plugin (zero code).** Any tool with SARIF/JUnit/JSON-file/stdout-JSONL output.
Right home for AGPL tools and commercial CLIs you cannot redistribute.

**B. Native `tool.*` check (first-class).** The built-in pattern (15 scanners):
pin image in `tools.lock.toml` → `Check` in `src/tools/checks.rs` → parser in
`src/tools/parsers.rs` → secret scrubbing → register in `docs/checks.md` + fixture
test. Choose B when the tool becomes a default gate member for everyone.

## Still on the wishlist

- `host = true` execution (PATH binaries like `pip-audit`) with the same caps as containers.
- Register popular plugin images in `tools.lock.toml` so `readyhai tools pull`
  and offline bundles ship Trivy et al. as *optional* extras.
- Orchestrator roadmap (Finding v2, DefectDojo, evidence DAG, MCP broker):
  [docs/superapp-orchestrator.md](../docs/superapp-orchestrator.md).
