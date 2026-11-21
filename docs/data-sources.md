# Data sources & feeds

ReadyHai plugins and lanes consume third-party data feeds. `scripts/fetch-feeds.sh`
caches them on the host (default `~/.local/share/readyhai/cache`, same dir
`readyhai tools pull` uses — visible to plugins as `/cache`); plugins mount the
cache read-only (or read-write with `cache_rw = true` for tools that self-update
their own DBs). Everything here is fetched **from primary upstreams with checksums**;
nothing is redistributed inside ReadyHai images.

| Feed | Upstream | License / redistribution | Cadence | Used by |
|---|---|---|---|---|
| OSV vulnerability DB | osv.dev (pypi/npm/go/etc.) | CC-BY 4.0 / open per-source | daily | osv-scanner, trivy fallback, enrichment |
| GitHub Advisory DB | github.com/github/advisory-database | CC-BY 4.0 | continuous | GHSA mapping, `fetch-feeds.sh vulndata` |
| CISA KEV | cisa.gov (JSON) | US-gov work, free to use | ~daily | known-exploited enrichment (prioritisation) |
| EPSS | first.org `epss_scores.csv` | free; **redistribution for commercial products needs terms — cache locally, don't re-publish** | daily | risk scoring / gate weighting |
| NVD API 2.0 | nvd.nist.gov (rate-limited; free key raises limits) | US-gov | on demand | CVSS enrichment (optional, cache aggressively) |
| Nuclei templates | projectdiscovery/nuclei-templates | MIT (v10 relicensing rumour disproven — still MIT) | weekly | nuclei plugin (`-t` from cache) |
| SecLists | danielmiessi/SecLists | MIT | monthly | feroxbuster/ffuf/gobuster wordlists |
| asset-note wordlists | assetnote.nl wordlists CDN | Apache-2.0, monthly CDN regeneration | monthly | discovery lane |
| PATT (attack patterns) | OWASP attack-patterns | community docs | occasional | docs/LLM-lane hints (documentary) |
| ReadyHai rego pack | this repo `policies/rego/` | AGPL (ours) | per release | conftest plugin |
| Trivy DB / Java DB | trivy-cache (aquasec) | tool-managed | tools self-update | trivy plugins via `cache_rw` (use `--cache-dir /cache`, tmpfs /tmp is too small) |
| nuclei / httpx / subfinder runtime data | tool-managed (wappalyzer etc.) | bundled with each tool | tools self-update | pinned images |

Rules:

1. **Fetch with checksums** — `fetch-feeds.sh` records sha256 per file; a corrupt
   cache entry is re-downloaded, never trusted.
2. **Local-cache-only for non-redistributable data** (EPSS; KEV aggregators): safe
   for in-place enrichment, not for shipping inside bundles. `readyhai bundle export`
   therefore includes tool DBs you point at explicitly, not auto-fetched EPSS.
3. **Air-gap:** every plugin must degrade to *Skipped with reason*, not crash, when
   its feed/DB/network is missing (loader + runner enforce).
4. **Refresh discipline:** run `scripts/fetch-feeds.sh all` weekly (cron) or before
   a deep scan; `doctor` shows feed ages.
