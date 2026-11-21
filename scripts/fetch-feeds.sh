#!/usr/bin/env bash
# ReadyHai feed/data-source fetcher (runs on the scanning HOST, not in a sandbox).
# Everything here is redistribution-safe OSS/US-gov data (see docs/data-sources.md
# for licenses). Files land under ReadyHai's tool cache so plugins see them at
# /cache. Idempotent: skips files whose sha256 matches a previous fetch.
#
#   scripts/fetch-feeds.sh            # core: wordlists + KEV + EPSS + nuclei templates
#   scripts/fetch-feeds.sh recon      # wordlists for ferox/ffuf/katana pipelines
#   scripts/fetch-feeds.sh vulndata   # CISA KEV, FIRST EPSS, GHSA clone
#   scripts/fetch-feeds.sh llm        # garak/promptfoo corpora (optional)
#   scripts/fetch-feeds.sh rego       # ReadyHai rego policy pack for conftest
#
# The cache dir resolves like the binary does: $READYHAI_DATA_DIR/cache, else
# ~/.local/share/readyhai/cache (Linux), ~/Library/Application Support/readyhai/cache (macOS).
set -euo pipefail

data_dir="${READYHAI_DATA_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/readyhai}"
[ -d "$data_dir" ] || { echo "data dir $data_dir absent; run 'readyhai doctor' first or set READYHAI_DATA_DIR" >&2; exit 1; }
cache="$data_dir/cache"
fail=0
fetch() { # fetch <dest-rel> <url> [--unzip] [--raw]
  local dest="$cache/$1" url="$2" mode="${3:-}" tmp
  mkdir -p "$(dirname "$dest")"
  tmp="$(mktemp)"
  echo "→ $1"
  if ! curl -fsSL --retry 2 --connect-timeout 20 -o "$tmp" "$url"; then echo "  FETCH FAILED $url" >&2; rm -f "$tmp"; fail=1; return; fi
  if [ "$mode" = "--unzip" ]; then
    local marker="$dest/.sha256"; sum; sum=$(sha256sum "$tmp" | cut -d' ' -f1)
    if [ -f "$marker" ] && [ "$(cat "$marker")" = "$sum" ]; then echo "  up to date"; rm -f "$tmp"; return; fi
    rm -rf "$dest"; mkdir -p "$dest"; unzip -qo "$tmp" -d "$dest"; echo "$sum" > "$marker"
  else
    if [ -f "$dest" ] && cmp -s "$tmp" "$dest"; then echo "  up to date"; rm -f "$tmp"; return; fi
    mv "$tmp" "$dest"; echo "  saved $(du -h "$dest" | cut -f1)"
    return
  fi
  rm -f "$tmp"
}
clone() { # clone <dest-rel> <url> [depth]
  local dest="$cache/$1" url="$2" depth="${3:-1}"
  if [ -d "$dest/.git" ]; then echo "↻ $1 (pull)"; git -C "$dest" fetch -q --depth "$depth" origin && git -C "$dest" reset -q --hard FETCH_HEAD || { echo "  PULL FAILED" >&2; fail=1; }; return; fi
  echo "→ $1 (clone)"; git clone -q --depth "$depth" "$url" "$dest"
}

case "${1:-recon}" in
recon)
  # SecLists (MIT): discovery/fuzzing content. Full zip (~250 MB) then prune.
  fetch wordlists/seclists.zip "https://github.com/danielmiessler/SecLists/archive/refs/heads/master.zip" --unzip
  secl="$cache/wordlists/seclists"; root="$secl/SecLists-master"
  [ -d "$secl/Discovery" ] || mv "$root" "$secl" 2>/dev/null || true
  # assetnote (Apache-2.0): regenerable monthly DNS/content wordlists.
  fetch wordlists/assetnote-apis.txt "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt" || true
  # smaller curated sets for CI plugins
  fetch wordlists/10k.txt "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" || true
  fetch wordlists/directory-list-2.3-medium.txt "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt" || true
  # nuclei templates (MIT) for nuclei template packs beyond the auto-updated builtin
  clone nuclei-templates https://github.com/projectdiscovery/nuclei-templates.git 1 || true
  ;;
vulndata)
  # CISA KEV (US-gov, no copyright): known-exploited list for gate weighting.
  fetch kev/known-exploited.json "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" || true
  # FIRST EPSS (free for internal use; DO NOT redistribute raw — cache locally,
  # see docs/data-sources.md license note).
  fetch epss/all-scores.json.bz2 "https://epss.first.org/epss/all-scores.json.bz2" || true
  # GitHub Advisory DB (MIT + CC-BY for some fields) — GHSA ids for enrichment.
  clone ghsa https://github.com/github/advisory-database.git 1 || true
  ;;
llm)
  # PayloadsAllTheThings (MIT): prompt-injection / LLM red-team payloads for eval-ai.
  clone payloads-all-the-things https://github.com/swisskyrepo/PayloadsAllTheThings.git 1 || true
  ;;
rego)
  # ReadyHai-authored conftest policy pack (this repo ships policies/rego).
  src="$(cd "$(dirname "$0")/.." && pwd)/policies/rego"
  if [ -d "$src" ]; then mkdir -p "$cache/rego"; cp -R "$src/." "$cache/rego/"; echo "→ rego pack copied"; else echo "reg: no policies/rego in $(pwd)" >&2; fail=1; fi
  ;;
all)
  "$0" recon; "$0" vulndata; "$0" llm; "$0" rego
  ;;
*) echo "usage: $0 [recon|vulndata|llm|rego|all]" >&2; exit 2;;
esac

if [ "$fail" != 0 ]; then
  echo "WARNING: some feeds failed; plugins depending on them will report missing data." >&2
  exit 3
fi
echo "done. cache: $(du -sh "$cache" | cut -f1) at $cache"
