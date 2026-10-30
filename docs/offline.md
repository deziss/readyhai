# Offline and LAN-LLM modes

Increment 2 (2026-10-25). Two independent modes; they can be combined only partly (see the caveat under READYHAI_OFFLINE).

| Mode | Network at scan time | AI | How to get there |
|---|---|---|---|
| Air-gapped (`offline`) | none; tool containers already run with network none, pulls and DB updates hard-fail | none (deterministic engine) | `bundle export` on a connected machine, `bundle import` on the target, `READYHAI_OFFLINE=1` |
| LAN LLM (`lan-llm`) | LAN only, to your vLLM/Ollama endpoint | single-shot advisory prose, triage hints, test ideas | set `READYHAI_VLLM_URL` (or `READYHAI_LLM_PROVIDER`) |
| `deterministic` | whatever you allow | none | default when no LLM is configured/reachable |

`readyhai doctor` prints the current mode.

## Bundle export (connected machine)

```bash
readyhai bundle export --set core --out readyhai-bundle.tar [--with-model model.gguf]
READYHAI_BUNDLE_TOOLS=grype,syft,gitleaks readyhai bundle export   # restrict to a comma-separated tool list
```

Refuses to run when `READYHAI_OFFLINE=1`. Needs Docker. Five steps: pull images and record image IDs into a lock; update vuln DB, semgrep rules, lynis; fetch the endoflife snapshot (falls back to the one embedded in the binary); `docker save` each image; assemble and hash.

| Content | Notes |
|---|---|
| `bin/readyhai` | the running binary |
| `tools.lock.toml` | resolved lock with image IDs |
| `images/<tool>.tar` | `docker save` of each pinned tool image; an image not present locally is skipped with a message |
| `cache/` | grype DB, semgrep rules, lynis tarball, endoflife snapshot |
| `model/<file>` | only with `--with-model` (GGUF copied as is) |
| `manifest.json` | version, created, set, sha256 + size of every file, image tool/ref/ID |

| Set | Tools | Size |
|---|---|---|
| `core` | all lock tools except `zap` and `mobsf` | 3.6 GB measured with grype, syft and gitleaks only (grype DB is about 3.3 GB of that) |
| `full` | every tool in the lock | about 8-9 GB (estimate from image sizes; not measured end to end) |

The manifest is not signed (cosign signing from the plan is not implemented). `playwright` is a locally built image: if you have not built `readyhai/playwright-runner:local`, it is skipped in the bundle, and so UI and PDF are unavailable offline. `postgres` (used for migration checks) is not a lock tool and is not bundled.

## Bundle import (air-gapped machine)

```bash
readyhai bundle import readyhai-bundle.tar
```

1. Extracts with system `tar` (`--no-same-owner`); `check_tar_safe` rejects absolute paths, `..` components and link entries.
2. Verifies every manifest entry's sha256 and size; a missing file, a mismatch or a path that escapes the bundle fails the import.
3. `docker load` per image, then checks the loaded image ID equals the manifest ID.
4. Writes `tools.lock.toml` into the data dir, copies `cache/` to `<data>/cache`, makes it world-readable (tool containers run as nobody), prints the DB age.

Why IDs: an image pinned as `repo@sha256:digest` does not resolve after `docker load` (no repo digest), so the lock records the image ID and the runner runs the image by ID.

## Lock precedence and run-by-ID

`READYHAI_TOOLS_LOCK` (file) > `<data>/tools.lock.toml` (installed by import) > lock embedded in the binary. An entry with a local image ID runs that ID with no pull; with `READYHAI_OFFLINE=1` every run is no-pull. A tool whose image is absent is `Skipped` ("not in bundle"), not an error.

## READYHAI_OFFLINE=1

- `bundle export`, `tools pull`/`tools update` and registry pulls fail hard.
- Grype runs with DB auto-update off; ReadyHai checks DB age itself: more than 7 days old makes the scan Partial, more than 30 days is flagged stale.
- `doctor` reports mode `offline`.
- **Offline + LAN LLM together:** `READYHAI_OFFLINE=1` blocks internet and registry access, but the LAN LLM is still probed and used. The report mode reads `offline+lan-llm`. Cloud providers stay refused unless `READYHAI_LLM_ALLOW_CLOUD` is set.
- Data dir: `READYHAI_DATA`.

## `readyhai doctor`

Prints: version, mode, LLM probe result (2 s timeout on `<base>/models`), data dir, Docker server version, one line per tool (`present`, `pinned`, 12-char image ID, image ref; `!` marks missing), grype DB age (`! > 30 stale`, `! > 7 Partial`, `! missing`), semgrep rules, lynis, endoflife snapshot date (or "embedded"), free disk (warns under 5 GB). Always exits 0.

## endoflife snapshot

`data/endoflife.json` is embedded in the binary; a cached copy in `<data>/cache/endoflife.json` (from `bundle import` or `tools update`) takes precedence. Products: python, nodejs, go, postgresql, ubuntu, debian, alpine, php, ruby, dotnet. Used by `qa.release.eol_runtime`.

## LAN LLM mode

| Setting | Value |
|---|---|
| `READYHAI_VLLM_URL` | OpenAI-compatible base, e.g. `http://vllm.lan:8000/v1`; setting it alone selects the `vllm` provider |
| `READYHAI_LLM_PROVIDER` | `vllm`, `ollama` (default `http://localhost:11434/v1`), or cloud providers `openai`, `anthropic`, `openrouter` |
| `READYHAI_LLM_MODEL` | default `Qwen/Qwen3-8B` for vllm (`qwen2.5-coder` for ollama) |
| `READYHAI_LLM_ALLOW_CLOUD` | `1`/`true` required for any cloud provider; otherwise the config is refused |

At the end of a `qa` run the endpoint is probed (GET `<base>/models`, 2 s). Unreachable: the run proceeds deterministically and the report carries the note "LLM configured but unreachable (2s probe): report is deterministic-only".

**What the AI does** (`src/qa/ai.rs`; each call is single shot, strict JSON, validated and length-capped, invalid output dropped; `<think>` blocks stripped):

| Use | Output |
|---|---|
| Executive summary prose (<= 900 chars) | `ai_summary`, shown as marked AI text |
| Per-defect note for the top 10 (impact, likely cause, <= 300 chars each) | `ai_note` |
| Triage hints: duplicate groups, shared root causes | report notes, "AI suggestion" |
| Test ideas for up to 30 operations | report notes ("AI-proposed test") |

**In `readyhai qa`:** The AI functions as an advisory enricher and does NOT change deterministic verdicts, suppress findings, or execute arbitrary tools.
**In `readyhai agent` (Increment 3):** An autonomous multi-agent pipeline (`Planner`, `Explorer`, `Triager`, `ReadinessGate`) synthesizes, executes, and triages test cases, computing an objective 4-pillar Evidence Ledger.

**Guardrails:** `redact_for_llm` on every input; target text is control-char-stripped, fence-neutralised and fenced as data; budget of 20 calls and 300 s per run; responses cached by sha256(model, system, prompt) under `<data>/llm-cache`, so reruns are reproducible and cache hits are free.

Status: Live-verified with local vLLM serving Qwen3 reasoning models (`qwen3.8-flash-next`). The autonomous agent loop in `src/agent/` handles reasoning token streams (`reasoning_content`), synthesizes adversarial test suites, executes probes, clusters defects, and calculates the 4-pillar Evidence Ledger with sub-second latencies.

## Fully air-gapped AI

`--with-model` carries a GGUF in the bundle and import prints its path, but nothing in ReadyHai serves it; an Ollama/llama.cpp image in the `full` set is not implemented. Treat it as a transport for a model you serve yourself.
