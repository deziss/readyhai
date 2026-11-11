#!/usr/bin/env bash
# Opt-in local benchmark harness against real OWASP training apps (Juice Shop / VAmPI / crAPI)
# or ReadyHai's deterministic `security-deep` + `whitebox-exploit` eval suites.
# NOT invoked by default CI/unit tests.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/bench_owasp.sh [--suite | --target URL] [--profile deep|standard] [--out DIR]

Modes:
  --suite           Run deterministic eval suites (`security-deep`, `whitebox-exploit`) locally.
  --target URL      Run ReadyHai autonomous agent against an explicitly launched local nonprod
                    OWASP benchmark (e.g. OWASP Juice Shop at http://127.0.0.1:3000 or VAmPI at
                    http://127.0.0.1:5000). Requires READYHAI_ALLOW_NONPROD=1.

Optional environment variables:
  READYHAI_ALLOW_NONPROD=1   Required when using --target for active nonprod write/XSS probes.
  READYHAI_USER_TOKEN=...    Optional user JWT/bearer token for authenticated scanning.
  READYHAI_ADMIN_TOKEN=...   Optional admin JWT/bearer token for BFLA differential checks.
  READYHAI_VERIFY_K=2        Replay k times on FAIL (default: 2).
  SPEC_URL=...               Optional OpenAPI spec URL (`--spec`).
  SCOPE_FILE=...             Optional scope TOML path (`--scope`, else READYHAI_SCOPE).
  REPO_PATH=/path/to/src     Optional source repo path for white-box AST + change analysis.
  DIFF_BASE=HEAD             Git diff base for `--diff-base` when REPO_PATH is set (default: HEAD).
EOF
}

MODE=""
TARGET_URL=""
PROFILE="deep"
OUT_DIR="${TMPDIR:-/tmp}/readyhai-owasp-bench"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --suite) MODE="suite"; shift ;;
    --target) MODE="target"; TARGET_URL="${2:-}"; shift 2 ;;
    --profile) PROFILE="${2:-deep}"; shift 2 ;;
    --out) OUT_DIR="${2:-$OUT_DIR}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$MODE" ]]; then
  MODE="suite"
fi

mkdir -p "$OUT_DIR"

if [[ "$MODE" == "suite" ]]; then
  echo "[bench_owasp] Running deterministic security-deep + whitebox-exploit eval suites -> $OUT_DIR"
  cargo run --quiet -- eval --suite security-deep --k 2 --out "$OUT_DIR/security-deep"
  cargo run --quiet -- eval --suite whitebox-exploit --k 2 --out "$OUT_DIR/whitebox-exploit"
  echo "[bench_owasp] Completed. Reports written under $OUT_DIR"
  exit 0
fi

if [[ -z "$TARGET_URL" ]]; then
  echo "ERROR: --target requires a URL (e.g. http://127.0.0.1:3000)" >&2
  exit 2
fi

if [[ "${READYHAI_ALLOW_NONPROD:-0}" != "1" ]]; then
  echo "Refusing active security benchmark without READYHAI_ALLOW_NONPROD=1 (safety policy)." >&2
  exit 2
fi

MAX_STEPS="50"
if [[ "$PROFILE" == "standard" ]]; then
  MAX_STEPS="20"
fi
export READYHAI_VERIFY_K="${READYHAI_VERIFY_K:-2}"

ARGS=(agent "$TARGET_URL" --max-steps "$MAX_STEPS")
if [[ -n "${SPEC_URL:-}" ]]; then
  ARGS+=(--spec "$SPEC_URL")
fi
if [[ -n "${SCOPE_FILE:-}" ]]; then
  ARGS+=(--scope "$SCOPE_FILE")
fi
if [[ -n "${REPO_PATH:-}" ]]; then
  ARGS+=(--repo "$REPO_PATH" --diff-base "${DIFF_BASE:-HEAD}")
fi

echo "[bench_owasp] Launching ReadyHai agent (profile=$PROFILE, max_steps=$MAX_STEPS) against $TARGET_URL -> $OUT_DIR/live-agent.log"
cargo run --quiet -- "${ARGS[@]}" | tee "$OUT_DIR/live-agent.log"

