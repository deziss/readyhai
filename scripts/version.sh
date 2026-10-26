#!/usr/bin/env bash
#
# ReadyHai Single Source of Truth Version Management Script
# Usage:
#   ./scripts/version.sh                  # print current version
#   ./scripts/version.sh get              # print current version
#   ./scripts/version.sh check            # verify consistency across all files
#   ./scripts/version.sh set <version>    # set explicit version (e.g., 0.2.0)
#   ./scripts/version.sh bump <patch|minor|major>
#   ./scripts/version.sh tag              # create annotated git tag for current version
#

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="$ROOT_DIR/VERSION"
CARGO_TOML="$ROOT_DIR/Cargo.toml"
PLAYWRIGHT_PKG="$ROOT_DIR/runners/playwright/package.json"
PLAYWRIGHT_LOCK="$ROOT_DIR/runners/playwright/package-lock.json"

get_version() {
  if [[ ! -f "$VERSION_FILE" ]]; then
    echo "Error: $VERSION_FILE does not exist." >&2
    exit 1
  fi
  tr -d '[:space:]' < "$VERSION_FILE"
}

get_cargo_version() {
  sed -nE 's/^version = "([^"]+)"/\1/p' "$CARGO_TOML" | head -n 1
}

get_playwright_version() {
  if [[ -f "$PLAYWRIGHT_PKG" ]]; then
    sed -nE 's/^[[:space:]]*"version": "([^"]+)",/\1/p' "$PLAYWRIGHT_PKG" | head -n 1
  fi
}

check_version() {
  local root_v cargo_v pw_v ok=0
  root_v="$(get_version)"
  cargo_v="$(get_cargo_version)"
  pw_v="$(get_playwright_version)"

  echo "Checking version consistency across components..."
  echo "  VERSION:                       $root_v"
  echo "  Cargo.toml:                    $cargo_v"
  if [[ -n "$pw_v" ]]; then
    echo "  runners/playwright/package.json: $pw_v"
  fi

  if [[ "$root_v" != "$cargo_v" ]]; then
    echo "❌ Mismatch: VERSION ($root_v) != Cargo.toml ($cargo_v)" >&2
    ok=1
  fi

  if [[ -n "$pw_v" && "$root_v" != "$pw_v" ]]; then
    echo "❌ Mismatch: VERSION ($root_v) != runners/playwright/package.json ($pw_v)" >&2
    ok=1
  fi

  if [[ $ok -eq 0 ]]; then
    echo "✅ All version references are synchronized ($root_v)."
  else
    exit 1
  fi
}

set_version() {
  local new_v="$1"
  if [[ ! "$new_v" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
    echo "Error: Invalid version format: '$new_v'. Expected semver (e.g., 0.1.0 or 1.0.0-rc1)." >&2
    exit 1
  fi

  echo "Setting project version to: $new_v"

  # 1. Update VERSION file (Single Source of Truth)
  printf "%s\n" "$new_v" > "$VERSION_FILE"

  # 2. Update Cargo.toml
  sed -i.bak -E "1,/^version = \"[^\"]+\"/ s/^version = \"[^\"]+\"/version = \"$new_v\"/" "$CARGO_TOML"
  rm -f "${CARGO_TOML}.bak"

  # 3. Update Cargo.lock using cargo check
  echo "Updating Cargo.lock..."
  (cd "$ROOT_DIR" && cargo check --quiet)

  # 4. Update runners/playwright/package.json and lockfile if present
  if [[ -f "$PLAYWRIGHT_PKG" ]]; then
    sed -i.bak -E "1,/\"version\": \"[^\"]+\"/ s/\"version\": \"[^\"]+\"/\"version\": \"$new_v\"/" "$PLAYWRIGHT_PKG"
    rm -f "${PLAYWRIGHT_PKG}.bak"
  fi
  if [[ -f "$PLAYWRIGHT_LOCK" ]]; then
    sed -i.bak -E "s/\"version\": \"[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?\"/\"version\": \"$new_v\"/g" "$PLAYWRIGHT_LOCK"
    rm -f "${PLAYWRIGHT_LOCK}.bak"
  fi

  check_version
}

bump_version() {
  local kind="${1:-patch}"
  local current
  current="$(get_version)"

  local major minor patch
  IFS='.' read -r major minor patch <<< "${current%%-*}"

  case "$kind" in
    major)
      major=$((major + 1))
      minor=0
      patch=0
      ;;
    minor)
      minor=$((minor + 1))
      patch=0
      ;;
    patch)
      patch=$((patch + 1))
      ;;
    *)
      echo "Error: unknown bump type '$kind'. Use major, minor, or patch." >&2
      exit 1
      ;;
  esac

  local next="${major}.${minor}.${patch}"
  echo "Bumping $kind: $current -> $next"
  set_version "$next"
}

create_tag() {
  local v tag
  v="$(get_version)"
  tag="v$v"

  # Verify git working tree
  if ! git diff-index --quiet HEAD --; then
    echo "Warning: Uncommitted changes detected. Commit your changes before tagging." >&2
  fi

  if git rev-parse "$tag" >/dev/null 2>&1; then
    echo "Tag $tag already exists."
    exit 0
  fi

  echo "Creating annotated git tag: $tag"
  git tag -a "$tag" -m "Release $tag: Production-readiness gate & QA tester"
  echo "✅ Tag $tag successfully created locally."
  echo "To push to GitHub when ready: git push origin $tag"
}

# Main CLI routing
CMD="${1:-get}"
case "$CMD" in
  get)
    get_version
    ;;
  check)
    check_version
    ;;
  set)
    if [[ -z "${2:-}" ]]; then
      echo "Usage: $0 set <version>" >&2
      exit 1
    fi
    set_version "$2"
    ;;
  bump)
    bump_version "${2:-patch}"
    ;;
  tag)
    create_tag
    ;;
  *)
    echo "Unknown command: $CMD" >&2
    echo "Usage: $0 [get|check|set <version>|bump <major|minor|patch>|tag]" >&2
    exit 1
    ;;
esac
