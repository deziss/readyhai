#!/usr/bin/env bash
# ReadyHai single-binary installer for Linux and macOS
set -euo pipefail

BOLD="$(tput bold 2>/dev/null || echo '')"
GREEN="$(tput setaf 2 2>/dev/null || echo '')"
YELLOW="$(tput setaf 3 2>/dev/null || echo '')"
RESET="$(tput sgr0 2>/dev/null || echo '')"

echo "${BOLD}ReadyHai Single-Binary Installer${RESET}"

INSTALL_DIR="${HOME}/.local/bin"
mkdir -p "${INSTALL_DIR}"

CONFIG_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/readyhai"
mkdir -p "${CONFIG_DIR}"

DATA_DIR="${XDG_DATA_HOME:-${HOME}/.local/share}/readyhai"
mkdir -p "${DATA_DIR}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_PATH="${INSTALL_DIR}/readyhai"

if [ -f "${SCRIPT_DIR}/target/release/readyhai" ]; then
    echo "Installing locally built binary from target/release/readyhai..."
    cp -f "${SCRIPT_DIR}/target/release/readyhai" "${BIN_PATH}"
    chmod +x "${BIN_PATH}"
else
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"
    if [ "${ARCH}" = "x86_64" ]; then
        TARGET="x86_64-unknown-linux-musl"
    elif [ "${ARCH}" = "aarch64" ] || [ "${ARCH}" = "arm64" ]; then
        TARGET="aarch64-unknown-linux-musl"
    else
        echo "${YELLOW}Warning: Unknown architecture ${ARCH}, falling back to cargo build${RESET}"
        cargo build --release
        cp -f target/release/readyhai "${BIN_PATH}"
    fi

    if [ ! -f "${BIN_PATH}" ]; then
        echo "Fetching release binary..."
        # If GitHub release artifact URL is available, download it:
        # curl -fsSL "https://github.com/deziss/readyhai/releases/latest/download/readyhai-${TARGET}.tar.gz" | tar -xz -C "${INSTALL_DIR}"
        # For local clone build fallback:
        if command -v cargo >/dev/null 2>&1; then
            echo "Building readyhai from local source..."
            cargo build --release
            cp -f target/release/readyhai "${BIN_PATH}"
            chmod +x "${BIN_PATH}"
        fi
    fi
fi

# Configure default scope.toml if missing
if [ ! -f "${CONFIG_DIR}/scope.toml" ]; then
    if [ -f "${SCRIPT_DIR}/scope.example.toml" ]; then
        cp "${SCRIPT_DIR}/scope.example.toml" "${CONFIG_DIR}/scope.toml"
        echo "${GREEN}Created default scope configuration:${RESET} ${CONFIG_DIR}/scope.toml"
    fi
fi

# Configure default .env if missing
if [ ! -f "${CONFIG_DIR}/.env" ]; then
    TOKEN="$(openssl rand -hex 24 2>/dev/null || head -c 24 /dev/urandom | xxd -p || echo "readyhai_secret_token_$(date +%s)")"
    cat > "${CONFIG_DIR}/.env" <<EOF
# ReadyHai Standalone Configuration
READYHAI_TOKEN=${TOKEN}
READYHAI_DATA=${DATA_DIR}
READYHAI_SCOPE=${CONFIG_DIR}/scope.toml
READYHAI_PORT=8080
EOF
    echo "${GREEN}Generated default environment configuration:${RESET} ${CONFIG_DIR}/.env"
fi

# PATH check
case ":${PATH}:" in
    *:"${INSTALL_DIR}":*) ;;
    *)
        echo "${YELLOW}Notice: ${INSTALL_DIR} is not currently in your PATH.${RESET}"
        echo "Add it with: export PATH=\"\${HOME}/.local/bin:\${PATH}\""
        ;;
esac

echo "${GREEN}Installation successful!${RESET}"
echo "Run '${BOLD}readyhai --help${RESET}' or '${BOLD}readyhai doctor${RESET}' to get started."
