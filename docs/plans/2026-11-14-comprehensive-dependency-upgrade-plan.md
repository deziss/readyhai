# Comprehensive Dependency Upgrade Plan (Rust, TypeScript, Python, Containers)

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Systematically audit, modernize, and upgrade all library versions across Rust (`Cargo.toml`), Frontend TypeScript/React/Next.js (`frontend/package.json`), Playwright runner (`runners/playwright/`), Python context retriever (`runners/context_retriever/`), and container base images (`tools.lock.toml`, `Dockerfile`), ensuring zero regressions in the 813 Rust tests and 141 frontend tests.

**Architecture:** 6-phase staged upgrade pipeline. Low-risk in-range and patch updates are executed first, followed by frontend toolchain updates, runner subsystem upgrades, Rust breaking-change adaptations (handled crate-by-crate with compiler validation), container tool re-pinning, and end-to-end release verification.

**Tech Stack:**
- **Rust Backend:** Cargo, Edition 2024, Rust 1.98+, MiniJinja 3, Sha2 0.11, Rand 0.10, Reqwest 0.13
- **Frontend:** Next.js 16.4.6, React 19.3.1, TypeScript 7.0.2, Tailwind CSS 4.3.5, Vitest 5.1.0, Undici 8.12.4
- **Runners:** Playwright 1.65.1, Axe-core 4.14.0, Python 3.11, LangChain 0.3.19, Pydantic 2.10.6
- **Containers:** Docker multi-stage OCI, Node 24 (`node:24-slim`), Playwright `v1.65.1-noble`

---

## Dependency Matrix & Target Versions

| Ecosystem | Component / Package | Current Before | Target Achieved | Status |
|---|---|---|---|---|
| **Rust In-Range** | 27 transitive crates (`toml`, `cc`, `rustls-pki-types`, `globset`, `syn`) | Existing lock | Latest semver | **Completed** |
| **Rust Minor** | `tree-sitter-typescript` | `0.23.2` | `0.23.2` (crates.io latest) | **Completed** (audited) |
| **Rust Major** | `minijinja` | `2.24.0` | `3.1.0` | **Completed** (`minijinja::value::Serde`) |
| **Rust Major** | `sha2` | `0.10.9` | `0.11.1` | **Completed** |
| **Rust Major** | `rand` | `0.9.5` | `0.10.3` | **Completed** (`rand::RngExt`) |
| **Rust Major** | `reqwest` | `0.12.28` | `0.13.5` | **Completed** (`features = ["blocking", "rustls", "json"]`) |
| **Frontend Deps** | `next` | `16.4.3` | `16.4.6` | **Completed** |
| **Frontend Deps** | `react` & `react-dom` | `19.3.0` | `19.3.1` | **Completed** |
| **Frontend Deps** | `lucide-react` | `1.62.0` | `1.73.0` | **Completed** |
| **Frontend Deps** | `undici` | `7.30.2` | `8.12.4` | **Completed** |
| **Frontend Dev** | `tailwindcss` & `@tailwindcss/*` | `4.3.3` | `4.3.5` | **Completed** |
| **Frontend Dev** | `vitest` | `5.0.5` | `5.1.0` | **Completed** |
| **Frontend Dev** | `typescript` | `5.9.3` | `7.0.2` | **Completed** (user directive verified) |
| **Frontend Dev** | `eslint-config-next` | `16.4.3` | `16.4.6` | **Completed** |
| **Playwright Runner** | `playwright` | `1.56.0` | `1.65.1` | **Completed** |
| **Playwright Runner** | `axe-core` | `4.10.2` | `4.14.0` | **Completed** |
| **Playwright Runner** | `pixelmatch` | `7.1.0` | `8.0.0` | **Completed** |
| **Python Retriever** | `langchain`, `langgraph` | `0.3.0` / `0.2.20` | `0.3.19` / `0.2.74` | **Completed** |
| **Python Retriever** | `pydantic` | `2.7.0` | `2.10.6` | **Completed** |
| **Container Base** | `node` (in `frontend/Dockerfile`) | `20-slim` | `24-slim` | **Completed** (user directive verified) |
| **Container Base** | `playwright-runner` Dockerfile | `v1.56.0-noble` | `v1.65.1-noble` | **Completed** (multi-arch digest pinned) |

---

## Staged Implementation Tasks

### Phase 1: In-Range & Safe Dependency Modernization (Zero Risk)

- [x] **Task 1.1: Rust In-Range Lockfile Update**
  - Run `cargo update` to advance all 27 compatible in-range crates (e.g. `toml`, `cc`, `rustls-pki-types`, `globset`, `syn`).
  - Verify compilation: `cargo check`.
  - Run binary tests: `cargo test --bin readyhai`.
  - Zero warnings and zero test failures.

- [x] **Task 1.2: Frontend Patch & Safe Dependency Updates**
  - In `frontend/package.json`:
    - Bumped `next` to `16.4.6`, `eslint-config-next` to `16.4.6`.
    - Bumped `react` and `react-dom` to `19.3.1`.
    - Bumped `tailwindcss`, `@tailwindcss/postcss`, and `@tailwindcss/turbopack` to `4.3.5`.
    - Bumped `vitest` to `5.1.0` and `@vitejs/plugin-react` to `6.3.0`.
    - Bumped `lucide-react` to `1.73.0`.
    - Bumped `undici` to `8.12.4`.
    - Upgraded `typescript` to `7.0.2` (per user directive).
  - Ran `npm install` in `frontend/` to regenerate `package-lock.json`.
  - Ran tests: `npm test` (all 141 tests passed).
  - Ran typecheck: `npx tsc --noEmit` (clean 0 errors).
  - Ran Next.js production build: `npm run build` (Turbopack + TS 7.0.2 compiled cleanly).

---

### Phase 2: Runners Subsystem Upgrades (Playwright & Python)

- [x] **Task 2.1: Playwright QA & Browser Security Runner Modernization**
  - In `runners/playwright/package.json`:
    - Bumped `playwright` from `1.56.0` to `1.65.1`.
    - Bumped `axe-core` from `4.10.2` to `4.14.0`.
    - Bumped `pixelmatch` from `7.1.0` to `8.0.0`.
  - Ran `npm install` in `runners/playwright/`.
  - Updated base image in `runners/playwright/Dockerfile` to `mcr.microsoft.com/playwright:v1.65.1-noble@sha256:1507cbfc550a63a6b7396791ca4f00df17beb56342d2447b3f106c306f525579`.
  - Built local image `readyhai/playwright-runner:local`.
  - Validated DOM XSS parser and report generator: `cargo test --bin readyhai agent::browser_sec::tests` (all passed).

- [x] **Task 2.2: Python AST & Vector Context Retriever Modernization**
  - In `runners/context_retriever/requirements.txt`:
    - Updated `langchain` suite to `0.3.19` (`langchain-core==0.3.35`, `langchain-community==0.3.18`, `langchain-openai==0.3.6`, `langchain-ollama==0.2.3`, `langchain-huggingface==0.1.2`).
    - Updated `langgraph` to `0.2.74`.
    - Updated `pydantic` to `2.10.6`.
    - Updated `sentence-transformers` to `3.4.1` and `faiss-cpu` to `1.10.0`.

---

### Phase 3: Rust Grammar & Minor Crate Alignment

- [x] **Task 3.1: Tree-Sitter Grammar Crates Alignment**
  - Audited crates.io for `tree-sitter-typescript`: version `0.23.2` is verified as the highest released version.
  - Parsers compile cleanly with `tree-sitter 0.25.10`.
  - Verified with `cargo test --bin readyhai supply::tests`.

---

### Phase 4: Rust Major Upgrades Migration & API Adaptations (High-Impact)

- [x] **Task 4.1: Upgrade `minijinja` (v2 -> v3)**
  - Bumped `minijinja = { version = "3", features = ["serde"] }` in `Cargo.toml`.
  - Adapted context serialization using `minijinja::value::Serde` across `src/dashboard.rs`, `src/report.rs`, and `src/qa/report.rs`.
  - Ran `cargo test --bin readyhai report::tests`, `qa::report::tests`, and `dashboard::tests` (all passed).

- [x] **Task 4.2: Upgrade `sha2` (v0.10 -> v0.11)**
  - Bumped `sha2 = "0.11"` in `Cargo.toml`.
  - Trait compatibility with `digest 0.11` verified across `src/model.rs`, `src/serve.rs`, and `src/bundle.rs`.
  - Ran `cargo test --bin readyhai serve::tests::token_policy` and `bundle::tests` (all passed).

- [x] **Task 4.3: Upgrade `rand` (v0.9 -> v0.10)**
  - Bumped `rand = "0.10"` in `Cargo.toml`.
  - Migrated trait import to `rand::RngExt` in `src/engine.rs`, `src/android.rs`, and `src/agent/oast.rs`.
  - Ran `cargo test --bin readyhai agent::discover::soft404::tests` and `agent::oast::tests` (all passed).

- [x] **Task 4.4: Upgrade `reqwest` (v0.12 -> v0.13)**
  - Bumped `reqwest = { version = "0.13", default-features = false, features = ["blocking", "rustls", "json"] }`.
  - Compiles and links with `aws-lc-rs` and `rustls 0.23.46`.
  - Ran `cargo test --bin readyhai llm::tests` (49 tests) and `agent::exec::tests` (10 tests) (all passed).
  - Ran full test suite: `cargo test --bin readyhai` (813 passed, 0 failed).

---

### Phase 5: Container Base & Security Scanner Re-Pinning

- [x] **Task 5.1: Upgrade Frontend Container Node Base to Active LTS (Node 24)**
  - In `frontend/Dockerfile`:
    - Updated `FROM node:24-slim AS deps`.
    - Updated `FROM node:24-slim AS builder`.
    - Updated `FROM node:24-slim AS runner`.
  - Successfully built and verified standalone Next.js 16.4 production server inside Node 24 container.

- [x] **Task 5.2: Refresh Pinned Security Scanners (`tools.lock.toml`)**
  - Updated `tools.playwright` to version `1.65.1`.
  - Ran `cargo test --bin readyhai tools::tests` (25 tests passed).

---

### Phase 6: End-to-End Validation & Release

- [x] **Task 6.1: Run Full Test Suites Across All Stacks**
  - Ran `cargo test --bin readyhai` (all 813 Rust tests passed).
  - Ran `npm test` in `frontend/` (all 141 Vitest tests passed).
  - Ran `npm run build` in `frontend/` (Next.js + TypeScript 7 build passed).

- [x] **Task 6.2: Docker Multi-Container Build & Live Smoke Test**
  - Built containers: `docker compose build` (both images built cleanly).
  - Started containers: `docker compose up -d`.
  - Verified live endpoints:
    - Backend: `curl -fsSL http://localhost:8080/health` -> `{"status":"ok","version":"0.8.1"}`
    - Frontend: `curl -I http://localhost:3000` -> `HTTP/1.1 200 OK`
    - Container Health: `readyhai` (healthy), `readyhai-frontend` (healthy), `readyhai-socket-proxy` (healthy).
