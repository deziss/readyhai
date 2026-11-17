# ReadyHai Development Rules & Governance for AI Agents

## Push Policy (MANDATORY & ABSOLUTE)
- **DO NOT PUSH TO REMOTE**: Never execute `git push` on any service or repository unless the user explicitly asks to push. Changes should only be made and committed locally.

---

## Architectural Guidelines & Modularity Standards
This codebase adheres to the **Codebase Modularizer & Agent Readiness Skill**:
See the full specification and protocol in [`codebase_modularizer_skill.md`](file://[/home/user]/Desktop/learn/readyhai/codebase_modularizer_skill.md).

### 1. Architectural Targets
- **Lines per file**: 100–300 ideal (Warning: 300–500, Critical: 500+)
- **Lines per function**: 5–30 ideal (Warning: 30–50, Critical: 50+)
- **Parameters per function**: 1–4 ideal (Use typed structs / DTOs for 5+)
- **Cyclomatic complexity**: $\le 10$, Nesting depth: $\le 3$
- **Dependencies per module**: 1–5, Dependency depth: 1–3
- **Responsibilities per file**: Exactly 1 primary responsibility
- **Feature Isolation**: Organize code into cohesive, vertical-slice modules so any future feature or bug fix requires inspecting 1–5 files and modifying only 1–3 files.

### 2. Mandatory 4-Phase Refactoring Protocol
When refactoring or splitting large/coupled files, agents MUST follow the 4-Phase Gate Process and obtain user approval between phases:
1. **Phase 1: Analyze (Read-Only)** — Inventory functions, line counts, distinct responsibilities, coupling risks, and calculate baseline Agent Modularity Score (AMS / 100).
2. **Phase 2: Modularization Plan (No Code Changes)** — Blueprint target directory structure, single responsibilities, symbols to move, dependencies, and backward-compatible facades/re-exports.
3. **Phase 3: Incremental Extraction (One Module at a Time)** — Extract single modules, update callers, add isolated unit tests, and confirm zero regressions.
4. **Phase 4: Verify & Document** — Check circular dependencies, create module `<module>/README.md` (<100 lines), run full test suite, and generate updated AI Agent Readiness Report.

---

## Workflow Before Modifying Code
1. Consult relevant module documentation (`README.md`) and architectural targets.
2. Inspect existing public interfaces, function signatures, and dependencies.
3. Run existing tests to verify baseline state.

## Workflow After Modifying Code
1. **Backend Tests**: `cargo test --all-targets`
2. **Backend Linter**: `cargo clippy -- -D warnings`
3. **Frontend Tests**: `PATH="$HOME/.nvm/versions/node/v24.19.0/bin:$PATH" npm --prefix frontend test`
4. **Docker Validation**: `docker compose ps` & verify healthy endpoints.
5. Verify zero unrelated files or modules were altered.

## Restrictions
- Do not rewrite or modify unrelated modules during a localized task.
- Do not alter public interfaces without updating all callers and providing backwards-compatible re-exports.
- Never introduce circular dependencies.
