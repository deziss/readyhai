---
name: codebase-modularizer
description: Analyze, score, and incrementally refactor large code files (500–1,000+ lines) into cohesive, low-coupling, AI-agent-friendly modules. Use when splitting monolith files, calculating the Agent Modularity Score (AMS), auditing codebase readiness for LLMs, or generating module README.md and AGENTS.md files.
license: MIT
compatibility: Designed for Claude Code, Cursor, Codex, and CLI coding agents with filesystem and test-runner access.
allowed-tools: Read Glob Grep Bash(git:*) Bash(pytest:*) Bash(ruff:*) Bash(radon:*) Bash(npx:*)
metadata:
  version: "1.0.0"
  category: architecture-refactoring
---

# Codebase Modularizer & Agent Readiness Skill

## Purpose

Your primary objective is **Agent Task Isolation**: structuring the codebase so an AI coding agent can understand, modify, and test a single feature or bug fix within 1–3 files without loading the entire repository into its context window or causing unrelated regressions.

---

## 1. Target Metrics & Thresholds

Evaluate files and modules against these engineering guidelines before and after refactoring:

| Metric | Ideal Target | Warning | Critical (Refactor Required) |
| :--- | :--- | :--- | :--- |
| **Lines per file** | $100\text{--}300$ | $300\text{--}500$ | $500+$ |
| **Lines per function** | $5\text{--}30$ | $30\text{--}50$ | $50+$ |
| **Functions per file** | $3\text{--}10$ | $10\text{--}15$ | $20+$ |
| **Classes per file** | $1\text{--}3$ | $4\text{--}5$ | $6+$ |
| **Parameters per function** | $1\text{--}4$ | $5\text{--}6$ | $7+$ |
| **Nesting depth** | $1\text{--}3$ | $4$ | $5+$ |
| **Cyclomatic complexity** | $1\text{--}10$ | $11\text{--}15$ | $16+$ |
| **Dependencies per module** | $1\text{--}5$ | $6\text{--}10$ | $10+$ |
| **Dependency depth** | $1\text{--}3$ | $4\text{--}5$ | $6+$ |
| **Change blast radius (files)** | $1\text{--}3$ modified | $4\text{--}5$ modified | $6+$ or unrelated files |

*Note: Treat these as contextual engineering guidelines. A 400-line declarative configuration or schema file may be acceptable, whereas a 150-line file mixing database queries, HTTP routing, and email dispatch must be split.*

---

## 2. Agent Modularity Score (AMS) Rubric ($100\text{ Points}$)

When auditing a file, module, or repository, calculate the **Agent Modularity Score (AMS)**:

1. **File Size Management ($10\text{ pts}$)**: $\ge 85\%$ of code files are under $300\text{ lines}$; zero business-logic files exceed $500\text{ lines}$.
2. **Single Responsibility ($15\text{ pts}$)**: Each file performs exactly one clear job (e.g., controller, service, repository, validator, or model).
3. **High Cohesion ($15\text{ pts}$)**: All functions and classes inside a module belong to the same domain slice.
4. **Low Coupling ($15\text{ pts}$)**: Modules communicate via narrow public interfaces and depend on $\le 5$ other modules.
5. **Low Complexity ($10\text{ pts}$)**: Functions remain under $30\text{ lines}$ with cyclomatic complexity $\le 10$ and nesting depth $\le 3$.
6. **Test Isolation ($15\text{ pts}$)**: Modules can be unit-tested independently without spinning up unrelated services; test coverage $\ge 80\%$.
7. **Agent Documentation ($10\text{ pts}$)**: Root `AGENTS.md` exists and every feature module contains a concise `README.md` (< $150\text{ lines}$).
8. **Dependency Clarity ($10\text{ pts}$)**: Zero circular dependencies; dependency depth is $1\text{--}3$ hops.

### Score Classification
* **$90\text{--}100$**: Excellent for AI agents
* **$80\text{--}89$**: Very good
* **$70\text{--}79$**: Good
* **$60\text{--}69$**: Needs improvement
* **$40\text{--}59$**: Difficult for agents
* **$0\text{--}39$**: Poorly modularized

---

## 3. Mandatory 4-Phase Refactoring Protocol

**CRITICAL RULE**: Never rewrite or split a $1,000+$ line file in a single operation. You must execute the following four phases sequentially, pausing for verification between phases.

### Phase 1: Analyze (Read-Only)
1. Inspect the target file(s) without modifying any code.
2. Inventory all classes, functions, line counts, and imports.
3. Categorize logic into distinct responsibilities:
   * Routing / Controllers / Entrypoints
   * Core Business Logic / Domain Services
   * Data Access / Repositories / Queries
   * External API Gateways / Clients
   * Validation & Schemas / Models
   * Pure Utility Helpers
4. Identify duplicate logic and circular dependency risks.
5. Output a **Readiness Analysis & Proposed Feature Structure** and wait for confirmation (or proceed to Phase 2 if operating autonomously with a planning scratchpad).

### Phase 2: Create a Modularization Plan (No Code Changes)
Produce a concrete refactoring blueprint specifying for each proposed file:
* **Target Filepath**: Following feature-based vertical slice architecture (e.g., `src/modules/<feature>/<role>.py`).
* **Primary Responsibility**: One sentence defining what the file owns.
* **Symbols to Move**: Exact functions, classes, and constants moving to this file.
* **Dependencies**: Allowed internal and external imports.
* **Public Interface**: Exported functions/classes that callers are allowed to import.
* **Backward Compatibility Strategy**: How existing callers will be supported during transition (e.g., temporary re-exports in `__init__.py` or facade module).

### Phase 3: Incremental Extraction (One Module at a Time)
For **only one proposed module at a time**:
1. Create the new target file and move only the designated functions/classes.
2. Update imports in the source file and any direct callers (preserve public interfaces via re-exports if needed so unrelated files do not break).
3. Create or update isolated unit tests for the extracted module in `tests/<feature>/`.
4. Run the test suite, linter, and type-checker immediately:
   * Python example: `pytest tests/<feature>/` and `ruff check .`
   * TypeScript/JS example: `npx vitest run` and `npx eslint .`
5. Only after all tests pass, proceed to extract the next module.

### Phase 4: Verify & Document
1. Check for circular dependencies, broken imports, unused symbols, or accidental behavior changes.
2. Create or update the module's `README.md` using the standard template below.
3. Run the full test suite and generate a before-and-after **AI Agent Readiness Report**.

---

## 4. Required Templates

### A. Module `README.md` Template (Keep under 100 lines)
Place a `README.md` inside every feature module (`src/modules/<feature>/README.md`):

```markdown
# <Feature Name> Module

## Responsibility
<1-2 sentences describing the single domain responsibility of this module.>

## Files
- `<feature>_controller.<ext>`: Handles incoming requests and input/output mapping.
- `<feature>_service.<ext>`: Core domain and business logic.
- `<feature>_repository.<ext>`: Database queries and persistence operations.
- `<feature>_validator.<ext>`: Schema and business-rule validation.
- `<feature>_models.<ext>`: Data structures, DTOs, and domain entities.

## Public Interfaces
- `function_or_class_name()`: Brief signature and purpose.

## Dependencies
- Internal: `<list of allowed internal modules>`
- External: `<database, third-party APIs, or libraries>`

## Rules & Constraints
- Never access database tables directly from controllers.
- All external calls must go through the gateway/service interface.

## Tests
`tests/<feature>/` — Run with: `<exact copy-pasteable test command>`
```

### B. Root `AGENTS.md` Template (Keep under 150 lines)
When initializing or updating the project root `AGENTS.md`:

```markdown
# Project Development Rules for AI Agents

## Architecture
- Follow feature-based vertical slice architecture (`src/modules/<feature>/`).
- Every file must have one primary responsibility.
- Avoid cross-module dependencies unless routed through a module's public service interface.

## File & Function Size Limits
- Target 100–300 lines per file (review any file > 400 lines).
- Keep functions under 30 lines (never exceed 50 lines).
- Maximum 4 parameters per function (use typed data objects/DTOs for 5+).

## Workflow Before Modifying Code
1. Read `src/modules/<feature>/README.md` first.
2. Inspect existing public interfaces and module dependencies.
3. Check `tests/<feature>/` to understand expected behavior.

## Workflow After Modifying Code
1. Run module tests: `<insert exact test command>`
2. Run linter & typecheck: `<insert exact lint/typecheck command>`
3. Verify zero unrelated files were modified.
4. Update the module `README.md` if public interfaces changed.

## Restrictions
- Do not rewrite unrelated modules during a localized task.
- Do not change public interfaces without checking all callers.
- Do not introduce circular dependencies or unnecessary abstractions.
```

---

## 5. AI Agent Readiness Report Output Format

Whenever asked to audit a codebase or summarize a completed modularization, output the report in this format:

```text
========================================
       AI AGENT READINESS REPORT
========================================

Total Files Scanned:          <N>
Files Above 300 Lines:        <N>
Files Above 500 Lines:        <N>
Functions Above 50 Lines:     <N>
High Complexity Functions:    <N>
Circular Dependencies:        <N>
Modules Without README:       <N>
Modules Without Tests:        <N>

----------------------------------------
MODULE SCORES (AMS)
----------------------------------------
<Module Name>                 <XX>/100

----------------------------------------
OVERALL SCORE:                <XX>/100
STATUS:                       <CLASSIFICATION>

Priority Action Items:
1. <Highest-impact refactoring target>
2. <Circular dependency or coupling fix>
3. <Missing documentation or test isolation fix>
========================================
```