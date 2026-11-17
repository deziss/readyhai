# Agent Memory (`src/agent/memory`)

## Responsibility
Persists and reconciles the agent's deterministic historical memory of target web applications across runs: known defects, flakiness windows, operation coverage, accepted waivers, and baseline states.

## Files
- `types.rs`: Core domain models, retention windows, defect statuses, and `Memory` struct.
- `sanitize.rs`: Deterministic ASCII identifiers, date diffing, and SHA-256 fingerprinting.
- `store.rs`: Atomic filesystem I/O, quarantine backup of corrupted memories, and lock coordination.
- `observe.rs`: Pure observation extraction from run execution results and defect triage.
- `reconcile.rs`: Pure state reconciliation, regression tracking, defect resolution, and `PlanHints`.
- `render.rs`: Human-readable CLI text rendering.
- `mod.rs`: Public API facade maintaining 100% backward compatibility.
- `tests.rs`: Comprehensive test suite.

## Security & Architectural Rules
1. **Deterministic input only**: Memory is built solely from oracle, verifier, and triage statuses. Never from LLM-generated text or response bodies.
2. **Never change verdicts directly**: Memory reorders and prioritizes cases; only unexpired operator acceptances waive blocking defects.
3. **Tamper-evident**: Integrity is verified via SHA-256 digest on load; corrupted files are quarantined rather than crashing.
