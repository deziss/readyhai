# `qa::suite` — Repository Quality & Release Analysis

Cohesive vertical slices for repository-side test-suite quality and release verification.

## Module Structure

- **`common.rs`**: Shared defect constructors (`Def`), snapshot reading caps, and test path heuristics.
- **`coverage.rs`**: Coverage report parsers (Cobertura XML, LCOV, JaCoCo XML) and critical path deficit checks.
- **`routes.rs`**: Web framework route extraction (Python, JS/TS, Java/Kotlin) and test reference coverage tracking.
- **`smells.rs`**: Assertion-free tests, skipped tests, and hard-coded sleep detection.
- **`eol.rs`**: Base image and runtime end-of-life auditing against vendor schedules (`endoflife.date`).
- **`migrations.rs`**: Database migration up/down/up verification via hardened Docker containers.
- **`licenses.rs`**: SBOM license extraction and organization deny-list compliance checks.
- **`mod.rs`**: Public check catalog (`checks()`) and backward-compatible re-exports.
- **`tests.rs`**: Comprehensive unit tests for all suite capabilities.
