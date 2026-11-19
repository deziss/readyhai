# qa/design — test-design technique generation (BVA, EP, pairwise, decision tables)

Generates classic black-box design cases from the OpenAPI spec and writes an
operation x technique coverage matrix into the QA report.

| Check | Technique | Profile |
|---|---|---|
| `qa.design.boundary` | boundary-value analysis from min/max/enum/length bounds | Standard |
| `qa.design.equivalence` | valid + invalid equivalence partitions per input | Standard |
| `qa.design.pairwise` | greedy all-pairs covering array over inputs | Deep |
| `qa.design.decision-table` | rule rows over boolean/enum flags | Deep |
| `qa.design.matrix` | op × {Positive, Boundary, Equivalence, Pairwise, DecisionTable} cells | Standard |

**Planned-only contract (important):** generated cases are registered as `TestCase`s with
paired `Skipped` results — they are *not executed* (arbitrary writes are never sent).
Checks report `Skipped("planned only, not executed")` honestly, and the matrix marks cells
`Untested` until a human/runner produces executed results (Pass/Fail cells come from
executed API/design results; Fail is sticky). This documents design gaps without faking
evidence.

`common.rs`: spec loading, bounds/class extraction (mirrors `api/synth.rs` logic),
`propose()` dedup and caps (400 cases, 60 ops, 8 params/op). `pairwise.rs` also exports
pure `all_pairs()` (unit-tested covering-array generator).
