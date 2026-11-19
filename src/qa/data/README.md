# qa/data — data-quality checks for test data

Repo-side only (snapshot reads; no live systems). QA checks over the fixtures/seed data
that feed tests — the "data quality" leg of a QA engineer's job.

| Check | Rule | Finds |
|---|---|---|
| `csvscan.rs` | `qa.data.duplicate_key`, `qa.data.null_violation` | dup PKs, empty required cols in fixture CSVs |
| `jsonscan.rs` | `qa.data.invalid_format` | malformed JSON fixtures, schema-ish violations (email/date shape) |
| `sqlscan.rs` | `qa.data.duplicate_key` (SQL) | duplicate PK inserts in seed SQL |
| `hygiene.rs` | `qa.data.pii_exposed`, `qa.data.stale_dates`, `qa.data.orphan_reference` | PII-looking values in fixtures, dates far in past/future, FK refs with no parent |

Scope is intentionally narrow: files named like `fixture/seed/sample/testdata` with
`.csv/.json/.sql` extensions. Defects appear as ordinary findings with remediation text.
