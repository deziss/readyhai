`format = "readyhai-json"` requires /out/dependency-check-report.json to be an array
of ReadyHai Findings (schema in `src/model.rs`), which Dependency-Check's own JSON
is not. Two clean options:

1. jq wrapper inside the same shell command that converts DC JSON -> readyhai-json
   (severity mapping: "High"/"Critical" -> high/critical, alias+description -> detail).
2. Add `parse_dependency_check()` to `src/tools/parsers.rs` (10 lines, follows the
   `parse_grype` pattern) and extend the plugin `format` enum with `dc-json`.
