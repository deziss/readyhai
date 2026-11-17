# Android Security Analysis Module (`src/android`)

## Responsibility
Provides static security analysis of Android APK/AAB packages via short-lived MobSF Docker containers, and dynamic ADB-based runtime crash/ANR detection on physical or emulated devices.

## Files
- `mod.rs`: Check registration (`android.mobsf`, `android.runtime`) and public facade re-exports.
- `util.rs`: Common string slugging, regex token redaction, process runner, and form/multipart body builders.
- `staging.rs`: App extraction, local staging in the run workspace, and file permission configuration.
- `mobsf/container.rs`: Docker container lifecycle manager with RAII `Drop` cleanup and port discovery.
- `mobsf/client.rs`: Synchronous HTTP client for MobSF upload, scan, report, and scorecard retrieval.
- `mobsf/mapping.rs`: Report scrubbing (redacting secret values) and mapping MobSF issues to readyhai findings.
- `mobsf/mod.rs`: `run_mobsf` check coordinator.
- `runtime/logcat.rs`: Android logcat stream parser, crash/ANR event extractor, and emulator heuristics.
- `runtime/adb.rs`: ADB device executor, package manager reconciliation, and monkey test coordinator.
- `runtime/mod.rs`: Runtime submodule exports.
- `tests.rs`: Unit test suite for MobSF report mapping, secret scrubbing, logcat parsing, and encoding.

## Public Interfaces
- `checks() -> Vec<Check>`
- `redact(s: &str) -> String`
- `multipart_body(boundary: &str, field: &str, filename: &str, bytes: &[u8]) -> Vec<u8>`
- `form_body(pairs: &[(&str, &str)]) -> String`
- `map_report(rep: &Value) -> Vec<Finding>`
- `scrub_report(rep: &Value) -> Value`
- `parse_docker_port(out: &str) -> Option<u16>`
- `is_emulator(serial: &str, qemu_prop: &str) -> bool`
- `scan_logcat(text: &str, pkg: &str) -> LogScan`

## Safety Rules
- Secrets must never be stored or leaked in findings or scrubbed reports.
- MobSF Docker containers must always be cleaned up via RAII guard.

## Tests
```bash
cargo test --bin readyhai -- android::tests
```
