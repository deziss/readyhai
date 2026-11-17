# Sandboxed Tools Architecture (`readyhai::tools`)

Containerized scanner isolation, deterministic image digest pinning, output parsing, and subprocess runner.

## Module Map

| File | Responsibility | Key Interfaces |
|---|---|---|
| [`types.rs`](types.rs) | Domain types, caps & errors | `MountMode`, `ToolSpec`, `ToolRun`, `LockEntry`, `Captured`, `OutTooLarge` |
| [`policy.rs`](policy.rs) | Container security policy & mount validation | `validate_create_policy`, `mount_args`, `Mount` |
| [`docker.rs`](docker.rs) | Docker runtime, process spawning & reaping | `Docker`, `run_capped`, `reap_run`, `reap_dead_runs`, `read_out` |
| [`pinning.rs`](pinning.rs) | Image resolution, lockfile & offline bundles | `lock_entries`, `local_image_id`, `image_for`, `tools_pull`, `tools_update` |
| [`parsers.rs`](parsers.rs) | Scanner outputs (SARIF, JUnit, JSON) & scrubbing | `parse_grype`, `parse_gitleaks`, `parse_checkov`, `scrub_semgrep` |
| [`checks.rs`](checks.rs) | Check definitions & plugin discovery | `checks()`, `plugin_checks()`, `junit_output`, `db_age_days` |
| [`mod.rs`](mod.rs) | Re-export facade | 100% backward-compatible public exports |
| [`tests.rs`](tests.rs) | Unit tests & golden fixtures | Test suite |

## Security Rules
1. **Zero Socket Access**: Mounting the Docker socket (`/var/run/docker.sock`) is strictly rejected.
2. **Capability Dropping**: Container tools execute with `--cap-drop ALL`, `--security-opt no-new-privileges`, `--read-only`, non-root user.
3. **Secret Scrubbing**: Raw secrets in tool outputs (e.g. gitleaks, semgrep) are scrubbed before persistence or telemetry.
4. **Bounded I/O**: stdout/stderr are capped to prevent memory exhaustion and pipe stalls.

## Testing
```bash
cargo test --bin readyhai -- tools::tests
```
