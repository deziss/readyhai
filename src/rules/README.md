# Native Readiness Rules (`src/rules`)

## Responsibility
In-process native readiness checks and fact detection for repository analysis. Audits Dockerfiles, dependency manifests, Docker Compose configurations, Kubernetes manifests, CI/CD pipelines, and general repository hygiene without container overhead.

## File Layout
- `facts.rs`: Fact detection (`detect_facts`), bounded file reading (`read_checked`, `read`), path helpers (`base`, `dir`, `normalize`), skip tracking (`Skips`), dependency manifest parsing (`Dep`, `req_deps`, `pkg_deps`, `manifest_deps`), and YAML parsing (`split_yaml_docs`, `k8s_docs_checked`, `k8s_docs`).
- `dockerfile.rs`: Dockerfile AST instruction and stage parsing (`Stage`, `parse_stages`), image tagging verification (`image_untagged`), healthcheck detection (`has_healthcheck`), one-shot image heuristics (`is_oneshot_image`), and rule check (`dockerfile_check`).
- `deps.rs`: Dependency pinning analysis, git ref pinning, and lockfile presence verification (`deps_check`).
- `compose.rs`: Docker Compose specification validation (`compose_check`), checking privileged mode, socket mounts, host networking, healthcheck definitions, missing binaries, resource limits, and restart policies.
- `k8s.rs`: Kubernetes manifest security audit (`k8s_check`), verifying committed plaintext secrets, host networking, privileged containers, missing probes, probe endpoints, resource limits, root execution, and untagged images.
- `ci.rs`: CI/CD pipeline auditing (`ci_check`), verifying SAST, secret-scanning, and dependency-scanning presence, plus detecting suppressed scanner exit codes or soft-fail settings.
- `repo.rs`: Repository hygiene auditing (`repo_check_fn`), checking tracked secret files, README presence, test suites, health routes, and OpenTelemetry instrumentation.
- `mod.rs`: Public facade re-exporting `detect_facts`, check definitions registry (`checks()`), and shared YAML/status helpers (`path`, `truthy`, `non_empty_map`, `str_of`, `repo_check`, `na`).
- `tests.rs`: Comprehensive test suite verifying all native readiness rules, fact detection, and YAML/Dockerfile/CI parsers.

## Public Interfaces
- `pub fn checks() -> Vec<Check>`: Returns all 6 native readiness checks for quick repository scans.
- `pub fn detect_facts(snap: &Snapshot) -> Facts`: Analyzes repository snapshot to populate target metadata and facts.

## Verification
```bash
PATH="$HOME/.cargo/bin:$PATH" cargo test --bin readyhai -- rules::tests
PATH="$HOME/.cargo/bin:$PATH" cargo clippy --bin readyhai -- -D warnings
```
