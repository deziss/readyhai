# Network Module (`src/network/`)

## 1. Responsibility
Provides comprehensive, agentic network reliability testing, latency jitter profiling, dual-stack Happy Eyeballs analysis, TLS certificate audits, MTU black-hole detection, and HAR 1.2 generation.

## 2. Directory Structure & Single Responsibilities
- `mod.rs`: Facade module exporting unified public API and backward-compatible types.
- `types.rs`: Core domain models, DTOs, regression report payloads, and constants.
- `utils.rs`: HTTP utilities, method safety guards, URL validation, and shell escaping.
- `ip.rs`: Egress public IP discovery, provider queries, and RFC1918 caching.
- `curl.rs`: Hardened curl command generation and subprocess execution.
- `regress.rs`: Iterative regression test runner, jitter calculation, and automated diagnostics.
- `tls.rs`: TLS handshakes, certificate chain inspection, and OpenSSL `s_client` parsing.
- `audit.rs`: Deep network audits (IPv4/v6 dual-stack, CORS, MTU sweep, subresources).
- `multi_region.rs`: Latency benchmarking and geographic disparity heuristics.
- `har.rs`: HTTP Archive (HAR 1.2) serialization for browser replay and triage.
- `tests.rs`: Isolated unit and integration test suite (36 tests).

## 3. Public Interfaces
- `run_regress_test(&RegressRequest) -> Result<RegressReport>`
- `run_curl_test(&CurlTestRequest) -> Result<CurlTestResponse>`
- `run_deep_audit(&DeepAuditRequest) -> Result<DeepAuditReport>`
- `run_multi_region_probe(&MultiRegionRequest) -> Result<MultiRegionReport>`
- `generate_har_from_regress(&RegressReport) -> Result<String>`
- `detect_requester_public_ip() -> RequesterIpInfo`

## 4. Key Architectural Constraints & Rules
- **Non-Intrusive by Default**: Read-only methods (`GET`, `HEAD`, `OPTIONS`) clamped to 25 iterations.
- **Protocol Pinning**: All child curl executions strictly pin `--proto =http,https`.
- **Egress Caching**: External IP lookups cached with 600s TTL; offline mode bypasses echo calls.
- **Fail-Safe Subprocesses**: All openssl and curl subprocesses bound by `run_capped` timeouts.

## 5. Verification Commands
- `cargo test --bin readyhai -- network::tests`
- `cargo clippy -- -D warnings`
