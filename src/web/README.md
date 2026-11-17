# Web & API Checks Module (`src/web`)

## Responsibility
Provides security scanning, contract validation, and health checks for Web and API targets.

## Submodules
- `client.rs`: HTTP client creation with SSRF protections, loopback resolution (`host.docker.internal`), and OpenAPI discovery.
- `smoke.rs`: Native HTTP endpoint smoke tests, CSP header analysis, cookie security flags, and TLS certificate validation.
- `schemathesis.rs`: Contract-driven fuzz testing using Schemathesis container runner and JUnit XML failure parsing.
- `playwright.rs`: Headless browser crawler via Playwright detecting JS exceptions, broken links, storage secrets, and postMessage issues.
- `nuclei.rs`: Community template-based vulnerability scanning for CVEs, exposures, and misconfigurations.
- `zap.rs`: OWASP ZAP passive baseline scan and intrusive active scan runners with JSON/XML alert parsing.
- `mod.rs`: Driver facade and check registration (`checks()`).
- `tests.rs`: Comprehensive test suite verifying URL parsing, container URL rewriting, and parser fidelity.

## Architectural Rules
1. **SSRF Guard**: Redirect policies restrict hops to the initial host (`same_host_redirects`).
2. **Container Isolation**: Target URLs referencing loopbacks are mapped to `host.docker.internal` with appropriate gateway flags.
3. **Shell Safety**: All URLs passed to container CLI flags must pass `has_shell_unsafe_chars` validation.
4. **Active Scanning Gate**: Intrusive checks (`tool.zap_active`) require `--profile deep` on explicit non-production targets.

## Verification
```bash
cargo test --bin readyhai -- web::tests
cargo clippy --bin readyhai -- -D warnings
```
