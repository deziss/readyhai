# Report Module (Multi-Format Test & Vulnerability Reporting)

The `report` module handles the synthesis, formatting, and file export of multi-standard vulnerability and QA verification reports.

## Architecture

- **`common.rs`**: Shared helper functions for XML/HTML escaping (`esc`), severity ordering (`sev_order`), status formatting (`status_str`), and URI reference percent-encoding (`uri_escape`).
- **`html.rs`**: Static, CSP-compliant HTML report generation with zero external script dependencies (`html`).
- **`sarif.rs`**: Industry-standard OASIS SARIF 2.1.0 output formatting for GitHub Advanced Security and IDE integrations (`sarif`).
- **`junit.rs`**: JUnit XML report generation for CI/CD test harness integration (`junit`).
- **`pr.rs`**: Sanitized Markdown comment generation for Pull Request / Merge Request automated feedback (`pr_comment`).
- **`writer.rs`**: Multi-format file system dispatch orchestrator (`write`).
- **`tests.rs`**: Complete test coverage verifying HTML escaping, SARIF URI conformance, and JUnit XML testcase structures.
