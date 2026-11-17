# QA Report Module (`src/qa/report`)

## Responsibility
Generates, renders, and exports QA run reports across formats: HTML (Jinja2 with CSP and no inline scripts), Markdown, Jira CSV, GitLab JSON, TestRail CSV, and Xray CSV, plus headless PDF rendering via Chromium.

## Files
- `mod.rs`: Public re-exports and module composition.
- `helpers.rs`: Escaping, CSV formula injection defense, markdown sanitization, base64 data URIs.
- `html.rs`: MiniJinja HTML template renderer (`qa-report.html.j2`), evidence staging, coverage matrices.
- `markdown.rs`: Standalone Markdown report generator.
- `exporters.rs`: Issue tracker and test management exports (Jira, GitLab, TestRail, Xray).
- `dispatch.rs`: Multi-format output dispatcher and Docker-based headless PDF renderer.
- `tests.rs`: Comprehensive unit tests covering sanitization, exports, and injection defense.

## Public Interfaces
- `qa_html(run: &Run, report_date: Option<&str>) -> Result<String>`
- `markdown(run: &Run) -> Result<String>`
- `jira_csv(q: &QaReport) -> String`
- `gitlab_json(q: &QaReport) -> serde_json::Value`
- `testrail_csv(q: &QaReport) -> String`
- `xray_csv(q: &QaReport) -> String`
- `write_formats(run: &Run, dir: &Path, formats: &[String]) -> Result<Vec<PathBuf>>`
- `render_pdf(dir: &Path) -> Result<PathBuf>`

## Rules & Safety
- **CSV Neutralization**: Prefix formula triggers (`=`, `+`, `-`, `@`, `\t`, `\r`) with `'` in all CSV exports.
- **XSS & Mention Neutralization**: Escape HTML entities and insert zero-width space in user mentions (`@\u{200B}username`).
- **Markdown Code Fences**: Dynamic backtick fence length calculated to exceed any backticks in payload.

## Tests
```bash
cargo test --bin readyhai -- qa::report::tests
```
