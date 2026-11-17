# Agent Report Module

## Responsibility
Generates multi-format production-readiness reports (HTML, Markdown, SARIF v2.1.0, JUnit XML, JSON) summarizing autonomous QA & adversarial testing runs, evidence ledgers, defect triage, verification results, and change-impact analysis.

## Architecture & Submodules
- `helpers.rs`: Text escaping primitives (HTML, XML, Markdown inline/code/fence) and shared metric/verdict/table formatting functions.
- `html.rs`: Standalone interactive HTML report generator with evidence ledger cards, technique coverage matrix, and test logs.
- `markdown.rs`: GFM Markdown report generator formatted for GitHub PR comments, issue trackers, and developer summaries.
- `sarif.rs`: Static Analysis Results Interchange Format (SARIF 2.1.0) JSON generator with rule taxonomy and location mapping.
- `junit.rs`: Standard JUnit XML testsuite generator compatible with enterprise CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins).
- `mod.rs`: Driver (`generate_agent_report_formats`) and backward-compatible re-exports.

## Public Interfaces
- `generate_agent_html_report(rep: &AgentRunReport) -> String`
- `generate_agent_markdown_report(rep: &AgentRunReport) -> String`
- `generate_agent_sarif_report(rep: &AgentRunReport) -> serde_json::Value`
- `generate_agent_junit_report(rep: &AgentRunReport) -> String`
- `generate_agent_report_formats(rep: &AgentRunReport, dir: &Path, formats: &[String]) -> Result<Vec<PathBuf>>`

## Security & Escaping Rules
1. **Target-Derived Text Escaping**: All target-controlled strings (route paths, titles, headers, defect notes, curl payloads) are strictly escaped for target format (HTML, XML, or Markdown) before inclusion.
2. **Fence Integrity**: Markdown code blocks dynamically measure backtick runs to prevent payload escape injection.
3. **No Fabrication**: Missing metrics render explicitly as `not evaluated` or `not detected`.

## Verification Commands
```bash
PATH="$HOME/.cargo/bin:$PATH" cargo test --bin readyhai -- agent::tests::reports_escape
PATH="$HOME/.cargo/bin:$PATH" cargo clippy --bin readyhai -- -D warnings
```
