# Fix Module (Agentic Fixer)

The `fix` module provides automated AST-grounded vulnerability and defect remediation, safe local sandbox verification, and GitHub Pull Request documentation authoring.

## Architecture

- **`types.rs`**: Core data models (`FixOpts`, `TargetDefect`, `PatchRemediation`, `PatchStatus`, `FixReport`).
- **`diff.rs`**: Standard unified diff computation (`compute_unified_diff`).
- **`sibling.rs`**: Sibling endpoint guard mining (`mine_sibling_guards`) to discover standard middleware conventions.
- **`remediate.rs`**: Pattern and AST-grounded remediation synthesis for auth guards, SQLi, path traversal, command injection, CORS, and secrets (`synthesize_remediation`).
- **`sandbox.rs`**: Test runner auto-detection (`detect_test_runner`) and isolated rollback test execution (`verify_in_sandbox`).
- **`defects.rs`**: Loading defects from previous run ledgers or live AST audit trees (`collect_target_defects`).
- **`pr.rs`**: High-detail Markdown description synthesis (`generate_pr_markdown`).
- **`git.rs`**: Local branch creation and commit authoring (`commit_local_branch`), adhering strictly to local-only push policy.
- **`runner.rs`**: Top-level CLI command orchestration and terminal summary (`run`, `print_text_summary`).
- **`tests.rs`**: Comprehensive test coverage across all remediation patterns and diff generation.
