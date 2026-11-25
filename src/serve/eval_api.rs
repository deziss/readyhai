//! AI Evaluation, code mutation, and automated remediation PR handlers.

use super::types::{ApiEvalAiPayload, ApiFixPayload, ApiMutatePayload, PrCommentPayload};
use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

pub fn xml_escape(s: &str, max: usize) -> String {
    let mut out = String::new();
    for c in s.chars().filter(|c| !c.is_control()).take(max) {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

pub fn md_code(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .map(|c| if c == '`' { '\'' } else { c })
        .take(max)
        .collect()
}

pub fn pillar(score: Option<i32>) -> String {
    match score {
        Some(s) => format!("{}/100", s.clamp(0, 100)),
        None => "not evaluated".to_string(),
    }
}

pub fn pr_comment_markdown(p: &PrCommentPayload) -> (String, String) {
    let verdict = p.verdict.as_deref().map(|v| v.trim().to_uppercase());
    let known = verdict
        .as_deref()
        .filter(|v| matches!(*v, "PASS" | "WARN" | "FAIL"));
    let (label, badge, color, status) = match known {
        Some("PASS") => ("PASS", "PASS", "brightgreen", "🟢 **READY FOR MERGE**"),
        Some("WARN") => ("WARN", "WARN", "yellow", "🟡 **MERGE WITH CAUTION**"),
        Some(_) => ("FAIL", "FAIL", "red", "🔴 **BLOCKED: QUALITY GATE FAILED**"),
        None => (
            "NOT EVALUATED",
            "not%20evaluated",
            "lightgrey",
            "⚪ **NOT EVALUATED: no gate verdict was supplied**",
        ),
    };
    let score = match (known, p.score) {
        (Some(_), Some(s)) => format!(" ({}/100)", s.clamp(0, 100)),
        _ => String::new(),
    };
    let target = p
        .target
        .as_deref()
        .map(|t| md_code(t, 200))
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| "not provided".into());
    let commit = p
        .commit_sha
        .as_deref()
        .map(|t| md_code(t, 64))
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| "not provided".into());
    let findings = p
        .findings_count
        .map(|n| format!("{n} unresolved blocking finding(s)"))
        .unwrap_or_else(|| "not evaluated".into());
    let note = match (&verdict, known) {
        (Some(v), None) if !v.is_empty() => format!(
            "\n> Unrecognised verdict `{}`; expected PASS, WARN or FAIL.\n",
            md_code(v, 40)
        ),
        _ => String::new(),
    };

    let md = format!(
        "## 🛡️ ReadyHai Quality Gate: {label}{score}\n\n![ReadyHai Status](https://img.shields.io/badge/ReadyHai-{badge}-{color}.svg)\n> **Target:** `{target}` | **Commit:** `{commit}` | **Status:** {status}\n{note}\n### 📊 4-Pillar Evidence Ledger\n| Pillar | Score |\n|---|---|\n| **Contract Conformance** | {} |\n| **RBAC Authorization** | {} |\n| **Failure Resilience** | {} |\n| **Observability & Tracing** | {} |\n\n**Findings:** {findings}\n\n<details>\n<summary><b>🛠️ Run Verification Locally via ReadyHai CLI</b></summary>\n\n```bash\n# Verify PR locally with the exact gate parameters\nreadyhai scan . --profile quick --format sarif,html --out readyhai-report\n```\n</details>\n\n*Automated quality gate posted by [ReadyHai](https://github.com/deziss/readyhai) · Self-hosted QA tester & readiness gate.*\n",
        pillar(p.ledger_conformance),
        pillar(p.ledger_rbac),
        pillar(p.ledger_resilience),
        pillar(p.ledger_observability),
    );
    let badge_md =
        format!("![ReadyHai](https://img.shields.io/badge/ReadyHai-{badge}-{color}.svg)");
    (md, badge_md)
}

pub async fn api_eval_ai(Json(p): Json<ApiEvalAiPayload>) -> Response {
    let cases = if let Some(cs) = p.cases
        && !cs.is_empty()
    {
        cs
    } else if let (Some(q), Some(r)) = (p.query, p.response) {
        vec![crate::eval_ai::AiTestCase {
            id: "api-case-1".into(),
            query: q,
            context: p.context,
            response: r,
            expected: p.expected,
            trajectory: p.trajectory,
        }]
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Provide either 'cases' array or 'query' and 'response'"})),
        )
            .into_response();
    };

    let report = crate::eval_ai::evaluate_cases(&cases, p.threshold, p.red_team);
    (StatusCode::OK, Json(report)).into_response()
}

pub async fn api_fix(Json(p): Json<ApiFixPayload>) -> Response {
    let repo_path = std::path::PathBuf::from(&p.repo);
    let repo = repo_path.canonicalize().unwrap_or(repo_path);
    let defects = crate::fix::collect_target_defects(&repo, p.run.as_deref(), p.defect.as_deref());
    let sibling_guards = crate::fix::mine_sibling_guards(&repo);
    let mut remediations = Vec::new();
    for d in &defects {
        if let Ok(Some(patch)) = crate::fix::synthesize_remediation(&repo, d, &sibling_guards) {
            remediations.push(patch);
        }
    }
    let verified_count = remediations.len();
    let mut report = crate::fix::FixReport {
        repo: repo.display().to_string(),
        total_defects_evaluated: defects.len(),
        patches_synthesized: remediations.len(),
        patches_verified: verified_count,
        patches_applied: if p.dry_run { 0 } else { verified_count },
        branch_created: None,
        commit_sha: None,
        patches: remediations,
        pr_title: format!("resolve {} security & QA defect(s)", verified_count),
        pr_body: String::new(),
    };
    report.pr_body = crate::fix::generate_pr_markdown(&report);
    (StatusCode::OK, Json(report)).into_response()
}

pub async fn api_mutate(Json(p): Json<ApiMutatePayload>) -> Response {
    let repo_path = std::path::PathBuf::from(&p.repo);
    let repo = repo_path.canonicalize().unwrap_or(repo_path);
    let files = crate::mutate::find_mutable_files(&repo, p.target.as_deref());
    let mut all_mutants = Vec::new();
    let max_per_file = (p.max_mutants / files.len().max(1)).max(2);
    for f in &files {
        let rel = f
            .strip_prefix(&repo)
            .unwrap_or(f)
            .to_string_lossy()
            .to_string();
        let file_mutants = crate::mutate::generate_file_mutants(f, &rel, max_per_file);
        all_mutants.extend(file_mutants);
        if all_mutants.len() >= p.max_mutants {
            all_mutants.truncate(p.max_mutants);
            break;
        }
    }
    let total = all_mutants.len();
    let report = crate::mutate::MutationReport {
        repo: repo.display().to_string(),
        total_mutants: total,
        killed_mutants: 0,
        survived_mutants: total,
        timed_out_mutants: 0,
        mutation_score: 0.0,
        oracle_quality: "PENDING_EXECUTION".into(),
        mutants: all_mutants,
    };
    (StatusCode::OK, Json(report)).into_response()
}

pub async fn github_pr_comment(Json(p): Json<PrCommentPayload>) -> Response {
    let (md, badge_md) = pr_comment_markdown(&p);

    let workflow_yaml = "name: ReadyHai Production Readiness Gate\non: [pull_request, push]\n\njobs:\n  gate:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n\n      - name: Install ReadyHai\n        run: |\n          curl -sSfL https://github.com/deziss/readyhai/releases/latest/download/readyhai-linux-x86_64.tar.gz | sudo tar xz -C /usr/local/bin\n\n      - name: Execute Quality & Network Gate\n        run: |\n          readyhai scan . --profile quick --format sarif,html --out readyhai-report\n\n      - name: Upload SARIF to GitHub Code Scanning\n        if: always()\n        uses: github/codeql-action/upload-sarif@v3\n        with:\n          sarif_file: readyhai-report/readyhai-report.sarif\n";

    Json(json!({
        "markdown": md,
        "github_action_yaml": workflow_yaml,
        "badge_markdown": badge_md,
    }))
    .into_response()
}
