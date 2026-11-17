//! Pull Request comment markdown generator with safe escaping and category breakdown.

use crate::model::*;
use crate::qa::report::md_inline;

use super::common::{sev_order, status_str};

/// Hidden marker the CI bots use to find and update their own PR / MR comment.
pub const PR_COMMENT_MARKER: &str = "<!-- readyhai-pr-comment -->";
/// Most findings listed in a PR comment; the rest are counted and left to the full report.
pub const PR_COMMENT_MAX: usize = 15;

/// Compact Markdown summary for a pull/merge request comment: verdict, reasons, per-category
/// counts and the top new (unsuppressed) findings. All finding text goes through `md_inline`, so
/// nothing from the scanned target can become markup, links or @mentions.
pub fn pr_comment(run: &Run) -> String {
    let (icon, word) = match run.verdict {
        Verdict::Pass => ("\u{2705}", "PASS"),
        Verdict::Warn => ("\u{26a0}\u{fe0f}", "WARN"),
        Verdict::Fail => ("\u{274c}", "FAIL"),
    };
    // Inside a code span Markdown escapes render literally, so strip what could end the span
    // or break the line instead of escaping it.
    let code = |t: &str| -> String {
        t.chars()
            .map(|c| if c == '`' || c.is_control() { ' ' } else { c })
            .take(200)
            .collect::<String>()
    };
    let mut o = format!(
        "{PR_COMMENT_MARKER}\n## {icon} ReadyHai: {word}\n\nTarget `{}` \u{b7} profile `{}` \u{b7} readyhai `{}`\n\n",
        code(&run.target.raw),
        format!("{:?}", run.profile).to_lowercase(),
        code(&run.version)
    );
    if let Some(qa) = &run.qa {
        o += &format!(
            "**Recommendation:** {}\n\n",
            md_inline(&format!("{:?}", qa.recommendation))
        );
    }
    for r in &run.reasons {
        o += &format!("- {}\n", md_inline(r));
    }
    let open: Vec<&Finding> = run
        .findings
        .iter()
        .filter(|f| f.status != FindingStatus::Suppressed)
        .collect();
    let new = open
        .iter()
        .filter(|f| f.status == FindingStatus::New)
        .count();
    o += &format!(
        "\n**{}** open findings ({new} new) \u{b7} {} fixed since baseline\n\n",
        open.len(),
        run.fixed
    );
    let cats: Vec<&CategorySummary> = run
        .categories
        .iter()
        .filter(|c| c.critical + c.high + c.medium + c.low > 0)
        .collect();
    if !cats.is_empty() {
        o += "| Category | Critical | High | Medium | Low |\n|---|---:|---:|---:|---:|\n";
        for c in cats {
            o += &format!(
                "| {} | {} | {} | {} | {} |\n",
                md_inline(&c.category),
                c.critical,
                c.high,
                c.medium,
                c.low
            );
        }
        o += "\n";
    }
    let mut top: Vec<&Finding> = open.clone();
    top.sort_by_key(|f| {
        (
            f.status != FindingStatus::New,
            sev_order(f.severity),
            f.rule.clone(),
        )
    });
    if !top.is_empty() {
        o += "<details><summary>Top findings</summary>\n\n| Severity | Status | Rule | Title | Location |\n|---|---|---|---|---|\n";
        for f in top.iter().take(PR_COMMENT_MAX) {
            o += &format!(
                "| {} | {} | {} | {} | {} |\n",
                f.severity.as_str(),
                status_str(f.status),
                md_inline(&f.rule).replace('|', "\\|"),
                md_inline(&f.title).replace('|', "\\|"),
                md_inline(&f.location).replace('|', "\\|"),
            );
        }
        if top.len() > PR_COMMENT_MAX {
            o += &format!(
                "\n_{} more in the full report artifact._\n",
                top.len() - PR_COMMENT_MAX
            );
        }
        o += "\n</details>\n";
    }
    o += "\n<sub>Exit codes: 0 PASS \u{b7} 1 WARN \u{b7} 2 FAIL. Full HTML/SARIF report is attached to the pipeline run.</sub>\n";
    o
}
