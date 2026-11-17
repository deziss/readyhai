//! Unified diff computation for remediation patches.

/// Compute a standard unified diff between two text versions.
pub fn compute_unified_diff(file_path: &str, old_src: &str, new_src: &str) -> String {
    if old_src == new_src {
        return String::new();
    }

    let old_lines: Vec<&str> = old_src.lines().collect();
    let new_lines: Vec<&str> = new_src.lines().collect();

    let mut start = 0;
    while start < old_lines.len()
        && start < new_lines.len()
        && old_lines[start] == new_lines[start]
    {
        start += 1;
    }

    let mut old_end = old_lines.len();
    let mut new_end = new_lines.len();

    while old_end > start && new_end > start && old_lines[old_end - 1] == new_lines[new_end - 1] {
        old_end -= 1;
        new_end -= 1;
    }

    let ctx_before = start.saturating_sub(3);
    let ctx_after_old = (old_end + 3).min(old_lines.len());
    let ctx_after_new = (new_end + 3).min(new_lines.len());

    let old_count = ctx_after_old - ctx_before;
    let new_count = ctx_after_new - ctx_before;

    let mut diff = format!("--- a/{file_path}\n+++ b/{file_path}\n");
    diff.push_str(&format!(
        "@@ -{},{} +{},{} @@\n",
        ctx_before + 1,
        old_count,
        ctx_before + 1,
        new_count
    ));

    for line in &old_lines[ctx_before..start] {
        diff.push_str(&format!(" {line}\n"));
    }
    for line in &old_lines[start..old_end] {
        diff.push_str(&format!("-{line}\n"));
    }
    for line in &new_lines[start..new_end] {
        diff.push_str(&format!("+{line}\n"));
    }
    for line in &old_lines[old_end..ctx_after_old] {
        diff.push_str(&format!(" {line}\n"));
    }

    diff
}
