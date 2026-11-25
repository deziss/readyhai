//! Memory recall checks, git fixture repository creation, and change impact assertions.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use super::scoring::expect_matches;
use super::types::{ChangeSpec, Check, Expect, RunStats, SuiteSpec};

fn rel(root: &Path, p: &str) -> std::path::PathBuf {
    let p = Path::new(p);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        root.join(p)
    }
}

/// Cases by status, the ledger's confidence and its blocker reasons (`auth_wall`, ...).
pub fn agent_stats(rep: &crate::agent::AgentRunReport) -> RunStats {
    let ledger = rep.evidence_ledger.as_ref();
    let blockers = ledger
        .map(|l| {
            l.blockers
                .iter()
                .filter_map(|b| serde_json::to_value(b.reason).ok())
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    RunStats::from_statuses(
        rep.executed_results.iter().map(|r| r.status.as_str()),
        ledger.and_then(|l| l.confidence),
        blockers,
    )
}

/// What an agent run reported: each triaged defect with the failing oracle checks of its cases
/// (a defect can carry several), and its fingerprint.
pub(crate) fn agent_defects(
    rep: &crate::agent::AgentRunReport,
) -> Vec<(super::types::Observed, String)> {
    use crate::agent::Verdict;
    rep.triaged_defects
        .iter()
        .map(|d| {
            let mut rules: Vec<String> = vec![];
            for cid in &d.case_ids {
                if let Some(o) = rep
                    .executed_results
                    .iter()
                    .find(|r| &r.case_id == cid)
                    .and_then(|r| r.oracle.as_ref())
                {
                    for c in o.checks.iter().filter(|c| c.verdict == Verdict::Fail) {
                        if !rules.contains(&c.code) {
                            rules.push(c.code.clone());
                        }
                    }
                }
            }
            (
                super::types::Observed {
                    rules,
                    component: d.component.clone(),
                    title: d.title.clone(),
                },
                d.fingerprint.clone(),
            )
        })
        .collect()
}

/// What `[memory]` asks of a series of runs in one data directory: the first run remembers what it
/// found, every later run reports the seeded defects as still open, leads its plan with their
/// reproduction cases, and plans every case the first run planned (memory only reorders).
pub fn memory_checks(spec: &SuiteSpec, reps: &[crate::agent::AgentRunReport]) -> Vec<Check> {
    let (Some(first), Some(last)) = (reps.first(), reps.last()) else {
        return vec![];
    };
    let mut out = vec![];
    let check = |name: &str, ok: bool, detail: String| Check {
        name: name.into(),
        ok,
        detail,
    };
    // the first run: nothing was known, everything it found is new, and it was remembered
    let s1 = first.since_last_run.as_ref();
    out.push(check(
        "memory: first run remembered",
        s1.is_some_and(|s| {
            s.first_run
                && s.committed
                && s.new.len() == first.triaged_defects.len()
                && !first.triaged_defects.is_empty()
        }),
        match s1 {
            Some(s) => format!(
                "first_run {}, remembered {}, {} new of {} defect(s)",
                s.first_run,
                s.committed,
                s.new.len(),
                first.triaged_defects.len()
            ),
            None => "the report has no since_last_run (memory off?)".into(),
        },
    ));
    let Some(sl) = last.since_last_run.as_ref().filter(|_| reps.len() > 1) else {
        out.push(check(
            "memory: seeded defects still open",
            false,
            "the last run has no since_last_run".into(),
        ));
        return out;
    };
    // the seeded defects: every required expectation is matched by a defect that is "still open"
    let defects = agent_defects(last);
    let still_open: std::collections::BTreeSet<&str> = sl
        .still_open
        .iter()
        .map(|l| l.fingerprint.as_str())
        .collect();
    let required: Vec<&Expect> = spec
        .expect
        .iter()
        .filter(|e| !e.optional && !e.known_gap)
        .collect();
    let not_open: Vec<&str> = required
        .iter()
        .filter(|e| {
            !defects
                .iter()
                .any(|(o, fp)| expect_matches(e, o) && still_open.contains(fp.as_str()))
        })
        .map(|e| e.id.as_str())
        .collect();
    let first_fps: std::collections::BTreeSet<&str> = first
        .triaged_defects
        .iter()
        .map(|d| d.fingerprint.as_str())
        .collect();
    let renewed: Vec<&str> = sl
        .new
        .iter()
        .filter(|l| first_fps.contains(l.fingerprint.as_str()))
        .map(|l| l.endpoint.as_str())
        .collect();
    out.push(check(
        "memory: seeded defects still open",
        not_open.is_empty() && renewed.is_empty(),
        format!(
            "{} of {} expected defect(s) reported still open ({} defect(s) in all){}{}",
            required.len() - not_open.len(),
            required.len(),
            sl.still_open.len(),
            if not_open.is_empty() {
                String::new()
            } else {
                format!("; not still open: {}", not_open.join(", "))
            },
            if renewed.is_empty() {
                String::new()
            } else {
                format!("; reported new again: {}", renewed.join(", "))
            }
        ),
    ));
    // the plan: the reproduction cases lead it, one for every still-open defect that has a planned
    // reproduction (a defect found by the teardown has none: no planned case deletes and re-reads)
    let plan: Vec<&crate::agent::PlannedCase> = last
        .planned_cases
        .iter()
        .filter(|c| !c.id.contains("-F"))
        .collect();
    let lead = plan
        .iter()
        .take_while(|c| !c.regression_of.is_empty())
        .count();
    let tagged_after = plan[lead..].iter().any(|c| !c.regression_of.is_empty());
    let planned_repro: Vec<&crate::agent::memory::DefectLine> = sl
        .still_open
        .iter()
        .filter(|l| l.rule != "delete_not_effective")
        .collect();
    let uncovered: Vec<&str> = planned_repro
        .iter()
        .filter(|l| {
            !plan[..lead]
                .iter()
                .any(|c| c.regression_of.contains(&l.fingerprint))
        })
        .map(|l| l.endpoint.as_str())
        .collect();
    out.push(check(
        "memory: regression probes lead the plan",
        lead > 0 && !tagged_after && uncovered.is_empty(),
        format!(
            "{lead} probe(s) lead the plan of {} case(s), none after the first other case; {} of {} still-open defect(s) have one{}",
            plan.len(),
            planned_repro.len() - uncovered.len(),
            planned_repro.len(),
            if uncovered.is_empty() {
                String::new()
            } else {
                format!("; without a probe: {}", uncovered.join(", "))
            }
        ),
    ));
    // memory reorders, it never drops a case: whatever passed before is planned (and run) again.
    // The target may list records it did not list before (the fixture keeps the orders its
    // no-op DELETE leaves behind), so the later plan may hold MORE reads; it never holds fewer cases.
    let shape = |rep: &crate::agent::AgentRunReport| {
        let mut v: Vec<String> = rep
            .planned_cases
            .iter()
            .filter(|c| !c.id.contains("-F"))
            .map(|c| {
                format!(
                    "{} {} {} {:?} {:?}",
                    c.method, c.component, c.technique, c.payload, c.role
                )
            })
            .collect();
        v.sort();
        v
    };
    let (a, b) = (shape(first), shape(last));
    let mut left = b.clone();
    let dropped: Vec<&String> = a
        .iter()
        .filter(|c| match left.iter().position(|x| x == *c) {
            Some(i) => {
                left.remove(i);
                false
            }
            None => true,
        })
        .collect();
    out.push(check(
        "memory: no case dropped",
        dropped.is_empty(),
        format!(
            "run 1 planned {} case(s), the last run {} ({} more)",
            a.len(),
            b.len(),
            b.len().saturating_sub(a.len())
        ) + &if dropped.is_empty() {
            String::new()
        } else {
            format!(
                "; no longer planned: {}",
                dropped
                    .iter()
                    .take(5)
                    .map(|d| d.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
    ));
    out
}

/// What `[change]` asks of the run's change impact: the right operations were found, their cases
/// lead the plan, and they were really sent.
pub fn change_checks(c: &ChangeSpec, rep: &crate::agent::AgentRunReport) -> Vec<Check> {
    let Some(ci) = &rep.change_impact else {
        return vec![Check {
            name: "change impact".into(),
            ok: false,
            detail: "the report has no change impact (repo or diff_base not applied)".into(),
        }];
    };
    let mut out = vec![];
    let mut got: Vec<String> = ci.operations.iter().map(|o| o.operation.clone()).collect();
    let mut want = c.operations.clone();
    got.sort();
    want.sort();
    out.push(Check {
        name: "changed operations".into(),
        ok: got == want,
        detail: format!(
            "{} changed file(s) -> reported [{}], expected [{}]",
            ci.changed_files_total,
            got.join(", "),
            want.join(", ")
        ),
    });
    if c.planned_first {
        let pos: Vec<usize> = rep
            .planned_cases
            .iter()
            .enumerate()
            .filter(|(_, p)| !p.changed_ops.is_empty())
            .map(|(i, _)| i)
            .collect();
        let first_other = rep
            .planned_cases
            .iter()
            .position(|p| p.changed_ops.is_empty() && p.component != "/");
        let last = pos.last().copied();
        out.push(Check {
            name: "changed operations planned first".into(),
            ok: match (last, first_other) {
                (Some(l), Some(o)) => l < o,
                (Some(_), None) => true,
                (None, _) => false,
            },
            detail: format!(
                "{} changed case(s), the last at position {}; the first other case at {}",
                pos.len(),
                last.map(|l| (l + 1).to_string())
                    .unwrap_or_else(|| "-".into()),
                first_other
                    .map(|o| (o + 1).to_string())
                    .unwrap_or_else(|| "-".into()),
            ),
        });
    }
    let (sent, planned) = crate::agent::change::coverage_totals(&ci.coverage);
    let share = if planned == 0 {
        0.0
    } else {
        sent as f64 / planned as f64
    };
    let uncovered: Vec<&str> = ci
        .coverage
        .iter()
        .filter(|o| o.executed == 0)
        .map(|o| o.operation.as_str())
        .collect();
    out.push(Check {
        name: "changed operations covered".into(),
        ok: planned > 0 && share + 1e-9 >= c.min_sent && uncovered.is_empty(),
        detail: format!(
            "{sent} of {planned} planned case(s) sent ({:.0}%) vs >= {:.0}%{}",
            share * 100.0,
            c.min_sent * 100.0,
            if uncovered.is_empty() {
                String::new()
            } else {
                format!("; not sent at all: {}", uncovered.join(", "))
            }
        ),
    });
    out
}

fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for e in std::fs::read_dir(src).with_context(|| format!("read {}", src.display()))? {
        let e = e?;
        let ty = e.file_type()?;
        let to = dst.join(e.file_name());
        if ty.is_dir() {
            copy_tree(&e.path(), &to)?;
        } else if ty.is_file() {
            std::fs::copy(e.path(), &to)?;
        } // symlinks are not fixtures
    }
    Ok(())
}

fn fixture_git(dir: &Path, args: &[&str]) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "readyhai-eval")
        .env("GIT_AUTHOR_EMAIL", "eval@example.invalid")
        .env("GIT_COMMITTER_NAME", "readyhai-eval")
        .env("GIT_COMMITTER_EMAIL", "eval@example.invalid");
    let out = crate::tools::run_capped(&mut cmd, Duration::from_secs(60), 16 * 1024, None)
        .context("run git (the change-aware eval needs git on PATH)")?;
    if !out.success() {
        bail!("git {}: {}", args.join(" "), out.stderr_lossy().trim());
    }
    Ok(())
}

/// A repository whose history is the fixture directories in order: each one is copied over the
/// working tree and committed, and the first commit is tagged `base`.
pub fn build_fixture_repo(root: &Path, commits: &[String], dest: &Path) -> Result<()> {
    let _ = std::fs::remove_dir_all(dest);
    std::fs::create_dir_all(dest)?;
    fixture_git(dest, &["init", "-q"])?;
    for (i, c) in commits.iter().enumerate() {
        let src = rel(root, c);
        if !src.is_dir() {
            bail!("fixture commit {} is not a directory", src.display());
        }
        copy_tree(&src, dest)?;
        fixture_git(dest, &["add", "-A"])?;
        fixture_git(
            dest,
            &[
                "commit",
                "-q",
                "--allow-empty",
                "--no-verify",
                "-m",
                &format!("fixture commit {}", i + 1),
            ],
        )?;
        if i == 0 {
            fixture_git(dest, &["tag", "base"])?;
        }
    }
    Ok(())
}
