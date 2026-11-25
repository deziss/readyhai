//! Pairwise (all-pairs) combination, decision-table derivation from boolean flags, and the
//! operation x technique coverage matrix.
use super::common::{
    CASE_CAP, case, classes, inputs, no_spec, ops, propose, schema_type, spec, valid_value,
};
use crate::ctx::Ctx;
use crate::model::{CheckOutput, CheckStatus};
use crate::qa::model::*;
use anyhow::Result;
use serde_json::Value;
use std::collections::BTreeSet;

/// Value classes for one input: [valid representative, up to 3 invalid classes].
fn levels(schema: &Value) -> Vec<(String, Value)> {
    let mut v = vec![("valid".to_string(), valid_value(schema))];
    for (label, value) in classes(schema) {
        if v.len() >= 4 {
            break;
        }
        v.push((label, value));
    }
    v
}

/// Greedy all-pairs generator: repeatedly pick the candidate tuple that covers the most
/// not-yet-covered value pairs, until every pair of inputs has every combination covered.
/// Each factor is (label, levels). Returns chosen rows as indices into each factor's levels.
pub(crate) fn all_pairs(factors: &[(String, Vec<(String, Value)>)]) -> Vec<Vec<usize>> {
    if factors.len() < 2 {
        return Vec::new();
    }
    // uncovered pairs: ((fi,li),(fj,lj)) for fi<fj
    let mut uncovered: BTreeSet<((usize, usize), (usize, usize))> = BTreeSet::new();
    for fi in 0..factors.len() {
        for fj in (fi + 1)..factors.len() {
            for li in 0..factors[fi].1.len() {
                for lj in 0..factors[fj].1.len() {
                    uncovered.insert(((fi, li), (fj, lj)));
                }
            }
        }
    }
    let cap = uncovered.len().min(200);
    let mut rows: Vec<Vec<usize>> = Vec::new();
    while !uncovered.is_empty() && rows.len() < cap {
        // candidate rows: fix each surviving uncovered pair and extend greedily
        let seed = *uncovered.iter().next().expect("non-empty");
        let mut row = vec![usize::MAX; factors.len()];
        row[seed.0.0] = seed.0.1;
        row[seed.1.0] = seed.1.1;
        // fill remaining factors with the level covering the most uncovered pairs vs assigned ones
        for f in 0..factors.len() {
            if row[f] != usize::MAX {
                continue;
            }
            let mut best = 0usize;
            let mut best_lvl = 0usize;
            for lvl in 0..factors[f].1.len() {
                let mut hits = 0usize;
                for (g, &g_lvl) in row.iter().enumerate() {
                    if g == f || g_lvl == usize::MAX {
                        continue;
                    }
                    let pair = if f < g {
                        ((f, lvl), (g, g_lvl))
                    } else {
                        ((g, g_lvl), (f, lvl))
                    };
                    if uncovered.contains(&pair) {
                        hits += 1;
                    }
                }
                if hits > best {
                    best = hits;
                    best_lvl = lvl;
                }
            }
            row[f] = best_lvl;
        }
        // mark covered
        for fi in 0..factors.len() {
            for fj in (fi + 1)..factors.len() {
                uncovered.remove(&((fi, row[fi]), (fj, row[fj])));
            }
        }
        rows.push(row);
    }
    rows
}

/// Pairwise parameter-combination cases per operation (Deep profile: bounded work).
pub(crate) fn pairwise(ctx: &Ctx) -> Result<CheckOutput> {
    let Some(spec) = spec(ctx)? else {
        return Ok(no_spec());
    };
    let qa = ctx.qa.as_ref().unwrap();
    let mut proposed = 0usize;
    let mut ops_hit = 0usize;
    'outer: for op in ops(&spec) {
        let ins = inputs(&op);
        if ins.len() < 2 {
            continue;
        }
        let factors: Vec<(String, Vec<(String, Value)>)> = ins
            .iter()
            .map(|(loc, name, schema)| {
                let label = match loc.as_str() {
                    "body" => format!("body.{name}"),
                    l => format!("{l}.{name}"),
                };
                (label, levels(schema))
            })
            .collect();
        for row in all_pairs(&factors) {
            if proposed >= CASE_CAP {
                break 'outer;
            }
            let mut parts = String::new();
            for (f, &lvl) in factors.iter().zip(&row) {
                if !parts.is_empty() {
                    parts.push_str(", ");
                }
                parts.push_str(&format!("{}={} ({})", f.0, f.1[lvl].1, f.1[lvl].0));
            }
            let tc = case(
                &op,
                Technique::Pairwise,
                "pairwise",
                format!("{}: pairwise {parts}", op.key()),
                vec![format!("Send {} {} with {parts}", op.method, op.path)],
                "each value combination behaves per its class: valid combos accepted, invalid rejected with 4xx".into(),
            );
            propose(
                qa,
                tc,
                "design-generated pairwise case; execute manually or via API runner",
            );
            proposed += 1;
            ops_hit += 1;
        }
    }
    let out = if proposed == 0 {
        CheckOutput::status(CheckStatus::Passed)
    } else {
        CheckOutput::status(CheckStatus::Skipped(format!(
            "{proposed} pairwise cases planned over {ops_hit} operations (planned only, not executed)"
        )))
    };
    if proposed > 0 {
        qa.with(|c| {
            c.notes.push(format!(
                "qa.design.pairwise: {proposed} all-pairs cases added to the plan (greedy covering array)."
            ))
        });
    }
    Ok(out)
}

/// Decision-table derivation: for operations with boolean/enum flags, propose a rule per
/// distinct rule row over up to 4 conditions (full table when small, else first rules).
pub(crate) fn decision_table(ctx: &Ctx) -> Result<CheckOutput> {
    let Some(spec) = spec(ctx)? else {
        return Ok(no_spec());
    };
    let qa = ctx.qa.as_ref().unwrap();
    let mut proposed = 0usize;
    'outer: for op in ops(&spec) {
        // conditions: boolean or small-enum inputs (the classic decision-table columns)
        let conds: Vec<(String, Vec<(String, Value)>)> = inputs(&op)
            .into_iter()
            .filter_map(|(loc, name, schema)| {
                let label = match loc.as_str() {
                    "body" => format!("body.{name}"),
                    l => format!("{l}.{name}"),
                };
                let vals: Vec<(String, Value)> = if schema_type(&schema) == "boolean" {
                    vec![
                        ("true".into(), serde_json::json!(true)),
                        ("false".into(), serde_json::json!(false)),
                    ]
                } else if let Some(vals) = schema.get("enum").and_then(|v| v.as_array())
                    && vals.len() <= 4
                {
                    vals.iter().map(|v| (v.to_string(), v.clone())).collect()
                } else {
                    return None;
                };
                Some((label, vals))
            })
            .take(4)
            .collect();
        if conds.is_empty() {
            continue;
        }
        let combos = (0..conds.iter().map(|c| c.1.len()).product::<usize>()).take(16);
        let total_combos: usize = conds.iter().map(|c| c.1.len()).product();
        for mut c_i in combos {
            if proposed >= CASE_CAP {
                break 'outer;
            }
            let mut parts = String::new();
            for cond in conds.iter().rev() {
                let idx = c_i % cond.1.len();
                c_i /= cond.1.len();
                if !parts.is_empty() {
                    parts.push_str(", ");
                }
                parts.push_str(&format!("{}={}", cond.0, cond.1[idx].0));
            }
            // decision: all-valid condition values => accept; any invalid class => reject.
            // Here all condition values come from the flag's own domain, so expected = action.
            let tc = case(
                &op,
                Technique::DecisionTable,
                "dt",
                format!("{}: rule [{parts}]", op.key()),
                vec![format!(
                    "Send {} {} with {parts} (other inputs valid)",
                    op.method, op.path
                )],
                if total_combos <= 8 {
                    "one of a complete decision table: each rule's documented action; undeclared combination must be rejected, not guessed".into()
                } else {
                    "one rule of a truncated decision table (16 of {total_combos} combos); business rules must define each".into()
                },
            );
            propose(
                qa,
                tc,
                "design-generated decision-table rule; confirm expected action with business rules, then execute",
            );
            proposed += 1;
        }
    }
    let out = if proposed == 0 {
        CheckOutput::status(CheckStatus::Passed)
    } else {
        CheckOutput::status(CheckStatus::Skipped(format!(
            "{proposed} decision-table rules planned (planned only; expected actions need business input)"
        )))
    };
    if proposed > 0 {
        qa.with(|c| {
            c.notes.push(format!(
                "qa.design.decision-table: {proposed} rules over boolean/enum flags; actions need business confirmation."
            ))
        });
    }
    Ok(out)
}

/// The coverage matrix: one row per spec operation, columns for each design technique.
/// Fills cells from what the collector already holds (executed results mark Pass/Fail);
/// everything else is explicitly Untested so gaps are visible to the QA report.
pub(crate) fn matrix(ctx: &Ctx) -> Result<CheckOutput> {
    let Some(spec) = spec(ctx)? else {
        return Ok(no_spec());
    };
    let qa = ctx.qa.as_ref().unwrap();
    let cols = [
        "Positive",
        "Boundary",
        "Equivalence",
        "Pairwise",
        "DecisionTable",
    ];
    let mut untested = 0usize;
    let mut total = 0usize;
    let op_list = ops(&spec);
    let keys: Vec<String> = op_list.iter().map(|o| o.key()).collect();
    // What techniques have per-op cases at all, and which have executed results.
    let snapshot = qa.with(|c| {
        let planned: BTreeSet<(String, String)> = c
            .cases
            .iter()
            .filter(|tc| tc.area == Area::Design || tc.area == Area::Api)
            .map(|tc| {
                (
                    tc.component.clone(),
                    match tc.technique {
                        Technique::Positive => "Positive",
                        Technique::Boundary => "Boundary",
                        Technique::Equivalence => "Equivalence",
                        Technique::Pairwise => "Pairwise",
                        Technique::DecisionTable => "DecisionTable",
                        _ => "",
                    }
                    .to_string(),
                )
            })
            .filter(|(_, t)| !t.is_empty())
            .collect();
        let executed: BTreeSet<(String, String)> = c
            .results
            .iter()
            .filter(|r| {
                matches!(
                    r.status,
                    ResultStatus::Pass | ResultStatus::Fail | ResultStatus::Flaky
                )
            })
            .filter_map(|r| {
                c.cases
                    .iter()
                    .find(|tc| tc.id == r.case_id)
                    .filter(|tc| tc.area == Area::Design || tc.area == Area::Api)
                    .map(|tc| {
                        (
                            tc.component.clone(),
                            match tc.technique {
                                Technique::Positive => "Positive",
                                Technique::Boundary => "Boundary",
                                Technique::Equivalence => "Equivalence",
                                Technique::Pairwise => "Pairwise",
                                Technique::DecisionTable => "DecisionTable",
                                _ => "",
                            }
                            .to_string(),
                        )
                    })
            })
            .filter(|(_, t)| !t.is_empty())
            .collect();
        (planned, executed)
    });
    for key in &keys {
        for col in cols {
            total += 1;
            let cell = if let Some((_, t)) = snapshot.1.iter().find(|(k, t)| k == key && t == col) {
                let _ = t;
                // executed results for this op+technique exist; Pass unless a Fail exists (CoverageMatrix::set keeps Fail sticky)
                Cell::Pass
            } else if snapshot.0.iter().any(|(k, t)| k == key && t == col) {
                Cell::Untested
            } else {
                Cell::Untested
            };
            if cell == Cell::Untested {
                untested += 1;
            }
            qa.with(|c| c.coverage.set(key, col, cell));
        }
    }
    // Fail cells: any executed Failed result for op+technique flips the cell.
    let fails = qa.with(|c| {
        c.results
            .iter()
            .filter(|r| r.status == ResultStatus::Fail)
            .filter_map(|r| {
                c.cases
                    .iter()
                    .find(|tc| tc.id == r.case_id)
                    .filter(|tc| tc.area == Area::Design || tc.area == Area::Api)
                    .map(|tc| {
                        (
                            tc.component.clone(),
                            match tc.technique {
                                Technique::Positive => "Positive",
                                Technique::Boundary => "Boundary",
                                Technique::Equivalence => "Equivalence",
                                Technique::Pairwise => "Pairwise",
                                Technique::DecisionTable => "DecisionTable",
                                _ => "",
                            }
                            .to_string(),
                        )
                    })
            })
            .filter(|(_, t)| !t.is_empty())
            .collect::<Vec<_>>()
    });
    for (k, t) in fails {
        qa.with(|c| c.coverage.set(&k, &t, Cell::Fail));
    }
    let pct = if total > 0 {
        100.0 * (total - untested) as f64 / total as f64
    } else {
        100.0
    };
    let note = format!(
        "qa.design.matrix: {} spec operations x {} techniques, {pct:.0}% executed, {untested} cells untested.",
        keys.len(),
        cols.len()
    );
    qa.with(|c| c.notes.push(note));
    let status = if keys.is_empty() {
        CheckStatus::NotApplicable("spec exposes no operations".into())
    } else if untested == 0 {
        CheckStatus::Passed
    } else {
        CheckStatus::Skipped(format!(
            "{untested}/{total} coverage cells untested (matrix written to the QA report)"
        ))
    };
    Ok(CheckOutput::status(status))
}

#[cfg(test)]
mod tests {
    use super::all_pairs;
    use serde_json::Value;

    fn f(name: &str, n: usize) -> (String, Vec<(String, Value)>) {
        (
            name.to_string(),
            (0..n)
                .map(|i| (format!("l{i}"), Value::from(i as i64)))
                .collect(),
        )
    }

    #[test]
    fn all_pairs_covers_every_pair() {
        let factors = vec![f("a", 3), f("b", 2), f("c", 4)];
        let rows = all_pairs(&factors);
        assert!(!rows.is_empty());
        for fi in 0..factors.len() {
            for fj in (fi + 1)..factors.len() {
                for li in 0..factors[fi].1.len() {
                    for lj in 0..factors[fj].1.len() {
                        assert!(
                            rows.iter().any(|r| r[fi] == li && r[fj] == lj),
                            "pair (({fi},{li}),({fj},{lj})) uncovered"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn all_pairs_rows_are_full_length() {
        let factors = vec![f("a", 2), f("b", 3)];
        for r in all_pairs(&factors) {
            assert_eq!(r.len(), 2);
            assert!(r.iter().all(|&x| x != usize::MAX));
        }
    }

    #[test]
    fn all_pairs_needs_two_factors() {
        assert!(all_pairs(&[f("a", 2)]).is_empty());
        assert!(all_pairs(&[]).is_empty());
    }
}
