//! Shared plumbing for the test-design checks: load the spec, register a generated case as
//! planned-but-not-executed, and small schema helpers (own copies so the module stays free of
//! runner internals).
use crate::ctx::Ctx;
use crate::model::{CheckOutput, CheckStatus};
use crate::qa::QaCtx;
use crate::qa::api::spec::{Op, Spec};
use crate::qa::model::*;
use anyhow::Result;
use serde_json::Value;

/// Cases one design check registers at most (keeps reports readable on huge specs).
pub(crate) const CASE_CAP: usize = 400;
/// Parameters examined per operation.
pub(crate) const PARAM_CAP: usize = 8;

/// Load the spec. Ok(None) = no QA context or no spec configured/discoverable.
pub(crate) fn spec(ctx: &Ctx) -> Result<Option<Spec>> {
    crate::qa::api::spec::load(ctx)
}

/// No spec = the check cannot propose anything: report NotApplicable, never a silent pass.
pub(crate) fn no_spec() -> CheckOutput {
    CheckOutput::status(CheckStatus::NotApplicable(
        "no OpenAPI spec (--spec or a discoverable openapi.json); test-design generation needs one"
            .into(),
    ))
}

/// Register a generated design case AND a Skipped result for it: the case documents a design
/// technique a human (or a later automated runner) still has to execute. It appears in the
/// plan and the coverage matrix but never counts as executed evidence.
pub(crate) fn propose(qa: &QaCtx, case: TestCase, why: &str) {
    let id = case.id.clone();
    qa.with(|c| {
        if !c.cases.iter().any(|x| x.id == id) {
            c.cases.push(case);
            c.results.push(TestResult {
                case_id: id,
                status: ResultStatus::Skipped,
                actual: why.to_string(),
                duration_ms: 0,
                attempts: 1,
                evidence: Vec::new(),
                defect_id: None,
            });
        }
    });
}

pub(crate) fn case(
    op: &Op,
    technique: Technique,
    suffix: &str,
    title: String,
    steps: Vec<String>,
    expected: String,
) -> TestCase {
    TestCase {
        id: format!("design.{suffix}.{}", op.key()),
        area: Area::Design,
        technique,
        title,
        priority: Priority::P2,
        component: op.key(),
        role: None,
        steps,
        expected,
        source: CaseSource::Deterministic,
    }
}

/// Resolve a numeric keyword straight or through one level of common wrappers.
pub(crate) fn num(s: &Value, k: &str) -> Option<f64> {
    if let Some(n) = s.get(k).and_then(|v| v.as_f64()) {
        return Some(n);
    }
    for w in ["items", "additionalProperties", "schema"] {
        if let Some(inner) = s.get(w)
            && let Some(n) = inner.get(k).and_then(|v| v.as_f64())
        {
            return Some(n);
        }
    }
    None
}

pub(crate) fn schema_type(s: &Value) -> &str {
    // oneOf/anyOf schemas: use the first branch's type when all branches agree.
    for k in ["type", "items"] {
        if let Some(t) = s.get(k).and_then(|v| v.as_str()) {
            return t;
        }
    }
    if let Some(Value::String(t)) = s.get("items").and_then(|v| v.get("type")) {
        return t.as_str();
    }
    for k in ["oneOf", "anyOf", "allOf"] {
        if let Some(arr) = s.get(k).and_then(|v| v.as_array())
            && let Some(first) = arr.first()
        {
            return match first.get("type").and_then(|v| v.as_str()) {
                Some(t) => t,
                None => "object",
            };
        }
    }
    if s.get("enum").is_some() {
        return "string";
    }
    if s.get("properties").is_some() {
        return "object";
    }
    "object"
}

/// Representative valid value for a schema (used as the equivalence "valid class" input).
pub(crate) fn valid_value(s: &Value) -> Value {
    if let Some(e) = s
        .get("enum")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
    {
        return e.clone();
    }
    match schema_type(s) {
        "integer" => match num(s, "minimum") {
            Some(m) => serde_json::json!(m.ceil() as i64),
            None => serde_json::json!(1),
        },
        "number" => match num(s, "minimum") {
            Some(m) => serde_json::json!(m),
            None => serde_json::json!(1.5),
        },
        "boolean" => serde_json::json!(true),
        "object" => serde_json::json!({}),
        "array" => {
            let n = num(s, "minItems").unwrap_or(0.0).clamp(0.0, 20.0) as usize;
            serde_json::json!(vec![serde_json::json!("x"); n])
        }
        _ => {
            let min = num(s, "minLength").unwrap_or(1.0).max(1.0) as usize;
            let mut v = "a".repeat(min.min(50));
            if let Some(pat) = s.get("pattern").and_then(|p| p.as_str()) {
                v = format!("{v} (must match pattern {pat})");
            }
            serde_json::Value::String(v)
        }
    }
}

/// Operations examined per check (spec order; the plan's risk ranking already covers ordering
/// of execution elsewhere).
pub(crate) fn ops(spec: &Spec) -> Vec<Op> {
    spec.ops.iter().take(60).cloned().collect()
}

/// Edge list for one numeric or length-bounded schema: (label, value, expect-valid).
pub(crate) fn boundaries(s: &Value) -> Vec<(String, Value, bool)> {
    let mut v = vec![];
    let t = schema_type(s);
    if matches!(t, "integer" | "number") {
        let int = t == "integer";
        if let Some(m) = num(s, "minimum") {
            let d = |f: f64| {
                if int {
                    serde_json::json!(f as i64)
                } else {
                    serde_json::json!(f)
                }
            };
            v.push((format!("{} - 1 (below minimum {m})", m), d(m - 1.0), false));
            v.push((format!("minimum {m}"), d(m), true));
            v.push(("minimum + 1".into(), d(m + 1.0), true));
        }
        if let Some(m) = num(s, "maximum") {
            let d = |f: f64| {
                if int {
                    serde_json::json!(f as i64)
                } else {
                    serde_json::json!(f)
                }
            };
            v.push(("maximum - 1".into(), d(m - 1.0), true));
            v.push((format!("maximum {m}"), d(m), true));
            v.push((
                format!("maximum + 1 (above maximum {m})"),
                d(m + 1.0),
                false,
            ));
        }
        if let Some(m) = num(s, "exclusiveMinimum") {
            v.push((
                format!("exactly exclusiveMinimum {m}"),
                d_edge(m, int),
                false,
            ));
        }
        if let Some(m) = num(s, "multipleOf")
            && m > 1.0
        {
            v.push((
                format!("{} (not a multiple of {m})", m + 1.0),
                d_edge(m + 1.0, int),
                false,
            ));
        }
    }
    if matches!(t, "string" | "array") {
        let (lo_k, hi_k) = if t == "string" {
            ("minLength", "maxLength")
        } else {
            ("minItems", "maxItems")
        };
        let unit = |n: f64| -> Value {
            if t == "string" {
                Value::String("a".repeat(n.max(0.0) as usize))
            } else {
                serde_json::json!(vec![serde_json::json!("x"); n.max(0.0) as usize])
            }
        };
        if let Some(m) = num(s, lo_k) {
            if m > 0.0 {
                v.push((
                    format!("{} {t} items/chars (below {lo_k} {m})", m - 1.0),
                    unit(m - 1.0),
                    false,
                ));
            }
            v.push((format!("{lo_k} {m} exactly"), unit(m), true));
            v.push((format!("{lo_k} + 1"), unit(m + 1.0), true));
        }
        if let Some(m) = num(s, hi_k) {
            v.push((format!("{hi_k} - 1"), unit(m - 1.0), true));
            v.push((format!("{hi_k} {m} exactly",), unit(m), true));
            if (m as usize) < 300 {
                v.push((
                    format!("{} {t} items/chars (above {hi_k} {m})", m + 1.0),
                    unit(m + 1.0),
                    false,
                ));
            }
        }
    }
    v.truncate(10);
    v
}

fn d_edge(f: f64, int: bool) -> Value {
    if int {
        serde_json::json!(f as i64)
    } else {
        serde_json::json!(f)
    }
}

/// (kind, value) invalid inputs for one schema: wrong type, out-of-enum and each violated bound.
pub(crate) fn classes(s: &Value) -> Vec<(String, Value)> {
    let t = schema_type(s);
    let mut v = vec![("wrong type".to_string(), wrong_type(t))];
    if let Some(vals) = s.get("enum").and_then(|v| v.as_array())
        && !vals
            .iter()
            .any(|x| x.as_str() == Some("readyhai-not-in-enum"))
    {
        v.push((
            format!("not among {} enum values", vals.len()),
            serde_json::json!("readyhai-not-in-enum"),
        ));
    }
    for (label, value, valid) in boundaries(s) {
        if !valid {
            v.push((label, value));
        }
    }
    v.truncate(8);
    v
}

fn wrong_type(t: &str) -> Value {
    match t {
        "string" => serde_json::json!(12345),
        "integer" | "number" => serde_json::json!("not-a-number"),
        "boolean" => serde_json::json!("maybe"),
        "array" => serde_json::json!("not-an-array"),
        _ => serde_json::json!("not-an-object"),
    }
}

/// One (location, name, schema) input per parameter, plus body properties.
pub(crate) fn inputs(op: &Op) -> Vec<(String, String, Value)> {
    let mut v: Vec<(String, String, Value)> = op
        .params
        .iter()
        .take(PARAM_CAP)
        .map(|p| (p.loc.clone(), p.name.clone(), p.schema.clone()))
        .collect();
    if let Some(b) = &op.body
        && let Some(props) = b.get("properties").and_then(|p| p.as_object())
    {
        for (name, schema) in props.iter().take(PARAM_CAP) {
            v.push(("body".into(), name.clone(), schema.clone()));
        }
    }
    v.truncate(24);
    v
}

/// Boundary-value analysis: for every bounded input, propose at-bound / just-inside /
/// just-outside cases with the expected accept-or-reject outcome.
pub(crate) fn boundary(ctx: &Ctx) -> Result<CheckOutput> {
    let Some(spec) = spec(ctx)? else {
        return Ok(no_spec());
    };
    let total = ops(&spec).len();
    let mut proposed = 0usize;
    let mut ops_hit = 0usize;
    for op in ops(&spec) {
        if proposed >= CASE_CAP {
            break;
        }
        let mut hit = false;
        for (loc, name, schema) in inputs(&op) {
            for (label, value, valid) in boundaries(&schema) {
                if proposed >= CASE_CAP {
                    break;
                }
                let where_ = match loc.as_str() {
                    "body" => format!("body field {name}"),
                    l => format!("{l} {name}"),
                };
                let tc = case(
                    &op,
                    Technique::Boundary,
                    "bva",
                    format!("{}: {where_} = {label}", op.key()),
                    vec![format!(
                        "Send {} {} with {where_} = {value}",
                        op.method, op.path
                    )],
                    if valid {
                        "accepted (on/inside the boundary)".into()
                    } else {
                        "rejected with 4xx (outside the boundary), not 5xx".into()
                    },
                );
                propose(
                    ctx.qa.as_ref().unwrap(),
                    tc,
                    "design-generated boundary case; execute manually or via API runner",
                );
                proposed += 1;
                hit = true;
            }
        }
        if hit {
            ops_hit += 1;
        }
    }
    // Zero proposals means "passed" only if there was something to inspect: a spec
    // that exposes no operations was never measured, so it must not look clean.
    let out = if total == 0 {
        CheckOutput::status(CheckStatus::NotApplicable(
            "spec exposes no operations".into(),
        ))
    } else if proposed == 0 {
        CheckOutput::status(CheckStatus::Passed)
    } else {
        CheckOutput::status(CheckStatus::Skipped(format!(
            "{proposed} boundary cases planned across {ops_hit}/{total} operations (planned only, not executed)"
        )))
    };
    if proposed > 0 {
        let qa = ctx.qa.as_ref().unwrap();
        qa.with(|c| {
            c.notes.push(format!(
                "qa.design.boundary: {proposed} boundary-value cases added to the plan (capped at {CASE_CAP}); mark executed results when run."
            ));
            for op in ops(&spec) {
                c.coverage.set(
                    &op.key(),
                    "Boundary",
                    if has_bounds(&op) {
                        crate::qa::model::Cell::Untested
                    } else {
                        crate::qa::model::Cell::NotApplicable
                    },
                );
            }
        });
    }
    Ok(out)
}

fn has_bounds(op: &Op) -> bool {
    inputs(op).iter().any(|(_, _, s)| !boundaries(s).is_empty())
}

/// Equivalence-partitioning: for every input propose one valid-class case and one case per
/// invalid class (wrong type, out-of-enum, violated bound).
pub(crate) fn equivalence(ctx: &Ctx) -> Result<CheckOutput> {
    let Some(spec) = spec(ctx)? else {
        return Ok(no_spec());
    };
    let mut proposed = 0usize;
    for op in ops(&spec) {
        if proposed >= CASE_CAP {
            break;
        }
        for (loc, name, schema) in inputs(&op) {
            let where_ = match loc.as_str() {
                "body" => format!("body field {name}"),
                l => format!("{l} {name}"),
            };
            // valid class
            let valid = valid_value(&schema);
            let tc = case(
                &op,
                Technique::Equivalence,
                "eq valid",
                format!("{}: {where_} = valid {}", op.key(), schema_type(&schema)),
                vec![format!(
                    "Send {} {} with {where_} = {valid}",
                    op.method, op.path
                )],
                "accepted (representative of the valid partition)".into(),
            );
            propose(
                ctx.qa.as_ref().unwrap(),
                tc,
                "design-generated equivalence case; execute manually or via API runner",
            );
            proposed += 1;
            // invalid classes
            for (label, value) in classes(&schema) {
                if proposed >= CASE_CAP {
                    break;
                }
                let tc = case(
                    &op,
                    Technique::Equivalence,
                    "eq invalid",
                    format!("{}: {where_} invalid ({label})", op.key()),
                    vec![format!(
                        "Send {} {} with {where_} = {value}",
                        op.method, op.path
                    )],
                    format!("rejected with 4xx ({label}), never 5xx or silent accept"),
                );
                propose(
                    ctx.qa.as_ref().unwrap(),
                    tc,
                    "design-generated equivalence case; execute manually or via API runner",
                );
                proposed += 1;
            }
        }
    }
    let out = if ops(&spec).is_empty() {
        CheckOutput::status(CheckStatus::NotApplicable(
            "spec exposes no operations".into(),
        ))
    } else if proposed == 0 {
        CheckOutput::status(CheckStatus::Passed)
    } else {
        CheckOutput::status(CheckStatus::Skipped(format!(
            "{proposed} equivalence-partition cases planned (planned only, not executed)"
        )))
    };
    if proposed > 0 {
        let qa = ctx.qa.as_ref().unwrap();
        let comps: Vec<String> = ops(&spec).iter().map(|o| o.key()).collect();
        qa.with(|c| {
            c.notes.push(format!(
                "qa.design.equivalence: {proposed} equivalence-partition cases added to the plan."
            ));
            for k in comps {
                c.coverage
                    .set(&k, "Equivalence", crate::qa::model::Cell::Untested);
            }
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{boundaries, classes, valid_value};
    use serde_json::json;

    #[test]
    fn boundaries_for_numeric_range() {
        let s = json!({"type": "integer", "minimum": 1, "maximum": 10});
        let b = boundaries(&s);
        assert!(
            b.iter()
                .any(|(l, v, ok)| l.contains("minimum") && *v == json!(1) && *ok)
        );
        assert!(
            b.iter()
                .any(|(l, v, ok)| l.contains("maximum") && *v == json!(10) && *ok)
        );
        assert!(b.iter().any(|(_, v, ok)| *v == json!(0) && !*ok));
        assert!(b.iter().any(|(_, v, ok)| *v == json!(11) && !*ok));
    }

    #[test]
    fn boundaries_for_string_length() {
        let s = json!({"type": "string", "minLength": 2, "maxLength": 5});
        let b = boundaries(&s);
        assert!(b.iter().any(|(_, v, ok)| *v == json!("a") && !*ok));
        assert!(b.iter().any(|(_, v, ok)| *v == json!("aaaaaa") && !*ok));
        assert!(b.iter().any(|(_, v, ok)| *v == json!("aa") && *ok));
    }

    #[test]
    fn boundaries_empty_without_constraints() {
        assert!(boundaries(&json!({"type": "string"})).is_empty());
    }

    #[test]
    fn classes_flags_wrong_type_and_enum() {
        let s = json!({"type": "string", "enum": ["a", "b"]});
        let c = classes(&s);
        assert!(c.iter().any(|(_, v)| v == &json!("readyhai-not-in-enum")));
        let s2 = json!({"type": "integer"});
        assert!(classes(&s2).iter().any(|(_, v)| v.is_string()));
    }

    #[test]
    fn valid_value_shapes() {
        assert_eq!(
            valid_value(&json!({"type": "integer", "enum": [7]})),
            json!(7)
        );
        assert!(valid_value(&json!({"type": "boolean"})).is_boolean());
        assert_eq!(
            valid_value(&json!({"type": "string", "minLength": 3})),
            json!("aaa")
        );
        assert_eq!(
            valid_value(&json!({"type": "array", "minItems": 1})),
            json!(["x"])
        );
        assert!(valid_value(&json!({"type": "object"})).is_object());
    }
}
