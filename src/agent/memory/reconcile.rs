//! Reconcile and fold run observations into persistent memory, plan hints, and atomic updates.

use std::collections::{BTreeMap, BTreeSet};

use super::observe::{ClassObs, Observation, class_of, is_cleanup, op_of_class};
use super::sanitize::{clean_ident, days_between, sev_rank};
use super::types::{
    Acceptance, DefectLine, DefectStatus, FlakyLine, KnownDefect, MAX_IDENT, MAX_LISTED, MAX_RUNS,
    Memory, RECENT_FIX_DAYS, SinceLastRun,
};
use crate::agent::triage::path_of;
use crate::agent::types::{INTEL_OPEN, INTEL_REPRODUCED, PlannedCase, TriagedDefect};

/// Lowercase alphanumeric tokens of length >= 3 (deterministic, locale-free).
fn tokens(s: &str) -> BTreeSet<String> {
    s.to_ascii_lowercase()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|t| t.len() >= 3)
        .map(str::to_string)
        .collect()
}

pub(crate) fn line(
    fp: &str,
    k: &KnownDefect,
    defect_id: Option<&str>,
    note: Option<String>,
    today: &str,
) -> DefectLine {
    DefectLine {
        fingerprint: fp.to_string(),
        rule: k.rule.clone(),
        endpoint: k.endpoint.clone(),
        methods: k.methods.clone(),
        severity: k.severity.clone(),
        status: k.status.as_str().to_string(),
        first_seen: k.first_seen.clone(),
        last_seen: k.last_seen.clone(),
        runs_seen: k.runs_seen,
        defect_id: defect_id.map(str::to_string),
        accepted: k
            .accepted
            .clone()
            .filter(|a| a.is_effective(today) || k.status != DefectStatus::Fixed),
        note,
    }
}

pub(crate) fn sort_lines(v: &mut [DefectLine]) {
    v.sort_by(|a, b| {
        (sev_rank(&a.severity), &a.endpoint, &a.rule, &a.fingerprint).cmp(&(
            sev_rank(&b.severity),
            &b.endpoint,
            &b.rule,
            &b.fingerprint,
        ))
    });
}

/// The result of folding one run into the memory.
pub struct Reconciled {
    pub memory: Memory,
    pub since: SinceLastRun,
    /// (this run's defect id, the acceptance that covers it): defects that do not block.
    pub waivers: Vec<(String, Acceptance)>,
}

impl Reconciled {
    /// Record the gate verdict of the run in its aggregate.
    pub fn set_verdict(&mut self, verdict: &str) {
        if let Some(r) = self.memory.runs.last_mut() {
            r.verdict = clean_ident(verdict, MAX_IDENT);
        }
    }

    /// Mark the defects an unexpired acceptance covers (`TriagedDefect::accepted`), so the ledger
    /// does not count them as blocking.
    pub fn apply_waivers(&self, defects: &mut [TriagedDefect]) {
        for d in defects {
            d.accepted = self
                .waivers
                .iter()
                .find(|(id, _)| *id == d.id)
                .map(|(_, a)| a.clone());
        }
    }
}

/// Fold a finished run into the memory. Pure: `today` (`YYYY-MM-DD`) and `now` (RFC 3339) are
/// inputs, so the same memory and the same run always give the same result.
///
/// * A defect seen now: new (unknown), still open (open or regressed before), regressed (fixed
///   before).
/// * A known open defect not seen now: fixed only when all its reproduction case classes ran and
///   every case passed; otherwise it stays open and is listed as not re-tested.
/// * A fixed defect drops its acceptance (it no longer applies).
pub fn reconcile(prior: &Memory, obs: &Observation, today: &str, now: &str) -> Reconciled {
    let mut mem = prior.clone();
    let mut since = SinceLastRun {
        first_run: prior.runs.is_empty() && prior.defects.is_empty(),
        previous_run: prior.runs.last().map(|r| r.run_id.clone()),
        previous_at: prior.runs.last().map(|r| r.at.clone()),
        runs_remembered: prior.runs.len(),
        regression_probes: obs.probes.clone(),
        ..Default::default()
    };
    let mut waivers = vec![];
    let seen: BTreeSet<&str> = obs.defects.iter().map(|d| d.fingerprint.as_str()).collect();

    for d in &obs.defects {
        match mem.defects.get_mut(&d.fingerprint) {
            None => {
                let k = KnownDefect {
                    rule: d.rule.clone(),
                    endpoint: d.endpoint.clone(),
                    methods: d.methods.clone(),
                    technique: d.technique.clone(),
                    severity: d.severity.clone(),
                    first_seen: today.to_string(),
                    last_seen: today.to_string(),
                    fixed_at: None,
                    status: DefectStatus::Open,
                    runs_seen: 1,
                    accepted: None,
                    repro: d.repro.clone(),
                };
                since
                    .new
                    .push(line(&d.fingerprint, &k, Some(&d.id), None, today));
                mem.defects.insert(d.fingerprint.clone(), k);
            }
            Some(k) => {
                let was = k.status;
                if was != DefectStatus::Fixed
                    && let Some(a) = k.accepted.as_ref().filter(|a| a.is_effective(today))
                {
                    waivers.push((d.id.clone(), a.clone()));
                }
                let fixed_on = k.fixed_at.clone();
                k.last_seen = today.to_string();
                k.runs_seen = k.runs_seen.saturating_add(1);
                k.severity = d.severity.clone();
                k.rule = d.rule.clone();
                k.endpoint = d.endpoint.clone();
                k.technique = d.technique.clone();
                for m in &d.methods {
                    if !k.methods.contains(m) {
                        k.methods.push(m.clone());
                    }
                }
                k.methods.sort();
                if !d.repro.is_empty() {
                    k.repro = d.repro.clone();
                }
                if was == DefectStatus::Fixed {
                    k.status = DefectStatus::Regressed;
                    k.fixed_at = None;
                    k.accepted = None;
                    let note = fixed_on.map(|d| format!("fixed on {d}, found again"));
                    since
                        .regressed
                        .push(line(&d.fingerprint, k, Some(&d.id), note, today));
                } else {
                    since
                        .still_open
                        .push(line(&d.fingerprint, k, Some(&d.id), None, today));
                }
            }
        }
    }
    for (fp, k) in mem.defects.iter_mut() {
        if seen.contains(fp.as_str()) || k.status == DefectStatus::Fixed {
            continue;
        }
        let ran = !k.repro.is_empty()
            && k.repro
                .iter()
                .all(|r| obs.classes.get(r).is_some_and(ClassObs::clean));
        if ran {
            k.status = DefectStatus::Fixed;
            k.fixed_at = Some(today.to_string());
            k.accepted = None;
            since.fixed.push(line(
                fp,
                k,
                None,
                Some("every reproduction case ran and passed".into()),
                today,
            ));
        } else {
            let any_ran = k.repro.iter().any(|r| {
                obs.classes
                    .get(r)
                    .is_some_and(|c| c.pass + c.fail + c.warn > 0)
            });
            since.not_retested.push(line(
                fp,
                k,
                None,
                Some(
                    if k.repro.is_empty() {
                        "no reproduction case is recorded for it"
                    } else if any_ran {
                        "its reproduction cases ran only in part or were not clean"
                    } else {
                        "its reproduction cases were not executed this run"
                    }
                    .into(),
                ),
                today,
            ));
        }
    }
    for (fp, k) in &mem.defects {
        if k.status == DefectStatus::Fixed {
            continue;
        }
        if let Some(a) = &k.accepted {
            let id = obs
                .defects
                .iter()
                .find(|d| d.fingerprint == *fp)
                .map(|d| d.id.as_str());
            if a.is_effective(today) {
                since.accepted.push(line(fp, k, id, None, today));
            } else {
                since.expired.push(line(
                    fp,
                    k,
                    id,
                    Some(format!(
                        "accepted by {} until {}: expired, blocking again",
                        a.by, a.expires
                    )),
                    today,
                ));
            }
        }
    }
    for l in [
        &mut since.new,
        &mut since.still_open,
        &mut since.fixed,
        &mut since.regressed,
        &mut since.accepted,
        &mut since.expired,
        &mut since.not_retested,
    ] {
        sort_lines(l);
        l.truncate(MAX_LISTED);
    }

    // flaky history: one outcome per class per run
    for (class, c) in &obs.classes {
        if is_cleanup(class) {
            continue;
        }
        if let Some(o) = c.outcome() {
            let e = mem.flaky.entry(class.clone()).or_default();
            e.operation = op_of_class(class);
            e.last_seen = today.to_string();
            e.push(o);
        }
    }
    since.known_flaky = mem
        .flaky
        .iter()
        .filter(|(_, f)| f.flaky > 0)
        .map(|(k, f)| FlakyLine {
            class: k.clone(),
            operation: f.operation.clone(),
            pass: f.pass,
            fail: f.fail,
            flaky: f.flaky,
        })
        .collect();
    since
        .known_flaky
        .sort_by(|a, b| b.flaky.cmp(&a.flaky).then(a.class.cmp(&b.class)));
    since.known_flaky.truncate(MAX_LISTED);

    // operations: the last run that executed one
    for (op, o) in &obs.ops {
        let e = mem.operations.entry(op.clone()).or_default();
        if o.executed > 0 || e.last_run.is_empty() {
            e.last_run = obs.run_id.clone();
            e.last_at = today.to_string();
            e.planned = o.planned;
            e.executed = o.executed;
            e.pass = o.pass;
            e.fail = o.fail;
            e.inconclusive = o.inconclusive;
            e.techniques = o.techniques.iter().cloned().collect();
            e.last_result = o.last_result().to_string();
        }
    }
    if let Some(b) = &obs.baselines {
        mem.baselines = b.clone();
    }

    let mut agg = obs.totals.clone();
    agg.run_id = obs.run_id.clone();
    agg.at = now.to_string();
    agg.dry_run = obs.dry_run;
    agg.planned = obs.planned as u32;
    agg.defects = obs.defects.len() as u32;
    agg.new = since.new.len() as u32;
    agg.still_open = since.still_open.len() as u32;
    agg.fixed = since.fixed.len() as u32;
    agg.regressed = since.regressed.len() as u32;
    mem.runs.push(agg);
    let n = mem.runs.len();
    if n > MAX_RUNS {
        mem.runs.drain(..n - MAX_RUNS);
    }
    mem.prune(today);
    Reconciled {
        memory: mem,
        since,
        waivers,
    }
}

// ---------------------------------------------------------------- what the planner takes from memory

/// What the planner may do with the memory: reorder, and raise k. Nothing here adds or removes a
/// case.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanHints {
    /// Case class -> fingerprints of the defects it re-tests (open, regressed, recently fixed).
    pub regression: BTreeMap<String, Vec<String>>,
    /// Operations (`METHOD endpoint`) that failed last time they ran, or have flaky classes.
    pub history_ops: BTreeSet<String>,
    /// Case classes with flaky outcomes: their failures are verified with the maximum k.
    pub flaky_classes: BTreeSet<String>,
    /// (fingerprint, rule, severity) of this host's *known-open* rows in the project
    /// vulnerability database — advisory context for prioritisation only, never a
    /// case source and never a verdict input. Ordered worst-first by the database.
    pub known_open: Vec<(String, String, String)>,
    /// Vulndb fingerprints that safe exploitation templates re-confirmed this run
    /// (opt-in engine only). Advisory: raises attention, changes nothing else.
    pub reproduced: Vec<String>,
}

impl PlanHints {
    pub fn is_empty(&self) -> bool {
        self.regression.is_empty()
            && self.history_ops.is_empty()
            && self.flaky_classes.is_empty()
            && self.known_open.is_empty()
            && self.reproduced.is_empty()
    }

    /// Fold project intel (vulnerability database + exploitation verdicts) into the
    /// memory-derived hints. Kept separate from [`PlanHints::from_memory`] so the
    /// memory path stays pure; merging is the pipeline's call. Deterministic data
    /// informing the plan — the same status as every other hint here.
    pub fn merge_intel(
        &mut self,
        known_open: Vec<(String, String, String)>,
        reproduced: Vec<String>,
    ) {
        self.known_open = known_open;
        self.reproduced = reproduced;
    }

    pub fn from_memory(m: &Memory, today: &str) -> PlanHints {
        let mut h = PlanHints::default();
        for (fp, d) in &m.defects {
            let recent_fix = d.status == DefectStatus::Fixed
                && d.fixed_at
                    .as_deref()
                    .and_then(|f| days_between(f, today))
                    .is_some_and(|n| n <= RECENT_FIX_DAYS);
            if d.status != DefectStatus::Fixed || recent_fix {
                for r in &d.repro {
                    h.regression.entry(r.clone()).or_default().push(fp.clone());
                }
                h.history_ops
                    .extend(d.methods.iter().map(|me| format!("{me} {}", d.endpoint)));
            }
        }
        for v in h.regression.values_mut() {
            v.sort();
            v.dedup();
        }
        for (op, o) in &m.operations {
            if o.last_result == "fail" {
                h.history_ops.insert(op.clone());
            }
        }
        for (class, f) in &m.flaky {
            if f.flaky > 0 {
                h.flaky_classes.insert(class.clone());
                h.history_ops.insert(op_of_class(class));
            }
        }
        h
    }

    /// The vulndb rules this run proved live with safe exploitation templates: the `reproduced`
    /// fingerprints, resolved to their rules through [`PlanHints::known_open`]. A reproduced
    /// fingerprint with no known-open row has no rule to match and is ignored (deterministic).
    fn reproduced_rules(&self) -> BTreeSet<String> {
        self.known_open
            .iter()
            .filter(|(fp, _, _)| self.reproduced.contains(fp))
            .map(|(_, rule, _)| rule.clone())
            .collect()
    }

    /// Deterministic, cheap relevance: does this open finding's rule relate to this planned
    /// case? The finding's URL is not carried in the hints, so matching uses the rule name
    /// only: normalized rule tokens matched against the case's URL-path fragments (or the
    /// whole rule appearing in the path). Deliberately not the title — rule names echo in
    /// generic titles ("server error", "access control") and would elevate everything.
    /// The second bucket of the regression mechanism — never adds or drops a case.
    fn rule_relates(rule: &str, c: &PlannedCase) -> bool {
        let rt = tokens(rule);
        if rt.is_empty() {
            return false;
        }
        let path = path_of(&c.component).to_ascii_lowercase();
        path.contains(&rule.to_ascii_lowercase()) || tokens(&path).iter().any(|t| rt.contains(t))
    }

    /// Tag the cases (`regression_of`, `history_priority`, `intel_note`) and order the plan:
    /// cases that re-test a finding the run just reproduced, then memory's regression probes
    /// (the agent's own remembered reproduction outranks advisory database context), then
    /// cases related to a merely-known-open database finding, then changed operations, then
    /// operations with a past, then the rest; each tier keeps the planner's order. Returns how
    /// many cases are regression probes. A pure reordering: the cases are the same before and
    /// after, and with no intel the order is exactly the one from before the intel tiers.
    pub fn apply(&self, cases: &mut [PlannedCase]) -> usize {
        let reproduced = self.reproduced_rules();
        for c in cases.iter_mut() {
            let class = class_of(c);
            c.regression_of = self.regression.get(&class).cloned().unwrap_or_default();
            c.history_priority = self.history_ops.contains(&op_of_class(&class))
                || self.flaky_classes.contains(&class);
            // second bucket: open/reproduced vulndb findings, matched by rule tokens.
            // A reproduced-related finding outranks a merely-open one; within a tier
            // the database's worst-first order decides which rule is recorded.
            let relates = |rule: &str| Self::rule_relates(rule, c);
            let hit_reproduced = self
                .known_open
                .iter()
                .find(|(fp, rule, _)| reproduced.contains(rule) || self.reproduced.contains(fp))
                .filter(|(_, rule, _)| relates(rule))
                .map(|(_, rule, _)| format!("{INTEL_REPRODUCED}{rule}"));
            c.intel_note = hit_reproduced.unwrap_or_else(|| {
                self.known_open
                    .iter()
                    .find(|(_, rule, _)| relates(rule))
                    .map(|(_, rule, _)| format!("{INTEL_OPEN}{rule}"))
                    .unwrap_or_default()
            });
        }
        cases.sort_by_key(|c| {
            // Same 5-tier ladder as plan_order: reproduced live > (regression probes
            // unless already tagged reproduced) > known-open > changed/history > rest.
            let rank = crate::agent::types::intel_rank(c);
            let probe = !c.regression_of.is_empty();
            let tier: u8 = match rank {
                0 => 0,
                _ if probe => 1,
                1 => 2,
                _ => 3,
            };
            (tier, c.changed_ops.is_empty(), !c.history_priority)
        });
        cases.iter().filter(|c| !c.regression_of.is_empty()).count()
    }

    /// Plan-case ids whose failures the verifier replays with the maximum k.
    pub fn flaky_case_ids(&self, cases: &[PlannedCase]) -> BTreeSet<String> {
        cases
            .iter()
            .filter(|c| self.flaky_classes.contains(&class_of(c)))
            .map(|c| c.id.clone())
            .collect()
    }
}
