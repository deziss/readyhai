use super::models::DEFAULT_ID_KEYS;
use super::vars::placeholder_names;
use super::violation::{Actor, actor_of};
use crate::agent::exec::{Credentials, normalize_method};
use crate::agent::types::StatefulStep;

/// `/items/{{id}}` -> `/items`. None when the path has no trailing placeholder segment.
fn strip_trailing_placeholder(path: &str) -> Option<String> {
    let p = path
        .split(['?', '#'])
        .next()
        .unwrap_or(path)
        .trim_end_matches('/');
    let (head, last) = p.rsplit_once('/')?;
    (last.starts_with("{{") && last.ends_with("}}")).then(|| head.to_string())
}

fn path_only(path: &str) -> String {
    let p = path
        .split(['?', '#'])
        .next()
        .unwrap_or(path)
        .trim_end_matches('/');
    if p.starts_with('/') {
        p.to_string()
    } else {
        format!("/{p}")
    }
}

/// Index of the access step: the last step that carries a violation condition.
pub(crate) fn access_index(steps: &[StatefulStep]) -> Option<usize> {
    steps.iter().rposition(|s| {
        s.violation_condition.as_deref().is_some_and(|c| {
            let t = c.trim();
            !t.starts_with("mass_assignment:")
                && !t.starts_with("business_logic:")
                && !t.starts_with("stored_xss:")
        })
    })
}

/// Everything that can be decided without sending a request. `Err` = skip the chain, with a note.
pub fn preflight(steps: &[StatefulStep], creds: &Credentials) -> Result<(), String> {
    if steps.is_empty() {
        return Err("the scenario has no steps".into());
    }
    // 1. methods: an unknown verb is rejected, never silently turned into GET
    for s in steps {
        if normalize_method(&s.method).is_none() {
            return Err(format!(
                "method '{}' in step {} is not allowed (GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE only)",
                s.method.chars().take(16).collect::<String>(),
                s.step_number
            ));
        }
    }
    // 2. every real actor needs its credential: a two-actor check with one token proves nothing
    let mut roles: Vec<String> = vec![];
    for s in steps {
        if let Actor::Role(r) = actor_of(&s.actor)
            && !roles.contains(&r)
        {
            roles.push(r);
        }
    }
    let missing: Vec<String> = roles
        .iter()
        .filter(|r| !creds.has_role(r))
        .map(|r| format!("'{r}' (set {})", Credentials::env_var(r)))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "missing credential for role {}; a stateful check needs the token of every actor it uses, nothing was sent",
            missing.join(", ")
        ));
    }
    // 3. placeholders must be produced by an earlier step before they are used
    let mut known: Vec<String> = vec![];
    for (i, s) in steps.iter().enumerate() {
        for text in std::iter::once(s.path.as_str()).chain(s.payload.as_deref()) {
            for name in placeholder_names(text) {
                // an id-like name may be filled by the default extraction of any earlier step
                let ok = known.iter().any(|k| k.eq_ignore_ascii_case(&name))
                    || (i > 0 && DEFAULT_ID_KEYS.contains(&name.to_ascii_lowercase().as_str()));
                if !ok {
                    return Err(format!(
                        "unresolved placeholder {{{{{name}}}}} in step {}: no earlier step extracts it",
                        s.step_number
                    ));
                }
            }
        }
        known.extend(s.extract_vars.iter().flatten().cloned());
    }
    // 4. shape of a cross-actor check
    if let Some(ai) = access_index(steps) {
        if ai == 0 {
            return Err("the access step has no creating step before it".into());
        }
        let creator = &steps[0];
        let access = &steps[ai];
        let (ca, aa) = (actor_of(&creator.actor), actor_of(&access.actor));
        if ca.is_anon() {
            return Err("the creating step is anonymous: there is no owner to isolate from".into());
        }
        if ca == aa {
            return Err(format!(
                "both steps use the same actor '{}': that is not a cross-actor check",
                creator.actor
            ));
        }
        match strip_trailing_placeholder(&access.path) {
            None => {
                return Err(
                    "the access step does not address the created resource (no trailing {{id}} segment)"
                        .into(),
                );
            }
            Some(base) => {
                if base != path_only(&creator.path) {
                    return Err(format!(
                        "the creating step and the access step are not the same resource: {} vs {}",
                        path_only(&creator.path),
                        base
                    ));
                }
            }
        }
    }
    Ok(())
}
