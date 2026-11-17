use super::super::{AuthKind, env_var};
use super::derive::Derived;

pub fn auth_str(k: AuthKind) -> &'static str {
    match k {
        AuthKind::Bearer => "bearer",
        AuthKind::Basic => "basic",
        AuthKind::Header => "header",
        AuthKind::Cookie => "cookie",
        AuthKind::None => "none",
    }
}

pub fn q(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

pub fn list(key: &str, v: &[String]) -> String {
    match v {
        [] => format!("{key} = []\n"),
        [one] => format!("{key} = [{}]\n", q(one)),
        many => {
            let mut s = format!("{key} = [\n");
            for x in many {
                s.push_str(&format!("  {},\n", q(x)));
            }
            s.push_str("]\n");
            s
        }
    }
}

/// roles.toml text. `source` names the spec in the header comment (empty = omitted).
pub fn render(d: &Derived, source: &str) -> String {
    let mut s = String::new();
    s.push_str("# roles.toml skeleton derived by `readyhai roles init`");
    if !source.is_empty() {
        s.push_str(&format!(" from {source}"));
    }
    s.push_str(&format!(" ({} operation(s)).\n", d.operations));
    s.push_str(
        "# Values below are env var NAMES. Never write a token, password or key into this file;\n",
    );
    s.push_str("# export the variables before `readyhai qa`, with credentials of dedicated TEST accounts:\n");
    let mut vars: Vec<String> = vec![];
    for r in &d.roles {
        match r.auth {
            AuthKind::Basic => {
                vars.push(format!("{}=...", env_var(&r.name, "USER")));
                vars.push(format!("{}=...", env_var(&r.name, "PASS")));
            }
            AuthKind::Bearer | AuthKind::Header => {
                vars.push(format!("{}=...", env_var(&r.name, "TOKEN")))
            }
            AuthKind::Cookie | AuthKind::None => {}
        }
    }
    if !vars.is_empty() {
        s.push_str(&format!("#   export {}\n", vars.join(" ")));
    }
    s.push_str(
        "# allow / deny are derived from the spec's security and scope names: review them.\n",
    );
    s.push_str("# Keep this file outside the target repo, mode 0600.\n");
    for w in &d.warnings {
        s.push_str(&format!("# NOTE: {}\n", w.replace('\n', " ")));
    }
    for r in &d.roles {
        s.push('\n');
        s.push_str("[[role]]\n");
        s.push_str(&format!("name = {}\n", q(&r.name)));
        s.push_str(&format!(
            "auth = {}    # {}\n",
            q(auth_str(r.auth)),
            r.note.replace('\n', " ")
        ));
        match r.auth {
            AuthKind::Bearer => s.push_str(&format!("token_env = {}\n", q(&env_var(&r.name, "TOKEN")))),
            AuthKind::Header => {
                s.push_str(&format!(
                    "header_name = {}\n",
                    q(r.header_name.as_deref().unwrap_or("X-API-Key"))
                ));
                s.push_str(&format!("token_env = {}\n", q(&env_var(&r.name, "TOKEN"))));
            }
            AuthKind::Basic => {
                s.push_str(&format!("username_env = {}\n", q(&env_var(&r.name, "USER"))));
                s.push_str(&format!("password_env = {}\n", q(&env_var(&r.name, "PASS"))));
            }
            AuthKind::Cookie => s.push_str(&format!(
                "storage_state = {}    # Playwright storageState of a logged-in test account, relative to this file\n",
                q(&format!("{}.state.json", r.name))
            )),
            AuthKind::None => {}
        }
        s.push_str(&list("allow", &r.allow));
        s.push_str(&list("deny", &r.deny));
    }
    s
}
