use super::credentials::Credentials;
use crate::agent::types::PlannedCase;

pub const FORGED_TOKEN: &str = "forged.signature.token123";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    None,
    Forged,
    Role(String),
}

/// Explicit `role` wins; legacy cases (no role) are inferred from the title/hint like before.
pub fn auth_for(case: &PlannedCase) -> Auth {
    if let Some(r) = case
        .role
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
    {
        return match r.to_ascii_lowercase().as_str() {
            "anon" | "anonymous" | "none" | "unauthenticated" | "raw_jwt" => Auth::None,
            "forged" => Auth::Forged,
            _ => Auth::Role(r.to_string()),
        };
    }
    let title = case.title.to_ascii_lowercase();
    let hint = case.input_hint.to_ascii_lowercase();
    if title.contains("forged") {
        return Auth::Forged;
    }
    if case.technique == "authz"
        && (title.contains("unauth")
            || hint.contains("without auth")
            || hint.contains("no auth")
            || case.expected_status.is_some_and(|s| s == 401 || s == 403)
            || case.component.starts_with("/."))
    {
        return Auth::None;
    }
    if case.technique == "authz" {
        return Auth::None;
    }
    Auth::Role("user".into())
}

/// An `Authorization: Bearer ...` value ready to send. `real` = it is a configured test
/// credential (RH_<ROLE>_TOKEN), not the public forged-token constant.
#[derive(Clone)]
pub struct Bearer {
    pub header: String,
    pub real: bool,
}

impl std::fmt::Debug for Bearer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bearer(real={}, ..)", self.real)
    }
}

pub struct ResolvedAuth {
    pub bearer: Option<Bearer>,
    pub extra_headers: Vec<(String, String)>,
    pub authenticated: bool,
    pub real: bool,
    pub note: Option<String>,
}

pub fn resolve_auth(auth: &Auth, creds: &Credentials) -> ResolvedAuth {
    match auth {
        Auth::None => ResolvedAuth {
            bearer: None,
            extra_headers: vec![],
            authenticated: false,
            real: false,
            note: None,
        },
        Auth::Forged => ResolvedAuth {
            bearer: Some(Bearer {
                header: format!("Bearer {FORGED_TOKEN}"),
                real: false,
            }),
            extra_headers: vec![],
            authenticated: true,
            real: false,
            note: None,
        },
        Auth::Role(r) => {
            let bearer = creds.token(r).map(|t| Bearer {
                header: format!("Bearer {t}"),
                real: true,
            });
            let mut extra_headers = Vec::new();
            if let Some(ck) = creds.cookie(r) {
                extra_headers.push(("Cookie".into(), ck.to_string()));
            }
            if let Some((hk, hv)) = creds.header(r) {
                extra_headers.push((hk.to_string(), hv.to_string()));
            }
            let authenticated = bearer.is_some() || !extra_headers.is_empty();
            if authenticated {
                ResolvedAuth {
                    bearer,
                    extra_headers,
                    authenticated: true,
                    real: true,
                    note: None,
                }
            } else {
                ResolvedAuth {
                    bearer: None,
                    extra_headers: vec![],
                    authenticated: false,
                    real: false,
                    note: Some(format!(
                        "no credential for role '{r}': request sent without Authorization (set {})",
                        Credentials::env_var(r)
                    )),
                }
            }
        }
    }
}

/// Role that sent `spec` (the same role deletes what it created, when a token is configured).
pub(crate) fn role_of(auth: &Auth) -> Option<&str> {
    match auth {
        Auth::Role(r) => Some(r.as_str()),
        _ => None,
    }
}
