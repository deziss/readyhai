//! Explorer: turns planned cases into real HTTP requests, judges them with the oracle, re-runs
//! safe failures to detect flakiness, and writes down exactly what was sent (reproduction curl)
//! and seen.

pub mod auth;
pub mod bootstrap;
pub mod builder;
pub mod clients;
pub mod credentials;
pub mod delete;
pub mod dispatch;
pub mod http;
pub mod probe;
pub mod subcases;

#[cfg(test)]
pub(crate) mod fixture;

#[cfg(test)]
mod tests;

pub(crate) use auth::role_of;
pub use auth::{Auth, Bearer, ResolvedAuth, auth_for, resolve_auth};
pub use bootstrap::{LoginBootstrap, LoginMode};
pub use builder::{
    RequestSpec, body_and_type, build_request, curl_auth_arg, curl_auth_args_for, curl_for,
    curl_for_auth, is_mutating, is_safe_method, normalize_component, normalize_method,
    payload_pairs, sanitize_custom_headers, validate_content_type,
};
pub use clients::{
    Clients, Followed, MAX_REDIRECTS, METHODS, OutReq, Seen, follows_redirects, needs_validated_tls,
};
pub use credentials::Credentials;
pub use delete::{DeleteCheck, confirm_deleted, confirm_deleted_as, confirm_deleted_resolved};
pub use dispatch::{
    CaseGate, ExecOptions, NEXT_STEP_AUTH_WALL, evidence_rel_path, execute_cases,
    execute_cases_gated, execute_cases_with,
};
pub use probe::{ProbeOutcome, send_with_probe_oracle};
