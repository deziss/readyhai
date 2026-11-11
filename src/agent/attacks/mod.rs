//! Deterministic adversarial attack generators organized by vulnerability class.
//!
//! Each generator plans strictly grounded `PlannedCase`s derived from discovered routes,
//! OpenAPI operations, observed parameters, and configured authentication credentials, keeping
//! request budgets tight on `quick` and `diff` runs while matching specialist DAST breadth in
//! `standard` and `deep` profiles.

pub mod auth;
pub mod bopla;
pub mod injection;
pub mod logic;
