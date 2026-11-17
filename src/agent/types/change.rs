//! Code diff change impact, affected operations, and coverage analysis models.

use serde::{Deserialize, Serialize};

/// An operation of the OpenAPI spec that the code diff touched.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangedOperation {
    /// `GET /search`, as the spec writes it.
    pub operation: String,
    /// `route`: a route extracted from a changed file matched it. `file`: a changed handler file
    /// maps to it (operationId or resource name) but its routes could not be extracted ("file
    /// changed, routes unknown").
    pub via: String,
    /// The changed files that lead to it.
    pub files: Vec<String>,
    pub detail: String,
}

/// How the run covered one changed operation.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ChangedOpCoverage {
    pub operation: String,
    pub planned: usize,
    /// Planned cases that were sent (not SKIPPED).
    pub executed: usize,
    pub pass: usize,
    pub fail: usize,
    /// WARN, INCONCLUSIVE or BLOCKED: sent, but not a clean answer.
    pub inconclusive: usize,
    /// Techniques of the executed cases (authz, boundary, negative, injection, state_transition).
    pub techniques: Vec<String>,
    pub case_ids: Vec<String>,
}

/// The "Change impact" of a change-aware run: what the diff touched, which operations that maps
/// to, what could not be mapped, and how the changed operations were covered. Deterministic; the
/// optional retriever notes are the only advisory part and are kept apart.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ChangeImpact {
    /// applied | no_changes | skipped | failed
    pub status: String,
    pub repo: String,
    pub diff_base: String,
    /// Changed files, at most `change::MAX_LISTED_FILES` of them.
    #[serde(default)]
    pub changed_files: Vec<String>,
    /// All of them (the list above is capped).
    #[serde(default)]
    pub changed_files_total: usize,
    #[serde(default)]
    pub operations: Vec<ChangedOperation>,
    /// Changed files that map to no operation (tests, docs, shared code, routes not in the spec),
    /// at most `change::MAX_LISTED_FILES` of them.
    #[serde(default)]
    pub unmapped_files: Vec<String>,
    /// All of them (the list above is capped).
    #[serde(default)]
    pub unmapped_total: usize,
    #[serde(default)]
    pub coverage: Vec<ChangedOpCoverage>,
    #[serde(default)]
    pub notes: Vec<String>,
    /// Text from the optional context retriever. UNTRUSTED and advisory: it never adds a case and
    /// never changes a verdict.
    #[serde(default)]
    pub context_notes: Vec<String>,
}
