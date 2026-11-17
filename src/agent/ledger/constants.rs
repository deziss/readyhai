pub const TECHNIQUES: [&str; 5] = [
    "authz",
    "boundary",
    "negative",
    "injection",
    "state_transition",
];

/// The techniques that need an input surface to exercise (see `plan::baseline`).
pub const INPUT_TECHNIQUES: [&str; 3] = ["boundary", "negative", "injection"];

/// (id, name, techniques, weight)
pub const PILLARS: [(&str, &str, &[&str], u32); 3] = [
    (
        "value",
        "Functional correctness and input handling",
        &["boundary", "negative", "state_transition"],
        30,
    ),
    (
        "authority",
        "Authorization and least privilege",
        &["authz"],
        30,
    ),
    (
        "safety",
        "Injection resistance and data safety",
        &["injection"],
        25,
    ),
];
pub const EVIDENCE_WEIGHT: u32 = 15;
/// A pillar is scored only when at least this share (percent) of its applicable cases was conclusive.
pub const MIN_PILLAR_CONFIDENCE: u32 = 50;
/// Below this overall confidence (percent) the run did not gather enough evidence to say GO or NO_GO.
pub const MIN_OVERALL_CONFIDENCE: u32 = 50;
/// The conclusive share (percent) a GO needs.
pub const FULL_CONFIDENCE: u32 = 80;
