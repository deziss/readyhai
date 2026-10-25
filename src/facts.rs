//! TargetFacts: what is in the snapshot. Computed once, shared by checks.
//! Paths are relative to the snapshot root, '/'-separated.
use serde::Serialize;

#[derive(Debug, Default, Clone, Serialize)]
pub struct Facts {
    pub dockerfiles: Vec<String>,
    pub compose_files: Vec<String>,
    /// YAML files that contain at least one k8s object (apiVersion + kind).
    pub k8s_files: Vec<String>,
    /// requirements*.txt
    pub requirement_files: Vec<String>,
    pub pyprojects: Vec<String>,
    pub package_jsons: Vec<String>,
    pub lockfiles: Vec<String>,
    /// Jenkinsfile*, .github/workflows/*.y*ml, .gitlab-ci.yml
    pub ci_files: Vec<String>,
    pub has_readme: bool,
    pub has_tests: bool,
    pub has_health_route: bool,
    pub has_otel: bool,
    /// Detected web framework (fastapi, flask, django, express, ...), if any.
    pub web_framework: Option<String>,
    /// Python/Node dependency counts across manifests (for CVE coverage honesty).
    pub total_deps: usize,
    pub unpinned_deps: usize,
}
