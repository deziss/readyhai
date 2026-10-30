//! Shared data model. Every check, parser and report speaks these types.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Lenient parse for tool outputs ("ERROR", "warning", "Negligible", "3"...).
    pub fn parse(s: &str) -> Severity {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" | "fatal" | "4" => Severity::Critical,
            "high" | "error" | "3" => Severity::High,
            "medium" | "moderate" | "warning" | "warn" | "2" => Severity::Medium,
            "low" | "1" => Severity::Low,
            _ => Severity::Info,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Security,
    SupplyChain,
    Reliability,
    Observability,
    Quality,
    Operability,
    Performance,
}

impl Category {
    pub const ALL: [Category; 7] = [
        Category::Security,
        Category::SupplyChain,
        Category::Reliability,
        Category::Quality,
        Category::Observability,
        Category::Operability,
        Category::Performance,
    ];
    pub fn as_str(&self) -> &'static str {
        match self {
            Category::Security => "security",
            Category::SupplyChain => "supply_chain",
            Category::Reliability => "reliability",
            Category::Observability => "observability",
            Category::Quality => "quality",
            Category::Operability => "operability",
            Category::Performance => "performance",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FindingStatus {
    #[default]
    New,
    Existing,
    Suppressed,
}

/// One problem. Never put secret values in any field: tools that emit
/// matched text must be parsed so that only rule/location survive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub fingerprint: String,
    /// Check that produced it, e.g. "readiness.dockerfile", "tool.grype".
    pub check: String,
    /// Stable rule id, e.g. "readiness.dockerfile.no_user", "CVE-2024-1234", "secrets.aws-access-token".
    pub rule: String,
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    #[serde(default)]
    pub detail: String,
    /// "path:line", "path", URL, host or component.
    pub location: String,
    #[serde(default)]
    pub ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epss: Option<f64>,
    #[serde(default)]
    pub kev: bool,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub status: FindingStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppressed_reason: Option<String>,
    /// Identity input for the fingerprint (defaults to location). Use something
    /// that survives unrelated edits: no line numbers for SAST, no version for vulns.
    #[serde(skip)]
    pub fp_key: Option<String>,
}

impl Finding {
    pub fn new(
        check: &str,
        rule: &str,
        category: Category,
        severity: Severity,
        title: impl Into<String>,
        location: impl Into<String>,
    ) -> Self {
        Finding {
            fingerprint: String::new(),
            check: check.to_string(),
            rule: rule.to_string(),
            category,
            severity,
            title: title.into(),
            detail: String::new(),
            location: location.into(),
            ids: vec![],
            package: None,
            version: None,
            fix_version: None,
            epss: None,
            kev: false,
            remediation: String::new(),
            status: FindingStatus::New,
            suppressed_reason: None,
            fp_key: None,
        }
    }
    pub fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = d.into();
        self
    }
    pub fn remediation(mut self, r: impl Into<String>) -> Self {
        self.remediation = r.into();
        self
    }
    pub fn fp_key(mut self, k: impl Into<String>) -> Self {
        self.fp_key = Some(k.into());
        self
    }
    pub fn ids(mut self, ids: Vec<String>) -> Self {
        self.ids = ids;
        self
    }
    pub fn package(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.package = Some(name.into());
        self.version = Some(version.into());
        self
    }
    /// Path part of `location` (strips a trailing ":line").
    pub fn path(&self) -> &str {
        match self.location.rsplit_once(':') {
            Some((p, l)) if !l.is_empty() && l.chars().all(|c| c.is_ascii_digit()) => p,
            _ => &self.location,
        }
    }
    /// Fill `fingerprint` from rule + fp_key (or location).
    pub fn finalize(&mut self) {
        let key = self.fp_key.clone().unwrap_or_else(|| self.location.clone());
        let mut h = Sha256::new();
        h.update(self.rule.as_bytes());
        h.update(b"\0");
        h.update(key.as_bytes());
        self.fingerprint = hex::encode(&h.finalize()[..12]);
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "state", content = "reason", rename_all = "snake_case")]
pub enum CheckStatus {
    Passed,
    Failed,
    Partial(String),
    Skipped(String),
    NotApplicable(String),
    Errored(String),
}

impl CheckStatus {
    pub fn label(&self) -> &'static str {
        match self {
            CheckStatus::Passed => "passed",
            CheckStatus::Failed => "failed",
            CheckStatus::Partial(_) => "partial",
            CheckStatus::Skipped(_) => "skipped",
            CheckStatus::NotApplicable(_) => "not_applicable",
            CheckStatus::Errored(_) => "errored",
        }
    }
    pub fn reason(&self) -> Option<&str> {
        match self {
            CheckStatus::Partial(r)
            | CheckStatus::Skipped(r)
            | CheckStatus::NotApplicable(r)
            | CheckStatus::Errored(r) => Some(r),
            _ => None,
        }
    }
}

/// What a check returns. `status: None` means "derive it": Failed if any
/// findings, else Passed.
#[derive(Debug, Default)]
pub struct CheckOutput {
    pub status: Option<CheckStatus>,
    pub findings: Vec<Finding>,
}

impl CheckOutput {
    pub fn findings(findings: Vec<Finding>) -> Self {
        CheckOutput {
            status: None,
            findings,
        }
    }
    pub fn status(status: CheckStatus) -> Self {
        CheckOutput {
            status: Some(status),
            findings: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    pub status: CheckStatus,
    pub findings: usize,
    pub duration_ms: u128,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    Repo,
    Image,
    Web,
    Host,
    Android,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub kind: TargetKind,
    /// As given by the user.
    pub raw: String,
    /// Repo: source directory on disk (never scanned directly; snapshot is).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openapi: Option<String>,
    /// Host targets (ssh://user@host:port).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<HostSpec>,
    /// Android: APK/AAB on disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apk: Option<PathBuf>,
    /// Android: adb serial or host:port of a device/emulator the user attached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    Linux,
    Macos,
    Windows,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostSpec {
    pub user: String,
    pub host: String,
    pub port: u16,
    pub os: Os,
    /// Private key path (else ssh-agent / ssh config). Never stored in reports.
    #[serde(skip)]
    pub key: Option<PathBuf>,
}

/// Same-signature log/error lines grouped together ("Top errors").
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ErrorCluster {
    /// Normalized signature (ids, numbers, timestamps stripped).
    pub signature: String,
    /// One real (redacted) example line.
    pub example: String,
    pub count: usize,
    /// e.g. "web.console", "host.journal", "android.logcat", "web.http"
    pub source: String,
    pub first_seen: String,
}

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Quick,
    Standard,
    Deep,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    Pass,
    Warn,
    Fail,
}

impl Verdict {
    pub fn exit_code(&self) -> i32 {
        match self {
            Verdict::Pass => 0,
            Verdict::Warn => 1,
            Verdict::Fail => 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CategorySummary {
    pub category: String,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub new: usize,
    pub existing: usize,
    pub suppressed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub id: String,
    pub version: String,
    pub target: Target,
    pub profile: Profile,
    pub started: String,
    pub finished: String,
    pub verdict: Verdict,
    /// Human reasons for the verdict, e.g. "FAIL: 2 new critical findings".
    pub reasons: Vec<String>,
    pub categories: Vec<CategorySummary>,
    pub checks: Vec<CheckResult>,
    pub findings: Vec<Finding>,
    /// Fingerprints in the baseline that no longer appear.
    pub fixed: usize,
    pub notes: Vec<String>,
    /// Clustered runtime errors gathered during the run (logs, console, logcat).
    #[serde(default)]
    pub errors: Vec<ErrorCluster>,
    /// Senior-QA report (only for `readyhai qa` runs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qa: Option<crate::qa::model::QaReport>,
}
