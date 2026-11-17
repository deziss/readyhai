//! Repository hygiene checks: tracked secrets, README, tests, health route, and OpenTelemetry.

use crate::ctx::Ctx;
use crate::model::{Category, CheckOutput, Finding, Severity};
use crate::snapshot::Snapshot;

pub(crate) fn repo_check_fn(ctx: &Ctx, snap: &Snapshot) -> CheckOutput {
    const C: &str = "readiness.repo";
    let fc = &ctx.facts;
    let mk = |r: &str, cat, sev, title: &str, loc: String| {
        Finding::new(C, &format!("{C}.{r}"), cat, sev, title, loc)
    };
    let mut out = vec![];
    for d in snap.denied.iter().filter(|d| d.tracked) {
        out.push(
            mk("tracked_secret_file", Category::Security, Severity::High, "Secret-bearing file tracked in git", d.path.clone())
                .detail("Path only; the file was not read.")
                .remediation("Rotate the credentials it contains first, then remove it from the index and purge history; add it to .gitignore."),
        );
    }
    if !fc.has_readme {
        out.push(
            mk(
                "no_readme",
                Category::Operability,
                Severity::Low,
                "No README",
                ".".into(),
            )
            .remediation("Add a README with setup, run and ops notes."),
        );
    }
    if !fc.has_tests {
        out.push(
            mk(
                "no_tests",
                Category::Quality,
                Severity::Medium,
                "No tests found",
                ".".into(),
            )
            .remediation("Add automated tests and run them in CI."),
        );
    }
    if fc.web_framework.is_some() {
        if !fc.has_health_route {
            out.push(
                mk(
                    "no_health_route",
                    Category::Reliability,
                    Severity::Low,
                    "No /health route detected",
                    ".".into(),
                )
                .remediation("Expose /health (liveness) and /ready (readiness)."),
            );
        }
        if !fc.has_otel {
            out.push(
                mk(
                    "no_otel",
                    Category::Observability,
                    Severity::Low,
                    "OpenTelemetry not wired",
                    ".".into(),
                )
                .remediation("Add OpenTelemetry tracing/metrics instrumentation."),
            );
        }
    }
    CheckOutput::findings(out)
}
