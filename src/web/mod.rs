//! Web/API checks: native smoke check (incl. CSP weakness & openssl TLS audit), Schemathesis, ZAP baseline, Nuclei, Playwright.

pub mod client;
pub mod nuclei;
pub mod playwright;
pub mod schemathesis;
pub mod security_headers;
pub mod smoke;
pub mod zap;

#[cfg(test)]
mod tests;

#[allow(unused_imports)]
pub use client::discover_openapi;
#[allow(unused_imports)]
pub use nuclei::parse_nuclei;
#[allow(unused_imports)]
pub use playwright::parse_playwright;
#[cfg(test)]
#[allow(unused_imports)]
pub use zap::parse_zap;
#[allow(unused_imports)]
pub use zap::parse_zap_report;

use crate::checks::Check;
use crate::model::*;

pub fn checks() -> Vec<Check> {
    let w = &[TargetKind::Web];
    vec![
        Check::new(
            "web.smoke",
            "Web smoke: status, headers, cookies, CORS, health",
            w,
            Profile::Quick,
            smoke::smoke,
        ),
        Check::new(
            "tool.schemathesis",
            "Schemathesis API fuzzing (OpenAPI)",
            w,
            Profile::Standard,
            schemathesis::schemathesis,
        )
        .tool("schemathesis"),
        Check::new(
            "tool.zap_baseline",
            "ZAP baseline (passive)",
            w,
            Profile::Standard,
            zap::zap,
        )
        .tool("zap"),
        Check::new(
            "tool.nuclei",
            "Nuclei template scanner (CVE, misconfig, exposure, takeover)",
            w,
            Profile::Standard,
            nuclei::nuclei,
        )
        .tool("nuclei"),
        Check::new(
            "tool.zap_active",
            "ZAP full active scan (intrusive)",
            w,
            Profile::Deep,
            zap::zap_active,
        )
        .tool("zap")
        .intrusive(),
        Check::new(
            "tool.playwright",
            "Browser crawl: JS errors, failed requests, broken links (Playwright)",
            w,
            Profile::Standard,
            playwright::playwright,
        )
        .tool("playwright"),
    ]
}
