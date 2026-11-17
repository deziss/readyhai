//! QA report generation, rendering, and export formats.

pub mod dispatch;
pub mod exporters;
pub mod helpers;
pub mod html;
pub mod markdown;

#[cfg(test)]
pub(crate) mod tests;

#[allow(unused_imports)]
pub use dispatch::{QA_FORMATS, owner_user, render_pdf, write_formats};

#[allow(unused_imports)]
pub use exporters::{gitlab_json, jira_csv, testrail_csv, xray_csv};

#[allow(unused_imports)]
pub use helpers::{
    csv_field, csv_neutralize, jira_code, jira_priority, jira_text, md_fence, md_inline, md_lines,
};

#[allow(unused_imports)]
pub use html::qa_html;

#[allow(unused_imports)]
pub use markdown::markdown;
