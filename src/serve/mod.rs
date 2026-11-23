//! REST API, agent studio endpoints, background workers, and quality gate servers.

pub mod agent_api;
pub mod auth;
pub mod badges;
pub mod eval_api;
pub mod guards;
pub mod network_api;
pub mod rbac;
pub mod router;
pub mod scans;
pub mod types;
pub mod worker;

#[cfg(test)]
mod tests;

// Re-export public symbols so existing callers (main.rs, mcp.rs) experience zero breaking changes
#[allow(unused_imports)]
pub use self::agent_api::*;
#[allow(unused_imports)]
pub use self::auth::*;
#[allow(unused_imports)]
pub use self::badges::*;
#[allow(unused_imports)]
pub use self::eval_api::*;
#[allow(unused_imports)]
pub use self::guards::*;
#[allow(unused_imports)]
pub use self::network_api::*;
#[allow(unused_imports)]
pub use self::rbac::*;
pub use self::router::*;
#[allow(unused_imports)]
pub use self::scans::*;
#[allow(unused_imports)]
pub use self::types::*;
#[allow(unused_imports)]
pub use self::worker::*;
