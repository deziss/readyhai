//! Regressive Network Testing & Flakiness Diagnostic Engine.

pub mod audit;
pub mod curl;
pub mod har;
pub mod ip;
pub mod multi_region;
pub mod regress;
pub mod tls;
pub mod types;
pub mod utils;

#[cfg(test)]
mod tests;

// Re-export public API symbols so existing callers experience zero breaking changes
#[allow(unused_imports)]
pub use self::audit::*;
#[allow(unused_imports)]
pub use self::curl::*;
#[allow(unused_imports)]
pub use self::har::*;
#[allow(unused_imports)]
pub use self::ip::*;
#[allow(unused_imports)]
pub use self::multi_region::*;
#[allow(unused_imports)]
pub use self::regress::*;
#[allow(unused_imports)]
pub use self::tls::*;
#[allow(unused_imports)]
pub use self::types::*;
#[allow(unused_imports)]
pub use self::utils::*;
