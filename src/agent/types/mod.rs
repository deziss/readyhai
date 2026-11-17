//! Wire/storage types of the agent. Everything added after the first release is `#[serde(default)]`
//! so reports persisted by older builds still load.
//!
//! Also home of the small shared run-lifecycle API that other agent modules call without any
//! plumbing: the [`CreatedLedger`] (resources a run created, for teardown), the [`CancelToken`]
//! registry ([`request_cancel`]) and the profile depth helper ([`profile_case_cap`]).

pub mod change;
pub mod created_ledger;
pub mod defaults;
pub mod discovery;
pub mod execution;
#[cfg(test)]
pub mod fixtures;
pub mod lifecycle;
pub mod planning;
pub mod reports;
#[cfg(test)]
mod tests;
pub mod verification;

pub use change::*;
pub use created_ledger::*;
pub use defaults::*;
pub use discovery::*;
pub use execution::*;
pub use lifecycle::*;
pub use planning::*;
pub use reports::*;
pub use verification::*;
