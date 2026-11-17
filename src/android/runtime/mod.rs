//! Android device runtime testing and logcat crash analysis.

pub mod adb;
pub mod logcat;

pub use adb::run_runtime;
pub use logcat::{LogScan, is_emulator, scan_logcat};
