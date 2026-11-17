//! Offline environment flag and process-wide test locks.

#[cfg(test)]
pub static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// True when READYHAI_OFFLINE=1: any registry pull / DB update must hard-fail.
pub fn offline() -> bool {
    matches!(
        std::env::var("READYHAI_OFFLINE").as_deref(),
        Ok("1" | "true")
    )
}
