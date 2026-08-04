//! Signal handling for graceful shutdown.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use log::info;

/// Install signal handlers for graceful shutdown.
pub fn install(shutdown_flag: Arc<AtomicBool>) {
    let handler = move || {
        info!("Received shutdown signal, stopping...");
        shutdown_flag.store(false, Ordering::SeqCst);
    };

    ctrlc::set_handler(handler).expect("Failed to set Ctrl+C handler");
}
