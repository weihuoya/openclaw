use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use gettextrs::gettext;

pub mod connect_dialog;
pub mod history;
pub mod main_window;

pub type ConnectionVisibilityFn = Rc<dyn Fn(bool)>;
pub type RefreshHistoryFn = Rc<dyn Fn()>;
pub type RefreshHistoryRef = Rc<RefCell<Option<RefreshHistoryFn>>>;
pub type ReachabilityResults = Arc<Mutex<Vec<(usize, bool)>>>;
pub type ReachabilityResultsQueue = Rc<RefCell<ReachabilityResults>>;

/// Convert a runtime media-stream error into a user-friendly localized message.
///
/// Media stream failures are non-fatal: the RFB connection can continue. When
/// the GStreamer H.264 decoder plugin is missing we give an actionable install
/// hint instead of a raw pipeline error.
pub fn media_stream_error_message(msg: &str) -> Option<String> {
    if !msg.contains("Failed to start media stream") {
        return None;
    }
    Some(
        if msg.contains("avdec_h264") || msg.contains("Pipeline creation failed") {
            gettext("H.264 media stream unavailable: the GStreamer decoder plugin (avdec_h264) is failed to load.")
        } else {
            gettext("H.264 media stream unavailable; the connection will continue in standard RFB mode.")
        },
    )
}

pub use main_window::build_ui;
