//! Clipboard support via wlr-data-control protocol.
//!
//! Supports bidirectional sync:
//! - VNC -> Wayland: client paste -> host clipboard (via ZwlrDataControlSourceV1)
//! - Wayland -> VNC: host clipboard change -> ServerCutText message

use std::collections::HashMap;
use std::os::fd::AsFd;
use std::sync::{Arc, Mutex, OnceLock};

use wayland_client::protocol::wl_seat::WlSeat;
use wayland_client::{Connection, Dispatch, Proxy, QueueHandle};
use wayland_protocols_wlr::data_control::v1::client::zwlr_data_control_device_v1::ZwlrDataControlDeviceV1;
use wayland_protocols_wlr::data_control::v1::client::zwlr_data_control_manager_v1::ZwlrDataControlManagerV1;
use wayland_protocols_wlr::data_control::v1::client::zwlr_data_control_offer_v1::ZwlrDataControlOfferV1;
use wayland_protocols_wlr::data_control::v1::client::zwlr_data_control_source_v1::ZwlrDataControlSourceV1;

use crate::wayland::wayland_ctx::WaylandState;

/// Pending clipboard text to be set on Wayland.
static CLIPBOARD_TEXT_OUT: Mutex<Option<String>> = Mutex::new(None);

/// Track pending offers and their supported mime types.
static CLIPBOARD_OFFERS: OnceLock<Arc<Mutex<HashMap<u32, OfferInfo>>>> = OnceLock::new();

#[derive(Debug, Clone)]
struct OfferInfo {
    mime_types: Vec<String>,
}

fn get_offers() -> Arc<Mutex<HashMap<u32, OfferInfo>>> {
    CLIPBOARD_OFFERS
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

/// Set the host clipboard text from VNC client.
pub fn set_clipboard_text(text: &str) {
    if let Ok(mut guard) = CLIPBOARD_TEXT_OUT.lock() {
        *guard = Some(text.to_string());
    }
}

/// Check if there's pending clipboard text to set.
pub fn take_clipboard_text() -> Option<String> {
    CLIPBOARD_TEXT_OUT.lock().ok().and_then(|mut g| g.take())
}

/// Clipboard manager for bidirectional sync.
pub struct ClipboardManager {
    manager: ZwlrDataControlManagerV1,
    device: ZwlrDataControlDeviceV1,
}

impl ClipboardManager {
    pub fn new(
        manager: &ZwlrDataControlManagerV1,
        seat: &WlSeat,
        qh: &QueueHandle<WaylandState>,
    ) -> Self {
        let device = manager.get_data_device(seat, qh, ());
        Self {
            manager: manager.clone(),
            device,
        }
    }

    /// Set the Wayland clipboard from pending VNC text.
    pub fn sync_to_wayland(&self, qh: &QueueHandle<WaylandState>) {
        if let Some(text) = take_clipboard_text() {
            let source = self.manager.create_data_source(qh, ());
            source.offer("text/plain".to_string());
            source.offer("TEXT".to_string());
            source.offer("STRING".to_string());
            source.offer("UTF8_STRING".to_string());

            // Store text for the send handler
            if let Ok(mut guard) = CLIPBOARD_TEXT_OUT.lock() {
                *guard = Some(text);
            }

            self.device.set_selection(Some(&source));
            log::debug!("Set Wayland clipboard selection");
        }
    }
}

// --- Dispatch implementations ---

impl Dispatch<ZwlrDataControlDeviceV1, ()> for WaylandState {
    fn event(
        state: &mut Self,
        _proxy: &ZwlrDataControlDeviceV1,
        event: <ZwlrDataControlDeviceV1 as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        match event {
            wayland_protocols_wlr::data_control::v1::client::zwlr_data_control_device_v1::Event::DataOffer { id } => {
                let id_num = id.id().protocol_id();
                let offers = get_offers();
                offers.lock().unwrap().insert(id_num, OfferInfo { mime_types: Vec::new() });
                log::debug!("Clipboard data offer received: id={}", id_num);
            }
            wayland_protocols_wlr::data_control::v1::client::zwlr_data_control_device_v1::Event::Selection { id } => {
                if let Some(offer) = id {
                    let id_num = offer.id().protocol_id();
                    let offers = get_offers();
                    let guard = offers.lock().unwrap();
                    if let Some(info) = guard.get(&id_num) {
                        let has_text = info.mime_types.iter().any(|m| {
                            m == "text/plain" || m == "TEXT" || m == "STRING" || m == "UTF8_STRING"
                        });
                        if has_text {
                            log::debug!("Clipboard selection has text, requesting...");
                            let (read_fd, write_fd) = match nix::unistd::pipe() {
                                Ok(pair) => pair,
                                Err(e) => {
                                    log::warn!("Failed to create pipe for clipboard: {}", e);
                                    return;
                                }
                            };

                            // Use text/plain as the preferred mime type
                            offer.receive("text/plain".to_string(), write_fd.as_fd());

                            // Read from the pipe in a background thread
                            let clipboard = state.clipboard_text.clone();
                            std::thread::spawn(move || {
                                let mut file = std::fs::File::from(read_fd);
                                let mut contents = String::new();
                                match std::io::Read::read_to_string(&mut file, &mut contents) {
                                    Ok(_) if !contents.is_empty() => {
                                        log::debug!("Clipboard text received ({} bytes)", contents.len());
                                        *clipboard.lock().unwrap() = Some(contents);
                                    }
                                    _ => {}
                                }
                            });
                        }
                    }
                } else {
                    log::debug!("Clipboard selection cleared");
                    *state.clipboard_text.lock().unwrap() = None;
                }
            }
            wayland_protocols_wlr::data_control::v1::client::zwlr_data_control_device_v1::Event::Finished => {
                log::debug!("Clipboard device finished");
            }
            _ => {}
        }
    }
}

impl Dispatch<ZwlrDataControlOfferV1, ()> for WaylandState {
    fn event(
        _state: &mut Self,
        proxy: &ZwlrDataControlOfferV1,
        event: <ZwlrDataControlOfferV1 as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        if let wayland_protocols_wlr::data_control::v1::client::zwlr_data_control_offer_v1::Event::Offer { mime_type } = event {
            let id_num = proxy.id().protocol_id();
            let offers = get_offers();
            if let Some(info) = offers.lock().unwrap().get_mut(&id_num) {
                info.mime_types.push(mime_type.clone());
            }
            log::debug!("Clipboard offer {}: {}", id_num, mime_type);
        }
    }
}

impl Dispatch<ZwlrDataControlSourceV1, ()> for WaylandState {
    fn event(
        _state: &mut Self,
        _proxy: &ZwlrDataControlSourceV1,
        event: <ZwlrDataControlSourceV1 as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        match event {
            wayland_protocols_wlr::data_control::v1::client::zwlr_data_control_source_v1::Event::Send { mime_type, fd } => {
                log::debug!("Clipboard source send requested: {}", mime_type);
                if let Ok(guard) = CLIPBOARD_TEXT_OUT.lock() {
                    if let Some(ref text) = *guard {
                        use std::io::Write;
                        let mut file = std::fs::File::from(fd);
                        let _ = file.write_all(text.as_bytes());
                    }
                }
            }
            wayland_protocols_wlr::data_control::v1::client::zwlr_data_control_source_v1::Event::Cancelled => {
                log::debug!("Clipboard source cancelled");
                if let Ok(mut guard) = CLIPBOARD_TEXT_OUT.lock() {
                    *guard = None;
                }
            }
            _ => {}
        }
    }
}
