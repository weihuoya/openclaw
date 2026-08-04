//! Screen capture using wlr-screencopy protocol.

use wayland_client::{Connection, Dispatch, Proxy, QueueHandle};
use wayland_protocols_wlr::screencopy::v1::client::zwlr_screencopy_frame_v1::ZwlrScreencopyFrameV1;

use crate::wayland::wayland_ctx::WaylandState;

// --- Dispatch implementations ---

impl Dispatch<ZwlrScreencopyFrameV1, ()> for WaylandState {
    fn event(
        state: &mut Self,
        _frame: &ZwlrScreencopyFrameV1,
        event: <ZwlrScreencopyFrameV1 as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        match event {
            wayland_protocols_wlr::screencopy::v1::client::zwlr_screencopy_frame_v1::Event::Buffer {
                format: _,
                width,
                height,
                stride,
            } => {
                log::debug!("Frame buffer: {}x{}, stride {}", width, height, stride);
            }
            wayland_protocols_wlr::screencopy::v1::client::zwlr_screencopy_frame_v1::Event::LinuxDmabuf {
                width,
                height,
                format: _,
            } => {
                log::debug!("Frame Linux DMA-BUF: {}x{}", width, height);
            }
            wayland_protocols_wlr::screencopy::v1::client::zwlr_screencopy_frame_v1::Event::BufferDone => {
                log::debug!("Frame buffer done");
            }
            wayland_protocols_wlr::screencopy::v1::client::zwlr_screencopy_frame_v1::Event::Flags { .. } => {}
            wayland_protocols_wlr::screencopy::v1::client::zwlr_screencopy_frame_v1::Event::Ready { .. } => {
                log::debug!("Frame ready");
                state.capture_ready = true;
            }
            wayland_protocols_wlr::screencopy::v1::client::zwlr_screencopy_frame_v1::Event::Failed => {
                log::error!("Frame capture failed");
                state.capture_failed = true;
            }
            wayland_protocols_wlr::screencopy::v1::client::zwlr_screencopy_frame_v1::Event::Damage { .. } => {}
            _ => {}
        }
    }
}
