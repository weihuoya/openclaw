//! Virtual input handling.

use wayland_client::protocol::wl_pointer::{Axis, ButtonState};
use wayland_client::protocol::wl_seat::WlSeat;
use wayland_client::{Connection, Dispatch, Proxy, QueueHandle};
use wayland_protocols_wlr::virtual_pointer::v1::client::zwlr_virtual_pointer_manager_v1::ZwlrVirtualPointerManagerV1;
use wayland_protocols_wlr::virtual_pointer::v1::client::zwlr_virtual_pointer_v1::ZwlrVirtualPointerV1;

use crate::wayland::wayland_ctx::WaylandState;

/// A virtual pointer device.
pub struct VirtualPointer {
    pointer: ZwlrVirtualPointerV1,
}

impl VirtualPointer {
    /// Create a new virtual pointer for the given seat.
    pub fn new(
        manager: &ZwlrVirtualPointerManagerV1,
        seat: &WlSeat,
        qh: &QueueHandle<WaylandState>,
    ) -> Self {
        let pointer = manager.create_virtual_pointer(Some(seat), qh, ());
        Self { pointer }
    }

    /// Move the pointer to normalized coordinates [0.0, 1.0].
    pub fn motion_normalized(&self, x: f64, y: f64) {
        let x_u32 = (x * u32::MAX as f64) as u32;
        let y_u32 = (y * u32::MAX as f64) as u32;
        self.pointer
            .motion_absolute(0, x_u32, y_u32, u32::MAX, u32::MAX);
    }

    /// Send a button press/release event.
    pub fn button(&self, button: u32, pressed: bool) {
        let state = if pressed {
            ButtonState::Pressed
        } else {
            ButtonState::Released
        };
        self.pointer.button(0, button, state);
    }

    /// Send a scroll event (axis discrete).
    pub fn scroll(&self, axis: u32, value: i32) {
        let axis_enum = match axis {
            0 => Axis::VerticalScroll,
            1 => Axis::HorizontalScroll,
            _ => Axis::VerticalScroll,
        };
        self.pointer.axis_discrete(0, axis_enum, 0.0, value);
    }

    /// Flush pending events.
    pub fn flush(&self) {
        // Events are batched by the Wayland connection
    }
}

impl Drop for VirtualPointer {
    fn drop(&mut self) {
        // The proxy will be destroyed when dropped
    }
}

/// Button codes for virtual pointer.
pub mod button {
    pub const LEFT: u32 = 272;
    pub const RIGHT: u32 = 273;
    pub const MIDDLE: u32 = 274;
    pub const SIDE: u32 = 275;
    pub const EXTRA: u32 = 276;
    pub const FORWARD: u32 = 277;
    pub const BACK: u32 = 278;
}

/// Axis codes for virtual pointer scroll.
pub mod axis {
    pub const VERTICAL: u32 = 0;
    pub const HORIZONTAL: u32 = 1;
}

// --- Dispatch implementations ---

impl Dispatch<ZwlrVirtualPointerV1, ()> for WaylandState {
    fn event(
        _state: &mut Self,
        _proxy: &ZwlrVirtualPointerV1,
        _event: <ZwlrVirtualPointerV1 as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}
