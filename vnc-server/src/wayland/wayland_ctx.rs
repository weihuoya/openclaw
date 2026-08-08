//! Wayland connection and protocol management.

use std::sync::{Arc, Mutex};

use wayland_client::backend::ObjectId;
use wayland_client::protocol::wl_buffer::WlBuffer;
use wayland_client::protocol::wl_output::WlOutput;
use wayland_client::protocol::wl_registry::WlRegistry;
use wayland_client::protocol::wl_seat::WlSeat;
use wayland_client::protocol::wl_shm_pool::WlShmPool;
use wayland_client::protocol::{wl_compositor, wl_output, wl_registry, wl_seat, wl_shm};
use wayland_client::{Connection, Dispatch, EventQueue, Proxy, QueueHandle, WEnum};
use wayland_protocols_misc::zwp_virtual_keyboard_v1::client::zwp_virtual_keyboard_manager_v1::ZwpVirtualKeyboardManagerV1;
use wayland_protocols_misc::zwp_virtual_keyboard_v1::client::zwp_virtual_keyboard_v1::ZwpVirtualKeyboardV1;
use wayland_protocols_wlr::data_control::v1::client::zwlr_data_control_manager_v1::ZwlrDataControlManagerV1;
use wayland_protocols_wlr::output_management::v1::client::zwlr_output_configuration_head_v1::ZwlrOutputConfigurationHeadV1;
use wayland_protocols_wlr::output_management::v1::client::zwlr_output_configuration_v1::ZwlrOutputConfigurationV1;
use wayland_protocols_wlr::output_management::v1::client::zwlr_output_head_v1::ZwlrOutputHeadV1;
use wayland_protocols_wlr::output_management::v1::client::zwlr_output_manager_v1::ZwlrOutputManagerV1;
use wayland_protocols_wlr::output_management::v1::client::zwlr_output_mode_v1::ZwlrOutputModeV1;
use wayland_protocols_wlr::output_management::v1::client::{
    zwlr_output_configuration_v1, zwlr_output_head_v1, zwlr_output_manager_v1,
};
use wayland_protocols_wlr::screencopy::v1::client::zwlr_screencopy_manager_v1::ZwlrScreencopyManagerV1;
use wayland_protocols_wlr::virtual_pointer::v1::client::zwlr_virtual_pointer_manager_v1::ZwlrVirtualPointerManagerV1;

/// Information about a wlr_output_management head.
#[derive(Debug)]
pub struct OutputHead {
    pub id: ObjectId,
    pub head: ZwlrOutputHeadV1,
    pub name: String,
    pub enabled: bool,
}

/// A pending resize request to be applied via wlr_output_management.
#[derive(Debug, Clone)]
pub struct ResizeRequest {
    pub width: u32,
    pub height: u32,
    pub head_id: ObjectId,
}

/// State shared between the Wayland event queue and the application.
pub struct WaylandState {
    pub compositor: Option<wl_compositor::WlCompositor>,
    pub shm: Option<wl_shm::WlShm>,
    pub outputs: Vec<OutputInfo>,
    pub seats: Vec<SeatInfo>,
    pub screencopy_manager: Option<ZwlrScreencopyManagerV1>,
    pub virtual_pointer_manager: Option<ZwlrVirtualPointerManagerV1>,
    pub data_control_manager: Option<ZwlrDataControlManagerV1>,
    pub virtual_keyboard_manager: Option<ZwpVirtualKeyboardManagerV1>,
    pub output_manager: Option<ZwlrOutputManagerV1>,
    /// wlr_output_management heads discovered by the compositor.
    pub output_heads: Vec<OutputHead>,
    /// Latest serial from the output manager, used to apply configurations.
    pub output_manager_serial: u32,
    /// A resize request waiting to be applied via the output manager.
    pub pending_resize: Option<ResizeRequest>,
    /// Result of the last resize configuration: Some(true) for succeeded.
    pub resize_result: Option<bool>,
    pub running: Arc<Mutex<bool>>,
    /// Latest clipboard text from Wayland (host -> VNC).
    pub clipboard_text: Arc<Mutex<Option<String>>>,
    /// Set by the screencopy dispatch when the pending frame is ready.
    pub capture_ready: bool,
    /// Set by the screencopy dispatch when the pending frame failed.
    pub capture_failed: bool,
    /// Set by the screencopy dispatch when the compositor sends `buffer_done`
    /// for the pending frame (the copy request may then be issued).
    pub capture_buffer_done: bool,
}

/// Information about a Wayland output.
#[derive(Debug, Clone)]
pub struct OutputInfo {
    pub id: u32,
    pub name: String,
    pub description: String,
    pub width: i32,
    pub height: i32,
    pub scale: i32,
    pub transform: wl_output::Transform,
    pub wl_output: Option<WlOutput>,
}

/// Information about a Wayland seat.
#[derive(Debug, Clone)]
pub struct SeatInfo {
    pub name: String,
    pub capabilities: wl_seat::Capability,
    pub wl_seat: WlSeat,
    pub registry_id: u32,
}

impl WaylandState {
    pub fn new(running: Arc<Mutex<bool>>) -> Self {
        Self {
            compositor: None,
            shm: None,
            outputs: Vec::new(),
            seats: Vec::new(),
            screencopy_manager: None,
            virtual_pointer_manager: None,
            data_control_manager: None,
            virtual_keyboard_manager: None,
            output_manager: None,
            output_heads: Vec::new(),
            output_manager_serial: 0,
            pending_resize: None,
            resize_result: None,
            running,
            clipboard_text: Arc::new(Mutex::new(None)),
            capture_ready: false,
            capture_failed: false,
            capture_buffer_done: false,
        }
    }

    pub fn check_requirements(&self, disable_input: bool) -> Result<(), String> {
        if self.screencopy_manager.is_none() {
            return Err("zwlr_screencopy_manager_v1 not available".to_string());
        }
        if !disable_input && self.virtual_pointer_manager.is_none() {
            return Err("zwlr_virtual_pointer_manager_v1 not available".to_string());
        }
        Ok(())
    }

    pub fn find_output_by_name(&self, name: &str) -> Option<&OutputInfo> {
        self.outputs.iter().find(|o| o.name == name)
    }

    pub fn find_seat_by_name(&self, name: &str) -> Option<&SeatInfo> {
        self.seats.iter().find(|s| s.name == name)
    }

    /// Request a new size for the named output head via wlr_output_management.
    ///
    /// Returns true if the output manager is available and a matching head was
    /// found. The actual result of the resize becomes available in
    /// `resize_result` after the compositor processes the configuration.
    pub fn request_resize(
        &mut self,
        name: &str,
        width: u32,
        height: u32,
        qh: &QueueHandle<WaylandState>,
    ) -> bool {
        let Some(ref manager) = self.output_manager else {
            return false;
        };
        let Some(head) = self.output_heads.iter().find(|h| h.name == name) else {
            return false;
        };

        let config = manager.create_configuration(self.output_manager_serial, qh, ());
        let config_head = config.enable_head(&head.head, qh, ());
        config_head.set_custom_mode(width as i32, height as i32, 0);
        config.apply();

        self.pending_resize = Some(ResizeRequest {
            width,
            height,
            head_id: head.id.clone(),
        });
        self.resize_result = None;
        true
    }
}

/// Connect to the Wayland display.
pub fn connect(
    display_name: Option<&str>,
) -> Result<(Connection, EventQueue<WaylandState>, WaylandState), String> {
    let conn = match display_name {
        Some(name) => {
            let path = std::path::PathBuf::from(name);
            use std::os::unix::net::UnixStream;
            let stream = UnixStream::connect(&path)
                .map_err(|e| format!("Failed to connect to Wayland display '{}': {}", name, e))?;
            Connection::from_socket(stream)
                .map_err(|e| format!("Failed to create Wayland connection: {}", e))?
        }
        None => Connection::connect_to_env()
            .map_err(|e| format!("Failed to connect to Wayland display: {}", e))?,
    };

    let mut queue = conn.new_event_queue();
    let qh = queue.handle();
    let display = conn.display();
    let _registry = display.get_registry(&qh, ());

    let running = Arc::new(Mutex::new(true));
    let mut state = WaylandState::new(running.clone());

    // Initial roundtrip to discover globals
    conn.roundtrip()
        .map_err(|e| format!("Wayland roundtrip failed: {}", e))?;
    queue
        .roundtrip(&mut state)
        .map_err(|e| format!("Wayland dispatch failed: {}", e))?;

    Ok((conn, queue, state))
}

// --- Dispatch implementations ---

impl Dispatch<wl_registry::WlRegistry, ()> for WaylandState {
    fn event(
        state: &mut Self,
        registry: &WlRegistry,
        event: wl_registry::Event,
        _data: &(),
        _conn: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        if let wl_registry::Event::Global {
            name,
            interface,
            version,
        } = event
        {
            match &interface[..] {
                "wl_compositor" => {
                    let compositor = registry.bind::<wl_compositor::WlCompositor, _, _>(
                        name,
                        version.min(4),
                        qh,
                        (),
                    );
                    state.compositor = Some(compositor);
                }
                "wl_shm" => {
                    let shm = registry.bind::<wl_shm::WlShm, _, _>(name, version.min(1), qh, ());
                    state.shm = Some(shm);
                }
                "wl_output" => {
                    let output =
                        registry.bind::<wl_output::WlOutput, _, _>(name, version.min(2), qh, name);
                    state.outputs.push(OutputInfo {
                        id: name,
                        name: String::new(),
                        description: String::new(),
                        width: 0,
                        height: 0,
                        scale: 1,
                        transform: wl_output::Transform::Normal,
                        wl_output: Some(output),
                    });
                }
                "wl_seat" => {
                    let seat =
                        registry.bind::<wl_seat::WlSeat, _, _>(name, version.min(5), qh, name);
                    state.seats.push(SeatInfo {
                        name: String::new(),
                        capabilities: wl_seat::Capability::empty(),
                        wl_seat: seat,
                        registry_id: name,
                    });
                }
                "zwlr_screencopy_manager_v1" => {
                    let manager = registry.bind::<ZwlrScreencopyManagerV1, _, _>(
                        name,
                        version.min(1),
                        qh,
                        (),
                    );
                    state.screencopy_manager = Some(manager);
                }
                "zwlr_virtual_pointer_manager_v1" => {
                    let manager = registry.bind::<ZwlrVirtualPointerManagerV1, _, _>(
                        name,
                        version.min(1),
                        qh,
                        (),
                    );
                    state.virtual_pointer_manager = Some(manager);
                }
                "zwlr_data_control_manager_v1" => {
                    let manager = registry.bind::<ZwlrDataControlManagerV1, _, _>(
                        name,
                        version.min(1),
                        qh,
                        (),
                    );
                    state.data_control_manager = Some(manager);
                }
                "zwp_virtual_keyboard_manager_v1" => {
                    let manager = registry.bind::<ZwpVirtualKeyboardManagerV1, _, _>(
                        name,
                        version.min(1),
                        qh,
                        (),
                    );
                    state.virtual_keyboard_manager = Some(manager);
                }
                "zwlr_output_manager_v1" => {
                    let manager =
                        registry.bind::<ZwlrOutputManagerV1, _, _>(name, version.min(1), qh, ());
                    state.output_manager = Some(manager);
                }
                _ => {}
            }
        }
    }
}

impl Dispatch<wl_output::WlOutput, u32> for WaylandState {
    fn event(
        state: &mut Self,
        _output: &WlOutput,
        event: wl_output::Event,
        id: &u32,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        if let Some(info) = state.outputs.iter_mut().find(|o| o.id == *id) {
            match event {
                wl_output::Event::Geometry { .. } => {}
                wl_output::Event::Mode {
                    width,
                    height,
                    refresh: _,
                    flags: _,
                } => {
                    info.width = width;
                    info.height = height;
                }
                wl_output::Event::Scale { factor } => {
                    info.scale = factor;
                }
                wl_output::Event::Name { name } => {
                    info.name = name;
                }
                wl_output::Event::Description { description } => {
                    info.description = description;
                }
                wl_output::Event::Done => {}
                _ => {}
            }
        }
    }
}

impl Dispatch<wl_seat::WlSeat, u32> for WaylandState {
    fn event(
        state: &mut Self,
        _seat: &WlSeat,
        event: wl_seat::Event,
        id: &u32,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        if let Some(info) = state.seats.iter_mut().find(|s| s.registry_id == *id) {
            match event {
                wl_seat::Event::Name { name } => {
                    info.name = name;
                }
                wl_seat::Event::Capabilities { capabilities } => {
                    info.capabilities = match capabilities {
                        WEnum::Value(v) => v,
                        WEnum::Unknown(u) => wl_seat::Capability::from_bits_truncate(u),
                    };
                }
                _ => {}
            }
        }
    }
}

impl Dispatch<ZwlrOutputManagerV1, ()> for WaylandState {
    fn event(
        state: &mut Self,
        _proxy: &ZwlrOutputManagerV1,
        event: <ZwlrOutputManagerV1 as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        match event {
            zwlr_output_manager_v1::Event::Done { serial } => {
                state.output_manager_serial = serial;
            }
            zwlr_output_manager_v1::Event::Head { head } => {
                let id = head.id();
                state.output_heads.push(OutputHead {
                    id,
                    head,
                    name: String::new(),
                    enabled: false,
                });
            }
            zwlr_output_manager_v1::Event::Finished => {
                state.output_manager = None;
                state.output_heads.clear();
            }
            _ => {}
        }
    }
}

impl Dispatch<ZwlrOutputHeadV1, ()> for WaylandState {
    fn event(
        state: &mut Self,
        proxy: &ZwlrOutputHeadV1,
        event: <ZwlrOutputHeadV1 as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        let Some(head) = state.output_heads.iter_mut().find(|h| h.id == proxy.id()) else {
            return;
        };
        match event {
            zwlr_output_head_v1::Event::Name { name } => {
                head.name = name;
            }
            zwlr_output_head_v1::Event::Enabled { enabled } => {
                head.enabled = enabled != 0;
            }
            zwlr_output_head_v1::Event::Finished => {
                state.output_heads.retain(|h| h.id != proxy.id());
            }
            _ => {}
        }
    }
}

impl Dispatch<ZwlrOutputConfigurationV1, ()> for WaylandState {
    fn event(
        state: &mut Self,
        proxy: &ZwlrOutputConfigurationV1,
        event: <ZwlrOutputConfigurationV1 as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        match event {
            zwlr_output_configuration_v1::Event::Succeeded => {
                state.resize_result = Some(true);
                proxy.destroy();
            }
            zwlr_output_configuration_v1::Event::Failed => {
                state.resize_result = Some(false);
                proxy.destroy();
            }
            zwlr_output_configuration_v1::Event::Cancelled => {
                state.resize_result = Some(false);
                proxy.destroy();
            }
            _ => {}
        }
    }
}

macro_rules! stub_dispatch {
    ($ty:ty) => {
        impl Dispatch<$ty, ()> for WaylandState {
            fn event(
                _state: &mut Self,
                _proxy: &$ty,
                _event: <$ty as Proxy>::Event,
                _data: &(),
                _conn: &Connection,
                _qh: &QueueHandle<Self>,
            ) {
            }
        }
    };
}

stub_dispatch!(wl_compositor::WlCompositor);
stub_dispatch!(wl_shm::WlShm);
stub_dispatch!(WlShmPool);
stub_dispatch!(WlBuffer);
stub_dispatch!(ZwlrScreencopyManagerV1);
stub_dispatch!(ZwlrVirtualPointerManagerV1);
stub_dispatch!(ZwlrDataControlManagerV1);
stub_dispatch!(ZwpVirtualKeyboardManagerV1);
stub_dispatch!(ZwpVirtualKeyboardV1);
stub_dispatch!(ZwlrOutputModeV1);
stub_dispatch!(ZwlrOutputConfigurationHeadV1);
