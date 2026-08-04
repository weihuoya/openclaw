//! Wayland connection and protocol management.

use std::sync::{Arc, Mutex};

use wayland_client::protocol::wl_buffer::WlBuffer;
use wayland_client::protocol::wl_output::WlOutput;
use wayland_client::protocol::wl_registry::WlRegistry;
use wayland_client::protocol::wl_seat::WlSeat;
use wayland_client::protocol::wl_shm_pool::WlShmPool;
use wayland_client::protocol::{wl_compositor, wl_output, wl_registry, wl_seat, wl_shm};
use wayland_client::{Connection, Dispatch, EventQueue, Proxy, QueueHandle, WEnum};
use wayland_protocols_wlr::data_control::v1::client::zwlr_data_control_manager_v1::ZwlrDataControlManagerV1;
use wayland_protocols_wlr::output_management::v1::client::zwlr_output_manager_v1::ZwlrOutputManagerV1;
use wayland_protocols_wlr::screencopy::v1::client::zwlr_screencopy_manager_v1::ZwlrScreencopyManagerV1;
use wayland_protocols_wlr::virtual_pointer::v1::client::zwlr_virtual_pointer_manager_v1::ZwlrVirtualPointerManagerV1;

/// State shared between the Wayland event queue and the application.
pub struct WaylandState {
    pub compositor: Option<wl_compositor::WlCompositor>,
    pub shm: Option<wl_shm::WlShm>,
    pub outputs: Vec<OutputInfo>,
    pub seats: Vec<SeatInfo>,
    pub screencopy_manager: Option<ZwlrScreencopyManagerV1>,
    pub virtual_pointer_manager: Option<ZwlrVirtualPointerManagerV1>,
    pub data_control_manager: Option<ZwlrDataControlManagerV1>,
    pub output_manager: Option<ZwlrOutputManagerV1>,
    pub running: Arc<Mutex<bool>>,
    /// Latest clipboard text from Wayland (host -> VNC).
    pub clipboard_text: Arc<Mutex<Option<String>>>,
    /// Set by the screencopy dispatch when the pending frame is ready.
    pub capture_ready: bool,
    /// Set by the screencopy dispatch when the pending frame failed.
    pub capture_failed: bool,
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
            output_manager: None,
            running,
            clipboard_text: Arc::new(Mutex::new(None)),
            capture_ready: false,
            capture_failed: false,
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
stub_dispatch!(ZwlrOutputManagerV1);
