//! Control interface via Unix domain socket.
//!
//! Provides a wayvncctl-compatible IPC mechanism for runtime control.
//! Protocol: JSON lines over Unix domain socket.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use crate::bandwidth::BandwidthSnapshot;
use crate::perf::PerfState;

/// Information about a connected client, exposed via the control interface.
#[derive(Debug, Clone, Serialize)]
pub struct ClientInfo {
    pub id: usize,
    pub address: String,
    pub connected_seconds: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub frames_sent: u64,
}

/// A command sent to the control interface.
#[derive(Debug, Deserialize)]
#[serde(tag = "action")]
pub enum ControlCommand {
    #[serde(rename = "status")]
    Status,
    #[serde(rename = "client-list")]
    ClientList,
    #[serde(rename = "disconnect-client")]
    DisconnectClient { id: usize },
    #[serde(rename = "output-list")]
    OutputList,
    #[serde(rename = "set-output")]
    SetOutput { name: String },
    #[serde(rename = "reload-config")]
    ReloadConfig,
    #[serde(rename = "set-password")]
    SetPassword { password: Option<String> },
    #[serde(rename = "set-rate")]
    SetRate { max_rate: u32 },
    #[serde(rename = "version")]
    Version,
    #[serde(rename = "set-latency")]
    SetLatency { latency_us: u64 },
    #[serde(rename = "exit")]
    Exit,
}

/// A response from the control interface.
#[derive(Debug, Serialize)]
pub struct ControlResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl ControlResponse {
    pub fn ok(data: Option<serde_json::Value>) -> Self {
        Self {
            success: true,
            error: None,
            data,
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            error: Some(msg.into()),
            data: None,
        }
    }
}

/// Shared state for the control interface.
pub struct ControlState {
    /// Current output name being captured.
    pub output_name: String,
    /// Current capture resolution.
    pub width: u16,
    pub height: u16,
    /// Connected client count.
    pub client_count: usize,
    /// Total bytes sent to all clients.
    pub total_bytes_sent: u64,
    /// Total bytes received from all clients.
    pub total_bytes_received: u64,
    /// Total frames sent.
    pub total_frames_sent: u64,
    /// Current password (None = no auth).
    pub password: Option<String>,
    /// Current max frame rate.
    pub max_rate: u32,
    /// Per-client information, updated by the main loop.
    pub clients: Arc<Mutex<Vec<ClientInfo>>>,
    /// Available output names, updated by the main loop.
    pub available_outputs: Arc<Mutex<Vec<String>>>,
    /// Latest performance snapshot, updated by the main loop.
    pub perf: PerfState,
    /// Latest bandwidth snapshot, updated by the main loop.
    pub bandwidth: Arc<Mutex<BandwidthSnapshot>>,
    /// Request to disconnect a client (set by control, read by main loop).
    pub disconnect_request: Arc<Mutex<Option<usize>>>,
    /// Request to switch output (set by control, read by main loop).
    pub switch_output_request: Arc<Mutex<Option<String>>>,
    /// Request to reload config (set by control, read by main loop).
    pub reload_config_request: Arc<Mutex<bool>>,
    /// Request to set password (set by control, read by main loop).
    pub set_password_request: Arc<Mutex<Option<Option<String>>>>,
    /// Request to set frame rate (set by control, read by main loop).
    pub set_rate_request: Arc<Mutex<Option<u32>>>,
    /// Request to set target latency for bandwidth control (set by control, read by main loop).
    pub set_latency_request: Arc<Mutex<Option<u64>>>,
    /// Request to exit the server (set by control, read by main loop).
    pub exit_request: Arc<Mutex<bool>>,
}

impl ControlState {
    pub fn new(
        output_name: String,
        width: u16,
        height: u16,
        password: Option<String>,
        max_rate: u32,
    ) -> Self {
        Self {
            output_name,
            width,
            height,
            client_count: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            total_frames_sent: 0,
            password,
            max_rate,
            clients: Arc::new(Mutex::new(Vec::new())),
            available_outputs: Arc::new(Mutex::new(Vec::new())),
            perf: PerfState::new(),
            bandwidth: Arc::new(Mutex::new(BandwidthSnapshot::default())),
            disconnect_request: Arc::new(Mutex::new(None)),
            switch_output_request: Arc::new(Mutex::new(None)),
            reload_config_request: Arc::new(Mutex::new(false)),
            set_password_request: Arc::new(Mutex::new(None)),
            set_rate_request: Arc::new(Mutex::new(None)),
            set_latency_request: Arc::new(Mutex::new(None)),
            exit_request: Arc::new(Mutex::new(false)),
        }
    }

    /// Update the list of available output names.
    pub fn set_outputs(&self, outputs: Vec<String>) {
        if let Ok(mut guard) = self.available_outputs.lock() {
            *guard = outputs;
        }
    }

    /// Update per-client information.
    pub fn set_clients(&self, clients: Vec<ClientInfo>) {
        if let Ok(mut guard) = self.clients.lock() {
            *guard = clients;
        }
    }
}

/// Control interface server.
pub struct ControlServer {
    listener: UnixListener,
    state: Arc<Mutex<ControlState>>,
}

impl ControlServer {
    /// Bind to a Unix domain socket path.
    pub fn bind(path: &PathBuf, state: ControlState) -> std::io::Result<Self> {
        // Remove stale socket
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let listener = UnixListener::bind(path)?;
        listener.set_nonblocking(true)?;
        info!("Control interface listening on {}", path.display());
        Ok(Self {
            listener,
            state: Arc::new(Mutex::new(state)),
        })
    }

    /// Accept and handle incoming control connections.
    pub fn poll(&self) {
        match self.listener.accept() {
            Ok((stream, _addr)) => {
                if let Err(e) = stream.set_nonblocking(false) {
                    warn!("Failed to set control stream blocking: {}", e);
                    return;
                }
                let state = self.state.clone();
                std::thread::spawn(move || {
                    if let Err(e) = handle_control_connection(stream, state) {
                        debug!("Control connection error: {}", e);
                    }
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => {
                warn!("Control accept error: {}", e);
            }
        }
    }

    /// Get shared state handle.
    pub fn state(&self) -> Arc<Mutex<ControlState>> {
        self.state.clone()
    }
}

fn handle_control_connection(
    mut stream: UnixStream,
    state: Arc<Mutex<ControlState>>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();

    while reader.read_line(&mut line)? > 0 {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }

        let response = match serde_json::from_str::<ControlCommand>(trimmed) {
            Ok(cmd) => process_command(cmd, &state),
            Err(e) => ControlResponse::err(format!("Invalid command: {}", e)),
        };
        let json = serde_json::to_string(&response)
            .unwrap_or_else(|_| r#"{"success":false,"error":"serialization failed"}"#.to_string());
        writeln!(stream, "{}", json)?;
        stream.flush()?;

        line.clear();
    }

    Ok(())
}

fn process_command(cmd: ControlCommand, state: &Arc<Mutex<ControlState>>) -> ControlResponse {
    // Recover from a poisoned mutex instead of panicking the control thread:
    // the state is still usable, the previous holder just panicked.
    let guard = state.lock().unwrap_or_else(|e| e.into_inner());

    match cmd {
        ControlCommand::Status => {
            let perf = guard
                .perf
                .snapshot
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let bandwidth = guard.bandwidth.lock().unwrap_or_else(|e| e.into_inner());
            let data = serde_json::json!({
                "output": guard.output_name,
                "width": guard.width,
                "height": guard.height,
                "clients": guard.client_count,
                "bytes_sent": guard.total_bytes_sent,
                "bytes_received": guard.total_bytes_received,
                "frames_sent": guard.total_frames_sent,
                "password_set": guard.password.is_some(),
                "max_rate": guard.max_rate,
                "perf": *perf,
                "bandwidth": *bandwidth,
            });
            ControlResponse::ok(Some(data))
        }
        ControlCommand::ClientList => {
            let clients = guard.clients.lock().unwrap_or_else(|e| e.into_inner());
            let data = serde_json::to_value(clients.clone()).unwrap_or(serde_json::Value::Null);
            ControlResponse::ok(Some(data))
        }
        ControlCommand::DisconnectClient { id } => {
            if let Ok(mut req) = guard.disconnect_request.lock() {
                *req = Some(id);
            }
            ControlResponse::ok(None)
        }
        ControlCommand::OutputList => {
            let outputs = guard
                .available_outputs
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let data = serde_json::to_value(outputs.clone()).unwrap_or(serde_json::Value::Null);
            ControlResponse::ok(Some(data))
        }
        ControlCommand::SetOutput { name } => {
            if let Ok(mut req) = guard.switch_output_request.lock() {
                *req = Some(name);
            }
            ControlResponse::ok(None)
        }
        ControlCommand::ReloadConfig => {
            if let Ok(mut req) = guard.reload_config_request.lock() {
                *req = true;
            }
            ControlResponse::ok(None)
        }
        ControlCommand::SetPassword { password } => {
            if let Ok(mut req) = guard.set_password_request.lock() {
                *req = Some(password);
            }
            ControlResponse::ok(None)
        }
        ControlCommand::SetRate { max_rate } => {
            if let Ok(mut req) = guard.set_rate_request.lock() {
                *req = Some(max_rate);
            }
            ControlResponse::ok(None)
        }
        ControlCommand::SetLatency { latency_us } => {
            if let Ok(mut req) = guard.set_latency_request.lock() {
                *req = Some(latency_us);
            }
            ControlResponse::ok(None)
        }
        ControlCommand::Version => {
            let data = serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
            });
            ControlResponse::ok(Some(data))
        }
        ControlCommand::Exit => {
            if let Ok(mut req) = guard.exit_request.lock() {
                *req = true;
            }
            ControlResponse::ok(None)
        }
    }
}
