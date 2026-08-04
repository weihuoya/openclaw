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

/// A command sent to the control interface.
#[derive(Debug, Deserialize)]
#[serde(tag = "action")]
pub enum ControlCommand {
    #[serde(rename = "status")]
    Status,
    #[serde(rename = "disconnect-client")]
    DisconnectClient { id: usize },
    #[serde(rename = "set-output")]
    SetOutput { name: String },
    #[serde(rename = "reload-config")]
    ReloadConfig,
    #[serde(rename = "set-password")]
    SetPassword { password: Option<String> },
    #[serde(rename = "set-rate")]
    SetRate { max_rate: u32 },
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
            disconnect_request: Arc::new(Mutex::new(None)),
            switch_output_request: Arc::new(Mutex::new(None)),
            reload_config_request: Arc::new(Mutex::new(false)),
            set_password_request: Arc::new(Mutex::new(None)),
            set_rate_request: Arc::new(Mutex::new(None)),
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
    let guard = state.lock().unwrap();

    match cmd {
        ControlCommand::Status => {
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
            });
            ControlResponse::ok(Some(data))
        }
        ControlCommand::DisconnectClient { id } => {
            if let Ok(mut req) = guard.disconnect_request.lock() {
                *req = Some(id);
            }
            ControlResponse::ok(None)
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
    }
}
