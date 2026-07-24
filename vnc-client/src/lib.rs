//! A Rust VNC client library implementing the RFB (Remote Framebuffer) protocol.
//!
//! ## Quick start
//!
//! ```no_run
//! use vnc_client::{VncClient, VncClientBuilder, VncEvent};
//! use vnc_client::auth::NoAuthHandler;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Builder API (recommended)
//!     let mut client = VncClientBuilder::new()
//!         .pixel_format(vnc_client::PixelFormat::rgba32())
//!         .encodings(vec![
//!             vnc_client::encodings::Encoding::Zrle,
//!             vnc_client::encodings::Encoding::Raw,
//!         ])
//!         .build();
//!
//!     client.connect("127.0.0.1:5900")?;
//!     let mut auth = NoAuthHandler;
//!     let events = client.handshake(&mut auth)?;
//!     println!("Connected: {}x{}", client.width(), client.height());
//!
//!     // Request full update
//!     client.request_update(false, 0, 0, client.width(), client.height())?;
//!
//!     // Read server messages
//!     loop {
//!         let events = client.read_messages()?;
//!         for event in events {
//!             match event {
//!                 VncEvent::FramebufferUpdate { .. } => {
//!                     // Pixels updated in framebuffer
//!                 }
//!                 VncEvent::GeometryChanged { .. } => {
//!                     // Desktop size changed
//!                 }
//!                 _ => {}
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! ## Platform-specific video decoding
//!
//! On Linux/GTK4, the default decoder uses **GStreamer** (`vnc-widget-gtk4`).
//! On Android, the default decoder uses **MediaCodec** (`vnc-client-android`).
//! The core `vnc-client` crate is platform-agnostic; decoding backends are selected
//! via conditional compilation.
//!
//! ## Features
//!
//! - RFB protocol 3.8
//! - Authentication: None, VNC password, VeNCrypt, RSA-AES, Apple DH
//! - Encodings: Raw, CopyRect, RRE, Hextile, Tight, TRLE, ZRLE, OpenH264
//! - Pseudo-encodings: DesktopSize, Cursor, Extended Clipboard, Fence
//! - TLS encryption via `rustls`
//! - H.264 hardware decoding on Android via MediaCodec

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::tls::TlsStream;

pub mod apple_dh;
pub mod auth;
pub mod clipboard;
pub mod cursor;
pub mod decoder;
pub mod encodings;
pub mod framebuffer;
pub mod hextile;
pub mod protocol;
pub mod rre;
pub mod rsa_aes;
pub mod sasl;
pub mod stats;
pub mod tight;
pub mod tls;
pub mod trle;
pub mod vencrypt;
pub mod ws;
pub mod zrle;

use auth::AuthHandler;
use cursor::CursorShape;
use decoder::DefaultDecoder;
use encodings::Encoding;
use flate2::Decompress;
use framebuffer::Framebuffer;

pub use framebuffer::PixelFormat;
pub use framebuffer::Transform;
pub use stats::ConnectionStats;

enum VncStreamInner {
    Plain(TcpStream),
    Tls(Box<TlsStream>),
    Aes(rsa_aes::AesCfbStream),
    Ws(ws::WsStream),
}

impl VncStreamInner {
    fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        match self {
            VncStreamInner::Plain(s) => s.set_read_timeout(timeout),
            VncStreamInner::Tls(s) => s.set_read_timeout(timeout),
            VncStreamInner::Aes(s) => s.set_read_timeout(timeout),
            VncStreamInner::Ws(s) => s.set_read_timeout(timeout),
        }
    }

    fn set_nodelay(&self, nodelay: bool) -> std::io::Result<()> {
        match self {
            VncStreamInner::Plain(s) => s.set_nodelay(nodelay),
            VncStreamInner::Tls(s) => s.set_nodelay(nodelay),
            VncStreamInner::Aes(s) => s.set_nodelay(nodelay),
            VncStreamInner::Ws(s) => s.set_nodelay(nodelay),
        }
    }
}

impl Read for VncStreamInner {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            VncStreamInner::Plain(s) => s.read(buf),
            VncStreamInner::Tls(s) => s.read(buf),
            VncStreamInner::Aes(s) => s.read(buf),
            VncStreamInner::Ws(s) => s.read(buf),
        }
    }
}

impl Write for VncStreamInner {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            VncStreamInner::Plain(s) => s.write(buf),
            VncStreamInner::Tls(s) => s.write(buf),
            VncStreamInner::Aes(s) => s.write(buf),
            VncStreamInner::Ws(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            VncStreamInner::Plain(s) => s.flush(),
            VncStreamInner::Tls(s) => s.flush(),
            VncStreamInner::Aes(s) => s.flush(),
            VncStreamInner::Ws(s) => s.flush(),
        }
    }
}

/// A stream that can be plain TCP, TLS-wrapped, AES-encrypted, or WebSocket.
pub struct VncStream {
    inner: VncStreamInner,
    bytes_read: u64,
    bytes_written: u64,
}

impl VncStream {
    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    pub fn set_nodelay(&self, nodelay: bool) -> std::io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }

    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}

impl Read for VncStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes_read += n as u64;
        Ok(n)
    }
}

impl Write for VncStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.bytes_written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// VNC client connection state.
///
/// Manages the TCP/TLS connection, protocol handshake, framebuffer updates,
/// and input event forwarding. Use [`VncClientBuilder`] for ergonomic configuration.
///
/// ## Lifecycle
///
/// 1. `new()` or [`VncClientBuilder::build()`]
/// 2. `connect()` / `connect_tls()`
/// 3. `handshake()`
/// 4. `request_update()` / `read_messages()` loop
/// 5. `send_pointer_event()` / `send_key_event()` for input
///
/// ## Example
///
/// ```no_run
/// use vnc_client::{VncClient, VncEvent};
/// use vnc_client::auth::NoAuthHandler;
///
/// let mut client = VncClient::new();
/// client.connect("127.0.0.1:5900").unwrap();
/// let mut auth = NoAuthHandler;
/// client.handshake(&mut auth).unwrap();
///
/// client.request_update(false, 0, 0, 800, 600).unwrap();
/// loop {
///     for event in client.read_messages().unwrap() {
///         if let VncEvent::FramebufferUpdate { .. } = event {
///             // Framebuffer pixels updated
///         }
///     }
/// }
/// ```
pub struct VncClient {
    stream: Option<VncStream>,
    state: ClientState,
    framebuffer: Framebuffer,
    pixel_format: PixelFormat,
    name: String,
    width: u16,
    height: u16,
    h264_decoder: Option<Box<dyn decoder::VideoDecoder>>,
    encodings: Vec<Encoding>,
    host: String,
    sasl_username: String,
    sasl_password: String,
    server_security_types: Vec<u8>,
    zrle_decompress: Option<Decompress>,
    stats_tracker: stats::ConnectionStatsTracker,
    /// Current read timeout, so handlers like Raw can temporarily extend it
    /// for large data reads and restore it afterwards.
    read_timeout: Option<Duration>,
    // Protocol diagnostics: last successfully parsed message type and rect
    // encoding. These are recorded to help diagnose "Unknown server message
    // type" errors caused by a previous handler reading the wrong number of
    // bytes.
    last_msg_type: Option<u8>,
    last_encoding: Option<i32>,
    // Encodings processed in the last FramebufferUpdate. Printed when the
    // stream desynchronises so we can identify which handler is at fault.
    recent_encodings: Vec<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ClientState {
    Disconnected,
    Connected,
    HandshakeVersion,
    HandshakeAuth,
    Initialization,
    Ready,
}

/// A single monitor/screen in the desktop layout.
#[derive(Debug, Clone, Copy)]
pub struct Screen {
    /// Screen identifier.
    pub id: u32,
    /// X offset in the desktop.
    pub x: u16,
    /// Y offset in the desktop.
    pub y: u16,
    /// Screen width in pixels.
    pub width: u16,
    /// Screen height in pixels.
    pub height: u16,
    /// Screen flags (e.g. primary, etc.).
    pub flags: u32,
}

/// Events emitted by the VNC client.
#[derive(Debug, Clone)]
pub enum VncEvent {
    /// Framebuffer geometry changed (width, height).
    GeometryChanged { width: u16, height: u16 },
    /// Framebuffer updated region (x, y, width, height).
    FramebufferUpdate {
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    },
    /// Desktop name changed.
    NameChanged(String),
    /// Bell received from server.
    Bell,
    /// Cursor shape update.
    CursorShape(CursorShape),
    /// Server cut text received.
    CutText(String),
    /// Clipboard data received.
    ClipboardData(clipboard::ClipboardMessage),
    /// Server signaled end of continuous updates.
    EndOfContinuousUpdates,
    /// Fence sync marker received.
    Fence { flags: u32, data: Vec<u8> },
    /// Cursor position update.
    CursorPos { x: u16, y: u16 },
    /// Keyboard LED state update (ScrollLock, NumLock, CapsLock).
    LedState {
        scroll_lock: bool,
        num_lock: bool,
        caps_lock: bool,
    },
    /// Multi-monitor screen layout changed.
    ScreenLayout(Vec<Screen>),
    /// Audio data received (QEMU extension).
    Audio {
        sample_rate: u32,
        channels: u8,
        bits_per_sample: u8,
        data: Vec<u8>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum VncError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(String),
    #[error("Server closed connection")]
    ServerClosed,
    #[error("Not connected")]
    NotConnected,
}

impl VncClient {
    /// Create a new VNC client (not connected yet).
    pub fn new() -> Self {
        Self {
            stream: None,
            state: ClientState::Disconnected,
            framebuffer: Framebuffer::new(0, 0),
            pixel_format: PixelFormat::rgba32(),
            name: String::new(),
            width: 0,
            height: 0,
            h264_decoder: None,
            encodings: Vec::new(),
            host: String::new(),
            sasl_username: String::new(),
            sasl_password: String::new(),
            server_security_types: Vec::new(),
            zrle_decompress: None,
            stats_tracker: stats::ConnectionStatsTracker::new(),
            read_timeout: None,
            last_msg_type: None,
            last_encoding: None,
            recent_encodings: Vec::new(),
        }
    }

    #[allow(dead_code)]
    fn stream(&mut self) -> Result<&mut VncStream, VncError> {
        self.stream.as_mut().ok_or(VncError::NotConnected)
    }

    pub fn connect<A: ToSocketAddrs>(&mut self, addr: A) -> Result<(), VncError> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        self.stream = Some(VncStream {
            inner: VncStreamInner::Plain(stream),
            bytes_read: 0,
            bytes_written: 0,
        });
        self.state = ClientState::Connected;
        Ok(())
    }

    /// Set the server hostname for TLS certificate verification.
    pub fn set_host(&mut self, host: &str) {
        self.host = host.to_string();
    }

    /// Connect to a VNC server using TLS.
    pub fn connect_tls(&mut self, host: &str, port: u16) -> Result<(), VncError> {
        let stream = TlsStream::connect(host, port)?;
        self.stream = Some(VncStream {
            inner: VncStreamInner::Tls(Box::new(stream)),
            bytes_read: 0,
            bytes_written: 0,
        });
        self.host = host.to_string();
        self.state = ClientState::Connected;
        Ok(())
    }

    /// Connect to a VNC server via WebSocket.
    pub fn connect_ws(&mut self, url: &str) -> Result<(), VncError> {
        let stream = ws::WsStream::connect(url)?;
        self.stream = Some(VncStream {
            inner: VncStreamInner::Ws(stream),
            bytes_read: 0,
            bytes_written: 0,
        });
        self.state = ClientState::Connected;
        Ok(())
    }

    /// Return the security types advertised by the server during the last handshake.
    ///
    /// The list is empty until a handshake has been attempted. Common values are:
    /// `1` (None), `2` (VNC authentication), and `19` (VeNCrypt).
    pub fn server_security_types(&self) -> &[u8] {
        &self.server_security_types
    }

    /// Perform the full handshake and initialization sequence.
    pub fn handshake(&mut self, auth: &mut dyn AuthHandler) -> Result<Vec<VncEvent>, VncError> {
        let mut events = Vec::new();
        self.handshake_version()?;
        self.handshake_auth(auth)?;
        self.initialization(&mut events)?;
        self.state = ClientState::Ready;

        // Apply encodings configured via VncClientBuilder.
        if !self.encodings.is_empty() {
            self.set_encodings(&self.encodings.clone())?;
        }

        Ok(events)
    }

    fn handshake_version(&mut self) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut buf = [0u8; 12];
        stream.read_exact(&mut buf)?;

        let version = String::from_utf8_lossy(&buf);
        let version = version.trim_end();
        if !version.starts_with("RFB ") {
            return Err(VncError::Protocol(format!(
                "Invalid protocol version string: {}",
                version
            )));
        }

        let our_version = match version {
            "RFB 003.008" => b"RFB 003.008\n",
            "RFB 003.007" => b"RFB 003.007\n",
            "RFB 003.003" => b"RFB 003.003\n",
            _ => return Err(VncError::UnsupportedVersion(version.to_string())),
        };

        stream.write_all(our_version)?;
        self.state = ClientState::HandshakeVersion;
        Ok(())
    }

    fn handshake_auth(&mut self, auth: &mut dyn AuthHandler) -> Result<(), VncError> {
        let selected = {
            let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
            let mut buf = [0u8; 1];
            stream.read_exact(&mut buf)?;
            let num_types = buf[0] as usize;

            if num_types == 0 {
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf)?;
                let len = u32::from_be_bytes(buf) as usize;
                let mut reason = vec![0u8; len];
                stream.read_exact(&mut reason)?;
                return Err(VncError::AuthFailed(
                    String::from_utf8_lossy(&reason).to_string(),
                ));
            }

            let mut types = vec![0u8; num_types];
            stream.read_exact(&mut types)?;
            self.server_security_types = types.clone();

            let selected = if types.contains(&19) {
                19u8 // VeNCrypt
            } else if types.contains(&1) {
                1u8
            } else {
                auth.select_security_type(&types)?
            };

            stream.write_all(&[selected])?;
            selected
        };

        match selected {
            1 => {
                let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf)?;
                let result = u32::from_be_bytes(buf);
                if result != 0 {
                    return Err(VncError::AuthFailed("Authentication failed".to_string()));
                }
            }
            2 => {
                let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                auth.authenticate_vnc(stream)?;
            }
            19 => {
                let result = {
                    let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                    let handler = vencrypt::VencryptHandler;
                    handler.negotiate(stream)?
                };
                match result {
                    vencrypt::VencryptResult::None => {
                        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                        let mut buf = [0u8; 4];
                        stream.read_exact(&mut buf)?;
                        let result = u32::from_be_bytes(buf);
                        if result != 0 {
                            return Err(VncError::AuthFailed(
                                "VeNCrypt None auth failed".to_string(),
                            ));
                        }
                    }
                    vencrypt::VencryptResult::VncAuth => {
                        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                        auth.authenticate_vnc(stream)?;
                    }
                    vencrypt::VencryptResult::Tls => {
                        let (tcp, bytes_read, bytes_written) = match self.stream.take() {
                            Some(VncStream {
                                inner: VncStreamInner::Plain(tcp),
                                bytes_read,
                                bytes_written,
                            }) => (tcp, bytes_read, bytes_written),
                            Some(VncStream {
                                inner: VncStreamInner::Tls(_),
                                ..
                            }) => {
                                return Err(VncError::Protocol("Already TLS".to_string()));
                            }
                            Some(VncStream {
                                inner: VncStreamInner::Aes(_),
                                ..
                            }) => {
                                return Err(VncError::Protocol(
                                    "Cannot upgrade AES stream to TLS".to_string(),
                                ));
                            }
                            Some(VncStream {
                                inner: VncStreamInner::Ws(_),
                                ..
                            }) => {
                                return Err(VncError::Protocol(
                                    "WebSocket not supported for VeNCrypt auth".to_string(),
                                ));
                            }
                            None => return Err(VncError::NotConnected),
                        };
                        let host = self.host.clone();
                        if host.is_empty() {
                            return Err(VncError::Protocol(
                                "Host not set for TLS upgrade".to_string(),
                            ));
                        }
                        let tls = TlsStream::from_tcp(tcp, &host)?;
                        self.stream = Some(VncStream {
                            inner: VncStreamInner::Tls(Box::new(tls)),
                            bytes_read,
                            bytes_written,
                        });
                        // TLS upgrade complete — read security result
                        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                        let mut buf = [0u8; 4];
                        stream.read_exact(&mut buf)?;
                        let result = u32::from_be_bytes(buf);
                        if result != 0 {
                            return Err(VncError::AuthFailed(
                                "VeNCrypt TLS security result failed".to_string(),
                            ));
                        }
                    }
                    vencrypt::VencryptResult::X509 => {
                        // X509: TLS + X509 certificate verification
                        // Simplified: same as TLS for now (server cert verified by webpki roots)
                        let (tcp, bytes_read, bytes_written) = match self.stream.take() {
                            Some(VncStream {
                                inner: VncStreamInner::Plain(tcp),
                                bytes_read,
                                bytes_written,
                            }) => (tcp, bytes_read, bytes_written),
                            Some(VncStream {
                                inner: VncStreamInner::Tls(_),
                                ..
                            }) => {
                                return Err(VncError::Protocol("Already TLS".to_string()));
                            }
                            Some(VncStream {
                                inner: VncStreamInner::Aes(_),
                                ..
                            }) => {
                                return Err(VncError::Protocol(
                                    "Cannot upgrade AES stream to X509 TLS".to_string(),
                                ));
                            }
                            Some(VncStream {
                                inner: VncStreamInner::Ws(_),
                                ..
                            }) => {
                                return Err(VncError::Protocol(
                                    "WebSocket not supported for VeNCrypt auth".to_string(),
                                ));
                            }
                            None => return Err(VncError::NotConnected),
                        };
                        let host = self.host.clone();
                        if host.is_empty() {
                            return Err(VncError::Protocol(
                                "Host not set for X509 TLS upgrade".to_string(),
                            ));
                        }
                        let tls = TlsStream::from_tcp(tcp, &host)?;
                        self.stream = Some(VncStream {
                            inner: VncStreamInner::Tls(Box::new(tls)),
                            bytes_read,
                            bytes_written,
                        });
                        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                        let mut buf = [0u8; 4];
                        stream.read_exact(&mut buf)?;
                        let result = u32::from_be_bytes(buf);
                        if result != 0 {
                            return Err(VncError::AuthFailed(
                                "VeNCrypt X509 security result failed".to_string(),
                            ));
                        }
                    }
                    vencrypt::VencryptResult::RsaAes => {
                        let (mut tcp, bytes_read, bytes_written) = match self.stream.take() {
                            Some(VncStream {
                                inner: VncStreamInner::Plain(tcp),
                                bytes_read,
                                bytes_written,
                            }) => (tcp, bytes_read, bytes_written),
                            Some(VncStream {
                                inner: VncStreamInner::Tls(_),
                                ..
                            }) => {
                                return Err(VncError::Protocol(
                                    "RSA-AES over TLS not supported".to_string(),
                                ));
                            }
                            Some(VncStream {
                                inner: VncStreamInner::Aes(_),
                                ..
                            }) => {
                                return Err(VncError::Protocol(
                                    "Already AES encrypted".to_string(),
                                ));
                            }
                            Some(VncStream {
                                inner: VncStreamInner::Ws(_),
                                ..
                            }) => {
                                return Err(VncError::Protocol(
                                    "WebSocket not supported for VeNCrypt auth".to_string(),
                                ));
                            }
                            None => return Err(VncError::NotConnected),
                        };
                        let rsa_auth = rsa_aes::RsaAesAuth::new_128();
                        let key = rsa_auth.authenticate(&mut tcp)?;
                        let aes = rsa_aes::AesCfbStream::new(tcp, &key)?;
                        self.stream = Some(VncStream {
                            inner: VncStreamInner::Aes(aes),
                            bytes_read,
                            bytes_written,
                        });
                    }
                    vencrypt::VencryptResult::RsaAes256 => {
                        let (mut tcp, bytes_read, bytes_written) = match self.stream.take() {
                            Some(VncStream {
                                inner: VncStreamInner::Plain(tcp),
                                bytes_read,
                                bytes_written,
                            }) => (tcp, bytes_read, bytes_written),
                            Some(VncStream {
                                inner: VncStreamInner::Tls(_),
                                ..
                            }) => {
                                return Err(VncError::Protocol(
                                    "RSA-AES-256 over TLS not supported".to_string(),
                                ));
                            }
                            Some(VncStream {
                                inner: VncStreamInner::Aes(_),
                                ..
                            }) => {
                                return Err(VncError::Protocol(
                                    "Already AES encrypted".to_string(),
                                ));
                            }
                            Some(VncStream {
                                inner: VncStreamInner::Ws(_),
                                ..
                            }) => {
                                return Err(VncError::Protocol(
                                    "WebSocket not supported for VeNCrypt auth".to_string(),
                                ));
                            }
                            None => return Err(VncError::NotConnected),
                        };
                        let rsa_auth = rsa_aes::RsaAesAuth::new_256();
                        let key = rsa_auth.authenticate(&mut tcp)?;
                        let aes = rsa_aes::AesCfbStream::new(tcp, &key)?;
                        self.stream = Some(VncStream {
                            inner: VncStreamInner::Aes(aes),
                            bytes_read,
                            bytes_written,
                        });
                    }
                    vencrypt::VencryptResult::AppleDh => {
                        let (mut tcp, bytes_read, bytes_written) = match self.stream.take() {
                            Some(VncStream {
                                inner: VncStreamInner::Plain(tcp),
                                bytes_read,
                                bytes_written,
                            }) => (tcp, bytes_read, bytes_written),
                            Some(VncStream {
                                inner: VncStreamInner::Tls(_),
                                ..
                            }) => {
                                return Err(VncError::Protocol(
                                    "Apple DH over TLS not supported".to_string(),
                                ));
                            }
                            Some(VncStream {
                                inner: VncStreamInner::Aes(_),
                                ..
                            }) => {
                                return Err(VncError::Protocol(
                                    "Already AES encrypted".to_string(),
                                ));
                            }
                            Some(VncStream {
                                inner: VncStreamInner::Ws(_),
                                ..
                            }) => {
                                return Err(VncError::Protocol(
                                    "WebSocket not supported for Apple DH".to_string(),
                                ));
                            }
                            None => return Err(VncError::NotConnected),
                        };
                        let dh_auth = apple_dh::AppleDhAuth;
                        let key = dh_auth.authenticate(&mut tcp)?;
                        // Truncate to 16 bytes for AES-128
                        let aes_key = &key[..16.min(key.len())];
                        let aes = rsa_aes::AesCfbStream::new(tcp, aes_key)?;
                        self.stream = Some(VncStream {
                            inner: VncStreamInner::Aes(aes),
                            bytes_read,
                            bytes_written,
                        });
                    }
                    vencrypt::VencryptResult::Sasl => {
                        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                        if self.sasl_username.is_empty() {
                            return Err(VncError::AuthFailed(
                                "SASL username not configured".to_string(),
                            ));
                        }
                        let sasl_auth =
                            sasl::SaslAuth::new(&self.sasl_username, &self.sasl_password);
                        sasl_auth.authenticate(stream)?;
                    }
                }
            }
            _ => {
                let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                auth.authenticate(stream, selected)?;
            }
        }

        self.state = ClientState::HandshakeAuth;
        Ok(())
    }

    fn initialization(&mut self, events: &mut Vec<VncEvent>) -> Result<(), VncError> {
        let mut buf = [0u8; 24];
        let name = {
            let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
            // Send ClientInit (shared flag = true)
            stream.write_all(&[1u8])?;
            // Read ServerInit
            stream.read_exact(&mut buf)?;

            let name_len = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]) as usize;
            let mut name_buf = vec![0u8; name_len];
            stream.read_exact(&mut name_buf)?;
            String::from_utf8_lossy(&name_buf).to_string()
        };

        self.width = u16::from_be_bytes([buf[0], buf[1]]);
        self.height = u16::from_be_bytes([buf[2], buf[3]]);
        self.pixel_format = PixelFormat::from_bytes(&buf[4..20])?;
        self.name = name;

        self.framebuffer
            .resize(self.width as usize, self.height as usize);

        events.push(VncEvent::GeometryChanged {
            width: self.width,
            height: self.height,
        });
        events.push(VncEvent::NameChanged(self.name.clone()));

        self.state = ClientState::Initialization;
        Ok(())
    }

    /// Set the desired pixel format.
    pub fn set_pixel_format(&mut self, format: PixelFormat) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut msg = [0u8; 20];
        msg[0] = 0; // SetPixelFormat
                    // msg[1..4] padding (already zero)
        format.write_to(&mut msg[4..20]);
        stream.write_all(&msg)?;
        self.pixel_format = format;
        Ok(())
    }

    /// Set the supported encodings.
    ///
    /// Sends a `SetEncodings` message to the server. Must be called after
    /// `handshake()` completes. The server will use the first encoding in the
    /// list that it also supports.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use vnc_client::encodings::Encoding;
    /// # use vnc_client::VncClient;
    /// # let mut client = VncClient::new();
    /// client.set_encodings(&[Encoding::Zrle, Encoding::Raw]).unwrap();
    /// ```
    pub fn set_encodings(&mut self, encodings: &[Encoding]) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut msg = Vec::with_capacity(4 + encodings.len() * 4);
        msg.push(2); // SetEncodings
        msg.push(0); // padding
        msg.extend_from_slice(&(encodings.len() as u16).to_be_bytes());
        for enc in encodings {
            msg.extend_from_slice(&enc.as_i32().to_be_bytes());
        }
        stream.write_all(&msg)?;
        Ok(())
    }

    /// Request a framebuffer update from the server.
    ///
    /// Sends a `FramebufferUpdateRequest` message. Set `incremental` to `false`
    /// for a full refresh, or `true` for incremental updates (only changed regions).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use vnc_client::VncClient;
    /// # let mut client = VncClient::new();
    /// // Request full update of the entire desktop
    /// client.request_update(false, 0, 0, 1920, 1080).unwrap();
    /// ```
    pub fn request_update(
        &mut self,
        incremental: bool,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut msg = [0u8; 10];
        msg[0] = 3; // FramebufferUpdateRequest
        msg[1] = if incremental { 1 } else { 0 };
        msg[2..4].copy_from_slice(&x.to_be_bytes());
        msg[4..6].copy_from_slice(&y.to_be_bytes());
        msg[6..8].copy_from_slice(&width.to_be_bytes());
        msg[8..10].copy_from_slice(&height.to_be_bytes());
        stream.write_all(&msg)?;
        Ok(())
    }

    /// Send a pointer (mouse) event.
    ///
    /// `button_mask` is a bitmask of pressed buttons:
    /// - bit 0: left button
    /// - bit 1: middle button
    /// - bit 2: right button
    /// - bit 3: scroll up
    /// - bit 4: scroll down
    /// - bit 5: scroll left
    /// - bit 6: scroll right
    pub fn send_pointer_event(&mut self, button_mask: u8, x: u16, y: u16) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let msg = [
            5u8, // PointerEvent
            button_mask,
            (x >> 8) as u8,
            x as u8,
            (y >> 8) as u8,
            y as u8,
        ];
        stream.write_all(&msg)?;
        Ok(())
    }

    /// Send a key event (key press or release).
    ///
    /// `keysym` is an X11 keysym value. Common values:
    /// - `0xff08`: BackSpace
    /// - `0xff09`: Tab
    /// - `0xff0d`: Return / Enter
    /// - `0xff1b`: Escape
    /// - `0xffe1`: Shift_L
    /// - `0xffe3`: Control_L
    /// - ASCII characters use their literal code (e.g. `'a'` = 0x61)
    pub fn send_key_event(&mut self, down: bool, keysym: u32) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut msg = [0u8; 8];
        msg[0] = 4; // KeyEvent
        msg[1] = if down { 1 } else { 0 };
        msg[4..8].copy_from_slice(&keysym.to_be_bytes());
        stream.write_all(&msg)?;
        Ok(())
    }

    /// Enable continuous updates (server pushes frames without client requests).
    pub fn enable_continuous_updates(
        &mut self,
        enable: bool,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut msg = [0u8; 10];
        msg[0] = protocol::CLIENT_ENABLE_CONTINUOUS_UPDATES;
        msg[1] = if enable { 1 } else { 0 };
        msg[2..4].copy_from_slice(&x.to_be_bytes());
        msg[4..6].copy_from_slice(&y.to_be_bytes());
        msg[6..8].copy_from_slice(&width.to_be_bytes());
        msg[8..10].copy_from_slice(&height.to_be_bytes());
        stream.write_all(&msg)?;
        Ok(())
    }

    /// Send a fence request to the server.
    pub fn send_fence(&mut self, flags: u32, data: &[u8]) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut msg = Vec::with_capacity(9 + data.len());
        msg.push(protocol::CLIENT_FENCE); // ClientFence
        msg.extend_from_slice(&flags.to_be_bytes());
        msg.extend_from_slice(&(data.len() as u32).to_be_bytes());
        msg.extend_from_slice(data);
        stream.write_all(&msg)?;
        Ok(())
    }

    /// Send extended clipboard text to the server.
    pub fn send_extended_clipboard_text(&mut self, text: &str) -> Result<(), VncError> {
        let data = clipboard::build_text_provide(text)?;
        self.send_cut_text_raw(&data)
    }

    fn send_cut_text_raw(&mut self, data: &[u8]) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut msg = Vec::with_capacity(8 + data.len());
        msg.push(6); // ClientCutText
        msg.extend_from_slice(&[0, 0, 0]); // padding
        msg.extend_from_slice(&(data.len() as u32).to_be_bytes());
        msg.extend_from_slice(data);
        stream.write_all(&msg)?;
        Ok(())
    }

    /// Send client cut text (legacy).
    pub fn send_cut_text(&mut self, text: &str) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let text_bytes = text.as_bytes();
        let mut msg = Vec::with_capacity(8 + text_bytes.len());
        msg.push(6); // ClientCutText
        msg.extend_from_slice(&[0, 0, 0]); // padding
        msg.extend_from_slice(&(text_bytes.len() as u32).to_be_bytes());
        msg.extend_from_slice(text_bytes);
        stream.write_all(&msg)?;
        Ok(())
    }

    /// Read and process server messages, returning any events.
    ///
    /// This is the main event loop function. It reads one server message,
    /// processes it (updating the framebuffer, cursor, clipboard, etc.),
    /// and returns a list of events for the UI to handle.
    ///
    /// # Typical usage
    ///
    /// ```no_run
    /// # use vnc_client::{VncClient, VncEvent};
    /// # let mut client = VncClient::new();
    /// loop {
    ///     match client.read_messages() {
    ///         Ok(events) => {
    ///             for event in events {
    ///                 match event {
    ///                     VncEvent::FramebufferUpdate { x, y, width, height } => {
    ///                         // Repaint region (x, y, w, h)
    ///                     }
    ///                     VncEvent::CursorShape(cursor) => {
    ///                         // Update local cursor image
    ///                     }
    ///                     _ => {}
    ///                 }
    ///             }
    ///         }
    ///         Err(e) => {
    ///             eprintln!("Connection error: {}", e);
    ///             break;
    ///         }
    ///     }
    /// }
    /// ```
    pub fn read_messages(&mut self) -> Result<Vec<VncEvent>, VncError> {
        if self.state != ClientState::Ready {
            return Err(VncError::Protocol("Client not in Ready state".to_string()));
        }

        let mut events = Vec::new();
        let mut msg_type = [0u8; 1];
        match self
            .stream
            .as_mut()
            .ok_or(VncError::NotConnected)?
            .read_exact(&mut msg_type)
        {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(VncError::ServerClosed);
            }
            Err(e) => return Err(e.into()),
        }

        match msg_type[0] {
            0 => {
                log::debug!("Server message: FramebufferUpdate");
                self.last_msg_type = Some(0);
                self.handle_framebuffer_update(&mut events)?;
            }
            2 => {
                log::debug!("Server message: Bell");
                self.last_msg_type = Some(2);
                events.push(VncEvent::Bell);
            }
            3 => {
                log::debug!("Server message: ServerCutText");
                self.last_msg_type = Some(3);
                self.handle_server_cut_text(&mut events)?;
            }
            4 => {
                log::debug!("Server message: EndOfContinuousUpdates (legacy type 4)");
                self.last_msg_type = Some(4);
                events.push(VncEvent::EndOfContinuousUpdates);
            }
            5 => {
                log::debug!("Server message: ServerFence (legacy type 5)");
                self.last_msg_type = Some(5);
                self.handle_server_fence(&mut events)?;
            }
            150 => {
                log::debug!("Server message: EndOfContinuousUpdates");
                self.last_msg_type = Some(150);
                events.push(VncEvent::EndOfContinuousUpdates);
            }
            248 => {
                log::debug!("Server message: ServerFence");
                self.last_msg_type = Some(248);
                self.handle_server_fence(&mut events)?;
            }
            255 => {
                log::debug!("Server message: QEMU extension");
                self.last_msg_type = Some(255);
                self.handle_qemu_extension(&mut events)?;
            }
            _ => {
                let bytes_read = self.stream.as_ref().map(|s| s.bytes_read()).unwrap_or(0);
                log::debug!(
                    "Unknown server message type: {} (last_msg_type={:?}, last_encoding={:?}, recent_encodings={:?}, pixel_format={:?}, bytes_read={})",
                    msg_type[0],
                    self.last_msg_type,
                    self.last_encoding,
                    self.recent_encodings,
                    self.pixel_format,
                    bytes_read
                );
                return Err(VncError::Protocol(format!(
                    "Unknown server message type: {} (last_msg_type={:?}, last_encoding={:?}, recent_encodings={:?})",
                    msg_type[0],
                    self.last_msg_type,
                    self.last_encoding,
                    self.recent_encodings
                )));
            }
        }

        Ok(events)
    }

    fn handle_framebuffer_update(&mut self, events: &mut Vec<VncEvent>) -> Result<(), VncError> {
        let mut buf = [0u8; 3];
        let num_rects = {
            let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
            stream.read_exact(&mut buf)?;
            u16::from_be_bytes([buf[1], buf[2]])
        };
        log::debug!("Framebuffer update: {} rectangles", num_rects);
        self.recent_encodings.clear();
        self.recent_encodings.reserve(num_rects as usize);
        let bytes_before = self.stream.as_ref().map(|s| s.bytes_read()).unwrap_or(0);

        for _ in 0..num_rects {
            let mut rect_header = [0u8; 12];
            let (x, y, width, height, encoding) = {
                let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                stream.read_exact(&mut rect_header)?;
                let x = u16::from_be_bytes([rect_header[0], rect_header[1]]);
                let y = u16::from_be_bytes([rect_header[2], rect_header[3]]);
                let width = u16::from_be_bytes([rect_header[4], rect_header[5]]);
                let height = u16::from_be_bytes([rect_header[6], rect_header[7]]);
                let encoding = i32::from_be_bytes([
                    rect_header[8],
                    rect_header[9],
                    rect_header[10],
                    rect_header[11],
                ]);
                log::debug!(
                    "Framebuffer update rectangle: {}x{}@({}, {}) encoding={}",
                    width,
                    height,
                    x,
                    y,
                    encoding
                );
                self.last_encoding = Some(encoding);
                self.recent_encodings.push(encoding);
                (x, y, width, height, encoding)
            };

            match encoding {
                0 => self.handle_raw_encoding(x, y, width, height)?,
                1 => self.handle_copyrect_encoding(x, y, width, height)?,
                2 => self.handle_rre_encoding(x, y, width, height)?,
                5 => self.handle_hextile_encoding(x, y, width, height)?,
                6 => self.handle_tight_encoding(x, y, width, height)?,
                15 => self.handle_trle_encoding(x, y, width, height)?,
                16 => self.handle_zrle_encoding(x, y, width, height)?,
                50 => self.handle_openh264_encoding(x, y, width, height)?,
                -223 => self.handle_desktop_size_pseudo_encoding(x, y, width, height, events)?,
                -240 => {
                    // CursorPos pseudo-encoding: no extra data
                    events.push(VncEvent::CursorPos { x, y });
                }
                -239 => self.handle_cursor_pseudo_encoding(x, y, width, height, events)?,
                -307 => self.handle_desktop_name_pseudo_encoding(events)?,
                -308 => {
                    self.handle_extended_desktop_size_pseudo_encoding(x, y, width, height, events)?
                }
                -1063131699 => {
                    // Extended Clipboard pseudo-encoding is only a capability
                    // declaration; actual clipboard data comes via ServerCutText.
                    // The server should not send pixel data for this encoding.
                    log::debug!("Ignoring ExtendedClipboard pseudo-encoding rectangle");
                }
                -312 => self.handle_fence_pseudo_encoding(events, width, height)?,
                _ => {
                    return Err(VncError::Protocol(format!(
                        "Unsupported encoding: {}",
                        encoding
                    )));
                }
            }

            events.push(VncEvent::FramebufferUpdate {
                x,
                y,
                width,
                height,
            });
        }

        let bytes_after = self.stream.as_ref().map(|s| s.bytes_read()).unwrap_or(0);
        log::debug!(
            "Framebuffer update completed: {} rectangles, consumed {} bytes",
            num_rects,
            bytes_after - bytes_before
        );

        let most_common = stats::most_common_encoding(&self.recent_encodings);
        self.stats_tracker.record_frame(most_common);

        Ok(())
    }

    fn handle_raw_encoding(
        &mut self,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) -> Result<(), VncError> {
        let pixel_format = self.pixel_format;
        let bpp = pixel_format.bytes_per_pixel();
        let row_size = width as usize * bpp;
        let total_size = row_size * height as usize;
        log::debug!(
            "Raw encoding: {}x{}@({}, {}) bpp={} total_size={} pixel_format={:?}",
            width,
            height,
            x,
            y,
            bpp,
            total_size,
            pixel_format
        );

        // Raw frames can be very large (e.g. 2560x1440 x 4 bytes). Temporarily
        // extend the read timeout so that short per-read timeouts don't cause the
        // stream to become misaligned mid-frame.
        let saved_timeout = self.read_timeout;
        self.set_read_timeout(Some(Duration::from_secs(60)))?;

        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut data = vec![0u8; total_size];
        let read_result = stream.read_exact(&mut data);

        // Restore the previous timeout best-effort; report the original read
        // error if it failed.
        let _ = self.set_read_timeout(saved_timeout);
        read_result?;

        self.framebuffer.write_region(
            x as usize,
            y as usize,
            width as usize,
            height as usize,
            &data,
            &pixel_format,
        );

        log::debug!(
            "Raw encoding complete: {}x{}@({}, {}) total_size={}",
            width,
            height,
            x,
            y,
            total_size
        );
        Ok(())
    }

    fn handle_copyrect_encoding(
        &mut self,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf)?;
        let src_x = u16::from_be_bytes([buf[0], buf[1]]);
        let src_y = u16::from_be_bytes([buf[2], buf[3]]);
        self.framebuffer.copy_rect(
            src_x as usize,
            src_y as usize,
            x as usize,
            y as usize,
            width as usize,
            height as usize,
        );
        Ok(())
    }

    fn handle_rre_encoding(
        &mut self,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) -> Result<(), VncError> {
        let pixel_format = self.pixel_format;
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        rre::decode(
            stream,
            &mut self.framebuffer,
            x as usize,
            y as usize,
            width as usize,
            height as usize,
            &pixel_format,
        )?;
        Ok(())
    }

    fn handle_hextile_encoding(
        &mut self,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) -> Result<(), VncError> {
        let pixel_format = self.pixel_format;
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        hextile::decode(
            stream,
            &mut self.framebuffer,
            x as usize,
            y as usize,
            width as usize,
            height as usize,
            &pixel_format,
        )?;
        Ok(())
    }

    fn handle_trle_encoding(
        &mut self,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) -> Result<(), VncError> {
        let pixel_format = self.pixel_format;
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        trle::decode(
            stream,
            &mut self.framebuffer,
            x as usize,
            y as usize,
            width as usize,
            height as usize,
            &pixel_format,
        )?;
        Ok(())
    }

    fn handle_zrle_encoding(
        &mut self,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) -> Result<(), VncError> {
        let pixel_format = self.pixel_format;
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        zrle::decode(
            stream,
            &mut self.zrle_decompress,
            &mut self.framebuffer,
            x as usize,
            y as usize,
            width as usize,
            height as usize,
            &pixel_format,
        )?;
        Ok(())
    }

    fn handle_tight_encoding(
        &mut self,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) -> Result<(), VncError> {
        let pixel_format = self.pixel_format;
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        tight::decode(
            stream,
            &mut self.framebuffer,
            x as usize,
            y as usize,
            width as usize,
            height as usize,
            &pixel_format,
        )?;
        Ok(())
    }

    fn handle_openh264_encoding(
        &mut self,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        // Read the H264 frame data. The size is encoded in width*height as a
        // workaround since H264 frames are variable-length.
        let data_len = (width as usize) * (height as usize);
        let mut data = vec![0u8; data_len];
        stream.read_exact(&mut data)?;

        if self.h264_decoder.is_none() {
            self.h264_decoder = Some(Box::new(DefaultDecoder::new()?));
        }

        let decoder = self.h264_decoder.as_ref().unwrap();
        let rgba = decoder.decode_frame(&data)?;
        let rgba_format = PixelFormat::rgba32();

        // The decoded frame dimensions should match the negotiated video size
        // or the expected rectangle. Write to framebuffer.
        if let Some((vw, vh)) = decoder.video_size() {
            self.framebuffer.write_region(
                x as usize,
                y as usize,
                vw as usize,
                vh as usize,
                &rgba,
                &rgba_format,
            );
        } else {
            // Fallback: assume the rectangle dimensions
            let row_size = width as usize * 4;
            let expected_size = row_size * height as usize;
            if rgba.len() >= expected_size {
                self.framebuffer.write_region(
                    x as usize,
                    y as usize,
                    width as usize,
                    height as usize,
                    &rgba[..expected_size],
                    &rgba_format,
                );
            }
        }

        Ok(())
    }

    fn handle_desktop_size_pseudo_encoding(
        &mut self,
        _x: u16,
        _y: u16,
        width: u16,
        height: u16,
        events: &mut Vec<VncEvent>,
    ) -> Result<(), VncError> {
        self.width = width;
        self.height = height;
        self.framebuffer.resize(width as usize, height as usize);
        events.push(VncEvent::GeometryChanged { width, height });
        Ok(())
    }

    fn handle_cursor_pseudo_encoding(
        &mut self,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        events: &mut Vec<VncEvent>,
    ) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let bpp = self.pixel_format.bytes_per_pixel();
        let pixel_data_size = width as usize * height as usize * bpp;
        let mask_row_bytes = (width as usize).div_ceil(8);
        let mask_size = mask_row_bytes * height as usize;
        let mut data = vec![0u8; pixel_data_size + mask_size];
        stream.read_exact(&mut data)?;
        let cursor = CursorShape::decode(width, height, x, y, &data, &self.pixel_format)?;
        events.push(VncEvent::CursorShape(cursor));
        Ok(())
    }

    fn handle_desktop_name_pseudo_encoding(
        &mut self,
        events: &mut Vec<VncEvent>,
    ) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf)?;
        let name_len = u32::from_be_bytes(buf) as usize;
        let mut name_buf = vec![0u8; name_len];
        stream.read_exact(&mut name_buf)?;
        self.name = String::from_utf8_lossy(&name_buf).to_string();
        events.push(VncEvent::NameChanged(self.name.clone()));
        Ok(())
    }

    fn handle_extended_desktop_size_pseudo_encoding(
        &mut self,
        _x: u16,
        _y: u16,
        width: u16,
        height: u16,
        events: &mut Vec<VncEvent>,
    ) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf)?;
        let num_screens = u32::from_be_bytes(buf) as usize;

        // Read screen data (each screen: u32 id, u16 x, u16 y, u16 width, u16 height, u32 flags)
        let screen_data_size = num_screens * 16;
        let mut screen_data = vec![0u8; screen_data_size];
        stream.read_exact(&mut screen_data)?;

        let mut screens = Vec::with_capacity(num_screens);
        for i in 0..num_screens {
            let off = i * 16;
            let id = u32::from_be_bytes([
                screen_data[off],
                screen_data[off + 1],
                screen_data[off + 2],
                screen_data[off + 3],
            ]);
            let x = u16::from_be_bytes([screen_data[off + 4], screen_data[off + 5]]);
            let y = u16::from_be_bytes([screen_data[off + 6], screen_data[off + 7]]);
            let w = u16::from_be_bytes([screen_data[off + 8], screen_data[off + 9]]);
            let h = u16::from_be_bytes([screen_data[off + 10], screen_data[off + 11]]);
            let flags = u32::from_be_bytes([
                screen_data[off + 12],
                screen_data[off + 13],
                screen_data[off + 14],
                screen_data[off + 15],
            ]);
            screens.push(Screen {
                id,
                x,
                y,
                width: w,
                height: h,
                flags,
            });
        }

        self.width = width;
        self.height = height;
        self.framebuffer.resize(width as usize, height as usize);

        events.push(VncEvent::GeometryChanged { width, height });
        events.push(VncEvent::ScreenLayout(screens));
        Ok(())
    }

    fn handle_fence_pseudo_encoding(
        &mut self,
        events: &mut Vec<VncEvent>,
        _width: u16,
        _height: u16,
    ) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf)?;
        let flags = u32::from_be_bytes(buf);
        let mut len_buf = [0u8; 1];
        stream.read_exact(&mut len_buf)?;
        let len = len_buf[0] as usize;
        let mut data = vec![0u8; len];
        stream.read_exact(&mut data)?;
        log::debug!(
            "Fence pseudo-encoding rect flags={:#010x} len={}",
            flags,
            len
        );
        events.push(VncEvent::Fence { flags, data });
        Ok(())
    }

    fn handle_server_cut_text(&mut self, events: &mut Vec<VncEvent>) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut buf = [0u8; 7];
        stream.read_exact(&mut buf)?;
        let len = i32::from_be_bytes([buf[3], buf[4], buf[5], buf[6]]);
        log::debug!("ServerCutText length: {}", len);

        if len >= 0 {
            let len = len as usize;
            let mut text = vec![0u8; len];
            stream.read_exact(&mut text)?;
            events.push(VncEvent::CutText(
                String::from_utf8_lossy(&text).to_string(),
            ));
        } else {
            // Extended Clipboard format: abs(length) bytes of extended data
            // follow the header. The first 4 bytes of that data are flags.
            let len = len.abs() as usize;
            let mut data = vec![0u8; len];
            stream.read_exact(&mut data)?;
            let message = clipboard::decode_message(&data)?;
            events.push(VncEvent::ClipboardData(message));
        }
        Ok(())
    }

    /// Get the current framebuffer.
    pub fn framebuffer(&self) -> &Framebuffer {
        &self.framebuffer
    }

    /// Get mutable framebuffer.
    pub fn framebuffer_mut(&mut self) -> &mut Framebuffer {
        &mut self.framebuffer
    }

    /// Get dimensions.
    pub fn dimensions(&self) -> (u16, u16) {
        (self.width, self.height)
    }

    /// Get a snapshot of connection statistics.
    pub fn stats(&mut self) -> ConnectionStats {
        self.stats_tracker
            .sample(self.width, self.height, self.stream.as_ref())
    }

    /// Get desktop width.
    pub fn width(&self) -> u16 {
        self.width
    }

    /// Get desktop height.
    pub fn height(&self) -> u16 {
        self.height
    }

    /// Get desktop name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get pixel format.
    pub fn pixel_format(&self) -> &PixelFormat {
        &self.pixel_format
    }

    /// Set read timeout on the underlying TCP stream.
    /// Set framebuffer transform for rendering (rotation, flip).
    pub fn set_transform(&mut self, transform: Transform) {
        self.framebuffer.set_transform(transform);
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<(), VncError> {
        self.read_timeout = timeout;
        self.stream
            .as_mut()
            .ok_or(VncError::NotConnected)?
            .set_read_timeout(timeout)?;
        Ok(())
    }

    /// Handle ServerFence messages (message type 248).
    ///
    /// The server sends this after the client requests the Fence pseudo-encoding.
    /// Format: 3 bytes padding, 4 bytes flags, 1 byte length, length bytes payload.
    fn handle_server_fence(&mut self, events: &mut Vec<VncEvent>) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf)?; // padding
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf)?;
        let flags = u32::from_be_bytes(buf);
        let mut len_buf = [0u8; 1];
        stream.read_exact(&mut len_buf)?;
        let len = len_buf[0] as usize;
        let mut data = vec![0u8; len];
        stream.read_exact(&mut data)?;
        log::debug!("ServerFence flags={:#010x} len={}", flags, len);
        events.push(VncEvent::Fence { flags, data });
        Ok(())
    }

    /// Handle QEMU extension messages (type 255).
    ///
    /// Sub-types:
    /// - 0: QEMU Extended Key Event (client → server, ignored here)
    /// - 1: LED State (server → client)
    fn handle_qemu_extension(&mut self, events: &mut Vec<VncEvent>) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf)?;
        let sub_type = buf[0];

        match sub_type {
            1 => {
                // LED State
                stream.read_exact(&mut buf)?;
                let state = buf[0];
                events.push(VncEvent::LedState {
                    scroll_lock: (state & 0x01) != 0,
                    num_lock: (state & 0x02) != 0,
                    caps_lock: (state & 0x04) != 0,
                });
            }
            2 => {
                // Audio (QEMU extension)
                stream.read_exact(&mut buf)?;
                let operation = buf[0];
                match operation {
                    0 => {
                        // Stop audio
                        // No additional data; UI should stop playback
                    }
                    1 => {
                        // Start audio / format info
                        let mut fmt_buf = [0u8; 10];
                        stream.read_exact(&mut fmt_buf)?;
                        let sample_rate =
                            u32::from_be_bytes([fmt_buf[0], fmt_buf[1], fmt_buf[2], fmt_buf[3]]);
                        let channels = fmt_buf[4];
                        let bits_per_sample = fmt_buf[5];
                        let data_len =
                            u32::from_be_bytes([fmt_buf[6], fmt_buf[7], fmt_buf[8], fmt_buf[9]])
                                as usize;
                        let mut data = vec![0u8; data_len];
                        if data_len > 0 {
                            stream.read_exact(&mut data)?;
                        }
                        events.push(VncEvent::Audio {
                            sample_rate,
                            channels,
                            bits_per_sample,
                            data,
                        });
                    }
                    2 => {
                        // Audio data
                        let mut len_buf = [0u8; 4];
                        stream.read_exact(&mut len_buf)?;
                        let data_len = u32::from_be_bytes(len_buf) as usize;
                        let mut data = vec![0u8; data_len];
                        if data_len > 0 {
                            stream.read_exact(&mut data)?;
                        }
                        events.push(VncEvent::Audio {
                            sample_rate: 0, // unknown, use last format
                            channels: 0,
                            bits_per_sample: 0,
                            data,
                        });
                    }
                    _ => {
                        eprintln!("Warning: Unknown QEMU audio operation: {}", operation);
                    }
                }
            }
            other => {
                // Unknown QEMU extension sub-type; skip 1 byte payload
                stream.read_exact(&mut buf)?;
                eprintln!("Warning: Unknown QEMU extension sub-type: {}", other);
            }
        }

        Ok(())
    }
}

impl Default for VncClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for [`VncClient`].
///
/// Provides a fluent API for configuring connection parameters before
/// creating the client. All settings are optional; defaults are reasonable
/// for most use cases.
///
/// ```no_run
/// use vnc_client::VncClientBuilder;
///
/// let client = VncClientBuilder::new()
///     .pixel_format(vnc_client::PixelFormat::rgba32())
///     .encodings(vec![
///         vnc_client::encodings::Encoding::Tight,
///         vnc_client::encodings::Encoding::Zrle,
///         vnc_client::encodings::Encoding::Raw,
///     ])
///     .build();
/// ```
pub struct VncClientBuilder {
    pixel_format: Option<PixelFormat>,
    encodings: Vec<Encoding>,
    sasl_username: String,
    sasl_password: String,
}

impl VncClientBuilder {
    pub fn new() -> Self {
        Self {
            pixel_format: None,
            encodings: vec![
                Encoding::Tight,
                Encoding::Zrle,
                Encoding::Hextile,
                Encoding::Raw,
                Encoding::CopyRect,
                Encoding::Rre,
                Encoding::Trle,
                Encoding::OpenH264,
                Encoding::DesktopSize,
                Encoding::DesktopName,
                Encoding::ExtendedDesktopSize,
                Encoding::Cursor,
                Encoding::ContinuousUpdates,
                Encoding::ExtendedClipboard,
                Encoding::Fence,
            ],
            sasl_username: String::new(),
            sasl_password: String::new(),
        }
    }

    /// Set SASL credentials for VeNCrypt SASL authentication.
    pub fn sasl_credentials(mut self, username: &str, password: &str) -> Self {
        self.sasl_username = username.to_string();
        self.sasl_password = password.to_string();
        self
    }

    pub fn pixel_format(mut self, format: PixelFormat) -> Self {
        self.pixel_format = Some(format);
        self
    }

    pub fn encodings(mut self, encodings: Vec<Encoding>) -> Self {
        self.encodings = encodings;
        self
    }

    /// Set JPEG quality level (0-9) as a pseudo-encoding.
    pub fn jpeg_quality(mut self, level: u8) -> Self {
        self.encodings
            .push(Encoding::JpegQuality(level.clamp(0, 9) as i32));
        self
    }

    pub fn build(self) -> VncClient {
        let mut client = VncClient::new();
        if let Some(format) = self.pixel_format {
            client.pixel_format = format;
        }
        client.encodings = self.encodings;
        client.sasl_username = self.sasl_username;
        client.sasl_password = self.sasl_password;
        client
    }
}

impl Default for VncClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_copies_encodings_to_client() {
        let client = VncClientBuilder::new()
            .encodings(vec![Encoding::Raw, Encoding::CopyRect])
            .build();
        assert_eq!(client.encodings, vec![Encoding::Raw, Encoding::CopyRect]);
    }

    #[test]
    fn builder_default_encodings_applied() {
        let client = VncClientBuilder::new().build();
        assert!(!client.encodings.is_empty());
        assert!(client.encodings.contains(&Encoding::Zrle));
        assert!(client.encodings.contains(&Encoding::Raw));
    }
}
