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

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::tls::TlsStream;

pub mod apple_dh;
pub mod apple_record_layer;
pub mod apple_srp;
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
pub mod zlib;
pub mod zrle;

use auth::AuthHandler;
use cursor::CursorShape;
use decoder::DefaultDecoder;
use encodings::Encoding;
use flate2::read::ZlibDecoder;
use flate2::Decompress;
use framebuffer::Framebuffer;

pub use framebuffer::PixelFormat;
pub use framebuffer::Transform;
pub use stats::ConnectionStats;

enum VncStreamInner {
    Plain(TcpStream),
    Tls(Box<TlsStream>),
    Aes(Box<rsa_aes::AesCfbStream>),
    Ws(Box<ws::WsStream>),
    AppleHp(Box<apple_record_layer::AppleRecordLayer<TcpStream>>),
}

impl VncStreamInner {
    fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        match self {
            VncStreamInner::Plain(s) => s.set_read_timeout(timeout),
            VncStreamInner::Tls(s) => s.set_read_timeout(timeout),
            VncStreamInner::Aes(s) => s.set_read_timeout(timeout),
            VncStreamInner::Ws(s) => s.set_read_timeout(timeout),
            VncStreamInner::AppleHp(s) => s.set_read_timeout(timeout),
        }
    }

    fn set_nodelay(&self, nodelay: bool) -> std::io::Result<()> {
        match self {
            VncStreamInner::Plain(s) => s.set_nodelay(nodelay),
            VncStreamInner::Tls(s) => s.set_nodelay(nodelay),
            VncStreamInner::Aes(s) => s.set_nodelay(nodelay),
            VncStreamInner::Ws(s) => s.set_nodelay(nodelay),
            VncStreamInner::AppleHp(s) => s.set_nodelay(nodelay),
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
            VncStreamInner::AppleHp(s) => s.read(buf),
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
            VncStreamInner::AppleHp(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            VncStreamInner::Plain(s) => s.flush(),
            VncStreamInner::Tls(s) => s.flush(),
            VncStreamInner::Aes(s) => s.flush(),
            VncStreamInner::Ws(s) => s.flush(),
            VncStreamInner::AppleHp(s) => s.flush(),
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

    /// Rekey the Apple high-performance record layer, if active.
    pub fn rekey_apple_record_layer(&mut self, body: &[u8]) -> Result<(), VncError> {
        match &mut self.inner {
            VncStreamInner::AppleHp(layer) => layer.rekey(body),
            _ => Err(VncError::Protocol(
                "Apple record layer not active".to_string(),
            )),
        }
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
    /// Value sent in the ClientInit shared byte. Apple high-performance mode
    /// uses [`protocol::apple::CLIENT_INIT_SHARED`]; legacy Apple DH type 30 used
    /// [`protocol::apple::CLIENT_INIT_SHARED_LEGACY_ARD`].
    client_init_shared: u8,
    h264_decoder: Option<Box<dyn decoder::VideoDecoder>>,
    encodings: Vec<Encoding>,
    host: String,
    sasl_username: String,
    sasl_password: String,
    server_security_types: Vec<u8>,
    zrle_decompress: Option<Decompress>,
    zlib_decompress: Option<Decompress>,
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
    /// Whether to negotiate Apple high-performance mode (requires `RFB 003.889`).
    high_performance: bool,
    /// Initial AES wrap key returned by Apple authentication (type 30 or 33).
    apple_wrap_key: Option<Vec<u8>>,
    /// Apple virtual display configuration requested by the builder.
    apple_display_width: u16,
    apple_display_height: u16,
    apple_display_dynamic: bool,
    apple_hidpi_scale: f32,
    /// Whether to request a virtual display (curtain mode) in Apple HP mode.
    /// When false, the server's physical display is mirrored.
    apple_virtual_display: bool,
    /// Apple cursor cache keyed by `cache_id`. STOREd cursors are kept here;
    /// SELECT rectangles reference a cached id and emit a `CursorShape` event.
    apple_cursor_cache: HashMap<u32, AppleCursor>,
}

/// A cached Apple HP cursor image (encoding [`protocol::apple::ENC_CURSOR`]).
#[derive(Debug, Clone)]
struct AppleCursor {
    width: u16,
    height: u16,
    pixels: Vec<u8>, // RGBA8888, non-premultiplied
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
            client_init_shared: 1,
            h264_decoder: None,
            encodings: Vec::new(),
            host: String::new(),
            sasl_username: String::new(),
            sasl_password: String::new(),
            server_security_types: Vec::new(),
            zrle_decompress: None,
            zlib_decompress: None,
            stats_tracker: stats::ConnectionStatsTracker::new(),
            read_timeout: None,
            last_msg_type: None,
            last_encoding: None,
            recent_encodings: Vec::new(),
            high_performance: false,
            apple_wrap_key: None,
            apple_display_width: 1920,
            apple_display_height: 1080,
            apple_display_dynamic: false,
            apple_hidpi_scale: 2.0,
            apple_virtual_display: true,
            apple_cursor_cache: HashMap::new(),
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
            inner: VncStreamInner::Ws(Box::new(stream)),
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
        // Apple HP mode already negotiates encodings during the encrypted record
        // layer setup, so skip the post-initialization SetEncodings for HP.
        if !self.encodings.is_empty() && !self.high_performance {
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
            "RFB 003.889" => {
                if self.high_performance {
                    protocol::apple::PROTOCOL_VERSION
                } else {
                    // Some servers advertise 003.889 to indicate vendor extensions, but
                    // the wire protocol is compatible with 003.008, so downgrade to 003.008.
                    b"RFB 003.008\n"
                }
            }
            "RFB 003.008" => b"RFB 003.008\n",
            "RFB 003.007" => b"RFB 003.007\n",
            "RFB 003.003" => b"RFB 003.003\n",
            _ => return Err(VncError::UnsupportedVersion(version.to_string())),
        };

        stream.write_all(our_version)?;
        self.state = ClientState::HandshakeVersion;
        Ok(())
    }

    /// Upgrade the current Plain TCP stream to TLS.
    /// Used by both TLS and X509 VeNCrypt sub-types.
    fn upgrade_to_tls(&mut self) -> Result<(), VncError> {
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
            Some(VncStream {
                inner: VncStreamInner::AppleHp(_),
                ..
            }) => {
                return Err(VncError::Protocol(
                    "Apple HP stream cannot be upgraded to TLS".to_string(),
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
            log::debug!("Server offered security types: {:?}", types);

            // Let the auth handler decide which non-VeNCrypt type to use. This
            // allows handlers like AppleDhAuthHandler to select type 30 while
            // NoAuthHandler and PasswordAuthHandler continue to prefer 1 / 2.
            let selected = if types.contains(&protocol::SECURITY_VENCRYPT) {
                protocol::SECURITY_VENCRYPT // VeNCrypt
            } else {
                auth.select_security_type(&types)?
            };

            stream.write_all(&[selected])?;
            selected
        };

        match selected {
            protocol::SECURITY_NONE => {
                let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf)?;
                let result = u32::from_be_bytes(buf);
                if result != 0 {
                    return Err(VncError::AuthFailed("Authentication failed".to_string()));
                }
            }
            protocol::SECURITY_VNC_AUTH => {
                let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                auth.authenticate_vnc(stream)?;
            }
            protocol::apple::SECURITY_DH => {
                let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                auth.authenticate(stream, protocol::apple::SECURITY_DH)?;
                if self.high_performance {
                    // High-performance mode uses the Apple HP ClientInit shared byte.
                    self.client_init_shared = protocol::apple::CLIENT_INIT_SHARED;
                } else {
                    // Apple's RFB type 30 uses a non-standard ClientInit shared byte.
                    // 0x1C triggers the extended session setup used by macOS Screen Sharing.
                    self.client_init_shared = protocol::apple::CLIENT_INIT_SHARED_LEGACY_ARD;
                }
                // Capture any session key for the record layer.
                if let Some(key) = auth.session_key() {
                    self.apple_wrap_key = Some(key);
                }
            }
            protocol::apple::SECURITY_RSA_SRP => {
                let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                auth.authenticate(stream, protocol::apple::SECURITY_RSA_SRP)?;
                self.client_init_shared = protocol::apple::CLIENT_INIT_SHARED;
                if let Some(key) = auth.session_key() {
                    self.apple_wrap_key = Some(key);
                }
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
                        self.upgrade_to_tls()?;
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
                        // X509: TLS + X509 certificate verification.
                        // Server cert is verified by webpki-roots via rustls.
                        self.upgrade_to_tls()?;
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
                            Some(VncStream {
                                inner: VncStreamInner::AppleHp(_),
                                ..
                            }) => {
                                return Err(VncError::Protocol(
                                    "Apple HP stream cannot use RSA-AES".to_string(),
                                ));
                            }
                            None => return Err(VncError::NotConnected),
                        };
                        let rsa_auth = rsa_aes::RsaAesAuth::new_128();
                        let key = rsa_auth.authenticate(&mut tcp)?;
                        let aes = rsa_aes::AesCfbStream::new(tcp, &key)?;
                        self.stream = Some(VncStream {
                            inner: VncStreamInner::Aes(Box::new(aes)),
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
                            Some(VncStream {
                                inner: VncStreamInner::AppleHp(_),
                                ..
                            }) => {
                                return Err(VncError::Protocol(
                                    "Apple HP stream cannot use RSA-AES-256".to_string(),
                                ));
                            }
                            None => return Err(VncError::NotConnected),
                        };
                        let rsa_auth = rsa_aes::RsaAesAuth::new_256();
                        let key = rsa_auth.authenticate(&mut tcp)?;
                        let aes = rsa_aes::AesCfbStream::new(tcp, &key)?;
                        self.stream = Some(VncStream {
                            inner: VncStreamInner::Aes(Box::new(aes)),
                            bytes_read,
                            bytes_written,
                        });
                    }
                    vencrypt::VencryptResult::AppleDh => {
                        // VeNCrypt Apple DH sub-type 30 is distinct from macOS Screen
                        // Sharing's direct security type 30. The direct type 30 flow is
                        // handled above (match arm `30 =>`); this VeNCrypt sub-type
                        // path is not yet implemented.
                        return Err(VncError::AuthFailed(
                            "VeNCrypt Apple DH sub-type not yet implemented".to_string(),
                        ));
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
            log::debug!(
                "Sending ClientInit (shared = 0x{:02x})",
                self.client_init_shared
            );
            stream.write_all(&[self.client_init_shared])?;
            // Read ServerInit
            stream.read_exact(&mut buf)?;

            let name_len = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]) as usize;
            log::debug!("ServerInit header: name_len = {}", name_len);
            if name_len > 4096 {
                return Err(VncError::Protocol(format!(
                    "ServerInit name length too large: {}",
                    name_len
                )));
            }
            let mut name_buf = vec![0u8; name_len];
            stream.read_exact(&mut name_buf)?;
            String::from_utf8_lossy(&name_buf).to_string()
        };

        self.width = u16::from_be_bytes([buf[0], buf[1]]);
        self.height = u16::from_be_bytes([buf[2], buf[3]]);
        self.pixel_format = PixelFormat::from_bytes(&buf[4..20])?;
        self.name = name;

        log::debug!(
            "ServerInit: {}x{} name = {:?}",
            self.width,
            self.height,
            self.name
        );

        self.framebuffer
            .resize(self.width as usize, self.height as usize);

        events.push(VncEvent::GeometryChanged {
            width: self.width,
            height: self.height,
        });
        events.push(VncEvent::NameChanged(self.name.clone()));

        if self.high_performance {
            let wrap_key = self
                .apple_wrap_key
                .as_ref()
                .ok_or_else(|| {
                    VncError::Protocol(
                        "Apple high-performance mode requires a session wrap key".to_string(),
                    )
                })?
                .clone();

            // Plaintext prelude before the record layer is activated.
            // Native Screen Sharing.app sends ViewerInfo + 0x12 follow-up,
            // then (optionally) SetDisplayConfiguration, then the first
            // SetEncodings before the server emits the rekey rectangle.
            {
                let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                log::debug!("Apple HP: sending ViewerInfo");
                stream.write_all(&apple_record_layer::build_viewer_info(&[]))?;
                log::debug!("Apple HP: sending SetEncryption command=1");
                stream.write_all(&apple_record_layer::build_set_encryption_command1())?;
                if self.apple_virtual_display {
                    log::debug!("Apple HP: sending SetDisplayConfiguration");
                    stream.write_all(&apple_record_layer::build_set_display_configuration(
                        self.apple_display_width,
                        self.apple_display_height,
                        self.apple_display_dynamic,
                        self.apple_hidpi_scale,
                    ))?;
                }
                log::debug!("Apple HP: sending initial SetEncodings");
                stream.write_all(&apple_record_layer::build_set_encodings(
                    apple_record_layer::APPLE_HP_ENCODINGS,
                ))?;
            }

            // The server replies with a FramebufferUpdate containing a rekey rectangle.
            let rekey_body = self.read_apple_initial_rekey_body()?;
            log::debug!(
                "Apple HP: received initial rekey ({} bytes)",
                rekey_body.len()
            );

            // Tell the server we are switching to the encrypted record layer.
            {
                let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                log::debug!("Apple HP: sending PostEncryptionToggle");
                stream.write_all(&apple_record_layer::build_post_encryption_toggle())?;
            }

            // Replace the plain TCP stream with the encrypted record layer.
            let (tcp, bytes_read, bytes_written) = match self.stream.take() {
                Some(VncStream {
                    inner: VncStreamInner::Plain(tcp),
                    bytes_read,
                    bytes_written,
                }) => (tcp, bytes_read, bytes_written),
                Some(other) => {
                    self.stream = Some(other);
                    return Err(VncError::Protocol(
                        "Apple high-performance mode requires a plain TCP stream".to_string(),
                    ));
                }
                None => return Err(VncError::NotConnected),
            };
            let layer =
                apple_record_layer::AppleRecordLayer::new_from_rekey(tcp, &wrap_key, &rekey_body)?;
            self.stream = Some(VncStream {
                inner: VncStreamInner::AppleHp(Box::new(layer)),
                bytes_read,
                bytes_written,
            });

            // Encrypted preface: send SetEncodings, a full update request, and
            // AutoFrameBufferUpdate to arm the server sender.
            log::debug!("Apple HP: sending encrypted SetEncodings");
            self.set_encodings(&self.encodings.clone())?;
            log::debug!("Apple HP: sending encrypted FramebufferUpdateRequest");
            self.request_update(false, 0, 0, self.width, self.height)?;
            log::debug!("Apple HP: sending encrypted AutoFrameBufferUpdate");
            self.stream
                .as_mut()
                .ok_or(VncError::NotConnected)?
                .write_all(&apple_record_layer::build_auto_framebuffer_update(
                    protocol::apple::SELECTED_SCREEN_ALL,
                    0,
                    0,
                    self.width,
                    self.height,
                ))?;
        }

        self.state = ClientState::Initialization;
        Ok(())
    }

    /// Read the initial plaintext rekey rectangle (encoding [`protocol::apple::ENC_REKEY`]) that the
    /// server emits during the Apple HP handshake. Tolerates a small amount of
    /// [`protocol::apple::MISC_STATUS`] traffic and Apple still-image codec
    /// announcement rectangles (`1010`, `1011`) that can precede the rekey.
    fn read_apple_initial_rekey_body(&mut self) -> Result<Vec<u8>, VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        loop {
            let mut msg_type = [0u8; 1];
            stream.read_exact(&mut msg_type)?;
            match msg_type[0] {
                protocol::SERVER_FRAMEBUFFER_UPDATE => {
                    let mut buf = [0u8; 3];
                    stream.read_exact(&mut buf)?;
                    let num_rects = u16::from_be_bytes([buf[1], buf[2]]);
                    let mut found_rekey: Option<Vec<u8>> = None;
                    for _ in 0..num_rects {
                        let mut rect = [0u8; 12];
                        stream.read_exact(&mut rect)?;
                        let x = u16::from_be_bytes([rect[0], rect[1]]);
                        let y = u16::from_be_bytes([rect[2], rect[3]]);
                        let w = u16::from_be_bytes([rect[4], rect[5]]);
                        let h = u16::from_be_bytes([rect[6], rect[7]]);
                        let enc = i32::from_be_bytes([rect[8], rect[9], rect[10], rect[11]]);

                        if enc == protocol::apple::ENC_REKEY && x == 0 && y == 0 && w == 0 && h == 0
                        {
                            let mut body = vec![0u8; 36];
                            stream.read_exact(&mut body)?;
                            found_rekey = Some(body);
                            continue;
                        }

                        // Still-image codec announcement rectangles may precede the
                        // rekey; they carry a u16 length prefix and a payload.
                        if enc == 1010 || enc == 1011 {
                            let mut len_buf = [0u8; 2];
                            stream.read_exact(&mut len_buf)?;
                            let len = u16::from_be_bytes(len_buf) as usize;
                            let mut payload = vec![0u8; len];
                            stream.read_exact(&mut payload)?;
                            log::debug!(
                                "Apple HP: skipped {:#x} announcement ({} bytes) before rekey",
                                enc,
                                len
                            );
                            continue;
                        }

                        // Any other encoding before the rekey is unexpected.
                        return Err(VncError::Protocol(format!(
                            "Apple HP initial rekey FBU contained unexpected encoding {:#x}",
                            enc
                        )));
                    }
                    if let Some(body) = found_rekey {
                        return Ok(body);
                    }
                    // No rekey in this FBU; keep reading.
                }
                protocol::apple::MISC_STATUS => {
                    // MiscStatus server-to-client control message (8 bytes total).
                    let mut skip = [0u8; 7];
                    stream.read_exact(&mut skip)?;
                }
                other => {
                    return Err(VncError::Protocol(format!(
                        "Apple HP expected rekey FramebufferUpdate ({:#x}) or MiscStatus ({:#x}), got {:#x}",
                        protocol::SERVER_FRAMEBUFFER_UPDATE,
                        protocol::apple::MISC_STATUS,
                        other
                    )));
                }
            }
        }
    }

    /// Set the desired pixel format.
    pub fn set_pixel_format(&mut self, format: PixelFormat) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut msg = [0u8; 20];
        msg[0] = 0; // SetPixelFormat
                    // msg[1..4] padding (already zero)
        format.write_to(&mut msg[4..20]);
        log::debug!("Sending SetPixelFormat: {:?}", format);
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
        log::debug!("Sending SetEncodings with {} encodings", encodings.len());
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
    /// `button_mask` is a bitmask of pressed buttons using the standard RFB
    /// layout (RFC 6143):
    /// - bit 0: left button
    /// - bit 1: middle button
    /// - bit 2: right button
    /// - bit 3: scroll up
    /// - bit 4: scroll down
    /// - bit 5: scroll left
    /// - bit 6: scroll right
    ///
    /// In Apple high-performance mode the right and middle button bits are
    /// swapped on the wire relative to RFC 6143; this method performs the
    /// swap automatically when HP mode is active.
    pub fn send_pointer_event(&mut self, button_mask: u8, x: u16, y: u16) -> Result<(), VncError> {
        let button_mask = if self.high_performance {
            apple_pointer_button_mask(button_mask)
        } else {
            button_mask
        };
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

    /// Send a raw pointer event without applying any Apple HP button swap.
    ///
    /// Use this when you already have the on-wire button mask for the active
    /// security/encoding mode.
    pub fn send_pointer_event_raw(
        &mut self,
        button_mask: u8,
        x: u16,
        y: u16,
    ) -> Result<(), VncError> {
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
        log::debug!(
            "Sending EnableContinuousUpdates enable={} {}x{}@({},{})",
            enable,
            width,
            height,
            x,
            y
        );
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

        // Use a short timeout while waiting for the next message type so the
        // caller can periodically check for input events and heartbeats.
        let saved_timeout = self.read_timeout;
        self.set_read_timeout(Some(Duration::from_millis(50)))?;

        let mut msg_type = [0u8; 1];
        let msg_type_result = self
            .stream
            .as_mut()
            .ok_or(VncError::NotConnected)?
            .read_exact(&mut msg_type);

        if let Err(e) = msg_type_result {
            let _ = self.set_read_timeout(saved_timeout);
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return Err(VncError::ServerClosed);
            }
            return Err(e.into());
        }

        // Once we know a message is arriving, use a longer timeout while reading
        // the payload. Large frame updates (e.g. ZRLE, Raw, Tight) can take many
        // read calls; a short per-read timeout causes partial reads and stream
        // desynchronisation.
        self.set_read_timeout(Some(Duration::from_secs(60)))?;

        let payload_result = match msg_type[0] {
            protocol::SERVER_FRAMEBUFFER_UPDATE => {
                self.last_msg_type = Some(protocol::SERVER_FRAMEBUFFER_UPDATE);
                self.handle_framebuffer_update(&mut events)
            }
            protocol::SERVER_BELL => {
                log::debug!("Server message: Bell");
                self.last_msg_type = Some(protocol::SERVER_BELL);
                events.push(VncEvent::Bell);
                Ok(())
            }
            protocol::SERVER_SERVER_CUT_TEXT => {
                log::debug!("Server message: ServerCutText");
                self.last_msg_type = Some(protocol::SERVER_SERVER_CUT_TEXT);
                self.handle_server_cut_text(&mut events)
            }
            4 => {
                log::debug!("Server message: EndOfContinuousUpdates (legacy type 4)");
                self.last_msg_type = Some(4);
                events.push(VncEvent::EndOfContinuousUpdates);
                Ok(())
            }
            5 => {
                log::debug!("Server message: ServerFence (legacy type 5)");
                self.last_msg_type = Some(5);
                self.handle_server_fence(&mut events)
            }
            protocol::SERVER_END_OF_CONTINUOUS_UPDATES => {
                log::debug!("Server message: EndOfContinuousUpdates");
                self.last_msg_type = Some(protocol::SERVER_END_OF_CONTINUOUS_UPDATES);
                events.push(VncEvent::EndOfContinuousUpdates);
                Ok(())
            }
            protocol::CLIENT_FENCE => {
                log::debug!("Server message: ServerFence");
                self.last_msg_type = Some(protocol::CLIENT_FENCE);
                self.handle_server_fence(&mut events)
            }
            255 => {
                log::debug!("Server message: QEMU extension");
                self.last_msg_type = Some(255);
                self.handle_qemu_extension(&mut events)
            }
            protocol::apple::MISC_STATUS => {
                // Apple MiscStatus (8-byte control message); ignore for now.
                log::debug!("Server message: Apple MiscStatus (ignored)");
                self.last_msg_type = Some(protocol::apple::MISC_STATUS);
                let mut skip = [0u8; 7];
                let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                stream.read_exact(&mut skip)?;
                Ok(())
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
                Err(VncError::Protocol(format!(
                    "Unknown server message type: {} (last_msg_type={:?}, last_encoding={:?}, recent_encodings={:?})",
                    msg_type[0],
                    self.last_msg_type,
                    self.last_encoding,
                    self.recent_encodings
                )))
            }
        };

        // Restore the caller's preferred timeout for the next message-type wait.
        let _ = self.set_read_timeout(saved_timeout);
        payload_result?;

        Ok(events)
    }

    fn handle_framebuffer_update(&mut self, events: &mut Vec<VncEvent>) -> Result<(), VncError> {
        let mut buf = [0u8; 3];
        let num_rects = {
            let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
            stream.read_exact(&mut buf)?;
            u16::from_be_bytes([buf[1], buf[2]])
        };
        self.recent_encodings.clear();
        self.recent_encodings.reserve(num_rects as usize);

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
                self.last_encoding = Some(encoding);
                self.recent_encodings.push(encoding);
                (x, y, width, height, encoding)
            };

            match encoding {
                0 => self.handle_raw_encoding(x, y, width, height)?,
                1 => self.handle_copyrect_encoding(x, y, width, height)?,
                2 => self.handle_rre_encoding(x, y, width, height)?,
                5 => self.handle_hextile_encoding(x, y, width, height)?,
                6 => self.handle_zlib_encoding(x, y, width, height)?,
                7 => self.handle_tight_encoding(x, y, width, height)?,
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
                // Apple high-performance pseudo-encodings.
                enc if enc == protocol::apple::ENC_REKEY => {
                    let mut body = vec![0u8; 36];
                    {
                        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                        stream.read_exact(&mut body)?;
                    }
                    self.stream
                        .as_mut()
                        .unwrap()
                        .rekey_apple_record_layer(&body)?;
                    log::debug!(
                        "Apple HP rekey (encoding {:#x}) applied",
                        protocol::apple::ENC_REKEY
                    );
                    continue;
                }
                enc if enc == protocol::apple::ENC_CURSOR => {
                    self.handle_apple_cursor_encoding(x, y, width, height, events)?;
                    continue;
                }
                enc if enc == protocol::apple::ENC_DISPLAY_LAYOUT => {
                    self.handle_apple_display_layout(x, y, width, height, events)?;
                    continue;
                }
                enc if enc == protocol::apple::ENC_VENDOR_KEYSYMS => {
                    // Apple vendor keysyms (fixed 22-byte payload).
                    let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                    let mut payload = vec![0u8; 22];
                    stream.read_exact(&mut payload)?;
                    log::debug!(
                        "Apple vendor keysyms (encoding {:#x}) ignored",
                        protocol::apple::ENC_VENDOR_KEYSYMS
                    );
                    continue;
                }
                enc if enc == protocol::apple::ENC_KEYBOARD_INPUT_SOURCE => {
                    // Apple keyboard input source (u16 prefix_len + payload).
                    let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                    let mut prefix = [0u8; 2];
                    stream.read_exact(&mut prefix)?;
                    let prefix_len = u16::from_be_bytes(prefix) as usize;
                    let mut payload = vec![0u8; prefix_len];
                    stream.read_exact(&mut payload)?;
                    log::debug!(
                        "Apple keyboard input source (encoding {:#x}) ignored",
                        protocol::apple::ENC_KEYBOARD_INPUT_SOURCE
                    );
                    continue;
                }
                enc if enc == protocol::apple::ENC_DEVICE_INFO => {
                    // Apple device info (u16 message_size + message_size bytes).
                    let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                    let mut msg_size_buf = [0u8; 2];
                    stream.read_exact(&mut msg_size_buf)?;
                    let msg_size = u16::from_be_bytes(msg_size_buf) as usize;
                    if msg_size < 2 {
                        return Err(VncError::Protocol(
                            "Apple device info message size too small".to_string(),
                        ));
                    }
                    let mut payload = vec![0u8; msg_size - 2];
                    stream.read_exact(&mut payload)?;
                    log::debug!(
                        "Apple device info (encoding {:#x}) ignored",
                        protocol::apple::ENC_DEVICE_INFO
                    );
                    continue;
                }
                enc if enc == protocol::apple::ENC_MEDIA_STREAM => {
                    // Apple media stream announcement (u16 payload_len + payload).
                    let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                    let mut len_buf = [0u8; 2];
                    stream.read_exact(&mut len_buf)?;
                    let payload_len = u16::from_be_bytes(len_buf) as usize;
                    let mut payload = vec![0u8; payload_len];
                    stream.read_exact(&mut payload)?;
                    log::debug!(
                        "Apple media stream announcement (encoding {:#x}) ignored",
                        protocol::apple::ENC_MEDIA_STREAM
                    );
                    continue;
                }
                enc if enc == protocol::apple::ENC_LOW_QUALITY
                    || enc == protocol::apple::ENC_MEDIUM_QUALITY
                    || enc == protocol::apple::ENC_HIGH_QUALITY
                    || enc == protocol::apple::ENC_MULTI_VARIANT_SCALED =>
                {
                    // Apple still-image codecs (u32 nbytes + payload).
                    let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                    let mut len_buf = [0u8; 4];
                    stream.read_exact(&mut len_buf)?;
                    let len = u32::from_be_bytes(len_buf) as usize;
                    let mut payload = vec![0u8; len];
                    stream.read_exact(&mut payload)?;
                    log::debug!("Apple still-image codec (encoding {:#x}) ignored", enc);
                    continue;
                }
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

    fn handle_zlib_encoding(
        &mut self,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) -> Result<(), VncError> {
        let pixel_format = self.pixel_format;
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        zlib::decode(
            stream,
            &mut self.zlib_decompress,
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

        // OpenH264 encoding data format:
        //   4 bytes big-endian length
        //   4 bytes big-endian flags
        //   length bytes H.264 payload
        let mut header = [0u8; 8];
        stream.read_exact(&mut header)?;
        let data_len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let _flags = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);

        if data_len == 0 {
            // Zero-length frames are used for reset signalling; nothing to decode.
            return Ok(());
        }

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

    /// Handle the Apple cursor image pseudo-encoding (`0x450`).
    ///
    /// STORE (`compressed_len > 0`): decompress the BGRA pixmap and separate
    /// alpha plane, convert to RGBA, and cache under `cache_id`.
    /// SELECT (`compressed_len = 0`): emit a `CursorShape` event from the cached
    /// pixmap. The rectangle header carries the hotspot in `x`/`y` and the size
    /// in `width`/`height`.
    fn handle_apple_cursor_encoding(
        &mut self,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        events: &mut Vec<VncEvent>,
    ) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut header = [0u8; 8];
        stream.read_exact(&mut header)?;
        let cache_id = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        let compressed_len =
            u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;

        if compressed_len > 0 {
            // STORE: read and cache a new cursor shape.
            let mut payload = vec![0u8; compressed_len];
            stream.read_exact(&mut payload)?;
            let cursor = self.decode_apple_cursor_store(width, height, &payload)?;
            self.apple_cursor_cache.insert(cache_id, cursor);
            log::debug!(
                "Apple cursor STORE cache_id={} size={}x{}",
                cache_id,
                width,
                height
            );
        } else {
            self.handle_apple_cursor_select(x, y, cache_id, events)?;
        }
        Ok(())
    }

    /// Emit a `CursorShape` event for a SELECT-style Apple cursor rectangle.
    fn handle_apple_cursor_select(
        &mut self,
        x: u16,
        y: u16,
        cache_id: u32,
        events: &mut Vec<VncEvent>,
    ) -> Result<(), VncError> {
        if let Some(cursor) = self.apple_cursor_cache.get(&cache_id) {
            let shape = CursorShape {
                width: cursor.width,
                height: cursor.height,
                hotspot_x: x,
                hotspot_y: y,
                pixels: cursor.pixels.clone(),
            };
            log::debug!(
                "Apple cursor SELECT cache_id={} size={}x{}",
                cache_id,
                cursor.width,
                cursor.height
            );
            events.push(VncEvent::CursorShape(shape));
        } else {
            log::debug!(
                "Apple cursor SELECT cache_id={} unknown; ignoring",
                cache_id
            );
        }
        Ok(())
    }

    /// Decompress an Apple HP cursor STORE payload into a cached RGBA image.
    fn decode_apple_cursor_store(
        &self,
        width: u16,
        height: u16,
        payload: &[u8],
    ) -> Result<AppleCursor, VncError> {
        let pixel_count = width as usize * height as usize;
        let expected_bgra = pixel_count * 4;
        let expected_alpha = pixel_count;

        let mut decoder = ZlibDecoder::new(payload);
        let mut decompressed = Vec::with_capacity(expected_bgra + expected_alpha);
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| VncError::Protocol(format!("Apple cursor zlib decode error: {}", e)))?;

        if decompressed.len() < expected_bgra + expected_alpha {
            return Err(VncError::Protocol(format!(
                "Apple cursor payload too short: got {} bytes, expected {}",
                decompressed.len(),
                expected_bgra + expected_alpha
            )));
        }

        let bgra = &decompressed[..expected_bgra];
        let alpha = &decompressed[expected_bgra..expected_bgra + expected_alpha];
        let mut pixels = Vec::with_capacity(expected_bgra);

        for i in 0..pixel_count {
            let b = bgra[i * 4];
            let g = bgra[i * 4 + 1];
            let r = bgra[i * 4 + 2];
            let a = alpha[i];
            // Non-premultiplied RGBA.
            pixels.push(r);
            pixels.push(g);
            pixels.push(b);
            pixels.push(a);
        }

        Ok(AppleCursor {
            width,
            height,
            pixels,
        })
    }

    /// Handle the Apple display layout pseudo-encoding (`0x451`).
    ///
    /// Parses the leading scaled/backing geometry and per-display rectangles,
    /// resizes the local framebuffer to the backing dimensions, and emits a
    /// `ScreenLayout` event. After every layout update we re-arm the server's
    /// framebuffer sender with `AutoFrameBufferUpdate` plus a non-incremental
    /// `FramebufferUpdateRequest` so that cursor SELECTs keep flowing across
    /// login/lock/agent transitions.
    fn handle_apple_display_layout(
        &mut self,
        _x: u16,
        _y: u16,
        _width: u16,
        _height: u16,
        events: &mut Vec<VncEvent>,
    ) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf)?;
        let payload_len = u16::from_be_bytes(len_buf) as usize;
        let mut payload = vec![0u8; payload_len];
        stream.read_exact(&mut payload)?;

        let Some((scaled_width, scaled_height, backing_width, backing_height, screens)) =
            parse_apple_display_layout(&payload)
        else {
            return self.rearm_apple_framebuffer_sender();
        };

        log::debug!(
            "Apple display layout: scaled={}x{} backing={}x{} displays={}",
            scaled_width,
            scaled_height,
            backing_width,
            backing_height,
            screens.len()
        );

        // Use the backing geometry for the local framebuffer, which is where
        // decoded rectangles are written. The scaled size is for window sizing.
        if backing_width > 0 && backing_height > 0 {
            self.width = backing_width;
            self.height = backing_height;
            self.framebuffer
                .resize(backing_width as usize, backing_height as usize);
            events.push(VncEvent::GeometryChanged {
                width: backing_width,
                height: backing_height,
            });
        }

        if !screens.is_empty() {
            events.push(VncEvent::ScreenLayout(screens));
        }

        // Always re-arm the sender so cursor updates continue.
        self.rearm_apple_framebuffer_sender()
    }

    /// Re-send `AutoFrameBufferUpdate` (0x09) + a non-incremental
    /// `FramebufferUpdateRequest` to re-arm the server after layout changes.
    fn rearm_apple_framebuffer_sender(&mut self) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        log::debug!("Apple HP: re-arming framebuffer sender after layout change");
        stream.write_all(&apple_record_layer::build_auto_framebuffer_update(
            protocol::apple::SELECTED_SCREEN_ALL,
            0,
            0,
            self.width,
            self.height,
        ))?;
        self.request_update(false, 0, 0, self.width, self.height)
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
            let len = len.unsigned_abs() as usize;
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

/// Convert a standard RFC 6143 pointer button mask to Apple's HP wire mask.
///
/// Apple swaps the right (bit 2) and middle (bit 1) button bits. All other
/// bits are passed through unchanged.
fn apple_pointer_button_mask(mask: u8) -> u8 {
    let mut apple = mask & !0x06;
    if mask & 0x02 != 0 {
        apple |= 0x04;
    }
    if mask & 0x04 != 0 {
        apple |= 0x02;
    }
    apple
}

/// Parse an AppleDisplayLayout (`0x451`) rectangle payload.
///
/// Returns `(scaled_width, scaled_height, backing_width, backing_height,
/// screens)` on success, or `None` if the payload is too short or malformed.
fn parse_apple_display_layout(payload: &[u8]) -> Option<(u16, u16, u16, u16, Vec<Screen>)> {
    const ENTRY_LEN: usize = 56;
    if payload.len() < 20 {
        log::debug!(
            "Apple display layout payload too short ({} bytes); skipping",
            payload.len()
        );
        return None;
    }

    let _version = u16::from_be_bytes([payload[0], payload[1]]);
    let scaled_width = u16::from_be_bytes([payload[2], payload[3]]);
    let scaled_height = u16::from_be_bytes([payload[4], payload[5]]);
    let backing_width = u16::from_be_bytes([payload[6], payload[7]]);
    let backing_height = u16::from_be_bytes([payload[8], payload[9]]);
    let display_count = u16::from_be_bytes([payload[18], payload[19]]) as usize;

    let mut screens = Vec::with_capacity(display_count);
    let mut off = 20usize;
    for _ in 0..display_count {
        if off + ENTRY_LEN > payload.len() {
            log::debug!(
                "Apple display layout payload truncated at display entry (off={})",
                off
            );
            break;
        }
        let display_id = u32::from_be_bytes([
            payload[off + 16],
            payload[off + 17],
            payload[off + 18],
            payload[off + 19],
        ]);
        // Pixel (backing) rect, expressed as y0,x0,y1,x1.
        let py0 = u16::from_be_bytes([payload[off + 36], payload[off + 37]]);
        let px0 = u16::from_be_bytes([payload[off + 38], payload[off + 39]]);
        let py1 = u16::from_be_bytes([payload[off + 40], payload[off + 41]]);
        let px1 = u16::from_be_bytes([payload[off + 42], payload[off + 43]]);
        let flags = u32::from_be_bytes([
            payload[off + 48],
            payload[off + 49],
            payload[off + 50],
            payload[off + 51],
        ]);

        if px1 > px0 && py1 > py0 {
            screens.push(Screen {
                id: display_id,
                x: px0,
                y: py0,
                width: px1 - px0,
                height: py1 - py0,
                flags,
            });
        }
        off += ENTRY_LEN;
    }

    Some((
        scaled_width,
        scaled_height,
        backing_width,
        backing_height,
        screens,
    ))
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
    high_performance: bool,
    apple_display_width: u16,
    apple_display_height: u16,
    apple_display_dynamic: bool,
    apple_hidpi_scale: f32,
    apple_virtual_display: bool,
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
            high_performance: false,
            apple_display_width: 1920,
            apple_display_height: 1080,
            apple_display_dynamic: false,
            apple_hidpi_scale: 2.0,
            apple_virtual_display: true,
        }
    }

    /// Enable Apple high-performance mode (RFB 003.889 + RSA-SRP + encrypted record layer).
    ///
    /// When enabled, the default encoding list is replaced with the Apple HP
    /// encoding set. You can override it with [`Self::encodings`] afterwards.
    pub fn high_performance(mut self, enable: bool) -> Self {
        self.high_performance = enable;
        if enable {
            self.encodings = vec![
                Encoding::AppleHp(1010),
                Encoding::AppleHp(1011),
                Encoding::AppleHp(1002),
                Encoding::Zlib,
                Encoding::Zrle,
                Encoding::AppleHp(1104),
                Encoding::AppleHp(1100),
                Encoding::DesktopSize,
                Encoding::AppleHp(1101),
                Encoding::AppleHp(1105),
                Encoding::AppleHp(1107),
                Encoding::AppleHp(1109),
                Encoding::AppleHp(1110),
            ];
        }
        self
    }

    /// Configure the Apple HP virtual display resolution sent in
    /// `SetDisplayConfiguration` (0x1d).
    ///
    /// Only used when [`Self::high_performance`] is enabled. The default is
    /// 1920×1080.
    pub fn apple_display_size(mut self, width: u16, height: u16) -> Self {
        self.apple_display_width = width;
        self.apple_display_height = height;
        self
    }

    /// Request a dynamic-resolution Apple virtual display.
    ///
    /// When enabled, the `SetDisplayConfiguration` descriptor sets the
    /// dynamic flag and `display_type = 4`, allowing in-band resolution changes
    /// via `AppleDisplayLayout` (0x451).
    pub fn apple_display_dynamic(mut self, dynamic: bool) -> Self {
        self.apple_display_dynamic = dynamic;
        self
    }

    /// Set the Apple HP virtual display HiDPI scale.
    ///
    /// `2.0` requests a Retina-style backing:point ratio (the default);
    /// `1.0` requests a flat 1:1 display, which uses roughly one quarter the
    /// bandwidth and is appropriate for non-Retina clients.
    pub fn apple_hidpi_scale(mut self, scale: f32) -> Self {
        self.apple_hidpi_scale = scale.max(0.1);
        self
    }

    /// Control whether Apple HP mode requests a virtual display.
    ///
    /// When enabled (the default), `SetDisplayConfiguration` is sent during the
    /// plaintext handshake, requesting a virtual display with the configured
    /// resolution and curtaining the host's physical screen. When disabled, the
    /// server's physical display is mirrored instead.
    pub fn apple_virtual_display(mut self, enable: bool) -> Self {
        self.apple_virtual_display = enable;
        self
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
        client.high_performance = self.high_performance;
        client.apple_display_width = self.apple_display_width;
        client.apple_display_height = self.apple_display_height;
        client.apple_display_dynamic = self.apple_display_dynamic;
        client.apple_hidpi_scale = self.apple_hidpi_scale;
        client.apple_virtual_display = self.apple_virtual_display;
        if self.high_performance {
            // Apple HP uses the dedicated shared byte to request virtual-display setup.
            client.client_init_shared = protocol::apple::CLIENT_INIT_SHARED;
        }
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
    fn builder_apple_display_options_applied() {
        let client = VncClientBuilder::new()
            .high_performance(true)
            .apple_display_size(1280, 720)
            .apple_display_dynamic(true)
            .apple_hidpi_scale(1.0)
            .apple_virtual_display(false)
            .build();
        assert!(client.high_performance);
        assert_eq!(client.apple_display_width, 1280);
        assert_eq!(client.apple_display_height, 720);
        assert!(client.apple_display_dynamic);
        assert_eq!(client.apple_hidpi_scale, 1.0);
        assert!(!client.apple_virtual_display);
        assert_eq!(
            client.client_init_shared,
            protocol::apple::CLIENT_INIT_SHARED
        );
    }

    #[test]
    fn apple_cursor_decode_store() {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;

        let bgra = vec![
            0x00, 0x00, 0xff, 0x00, // blue pixel in BGRA
            0x00, 0xff, 0x00, 0x00, // green pixel in BGRA
        ];
        let alpha = vec![0xff, 0x80];
        let mut raw = bgra.clone();
        raw.extend_from_slice(&alpha);
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&raw).unwrap();
        let payload = encoder.finish().unwrap();

        let client = VncClientBuilder::new().high_performance(true).build();
        let cursor = client.decode_apple_cursor_store(2, 1, &payload).unwrap();
        assert_eq!(cursor.width, 2);
        assert_eq!(cursor.height, 1);
        assert_eq!(
            cursor.pixels,
            vec![
                0xff, 0x00, 0x00, 0xff, // red pixel (was BGRA blue -> RGBA red)
                0x00, 0xff, 0x00, 0x80, // green pixel with 0x80 alpha
            ]
        );
    }

    #[test]
    fn apple_cursor_select_emits_shape() {
        let mut client = VncClientBuilder::new().high_performance(true).build();
        client.apple_cursor_cache.insert(
            42,
            AppleCursor {
                width: 1,
                height: 1,
                pixels: vec![0x12, 0x34, 0x56, 0x78],
            },
        );
        let mut events = Vec::new();
        client
            .handle_apple_cursor_select(5, 6, 42, &mut events)
            .unwrap();
        assert_eq!(events.len(), 1);
        let shape = match events.remove(0) {
            VncEvent::CursorShape(s) => s,
            _ => panic!("expected CursorShape event"),
        };
        assert_eq!(shape.width, 1);
        assert_eq!(shape.height, 1);
        assert_eq!(shape.hotspot_x, 5);
        assert_eq!(shape.hotspot_y, 6);
        assert_eq!(shape.pixels, vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn apple_cursor_select_unknown_id_ignored() {
        let mut client = VncClientBuilder::new().high_performance(true).build();
        let mut events = Vec::new();
        client
            .handle_apple_cursor_select(0, 0, 99, &mut events)
            .unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn apple_pointer_button_mask_swaps_right_middle() {
        // Standard RFC mask: bit 0 left, bit 1 middle, bit 2 right.
        // Apple HP mask: bit 0 left, bit 1 right, bit 2 middle.
        assert_eq!(apple_pointer_button_mask(0x00), 0x00);
        assert_eq!(apple_pointer_button_mask(0x01), 0x01); // left unchanged
        assert_eq!(apple_pointer_button_mask(0x02), 0x04); // middle -> right
        assert_eq!(apple_pointer_button_mask(0x04), 0x02); // right -> middle
        assert_eq!(apple_pointer_button_mask(0x07), 0x07); // all three -> same set
        assert_eq!(apple_pointer_button_mask(0x18), 0x18); // scroll bits unchanged
    }

    #[test]
    fn parse_apple_display_layout_extracts_screens() {
        // Build a payload for a single 1920×1080 display.
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u16.to_be_bytes()); // version
        payload.extend_from_slice(&1920u16.to_be_bytes()); // scaled_width
        payload.extend_from_slice(&1080u16.to_be_bytes()); // scaled_height
        payload.extend_from_slice(&3840u16.to_be_bytes()); // backing_width
        payload.extend_from_slice(&2160u16.to_be_bytes()); // backing_height
        payload.extend_from_slice(&0xffffffffu32.to_be_bytes()); // current_display sentinel
        payload.extend_from_slice(&0u32.to_be_bytes()); // field/flags
        payload.extend_from_slice(&1u16.to_be_bytes()); // display_count

        // Per-display entry (56 bytes).
        let mut entry = vec![0u8; 56];
        entry[16..20].copy_from_slice(&0x12345678u32.to_be_bytes()); // display_id
                                                                     // Virtual rect (ignored by parser).
                                                                     // Pixel rect y0,x0,y1,x1 at offsets 36..44.
        entry[36..38].copy_from_slice(&0u16.to_be_bytes()); // y0
        entry[38..40].copy_from_slice(&0u16.to_be_bytes()); // x0
        entry[40..42].copy_from_slice(&2160u16.to_be_bytes()); // y1
        entry[42..44].copy_from_slice(&3840u16.to_be_bytes()); // x1
                                                               // flags at offsets 48..52.
        entry[48..52].copy_from_slice(&0x00000001u32.to_be_bytes());
        payload.extend_from_slice(&entry);

        let result = parse_apple_display_layout(&payload);
        let (sw, sh, bw, bh, screens) = result.unwrap();
        assert_eq!(sw, 1920);
        assert_eq!(sh, 1080);
        assert_eq!(bw, 3840);
        assert_eq!(bh, 2160);
        assert_eq!(screens.len(), 1);
        assert_eq!(screens[0].id, 0x12345678);
        assert_eq!(screens[0].x, 0);
        assert_eq!(screens[0].y, 0);
        assert_eq!(screens[0].width, 3840);
        assert_eq!(screens[0].height, 2160);
        assert_eq!(screens[0].flags, 0x00000001);
    }

    #[test]
    fn parse_apple_display_layout_rejects_short_payload() {
        assert!(parse_apple_display_layout(&[0u8; 10]).is_none());
    }
}
