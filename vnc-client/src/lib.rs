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
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::tls::TlsStream;

pub mod apple;
pub mod apple_dh;
pub mod apple_media;
pub mod apple_media_stream;
pub mod apple_record_layer;
pub mod apple_srp;
#[cfg(not(target_os = "android"))]
pub use apple_media_stream::MediaStreamEvent;
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

use apple_media::{MediaStreamAnswer, MediaStreamInit, MediaStreamKeys};
use auth::AuthHandler;
use cursor::CursorShape;
use decoder::{Codec, DefaultDecoder, VideoDecoder};
use encodings::{from_i32, Encoding};
use flate2::read::ZlibDecoder;
use framebuffer::Framebuffer;
use vnc_protocol::rect::check_dimensions;

pub use framebuffer::PixelFormat;
pub use framebuffer::Transform;
pub use stats::ConnectionStats;

/// Maximum length of a single QEMU audio extension chunk.
///
/// Audio chunks carry a few milliseconds of samples; 16 MiB is ~40+ seconds
/// of 48 kHz/16-bit stereo — far beyond any legitimate chunk — and stops a
/// hostile server from forcing a giant allocation.
const MAX_QEMU_AUDIO_LEN: usize = 16 * 1024 * 1024;

enum VncStreamInner {
    Plain(TcpStream),
    Tls(Box<TlsStream>),
    Aes(Box<rsa_aes::AesCtrStream>),
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

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            VncStreamInner::Plain(s) => s.write_all(buf),
            VncStreamInner::Tls(s) => s.write_all(buf),
            VncStreamInner::Aes(s) => s.write_all(buf),
            VncStreamInner::Ws(s) => s.write_all(buf),
            VncStreamInner::AppleHp(s) => s.write_all(buf),
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

    /// Return the peer address of the underlying transport, if available.
    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        match &self.inner {
            VncStreamInner::Plain(s) => s.peer_addr(),
            VncStreamInner::Tls(s) => s.get_ref().peer_addr(),
            VncStreamInner::Aes(s) => s.peer_addr(),
            VncStreamInner::Ws(s) => s.peer_addr(),
            VncStreamInner::AppleHp(s) => s.peer_addr(),
        }
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

    /// Build an Apple HP encrypted key event (0x10, subtype 1) if the record
    /// layer is active.
    pub fn build_apple_encrypted_key_event(
        &self,
        down: bool,
        keysym: u32,
        key_type: u16,
        key_code: u16,
    ) -> Result<Vec<u8>, VncError> {
        match &self.inner {
            VncStreamInner::AppleHp(layer) => {
                Ok(layer.build_encrypted_key_event(down, keysym, key_type, key_code))
            }
            _ => Err(VncError::Protocol(
                "Apple record layer not active".to_string(),
            )),
        }
    }

    /// Build an Apple HP encrypted pointer event (0x10, subtype 3) if the
    /// record layer is active.
    pub fn build_apple_encrypted_pointer_event(
        &self,
        button_mask: u8,
        x: u16,
        y: u16,
    ) -> Result<Vec<u8>, VncError> {
        match &self.inner {
            VncStreamInner::AppleHp(layer) => {
                Ok(layer.build_encrypted_pointer_event(button_mask, x, y))
            }
            _ => Err(VncError::Protocol(
                "Apple record layer not active".to_string(),
            )),
        }
    }

    /// Read the remainder of the current Apple HP record.
    pub fn read_remaining_record(&mut self) -> Result<Vec<u8>, VncError> {
        match &mut self.inner {
            VncStreamInner::AppleHp(layer) => layer.read_remaining_record().map_err(VncError::Io),
            _ => Err(VncError::Protocol(
                "read_remaining_record only available for Apple HP record layer".to_string(),
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

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        // Delegate to the inner stream's write_all so that buffered transports
        // (notably the Apple HP record layer) flush their records. The default
        // std::io::Write::write_all only calls write() and never flushes, which
        // caused Apple HP messages such as the 0x1c media-stream offer to be stuck
        // in the record layer's internal buffer.
        self.inner.write_all(buf)?;
        self.bytes_written += buf.len() as u64;
        Ok(())
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
    zrle_decompress: Option<zlib::SessionInflate>,
    zlib_decompress: zlib::SessionInflate,
    tight_streams: tight::TightStreams,
    hextile_state: hextile::HextileState,
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
    /// Whether to enable the Apple HP adaptive media stream path and advertise
    /// the media-init encodings (`0x3ea`, `0x3f2`, `0x3f3`).
    apple_media_stream_h264: bool,
    /// SRTP master keys generated for the Apple HP adaptive media stream.
    /// Set during handshake when `apple_media_stream_h264` is true.
    apple_media_stream_keys: Option<MediaStreamKeys>,
    /// Apple HP encoding list used during the plaintext and encrypted SetEncodings
    /// handshake. Varies depending on whether the media stream path is enabled.
    apple_hp_encodings: Vec<i32>,
    /// Apple cursor cache keyed by `cache_id`. STOREd cursors are kept here;
    /// SELECT rectangles reference a cached id and emit a `CursorShape` event.
    apple_cursor_cache: HashMap<u32, AppleCursor>,
    /// Scaled (logical-point) geometry from the latest Apple display layout
    /// (`0x451`). Pointer input must be mapped into this space, not the
    /// backing-pixel space used for the framebuffer.
    apple_scaled_size: Option<(u16, u16)>,
    #[cfg(not(target_os = "android"))]
    /// Optional Apple HP HEVC media stream receiver running on a background thread.
    media_stream: Option<apple_media_stream::AppleMediaStream>,
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
///
/// Re-exported from the shared `vnc-protocol` crate; the wire layout is
/// parsed and built by [`protocol::framing::Screen`].
pub use protocol::framing::Screen;

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
    /// Keyboard input source information received from the server (Apple HP).
    KeyboardInputSource {
        input_source_id: String,
        secure_event_input: bool,
    },
    /// Device information received from the server (Apple HP).
    DeviceInfo {
        device_identifier: String,
        device_color: String,
        enclosure_color: String,
        enclosure_rgb_color: u32,
        housing_color: i32,
    },
    /// Remote clipboard changed; the caller may call `request_clipboard_fetch` to
    /// pull the updated pasteboard (Apple HP).
    ClipboardChanged,
    /// Apple HP media stream answer received after sending a `0x1c` offer.
    ///
    /// Carries the negotiated video canvas dimensions and tile/SSRC count. A
    /// degenerate answer with zero dimensions may be emitted if the encoder is not
    /// ready yet; callers should re-send the offer and retry.
    MediaStreamAnswer(MediaStreamAnswer),
    /// Apple HP media stream init announcement (`0x3f2` stage 1 / stage 2).
    ///
    /// Provides the UDP base port hint and stream count. The caller can start the
    /// HEVC receiver with [`VncClient::start_media_stream`].
    MediaStreamInit(MediaStreamInit),
    /// Decoded HEVC frame from the Apple HP adaptive media stream.
    ///
    /// Emitted once [`VncClient::start_media_stream`] has started the UDP
    /// receiver and the decoder has produced a frame. The RGBA buffer has
    /// dimensions `width x height`.
    MediaFrame {
        width: u16,
        height: u16,
        rgba: Vec<u8>,
    },
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
    #[error("Read timed out")]
    Timeout,
}

impl From<vnc_protocol::ProtocolError> for VncError {
    fn from(err: vnc_protocol::ProtocolError) -> Self {
        match err {
            vnc_protocol::ProtocolError::Io(io) => VncError::Io(io),
            vnc_protocol::ProtocolError::Protocol(msg) => VncError::Protocol(msg),
        }
    }
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
            zlib_decompress: zlib::SessionInflate::new(),
            tight_streams: tight::TightStreams::new(),
            hextile_state: hextile::HextileState::new(),
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
            apple_media_stream_h264: false,
            apple_media_stream_keys: None,
            apple_hp_encodings: apple_record_layer::APPLE_HP_ENCODINGS.to_vec(),
            apple_cursor_cache: HashMap::new(),
            apple_scaled_size: None,
            #[cfg(not(target_os = "android"))]
            media_stream: None,
        }
    }

    #[allow(dead_code)]
    fn stream(&mut self) -> Result<&mut VncStream, VncError> {
        self.stream.as_mut().ok_or(VncError::NotConnected)
    }

    /// Connect to a VNC server over plain TCP.
    ///
    /// Note: this does not set the hostname used for TLS certificate verification.
    /// If you later upgrade to TLS (e.g. via VeNCrypt), call [`Self::set_host`] first,
    /// or use [`Self::connect_with_host`] instead.
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

    /// Connect to a plain TCP server and record the hostname for later TLS upgrades.
    ///
    /// This is a convenience wrapper around [`Self::connect`] and [`Self::set_host`].
    /// If you plan to upgrade the connection to TLS (e.g. via VeNCrypt), use this
    /// method or call `set_host` before the TLS upgrade.
    pub fn connect_with_host(&mut self, host: &str, port: u16) -> Result<(), VncError> {
        self.set_host(host);
        self.connect((host, port))
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
        let mut buf = [0u8; protocol::handshake::RFB_VERSION_BANNER_LEN];
        stream.read_exact(&mut buf)?;

        let version = String::from_utf8_lossy(&buf).trim_end().to_string();
        let (major, minor) = match protocol::handshake::parse_rfb_version(&buf) {
            Some(Ok(version)) => version,
            Some(Err(_)) | None => {
                return Err(VncError::Protocol(format!(
                    "Invalid protocol version string: {}",
                    version
                )))
            }
        };

        let our_version = match (major, minor) {
            (3, 889) => {
                if self.high_performance {
                    protocol::apple::PROTOCOL_VERSION
                } else {
                    // Some servers advertise 003.889 to indicate vendor extensions, but
                    // the wire protocol is compatible with 003.008, so downgrade to 003.008.
                    b"RFB 003.008\n"
                }
            }
            (3, 8) => b"RFB 003.008\n",
            (3, 7) => b"RFB 003.007\n",
            (3, 3) => b"RFB 003.003\n",
            _ => return Err(VncError::UnsupportedVersion(version)),
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

    /// Upgrade the current Plain TCP stream to AES-CTR encryption using RSA-AES.
    /// Used by direct security types 5/129 and by VeNCrypt RSA-AES sub-types.
    fn upgrade_to_aes_ctr(&mut self, key_size: usize) -> Result<(), VncError> {
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
                return Err(VncError::Protocol("Already AES encrypted".to_string()));
            }
            Some(VncStream {
                inner: VncStreamInner::Ws(_),
                ..
            }) => {
                return Err(VncError::Protocol(
                    "WebSocket not supported for RSA-AES auth".to_string(),
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

        let rsa_auth = match key_size {
            16 => rsa_aes::RsaAesAuth::new_128(),
            32 => rsa_aes::RsaAesAuth::new_256(),
            _ => {
                return Err(VncError::Protocol(format!(
                    "Invalid AES key size for RSA-AES: {}",
                    key_size
                )));
            }
        };
        let key = rsa_auth.authenticate(&mut tcp)?;
        let mut aes = rsa_aes::AesCtrStream::new(tcp, &key)?;
        // Both sides switch to AES-CTR immediately after the encrypted session
        // key is sent; the security result is the first encrypted message.
        rsa_aes::RsaAesAuth::read_security_result(&mut aes)?;
        self.stream = Some(VncStream {
            inner: VncStreamInner::Aes(Box::new(aes)),
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
                // A reason length over the cap maps to VncError::Protocol
                // (not Io) via the ProtocolError conversion.
                let reason = protocol::handshake::read_failure_reason(stream)?;
                return Err(VncError::AuthFailed(reason));
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
            protocol::SECURITY_RSA_AES => {
                self.upgrade_to_aes_ctr(16)?;
            }
            protocol::SECURITY_RSA_AES256 => {
                self.upgrade_to_aes_ctr(32)?;
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
                        self.upgrade_to_aes_ctr(16)?;
                    }
                    vencrypt::VencryptResult::RsaAes256 => {
                        self.upgrade_to_aes_ctr(32)?;
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
        let init = {
            let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
            // Send ClientInit (shared flag = true)
            log::debug!(
                "Sending ClientInit (shared = 0x{:02x})",
                self.client_init_shared
            );
            stream.write_all(&[self.client_init_shared])?;
            // Read ServerInit
            let init = protocol::ServerInit::read(stream)?;
            log::debug!("ServerInit header: name_len = {}", init.name.len());
            init
        };

        self.width = init.width;
        self.height = init.height;
        self.pixel_format = init.pixel_format;
        self.name = init.name;
        check_dimensions(self.width as u32, self.height as u32)?;

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
                stream.write_all(&protocol::framing::build_set_encodings(
                    &self.apple_hp_encodings,
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

            // Encrypted preface. Send SetEncodings first, then the 0x1c media
            // stream offer immediately after it, then a FramebufferUpdateRequest.
            // Native Screen Sharing.app and the reference iShareScreen client both
            // place the 0x1c offer before any AutoFrameBufferUpdate / free-run
            // request; sending 0x09 first arms the TCP framebuffer sender and
            // prevents the daemon from starting the UDP media path.
            log::debug!("Apple HP: sending encrypted SetEncodings");
            self.set_encodings(&self.encodings.clone())?;

            if self.apple_media_stream_h264 {
                log::debug!("Apple HP: sending encrypted MediaStreamOptions (0x1c)");
                let _ = self.send_hp_media_stream_options(true)?;
            }

            log::debug!("Apple HP: sending encrypted FramebufferUpdateRequest");
            self.request_update(false, 0, 0, self.width, self.height)?;
        }

        self.state = ClientState::Initialization;
        Ok(())
    }

    /// Read the initial plaintext rekey rectangle (encoding [`protocol::apple::ENC_REKEY`]) that the
    /// server emits during the Apple HP handshake. Tolerates a small amount of
    /// [`protocol::apple::MISC_STATUS`] traffic and Apple still-image codec
    /// announcement rectangles ([`protocol::apple::ENC_MEDIA_STREAM`],
    /// [`protocol::apple::ENC_MULTI_VARIANT_SCALED`]) that can precede the rekey.
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
                        let mut rect = [0u8; protocol::framing::RectHeader::WIRE_LEN];
                        stream.read_exact(&mut rect)?;
                        let header = protocol::framing::RectHeader::from_bytes(&rect);
                        let (x, y, w, h, enc) = (
                            header.x,
                            header.y,
                            header.width,
                            header.height,
                            header.encoding,
                        );

                        if enc == protocol::apple::ENC_REKEY && x == 0 && y == 0 && w == 0 && h == 0
                        {
                            let mut body = vec![0u8; 36];
                            stream.read_exact(&mut body)?;
                            found_rekey = Some(body);
                            continue;
                        }

                        // Still-image codec announcement rectangles may precede the
                        // rekey; they carry a u16 length prefix and a payload.
                        if enc == protocol::apple::ENC_MEDIA_STREAM
                            || enc == protocol::apple::ENC_MULTI_VARIANT_SCALED
                        {
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
        let msg = protocol::framing::build_set_pixel_format(&format);
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
        let raw: Vec<i32> = encodings.iter().map(|e| e.as_i32()).collect();
        let msg = protocol::framing::build_set_encodings(&raw);
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
        let msg = protocol::framing::FramebufferUpdateRequest {
            incremental,
            x,
            y,
            width,
            height,
        }
        .to_bytes();
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
        let msg = protocol::framing::PointerEvent { button_mask, x, y }.to_bytes();
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
        let msg = protocol::framing::PointerEvent { button_mask, x, y }.to_bytes();
        stream.write_all(&msg)?;
        Ok(())
    }

    /// Scaled (logical-point) geometry from the latest Apple display layout
    /// (`0x451`), if one has been received. In HP mode pointer coordinates
    /// must be sent in this space, while the framebuffer uses the larger
    /// backing-pixel geometry.
    pub fn apple_scaled_size(&self) -> Option<(u16, u16)> {
        self.apple_scaled_size
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
        let msg = protocol::framing::KeyEvent { down, keysym }.to_bytes();
        stream.write_all(&msg)?;
        Ok(())
    }

    /// Send an encrypted Apple HP key event (0x10).
    ///
    /// Only available when the session is in Apple high-performance mode and the
    /// encrypted record layer is active. `key_type` and `key_code` are Apple-specific
    /// fields that callers without native key information can leave as `0`.
    pub fn send_hp_key_event(
        &mut self,
        down: bool,
        keysym: u32,
        key_type: u16,
        key_code: u16,
    ) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let msg = stream.build_apple_encrypted_key_event(down, keysym, key_type, key_code)?;
        stream.write_all(&msg)?;
        Ok(())
    }

    /// Send an encrypted Apple HP pointer event (0x10).
    ///
    /// Only available when the session is in Apple high-performance mode and the
    /// encrypted record layer is active. The `button_mask` uses the standard RFB
    /// layout (RFC 6143); the right/middle bits are swapped into the Apple HP
    /// wire format automatically.
    pub fn send_hp_pointer_event(
        &mut self,
        button_mask: u8,
        x: u16,
        y: u16,
    ) -> Result<(), VncError> {
        let button_mask = apple_pointer_button_mask(button_mask);
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let msg = stream.build_apple_encrypted_pointer_event(button_mask, x, y)?;
        stream.write_all(&msg)?;
        Ok(())
    }

    /// Send an Apple HP `SetMode` (0x0a) message.
    ///
    /// `mode = 0` is observe-only, `mode = 1` is normal control. This message is
    /// optional; native Screen Sharing.app sends it during the plaintext prelude.
    pub fn send_hp_set_mode(&mut self, mode: u16) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        stream.write_all(&apple_record_layer::build_set_mode(mode))?;
        Ok(())
    }

    /// Send an Apple HP `ScaleFactor` (0x08) message.
    ///
    /// The server uses a positive scale factor to decide whether to downscale the
    /// framebuffer stream. This is typically sent during the encrypted preface.
    pub fn send_hp_scale_factor(&mut self, scale: f64) -> Result<(), VncError> {
        if scale <= 0.0 {
            return Err(VncError::Protocol(format!(
                "Apple HP scale factor must be positive, got {}",
                scale
            )));
        }
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        stream.write_all(&apple_record_layer::build_scale_factor(scale))?;
        Ok(())
    }

    /// Send an Apple HP `SetDisplayMessage` (0x0d) message.
    ///
    /// When `combine_all_displays` is true, `display_id` is ignored and the server
    /// selects the combined-display aggregate.
    pub fn send_hp_set_display_message(
        &mut self,
        combine_all_displays: bool,
        display_id: u32,
    ) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        stream.write_all(&apple_record_layer::build_set_display_message(
            combine_all_displays,
            display_id,
        ))?;
        Ok(())
    }

    /// Send an Apple HP `AutoPasteboard` (0x15) command.
    ///
    /// `selector = 1` starts monitoring the local pasteboard for universal-clipboard
    /// sync; `selector = 2` stops it. Only selectors `1` and `2` are accepted by the
    /// server.
    pub fn send_hp_auto_pasteboard(&mut self, selector: u8) -> Result<(), VncError> {
        if selector != 1 && selector != 2 {
            return Err(VncError::Protocol(format!(
                "Apple HP AutoPasteboard selector must be 1 or 2, got {}",
                selector
            )));
        }
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        stream.write_all(&apple_record_layer::build_auto_pasteboard(selector))?;
        Ok(())
    }

    /// Send an Apple HP `SetKeyboardInputSource` (0x1a) message.
    ///
    /// Carries the keyboard input-source identifier (e.g.
    /// `"com.apple.keylayout.ABC"`) to the server agent.
    pub fn send_hp_set_keyboard_input_source(&mut self, source_id: &str) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        stream.write_all(&apple_record_layer::build_set_keyboard_input_source(
            source_id,
        ))?;
        Ok(())
    }

    /// Send an Apple HP `AutoFrameBufferUpdate` (0x09) message.
    ///
    /// This arms the daemon's framebuffer sender so it freely emits cursor
    /// pseudo-encoding updates and other TCP-side rectangles. The native client
    /// sends this together with a non-incremental `FramebufferUpdateRequest`
    /// at startup and after every display-layout transition.
    pub fn send_hp_auto_framebuffer_update(
        &mut self,
        selected_screen: u32,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        stream.write_all(&apple_record_layer::build_auto_framebuffer_update(
            selected_screen,
            x,
            y,
            width,
            height,
        ))?;
        Ok(())
    }

    /// Request a remote pasteboard fetch after a `ClipboardChanged` event (Apple HP).
    ///
    /// Sends a `ClipboardFetch` (0x0b) message; the server replies with the current
    /// pasteboard contents via the standard `ServerCutText` / `ClipboardSend` path.
    pub fn request_clipboard_fetch(&mut self) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        stream.write_all(&apple_record_layer::build_clipboard_fetch())?;
        Ok(())
    }

    /// Return the SRTP master keys most recently generated for the Apple HP
    /// adaptive media stream, if any.
    ///
    /// Keys are created when the 0x1c offer is sent (either automatically during
    /// handshake or manually via [`Self::send_hp_media_stream_options`]).
    pub fn apple_media_stream_keys(&self) -> Option<&MediaStreamKeys> {
        self.apple_media_stream_keys.as_ref()
    }

    /// Send an Apple HP `MediaStreamOptions` (0x1c) offer to negotiate the adaptive
    /// media path.
    ///
    /// Only available when Apple high-performance mode is active. The offer
    /// requests a single HEVC video stream (one tile per frame) and an audio
    /// stream. The audio stream can be suppressed with `audio_enabled = false`.
    ///
    /// Returns the generated SRTP master keys; the caller should keep them for the
    /// application-level media channel. The server reply is read with
    /// [`Self::read_hp_media_stream_answer`] or emitted as a
    /// [`VncEvent::MediaStreamAnswer`] through the regular message loop.
    pub fn send_hp_media_stream_options(
        &mut self,
        audio_enabled: bool,
    ) -> Result<MediaStreamKeys, VncError> {
        let keys = MediaStreamKeys::random();
        self.send_hp_media_stream_options_with_keys(keys.clone(), audio_enabled)?;
        Ok(keys)
    }

    /// Send an Apple HP `MediaStreamOptions` (0x1c) offer using caller-supplied
    /// SRTP master keys.
    ///
    /// This allows the caller to bind the UDP media sockets and generate the
    /// SRTP keys *before* sending the first offer, and then re-send the same
    /// offer (with the same keys) while waiting for the encoder to become ready.
    /// Apple rejects offers whose keys do not match the sockets it has already
    /// seen, so reusing keys is required for reliable negotiation.
    pub fn send_hp_media_stream_options_with_keys(
        &mut self,
        keys: MediaStreamKeys,
        audio_enabled: bool,
    ) -> Result<(), VncError> {
        if !self.high_performance {
            return Err(VncError::Protocol(
                "Apple HP media stream requires high-performance mode".to_string(),
            ));
        }
        let msg = apple_media::build_media_stream_options(&keys, audio_enabled);
        log::debug!(
            "Apple HP: sending MediaStreamOptions offer ({} bytes)",
            msg.len()
        );
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        stream.write_all(&msg)?;
        self.apple_media_stream_keys = Some(keys);
        Ok(())
    }

    /// Read a server-side `0x1c` media-stream answer from the record layer.
    ///
    /// This is a synchronous helper that reads a single record and attempts to parse
    /// the binary plist answer. Returns a degenerate `(0, 0, 0)`-style answer if the
    /// encoder has not yet populated the media blob; callers should retry the offer
    /// in that case.
    pub fn read_hp_media_stream_answer(&mut self) -> Result<MediaStreamAnswer, VncError> {
        let mut buf = vec![0u8; 8192];
        let n = self
            .stream
            .as_mut()
            .ok_or(VncError::NotConnected)?
            .read(&mut buf)?;
        buf.truncate(n);
        apple_media::parse_media_stream_answer(&buf).ok_or_else(|| {
            VncError::Protocol("Failed to parse Apple HP media stream answer".to_string())
        })
    }

    /// Start the Apple HP adaptive media stream receiver (H.264 or HEVC).
    ///
    /// This binds a local UDP socket, sends a firewall-punch packet to the
    /// server, starts the background RTP/SRTP receiver thread, and feeds decoded
    /// frames into the event channel. Decoded frames are surfaced through
    /// [`VncEvent::MediaFrame`] by [`Self::read_messages`].
    ///
    /// `canvas_width` and `canvas_height` are the negotiated video dimensions from
    /// the [`MediaStreamAnswer`] returned by the `0x1c` exchange. `codec` selects
    /// the video decoder (H.264 or HEVC).
    ///
    /// This is only available on non-Android targets and requires the session
    /// to be in Apple high-performance mode.
    #[cfg(not(target_os = "android"))]
    pub fn start_media_stream(
        &mut self,
        keys: MediaStreamKeys,
        init: MediaStreamInit,
        canvas_width: u16,
        canvas_height: u16,
        codec: Codec,
    ) -> Result<(), VncError> {
        if !self.high_performance {
            return Err(VncError::Protocol(
                "Apple HP media stream requires high-performance mode".to_string(),
            ));
        }
        let server_addr = self
            .stream
            .as_ref()
            .ok_or(VncError::NotConnected)?
            .peer_addr()
            .map_err(VncError::Io)?;
        let decoder = DefaultDecoder::for_codec(codec)?;
        decoder.set_size(canvas_width, canvas_height);
        let stream = apple_media_stream::AppleMediaStream::start(
            &keys,
            init,
            server_addr,
            canvas_width,
            canvas_height,
            codec,
            Box::new(decoder),
        )?;
        self.media_stream = Some(stream);
        Ok(())
    }

    /// Stop the Apple HP media stream receiver, if it is running.
    #[cfg(not(target_os = "android"))]
    pub fn stop_media_stream(&mut self) {
        self.media_stream = None;
    }

    /// Ask the media stream receiver to request a fresh IDR (FIR/PLI) from the
    /// server and forget previously seen parameter sets.
    ///
    /// Call this after re-sending the `0x1c` offer in response to an Apple
    /// display-layout change (`0x451`): the encoder restarts its burst and
    /// waits for an explicit keyframe request before sending decodable frames.
    /// No-op when no media stream is running.
    #[cfg(not(target_os = "android"))]
    pub fn request_media_keyframe(&self) {
        if let Some(stream) = self.media_stream.as_ref() {
            stream.request_keyframe();
        }
    }

    /// Number of Apple HP media video RTP packets received so far (0 when no
    /// media stream is running). Useful to tell "server never started
    /// streaming" (re-offer the 0x1c) from "streaming but not decoding"
    /// (request a keyframe instead).
    #[cfg(not(target_os = "android"))]
    pub fn media_video_packets(&self) -> u64 {
        self.media_stream
            .as_ref()
            .map(|s| s.video_packets())
            .unwrap_or(0)
    }

    /// Resize the running Apple HP media stream decoder.
    ///
    /// The negotiated canvas dimensions are not known until the server sends a
    /// non-degenerate `0x1c` answer. Call this method after receiving
    /// [`VncEvent::MediaStreamAnswer`] to update the decoder size accordingly.
    #[cfg(not(target_os = "android"))]
    pub fn set_media_stream_size(&mut self, width: u16, height: u16) -> Result<(), VncError> {
        if let Some(stream) = self.media_stream.as_ref() {
            stream.resize(width, height);
            Ok(())
        } else {
            Err(VncError::Protocol("No active media stream".to_string()))
        }
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
        let msg = protocol::framing::EnableContinuousUpdates {
            enable,
            x,
            y,
            width,
            height,
        }
        .to_bytes();
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
    ///
    /// Wire format (RFB 7.6.7 ClientFence): message-type U8 (248), 3 bytes
    /// padding, flags U32, length U8, then `length` payload bytes. The payload
    /// is limited to 255 bytes by the U8 length field (the spec recommends a
    /// maximum of 64 bytes).
    pub fn send_fence(&mut self, flags: u32, data: &[u8]) -> Result<(), VncError> {
        if data.len() > u8::MAX as usize {
            return Err(VncError::Protocol(format!(
                "fence payload too long: {} bytes (max {})",
                data.len(),
                u8::MAX
            )));
        }
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut msg = Vec::with_capacity(9 + data.len());
        protocol::framing::Fence::write_message(&mut msg, flags, data);
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
        protocol::framing::write_cut_text(&mut msg, protocol::CLIENT_CUT_TEXT, data);
        stream.write_all(&msg)?;
        Ok(())
    }

    /// Send client cut text (legacy).
    pub fn send_cut_text(&mut self, text: &str) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut msg = Vec::with_capacity(8 + text.len());
        protocol::framing::write_cut_text(&mut msg, protocol::CLIENT_CUT_TEXT, text.as_bytes());
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

        // Drain any decoded frames produced by the Apple HP media stream receiver
        // before blocking on the TCP control channel.
        #[cfg(not(target_os = "android"))]
        if let Some(stream) = self.media_stream.as_ref() {
            while let Some(event) = stream.try_recv() {
                match event {
                    apple_media_stream::MediaStreamEvent::Frame {
                        width,
                        height,
                        rgba,
                    } => {
                        events.push(VncEvent::MediaFrame {
                            width,
                            height,
                            rgba,
                        });
                    }
                    apple_media_stream::MediaStreamEvent::Error(msg) => {
                        log::warn!("Apple media stream error: {}", msg);
                    }
                }
            }
        }

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

        log::trace!("read_messages msg_type=0x{:02x}", msg_type[0]);

        if let Err(e) = msg_type_result {
            let _ = self.set_read_timeout(saved_timeout);
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return Err(VncError::ServerClosed);
            }
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut
            {
                // Do not drop events that were already drained this call (e.g.
                // decoded Apple HP media frames) just because no TCP message
                // arrived within the timeout window.
                if !events.is_empty() {
                    return Ok(events);
                }
                return Err(VncError::Timeout);
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
            protocol::SERVER_END_OF_CONTINUOUS_UPDATES_LEGACY => {
                log::debug!("Server message: EndOfContinuousUpdates (legacy type 4)");
                self.last_msg_type = Some(protocol::SERVER_END_OF_CONTINUOUS_UPDATES_LEGACY);
                events.push(VncEvent::EndOfContinuousUpdates);
                Ok(())
            }
            protocol::SERVER_FENCE_LEGACY => {
                log::debug!("Server message: ServerFence (legacy type 5)");
                self.last_msg_type = Some(protocol::SERVER_FENCE_LEGACY);
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
            protocol::qemu::MESSAGE_TYPE => {
                log::debug!("Server message: QEMU extension");
                self.last_msg_type = Some(protocol::qemu::MESSAGE_TYPE);
                self.handle_qemu_extension(&mut events)
            }
            protocol::apple::MEDIA_STREAM_OPTIONS => {
                self.last_msg_type = Some(protocol::apple::MEDIA_STREAM_OPTIONS);
                self.handle_apple_media_stream_options(&mut events)
            }
            protocol::apple::MISC_STATUS => {
                self.last_msg_type = Some(protocol::apple::MISC_STATUS);
                self.handle_apple_misc_status(&mut events)
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
        let num_rects = {
            let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
            protocol::framing::read_fb_update_header(stream)?
        };
        self.recent_encodings.clear();
        self.recent_encodings.reserve(num_rects as usize);

        for _ in 0..num_rects {
            let mut rect_header = [0u8; 12];
            let (x, y, width, height, encoding) = {
                let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                stream.read_exact(&mut rect_header)?;
                let header = protocol::framing::RectHeader::from_bytes(&rect_header);
                let (x, y, width, height, encoding) = (
                    header.x,
                    header.y,
                    header.width,
                    header.height,
                    header.encoding,
                );
                self.last_encoding = Some(encoding);
                self.recent_encodings.push(encoding);
                log::trace!("FramebufferUpdate rect x={x} y={y} w={width} h={height} encoding={encoding:#x}");
                (x, y, width, height, encoding)
            };

            // Rectangles carry peer-controlled u16 dimensions; reject absurd
            // sizes before any decoder derives an allocation from them. This
            // also covers the DesktopSize-family pseudo-encodings, whose
            // width/height are the new framebuffer size.
            check_dimensions(width as u32, height as u32)?;

            match encodings::from_i32(encoding) {
                Encoding::Raw => self.handle_raw_encoding(x, y, width, height)?,
                Encoding::CopyRect => self.handle_copyrect_encoding(x, y, width, height)?,
                Encoding::Rre => self.handle_rre_encoding(x, y, width, height)?,
                Encoding::Hextile => self.handle_hextile_encoding(x, y, width, height)?,
                Encoding::Zlib => self.handle_zlib_encoding(x, y, width, height)?,
                Encoding::Tight => self.handle_tight_encoding(x, y, width, height)?,
                Encoding::Trle => self.handle_trle_encoding(x, y, width, height)?,
                Encoding::Zrle => self.handle_zrle_encoding(x, y, width, height)?,
                Encoding::OpenH264 => self.handle_openh264_encoding(x, y, width, height)?,
                Encoding::DesktopSize => {
                    self.handle_desktop_size_pseudo_encoding(x, y, width, height, events)?
                }
                Encoding::CursorPos => {
                    // CursorPos pseudo-encoding: no extra data
                    events.push(VncEvent::CursorPos { x, y });
                }
                Encoding::Cursor => {
                    self.handle_cursor_pseudo_encoding(x, y, width, height, events)?
                }
                Encoding::DesktopName => self.handle_desktop_name_pseudo_encoding(events)?,
                Encoding::ExtendedDesktopSize => {
                    self.handle_extended_desktop_size_pseudo_encoding(x, y, width, height, events)?
                }
                Encoding::ExtendedClipboard => {
                    // Extended Clipboard pseudo-encoding is only a capability
                    // declaration; actual clipboard data comes via ServerCutText.
                    // The server should not send pixel data for this encoding.
                    // Both wire values exist in the wild (LibVNCServer/UltraVNC
                    // vs QEMU-derived servers); `from_i32` maps either to this
                    // variant.
                    log::debug!("Ignoring ExtendedClipboard pseudo-encoding rectangle");
                }
                Encoding::Fence => self.handle_fence_pseudo_encoding(events, width, height)?,
                // Apple high-performance pseudo-encodings.
                Encoding::AppleHp(enc) if enc == protocol::apple::ENC_REKEY => {
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
                Encoding::AppleHp(enc) if enc == protocol::apple::ENC_CURSOR => {
                    self.handle_apple_cursor_encoding(x, y, width, height, events)?;
                    continue;
                }
                Encoding::AppleHp(enc) if enc == protocol::apple::ENC_DISPLAY_LAYOUT => {
                    self.handle_apple_display_layout(x, y, width, height, events)?;
                    continue;
                }
                Encoding::AppleHp(enc) if enc == protocol::apple::ENC_VENDOR_KEYSYMS => {
                    // Apple vendor keysyms (u16 payload_len + opaque payload).
                    let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                    let mut len_buf = [0u8; 2];
                    stream.read_exact(&mut len_buf)?;
                    let payload_len = u16::from_be_bytes(len_buf) as usize;
                    const MAX_VENDOR_KEYSYM_LEN: usize = 64 * 1024;
                    if payload_len > MAX_VENDOR_KEYSYM_LEN {
                        return Err(VncError::Protocol(format!(
                            "Apple vendor keysyms payload length {} exceeds limit",
                            payload_len
                        )));
                    }
                    let mut payload = vec![0u8; payload_len];
                    stream.read_exact(&mut payload)?;
                    log::debug!(
                        "Apple vendor keysyms (encoding {:#x}) ignored ({} bytes)",
                        protocol::apple::ENC_VENDOR_KEYSYMS,
                        payload_len
                    );
                    continue;
                }
                Encoding::AppleHp(enc) if enc == protocol::apple::ENC_KEYBOARD_INPUT_SOURCE => {
                    self.handle_apple_keyboard_input_source(events)?;
                    continue;
                }
                Encoding::AppleHp(enc) if enc == protocol::apple::ENC_DEVICE_INFO => {
                    self.handle_apple_device_info(events)?;
                    continue;
                }
                Encoding::AppleHp(enc) if enc == protocol::apple::ENC_MEDIA_STREAM => {
                    // Apple media stream announcement (u16 payload_len + payload).
                    let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                    let mut len_buf = [0u8; 2];
                    stream.read_exact(&mut len_buf)?;
                    let payload_len = u16::from_be_bytes(len_buf) as usize;
                    let mut payload = vec![0u8; payload_len];
                    stream.read_exact(&mut payload)?;
                    // parse_media_stream_init expects the length-prefixed form.
                    let mut prefixed = Vec::with_capacity(2 + payload_len);
                    prefixed.extend_from_slice(&len_buf);
                    prefixed.extend_from_slice(&payload);
                    if let Some(init) = apple_media::parse_media_stream_init(&prefixed) {
                        log::trace!(
                            "Apple media stream init stage={} port={}",
                            init.stage,
                            init.base_udp_port
                        );
                        events.push(VncEvent::MediaStreamInit(init));
                    } else if let Some(answer) = apple_media::parse_media_stream_answer(&prefixed) {
                        log::debug!(
                            "Apple media stream answer (encoding {:#x}): {}x{} tiles={} codec={:?}",
                            protocol::apple::ENC_MEDIA_STREAM,
                            answer.canvas_width,
                            answer.canvas_height,
                            answer.tile_count,
                            answer.codec
                        );
                        events.push(VncEvent::MediaStreamAnswer(answer));
                    } else {
                        log::debug!(
                            "Apple media stream announcement (encoding {:#x}) malformed",
                            protocol::apple::ENC_MEDIA_STREAM
                        );
                    }
                    continue;
                }
                Encoding::AppleHp(enc) if enc == protocol::apple::MEDIA_STREAM_OPTIONS as i32 => {
                    log::warn!("Apple media stream options answer rect (encoding 0x1c)");
                    // The 0x1c answer is a single rect inside a FramebufferUpdate.
                    // Its body is a zlib-compressed binary plist; read the rest of
                    // the current record, decompress, and parse it.
                    let body = {
                        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                        stream.read_remaining_record()?
                    };
                    log::warn!(
                        "0x1c answer body {} bytes prefix={:02x?}",
                        body.len(),
                        &body[..body.len().min(16)]
                    );
                    let decompressed =
                        apple_media::zlib_decompress(&body).unwrap_or_else(|| body.clone());
                    if let Some(parsed) = apple_media::parse_media_stream_answer(&decompressed) {
                        log::warn!(
                            "0x1c answer parsed: {}x{} tiles={} codec={:?}",
                            parsed.canvas_width,
                            parsed.canvas_height,
                            parsed.tile_count,
                            parsed.codec
                        );
                        events.push(VncEvent::MediaStreamAnswer(parsed));
                    } else {
                        log::warn!("0x1c answer could not be parsed");
                    }
                    continue;
                }
                Encoding::AppleHp(enc)
                    if enc == protocol::apple::ENC_LOW_QUALITY
                        || enc == protocol::apple::ENC_MEDIUM_QUALITY =>
                {
                    // Apple still-image codecs (u32 nbytes + payload).
                    let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                    let mut len_buf = [0u8; 4];
                    stream.read_exact(&mut len_buf)?;
                    let len = u32::from_be_bytes(len_buf) as usize;
                    // Compressed still images (JPEG/HEIF-style) of a full
                    // screen are a few MiB even at 8K; 32 MiB is generous and
                    // stops a malicious length from forcing a huge allocation.
                    const MAX_STILL_IMAGE_LEN: usize = 32 * 1024 * 1024;
                    if len > MAX_STILL_IMAGE_LEN {
                        return Err(VncError::Protocol(format!(
                            "Apple still-image payload length {} exceeds limit",
                            len
                        )));
                    }
                    let mut payload = vec![0u8; len];
                    stream.read_exact(&mut payload)?;
                    log::debug!("Apple still-image codec (encoding {:#x}) ignored", enc);
                    continue;
                }
                Encoding::AppleHp(enc)
                    if enc == protocol::apple::ENC_HIGH_QUALITY
                        || enc == protocol::apple::ENC_MULTI_VARIANT_SCALED =>
                {
                    // In the adaptive media path these encodings are media-stream
                    // reconfig rectangles sharing the same u16-prefixed wire shape
                    // as 0x3f2. We parse the prefix and emit a media-init event.
                    // If the server is using them as still-image codecs instead, this
                    // branch will misread; that is a known limitation of preliminary
                    // H.264 media support.
                    let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
                    let mut len_buf = [0u8; 2];
                    stream.read_exact(&mut len_buf)?;
                    let payload_len = u16::from_be_bytes(len_buf) as usize;
                    let mut payload = vec![0u8; payload_len];
                    stream.read_exact(&mut payload)?;
                    let mut prefixed = Vec::with_capacity(2 + payload_len);
                    prefixed.extend_from_slice(&len_buf);
                    prefixed.extend_from_slice(&payload);
                    if let Some(init) = apple_media::parse_media_stream_init(&prefixed) {
                        log::debug!(
                            "Apple media reconfig {:#x} stage={} port={}",
                            enc,
                            init.stage,
                            init.base_udp_port
                        );
                        events.push(VncEvent::MediaStreamInit(init));
                    } else if let Some(answer) = apple_media::parse_media_stream_answer(&prefixed) {
                        log::debug!(
                            "Apple media stream answer (encoding {:#x}): {}x{} tiles={} codec={:?}",
                            enc,
                            answer.canvas_width,
                            answer.canvas_height,
                            answer.tile_count,
                            answer.codec
                        );
                        events.push(VncEvent::MediaStreamAnswer(answer));
                    } else {
                        log::debug!("Apple media reconfig (encoding {:#x}) malformed", enc);
                    }
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
        log::debug!(
            "Raw encoding: {}x{}@({}, {}) pixel_format={:?}",
            width,
            height,
            x,
            y,
            pixel_format
        );

        // Raw frames can be very large (e.g. 2560x1440 x 4 bytes). Temporarily
        // extend the read timeout so that short per-read timeouts don't cause the
        // stream to become misaligned mid-frame.
        let saved_timeout = self.read_timeout;
        self.set_read_timeout(Some(Duration::from_secs(60)))?;

        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let decode_result = protocol::raw::decode(
            stream,
            &mut self.framebuffer,
            x as usize,
            y as usize,
            width as usize,
            height as usize,
            &pixel_format,
        );

        // Restore the previous timeout best-effort; report the original decode
        // error if it failed.
        let _ = self.set_read_timeout(saved_timeout);
        decode_result?;

        log::debug!("Raw encoding complete: {}x{}@({}, {})", width, height, x, y);
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
        let mut buf = [0u8; protocol::framing::CopyRectBody::WIRE_LEN];
        stream.read_exact(&mut buf)?;
        let body = protocol::framing::CopyRectBody::parse(&buf)
            .ok_or_else(|| VncError::Protocol("Truncated CopyRect body".to_string()))?;
        self.framebuffer.copy_rect(
            body.src_x as usize,
            body.src_y as usize,
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
            &mut self.hextile_state,
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
            &mut self.tight_streams,
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
        //   4 bytes big-endian flags (currently unused)
        //   length bytes H.264 payload
        let mut header = [0u8; protocol::framing::OpenH264Header::WIRE_LEN];
        stream.read_exact(&mut header)?;
        let header = protocol::framing::OpenH264Header::parse(&header)
            .ok_or_else(|| VncError::Protocol("Truncated OpenH264 header".to_string()))?;
        let data_len = header.len as usize;
        let _flags = header.flags;

        if data_len == 0 {
            // Zero-length frames are used for reset signalling; nothing to decode.
            return Ok(());
        }

        // An H.264 access unit for one frame is always smaller than the
        // uncompressed frame (w*h*3 for 4:2:0 at 8 bits is w*h*3/2; use
        // w*h*3 as a loose bound) plus slack for Annex-B start codes and
        // SPS/PPS. Reject larger lengths before allocating.
        let max_data_len = width as usize * height as usize * 3 + 64 * 1024;
        if data_len > max_data_len {
            return Err(VncError::Protocol(format!(
                "OpenH264 payload length {} exceeds bound {} for {}x{} frame",
                data_len, max_data_len, width, height
            )));
        }

        let mut data = vec![0u8; data_len];
        stream.read_exact(&mut data)?;

        if self.h264_decoder.is_none() {
            self.h264_decoder = Some(Box::new(DefaultDecoder::new()?));
        }

        let decoder = self.h264_decoder.as_ref().unwrap();
        // Ensure the decoder knows the expected frame size before decoding.
        decoder.set_size(width, height);
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
        let mut data = vec![0u8; CursorShape::wire_len(width, height, &self.pixel_format)];
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
        // A name length over the cap maps to VncError::Protocol (not Io) via
        // the ProtocolError conversion.
        self.name = protocol::framing::read_desktop_name_body(stream)?;
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
        let screens = protocol::framing::read_screen_list(stream)?;

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
        let fence = protocol::framing::Fence::read_rect_body(stream)?;
        log::debug!(
            "Fence pseudo-encoding rect flags={:#010x} len={}",
            fence.flags,
            fence.payload.len()
        );
        events.push(VncEvent::Fence {
            flags: fence.flags,
            data: fence.payload,
        });
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
            // The payload is zlib-compressed BGRA pixels plus a separate
            // alpha plane: 5 bytes per pixel uncompressed. A zlib stream
            // never needs more bytes than its output plus format overhead,
            // so reject larger lengths before allocating.
            let max_len = width as usize * height as usize * 5 + 64 * 1024;
            if compressed_len > max_len {
                return Err(VncError::Protocol(format!(
                    "Apple cursor STORE length {} exceeds bound {} for {}x{} cursor",
                    compressed_len, max_len, width, height
                )));
            }
            let mut payload = vec![0u8; compressed_len];
            stream.read_exact(&mut payload)?;
            let cursor = self.decode_apple_cursor_store(width, height, &payload)?;
            const MAX_APPLE_CURSOR_CACHE: usize = 64;
            if self.apple_cursor_cache.len() >= MAX_APPLE_CURSOR_CACHE {
                // Evict an arbitrary entry to bound memory use.
                if let Some(key) = self.apple_cursor_cache.keys().next().copied() {
                    self.apple_cursor_cache.remove(&key);
                }
            }
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
            // Apple HP cursor images are RGBA with an alpha channel. The shared
            // CursorShape stores a separate 1-bit mask and RGBA pixels with alpha
            // already applied; treat the cursor as fully opaque in the mask and
            // keep the original alpha in pixels.
            let mask_row_bytes = (cursor.width as usize).div_ceil(8);
            let mask = vec![0xff; mask_row_bytes * cursor.height as usize];
            let shape = CursorShape {
                width: cursor.width,
                height: cursor.height,
                hotspot_x: x,
                hotspot_y: y,
                pixels: cursor.pixels.clone(),
                mask,
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

        let decoder = ZlibDecoder::new(payload);
        // The expected output is known exactly (BGRA + alpha plane); cap the
        // inflate at one byte more so a decompression bomb is rejected
        // instead of growing the buffer without bound.
        let mut decompressed = Vec::with_capacity(expected_bgra + expected_alpha);
        decoder
            .take((expected_bgra + expected_alpha + 1) as u64)
            .read_to_end(&mut decompressed)
            .map_err(|e| VncError::Protocol(format!("Apple cursor zlib decode error: {}", e)))?;

        if decompressed.len() > expected_bgra + expected_alpha {
            return Err(VncError::Protocol(format!(
                "Apple cursor payload too large: got more than {} bytes for {}x{} cursor",
                expected_bgra + expected_alpha,
                width,
                height
            )));
        }
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

        if scaled_width > 0 && scaled_height > 0 {
            self.apple_scaled_size = Some((scaled_width, scaled_height));
        }

        // Use the backing geometry for the local framebuffer, which is where
        // decoded rectangles are written. The scaled size is for window sizing.
        if backing_width > 0 && backing_height > 0 {
            check_dimensions(backing_width as u32, backing_height as u32)?;
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

    /// Handle the Apple `KeyboardInputSource` pseudo-encoding (`0x455`).
    fn handle_apple_keyboard_input_source(
        &mut self,
        events: &mut Vec<VncEvent>,
    ) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix)?;
        let prefix_len = u16::from_be_bytes(prefix) as usize;
        if prefix_len < 8 {
            return Err(VncError::Protocol(format!(
                "Apple keyboard input source prefix length too small: {}",
                prefix_len
            )));
        }
        let mut payload = vec![0u8; prefix_len];
        stream.read_exact(&mut payload)?;

        let Some(info) = parse_apple_keyboard_input_source(&payload) else {
            return Err(VncError::Protocol(
                "Apple keyboard input source payload malformed".to_string(),
            ));
        };
        log::debug!(
            "Apple keyboard input source: version_marker={} flags={} id={:?}",
            info.version_marker,
            info.keyboard_input_flags,
            info.input_source_id
        );
        events.push(VncEvent::KeyboardInputSource {
            input_source_id: info.input_source_id,
            secure_event_input: info.secure_event_input,
        });
        Ok(())
    }

    /// Handle the Apple `DeviceInfo` pseudo-encoding (`0x456`).
    fn handle_apple_device_info(&mut self, events: &mut Vec<VncEvent>) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut msg_size_buf = [0u8; 2];
        stream.read_exact(&mut msg_size_buf)?;
        let msg_size = u16::from_be_bytes(msg_size_buf) as usize;
        if msg_size < 16 {
            return Err(VncError::Protocol(
                "Apple device info message size too small".to_string(),
            ));
        }
        // `message_size` covers the fixed 16-byte header and the trailing
        // info block (strings + housing_color), not the 2-byte `message_size`
        // field itself. Read exactly that many bytes.
        let mut payload = vec![0u8; msg_size];
        stream.read_exact(&mut payload)?;

        let Some(info) = parse_apple_device_info(&payload) else {
            return Err(VncError::Protocol(
                "Apple device info payload malformed".to_string(),
            ));
        };
        log::debug!(
            "Apple device info: structure_version={} enclosure_rgb_color={} housing_color={} identifier={:?}",
            info.structure_version,
            info.enclosure_rgb_color,
            info.housing_color,
            info.device_identifier
        );
        events.push(VncEvent::DeviceInfo {
            device_identifier: info.device_identifier,
            device_color: info.device_color,
            enclosure_color: info.enclosure_color,
            enclosure_rgb_color: info.enclosure_rgb_color,
            housing_color: info.housing_color,
        });
        Ok(())
    }

    /// Handle a server-side `0x1c` MediaStreamOptions answer.
    fn handle_apple_media_stream_options(
        &mut self,
        events: &mut Vec<VncEvent>,
    ) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut header = [0u8; 4];
        stream.read_exact(&mut header)?;
        let message_size = u16::from_be_bytes([header[2], header[3]]) as usize;
        const MAX_MEDIA_OPTIONS_LEN: usize = 64 * 1024;
        if message_size > MAX_MEDIA_OPTIONS_LEN {
            return Err(VncError::Protocol(format!(
                "Apple media stream options answer message size {} exceeds limit",
                message_size
            )));
        }
        let mut body = vec![0u8; message_size];
        stream.read_exact(&mut body)?;
        let mut answer = Vec::with_capacity(4 + message_size);
        answer.extend_from_slice(&header);
        answer.extend_from_slice(&body);
        if let Some(parsed) = apple_media::parse_media_stream_answer(&answer) {
            log::debug!(
                "Apple media stream answer: {}x{} tiles={} codec={:?}",
                parsed.canvas_width,
                parsed.canvas_height,
                parsed.tile_count,
                parsed.codec
            );
            events.push(VncEvent::MediaStreamAnswer(parsed));
        } else {
            log::debug!(
                "Apple media stream answer degenerate or malformed ({} bytes)",
                answer.len()
            );
            // The offer only advertises HEVC, so a degenerate answer still
            // implies the HEVC path.
            events.push(VncEvent::MediaStreamAnswer(MediaStreamAnswer {
                canvas_width: 0,
                canvas_height: 0,
                tile_count: 0,
                codec: Codec::Hevc,
            }));
        }
        Ok(())
    }

    /// Handle the Apple `MiscStatus` server-to-client control message (`0x14`).
    fn handle_apple_misc_status(&mut self, events: &mut Vec<VncEvent>) -> Result<(), VncError> {
        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let mut buf = [0u8; 7];
        stream.read_exact(&mut buf)?;
        let _body_len = u16::from_be_bytes([buf[1], buf[2]]);
        let _flags = u16::from_be_bytes([buf[3], buf[4]]);
        let cmd = u16::from_be_bytes([buf[5], buf[6]]);
        match cmd {
            12 => {
                log::debug!("Apple MiscStatus: heartbeat");
            }
            2 => {
                log::debug!("Apple MiscStatus: remote clipboard changed");
                events.push(VncEvent::ClipboardChanged);
            }
            11 => {
                log::debug!("Apple MiscStatus: user session changed");
            }
            other => {
                log::debug!("Apple MiscStatus: unknown cmd={}", other);
            }
        }
        Ok(())
    }

    fn handle_server_cut_text(&mut self, events: &mut Vec<VncEvent>) -> Result<(), VncError> {
        const MAX_CUT_TEXT_LEN: usize = 10 * 1024 * 1024;

        let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
        let len = protocol::framing::read_cut_text_length(stream)?;
        log::debug!("ServerCutText length: {}", len);

        if len >= 0 {
            let len = len as usize;
            if len > MAX_CUT_TEXT_LEN {
                return Err(VncError::Protocol(format!(
                    "ServerCutText length {} exceeds limit",
                    len
                )));
            }
            let mut text = vec![0u8; len];
            stream.read_exact(&mut text)?;
            events.push(VncEvent::CutText(
                String::from_utf8_lossy(&text).to_string(),
            ));
        } else {
            // Extended Clipboard format: abs(length) bytes of extended data
            // follow the header. The first 4 bytes of that data are flags.
            let len = len.unsigned_abs() as usize;
            if len > MAX_CUT_TEXT_LEN {
                return Err(VncError::Protocol(format!(
                    "ExtendedClipboard data length {} exceeds limit",
                    len
                )));
            }
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
        let fence = {
            let stream = self.stream.as_mut().ok_or(VncError::NotConnected)?;
            protocol::framing::Fence::read_body(stream)?
        };
        let flags = fence.flags;
        let data = fence.payload;
        log::debug!("ServerFence flags={:#010x} len={}", flags, data.len());

        // Echo the fence back to the server when it requested a response.
        // This is the standard client-side behaviour for the Fence
        // pseudo-encoding and allows servers (e.g. wayvnc/neatvnc) to measure
        // their own round-trip times and bandwidth. Per the spec the response
        // clears the Request bit plus any bits we do not understand, keeps the
        // known synchronisation bits, and echoes the payload.
        if flags & protocol::FENCE_FLAG_REQUEST != 0 {
            let echo_flags = flags
                & (protocol::FENCE_FLAG_BLOCK_BEFORE
                    | protocol::FENCE_FLAG_BLOCK_AFTER
                    | protocol::FENCE_FLAG_SYNC_NEXT);
            let _ = self.send_fence(echo_flags, &data);
        }

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
            protocol::qemu::SUB_TYPE_LED_STATE => {
                // LED State
                stream.read_exact(&mut buf)?;
                let led = protocol::qemu::parse_led_state(buf[0]);
                events.push(VncEvent::LedState {
                    scroll_lock: led.scroll_lock,
                    num_lock: led.num_lock,
                    caps_lock: led.caps_lock,
                });
            }
            protocol::qemu::SUB_TYPE_AUDIO => {
                // Audio (QEMU extension)
                stream.read_exact(&mut buf)?;
                let operation = buf[0];
                match operation {
                    protocol::qemu::AUDIO_OP_STOP => {
                        // Stop audio
                        // No additional data; UI should stop playback
                    }
                    protocol::qemu::AUDIO_OP_START => {
                        // Start audio / format info
                        let mut fmt_buf = [0u8; protocol::qemu::AudioFormatHeader::WIRE_LEN];
                        stream.read_exact(&mut fmt_buf)?;
                        let fmt = protocol::qemu::AudioFormatHeader::parse(&fmt_buf).ok_or_else(
                            || VncError::Protocol("Truncated QEMU audio header".to_string()),
                        )?;
                        let data_len = fmt.data_len as usize;
                        if data_len > MAX_QEMU_AUDIO_LEN {
                            return Err(VncError::Protocol(format!(
                                "QEMU audio length {} exceeds limit",
                                data_len
                            )));
                        }
                        let mut data = vec![0u8; data_len];
                        if data_len > 0 {
                            stream.read_exact(&mut data)?;
                        }
                        events.push(VncEvent::Audio {
                            sample_rate: fmt.sample_rate,
                            channels: fmt.channels,
                            bits_per_sample: fmt.bits_per_sample,
                            data,
                        });
                    }
                    protocol::qemu::AUDIO_OP_DATA => {
                        // Audio data
                        let mut len_buf = [0u8; 4];
                        stream.read_exact(&mut len_buf)?;
                        let data_len = u32::from_be_bytes(len_buf) as usize;
                        if data_len > MAX_QEMU_AUDIO_LEN {
                            return Err(VncError::Protocol(format!(
                                "QEMU audio length {} exceeds limit",
                                data_len
                            )));
                        }
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

/// Parsed Apple `KeyboardInputSource` (0x455) rectangle payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleKeyboardInputSource {
    pub version_marker: u16,
    pub keyboard_input_flags: u32,
    pub input_source_id: String,
    pub secure_event_input: bool,
}

/// Parse an Apple `KeyboardInputSource` (`0x455`) rectangle payload.
///
/// Returns `None` if the payload is too short or malformed.
fn parse_apple_keyboard_input_source(payload: &[u8]) -> Option<AppleKeyboardInputSource> {
    if payload.len() < 8 {
        return None;
    }
    let version_marker = u16::from_be_bytes([payload[0], payload[1]]);
    let keyboard_input_flags = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]);
    let id_len = u16::from_be_bytes([payload[6], payload[7]]) as usize;
    if 8 + id_len > payload.len() {
        return None;
    }
    let input_source_id = String::from_utf8_lossy(&payload[8..8 + id_len]).to_string();
    Some(AppleKeyboardInputSource {
        version_marker,
        keyboard_input_flags,
        input_source_id,
        secure_event_input: (keyboard_input_flags & 1) != 0,
    })
}

/// Parsed Apple `DeviceInfo` (0x456) rectangle payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleDeviceInfo {
    pub structure_version: u32,
    pub enclosure_rgb_color: u32,
    pub device_identifier: String,
    pub device_color: String,
    pub enclosure_color: String,
    pub housing_color: i32,
}

/// Parse an Apple `DeviceInfo` (`0x456`) rectangle payload.
///
/// Returns `None` if the payload is too short or malformed.
fn parse_apple_device_info(payload: &[u8]) -> Option<AppleDeviceInfo> {
    // Fixed header: block_pair_count(2) + structure_version(4) +
    // enclosure_rgb_color(4) + three u16 string lengths = 16 bytes.
    if payload.len() < 16 {
        return None;
    }
    let _block_pair_count = u16::from_be_bytes([payload[0], payload[1]]);
    let structure_version = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]);
    let enclosure_rgb_color = u32::from_be_bytes([payload[6], payload[7], payload[8], payload[9]]);
    let identifier_len = u16::from_be_bytes([payload[10], payload[11]]) as usize;
    let color_len = u16::from_be_bytes([payload[12], payload[13]]) as usize;
    let enclosure_len = u16::from_be_bytes([payload[14], payload[15]]) as usize;

    let mut off = 16usize;
    let read_string = |len: usize, off: &mut usize| -> Option<String> {
        if *off + len > payload.len() {
            return None;
        }
        let s = String::from_utf8_lossy(&payload[*off..*off + len])
            .trim_end_matches('\0')
            .to_string();
        *off += len;
        Some(s)
    };

    let device_identifier = read_string(identifier_len, &mut off)?;
    let device_color = read_string(color_len, &mut off)?;
    let enclosure_color = read_string(enclosure_len, &mut off)?;

    if off + 4 > payload.len() {
        return None;
    }
    let housing_color = i32::from_be_bytes([
        payload[off],
        payload[off + 1],
        payload[off + 2],
        payload[off + 3],
    ]);

    Some(AppleDeviceInfo {
        structure_version,
        enclosure_rgb_color,
        device_identifier,
        device_color,
        enclosure_color,
        housing_color,
    })
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
    apple_media_stream_h264: bool,
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
            apple_media_stream_h264: false,
        }
    }

    /// Enable Apple high-performance mode (RFB 003.889 + RSA-SRP + encrypted record layer).
    ///
    /// When enabled, the Apple HP encodings are prepended to the current
    /// encoding list rather than replacing it, so user-supplied fallbacks are
    /// preserved. The exact HP encoding list (with or without the adaptive media
    /// path encodings) is finalized in [`Self::build`].
    pub fn high_performance(mut self, enable: bool) -> Self {
        self.high_performance = enable;
        self
    }

    /// Enable the Apple HP adaptive media stream path and request HEVC.
    ///
    /// The Apple HP encoding list already advertises the media-path values
    /// (`0x3ea` = 1002, `0x3f2` = 1010, `0x3f3` = 1011), so this flag does not
    /// change the advertised encodings. It enables the `0x1c` MediaStreamOptions
    /// offer API (`send_hp_media_stream_options`), the parser for media-init
    /// rectangles (`VncEvent::MediaStreamInit`), and the HEVC UDP/SRTP media
    /// stream receiver (`VncClient::start_media_stream`,
    /// `VncEvent::MediaFrame`).
    ///
    /// The receiver is only available on non-Android targets.
    ///
    /// Has no effect unless [`Self::high_performance`] is also enabled.
    pub fn apple_media_stream_h264(mut self, enable: bool) -> Self {
        self.apple_media_stream_h264 = enable;
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
        client.sasl_username = self.sasl_username;
        client.sasl_password = self.sasl_password;
        client.high_performance = self.high_performance;
        client.apple_display_width = self.apple_display_width;
        client.apple_display_height = self.apple_display_height;
        client.apple_display_dynamic = self.apple_display_dynamic;
        client.apple_hidpi_scale = self.apple_hidpi_scale;
        client.apple_virtual_display = self.apple_virtual_display;
        client.apple_media_stream_h264 = self.apple_media_stream_h264;

        if self.high_performance {
            // Apple HP uses the dedicated shared byte to request virtual-display setup.
            client.client_init_shared = protocol::apple::CLIENT_INIT_SHARED;

            // The HP encoding list already advertises the media-path values
            // (0x3ea = 1002, 0x3f2 = 1010, 0x3f3 = 1011). Deduplicate while mapping
            // so the plaintext/encrypted SetEncodings messages do not list any value
            // twice.
            let mut merged: Vec<Encoding> = Vec::with_capacity(
                apple_record_layer::APPLE_HP_ENCODINGS.len() + self.encodings.len(),
            );
            for &v in apple_record_layer::APPLE_HP_ENCODINGS {
                let enc = from_i32(v);
                if !merged.contains(&enc) {
                    merged.push(enc);
                }
            }
            for enc in self.encodings {
                if !merged.contains(&enc) {
                    merged.push(enc);
                }
            }
            client.apple_hp_encodings = merged.iter().map(|e| e.as_i32()).collect();
            client.encodings = merged;
        } else {
            client.encodings = self.encodings;
            client.apple_hp_encodings = apple_record_layer::APPLE_HP_ENCODINGS.to_vec();
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
    fn high_performance_preserves_user_encodings() {
        let client = VncClientBuilder::new()
            .encodings(vec![Encoding::Raw, Encoding::CopyRect])
            .high_performance(true)
            .build();
        assert!(client.high_performance);
        assert_eq!(client.encodings[0], Encoding::AppleHp(1010));
        assert!(client.encodings.contains(&Encoding::Raw));
        assert!(client.encodings.contains(&Encoding::CopyRect));
        // Apple HP encodings come first; duplicates are removed.
        assert_eq!(
            client
                .encodings
                .iter()
                .filter(|&&e| e == Encoding::Raw)
                .count(),
            1
        );
    }

    #[test]
    fn high_performance_media_stream_h264_sets_flag() {
        let client = VncClientBuilder::new()
            .high_performance(true)
            .apple_media_stream_h264(true)
            .build();
        assert!(client.high_performance);
        assert!(client.apple_media_stream_h264);
        // The HP encoding list already advertises the media-path values.
        assert!(client.apple_hp_encodings.contains(&1002)); // 0x3ea
        assert!(client.apple_hp_encodings.contains(&1010)); // 0x3f2
        assert!(client.apple_hp_encodings.contains(&1011)); // 0x3f3
                                                            // No duplicate values should be present.
        let mut uniq = client.apple_hp_encodings.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(uniq.len(), client.apple_hp_encodings.len());
    }

    #[test]
    fn high_performance_without_media_stream_h264_clears_flag() {
        let client = VncClientBuilder::new().high_performance(true).build();
        assert!(!client.apple_media_stream_h264);
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
    fn parse_apple_device_info_short_payload_is_rejected() {
        // Regression: the fixed header is 16 bytes (2 + 4 + 4 + 3 * u16
        // string lengths). A 12-byte payload previously passed the length
        // check and then panicked reading payload[12..16].
        let payload = [0u8; 12];
        assert_eq!(parse_apple_device_info(&payload), None);

        // 15 bytes is still too short.
        let payload = [0u8; 15];
        assert_eq!(parse_apple_device_info(&payload), None);

        // A minimal well-formed payload: no strings, just the fixed header
        // plus the trailing housing_color i32.
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u16.to_be_bytes()); // block_pair_count
        payload.extend_from_slice(&1u32.to_be_bytes()); // structure_version
        payload.extend_from_slice(&0xaabbccddu32.to_be_bytes()); // enclosure_rgb_color
        payload.extend_from_slice(&0u16.to_be_bytes()); // identifier_len
        payload.extend_from_slice(&0u16.to_be_bytes()); // color_len
        payload.extend_from_slice(&0u16.to_be_bytes()); // enclosure_len
        payload.extend_from_slice(&7i32.to_be_bytes()); // housing_color
        let info = parse_apple_device_info(&payload).expect("16-byte header parses");
        assert_eq!(info.structure_version, 1);
        assert_eq!(info.enclosure_rgb_color, 0xaabbccdd);
        assert_eq!(info.housing_color, 7);
        assert_eq!(info.device_identifier, "");
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
        assert_eq!(shape.mask, vec![0xff]); // 1 visible pixel, remaining padding bits also 1
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
    fn handle_apple_media_stream_init_yields_event() {
        use protocol::apple;
        let (mut client, mut server) = fence_test_client();

        // One FBUpdate rectangle with encoding 0x3f2 and a stage-1 payload.
        // The 0x3f2 body has a u16 length prefix and a 14-byte fixed header;
        // there is no leading padding before the version/type pair.
        let mut init_payload = Vec::new();
        init_payload.extend_from_slice(&1u16.to_be_bytes()); // version = 1
        init_payload.extend_from_slice(&1u16.to_be_bytes()); // type = 1 (stage 1)
        init_payload.extend_from_slice(&0u16.to_be_bytes()); // field6 = next stream port
        init_payload.extend_from_slice(&1u16.to_be_bytes()); // field8 = stream_count
        init_payload.extend_from_slice(&5900u16.to_be_bytes()); // field10 = base UDP port
        init_payload.extend_from_slice(&0u32.to_be_bytes()); // field12

        server.write_all(&[0, 0, 1]).unwrap(); // padding + num_rects = 1
        let header = protocol::framing::RectHeader {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
            encoding: apple::ENC_MEDIA_STREAM,
        };
        server.write_all(&header.to_bytes()).unwrap();
        server
            .write_all(&(init_payload.len() as u16).to_be_bytes())
            .unwrap();
        server.write_all(&init_payload).unwrap();

        let mut events = Vec::new();
        client.handle_framebuffer_update(&mut events).unwrap();
        assert_eq!(events.len(), 1);
        match events.remove(0) {
            VncEvent::MediaStreamInit(init) => {
                assert_eq!(init.stage, 1);
                assert_eq!(init.base_udp_port, 5900);
                assert_eq!(init.stream_count, 1);
            }
            _ => panic!("expected MediaStreamInit event"),
        }
    }

    #[test]
    fn handle_apple_media_stream_options_yields_answer_event() {
        let (mut client, mut server) = fence_test_client();

        // Build a degenerate answer (empty body) — still valid 0x1c framing.
        server
            .write_all(&[protocol::apple::MEDIA_STREAM_OPTIONS, 0])
            .unwrap();
        server.write_all(&0u16.to_be_bytes()).unwrap(); // message_size = 0

        let mut events = Vec::new();
        client
            .handle_apple_media_stream_options(&mut events)
            .unwrap();
        assert_eq!(events.len(), 1);
        match events.remove(0) {
            VncEvent::MediaStreamAnswer(answer) => {
                assert_eq!(answer.canvas_width, 0);
                assert_eq!(answer.canvas_height, 0);
                assert_eq!(answer.tile_count, 0);
            }
            _ => panic!("expected MediaStreamAnswer event"),
        }
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

    #[test]
    fn parse_apple_keyboard_input_source_extracts_fields() {
        let id = "com.apple.keylayout.ABC";
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u16.to_be_bytes()); // version_marker
        payload.extend_from_slice(&1u32.to_be_bytes()); // keyboard_input_flags
        payload.extend_from_slice(&(id.len() as u16).to_be_bytes()); // id_len
        payload.extend_from_slice(id.as_bytes());

        let info = parse_apple_keyboard_input_source(&payload).unwrap();
        assert_eq!(info.version_marker, 1);
        assert_eq!(info.keyboard_input_flags, 1);
        assert_eq!(info.input_source_id, id);
        assert!(info.secure_event_input);
    }

    #[test]
    fn parse_apple_keyboard_input_source_rejects_short_payload() {
        assert!(parse_apple_keyboard_input_source(&[0u8; 6]).is_none());
        // id_len exceeds payload
        let mut payload = vec![0u8; 8];
        payload[6..8].copy_from_slice(&10u16.to_be_bytes());
        assert!(parse_apple_keyboard_input_source(&payload).is_none());
    }

    #[test]
    fn parse_apple_device_info_extracts_fields() {
        let identifier = "MacBookPro18,1";
        let color = "Silver";
        let mut payload = Vec::new();
        payload.extend_from_slice(&2u16.to_be_bytes()); // block_pair_count
        payload.extend_from_slice(&1u32.to_be_bytes()); // structure_version
        payload.extend_from_slice(&0x12345678u32.to_be_bytes()); // enclosure_rgb_color
        payload.extend_from_slice(&((identifier.len() + 1) as u16).to_be_bytes()); // device_identifier_len
        payload.extend_from_slice(&((color.len() + 1) as u16).to_be_bytes()); // device_color_len
        payload.extend_from_slice(&((color.len() + 1) as u16).to_be_bytes()); // enclosure_color_len
        payload.extend_from_slice(identifier.as_bytes());
        payload.push(0);
        payload.extend_from_slice(color.as_bytes());
        payload.push(0);
        payload.extend_from_slice(color.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&42i32.to_be_bytes()); // housing_color

        let info = parse_apple_device_info(&payload).unwrap();
        assert_eq!(info.structure_version, 1);
        assert_eq!(info.enclosure_rgb_color, 0x12345678);
        assert_eq!(info.device_identifier, identifier);
        assert_eq!(info.device_color, color);
        assert_eq!(info.enclosure_color, color);
        assert_eq!(info.housing_color, 42);
    }

    #[test]
    fn handle_apple_device_info_reads_message_size_prefix() {
        let (mut client, mut server) = fence_test_client();
        let identifier = "MacBookPro18,1";
        let color = "Silver";
        let mut payload = Vec::new();
        payload.extend_from_slice(&2u16.to_be_bytes()); // block_pair_count
        payload.extend_from_slice(&1u32.to_be_bytes()); // structure_version
        payload.extend_from_slice(&0u32.to_be_bytes()); // enclosure_rgb_color
        payload.extend_from_slice(&((identifier.len() + 1) as u16).to_be_bytes()); // device_identifier_len
        payload.extend_from_slice(&((color.len() + 1) as u16).to_be_bytes()); // device_color_len
        payload.extend_from_slice(&((color.len() + 1) as u16).to_be_bytes()); // enclosure_color_len
        payload.extend_from_slice(identifier.as_bytes());
        payload.push(0);
        payload.extend_from_slice(color.as_bytes());
        payload.push(0);
        payload.extend_from_slice(color.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&7i32.to_be_bytes()); // housing_color

        server
            .write_all(&(payload.len() as u16).to_be_bytes())
            .unwrap();
        server.write_all(&payload).unwrap();

        let mut events = Vec::new();
        client.handle_apple_device_info(&mut events).unwrap();
        assert_eq!(events.len(), 1);
        match events.remove(0) {
            VncEvent::DeviceInfo {
                device_identifier,
                housing_color,
                ..
            } => {
                assert_eq!(device_identifier, identifier);
                assert_eq!(housing_color, 7);
            }
            _ => panic!("expected DeviceInfo event"),
        }
    }

    #[test]
    fn handle_apple_device_info_rejects_short_message_size() {
        let (mut client, mut server) = fence_test_client();
        server.write_all(&2u16.to_be_bytes()).unwrap(); // message_size = 2 (too small)
        server.write_all(&[0u8; 2]).unwrap();

        let mut events = Vec::new();
        assert!(matches!(
            client.handle_apple_device_info(&mut events),
            Err(VncError::Protocol(_))
        ));
    }

    #[test]
    fn hp_send_methods_require_connection() {
        let mut client = VncClientBuilder::new().high_performance(true).build();
        assert!(matches!(
            client.send_hp_key_event(true, 0x61, 0, 0),
            Err(VncError::NotConnected)
        ));
        assert!(matches!(
            client.send_hp_pointer_event(0, 0, 0),
            Err(VncError::NotConnected)
        ));
        assert!(matches!(
            client.send_hp_set_mode(1),
            Err(VncError::NotConnected)
        ));
        assert!(matches!(
            client.send_hp_scale_factor(2.0),
            Err(VncError::NotConnected)
        ));
        assert!(matches!(
            client.send_hp_set_display_message(true, 0),
            Err(VncError::NotConnected)
        ));
        assert!(matches!(
            client.send_hp_auto_pasteboard(1),
            Err(VncError::NotConnected)
        ));
        assert!(matches!(
            client.send_hp_set_keyboard_input_source("com.apple.keylayout.ABC"),
            Err(VncError::NotConnected)
        ));
        assert!(matches!(
            client.request_clipboard_fetch(),
            Err(VncError::NotConnected)
        ));
    }

    #[test]
    fn hp_scale_factor_rejects_non_positive() {
        let mut client = VncClientBuilder::new().high_performance(true).build();
        assert!(matches!(
            client.send_hp_scale_factor(0.0),
            Err(VncError::Protocol(_))
        ));
        assert!(matches!(
            client.send_hp_scale_factor(-1.0),
            Err(VncError::Protocol(_))
        ));
    }

    #[test]
    fn hp_auto_pasteboard_rejects_invalid_selector() {
        let mut client = VncClientBuilder::new().high_performance(true).build();
        assert!(matches!(
            client.send_hp_auto_pasteboard(0),
            Err(VncError::Protocol(_))
        ));
        assert!(matches!(
            client.send_hp_auto_pasteboard(3),
            Err(VncError::Protocol(_))
        ));
    }

    /// Build a client connected to a loopback socket, returning the client and
    /// the server end of the connection for reading/writing wire bytes.
    fn fence_test_client() -> (VncClient, std::net::TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = std::net::TcpStream::connect(addr).unwrap();
        let server_side = listener.accept().unwrap().0;
        let mut client = VncClientBuilder::new().build();
        client.stream = Some(VncStream {
            inner: VncStreamInner::Plain(stream),
            bytes_read: 0,
            bytes_written: 0,
        });
        (client, server_side)
    }

    #[test]
    fn send_fence_writes_spec_wire_format() {
        let (mut client, mut server) = fence_test_client();
        let flags = protocol::FENCE_FLAG_REQUEST | protocol::FENCE_FLAG_BLOCK_BEFORE;
        client.send_fence(flags, b"ping").unwrap();

        // ClientFence: type u8 (248), 3 bytes padding, flags u32, length u8,
        // payload[length].
        let mut buf = [0u8; 13];
        server.read_exact(&mut buf).unwrap();
        assert_eq!(
            buf,
            [
                248, 0, 0, 0, // message type + padding
                0x80, 0x00, 0x00, 0x01, // flags: Request | BlockBefore
                4,    // payload length (u8)
                b'p', b'i', b'n', b'g',
            ]
        );
    }

    #[test]
    fn send_fence_rejects_payload_over_255_bytes() {
        let (mut client, _server) = fence_test_client();
        let data = vec![0u8; 256];
        assert!(matches!(
            client.send_fence(protocol::FENCE_FLAG_REQUEST, &data),
            Err(VncError::Protocol(_))
        ));
        // 255 bytes is the maximum the u8 length field can express.
        let data = vec![0u8; 255];
        client
            .send_fence(protocol::FENCE_FLAG_REQUEST, &data)
            .unwrap();
    }

    #[test]
    fn server_fence_request_is_echoed_with_request_cleared() {
        let (mut client, mut server) = fence_test_client();
        // ServerFence: 3 bytes padding, flags u32, length u8, payload.
        server
            .write_all(&[
                0, 0, 0, // padding
                0x80, 0x00, 0x00, 0x03, // flags: Request | BlockBefore | BlockAfter
                3,    // payload length
                1, 2, 3, // payload
            ])
            .unwrap();

        let mut events = Vec::new();
        client.handle_server_fence(&mut events).unwrap();

        // The echo clears the Request bit and keeps the payload.
        let mut buf = [0u8; 12];
        server.read_exact(&mut buf).unwrap();
        assert_eq!(
            buf,
            [
                248, 0, 0, 0, // ClientFence + padding
                0x00, 0x00, 0x00, 0x03, // BlockBefore | BlockAfter, Request cleared
                3,    // payload length
                1, 2, 3,
            ]
        );

        assert_eq!(events.len(), 1);
        match events.remove(0) {
            VncEvent::Fence { flags, data } => {
                assert_eq!(flags, 0x8000_0003);
                assert_eq!(data, vec![1, 2, 3]);
            }
            _ => panic!("expected Fence event"),
        }
    }

    #[test]
    fn server_fence_without_request_is_not_echoed() {
        let (mut client, mut server) = fence_test_client();
        server
            .write_all(&[
                0, 0, 0, // padding
                0x00, 0x00, 0x00, 0x01, // flags: BlockBefore only, no Request
                2,    // payload length
                9, 9,
            ])
            .unwrap();

        let mut events = Vec::new();
        client.handle_server_fence(&mut events).unwrap();
        assert_eq!(events.len(), 1);

        // No response should have been written back to the server.
        server.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 1];
        assert!(matches!(
            server.read(&mut buf),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn handshake_failure_reason_over_limit_rejected() {
        let (mut client, mut server) = fence_test_client();
        // num_types == 0 followed by a huge reason length: the client must
        // reject before allocating or reading the reason bytes.
        server.write_all(&[0]).unwrap();
        server.write_all(&70_000u32.to_be_bytes()).unwrap();

        let mut auth = auth::NoAuthHandler;
        assert!(matches!(
            client.handshake_auth(&mut auth),
            Err(VncError::Protocol(_))
        ));
    }

    #[test]
    fn handshake_failure_reason_within_limit_returned() {
        let (mut client, mut server) = fence_test_client();
        server.write_all(&[0]).unwrap();
        server.write_all(&5u32.to_be_bytes()).unwrap();
        server.write_all(b"nope!").unwrap();

        let mut auth = auth::NoAuthHandler;
        match client.handshake_auth(&mut auth) {
            Err(VncError::AuthFailed(reason)) => assert_eq!(reason, "nope!"),
            other => panic!("expected AuthFailed, got {:?}", other.is_ok()),
        }
    }

    #[test]
    fn framebuffer_update_rejects_absurd_rect_dimensions() {
        let (mut client, mut server) = fence_test_client();
        // One Raw rectangle of 65535x1: exceeds the per-dimension cap and
        // must be rejected before any pixel data is read.
        server.write_all(&[0, 0, 1]).unwrap(); // padding + num_rects = 1
        server
            .write_all(&[
                0, 0, // x
                0, 0, // y
                0xff, 0xff, // width = 65535
                0, 1, // height = 1
                0, 0, 0, 0, // encoding = Raw
            ])
            .unwrap();

        let mut events = Vec::new();
        assert!(matches!(
            client.handle_framebuffer_update(&mut events),
            Err(VncError::Protocol(_))
        ));
    }

    #[test]
    fn qemu_audio_length_over_limit_rejected() {
        let (mut client, mut server) = fence_test_client();
        // QEMU extension, sub-type 2 (audio), operation 2 (audio data) with
        // a huge length.
        server.write_all(&[2, 2]).unwrap();
        server.write_all(&u32::MAX.to_be_bytes()).unwrap();

        let mut events = Vec::new();
        assert!(matches!(
            client.handle_qemu_extension(&mut events),
            Err(VncError::Protocol(_))
        ));
    }
}
