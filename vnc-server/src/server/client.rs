//! Per-client connection state machine.

use byteorder::WriteBytesExt;
use log::{debug, info, warn};
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::ops::{Deref, DerefMut};

use crate::auth::rsa_aes::{AesCtrStream, RsaAesServerAuth};
use crate::bandwidth::BandwidthEstimator;
use crate::damage::{ClientDamage, CopyRect, DamageRect};
use crate::encode::cursor::{encode_cursor, encode_cursor_pos, CursorShape};
use crate::encode::tight::TightEncoder;
use crate::encode::zlib::ZlibEncoder;
use crate::encode::zrle::ZrleEncoder;
use crate::protocol::*;
use crate::server::tls::{ServerTlsConfig, TlsStream};

/// Maximum read buffer size per client to prevent memory exhaustion.
const MAX_BUFFER_LEN: usize = 16 * 1024 * 1024;

/// Maximum number of unacknowledged fence pings kept per client. A client
/// that never echoes fences back must not grow `pending_fences` without
/// bound; once the cap is reached no new pings are sent until a response
/// arrives.
const MAX_PENDING_FENCES: usize = 32;

/// Maximum number of bytes queued for a single client before it is
/// disconnected as too slow. A 4K RGBA frame is ~33 MiB raw, so 64 MiB holds
/// at least two worst-case full frames (or many seconds of typical encoded
/// traffic); a client that falls further behind than that cannot keep up and
/// would otherwise grow server memory without bound.
pub const MAX_OUTBOUND_QUEUE: usize = 64 * 1024 * 1024;

/// Decide which security types the server advertises to a client. Pure
/// decision function, kept separate from IO so it can be unit-tested without
/// a socket pair.
///
/// `vencrypt_enabled` must already account for the availability of a TLS
/// config: VeNCrypt is only advertised when it can actually be served.
fn advertised_security_types(
    auth_enabled: bool,
    rsa_aes_enabled: bool,
    vencrypt_enabled: bool,
) -> Vec<SecurityType> {
    let mut types = Vec::new();
    if vencrypt_enabled {
        // VeNCrypt is the preferred path; the direct security types below
        // are fallbacks for clients that do not support VeNCrypt.
        types.push(SecurityType::VeNCrypt);
    }
    if auth_enabled {
        if rsa_aes_enabled {
            types.push(SecurityType::RsaAes256);
            types.push(SecurityType::RsaAes);
        }
        types.push(SecurityType::VncAuth);
    } else {
        types.push(SecurityType::None);
    }
    types
}

/// Decide which VeNCrypt sub-types the server advertises. Pure decision
/// function, kept separate from IO so it can be unit-tested without a socket
/// pair.
///
/// TLS and X509 are always available when VeNCrypt is offered because a TLS
/// config is required to advertise VeNCrypt in the first place.
fn advertised_vencrypt_sub_types(
    rsa_aes_enabled: bool,
    auth_enabled: bool,
    has_password: bool,
) -> Vec<VeNCryptSubType> {
    let mut sub_types = vec![VeNCryptSubType::Tls, VeNCryptSubType::X509];
    if rsa_aes_enabled && has_password {
        sub_types.push(VeNCryptSubType::RsaAes256);
        sub_types.push(VeNCryptSubType::RsaAes);
    }
    if auth_enabled && has_password {
        sub_types.push(VeNCryptSubType::VncAuth);
    } else {
        sub_types.push(VeNCryptSubType::Plain);
    }
    sub_types
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    WaitingForVersion,
    WaitingForSecurity,
    WaitingForVncAuth,
    WaitingForRsaAes,
    WaitingForInit,
    Ready,
    // VeNCrypt sub-states
    WaitingForVeNCryptVersion,
    WaitingForVeNCryptSubType,
}

/// A transport stream that can be plain TCP, AES-CTR encrypted (RSA-AES), or
/// TLS encrypted (VeNCrypt TLS/X509 sub-types).
pub enum VncStream {
    Plain(TcpStream),
    AesCtr(AesCtrStream),
    Tls(Box<TlsStream>),
}

impl Read for VncStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            VncStream::Plain(s) => s.read(buf),
            VncStream::AesCtr(s) => s.read(buf),
            VncStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for VncStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            VncStream::Plain(s) => s.write(buf),
            VncStream::AesCtr(s) => s.write(buf),
            VncStream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            VncStream::Plain(s) => s.flush(),
            VncStream::AesCtr(s) => s.flush(),
            VncStream::Tls(s) => s.flush(),
        }
    }
}

impl VncStream {
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            VncStream::Plain(s) => s.peer_addr(),
            VncStream::AesCtr(s) => s.peer_addr(),
            VncStream::Tls(s) => s.peer_addr(),
        }
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match self {
            VncStream::Plain(s) => s.set_nonblocking(nonblocking),
            VncStream::AesCtr(s) => {
                // AesCtrStream does not expose set_nonblocking directly;
                // the underlying TcpStream is set nonblocking by the listener.
                s.set_read_timeout(None).map(|_| ())
            }
            VncStream::Tls(s) => s.set_nonblocking(nonblocking),
        }
    }

    /// True when the stream layer itself holds no queued outbound data.
    fn write_idle(&self) -> bool {
        match self {
            // Plain TCP has no internal buffer; `VncClient::out_queue`
            // tracks everything not yet written to the socket.
            VncStream::Plain(_) => true,
            VncStream::AesCtr(s) => s.is_write_idle(),
            VncStream::Tls(s) => s.is_write_idle(),
        }
    }

    /// Bytes queued inside the stream layer waiting to reach the socket.
    fn queued_outbound(&self) -> usize {
        match self {
            VncStream::Plain(_) => 0,
            VncStream::AesCtr(s) => s.queued_bytes(),
            // rustls does not expose the size of its internal send queue.
            VncStream::Tls(_) => 0,
        }
    }
}

/// Wrapper that lets `VncClient` hold an optional stream while still allowing
/// `self.stream.write(...)` style calls via `Deref`/`DerefMut`.
pub struct StreamHolder(Option<VncStream>);

impl Read for StreamHolder {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stream not held"))?
            .read(buf)
    }
}

impl Write for StreamHolder {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stream not held"))?
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stream not held"))?
            .flush()
    }
}

impl Deref for StreamHolder {
    type Target = VncStream;

    fn deref(&self) -> &VncStream {
        self.0.as_ref().unwrap()
    }
}

impl DerefMut for StreamHolder {
    fn deref_mut(&mut self) -> &mut VncStream {
        self.0.as_mut().unwrap()
    }
}

/// A Fence message received from a client.
#[derive(Debug, Clone)]
pub struct FenceEvent {
    pub flags: u32,
    pub payload: Vec<u8>,
}

/// A Fence that was sent to a client and is awaiting a response.
#[derive(Debug, Clone)]
pub struct PingFence {
    pub sent_at: std::time::Instant,
    pub bytes_sent_at_send: u64,
}

pub struct VncClient {
    pub stream: StreamHolder,
    pub state: ClientState,
    pub pixel_format: PixelFormat,
    pub encodings: Vec<Encoding>,
    pub width: u16,
    pub height: u16,
    pub name: String,
    pub pending_requests: u32,
    pub continuous_updates: bool,
    pub cu_x: u16,
    pub cu_y: u16,
    pub cu_w: u16,
    pub cu_h: u16,
    pub damage: ClientDamage,
    /// Whether CopyRect moves may be sent to this client for the current
    /// frame. Set by [`VncClient::record_frame_damage`]: true only when the
    /// client's damage accumulator was empty at frame start, meaning its
    /// framebuffer is in sync with the server's previous frame and CopyRect
    /// source pixels are guaranteed valid on the client side.
    pub allow_copyrect: bool,
    pub key_events: Vec<(bool, u32)>,        // (down, keysym)
    pub keycode_events: Vec<(bool, u32)>,    // (down, linux keycode)
    pub pointer_events: Vec<(u8, u16, u16)>, // (button_mask, x, y)
    pub buffer: Vec<u8>,
    pub buffer_pos: usize,
    pub buffer_len: usize,
    pub auth_enabled: bool,
    pub password: Option<String>,
    pub challenge: Option<[u8; 16]>,
    /// Bytes sent to this client.
    pub bytes_sent: u64,
    /// Bytes received from this client.
    pub bytes_received: u64,
    /// Frames sent to this client.
    pub frames_sent: u64,
    /// Connection start time.
    pub connected_at: std::time::Instant,
    /// Previous pointer button mask (for detecting button changes per client).
    pub prev_button_mask: u8,
    /// Current cursor position inferred from this client's pointer events.
    pub cursor_pos: Option<(u16, u16)>,
    /// Last cursor position sent to the client via CursorPos pseudo-encoding.
    pub last_cursor_pos: Option<(u16, u16)>,
    /// Whether the default cursor shape has been sent to the client.
    pub cursor_shape_sent: bool,
    /// Whether the DesktopName pseudo-encoding has been sent to the client.
    pub desktop_name_sent: bool,
    pub tight_encoder: TightEncoder,
    pub zlib_encoder: ZlibEncoder,
    pub zrle_encoder: ZrleEncoder,
    pub openh264_encoder: Option<crate::encode::openh264::OpenH264Encoder>,
    pub bandwidth_estimator: BandwidthEstimator,
    /// Fences sent to the client that have not yet been echoed back.
    pub pending_fences: VecDeque<PingFence>,
    /// Whether the "client not responding to fences" warning has been logged.
    fence_cap_warned: bool,
    /// Fences received from the client since the last main loop iteration.
    pub fence_events: Vec<FenceEvent>,
    /// Bytes sent to this client since the last echoed Fence.
    pub bytes_inflight: u64,
    /// Total bytes sent at the time of the last echoed fence.
    bytes_at_last_response: u64,
    /// Whether RSA-AES security types should be advertised.
    pub rsa_aes_enabled: bool,
    /// Whether VeNCrypt security type should be advertised.
    pub vencrypt_enabled: bool,
    /// TLS configuration used when a client selects VeNCrypt TLS/X509 sub-types.
    pub tls_config: Option<ServerTlsConfig>,
    /// Whether the client advertised the ExtendedClipboard pseudo-encoding in
    /// SetEncodings. When set, negative-length ClientCutText payloads are
    /// parsed as extended clipboard messages.
    pub extended_clipboard: bool,
    /// Pending desktop size request from the client (width, height).
    pub desktop_size_request: Option<(u16, u16)>,
    /// RSA-AES authentication state, used while waiting for the encrypted key.
    pub rsa_aes_auth: Option<RsaAesServerAuth>,
    /// Plaintext protocol bytes queued for sending. Every server→client
    /// message is serialized here first; bytes leave the queue only through
    /// [`VncClient::flush_pending`], preserving message order across partial
    /// writes and `WouldBlock` on the non-blocking socket.
    pub out_queue: Vec<u8>,
    /// Offset into `out_queue` of the first byte not yet handed to the
    /// stream layer.
    pub out_pos: usize,
    /// Whether a framebuffer update has been queued but not yet fully
    /// flushed to the socket. The damage covered by the update is only
    /// cleared once the whole update (header + all rects) has been written
    /// and flushed; until then this client is skipped for new updates.
    pub update_in_flight: bool,
}

impl VncClient {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        stream: TcpStream,
        width: u16,
        height: u16,
        name: String,
        password: Option<String>,
        auth_enabled: bool,
        rsa_aes_enabled: bool,
        vencrypt_enabled: bool,
        tls_config: Option<ServerTlsConfig>,
    ) -> Self {
        Self {
            stream: StreamHolder(Some(VncStream::Plain(stream))),
            state: ClientState::WaitingForVersion,
            pixel_format: PixelFormat::bgra32(),
            encodings: vec![Encoding::Raw],
            width,
            height,
            name,
            pending_requests: 0,
            continuous_updates: false,
            cu_x: 0,
            cu_y: 0,
            cu_w: 0,
            cu_h: 0,
            damage: ClientDamage::new(width as u32, height as u32),
            allow_copyrect: false,
            key_events: Vec::new(),
            keycode_events: Vec::new(),
            pointer_events: Vec::new(),
            buffer: vec![0u8; 8192],
            buffer_pos: 0,
            buffer_len: 0,
            auth_enabled,
            password,
            challenge: None,
            bytes_sent: 0,
            bytes_received: 0,
            frames_sent: 0,
            connected_at: std::time::Instant::now(),
            prev_button_mask: 0,
            cursor_pos: None,
            last_cursor_pos: None,
            cursor_shape_sent: false,
            desktop_name_sent: false,
            tight_encoder: TightEncoder::new(),
            zlib_encoder: ZlibEncoder::new(),
            zrle_encoder: ZrleEncoder::new(),
            openh264_encoder: crate::encode::openh264::OpenH264Encoder::new(
                width as u32,
                height as u32,
            ),
            bandwidth_estimator: BandwidthEstimator::new(50_000),
            pending_fences: VecDeque::new(),
            fence_cap_warned: false,
            fence_events: Vec::new(),
            bytes_inflight: 0,
            bytes_at_last_response: 0,
            desktop_size_request: None,
            extended_clipboard: false,
            rsa_aes_auth: None,
            rsa_aes_enabled,
            vencrypt_enabled,
            tls_config,
            out_queue: Vec::new(),
            out_pos: 0,
            update_in_flight: false,
        }
    }

    /// Write the protocol version to the client.
    pub fn send_version(&mut self) -> io::Result<()> {
        self.out_queue.write_all(RFB_VERSION)?;
        self.flush_pending()?;
        Ok(())
    }

    /// Send the list of supported security types.
    pub fn send_security_types(&mut self) -> io::Result<()> {
        let types = advertised_security_types(
            self.auth_enabled,
            self.rsa_aes_enabled,
            self.vencrypt_enabled && self.tls_config.is_some(),
        );

        self.out_queue.write_u8(types.len() as u8)?;
        for security_type in &types {
            self.out_queue.write_u8(*security_type as u8)?;
        }
        self.flush_pending()?;
        self.state = ClientState::WaitingForSecurity;
        Ok(())
    }

    /// Send security handshake result.
    pub fn send_security_result(&mut self, result: SecurityResult) -> io::Result<()> {
        write_security_result(&mut self.out_queue, result, None);
        self.flush_pending()?;
        if result == SecurityResult::Ok {
            self.state = ClientState::WaitingForInit;
        }
        Ok(())
    }

    /// Send server init message.
    pub fn send_server_init(&mut self) -> io::Result<()> {
        let init = ServerInit {
            width: self.width,
            height: self.height,
            pixel_format: self.pixel_format,
            name: self.name.clone(),
        };
        init.write(&mut self.out_queue)?;
        self.flush_pending()?;
        self.state = ClientState::Ready;
        info!("Client ready: {}x{}", self.width, self.height);
        Ok(())
    }

    /// Send ServerCutText message to client.
    pub fn send_cut_text(&mut self, text: &str) -> io::Result<()> {
        let bytes = text.as_bytes();
        write_cut_text(
            &mut self.out_queue,
            ServerMsgType::ServerCutText as u8,
            bytes,
        );
        self.flush_pending()?;
        self.bytes_sent += 8 + bytes.len() as u64;
        Ok(())
    }

    /// Send SetColorMapEntries message to client.
    ///
    /// `colors` contains 8-bit RGB triples. Each component is scaled to 16-bit
    /// values as required by the RFB protocol.
    pub fn send_color_map_entries(
        &mut self,
        first_color: u16,
        colors: &[[u8; 3]],
    ) -> io::Result<()> {
        write_set_color_map_entries(&mut self.out_queue, first_color, colors);
        self.flush_pending()?;
        self.bytes_sent += 6 + colors.len() as u64 * 6;
        Ok(())
    }

    /// Send a Fence message to the client.
    ///
    /// The caller should flush the stream after all pending messages are queued.
    pub fn send_fence(&mut self, flags: u32, payload: &[u8]) -> io::Result<()> {
        debug_assert!(payload.len() <= 64, "Fence payload too long");
        Fence::write_message(&mut self.out_queue, flags, payload);
        self.bytes_sent += 9 + payload.len() as u64;
        Ok(())
    }

    /// Send a Fence ping and record it for RTT measurement.
    pub fn send_fence_ping(&mut self) -> io::Result<()> {
        // Bound the number of outstanding pings: a client that never echoes
        // fences back must not grow `pending_fences` without bound.
        if self.pending_fences.len() >= MAX_PENDING_FENCES {
            if !self.fence_cap_warned {
                warn!(
                    "Client not responding to fences; suspending fence pings ({} pending)",
                    self.pending_fences.len()
                );
                self.fence_cap_warned = true;
            }
            return Ok(());
        }
        // Request that the client echo the fence back as soon as possible.
        // The Request flag is bit 31; the client responds with it cleared.
        let flags = FENCE_FLAG_REQUEST;
        self.send_fence(flags, b"ping")?;
        self.pending_fences.push_back(PingFence {
            sent_at: std::time::Instant::now(),
            bytes_sent_at_send: self.bytes_sent,
        });
        Ok(())
    }

    /// Write a generic rectangle header followed by its pixel data.
    fn send_rect(&mut self, rect: &FbRect) -> io::Result<()> {
        rect.write_header(&mut self.out_queue)?;
        self.out_queue.write_all(&rect.data)?;
        self.bytes_sent += 12 + rect.data.len() as u64;
        Ok(())
    }

    /// Send the FramebufferUpdate message header with the number of rectangles.
    pub fn send_fb_update_header(&mut self, n_rects: u16) -> io::Result<()> {
        write_fb_update_header(&mut self.out_queue, n_rects);
        self.bytes_sent += 4;
        Ok(())
    }

    /// Send a CopyRect rectangle.
    pub fn send_copyrect_rect(&mut self, rect: &FbRect) -> io::Result<()> {
        self.send_rect(rect)
    }

    /// Send a Raw-encoded rectangle.
    pub fn send_raw_rect(&mut self, rect: &FbRect) -> io::Result<()> {
        self.send_rect(rect)
    }

    /// Send a Tight-encoded rectangle.
    pub fn send_tight_rect(&mut self, rect: &FbRect) -> io::Result<()> {
        self.send_rect(rect)
    }

    /// Send a ZRLE-encoded rectangle.
    pub fn send_zrle_rect(&mut self, rect: &FbRect) -> io::Result<()> {
        self.send_rect(rect)
    }

    /// Send a Zlib-encoded rectangle.
    pub fn send_zlib_rect(&mut self, rect: &FbRect) -> io::Result<()> {
        self.send_rect(rect)
    }

    /// Send a cursor shape using the Cursor pseudo-encoding.
    ///
    /// The shape is sent as a single rectangle in a FramebufferUpdate message.
    pub fn send_cursor_shape(&mut self, shape: &CursorShape) -> io::Result<()> {
        let rect = encode_cursor(shape, &self.pixel_format);
        self.send_fb_update_header(1)?;
        self.send_rect(&rect)?;
        self.flush_pending()?;
        self.cursor_shape_sent = true;
        Ok(())
    }

    /// Send a cursor position update using the CursorPos pseudo-encoding.
    ///
    /// The position is encoded in the rectangle header (x, y, width=0, height=0)
    /// and no pixel data follows.
    pub fn send_cursor_pos(&mut self, x: u16, y: u16) -> io::Result<()> {
        let rect = encode_cursor_pos(x, y);
        self.send_fb_update_header(1)?;
        self.send_rect(&rect)?;
        self.flush_pending()?;
        self.last_cursor_pos = Some((x, y));
        Ok(())
    }

    /// Send a Hextile-encoded rectangle.
    pub fn send_hextile_rect(&mut self, rect: &FbRect) -> io::Result<()> {
        self.send_rect(rect)
    }

    /// Send a TRLE-encoded rectangle.
    pub fn send_trle_rect(&mut self, rect: &FbRect) -> io::Result<()> {
        self.send_rect(rect)
    }

    /// Send an RRE-encoded rectangle.
    pub fn send_rre_rect(&mut self, rect: &FbRect) -> io::Result<()> {
        self.send_rect(rect)
    }

    /// Send an OpenH264-encoded rectangle.
    pub fn send_openh264_rect(&mut self, rect: &FbRect) -> io::Result<()> {
        self.send_rect(rect)
    }

    /// Hand queued plaintext to the stream layer and flush it towards the
    /// socket.
    ///
    /// `WouldBlock` is not an error: unwritten bytes stay queued (here for a
    /// plain socket, inside the stream layer for AES-CTR/TLS) and the next
    /// call resumes exactly where this one stopped, so no byte is lost,
    /// duplicated, or reordered. Only hard I/O errors are returned.
    pub fn flush_pending(&mut self) -> io::Result<()> {
        while self.out_pos < self.out_queue.len() {
            match self.stream.write(&self.out_queue[self.out_pos..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write to client socket",
                    ));
                }
                Ok(n) => self.out_pos += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        if self.out_pos == self.out_queue.len() {
            self.out_queue.clear();
            self.out_pos = 0;
        }
        match self.stream.flush() {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Flush the outbound stream (alias for [`VncClient::flush_pending`]).
    pub fn flush(&mut self) -> io::Result<()> {
        self.flush_pending()
    }

    /// True when every queued byte has been written to the socket, i.e. the
    /// client is fully caught up.
    pub fn outbound_idle(&self) -> bool {
        self.out_queue.is_empty() && self.stream.write_idle()
    }

    /// Total bytes waiting to be written to the socket, both in the
    /// client-level queue and inside the stream layer.
    pub fn outbound_queued(&self) -> usize {
        (self.out_queue.len() - self.out_pos) + self.stream.queued_outbound()
    }

    /// If a queued framebuffer update has now been fully flushed to the
    /// socket, clear the damage it covered and count the frame. Returns true
    /// when an in-flight update completed with this call.
    pub fn complete_update_if_flushed(&mut self) -> bool {
        if self.update_in_flight && self.outbound_idle() {
            self.update_in_flight = false;
            self.damage.clear();
            self.frame_sent();
            true
        } else {
            false
        }
    }

    /// Refuse a stream upgrade while plaintext is still queued: bytes queued
    /// before the upgrade must go out on the old (plaintext) channel, and
    /// writing them through the upgraded stream would corrupt the protocol
    /// stream. Callers treat this error like any other client failure and
    /// drop the connection.
    fn ensure_outbound_drained_for_upgrade(&mut self) -> io::Result<()> {
        self.flush_pending()?;
        if !self.out_queue.is_empty() || !self.stream.write_idle() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "cannot upgrade stream with outbound data still queued",
            ));
        }
        Ok(())
    }

    /// Record that a frame has been fully sent and decrement pending requests.
    pub fn frame_sent(&mut self) {
        self.frames_sent += 1;
        if self.pending_requests > 0 {
            self.pending_requests -= 1;
        }
    }

    /// Process any received fence responses, updating bandwidth estimates and
    /// resetting the inflight byte counter.
    pub fn process_fence_events(&mut self) {
        for _event in self.fence_events.drain(..) {
            if let Some(ping) = self.pending_fences.pop_front() {
                self.fence_cap_warned = false;
                let rtt_us = ping.sent_at.elapsed().as_micros() as u64;
                let bytes_window = ping
                    .bytes_sent_at_send
                    .saturating_sub(self.bytes_at_last_response);
                self.bytes_at_last_response = ping.bytes_sent_at_send;
                self.bytes_inflight = self.bytes_sent.saturating_sub(self.bytes_at_last_response);
                self.bandwidth_estimator.record_sample(bytes_window, rtt_us);
                debug!(
                    "Fence RTT: {} us, window: {} bytes, bandwidth: {:.0} bps",
                    rtt_us,
                    bytes_window,
                    self.bandwidth_estimator.bandwidth_bps()
                );
            } else {
                self.bytes_inflight = 0;
                self.bytes_at_last_response = self.bytes_sent;
                debug!("Received unexpected fence response");
            }
        }
    }

    /// Recompute the number of bytes sent since the last echoed fence.
    pub fn recompute_inflight(&mut self) {
        self.bytes_inflight = self.bytes_sent.saturating_sub(self.bytes_at_last_response);
    }

    fn handle_fence(&mut self, avail: usize) -> io::Result<usize> {
        let Some((fence, msg_size)) =
            Fence::parse(&self.buffer[self.buffer_pos..self.buffer_pos + avail])
        else {
            return Ok(0);
        };
        let payload_len = fence.payload.len();
        self.fence_events.push(FenceEvent {
            flags: fence.flags,
            payload: fence.payload,
        });
        debug!(
            "Received fence response: flags={:08x}, len={}",
            fence.flags, payload_len
        );
        Ok(msg_size)
    }

    /// Read and process incoming messages. Returns number of bytes consumed or 0 if more needed.
    pub fn process_messages(&mut self) -> io::Result<bool> {
        // Fill buffer
        let buf = &mut self.buffer[self.buffer_len..];
        if buf.is_empty() {
            // Buffer full, expand
            if self.buffer.len() >= MAX_BUFFER_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "client read buffer exceeded limit",
                ));
            }
            self.buffer
                .resize(self.buffer.len().saturating_mul(2).min(MAX_BUFFER_LEN), 0);
        }
        match self.stream.read(&mut self.buffer[self.buffer_len..]) {
            Ok(0) => return Ok(false), // disconnected
            Ok(n) => {
                self.buffer_len += n;
                self.bytes_received += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(true),
            Err(e) => return Err(e),
        }

        let mut _consumed = 0usize;
        loop {
            if self.buffer_pos >= self.buffer_len {
                break;
            }
            let available = self.buffer_len - self.buffer_pos;
            let rc = match self.state {
                ClientState::WaitingForVersion => self.handle_version(available),
                ClientState::WaitingForSecurity => self.handle_security(available),
                ClientState::WaitingForVncAuth => self.handle_vnc_auth(available),
                ClientState::WaitingForRsaAes => self.handle_rsa_aes(available),
                ClientState::WaitingForInit => self.handle_init(available),
                ClientState::WaitingForVeNCryptVersion => self.handle_vencrypt_version(available),
                ClientState::WaitingForVeNCryptSubType => self.handle_vencrypt_sub_type(available),
                ClientState::Ready => self.handle_client_message(available),
            };
            match rc {
                Ok(0) => break, // need more data
                Ok(n) => {
                    self.buffer_pos += n;
                    _consumed += n;
                }
                Err(e) => {
                    warn!("Client message error: {}", e);
                    return Ok(false);
                }
            }
        }

        // Compact buffer
        if self.buffer_pos > 0 {
            self.buffer.copy_within(self.buffer_pos..self.buffer_len, 0);
            self.buffer_len -= self.buffer_pos;
            self.buffer_pos = 0;
        }

        Ok(true)
    }

    fn handle_version(&mut self, avail: usize) -> io::Result<usize> {
        let Some(result) =
            handshake::parse_rfb_version(&self.buffer[self.buffer_pos..self.buffer_pos + avail])
        else {
            return Ok(0);
        };
        // Malformed banners (e.g. port scanners, HTTP probes) are rejected
        // instead of driving the handshake with a protocol that is not RFB.
        let (major, minor) = result?;
        debug!("Client version: RFB {:03}.{:03}", major, minor);

        // Only RFB 3.8 is supported: 3.3 uses a different security-type
        // handshake (the server picks the type instead of offering a list),
        // and other versions were never tested against this server.
        if (major, minor) != (3, 8) {
            warn!(
                "Rejecting client with unsupported RFB version {}.{}",
                major, minor
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported RFB version {}.{}", major, minor),
            ));
        }

        self.send_security_types()?;
        Ok(12)
    }

    fn handle_security(&mut self, avail: usize) -> io::Result<usize> {
        if avail < 1 {
            return Ok(0);
        }
        let sec_type = self.buffer[self.buffer_pos];
        debug!("Client chose security type: {}", sec_type);

        match SecurityType::from_u8(sec_type) {
            Some(SecurityType::None) => {
                if self.auth_enabled {
                    self.send_security_failed("Authentication required")?;
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "auth required",
                    ));
                }
                self.send_security_result(SecurityResult::Ok)?;
            }
            Some(SecurityType::VncAuth) => {
                if self.password.is_none() {
                    self.send_security_failed("No password configured")?;
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "no password",
                    ));
                }
                let challenge = crate::auth::generate_challenge();
                self.out_queue.write_all(&challenge)?;
                self.flush_pending()?;
                self.challenge = Some(challenge);
                self.state = ClientState::WaitingForVncAuth;
                debug!("Sent VNC Auth challenge");
            }
            Some(SecurityType::RsaAes) | Some(SecurityType::RsaAes256) => {
                if !self.rsa_aes_enabled {
                    self.send_security_failed("RSA-AES not enabled")?;
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "rsa-aes not enabled",
                    ));
                }
                let auth = match SecurityType::from_u8(sec_type) {
                    Some(SecurityType::RsaAes) => RsaAesServerAuth::new_128(),
                    Some(SecurityType::RsaAes256) => RsaAesServerAuth::new_256(),
                    _ => unreachable!(),
                }
                .map_err(|e| io::Error::other(format!("failed to create RSA-AES auth: {}", e)))?;
                // Send the public key; the encrypted AES key will arrive next.
                auth.send_public_key(&mut self.out_queue)?;
                self.flush_pending()?;
                self.rsa_aes_auth = Some(auth);
                self.state = ClientState::WaitingForRsaAes;
                debug!("Sent RSA-AES public key");
            }
            Some(SecurityType::VeNCrypt) => {
                if !self.vencrypt_enabled || self.tls_config.is_none() {
                    self.send_security_failed("VeNCrypt not enabled")?;
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "vencrypt not enabled",
                    ));
                }
                // Send VeNCrypt version 0.2 and wait for the client reply.
                vencrypt::write_version(&mut self.out_queue);
                self.flush_pending()?;
                self.state = ClientState::WaitingForVeNCryptVersion;
                debug!("Sent VeNCrypt version");
            }
            _ => {
                self.send_security_failed("Unsupported security type")?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bad security type",
                ));
            }
        }
        Ok(1)
    }

    fn handle_vencrypt_version(&mut self, avail: usize) -> io::Result<usize> {
        let Some((major, minor)) =
            vencrypt::parse_version_reply(&self.buffer[self.buffer_pos..self.buffer_pos + avail])
        else {
            return Ok(0);
        };
        debug!("Client VeNCrypt version reply: {}.{}", major, minor);
        if !vencrypt::version_supported(major, minor) {
            self.send_security_failed("Unsupported VeNCrypt version")?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported VeNCrypt version {}.{}", major, minor),
            ));
        }
        self.send_vencrypt_sub_types()?;
        Ok(2)
    }

    fn send_vencrypt_sub_types(&mut self) -> io::Result<()> {
        let sub_types = advertised_vencrypt_sub_types(
            self.rsa_aes_enabled,
            self.auth_enabled,
            self.password.is_some(),
        );
        let raw: Vec<u32> = sub_types.iter().map(|sub_type| *sub_type as u32).collect();
        vencrypt::write_sub_types(&mut self.out_queue, &raw);
        self.flush_pending()?;
        self.state = ClientState::WaitingForVeNCryptSubType;
        debug!("Sent VeNCrypt sub-types: {:?}", sub_types);
        Ok(())
    }

    fn handle_vencrypt_sub_type(&mut self, avail: usize) -> io::Result<usize> {
        let Some(subtype) =
            vencrypt::parse_sub_type(&self.buffer[self.buffer_pos..self.buffer_pos + avail])
        else {
            return Ok(0);
        };
        debug!("Client chose VeNCrypt sub-type: {}", subtype);

        match VeNCryptSubType::from_u32(subtype) {
            Some(VeNCryptSubType::Plain) => {
                if self.auth_enabled {
                    self.send_security_failed("Authentication required")?;
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "auth required",
                    ));
                }
                self.send_security_result(SecurityResult::Ok)?;
            }
            Some(VeNCryptSubType::VncAuth) => {
                if self.password.is_none() {
                    self.send_security_failed("No password configured")?;
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "no password",
                    ));
                }
                let challenge = crate::auth::generate_challenge();
                self.out_queue.write_all(&challenge)?;
                self.flush_pending()?;
                self.challenge = Some(challenge);
                self.state = ClientState::WaitingForVncAuth;
                debug!("Sent VeNCrypt VNC Auth challenge");
            }
            Some(VeNCryptSubType::Tls) | Some(VeNCryptSubType::X509) => {
                let tls_config = self.tls_config.take().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "missing TLS config")
                })?;
                // Bytes queued before the upgrade must go out as plaintext;
                // refuse the upgrade if they could not be flushed.
                self.ensure_outbound_drained_for_upgrade()?;
                let tcp = self.take_plain_tcp()?;
                // Any bytes that arrived after the sub-type selection are TLS
                // records and must be fed to the TLS connection, then dropped
                // from the buffer so each byte is processed exactly once.
                let buffered = &self.buffer[self.buffer_pos + 4..self.buffer_len];
                let buffered_len = buffered.len();
                let (tls, consumed) = tls_config.accept(tcp, buffered)?;
                self.stream.0 = Some(VncStream::Tls(Box::new(tls)));
                if consumed != buffered_len {
                    // rustls stopped before the end of the buffered input.
                    // The unread tail is TLS ciphertext that can no longer be
                    // parsed by the plaintext state machine nor fed back
                    // through the TLS stream; the connection cannot continue.
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "TLS upgrade could not consume all buffered records",
                    ));
                }
                self.send_security_result(SecurityResult::Ok)?;
                debug!("Upgraded to TLS for VeNCrypt sub-type {}", subtype);
                return Ok(4 + consumed);
            }
            Some(VeNCryptSubType::RsaAes) | Some(VeNCryptSubType::RsaAes256) => {
                if !self.rsa_aes_enabled || self.password.is_none() {
                    self.send_security_failed("RSA-AES not enabled")?;
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "rsa-aes not enabled",
                    ));
                }
                let auth = match VeNCryptSubType::from_u32(subtype) {
                    Some(VeNCryptSubType::RsaAes) => RsaAesServerAuth::new_128(),
                    Some(VeNCryptSubType::RsaAes256) => RsaAesServerAuth::new_256(),
                    _ => unreachable!(),
                }
                .map_err(|e| io::Error::other(format!("failed to create RSA-AES auth: {}", e)))?;
                auth.send_public_key(&mut self.out_queue)?;
                self.flush_pending()?;
                self.rsa_aes_auth = Some(auth);
                self.state = ClientState::WaitingForRsaAes;
                debug!("Sent VeNCrypt RSA-AES public key");
            }
            _ => {
                self.send_security_failed("Unsupported VeNCrypt sub-type")?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported VeNCrypt sub-type {}", subtype),
                ));
            }
        }
        Ok(4)
    }

    fn take_plain_tcp(&mut self) -> io::Result<TcpStream> {
        let taken = self.stream.0.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "stream already consumed")
        })?;
        match taken {
            VncStream::Plain(tcp) => Ok(tcp),
            other => {
                self.stream.0 = Some(other);
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "expected plain TCP stream",
                ))
            }
        }
    }

    fn handle_vnc_auth(&mut self, avail: usize) -> io::Result<usize> {
        if avail < 16 {
            return Ok(0);
        }
        let mut response = [0u8; 16];
        response.copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + 16]);

        if let (Some(ref challenge), Some(ref password)) = (&self.challenge, &self.password) {
            if crate::auth::verify_response(challenge, &response, password) {
                info!("VNC Auth successful");
                self.send_security_result(SecurityResult::Ok)?;
            } else {
                warn!("VNC Auth failed: incorrect password");
                self.send_security_failed("Authentication failed")?;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "auth failed",
                ));
            }
        } else {
            self.send_security_failed("Internal error")?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing challenge",
            ));
        }

        self.challenge = None;
        Ok(16)
    }

    fn handle_rsa_aes(&mut self, avail: usize) -> io::Result<usize> {
        let msg_size = {
            let frame = &self.buffer[self.buffer_pos..self.buffer_pos + avail];
            let Some(parsed) = rsa_aes::parse_encrypted_key_frame(frame) else {
                return Ok(0);
            };
            match parsed {
                Ok(ciphertext) => 4 + ciphertext.len(),
                Err(_) => {
                    self.send_security_failed("Encrypted AES key too large")?;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "encrypted AES key too large",
                    ));
                }
            }
        };

        let auth = self
            .rsa_aes_auth
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing RSA-AES auth"))?;

        // The length prefix was already consumed from the buffer above, so
        // decrypt the raw ciphertext directly; the length must be read
        // exactly once.
        let encrypted_key = &self.buffer[self.buffer_pos + 4..self.buffer_pos + msg_size];
        let aes_key = match auth.decrypt_encrypted_key(encrypted_key) {
            Ok(key) => key,
            Err(e) => {
                self.send_security_failed("RSA-AES key exchange failed")?;
                return Err(e);
            }
        };

        // Upgrade the stream to AES-CTR before sending the security result,
        // because the result is the first encrypted message.
        if let Err(e) = self.upgrade_to_aes_ctr(&aes_key) {
            self.send_security_failed("Failed to initialize AES-CTR")?;
            return Err(e);
        }

        // Bytes that were already read from the socket beyond the encrypted
        // key (e.g. a ClientInit pipelined in the same TCP segment) are
        // AES-CTR ciphertext, not plaintext. Decrypt them in place so the
        // message parser below processes each byte exactly once.
        let leftover = self.buffer_pos + msg_size;
        if leftover < self.buffer_len {
            if let VncStream::AesCtr(ref mut aes) = *self.stream {
                aes.decrypt_buffered(&mut self.buffer[leftover..self.buffer_len]);
            }
        }

        info!("RSA-AES handshake successful");
        self.send_security_result(SecurityResult::Ok)?;
        Ok(msg_size)
    }

    fn handle_init(&mut self, avail: usize) -> io::Result<usize> {
        if avail < 1 {
            return Ok(0);
        }
        let shared = self.buffer[self.buffer_pos];
        debug!("Client init: shared={}", shared);
        self.send_server_init()?;
        Ok(1)
    }

    fn handle_client_message(&mut self, avail: usize) -> io::Result<usize> {
        if avail < 1 {
            return Ok(0);
        }
        let msg_type = self.buffer[self.buffer_pos];
        match msg_type {
            CLIENT_SET_PIXEL_FORMAT => self.handle_set_pixel_format(avail),
            CLIENT_SET_ENCODINGS => self.handle_set_encodings(avail),
            CLIENT_FRAMEBUFFER_UPDATE_REQUEST => self.handle_fb_update_request(avail),
            CLIENT_KEY_EVENT => self.handle_key_event(avail),
            CLIENT_POINTER_EVENT => self.handle_pointer_event(avail),
            CLIENT_CUT_TEXT => self.handle_cut_text(avail),
            CLIENT_ENABLE_CONTINUOUS_UPDATES => self.handle_enable_continuous_updates(avail),
            CLIENT_FENCE => self.handle_fence(avail),
            CLIENT_SET_DESKTOP_SIZE => self.handle_set_desktop_size(avail),
            CLIENT_QEMU => self.handle_qemu_message(avail),
            _ => {
                warn!("Unknown client message type: {}", msg_type);
                Ok(1) // skip unknown byte
            }
        }
    }

    fn handle_set_pixel_format(&mut self, avail: usize) -> io::Result<usize> {
        let Some(pixel_format) =
            parse_set_pixel_format(&self.buffer[self.buffer_pos..self.buffer_pos + avail])
        else {
            return Ok(0);
        };
        self.pixel_format = pixel_format?;
        debug!("Set pixel format: {:?}", self.pixel_format);
        Ok(SET_PIXEL_FORMAT_WIRE_LEN)
    }

    fn handle_set_encodings(&mut self, avail: usize) -> io::Result<usize> {
        let Some((raw_encodings, msg_size)) =
            parse_set_encodings(&self.buffer[self.buffer_pos..self.buffer_pos + avail])
        else {
            return Ok(0);
        };
        self.encodings.clear();
        self.extended_clipboard = false;
        for enc in raw_encodings {
            match from_i32(enc) {
                Encoding::AppleHp(_) => debug!("Ignoring unknown encoding: {}", enc),
                e => {
                    if e == Encoding::ExtendedClipboard {
                        // from_i32 maps both extended-clipboard wire values
                        // (-1063131698 and the QEMU -1063131699) here.
                        self.extended_clipboard = true;
                    }
                    self.encodings.push(e);
                }
            }
        }
        debug!("Client encodings: {:?}", self.encodings);
        Ok(msg_size)
    }

    fn handle_fb_update_request(&mut self, avail: usize) -> io::Result<usize> {
        let Some(req) =
            FramebufferUpdateRequest::parse(&self.buffer[self.buffer_pos..self.buffer_pos + avail])
        else {
            return Ok(0);
        };
        debug!(
            "Framebuffer update request: {}x{}+{}+{}",
            req.width, req.height, req.x, req.y
        );
        self.pending_requests += 1;
        if !req.incremental {
            // Non-incremental request: the client wants the full current
            // content of the requested region, regardless of what changed.
            self.damage.add_rect(req.x, req.y, req.width, req.height);
        }
        Ok(FramebufferUpdateRequest::WIRE_LEN)
    }

    fn handle_key_event(&mut self, avail: usize) -> io::Result<usize> {
        let Some(event) = KeyEvent::parse(&self.buffer[self.buffer_pos..self.buffer_pos + avail])
        else {
            return Ok(0);
        };
        self.key_events.push((event.down, event.keysym));
        Ok(KeyEvent::WIRE_LEN)
    }

    fn handle_pointer_event(&mut self, avail: usize) -> io::Result<usize> {
        let Some(event) =
            PointerEvent::parse(&self.buffer[self.buffer_pos..self.buffer_pos + avail])
        else {
            return Ok(0);
        };
        self.pointer_events
            .push((event.button_mask, event.x, event.y));
        self.cursor_pos = Some((event.x, event.y));
        Ok(PointerEvent::WIRE_LEN)
    }

    fn handle_cut_text(&mut self, avail: usize) -> io::Result<usize> {
        let Some(len) =
            parse_cut_text_header(&self.buffer[self.buffer_pos..self.buffer_pos + avail])
        else {
            return Ok(0);
        };
        if len < 0 {
            // Extended Clipboard: abs(length) bytes of extended data follow the
            // header.
            let ext_len = len.unsigned_abs() as usize;
            let msg_size = CUT_TEXT_HEADER_LEN + ext_len;
            if avail < msg_size {
                return Ok(0);
            }
            if !self.extended_clipboard {
                // The client never advertised the ExtendedClipboard
                // pseudo-encoding; skip the payload so the connection does not
                // stall waiting for the ~4 GiB that a sign-truncated length
                // would imply.
                debug!(
                    "Skipping extended clipboard message from a client that did not advertise it: {} bytes",
                    ext_len
                );
                return Ok(msg_size);
            }
            let payload =
                &self.buffer[self.buffer_pos + CUT_TEXT_HEADER_LEN..self.buffer_pos + msg_size];
            match crate::protocol::clipboard::decode_message(payload) {
                Ok(crate::protocol::clipboard::ClipboardMessage::Provide { data }) => {
                    // Extract plain text entries and feed them into the
                    // client -> Wayland clipboard sync path.
                    for (format, entry) in &data {
                        if *format == crate::protocol::clipboard::ClipboardFormat::Text {
                            let text = String::from_utf8_lossy(entry).to_string();
                            debug!("Extended clipboard provide: {} bytes of text", text.len());
                            crate::clipboard::set_clipboard_text(&text);
                        }
                    }
                }
                Ok(other) => {
                    // Caps/Request/Peek/Notify carry no data; nothing to sync.
                    debug!("Extended clipboard message: {:?}", other);
                }
                Err(e) => {
                    // Malformed payload: log and skip it without disturbing
                    // the connection.
                    warn!("Failed to parse extended clipboard message: {}", e);
                }
            }
            return Ok(msg_size);
        }
        let len = len as usize;
        let msg_size = CUT_TEXT_HEADER_LEN + len;
        if avail < msg_size {
            return Ok(0);
        }
        let text = String::from_utf8_lossy(
            &self.buffer[self.buffer_pos + CUT_TEXT_HEADER_LEN..self.buffer_pos + msg_size],
        )
        .to_string();
        // Placeholder: clipboard input from VNC client would be handled here.
        debug!("Received client cut text: {} bytes", text.len());
        Ok(msg_size)
    }

    fn handle_enable_continuous_updates(&mut self, avail: usize) -> io::Result<usize> {
        let Some(msg) =
            EnableContinuousUpdates::parse(&self.buffer[self.buffer_pos..self.buffer_pos + avail])
        else {
            return Ok(0);
        };
        self.continuous_updates = msg.enable;
        self.cu_x = msg.x;
        self.cu_y = msg.y;
        self.cu_w = msg.width;
        self.cu_h = msg.height;
        if msg.enable {
            // Deliver the current content of the continuous-updates region
            // once, so the client starts from a correct state.
            self.damage.add_rect(msg.x, msg.y, msg.width, msg.height);
        }
        debug!(
            "Continuous updates: {} {}x{}+{}+{}",
            msg.enable, msg.width, msg.height, msg.x, msg.y
        );
        Ok(EnableContinuousUpdates::WIRE_LEN)
    }

    fn handle_qemu_message(&mut self, avail: usize) -> io::Result<usize> {
        if avail < 2 {
            return Ok(0);
        }
        let subtype = self.buffer[self.buffer_pos + 1];
        match subtype {
            qemu::SUB_TYPE_EXTENDED_KEY_EVENT => {
                // QEMU extended key event
                let Some(event) = QemuExtendedKeyEvent::parse(
                    &self.buffer[self.buffer_pos..self.buffer_pos + avail],
                ) else {
                    return Ok(0);
                };
                self.key_events.push((event.down, event.keysym));
                self.keycode_events.push((event.down, event.keycode));
                debug!(
                    "QEMU extended key event: down={} keysym={} keycode={}",
                    event.down, event.keysym, event.keycode
                );
                Ok(QemuExtendedKeyEvent::WIRE_LEN)
            }
            _ => {
                // Unknown QEMU sub-type: skip the header.
                warn!("Unknown QEMU message sub-type: {}", subtype);
                Ok(2)
            }
        }
    }

    fn handle_set_desktop_size(&mut self, avail: usize) -> io::Result<usize> {
        // SetDesktopSize: type(1), padding(1), width(2), height(2),
        // number-of-screens(1), padding(3), then 16 bytes per screen.
        let Some((msg, msg_size)) =
            SetDesktopSize::parse(&self.buffer[self.buffer_pos..self.buffer_pos + avail])
        else {
            return Ok(0);
        };
        debug!(
            "SetDesktopSize request: {}x{} ({} screens)",
            msg.width,
            msg.height,
            msg.screens.len()
        );
        self.desktop_size_request = Some((msg.width, msg.height));
        Ok(msg_size)
    }

    /// Check whether the client has advertised a specific encoding.
    pub fn has_encoding(&self, encoding: Encoding) -> bool {
        self.encodings.contains(&encoding)
    }

    /// Update client dimensions and reset damage to a full-screen update.
    pub fn set_dimensions(&mut self, width: u16, height: u16) {
        self.width = width;
        self.height = height;
        self.damage = ClientDamage::new(width as u32, height as u32);
        self.allow_copyrect = false;
    }

    /// Record a newly computed frame diff in this client's damage accumulator.
    ///
    /// This must be called for every ready client whenever the global damage
    /// tracker produces a diff between two captures — including clients with
    /// no pending update request, so that missed changes are delivered with
    /// the client's next update instead of being lost.
    ///
    /// `allow_copyrect` is updated as a side effect: CopyRect moves reference
    /// pixels in the client's existing framebuffer, which only match the
    /// server's previous frame when the accumulator was empty before this
    /// frame's changes were added (i.e. the client is fully up-to-date).
    pub fn record_frame_damage(&mut self, damage: &[DamageRect], copy_rects: &[CopyRect]) {
        self.allow_copyrect = self.damage.is_empty();
        self.damage.add_damage_rects(damage);
        self.damage.add_copyrect_dsts(copy_rects);
    }

    /// Take the pending desktop size request, if any.
    pub fn take_desktop_size_request(&mut self) -> Option<(u16, u16)> {
        self.desktop_size_request.take()
    }

    /// Send security handshake failure with a reason string.
    pub fn send_security_failed(&mut self, reason: &str) -> io::Result<()> {
        write_security_result(&mut self.out_queue, SecurityResult::Failed, Some(reason));
        self.flush_pending()?;
        Ok(())
    }

    /// Upgrade the plain TCP stream to an AES-CTR encrypted stream.
    pub fn upgrade_to_aes_ctr(&mut self, key: &[u8]) -> io::Result<()> {
        // Bytes queued before the upgrade must go out as plaintext; refuse
        // the upgrade if they could not be flushed.
        self.ensure_outbound_drained_for_upgrade()?;
        let taken = self.stream.0.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "stream already consumed")
        })?;
        match taken {
            VncStream::Plain(tcp) => {
                let aes = AesCtrStream::new(tcp, key)?;
                self.stream.0 = Some(VncStream::AesCtr(aes));
                Ok(())
            }
            VncStream::AesCtr(aes) => {
                self.stream.0 = Some(VncStream::AesCtr(aes));
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "stream is already encrypted",
                ))
            }
            VncStream::Tls(tls) => {
                self.stream.0 = Some(VncStream::Tls(tls));
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "RSA-AES over TLS is not supported",
                ))
            }
        }
    }

    /// Return the peer address of this client, if available.
    pub fn peer_address(&self) -> String {
        self.stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }

    /// Send a DesktopSize pseudo-rectangle to notify the client of a resize.
    pub fn send_desktop_size(&mut self, width: u16, height: u16) -> io::Result<()> {
        write_fb_update_header(&mut self.out_queue, 1);
        RectHeader {
            x: 0,
            y: 0,
            width,
            height,
            encoding: Encoding::DesktopSize.as_i32(),
        }
        .write_to(&mut self.out_queue);
        self.flush_pending()?;
        self.bytes_sent += 12;
        Ok(())
    }

    /// Send an ExtendedDesktopSize pseudo-rectangle to notify the client of a resize.
    pub fn send_extended_desktop_size(&mut self, width: u16, height: u16) -> io::Result<()> {
        write_fb_update_header(&mut self.out_queue, 1);
        RectHeader {
            x: 0,
            y: 0,
            width,
            height,
            encoding: Encoding::ExtendedDesktopSize.as_i32(),
        }
        .write_to(&mut self.out_queue);
        // One screen covering the whole desktop.
        write_screen_list(
            &mut self.out_queue,
            &[Screen {
                id: 0,
                x: 0,
                y: 0,
                width,
                height,
                flags: 0,
            }],
        );
        self.flush_pending()?;
        self.bytes_sent += 12 + 4 + 2 + 2 + 2 + 2 + 4;
        Ok(())
    }

    /// Send a DesktopName pseudo-rectangle to notify the client of a desktop name change.
    pub fn send_desktop_name(&mut self, name: &str) -> io::Result<()> {
        write_fb_update_header(&mut self.out_queue, 1);
        RectHeader {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
            encoding: Encoding::DesktopName.as_i32(),
        }
        .write_to(&mut self.out_queue);
        write_desktop_name_body(&mut self.out_queue, name);
        self.flush_pending()?;
        self.bytes_sent += 12 + 4 + name.len() as u64;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let server = listener.accept().unwrap().0;
        (server, client)
    }

    #[test]
    fn security_types_includes_vencrypt_when_enabled() {
        let (server, mut client) = connected_pair();
        let mut vnc = VncClient::new(
            server,
            1920,
            1080,
            "test".into(),
            Some("password".into()),
            true,
            true,
            true,
            ServerTlsConfig::self_signed().ok(),
        );
        vnc.send_security_types().unwrap();

        let mut buf = [0u8; 16];
        let n = client.read(&mut buf).unwrap();
        let _count = buf[0] as usize;
        let types = &buf[1..n];
        assert!(types.contains(&SECURITY_VENCRYPT));
        assert!(types.contains(&SECURITY_RSA_AES256));
        assert!(types.contains(&SECURITY_VNC_AUTH));
        assert_eq!(vnc.state, ClientState::WaitingForSecurity);
    }

    #[test]
    fn security_types_no_vencrypt_when_disabled() {
        let (server, mut client) = connected_pair();
        let mut vnc = VncClient::new(
            server,
            1920,
            1080,
            "test".into(),
            Some("password".into()),
            true,
            true,
            false,
            None,
        );
        vnc.send_security_types().unwrap();

        let mut buf = [0u8; 16];
        let n = client.read(&mut buf).unwrap();
        let _count = buf[0] as usize;
        let types = &buf[1..n];
        assert!(!types.contains(&SECURITY_VENCRYPT));
        assert!(types.contains(&SECURITY_RSA_AES256));
        assert!(types.contains(&SECURITY_VNC_AUTH));
    }

    #[test]
    fn vencrypt_version_reply_advances_to_sub_types() {
        let (server, mut client) = connected_pair();
        let mut vnc = VncClient::new(
            server,
            1920,
            1080,
            "test".into(),
            Some("password".into()),
            true,
            true,
            true,
            ServerTlsConfig::self_signed().ok(),
        );
        vnc.state = ClientState::WaitingForVeNCryptVersion;

        // Simulate client sending VeNCrypt version 0.2.
        client.write_all(&[0x00, 0x02]).unwrap();
        client.flush().unwrap();

        vnc.process_messages().unwrap();
        assert_eq!(vnc.state, ClientState::WaitingForVeNCryptSubType);

        // Read the sub-types advertisement.
        let mut buf = [0u8; 256];
        let n = client.read(&mut buf).unwrap();
        assert!(n > 0);
        let count = buf[0] as usize;
        let mut subtypes = Vec::new();
        for i in 0..count {
            let subtype = u32::from_be_bytes([
                buf[1 + i * 4],
                buf[2 + i * 4],
                buf[3 + i * 4],
                buf[4 + i * 4],
            ]);
            subtypes.push(subtype);
        }
        assert!(subtypes.contains(&2)); // TLS
        assert!(subtypes.contains(&26)); // RSA-AES
        assert!(subtypes.contains(&1)); // VNCAuth
    }

    #[test]
    fn advertised_security_types_decisions() {
        // VeNCrypt first, RSA-AES before VNC Auth when both are enabled.
        assert_eq!(
            advertised_security_types(true, true, true),
            vec![
                SecurityType::VeNCrypt,
                SecurityType::RsaAes256,
                SecurityType::RsaAes,
                SecurityType::VncAuth,
            ]
        );
        // Without RSA-AES only VNC Auth is offered on an authenticated server.
        assert_eq!(
            advertised_security_types(true, false, false),
            vec![SecurityType::VncAuth]
        );
        // Without authentication only None is offered.
        assert_eq!(
            advertised_security_types(false, true, false),
            vec![SecurityType::None]
        );
        // VeNCrypt combines with the unauthenticated fallback.
        assert_eq!(
            advertised_security_types(false, false, true),
            vec![SecurityType::VeNCrypt, SecurityType::None]
        );
    }

    #[test]
    fn advertised_vencrypt_sub_types_decisions() {
        // TLS and X509 are always offered; RSA-AES needs a password.
        assert_eq!(
            advertised_vencrypt_sub_types(true, true, true),
            vec![
                VeNCryptSubType::Tls,
                VeNCryptSubType::X509,
                VeNCryptSubType::RsaAes256,
                VeNCryptSubType::RsaAes,
                VeNCryptSubType::VncAuth,
            ]
        );
        // No RSA-AES: falls back to VNC Auth.
        assert_eq!(
            advertised_vencrypt_sub_types(false, true, true),
            vec![
                VeNCryptSubType::Tls,
                VeNCryptSubType::X509,
                VeNCryptSubType::VncAuth,
            ]
        );
        // Without a password neither RSA-AES nor VNC Auth can be served.
        assert_eq!(
            advertised_vencrypt_sub_types(true, true, false),
            vec![
                VeNCryptSubType::Tls,
                VeNCryptSubType::X509,
                VeNCryptSubType::Plain,
            ]
        );
    }

    #[test]
    fn handle_version_accepts_rfb_3_8() {
        let (server, mut client) = connected_pair();
        let mut vnc = VncClient::new(
            server,
            1920,
            1080,
            "test".into(),
            None,
            false,
            false,
            false,
            None,
        );
        client.write_all(b"RFB 003.008\n").unwrap();
        client.flush().unwrap();

        assert!(vnc.process_messages().unwrap());
        assert_eq!(vnc.state, ClientState::WaitingForSecurity);
    }

    #[test]
    fn handle_version_rejects_unsupported_versions() {
        for banner in [
            &b"RFB 003.003\n"[..],
            &b"RFB 003.007\n"[..],
            &b"RFB 004.000\n"[..],
        ] {
            let (server, mut client) = connected_pair();
            let mut vnc = VncClient::new(
                server,
                1920,
                1080,
                "test".into(),
                None,
                false,
                false,
                false,
                None,
            );
            client.write_all(banner).unwrap();
            client.flush().unwrap();

            // The handler error maps to "drop the client": process_messages
            // reports a disconnect.
            assert!(!vnc.process_messages().unwrap(), "banner={:?}", banner);
        }
    }

    #[test]
    fn send_desktop_name_encoding() {
        let (server, mut client) = connected_pair();
        let mut vnc = VncClient::new(
            server,
            1920,
            1080,
            "test-desktop".into(),
            Some("password".into()),
            true,
            false,
            false,
            None,
        );
        vnc.state = ClientState::Ready;
        vnc.send_desktop_name("test-desktop").unwrap();

        let mut header = [0u8; 4];
        client.read_exact(&mut header).unwrap();
        assert_eq!(header[0], ServerMsgType::FramebufferUpdate as u8);
        assert_eq!(header[1], 0); // padding
        assert_eq!(u16::from_be_bytes([header[2], header[3]]), 1); // one rectangle

        let mut rect = [0u8; 12];
        client.read_exact(&mut rect).unwrap();
        assert_eq!(u16::from_be_bytes([rect[0], rect[1]]), 0); // x
        assert_eq!(u16::from_be_bytes([rect[2], rect[3]]), 0); // y
        assert_eq!(u16::from_be_bytes([rect[4], rect[5]]), 0); // width
        assert_eq!(u16::from_be_bytes([rect[6], rect[7]]), 0); // height
        assert_eq!(
            i32::from_be_bytes([rect[8], rect[9], rect[10], rect[11]]),
            -307
        ); // DesktopName

        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).unwrap();
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut name_buf = vec![0u8; len];
        client.read_exact(&mut name_buf).unwrap();
        assert_eq!(String::from_utf8_lossy(&name_buf), "test-desktop");
    }

    #[test]
    fn fence_ping_wire_bytes_have_request_flag() {
        let (server, mut client) = connected_pair();
        let mut vnc = VncClient::new(
            server,
            1920,
            1080,
            "test".into(),
            None,
            false,
            false,
            false,
            None,
        );
        vnc.state = ClientState::Ready;
        vnc.send_fence_ping().unwrap();
        vnc.flush().unwrap();

        // ServerFence: type u8 (248), 3 bytes padding, flags u32, length u8,
        // payload[length]. The Request flag is bit 31 (0x80000000).
        let mut buf = [0u8; 13];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(
            buf,
            [
                248, 0, 0, 0, // message type + padding
                0x80, 0x00, 0x00, 0x00, // flags: Request
                4,    // payload length (u8)
                b'p', b'i', b'n', b'g',
            ]
        );
        assert_eq!(vnc.pending_fences.len(), 1);
    }

    #[test]
    fn fence_response_pops_pending_fences() {
        let (server, mut client) = connected_pair();
        let mut vnc = VncClient::new(
            server,
            1920,
            1080,
            "test".into(),
            None,
            false,
            false,
            false,
            None,
        );
        vnc.state = ClientState::Ready;
        vnc.send_fence_ping().unwrap();
        vnc.flush().unwrap();
        assert_eq!(vnc.pending_fences.len(), 1);

        // Simulate the client echoing the fence back with Request cleared.
        client
            .write_all(&[
                248, 0, 0, 0, // ClientFence + padding
                0x00, 0x00, 0x00, 0x00, // flags: response, Request cleared
                4, b'p', b'i', b'n', b'g',
            ])
            .unwrap();
        client.flush().unwrap();

        vnc.process_messages().unwrap();
        vnc.process_fence_events();
        assert!(vnc.pending_fences.is_empty());
        assert!(vnc.fence_events.is_empty());
    }

    #[test]
    fn pending_fences_stays_bounded_when_client_never_responds() {
        let (server, _client) = connected_pair();
        let mut vnc = VncClient::new(
            server,
            1920,
            1080,
            "test".into(),
            None,
            false,
            false,
            false,
            None,
        );
        vnc.state = ClientState::Ready;
        for _ in 0..MAX_PENDING_FENCES + 8 {
            vnc.send_fence_ping().unwrap();
        }
        vnc.flush().unwrap();
        assert_eq!(vnc.pending_fences.len(), MAX_PENDING_FENCES);
    }

    /// Build a FramebufferUpdateRequest message.
    fn fb_update_request(incremental: u8, x: u16, y: u16, w: u16, h: u16) -> [u8; 10] {
        let mut msg = [0u8; 10];
        msg[0] = 3;
        msg[1] = incremental;
        msg[2..4].copy_from_slice(&x.to_be_bytes());
        msg[4..6].copy_from_slice(&y.to_be_bytes());
        msg[6..8].copy_from_slice(&w.to_be_bytes());
        msg[8..10].copy_from_slice(&h.to_be_bytes());
        msg
    }

    fn ready_client() -> (VncClient, TcpStream) {
        let (server, client) = connected_pair();
        let mut vnc = VncClient::new(
            server,
            256,
            256,
            "test".into(),
            None,
            false,
            false,
            false,
            None,
        );
        vnc.state = ClientState::Ready;
        (vnc, client)
    }

    #[test]
    fn new_client_has_full_damage() {
        let (vnc, _client) = ready_client();
        assert!(!vnc.damage.is_empty());
        let rects = vnc.damage.rects();
        assert_eq!(rects.len(), 1);
        assert_eq!(rects[0].width, 256);
        assert_eq!(rects[0].height, 256);
    }

    #[test]
    fn non_incremental_request_marks_requested_rect_damaged() {
        let (mut vnc, mut client) = ready_client();
        vnc.damage.clear();

        client
            .write_all(&fb_update_request(0, 64, 64, 64, 64))
            .unwrap();
        client.flush().unwrap();
        vnc.process_messages().unwrap();

        assert_eq!(vnc.pending_requests, 1);
        assert!(!vnc.damage.is_empty());
        let rects = vnc.damage.rects();
        assert_eq!(rects.len(), 1);
        assert_eq!(rects[0].x, 64);
        assert_eq!(rects[0].y, 64);
        assert_eq!(rects[0].width, 64);
        assert_eq!(rects[0].height, 64);
    }

    #[test]
    fn incremental_request_does_not_add_damage() {
        let (mut vnc, mut client) = ready_client();
        vnc.damage.clear();

        client
            .write_all(&fb_update_request(1, 0, 0, 256, 256))
            .unwrap();
        client.flush().unwrap();
        vnc.process_messages().unwrap();

        assert_eq!(vnc.pending_requests, 1);
        assert!(vnc.damage.is_empty());
    }

    #[test]
    fn damage_accumulates_without_pending_request() {
        // Changes recorded while the client has no pending request must still
        // be present when the client finally asks for an update.
        let (mut vnc, mut client) = ready_client();
        vnc.damage.clear();

        // Two frame diffs arrive with no request in between.
        vnc.record_frame_damage(
            &[DamageRect {
                x: 0,
                y: 0,
                width: 64,
                height: 64,
            }],
            &[],
        );
        vnc.record_frame_damage(
            &[DamageRect {
                x: 192,
                y: 192,
                width: 64,
                height: 64,
            }],
            &[],
        );
        assert_eq!(vnc.damage.rects().len(), 2);

        // The client sends an incremental request: accumulated damage stays.
        client
            .write_all(&fb_update_request(1, 0, 0, 256, 256))
            .unwrap();
        client.flush().unwrap();
        vnc.process_messages().unwrap();
        assert_eq!(vnc.pending_requests, 1);
        let rects = vnc.damage.rects();
        assert_eq!(rects.len(), 2);
        assert!(rects.iter().any(|r| r.x == 0 && r.y == 0));
        assert!(rects.iter().any(|r| r.x == 192 && r.y == 192));

        // After the update is sent the damage is cleared.
        vnc.damage.clear();
        vnc.frame_sent();
        assert!(vnc.damage.is_empty());
        assert_eq!(vnc.pending_requests, 0);
    }

    #[test]
    fn copyrect_allowed_only_when_client_up_to_date() {
        let (mut vnc, _client) = ready_client();
        let copy_rects = [CopyRect {
            src_x: 0,
            src_y: 0,
            x: 0,
            y: 64,
            width: 64,
            height: 64,
        }];

        // Client with an empty accumulator is in sync with the server's
        // previous frame: CopyRect sources are valid.
        vnc.damage.clear();
        vnc.record_frame_damage(&[], &copy_rects);
        assert!(vnc.allow_copyrect);
        // The copy destination was recorded as damage.
        assert!(!vnc.damage.is_empty());

        // Client with leftover damage may have an older framebuffer: CopyRect
        // would copy stale pixels, so it must be disabled for this frame.
        vnc.record_frame_damage(
            &[DamageRect {
                x: 128,
                y: 0,
                width: 64,
                height: 64,
            }],
            &[],
        );
        assert!(!vnc.allow_copyrect);
    }

    #[test]
    fn set_dimensions_resets_damage_to_full() {
        let (mut vnc, _client) = ready_client();
        vnc.damage.clear();
        vnc.set_dimensions(128, 64);
        assert!(!vnc.damage.is_empty());
        let rects = vnc.damage.rects();
        assert_eq!(rects.len(), 1);
        assert_eq!(rects[0].width, 128);
        assert_eq!(rects[0].height, 64);
        assert!(!vnc.allow_copyrect);
    }

    #[test]
    fn enable_continuous_updates_marks_region_damaged() {
        let (mut vnc, mut client) = ready_client();
        vnc.damage.clear();

        let mut msg = [0u8; 10];
        msg[0] = 150; // EnableContinuousUpdates
        msg[1] = 1; // enable
        msg[6..8].copy_from_slice(&256u16.to_be_bytes());
        msg[8..10].copy_from_slice(&256u16.to_be_bytes());
        client.write_all(&msg).unwrap();
        client.flush().unwrap();
        vnc.process_messages().unwrap();

        assert!(vnc.continuous_updates);
        assert!(!vnc.damage.is_empty());
    }

    /// Stream half used to run the client side of the RSA-AES handshake
    /// against canned server bytes.
    struct MockStream {
        read: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read.read(buf)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Shared write sink used to capture AES-CTR ciphertext produced by an
    /// `AesCtrStream` standing in for the remote client.
    #[derive(Clone, Default)]
    struct SharedSink(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);

    impl Read for SharedSink {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "no data"))
        }
    }

    impl Write for SharedSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn version_without_rfb_prefix_is_rejected() {
        let (server, mut client) = connected_pair();
        let mut vnc = VncClient::new(
            server,
            256,
            256,
            "test".into(),
            None,
            false,
            false,
            false,
            None,
        );
        client.write_all(b"HTTP/1.1 200 ").unwrap(); // 13 bytes, not RFB
        client.flush().unwrap();
        // Garbage must drop the connection (Ok(false)) instead of driving
        // the handshake.
        assert!(!vnc.process_messages().unwrap());
    }

    #[test]
    fn vencrypt_tls_upgrade_consumes_buffered_bytes() {
        let (server, mut client) = connected_pair();
        // The TLS layer drives socket I/O during writes; the socket must be
        // non-blocking for those reads to return WouldBlock instead of
        // hanging.
        server.set_nonblocking(true).unwrap();
        let mut vnc = VncClient::new(
            server,
            256,
            256,
            "test".into(),
            Some("pw".into()),
            true,
            true,
            true,
            ServerTlsConfig::self_signed().ok(),
        );
        vnc.state = ClientState::WaitingForVeNCryptSubType;

        // Sub-type 2 (TLS) followed, in the same TCP segment, by the start of
        // a TLS handshake record (content type 22, version 3.1, length 512 —
        // deliberately incomplete so rustls buffers it and waits for more).
        let mut msg = vec![0, 0, 0, 2];
        msg.extend_from_slice(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00]);
        client.write_all(&msg).unwrap();
        client.flush().unwrap();

        vnc.process_messages().unwrap();

        assert!(matches!(vnc.stream.0, Some(VncStream::Tls(_))));
        // The pipelined TLS record bytes were consumed by the upgrade and must
        // NOT be parsed again as a plaintext ClientInit (which would move the
        // state to Ready and send a ServerInit).
        assert_eq!(vnc.state, ClientState::WaitingForInit);
        assert_eq!(vnc.buffer_len - vnc.buffer_pos, 0);
    }

    #[test]
    fn rsa_aes_upgrade_decrypts_pipelined_messages() {
        use vnc_protocol::rsa_aes::RsaAesClientAuth;

        let (server, mut client) = connected_pair();
        server.set_nonblocking(true).unwrap();
        let mut vnc = VncClient::new(
            server,
            256,
            256,
            "test".into(),
            Some("pw".into()),
            true,
            true,
            false,
            None,
        );

        let auth = RsaAesServerAuth::new_128().unwrap();
        let mut pk_wire = Vec::new();
        auth.send_public_key(&mut pk_wire).unwrap();

        // Run the client half against the server's public key.
        let client_auth = RsaAesClientAuth::new_128();
        let mut client_half = MockStream {
            read: std::io::Cursor::new(pk_wire),
            written: Vec::new(),
        };
        let client_key = client_auth.authenticate(&mut client_half).unwrap();

        // Plaintext messages pipelined behind the encrypted key: ClientInit,
        // a pointer event, a key event, and an incremental update request.
        let mut pipelined = vec![1u8]; // ClientInit: shared
        pipelined.extend_from_slice(&[5, 1, 0, 10, 0, 20]); // PointerEvent
        pipelined.extend_from_slice(&[4, 1, 0, 0, 0, 0, 0, 65]); // KeyEvent 'a'
        pipelined.extend_from_slice(&fb_update_request(1, 0, 0, 256, 256));

        // Encrypt them with the client→server keystream, as a real client
        // would after its own upgrade.
        let sink = SharedSink::default();
        let mut enc = AesCtrStream::new(sink.clone(), &client_key).unwrap();
        enc.write_all(&pipelined).unwrap();
        enc.flush().unwrap();
        let ciphertext = sink.0.borrow().clone();

        // One TCP segment: encrypted key + pipelined ciphertext.
        let mut wire = client_half.written.clone();
        wire.extend_from_slice(&ciphertext);
        client.write_all(&wire).unwrap();
        client.flush().unwrap();

        vnc.state = ClientState::WaitingForRsaAes;
        vnc.rsa_aes_auth = Some(auth);
        vnc.process_messages().unwrap();

        // Every pipelined message was decrypted and processed exactly once.
        assert_eq!(vnc.state, ClientState::Ready);
        assert_eq!(vnc.pointer_events.len(), 1);
        assert_eq!(vnc.pointer_events[0], (1, 10, 20));
        assert_eq!(vnc.key_events.len(), 1);
        assert_eq!(vnc.key_events[0], (true, 65));
        assert_eq!(vnc.pending_requests, 1);
        assert_eq!(vnc.buffer_len - vnc.buffer_pos, 0);
    }

    #[test]
    fn outbound_queue_preserves_order_across_wouldblock() {
        let (server, mut client) = connected_pair();
        server.set_nonblocking(true).unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_millis(2000)))
            .unwrap();
        let mut vnc = VncClient::new(
            server,
            256,
            256,
            "test".into(),
            None,
            false,
            false,
            false,
            None,
        );
        vnc.state = ClientState::Ready;

        let rect = FbRect {
            x: 0,
            y: 0,
            width: 256,
            height: 256,
            encoding: Encoding::Raw,
            data: vec![0xAB; 512 * 1024],
        };

        // Queue rectangles until the kernel send buffer fills and bytes start
        // accumulating in the client-level queue.
        let mut rects_sent = 0usize;
        for _ in 0..512 {
            vnc.send_raw_rect(&rect).unwrap();
            vnc.flush_pending().unwrap();
            rects_sent += 1;
            if !vnc.outbound_idle() {
                break;
            }
        }
        assert!(!vnc.outbound_idle(), "kernel send buffer never filled");

        // This message is queued behind the backed-up rectangles.
        vnc.send_cut_text("MARKER").unwrap();

        let rect_bytes = 12 + rect.data.len();
        let cut_text_bytes = 8 + 6; // header + "MARKER"
        let expected_total = rects_sent * rect_bytes + cut_text_bytes;

        // Drain from the client side while retrying the server-side queue.
        let mut received = Vec::new();
        let mut buf = [0u8; 65536];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while received.len() < expected_total {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out draining queued output"
            );
            match client.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => received.extend_from_slice(&buf[..n]),
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut => {}
                Err(e) => panic!("client read failed: {}", e),
            }
            vnc.flush_pending().unwrap();
        }

        // Everything arrived, in order: all rectangles first, the cut text
        // last, with no byte lost or duplicated across the WouldBlock.
        assert!(vnc.outbound_idle());
        assert_eq!(received.len(), expected_total);
        // First rectangle header: x=0, y=0, w=256, h=256, encoding=Raw(0).
        assert_eq!(&received[..12], [0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0]);
        let tail = &received[expected_total - cut_text_bytes..];
        assert_eq!(tail[0], ServerMsgType::ServerCutText as u8);
        assert_eq!(&tail[8..], b"MARKER");
    }

    #[test]
    fn cut_text_negative_length_parses_extended_clipboard_payload() {
        use crate::protocol::clipboard::build_text_provide;

        let (server, _client) = connected_pair();
        let mut vnc = VncClient::new(
            server,
            1920,
            1080,
            "test".into(),
            None,
            false,
            false,
            false,
            None,
        );
        // The client advertised the ExtendedClipboard pseudo-encoding.
        vnc.extended_clipboard = true;

        // ClientCutText carrying a real extended-clipboard Provide message
        // (zlib-compressed): the negative length's abs() is the payload size.
        let ext = build_text_provide("extended hello").unwrap();
        let mut msg = vec![ClientMsgType::CutText as u8, 0, 0, 0];
        msg.extend_from_slice(&(-(ext.len() as i32)).to_be_bytes());
        msg.extend_from_slice(&ext);

        // Incomplete payload: need more data, consume nothing.
        vnc.buffer = msg[..msg.len() - 1].to_vec();
        vnc.buffer_pos = 0;
        let avail = vnc.buffer.len();
        assert_eq!(vnc.handle_cut_text(avail).unwrap(), 0);

        // Full message: consumed, and the text reaches the clipboard sync path.
        vnc.buffer = msg.clone();
        vnc.buffer_pos = 0;
        assert_eq!(vnc.handle_cut_text(msg.len()).unwrap(), msg.len());
        assert_eq!(
            crate::clipboard::take_clipboard_text().as_deref(),
            Some("extended hello")
        );

        // An unparseable payload is consumed (skipped) without panicking and
        // without touching the clipboard.
        let mut bad = vec![ClientMsgType::CutText as u8, 0, 0, 0];
        bad.extend_from_slice(&(-4i32).to_be_bytes());
        bad.extend_from_slice(&(9u32 << 24).to_be_bytes()); // unknown msg type
        vnc.buffer = bad.clone();
        vnc.buffer_pos = 0;
        assert_eq!(vnc.handle_cut_text(bad.len()).unwrap(), bad.len());
        assert_eq!(crate::clipboard::take_clipboard_text(), None);

        // A client that did not advertise the capability gets its payload
        // skipped without parsing.
        vnc.extended_clipboard = false;
        vnc.buffer = msg.clone();
        vnc.buffer_pos = 0;
        assert_eq!(vnc.handle_cut_text(msg.len()).unwrap(), msg.len());
        assert_eq!(crate::clipboard::take_clipboard_text(), None);

        // Ordinary (positive) cut text still parses.
        let mut plain = vec![ClientMsgType::CutText as u8, 0, 0, 0];
        plain.extend_from_slice(&3i32.to_be_bytes());
        plain.extend_from_slice(b"abc");
        vnc.buffer = plain.clone();
        vnc.buffer_pos = 0;
        assert_eq!(vnc.handle_cut_text(plain.len()).unwrap(), plain.len());
    }
}
