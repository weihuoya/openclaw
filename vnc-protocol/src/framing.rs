//! RFB message framing: byte-level parse and build helpers for the plain
//! client-to-server and server-to-client messages shared by `vnc-client`
//! and `vnc-server`.
//!
//! Two flavors of helpers are provided:
//!
//! - Slice parsers (`parse_*` functions and `*::parse` methods) for
//!   endpoints that buffer incoming bytes (the server's per-client state
//!   machine). They take a buffer that starts at the message-type byte and
//!   return `None` when the buffer does not yet hold a complete message,
//!   or `Some((message, consumed_bytes))` (`Some(message)` plus an
//!   associated `WIRE_LEN` for fixed-size messages). The message-type byte
//!   itself is not validated; the caller has already dispatched on it.
//! - `Read`/`Vec` helpers for endpoints with blocking stream reads and
//!   write-into-buffer sends (the client, and the server's outbound queue).

use std::io::{Read, Write};

use crate::error::ProtocolError;
use crate::messages::{
    CLIENT_ENABLE_CONTINUOUS_UPDATES, CLIENT_FRAMEBUFFER_UPDATE_REQUEST, CLIENT_KEY_EVENT,
    CLIENT_POINTER_EVENT, CLIENT_SET_ENCODINGS, CLIENT_SET_PIXEL_FORMAT, MESSAGE_TYPE_FENCE,
};
use crate::pixel_format::PixelFormat;

/// Read a big-endian u16 from `buf` at `off`; the caller guarantees the
/// slice is long enough.
fn be_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}

/// Read a big-endian u32 from `buf` at `off`; the caller guarantees the
/// slice is long enough.
fn be_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Wire length of a SetPixelFormat message (type + 3 padding + 16-byte
/// pixel format descriptor).
pub const SET_PIXEL_FORMAT_WIRE_LEN: usize = 20;

/// Build a SetPixelFormat message (client → server, type 0).
pub fn build_set_pixel_format(format: &PixelFormat) -> [u8; SET_PIXEL_FORMAT_WIRE_LEN] {
    let mut msg = [0u8; SET_PIXEL_FORMAT_WIRE_LEN];
    msg[0] = CLIENT_SET_PIXEL_FORMAT;
    // msg[1..4] padding (already zero)
    format.write_to(&mut msg[4..20]);
    msg
}

/// Parse a SetPixelFormat message from a buffer starting at the
/// message-type byte.
///
/// Returns `None` when fewer than [`SET_PIXEL_FORMAT_WIRE_LEN`] bytes are
/// available; otherwise the pixel format validation result (invalid formats
/// are an error, not a need-more-data signal).
pub fn parse_set_pixel_format(buf: &[u8]) -> Option<Result<PixelFormat, ProtocolError>> {
    if buf.len() < SET_PIXEL_FORMAT_WIRE_LEN {
        return None;
    }
    Some(PixelFormat::from_bytes(&buf[4..20]))
}

/// Build a SetEncodings message (client → server, type 2) from raw encoding
/// numbers.
pub fn build_set_encodings(encodings: &[i32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(4 + encodings.len() * 4);
    msg.push(CLIENT_SET_ENCODINGS);
    msg.push(0); // padding
    msg.extend_from_slice(&(encodings.len() as u16).to_be_bytes());
    for enc in encodings {
        msg.extend_from_slice(&enc.to_be_bytes());
    }
    msg
}

/// Parse a SetEncodings message from a buffer starting at the message-type
/// byte. Returns the raw encoding numbers (the callee maps them to
/// [`crate::encoding::Encoding`] as it sees fit) and the consumed byte count.
pub fn parse_set_encodings(buf: &[u8]) -> Option<(Vec<i32>, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let num_encodings = be_u16(buf, 2) as usize;
    let msg_size = 4 + num_encodings * 4;
    if buf.len() < msg_size {
        return None;
    }
    let mut encodings = Vec::with_capacity(num_encodings);
    for i in 0..num_encodings {
        encodings.push(be_u32(buf, 4 + i * 4) as i32);
    }
    Some((encodings, msg_size))
}

/// FramebufferUpdateRequest message (client → server, type 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FramebufferUpdateRequest {
    pub incremental: bool,
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

impl FramebufferUpdateRequest {
    /// Wire length of the whole message, including the type byte.
    pub const WIRE_LEN: usize = 10;

    /// Serialize to the 10-byte wire message.
    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut msg = [0u8; Self::WIRE_LEN];
        msg[0] = CLIENT_FRAMEBUFFER_UPDATE_REQUEST;
        msg[1] = self.incremental as u8;
        msg[2..4].copy_from_slice(&self.x.to_be_bytes());
        msg[4..6].copy_from_slice(&self.y.to_be_bytes());
        msg[6..8].copy_from_slice(&self.width.to_be_bytes());
        msg[8..10].copy_from_slice(&self.height.to_be_bytes());
        msg
    }

    /// Parse from a buffer starting at the message-type byte. Returns `None`
    /// when fewer than [`Self::WIRE_LEN`] bytes are available.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::WIRE_LEN {
            return None;
        }
        Some(Self {
            incremental: buf[1] != 0,
            x: be_u16(buf, 2),
            y: be_u16(buf, 4),
            width: be_u16(buf, 6),
            height: be_u16(buf, 8),
        })
    }
}

/// KeyEvent message (client → server, type 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    pub down: bool,
    pub keysym: u32,
}

impl KeyEvent {
    /// Wire length of the whole message, including the type byte.
    pub const WIRE_LEN: usize = 8;

    /// Serialize to the 8-byte wire message.
    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut msg = [0u8; Self::WIRE_LEN];
        msg[0] = CLIENT_KEY_EVENT;
        msg[1] = self.down as u8;
        // msg[2..4] padding (already zero)
        msg[4..8].copy_from_slice(&self.keysym.to_be_bytes());
        msg
    }

    /// Parse from a buffer starting at the message-type byte. Returns `None`
    /// when fewer than [`Self::WIRE_LEN`] bytes are available.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::WIRE_LEN {
            return None;
        }
        Some(Self {
            down: buf[1] != 0,
            keysym: be_u32(buf, 4),
        })
    }
}

/// PointerEvent message (client → server, type 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerEvent {
    pub button_mask: u8,
    pub x: u16,
    pub y: u16,
}

impl PointerEvent {
    /// Wire length of the whole message, including the type byte.
    pub const WIRE_LEN: usize = 6;

    /// Serialize to the 6-byte wire message.
    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut msg = [0u8; Self::WIRE_LEN];
        msg[0] = CLIENT_POINTER_EVENT;
        msg[1] = self.button_mask;
        msg[2..4].copy_from_slice(&self.x.to_be_bytes());
        msg[4..6].copy_from_slice(&self.y.to_be_bytes());
        msg
    }

    /// Parse from a buffer starting at the message-type byte. Returns `None`
    /// when fewer than [`Self::WIRE_LEN`] bytes are available.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::WIRE_LEN {
            return None;
        }
        Some(Self {
            button_mask: buf[1],
            x: be_u16(buf, 2),
            y: be_u16(buf, 4),
        })
    }
}

/// EnableContinuousUpdates message (client → server, type 150).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnableContinuousUpdates {
    pub enable: bool,
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

impl EnableContinuousUpdates {
    /// Wire length of the whole message, including the type byte.
    pub const WIRE_LEN: usize = 10;

    /// Serialize to the 10-byte wire message.
    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut msg = [0u8; Self::WIRE_LEN];
        msg[0] = CLIENT_ENABLE_CONTINUOUS_UPDATES;
        msg[1] = self.enable as u8;
        msg[2..4].copy_from_slice(&self.x.to_be_bytes());
        msg[4..6].copy_from_slice(&self.y.to_be_bytes());
        msg[6..8].copy_from_slice(&self.width.to_be_bytes());
        msg[8..10].copy_from_slice(&self.height.to_be_bytes());
        msg
    }

    /// Parse from a buffer starting at the message-type byte. Returns `None`
    /// when fewer than [`Self::WIRE_LEN`] bytes are available.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::WIRE_LEN {
            return None;
        }
        Some(Self {
            enable: buf[1] != 0,
            x: be_u16(buf, 2),
            y: be_u16(buf, 4),
            width: be_u16(buf, 6),
            height: be_u16(buf, 8),
        })
    }
}

/// A single monitor/screen in the desktop layout, as carried by the
/// ExtendedDesktopSize pseudo-encoding and the SetDesktopSize message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl Screen {
    /// Wire length of one screen descriptor.
    pub const WIRE_LEN: usize = 16;

    /// Parse one screen descriptor from the first 16 bytes of `buf`.
    ///
    /// The caller must ensure `buf` holds at least [`Self::WIRE_LEN`] bytes.
    pub fn from_bytes(buf: &[u8]) -> Self {
        Self {
            id: be_u32(buf, 0),
            x: be_u16(buf, 4),
            y: be_u16(buf, 6),
            width: be_u16(buf, 8),
            height: be_u16(buf, 10),
            flags: be_u32(buf, 12),
        }
    }

    /// Append the 16-byte wire descriptor to `out`.
    pub fn write_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.x.to_be_bytes());
        out.extend_from_slice(&self.y.to_be_bytes());
        out.extend_from_slice(&self.width.to_be_bytes());
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
    }
}

/// Append the screen-list body shared by the ExtendedDesktopSize
/// pseudo-encoding and the SetDesktopSize message: screen count (U8), 3
/// bytes padding, then one 16-byte descriptor per screen.
pub fn write_screen_list(out: &mut Vec<u8>, screens: &[Screen]) {
    debug_assert!(screens.len() <= u8::MAX as usize, "too many screens");
    out.push(screens.len() as u8);
    out.extend_from_slice(&[0, 0, 0]); // padding
    for screen in screens {
        screen.write_to(out);
    }
}

/// Read a screen-list body (the read-direction counterpart of
/// [`write_screen_list`]) from a blocking stream: screen count (U8), 3
/// bytes padding, then one 16-byte descriptor per screen.
pub fn read_screen_list<R: Read>(r: &mut R) -> Result<Vec<Screen>, ProtocolError> {
    let mut header = [0u8; 4];
    r.read_exact(&mut header)?;
    // The U8 count inherently caps the allocation at 255 screens.
    let num_screens = header[0] as usize;
    let mut data = vec![0u8; num_screens * Screen::WIRE_LEN];
    r.read_exact(&mut data)?;
    let mut screens = Vec::with_capacity(num_screens);
    for i in 0..num_screens {
        screens.push(Screen::from_bytes(&data[i * Screen::WIRE_LEN..]));
    }
    Ok(screens)
}

/// SetDesktopSize message (client → server, type 251): new desktop
/// dimensions plus the client's screen layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetDesktopSize {
    pub width: u16,
    pub height: u16,
    pub screens: Vec<Screen>,
}

impl SetDesktopSize {
    /// Length of the fixed header: type(1) + padding(1) + width(2) +
    /// height(2) + screen count(1) + padding(3).
    pub const HEADER_LEN: usize = 10;

    /// Parse from a buffer starting at the message-type byte. Returns the
    /// message and the consumed byte count, or `None` when the buffer does
    /// not yet hold the complete message.
    pub fn parse(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < Self::HEADER_LEN {
            return None;
        }
        let num_screens = buf[6] as usize;
        let msg_size = Self::HEADER_LEN + num_screens * Screen::WIRE_LEN;
        if buf.len() < msg_size {
            return None;
        }
        let mut screens = Vec::with_capacity(num_screens);
        for i in 0..num_screens {
            screens.push(Screen::from_bytes(
                &buf[Self::HEADER_LEN + i * Screen::WIRE_LEN..],
            ));
        }
        Some((
            Self {
                width: be_u16(buf, 2),
                height: be_u16(buf, 4),
                screens,
            },
            msg_size,
        ))
    }
}

/// QEMU extended key event (client → server, message type 255, sub-type 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QemuExtendedKeyEvent {
    pub down: bool,
    pub keysym: u32,
    pub keycode: u32,
}

impl QemuExtendedKeyEvent {
    /// Wire length of the whole message, including the type and sub-type
    /// bytes.
    pub const WIRE_LEN: usize = 12;

    /// Parse from a buffer starting at the QEMU message-type byte. The
    /// caller must already have dispatched on the sub-type byte (`buf[1] ==
    /// 0`). Returns `None` when fewer than [`Self::WIRE_LEN`] bytes are
    /// available.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::WIRE_LEN {
            return None;
        }
        Some(Self {
            down: buf[2] != 0,
            // buf[3] padding
            keysym: be_u32(buf, 4),
            keycode: be_u32(buf, 8),
        })
    }
}

/// Fence message payload (RFB 7.5.10 ServerFence / 7.6.7 ClientFence).
///
/// ClientFence and ServerFence share the same message-type value (248) and
/// layout, so a single parse/build pair serves both directions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fence {
    pub flags: u32,
    pub payload: Vec<u8>,
}

impl Fence {
    /// Length of the fixed message header: type(1) + padding(3) + flags(4) +
    /// payload length(1).
    pub const HEADER_LEN: usize = 9;

    /// Parse a fence message from a buffer starting at the message-type
    /// byte. Returns the fence and the consumed byte count, or `None` when
    /// the buffer does not yet hold the complete message.
    pub fn parse(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < Self::HEADER_LEN {
            return None;
        }
        Self::parse_body(&buf[1..]).map(|(fence, n)| (fence, n + 1))
    }

    /// Parse from the bytes following the message-type byte (3 padding +
    /// flags + length + payload). Returns the fence and the number of body
    /// bytes consumed, or `None` when more data is needed.
    pub fn parse_body(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < Self::HEADER_LEN - 1 {
            return None;
        }
        let payload_len = buf[7] as usize;
        let body_len = 8 + payload_len;
        if buf.len() < body_len {
            return None;
        }
        Some((
            Self {
                flags: be_u32(buf, 3),
                payload: buf[8..body_len].to_vec(),
            },
            body_len,
        ))
    }

    /// Read a fence message body (everything after the message-type byte)
    /// from a blocking stream.
    pub fn read_body<R: Read>(r: &mut R) -> Result<Self, ProtocolError> {
        let mut header = [0u8; 8]; // 3 padding + flags(4) + length(1)
        r.read_exact(&mut header)?;
        Self::read_payload(r, be_u32(&header, 3), header[7] as usize)
    }

    /// Read a fence pseudo-encoding rectangle body from a blocking stream:
    /// flags(4) + length(1) + payload, with no padding (the rectangle header
    /// already carried it).
    pub fn read_rect_body<R: Read>(r: &mut R) -> Result<Self, ProtocolError> {
        let mut header = [0u8; 5];
        r.read_exact(&mut header)?;
        Self::read_payload(r, be_u32(&header, 0), header[4] as usize)
    }

    fn read_payload<R: Read>(
        r: &mut R,
        flags: u32,
        payload_len: usize,
    ) -> Result<Self, ProtocolError> {
        let mut payload = vec![0u8; payload_len];
        r.read_exact(&mut payload)?;
        Ok(Self { flags, payload })
    }

    /// Append a complete fence message (type byte + padding + flags +
    /// length + payload) to `out`.
    ///
    /// The payload length must fit in the U8 length field (the RFB
    /// specification recommends at most [`crate::messages::FENCE_MAX_PAYLOAD`]
    /// bytes); callers are expected to validate this so they can report the
    /// error in their own error type.
    pub fn write_message(out: &mut Vec<u8>, flags: u32, payload: &[u8]) {
        debug_assert!(payload.len() <= u8::MAX as usize, "fence payload too long");
        out.push(MESSAGE_TYPE_FENCE);
        out.extend_from_slice(&[0, 0, 0]); // padding
        out.extend_from_slice(&flags.to_be_bytes());
        out.push(payload.len() as u8);
        out.extend_from_slice(payload);
    }
}

/// Wire length of a cut-text header (type + 3 padding + i32 length). Shared
/// by ClientCutText and ServerCutText.
pub const CUT_TEXT_HEADER_LEN: usize = 8;

/// Parse a cut-text header from a buffer starting at the message-type byte.
///
/// Returns the *signed* length: a negative value signals extended-clipboard
/// data (RFB 7.5.6 / 7.6.4). Returns `None` when fewer than
/// [`CUT_TEXT_HEADER_LEN`] bytes are available.
pub fn parse_cut_text_header(buf: &[u8]) -> Option<i32> {
    if buf.len() < CUT_TEXT_HEADER_LEN {
        return None;
    }
    Some(be_u32(buf, 4) as i32)
}

/// Read the 7 cut-text header bytes following the message-type byte from a
/// blocking stream and return the signed length (negative means
/// extended-clipboard data follows).
pub fn read_cut_text_length<R: Read>(r: &mut R) -> Result<i32, ProtocolError> {
    let mut buf = [0u8; 7]; // 3 padding + length(4)
    r.read_exact(&mut buf)?;
    Ok(be_u32(&buf, 3) as i32)
}

/// Append a complete cut-text message (header + payload) to `out`.
/// `msg_type` is [`crate::messages::CLIENT_CUT_TEXT`] or
/// [`crate::messages::SERVER_SERVER_CUT_TEXT`].
pub fn write_cut_text(out: &mut Vec<u8>, msg_type: u8, payload: &[u8]) {
    out.push(msg_type);
    out.extend_from_slice(&[0, 0, 0]); // padding
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
}

/// Header of one rectangle inside a FramebufferUpdate message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RectHeader {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
    /// Raw encoding number (pseudo-encodings are negative).
    pub encoding: i32,
}

impl RectHeader {
    /// Wire length of a rectangle header.
    pub const WIRE_LEN: usize = 12;

    /// Parse from the first 12 bytes of `buf`. The caller must ensure `buf`
    /// holds at least [`Self::WIRE_LEN`] bytes.
    pub fn from_bytes(buf: &[u8]) -> Self {
        Self {
            x: be_u16(buf, 0),
            y: be_u16(buf, 2),
            width: be_u16(buf, 4),
            height: be_u16(buf, 6),
            encoding: be_u32(buf, 8) as i32,
        }
    }

    /// Serialize to the 12-byte wire header.
    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut out = [0u8; Self::WIRE_LEN];
        out[0..2].copy_from_slice(&self.x.to_be_bytes());
        out[2..4].copy_from_slice(&self.y.to_be_bytes());
        out[4..6].copy_from_slice(&self.width.to_be_bytes());
        out[6..8].copy_from_slice(&self.height.to_be_bytes());
        out[8..12].copy_from_slice(&self.encoding.to_be_bytes());
        out
    }

    /// Append the 12-byte wire header to `out`.
    pub fn write_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_bytes());
    }

    /// Write the 12-byte wire header to a byte stream.
    pub fn write_to_io<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(&self.to_bytes())
    }
}

/// Append a FramebufferUpdate message header (type 0, 1 padding byte,
/// rectangle count) to `out`.
pub fn write_fb_update_header(out: &mut Vec<u8>, n_rects: u16) {
    out.push(crate::messages::SERVER_FRAMEBUFFER_UPDATE);
    out.push(0); // padding
    out.extend_from_slice(&n_rects.to_be_bytes());
}

/// Read the 3 FramebufferUpdate header bytes that follow the message-type
/// byte (1 padding byte + U16 rectangle count) from a blocking stream and
/// return the rectangle count. The read-direction counterpart of
/// [`write_fb_update_header`].
pub fn read_fb_update_header<R: Read>(r: &mut R) -> Result<u16, ProtocolError> {
    let mut buf = [0u8; 3];
    r.read_exact(&mut buf)?;
    Ok(be_u16(&buf, 1))
}

/// Body of a CopyRect rectangle (encoding 1): the source coordinates the
/// rectangle is copied from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyRectBody {
    pub src_x: u16,
    pub src_y: u16,
}

impl CopyRectBody {
    /// Wire length of the body.
    pub const WIRE_LEN: usize = 4;

    /// Parse from the first [`Self::WIRE_LEN`] bytes of `buf`. Returns `None`
    /// when fewer bytes are available.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::WIRE_LEN {
            return None;
        }
        Some(Self {
            src_x: be_u16(buf, 0),
            src_y: be_u16(buf, 2),
        })
    }

    /// Serialize to the 4-byte wire body.
    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut out = [0u8; Self::WIRE_LEN];
        out[0..2].copy_from_slice(&self.src_x.to_be_bytes());
        out[2..4].copy_from_slice(&self.src_y.to_be_bytes());
        out
    }
}

/// Header of an OpenH264 rectangle (encoding 50): a big-endian payload
/// length followed by big-endian flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenH264Header {
    /// Length of the H.264 payload following the header, in bytes.
    pub len: u32,
    /// Flags (currently unused by decoders; reserved by the encoding).
    pub flags: u32,
}

impl OpenH264Header {
    /// Wire length of the header.
    pub const WIRE_LEN: usize = 8;

    /// Parse from the first [`Self::WIRE_LEN`] bytes of `buf`. Returns `None`
    /// when fewer bytes are available.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::WIRE_LEN {
            return None;
        }
        Some(Self {
            len: be_u32(buf, 0),
            flags: be_u32(buf, 4),
        })
    }

    /// Serialize to the 8-byte wire header.
    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut out = [0u8; Self::WIRE_LEN];
        out[0..4].copy_from_slice(&self.len.to_be_bytes());
        out[4..8].copy_from_slice(&self.flags.to_be_bytes());
        out
    }
}

/// Append a SetColorMapEntries message (server → client, type 1) to `out`.
///
/// `colors` contains 8-bit RGB triples; each component is scaled to the
/// 16-bit wire range (`v * 257`).
pub fn write_set_color_map_entries(out: &mut Vec<u8>, first_color: u16, colors: &[[u8; 3]]) {
    out.push(crate::messages::SERVER_SET_COLOUR_MAP_ENTRIES);
    out.push(0); // padding
    out.extend_from_slice(&first_color.to_be_bytes());
    out.extend_from_slice(&(colors.len() as u16).to_be_bytes());
    for [r, g, b] in colors {
        out.extend_from_slice(&((*r as u16) * 257).to_be_bytes());
        out.extend_from_slice(&((*g as u16) * 257).to_be_bytes());
        out.extend_from_slice(&((*b as u16) * 257).to_be_bytes());
    }
}

/// Append a DesktopName pseudo-encoding body (U32 length + name bytes) to
/// `out`.
pub fn write_desktop_name_body(out: &mut Vec<u8>, name: &str) {
    out.extend_from_slice(&(name.len() as u32).to_be_bytes());
    out.extend_from_slice(name.as_bytes());
}

/// Read a DesktopName pseudo-encoding body (U32 length + name bytes) from a
/// blocking stream; the read-direction counterpart of
/// [`write_desktop_name_body`]. The name is decoded lossily and capped at
/// [`crate::server_init::MAX_NAME_LEN`] bytes; a larger advertised length is
/// a [`ProtocolError::Protocol`] error.
pub fn read_desktop_name_body<R: Read>(r: &mut R) -> Result<String, ProtocolError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let name_len = u32::from_be_bytes(len_buf) as usize;
    if name_len > crate::server_init::MAX_NAME_LEN {
        return Err(ProtocolError::Protocol(format!(
            "DesktopName length {} exceeds limit",
            name_len
        )));
    }
    let mut name_buf = vec![0u8; name_len];
    r.read_exact(&mut name_buf)?;
    Ok(String::from_utf8_lossy(&name_buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{
        CLIENT_CUT_TEXT, CLIENT_FENCE, FENCE_FLAG_REQUEST, SERVER_SERVER_CUT_TEXT,
    };

    #[test]
    fn set_pixel_format_exact_bytes_and_roundtrip() {
        let pf = PixelFormat::rgb16();
        let msg = build_set_pixel_format(&pf);
        assert_eq!(msg[0], CLIENT_SET_PIXEL_FORMAT);
        assert_eq!(&msg[1..4], &[0, 0, 0]);
        assert_eq!(msg[4], 16); // bits per pixel
        assert_eq!(msg[5], 16); // depth
        assert_eq!(msg.len(), SET_PIXEL_FORMAT_WIRE_LEN);

        let parsed = parse_set_pixel_format(&msg).unwrap().unwrap();
        assert_eq!(parsed, pf);
    }

    #[test]
    fn set_pixel_format_truncated_is_need_more_data() {
        let msg = build_set_pixel_format(&PixelFormat::rgba32());
        for len in 0..SET_PIXEL_FORMAT_WIRE_LEN {
            assert!(parse_set_pixel_format(&msg[..len]).is_none(), "len={}", len);
        }
    }

    #[test]
    fn set_pixel_format_invalid_format_is_error_not_need_more_data() {
        let mut msg = build_set_pixel_format(&PixelFormat::rgba32());
        msg[4] = 24; // unsupported bits-per-pixel
        let result = parse_set_pixel_format(&msg).expect("complete message");
        assert!(result.is_err());
    }

    #[test]
    fn set_encodings_exact_bytes_and_roundtrip() {
        let msg = build_set_encodings(&[16, 7, -308]);
        assert_eq!(
            msg,
            vec![
                CLIENT_SET_ENCODINGS,
                0,
                0,
                3, // count
                0,
                0,
                0,
                16, // ZRLE
                0,
                0,
                0,
                7, // Tight
                0xff,
                0xff,
                0xfe,
                0xcc, // -308 ExtendedDesktopSize
            ]
        );
        let (encodings, consumed) = parse_set_encodings(&msg).unwrap();
        assert_eq!(encodings, vec![16, 7, -308]);
        assert_eq!(consumed, msg.len());
    }

    #[test]
    fn set_encodings_truncated_is_need_more_data() {
        let msg = build_set_encodings(&[0, 1, 2]);
        // Header shorter than 4 bytes.
        for len in 0..4 {
            assert!(parse_set_encodings(&msg[..len]).is_none(), "len={}", len);
        }
        // Complete header but incomplete encoding list.
        for len in 4..msg.len() {
            assert!(parse_set_encodings(&msg[..len]).is_none(), "len={}", len);
        }
    }

    #[test]
    fn set_encodings_empty_list() {
        let msg = build_set_encodings(&[]);
        assert_eq!(msg, vec![CLIENT_SET_ENCODINGS, 0, 0, 0]);
        let (encodings, consumed) = parse_set_encodings(&msg).unwrap();
        assert!(encodings.is_empty());
        assert_eq!(consumed, 4);
    }

    #[test]
    fn fb_update_request_exact_bytes_and_roundtrip() {
        let req = FramebufferUpdateRequest {
            incremental: true,
            x: 1,
            y: 2,
            width: 640,
            height: 480,
        };
        let msg = req.to_bytes();
        assert_eq!(msg, [3, 1, 0, 1, 0, 2, 0x02, 0x80, 0x01, 0xe0]);
        assert_eq!(FramebufferUpdateRequest::parse(&msg), Some(req));
        assert!(FramebufferUpdateRequest::parse(&msg[..9]).is_none());
    }

    #[test]
    fn key_event_exact_bytes_and_roundtrip() {
        let ev = KeyEvent {
            down: true,
            keysym: 0xff0d,
        };
        let msg = ev.to_bytes();
        assert_eq!(msg, [4, 1, 0, 0, 0, 0, 0xff, 0x0d]);
        assert_eq!(KeyEvent::parse(&msg), Some(ev));
        assert!(KeyEvent::parse(&msg[..7]).is_none());

        let up = KeyEvent {
            down: false,
            keysym: 0x61,
        };
        assert_eq!(up.to_bytes()[1], 0);
        assert_eq!(KeyEvent::parse(&up.to_bytes()), Some(up));
    }

    #[test]
    fn pointer_event_exact_bytes_and_roundtrip() {
        let ev = PointerEvent {
            button_mask: 0b101,
            x: 100,
            y: 200,
        };
        let msg = ev.to_bytes();
        assert_eq!(msg, [5, 0b101, 0, 100, 0, 200]);
        assert_eq!(PointerEvent::parse(&msg), Some(ev));
        assert!(PointerEvent::parse(&msg[..5]).is_none());
    }

    #[test]
    fn enable_continuous_updates_exact_bytes_and_roundtrip() {
        let msg = EnableContinuousUpdates {
            enable: true,
            x: 10,
            y: 20,
            width: 300,
            height: 200,
        };
        let bytes = msg.to_bytes();
        assert_eq!(bytes, [150, 1, 0, 10, 0, 20, 0x01, 0x2c, 0, 200]);
        assert_eq!(EnableContinuousUpdates::parse(&bytes), Some(msg));
        assert!(EnableContinuousUpdates::parse(&bytes[..9]).is_none());
    }

    #[test]
    fn screen_exact_bytes_and_roundtrip() {
        let screen = Screen {
            id: 42,
            x: 1920,
            y: 0,
            width: 2560,
            height: 1440,
            flags: 1,
        };
        let mut buf = Vec::new();
        screen.write_to(&mut buf);
        assert_eq!(buf.len(), Screen::WIRE_LEN);
        assert_eq!(
            buf,
            vec![
                0, 0, 0, 42, // id
                0x07, 0x80, // x
                0, 0, // y
                0x0a, 0x00, // width
                0x05, 0xa0, // height
                0, 0, 0, 1, // flags
            ]
        );
        assert_eq!(Screen::from_bytes(&buf), screen);
    }

    #[test]
    fn screen_list_body_layout() {
        let screens = [
            Screen {
                id: 0,
                x: 0,
                y: 0,
                width: 800,
                height: 600,
                flags: 0,
            },
            Screen {
                id: 1,
                x: 800,
                y: 0,
                width: 800,
                height: 600,
                flags: 0,
            },
        ];
        let mut buf = Vec::new();
        write_screen_list(&mut buf, &screens);
        assert_eq!(buf.len(), 4 + 2 * Screen::WIRE_LEN);
        assert_eq!(buf[0], 2); // count
        assert_eq!(&buf[1..4], &[0, 0, 0]); // padding
        assert_eq!(Screen::from_bytes(&buf[4..]), screens[0]);
        assert_eq!(Screen::from_bytes(&buf[4 + Screen::WIRE_LEN..]), screens[1]);
    }

    #[test]
    fn set_desktop_size_parse_roundtrip_and_truncation() {
        // Build a wire message by hand: type(1) pad(1) w(2) h(2) count(1)
        // pad(3) screens.
        let screen = Screen {
            id: 7,
            x: 0,
            y: 0,
            width: 1024,
            height: 768,
            flags: 0,
        };
        let mut msg = vec![251, 0];
        msg.extend_from_slice(&1024u16.to_be_bytes());
        msg.extend_from_slice(&768u16.to_be_bytes());
        let mut list = Vec::new();
        write_screen_list(&mut list, &[screen]);
        msg.extend_from_slice(&list);

        let (parsed, consumed) = SetDesktopSize::parse(&msg).unwrap();
        assert_eq!(parsed.width, 1024);
        assert_eq!(parsed.height, 768);
        assert_eq!(parsed.screens, vec![screen]);
        assert_eq!(consumed, msg.len());

        for len in 0..msg.len() {
            assert!(SetDesktopSize::parse(&msg[..len]).is_none(), "len={}", len);
        }
    }

    #[test]
    fn set_desktop_size_zero_screens() {
        let msg = [251, 0, 0x04, 0x00, 0x03, 0x00, 0, 0, 0, 0];
        let (parsed, consumed) = SetDesktopSize::parse(&msg).unwrap();
        assert_eq!(parsed.width, 1024);
        assert_eq!(parsed.height, 768);
        assert!(parsed.screens.is_empty());
        assert_eq!(consumed, 10);
    }

    #[test]
    fn qemu_extended_key_event_parse() {
        let msg = [
            255, 0, // QEMU message, sub-type 0
            1, 0, // down + padding
            0, 0, 0xff, 0x0d, // keysym
            0, 0, 0, 28, // keycode
        ];
        let ev = QemuExtendedKeyEvent::parse(&msg).unwrap();
        assert!(ev.down);
        assert_eq!(ev.keysym, 0xff0d);
        assert_eq!(ev.keycode, 28);
        assert!(QemuExtendedKeyEvent::parse(&msg[..11]).is_none());
    }

    #[test]
    fn fence_message_exact_bytes_and_roundtrip() {
        let mut msg = Vec::new();
        Fence::write_message(&mut msg, FENCE_FLAG_REQUEST, b"ping");
        assert_eq!(
            msg,
            vec![
                CLIENT_FENCE,
                0,
                0,
                0, // padding
                0x80,
                0,
                0,
                0, // flags
                4, // length
                b'p',
                b'i',
                b'n',
                b'g',
            ]
        );
        let (fence, consumed) = Fence::parse(&msg).unwrap();
        assert_eq!(fence.flags, FENCE_FLAG_REQUEST);
        assert_eq!(fence.payload, b"ping");
        assert_eq!(consumed, msg.len());
    }

    #[test]
    fn fence_parse_truncated_is_need_more_data() {
        let mut msg = Vec::new();
        Fence::write_message(&mut msg, 0x1234, b"payload!");
        for len in 0..msg.len() {
            assert!(Fence::parse(&msg[..len]).is_none(), "len={}", len);
        }
        // parse_body agrees on the body slice.
        let (fence, body_len) = Fence::parse_body(&msg[1..]).unwrap();
        assert_eq!(fence.flags, 0x1234);
        assert_eq!(fence.payload, b"payload!");
        assert_eq!(body_len, msg.len() - 1);
    }

    #[test]
    fn fence_empty_payload() {
        let mut msg = Vec::new();
        Fence::write_message(&mut msg, 0, &[]);
        let (fence, consumed) = Fence::parse(&msg).unwrap();
        assert_eq!(fence.flags, 0);
        assert!(fence.payload.is_empty());
        assert_eq!(consumed, Fence::HEADER_LEN);
    }

    #[test]
    fn fence_read_body_and_rect_body() {
        let mut msg = Vec::new();
        Fence::write_message(&mut msg, 0xabcd, b"xy");
        let fence = Fence::read_body(&mut &msg[1..]).unwrap();
        assert_eq!(fence.flags, 0xabcd);
        assert_eq!(fence.payload, b"xy");

        // Rect body: flags + len + payload, no padding.
        let mut rect_body = Vec::new();
        rect_body.extend_from_slice(&0x55u32.to_be_bytes());
        rect_body.push(3);
        rect_body.extend_from_slice(b"abc");
        let fence = Fence::read_rect_body(&mut &rect_body[..]).unwrap();
        assert_eq!(fence.flags, 0x55);
        assert_eq!(fence.payload, b"abc");
    }

    #[test]
    fn cut_text_header_parse_and_build() {
        let mut msg = Vec::new();
        write_cut_text(&mut msg, SERVER_SERVER_CUT_TEXT, b"hello");
        assert_eq!(msg.len(), CUT_TEXT_HEADER_LEN + 5);
        assert_eq!(msg[0], SERVER_SERVER_CUT_TEXT);
        assert_eq!(&msg[1..4], &[0, 0, 0]);
        assert_eq!(parse_cut_text_header(&msg), Some(5));
        assert!(parse_cut_text_header(&msg[..7]).is_none());

        // Negative length (extended clipboard) round-trips as signed.
        let mut ext = vec![CLIENT_CUT_TEXT, 0, 0, 0];
        ext.extend_from_slice(&(-12i32).to_be_bytes());
        assert_eq!(parse_cut_text_header(&ext), Some(-12));
    }

    #[test]
    fn cut_text_read_length() {
        let mut msg = Vec::new();
        write_cut_text(&mut msg, CLIENT_CUT_TEXT, b"clipboard contents");
        let len = read_cut_text_length(&mut &msg[1..]).unwrap();
        assert_eq!(len, 18);
    }

    #[test]
    fn rect_header_exact_bytes_and_roundtrip() {
        let header = RectHeader {
            x: 1,
            y: 2,
            width: 640,
            height: 480,
            encoding: -308,
        };
        let mut buf = Vec::new();
        header.write_to(&mut buf);
        assert_eq!(
            buf,
            vec![0, 1, 0, 2, 0x02, 0x80, 0x01, 0xe0, 0xff, 0xff, 0xfe, 0xcc]
        );
        assert_eq!(RectHeader::from_bytes(&buf), header);
    }

    #[test]
    fn fb_update_header_exact_bytes() {
        let mut buf = Vec::new();
        write_fb_update_header(&mut buf, 3);
        assert_eq!(buf, vec![0, 0, 0, 3]);
        // The read direction consumes the 3 bytes after the type byte.
        assert_eq!(read_fb_update_header(&mut &buf[1..]).unwrap(), 3);
        // Truncated headers are IO errors, not panics.
        assert!(read_fb_update_header(&mut &buf[1..3]).is_err());
    }

    #[test]
    fn copy_rect_body_exact_bytes_and_roundtrip() {
        let body = CopyRectBody {
            src_x: 100,
            src_y: 200,
        };
        let bytes = body.to_bytes();
        assert_eq!(bytes, [0x00, 0x64, 0x00, 0xc8]);
        assert_eq!(CopyRectBody::parse(&bytes), Some(body));
        for len in 0..CopyRectBody::WIRE_LEN {
            assert!(CopyRectBody::parse(&bytes[..len]).is_none(), "len={}", len);
        }
    }

    #[test]
    fn openh264_header_exact_bytes_and_roundtrip() {
        let header = OpenH264Header {
            len: 1024,
            flags: 1,
        };
        let bytes = header.to_bytes();
        assert_eq!(bytes, [0, 0, 0x04, 0x00, 0, 0, 0, 1]);
        assert_eq!(OpenH264Header::parse(&bytes), Some(header));
        for len in 0..OpenH264Header::WIRE_LEN {
            assert!(
                OpenH264Header::parse(&bytes[..len]).is_none(),
                "len={}",
                len
            );
        }
    }

    #[test]
    fn screen_list_read_roundtrip() {
        let screens = [
            Screen {
                id: 0,
                x: 0,
                y: 0,
                width: 800,
                height: 600,
                flags: 0,
            },
            Screen {
                id: 1,
                x: 800,
                y: 0,
                width: 800,
                height: 600,
                flags: 1,
            },
        ];
        let mut buf = Vec::new();
        write_screen_list(&mut buf, &screens);
        assert_eq!(read_screen_list(&mut &buf[..]).unwrap(), screens);
        // Every truncation is an IO error, not a panic.
        for len in 0..buf.len() {
            assert!(read_screen_list(&mut &buf[..len]).is_err(), "len={}", len);
        }
    }

    #[test]
    fn desktop_name_body_read_roundtrip_and_limit() {
        let mut buf = Vec::new();
        write_desktop_name_body(&mut buf, "vm");
        assert_eq!(read_desktop_name_body(&mut &buf[..]).unwrap(), "vm");
        for len in 0..buf.len() {
            assert!(
                read_desktop_name_body(&mut &buf[..len]).is_err(),
                "len={}",
                len
            );
        }

        // Over-limit length is a protocol error before any allocation.
        let mut huge = Vec::new();
        huge.extend_from_slice(&((crate::server_init::MAX_NAME_LEN as u32) + 1).to_be_bytes());
        let err = read_desktop_name_body(&mut &huge[..]).unwrap_err();
        assert!(matches!(err, ProtocolError::Protocol(_)));
    }

    #[test]
    fn set_color_map_entries_exact_bytes() {
        let mut buf = Vec::new();
        write_set_color_map_entries(&mut buf, 2, &[[0xff, 0x80, 0x00]]);
        assert_eq!(
            buf,
            vec![
                1, 0, // type + padding
                0, 2, // first color
                0, 1, // count
                0xff, 0xff, // red   = 255 * 257
                0x80, 0x80, // green = 128 * 257
                0x00, 0x00, // blue
            ]
        );
    }

    #[test]
    fn desktop_name_body_exact_bytes() {
        let mut buf = Vec::new();
        write_desktop_name_body(&mut buf, "vm");
        assert_eq!(buf, vec![0, 0, 0, 2, b'v', b'm']);
    }
}
