//! Per-client connection state machine.

use byteorder::{BigEndian, WriteBytesExt};
use log::{debug, info, warn};
use std::io::{self, Read, Write};
use std::net::TcpStream;

use crate::encode::tight::TightEncoder;
use crate::encode::zrle::ZrleEncoder;
use crate::protocol::*;

/// Maximum read buffer size per client to prevent memory exhaustion.
const MAX_BUFFER_LEN: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    WaitingForVersion,
    WaitingForSecurity,
    WaitingForVncAuth,
    WaitingForInit,
    Ready,
}

pub struct VncClient {
    pub stream: TcpStream,
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
    pub damage: Vec<(u16, u16, u16, u16)>,   // x, y, w, h
    pub key_events: Vec<(bool, u32)>,        // (down, keysym)
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
    pub tight_encoder: TightEncoder,
    pub zrle_encoder: ZrleEncoder,
}

impl VncClient {
    pub fn new(
        stream: TcpStream,
        width: u16,
        height: u16,
        name: String,
        password: Option<String>,
        auth_enabled: bool,
    ) -> Self {
        Self {
            stream,
            state: ClientState::WaitingForVersion,
            pixel_format: PixelFormat::default(),
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
            damage: vec![(0, 0, width, height)],
            key_events: Vec::new(),
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
            tight_encoder: TightEncoder::new(),
            zrle_encoder: ZrleEncoder::new(),
        }
    }

    /// Write the protocol version to the client.
    pub fn send_version(&mut self) -> io::Result<()> {
        self.stream.write_all(RFB_VERSION)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Send the list of supported security types.
    pub fn send_security_types(&mut self) -> io::Result<()> {
        if self.auth_enabled {
            let types = [SecurityType::VncAuth as u8];
            self.stream.write_u8(types.len() as u8)?;
            self.stream.write_all(&types)?;
        } else {
            let types = [SecurityType::None as u8];
            self.stream.write_u8(types.len() as u8)?;
            self.stream.write_all(&types)?;
        }
        self.stream.flush()?;
        self.state = ClientState::WaitingForSecurity;
        Ok(())
    }

    /// Send security handshake result.
    pub fn send_security_result(&mut self, result: SecurityResult) -> io::Result<()> {
        self.stream.write_u32::<BigEndian>(result as u32)?;
        self.stream.flush()?;
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
        init.write(&mut self.stream)?;
        self.stream.flush()?;
        self.state = ClientState::Ready;
        info!("Client ready: {}x{}", self.width, self.height);
        Ok(())
    }

    /// Send ServerCutText message to client.
    pub fn send_cut_text(&mut self, text: &str) -> io::Result<()> {
        let bytes = text.as_bytes();
        self.stream.write_u8(ServerMsgType::ServerCutText as u8)?;
        self.stream.write_all(&[0, 0, 0])?; // padding
        self.stream.write_u32::<BigEndian>(bytes.len() as u32)?;
        self.stream.write_all(bytes)?;
        self.stream.flush()?;
        self.bytes_sent += 8 + bytes.len() as u64;
        Ok(())
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
                ClientState::WaitingForInit => self.handle_init(available),
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
        if avail < 12 {
            return Ok(0);
        }
        let version = &self.buffer[self.buffer_pos..self.buffer_pos + 12];
        let version_str = std::str::from_utf8(version).unwrap_or("");
        debug!("Client version: {}", version_str.trim());

        // Parse major.minor
        let parts: Vec<&str> = version_str.split_whitespace().collect();
        if parts.len() == 2 {
            let nums: Vec<&str> = parts[1].split('.').collect();
            if nums.len() == 2 {
                if let (Ok(3), Ok(minor)) = (nums[0].parse::<u32>(), nums[1].parse::<u32>()) {
                    debug!("RFB 3.{}", minor);
                }
            }
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

        match sec_type {
            1 => {
                // None
                if self.auth_enabled {
                    self.send_security_failed("Authentication required")?;
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "auth required",
                    ));
                }
                self.send_security_result(SecurityResult::Ok)?;
            }
            2 => {
                // VNC Auth
                if self.password.is_none() {
                    self.send_security_failed("No password configured")?;
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "no password",
                    ));
                }
                let challenge = crate::auth::generate_challenge();
                self.stream.write_all(&challenge)?;
                self.stream.flush()?;
                self.challenge = Some(challenge);
                self.state = ClientState::WaitingForVncAuth;
                debug!("Sent VNC Auth challenge");
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
            0 => self.handle_set_pixel_format(avail),
            2 => self.handle_set_encodings(avail),
            3 => self.handle_fb_update_request(avail),
            4 => self.handle_key_event(avail),
            5 => self.handle_pointer_event(avail),
            6 => self.handle_cut_text(avail),
            150 => self.handle_enable_continuous_updates(avail),
            _ => {
                warn!("Unknown client message type: {}", msg_type);
                Ok(1) // skip unknown byte
            }
        }
    }

    fn handle_set_pixel_format(&mut self, avail: usize) -> io::Result<usize> {
        if avail < 4 + 16 {
            return Ok(0);
        }
        // Skip padding (1 byte type + 3 padding)
        let fmt = PixelFormat::read(&mut &self.buffer[self.buffer_pos + 4..])?;
        debug!("Client set pixel format: {:?}", fmt);
        self.pixel_format = fmt;
        Ok(20)
    }

    fn handle_set_encodings(&mut self, avail: usize) -> io::Result<usize> {
        if avail < 4 {
            return Ok(0);
        }
        let n_encodings = u16::from_be_bytes([
            self.buffer[self.buffer_pos + 2],
            self.buffer[self.buffer_pos + 3],
        ]) as usize;
        let msg_size = 4 + n_encodings * 4;
        if avail < msg_size {
            return Ok(0);
        }
        self.encodings.clear();
        for i in 0..n_encodings {
            let off = self.buffer_pos + 4 + i * 4;
            let enc = i32::from_be_bytes([
                self.buffer[off],
                self.buffer[off + 1],
                self.buffer[off + 2],
                self.buffer[off + 3],
            ]);
            if let Some(e) = encoding_from_i32(enc) {
                self.encodings.push(e);
            }
        }
        debug!("Client set {} encodings", self.encodings.len());
        Ok(msg_size)
    }

    fn handle_fb_update_request(&mut self, avail: usize) -> io::Result<usize> {
        if avail < 10 {
            return Ok(0);
        }
        let incremental = self.buffer[self.buffer_pos + 1] != 0;
        let x = u16::from_be_bytes([
            self.buffer[self.buffer_pos + 2],
            self.buffer[self.buffer_pos + 3],
        ]);
        let y = u16::from_be_bytes([
            self.buffer[self.buffer_pos + 4],
            self.buffer[self.buffer_pos + 5],
        ]);
        let mut w = u16::from_be_bytes([
            self.buffer[self.buffer_pos + 6],
            self.buffer[self.buffer_pos + 7],
        ]);
        let mut h = u16::from_be_bytes([
            self.buffer[self.buffer_pos + 8],
            self.buffer[self.buffer_pos + 9],
        ]);

        // Clamp to the server framebuffer bounds.
        let max_w = self.width.saturating_sub(x);
        let max_h = self.height.saturating_sub(y);
        w = w.min(max_w);
        h = h.min(max_h);

        if !incremental {
            self.damage.clear();
            self.damage.push((x, y, w, h));
        }
        self.pending_requests += 1;
        debug!(
            "FB update request: inc={} {}x{}@{},{} pending={}",
            incremental, w, h, x, y, self.pending_requests
        );
        Ok(10)
    }

    fn handle_key_event(&mut self, avail: usize) -> io::Result<usize> {
        if avail < 8 {
            return Ok(0);
        }
        let down = self.buffer[self.buffer_pos + 1] != 0;
        let keysym = u32::from_be_bytes([
            self.buffer[self.buffer_pos + 4],
            self.buffer[self.buffer_pos + 5],
            self.buffer[self.buffer_pos + 6],
            self.buffer[self.buffer_pos + 7],
        ]);
        self.key_events.push((down, keysym));
        debug!("Key event: keysym=0x{:x} down={}", keysym, down);
        Ok(8)
    }

    fn handle_pointer_event(&mut self, avail: usize) -> io::Result<usize> {
        if avail < 6 {
            return Ok(0);
        }
        let button_mask = self.buffer[self.buffer_pos + 1];
        let x = u16::from_be_bytes([
            self.buffer[self.buffer_pos + 2],
            self.buffer[self.buffer_pos + 3],
        ]);
        let y = u16::from_be_bytes([
            self.buffer[self.buffer_pos + 4],
            self.buffer[self.buffer_pos + 5],
        ]);
        self.pointer_events.push((button_mask, x, y));
        debug!("Pointer event: mask={} x={} y={}", button_mask, x, y);
        Ok(6)
    }

    fn handle_cut_text(&mut self, avail: usize) -> io::Result<usize> {
        if avail < 8 {
            return Ok(0);
        }
        let len = u32::from_be_bytes([
            self.buffer[self.buffer_pos + 4],
            self.buffer[self.buffer_pos + 5],
            self.buffer[self.buffer_pos + 6],
            self.buffer[self.buffer_pos + 7],
        ]) as usize;
        const MAX_CUT_TEXT_LEN: usize = 10 * 1024 * 1024; // 10MB
        if len > MAX_CUT_TEXT_LEN {
            warn!(
                "Client sent oversized cut text: {} bytes, disconnecting",
                len
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cut text too large",
            ));
        }
        let msg_size = 8 + len;
        if avail < msg_size {
            return Ok(0);
        }
        let text =
            std::str::from_utf8(&self.buffer[self.buffer_pos + 8..self.buffer_pos + 8 + len])
                .unwrap_or("");
        crate::clipboard::set_clipboard_text(text);
        debug!("Client cut text: {} bytes -> clipboard", len);
        Ok(msg_size)
    }

    fn handle_enable_continuous_updates(&mut self, avail: usize) -> io::Result<usize> {
        if avail < 10 {
            return Ok(0);
        }
        let enable = self.buffer[self.buffer_pos + 1] != 0;
        let x = u16::from_be_bytes([
            self.buffer[self.buffer_pos + 2],
            self.buffer[self.buffer_pos + 3],
        ]);
        let y = u16::from_be_bytes([
            self.buffer[self.buffer_pos + 4],
            self.buffer[self.buffer_pos + 5],
        ]);
        let w = u16::from_be_bytes([
            self.buffer[self.buffer_pos + 6],
            self.buffer[self.buffer_pos + 7],
        ]);
        let h = u16::from_be_bytes([
            self.buffer[self.buffer_pos + 8],
            self.buffer[self.buffer_pos + 9],
        ]);
        self.continuous_updates = enable;
        self.cu_x = x;
        self.cu_y = y;
        self.cu_w = w;
        self.cu_h = h;
        debug!(
            "Continuous updates: enable={} {}x{}@{},{} ",
            enable, w, h, x, y
        );
        if !enable {
            // Send EndOfContinuousUpdates
            self.stream
                .write_u8(ServerMsgType::EndOfContinuousUpdates as u8)?;
            self.stream.flush()?;
        }
        Ok(10)
    }

    fn send_security_failed(&mut self, reason: &str) -> io::Result<()> {
        self.stream
            .write_u32::<BigEndian>(SecurityResult::Failed as u32)?;
        let reason_len = reason.len() as u32;
        self.stream.write_u32::<BigEndian>(reason_len)?;
        self.stream.write_all(reason.as_bytes())?;
        self.stream.flush()?;
        Ok(())
    }

    /// Send a framebuffer update header with N rectangles.
    pub fn send_fb_update_header(&mut self, n_rects: u16) -> io::Result<()> {
        self.stream
            .write_u8(ServerMsgType::FramebufferUpdate as u8)?;
        self.stream.write_u8(0)?; // padding
        self.stream.write_u16::<BigEndian>(n_rects)?;
        self.bytes_sent += 4;
        Ok(())
    }

    /// Send a raw rectangle.
    pub fn send_raw_rect(&mut self, rect: &FbRect) -> io::Result<()> {
        rect.write_header(&mut self.stream)?;
        self.stream.write_all(&rect.data)?;
        self.bytes_sent += 12 + rect.data.len() as u64;
        Ok(())
    }

    /// Send a ZRLE rectangle (data is already zlib-compressed).
    pub fn send_zrle_rect(&mut self, rect: &FbRect) -> io::Result<()> {
        rect.write_header(&mut self.stream)?;
        self.stream.write_all(&rect.data)?;
        self.bytes_sent += 12 + rect.data.len() as u64;
        Ok(())
    }

    /// Send a Tight rectangle.
    pub fn send_tight_rect(&mut self, rect: &FbRect) -> io::Result<()> {
        rect.write_header(&mut self.stream)?;
        self.stream.write_all(&rect.data)?;
        self.bytes_sent += 12 + rect.data.len() as u64;
        Ok(())
    }

    /// Send a Hextile rectangle.
    pub fn send_hextile_rect(&mut self, rect: &FbRect) -> io::Result<()> {
        rect.write_header(&mut self.stream)?;
        self.stream.write_all(&rect.data)?;
        self.bytes_sent += 12 + rect.data.len() as u64;
        Ok(())
    }

    /// Flush the stream and increment frame counter.
    pub fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()?;
        self.frames_sent += 1;
        Ok(())
    }

    /// Check if the client has a specific encoding.
    pub fn has_encoding(&self, enc: Encoding) -> bool {
        self.encodings.contains(&enc)
    }

    /// Mark a frame as sent, decrement pending requests, and clear damage.
    pub fn frame_sent(&mut self) {
        if self.pending_requests > 0 {
            self.pending_requests -= 1;
        }
        self.damage.clear();
    }
}

fn encoding_from_i32(v: i32) -> Option<Encoding> {
    match v {
        0 => Some(Encoding::Raw),
        1 => Some(Encoding::CopyRect),
        2 => Some(Encoding::Rre),
        5 => Some(Encoding::Hextile),
        7 => Some(Encoding::Tight),
        15 => Some(Encoding::Trle),
        16 => Some(Encoding::Zrle),
        50 => Some(Encoding::OpenH264),
        -239 => Some(Encoding::Cursor),
        -223 => Some(Encoding::DesktopSize),
        -307 => Some(Encoding::DesktopName),
        -308 => Some(Encoding::ExtendedDesktopSize),
        -312 => Some(Encoding::Fence),
        -313 => Some(Encoding::ContinuousUpdates),
        -316 => Some(Encoding::ExtMouseButtons),
        -258 => Some(Encoding::QemuExtKeyEvent),
        -1063131698 => Some(Encoding::ExtendedClipboard),
        _ => None,
    }
}
