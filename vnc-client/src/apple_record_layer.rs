//! Apple high-performance encrypted record layer.
//!
//! After the initial plaintext rekey rectangle (encoding `0x44f`), the control
//! channel is wrapped in AES-128-CBC records. Each record is:
//!
//! ```text
//! u16 BE ciphertext_len  (multiple of 16)
//! byte[ciphertext_len]   ciphertext
//! ```
//!
//! Inside the ciphertext (after CBC decryption):
//!
//! ```text
//! u16 BE body_len
//! byte[body_len] body
//! byte[filler_len] filler (zero, to make (2 + body_len + 20) a multiple of 16)
//! byte[20] integrity = SHA1(u32_be(seq) || everything before the mac)
//! ```
//!
//! Send and receive sequence counters start at zero and are never reset. Rekey
//! rectangles contain a new AES-128-CBC key/IV wrapped with the current wrap key
//! using AES-128-ECB.

use std::io::{self, Read, Write};
use std::net::TcpStream;

use aes::cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use sha1::{Digest, Sha1};

use crate::{protocol, VncError};

const BLOCK_LEN: usize = 16;
const MAC_LEN: usize = 20;

/// Size of a single display mode entry inside a `SetDisplayConfiguration` descriptor.
const DISPLAY_MODE_ENTRY_LEN: usize = 28;
/// Size of the fixed portion of a display descriptor (before the mode table).
const DISPLAY_DESCRIPTOR_HEADER_LEN: usize = 0x9c;

/// Apple high-performance encrypted record layer.
///
/// Generic over the underlying transport so that unit tests can use
/// [`std::io::Cursor`]; production code uses a [`TcpStream`].
pub struct AppleRecordLayer<S: Read + Write = TcpStream> {
    inner: S,
    enc_cipher: Aes128,
    dec_cipher: Aes128,
    enc_iv: [u8; BLOCK_LEN],
    dec_iv: [u8; BLOCK_LEN],
    enc_seq: u32,
    dec_seq: u32,
    wrap_key: [u8; BLOCK_LEN],
    /// Current AES-128 content key used for CBC records and for ECB-encrypting
    /// Apple HP `EncryptedInputEvent` (0x10) messages.
    content_key: [u8; BLOCK_LEN],
    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
}

impl<S: Read + Write> AppleRecordLayer<S> {
    /// Create the record layer from the first plaintext `0x44f` rekey body.
    ///
    /// `wrap_key` is the 16-byte AES wrap key derived from the authentication
    /// branch (e.g. `SHA256(SRP_K)[0..16]` for type 33). `rekey_body` is the
    /// 36-byte rectangle payload: `u32 generation || 16-byte enc_key || 16-byte enc_iv`.
    pub fn new_from_rekey(inner: S, wrap_key: &[u8], rekey_body: &[u8]) -> Result<Self, VncError> {
        if wrap_key.len() != BLOCK_LEN {
            return Err(VncError::Protocol(format!(
                "Apple record layer wrap key must be {} bytes, got {}",
                BLOCK_LEN,
                wrap_key.len()
            )));
        }
        if rekey_body.len() != 36 {
            return Err(VncError::Protocol(format!(
                "Apple rekey body must be 36 bytes, got {}",
                rekey_body.len()
            )));
        }
        let (key, iv) = Self::unwrap_rekey(wrap_key, rekey_body)?;
        let mut wrap = [0u8; BLOCK_LEN];
        wrap.copy_from_slice(wrap_key);
        Ok(Self::new(inner, wrap, key, iv))
    }

    /// Apply a mid-session rekey rectangle.
    ///
    /// The new key/IV are AES-128-ECB-unwrapped under the current wrap key, then
    /// installed as the new CBC state for both directions and as the new wrap key.
    pub fn rekey(&mut self, rekey_body: &[u8]) -> Result<(), VncError> {
        let (key, iv) = Self::unwrap_rekey(&self.wrap_key, rekey_body)?;
        self.enc_cipher = Aes128::new_from_slice(&key)
            .map_err(|e| VncError::Protocol(format!("Invalid AES key: {:?}", e)))?;
        self.dec_cipher = Aes128::new_from_slice(&key)
            .map_err(|e| VncError::Protocol(format!("Invalid AES key: {:?}", e)))?;
        self.enc_iv = iv;
        self.dec_iv = iv;
        self.wrap_key = key;
        self.content_key = key;
        Ok(())
    }

    fn new(inner: S, wrap_key: [u8; BLOCK_LEN], key: [u8; BLOCK_LEN], iv: [u8; BLOCK_LEN]) -> Self {
        let enc_cipher = Aes128::new_from_slice(&key).expect("valid AES-128 key length");
        let dec_cipher = Aes128::new_from_slice(&key).expect("valid AES-128 key length");
        Self {
            inner,
            enc_cipher,
            dec_cipher,
            enc_iv: iv,
            dec_iv: iv,
            enc_seq: 0,
            dec_seq: 0,
            wrap_key,
            content_key: key,
            read_buf: Vec::new(),
            write_buf: Vec::new(),
        }
    }

    fn unwrap_rekey(
        wrap_key: &[u8],
        rekey_body: &[u8],
    ) -> Result<([u8; BLOCK_LEN], [u8; BLOCK_LEN]), VncError> {
        let cipher = Aes128::new_from_slice(wrap_key)
            .map_err(|e| VncError::Protocol(format!("Invalid wrap key: {:?}", e)))?;
        let mut key = [0u8; BLOCK_LEN];
        let mut iv = [0u8; BLOCK_LEN];
        key.copy_from_slice(&rekey_body[4..20]);
        iv.copy_from_slice(&rekey_body[20..36]);
        let mut key_block = Block::<Aes128>::clone_from_slice(&key);
        let mut iv_block = Block::<Aes128>::clone_from_slice(&iv);
        cipher.decrypt_block(&mut key_block);
        cipher.decrypt_block(&mut iv_block);
        key.copy_from_slice(&key_block);
        iv.copy_from_slice(&iv_block);
        Ok((key, iv))
    }

    fn cbc_encrypt(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) {
        assert_eq!(plaintext.len(), ciphertext.len());
        assert_eq!(plaintext.len() % BLOCK_LEN, 0);
        let mut iv = self.enc_iv;
        for (pt, ct) in plaintext
            .chunks(BLOCK_LEN)
            .zip(ciphertext.chunks_mut(BLOCK_LEN))
        {
            let mut block = Block::<Aes128>::clone_from_slice(pt);
            for i in 0..BLOCK_LEN {
                block[i] ^= iv[i];
            }
            self.enc_cipher.encrypt_block(&mut block);
            ct.copy_from_slice(&block);
            iv.copy_from_slice(&block);
        }
        self.enc_iv = iv;
    }

    fn cbc_decrypt(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) {
        assert_eq!(ciphertext.len(), plaintext.len());
        assert_eq!(ciphertext.len() % BLOCK_LEN, 0);
        let mut iv = self.dec_iv;
        for (ct, pt) in ciphertext
            .chunks(BLOCK_LEN)
            .zip(plaintext.chunks_mut(BLOCK_LEN))
        {
            let mut block = Block::<Aes128>::clone_from_slice(ct);
            self.dec_cipher.decrypt_block(&mut block);
            for i in 0..BLOCK_LEN {
                block[i] ^= iv[i];
            }
            pt.copy_from_slice(&block);
            iv.copy_from_slice(ct);
        }
        self.dec_iv = iv;
    }

    fn integrity(seq: u32, body: &[u8]) -> [u8; MAC_LEN] {
        let mut hasher = Sha1::new();
        hasher.update(seq.to_be_bytes());
        hasher.update(body);
        hasher.finalize().into()
    }

    /// Encrypt a 16-byte input-event block with the current content key using
    /// AES-128-ECB. This is used for Apple HP `EncryptedInputEvent` (0x10)
    /// messages; the whole 16-byte plaintext is encrypted in place as one block.
    fn encrypt_input_block(&self, plaintext: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
        let cipher = Aes128::new_from_slice(&self.content_key).expect("valid AES-128 key");
        let mut block = Block::<Aes128>::clone_from_slice(plaintext);
        cipher.encrypt_block(&mut block);
        let mut out = [0u8; BLOCK_LEN];
        out.copy_from_slice(&block);
        out
    }

    fn write_record(&mut self, body: &[u8]) -> io::Result<()> {
        let pad_len = (BLOCK_LEN - ((2 + body.len() + MAC_LEN) % BLOCK_LEN)) % BLOCK_LEN;
        let body_with_len_and_pad_len = 2 + body.len() + pad_len;
        let total_len = body_with_len_and_pad_len + MAC_LEN;
        let mut frame = Vec::with_capacity(total_len);
        frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
        frame.extend_from_slice(body);
        frame.extend_from_slice(&vec![0u8; pad_len]);
        let mac = Self::integrity(self.enc_seq, &frame);
        frame.extend_from_slice(&mac);
        self.enc_seq = self.enc_seq.wrapping_add(1);
        let mut ciphertext = vec![0u8; total_len];
        self.cbc_encrypt(&frame, &mut ciphertext);
        self.inner.write_all(&(total_len as u16).to_be_bytes())?;
        self.inner.write_all(&ciphertext)?;
        Ok(())
    }

    fn read_record(&mut self) -> io::Result<Vec<u8>> {
        let mut len_buf = [0u8; 2];
        self.inner.read_exact(&mut len_buf)?;
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 || !len.is_multiple_of(BLOCK_LEN) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Apple record layer invalid ciphertext length: {}", len),
            ));
        }
        let mut ciphertext = vec![0u8; len];
        self.inner.read_exact(&mut ciphertext)?;
        let mut plaintext = vec![0u8; len];
        self.cbc_decrypt(&ciphertext, &mut plaintext);
        let mac_offset = plaintext.len().checked_sub(MAC_LEN).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Apple record layer plaintext too short for MAC",
            )
        })?;
        let body_with_mac = &plaintext[..mac_offset];
        let mac = &plaintext[mac_offset..];
        let expected = Self::integrity(self.dec_seq, body_with_mac);
        if mac != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Apple record layer integrity check failed",
            ));
        }
        self.dec_seq = self.dec_seq.wrapping_add(1);
        let body_len = u16::from_be_bytes([body_with_mac[0], body_with_mac[1]]) as usize;
        if body_len + 2 > body_with_mac.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Apple record layer body length {} exceeds plaintext {}",
                    body_len,
                    body_with_mac.len()
                ),
            ));
        }
        Ok(body_with_mac[2..2 + body_len].to_vec())
    }

    /// Build an encrypted Apple HP key-event message (0x10, subtype 1).
    ///
    /// The 16-byte plaintext block is AES-128-ECB-encrypted in place with the
    /// current record-layer content key. `key_type` and `key_code` are the Apple
    /// keyboard-type and local-keycode fields; callers that do not have them can
    /// pass `0`.
    pub fn build_encrypted_key_event(
        &self,
        down: bool,
        keysym: u32,
        key_type: u16,
        key_code: u16,
    ) -> Vec<u8> {
        let mut plain = [0u8; BLOCK_LEN];
        plain[0] = 0;
        plain[1] = if down { 1 } else { 0 };
        plain[2..6].copy_from_slice(&keysym.to_be_bytes());
        // bytes 6..9 event_delta left as zero
        // bytes 10..11 unknown_zero left as zero
        plain[12..14].copy_from_slice(&key_type.to_be_bytes());
        plain[14..16].copy_from_slice(&key_code.to_be_bytes());

        let mut msg = Vec::with_capacity(18);
        msg.push(protocol::apple::ENCRYPTED_INPUT_EVENT);
        msg.push(0x01); // subtype 1 = legacy encrypted key event
        msg.extend_from_slice(&self.encrypt_input_block(&plain));
        msg
    }

    /// Build an encrypted Apple HP pointer-event message (0x10, subtype 3).
    ///
    /// The 16-byte plaintext block is AES-128-ECB-encrypted in place with the
    /// current record-layer content key. `button_mask` must be in the Apple HP
    /// wire format (right/middle bits swapped relative to RFC 6143).
    pub fn build_encrypted_pointer_event(&self, button_mask: u8, x: u16, y: u16) -> Vec<u8> {
        let mut plain = [0u8; BLOCK_LEN];
        // bytes 0..5 zero for ordinary move events
        // bytes 6..9 event_delta left as zero
        plain[10] = 0xff; // event marker
        plain[11] = button_mask;
        plain[12..14].copy_from_slice(&x.to_be_bytes());
        plain[14..16].copy_from_slice(&y.to_be_bytes());

        let mut msg = Vec::with_capacity(18);
        msg.push(protocol::apple::ENCRYPTED_INPUT_EVENT);
        msg.push(0x03); // subtype 3 = legacy encrypted mouse event
        msg.extend_from_slice(&self.encrypt_input_block(&plain));
        msg
    }
}

impl AppleRecordLayer<TcpStream> {
    /// Set the read timeout on the underlying TCP socket.
    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    /// Set TCP_NODELAY on the underlying socket.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }
}

impl<S: Read + Write> Read for AppleRecordLayer<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.read_buf.is_empty() {
            self.read_buf = self.read_record()?;
        }
        let n = self.read_buf.len().min(buf.len());
        buf[..n].copy_from_slice(&self.read_buf[..n]);
        self.read_buf.drain(..n);
        Ok(n)
    }
}

impl<S: Read + Write> Write for AppleRecordLayer<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.write_buf.is_empty() {
            let body = std::mem::take(&mut self.write_buf);
            self.write_record(&body)?;
        }
        self.inner.flush()
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.write_buf.extend_from_slice(buf);
        self.flush()
    }
}

/// Apple high-performance encoding list.
///
/// This is the full list advertised by the native client during the HP handshake.
/// It already includes the media-path encodings (`0x3ea` = 1002, `0x3f2` = 1010,
/// `0x3f3` = 1011) because the same numeric values are used for both still-image
/// codec announcements and media-stream reconfiguration rectangles.
///
/// It is sent once in plaintext before the rekey and once encrypted after (via
/// [`vnc_protocol::framing::build_set_encodings`]).
pub const APPLE_HP_ENCODINGS: &[i32] = &[
    1010, 1011, 1002, 6, 16, 1104, 1100, -223, 1101, 1105, 1107, 1109, 1110,
];

/// Build a `ViewerInfo` (0x21) message.
///
/// `extra` is appended after the 32-byte command mask; the native client sends
/// an empty `extra` payload.
pub fn build_viewer_info(extra: &[u8]) -> Vec<u8> {
    // Capability bitmap matching native Screen Sharing.app.
    const MASK: [u8; 32] = [
        0xb0, 0, 0x0c, 0x03, 0x90, 0, 0, 0, 0, 0, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
    ];
    // 32-byte header: type(1) + reserved(1) + msgSize(2) + version(2) + app_id(4)
    // + app_ver(12) + os_ver(12).
    let msg_size = 32 + MASK.len() + extra.len();
    let mut msg = Vec::with_capacity(4 + msg_size);
    msg.push(protocol::apple::VIEWER_INFO);
    msg.push(0);
    msg.extend_from_slice(&(msg_size as u16).to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // version
    msg.extend_from_slice(&2u32.to_be_bytes()); // app_id
    msg.extend_from_slice(&6u32.to_be_bytes()); // app_ver major
    msg.extend_from_slice(&1u32.to_be_bytes()); // app_ver minor
    msg.extend_from_slice(&0u32.to_be_bytes()); // app_ver patch
    msg.extend_from_slice(&15u32.to_be_bytes()); // os_ver major
    msg.extend_from_slice(&3u32.to_be_bytes()); // os_ver minor
    msg.extend_from_slice(&0u32.to_be_bytes()); // os_ver patch
    msg.extend_from_slice(&MASK);
    msg.extend_from_slice(extra);
    msg
}

/// Build a `SetEncryption` (0x12) command=1 message.
pub fn build_set_encryption_command1() -> Vec<u8> {
    vec![
        protocol::apple::SET_ENCRYPTION,
        0x00,
        0x00,
        0x01,
        0x00,
        0x01,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x01,
    ]
}

/// Build a `PostEncryptionToggle` (0x12 command=2) message.
pub fn build_post_encryption_toggle() -> Vec<u8> {
    vec![
        protocol::apple::SET_ENCRYPTION,
        0x00,
        0x00,
        0x02,
        0x00,
        0x01,
        0x00,
        0x00,
    ]
}

/// Build an `AutoFrameBufferUpdate` (0x09) message.
///
/// Arms the server's framebuffer sender so it freely emits cursor updates and
/// framebuffer rectangles. `selected_screen` = `0xffffffff` targets all/main
/// displays.
pub fn build_auto_framebuffer_update(
    selected_screen: u32,
    x: u16,
    y: u16,
    w: u16,
    h: u16,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(16);
    msg.push(protocol::apple::AUTO_FRAMEBUFFER_UPDATE);
    msg.push(0x00);
    msg.extend_from_slice(&1u16.to_be_bytes()); // version
    msg.extend_from_slice(&selected_screen.to_be_bytes());
    msg.extend_from_slice(&x.to_be_bytes());
    msg.extend_from_slice(&y.to_be_bytes());
    msg.extend_from_slice(&w.to_be_bytes());
    msg.extend_from_slice(&h.to_be_bytes());
    msg
}

/// Build a `SetMode` (0x0a) message.
///
/// `mode` = 0 for observe-only, 1 for normal control. Native Screen Sharing.app
/// sends `mode = 1`; the reference client omits this optional message.
pub fn build_set_mode(mode: u16) -> Vec<u8> {
    let mut msg = Vec::with_capacity(4);
    msg.push(protocol::apple::SET_MODE);
    msg.push(0x00);
    msg.extend_from_slice(&mode.to_be_bytes());
    msg
}

/// Build a `ScaleFactor` (0x08) message.
///
/// The server derives an internal downscaling flag from `scale < 1.0`. The value
/// must be positive.
pub fn build_scale_factor(scale: f64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(10);
    msg.push(protocol::apple::SCALE_FACTOR);
    msg.push(0x00);
    msg.extend_from_slice(&scale.to_be_bytes());
    msg
}

/// Build a `SetDisplayMessage` (0x0d) message.
///
/// When `combine_all_displays` is true, `display_id` is ignored and the server
/// selects the combined-display aggregate.
pub fn build_set_display_message(combine_all_displays: bool, display_id: u32) -> Vec<u8> {
    let mut msg = Vec::with_capacity(8);
    msg.push(protocol::apple::SET_DISPLAY_MESSAGE);
    msg.push(if combine_all_displays { 1 } else { 0 });
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&display_id.to_be_bytes());
    msg
}

/// Build an `AutoPasteboard` (0x15) message.
///
/// `selector` = 1 starts local-pasteboard monitoring (universal-clipboard sync);
/// `selector` = 2 stops it. Only values 1 and 2 are accepted by the server.
pub fn build_auto_pasteboard(selector: u8) -> Vec<u8> {
    let mut msg = Vec::with_capacity(8);
    msg.push(protocol::apple::AUTO_PASTEBOARD);
    msg.extend_from_slice(&[0u8; 3]);
    msg.push(selector);
    msg.extend_from_slice(&[0u8; 3]);
    msg
}

/// Build a `SetKeyboardInputSource` (0x1a) message.
///
/// Carries the keyboard input-source identifier (e.g.
/// `"com.apple.keylayout.ABC"`) to the server agent. The string is truncated to
/// `u16::MAX` bytes if necessary.
pub fn build_set_keyboard_input_source(source_id: &str) -> Vec<u8> {
    let id_bytes = source_id.as_bytes();
    let id_len = id_bytes.len().min(u16::MAX as usize) as u16;
    let size = 4 + id_len as usize; // message_version + id_len + source_id
    let mut msg = Vec::with_capacity(3 + size);
    msg.push(protocol::apple::SET_KEYBOARD_INPUT_SOURCE);
    msg.extend_from_slice(&(size as u16).to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // message_version
    msg.extend_from_slice(&id_len.to_be_bytes());
    msg.extend_from_slice(&id_bytes[..id_len as usize]);
    msg
}

/// Build a `ClipboardFetch` (0x0b) message.
///
/// Sent by the viewer after a `MiscStatus` (0x14) `cmd = 2` to pull the updated
/// remote pasteboard.
pub fn build_clipboard_fetch() -> Vec<u8> {
    vec![protocol::apple::CLIPBOARD_FETCH]
}

/// Native mode-table template used by macOS Screen Sharing.app.
///
/// Each tuple is `(pixel_width, pixel_height, point_width, point_height)` for a
/// 2× (Retina) backing:point ratio. The template is scaled to the requested
/// logical size when building `SetDisplayConfiguration`.
const NATIVE_MODES: &[(u32, u32, u32, u32)] = &[
    (3840, 2160, 1920, 1080),
    (2880, 1800, 1440, 900),
    (3840, 2160, 1920, 1080),
    (2880, 1620, 1440, 810),
    (2624, 1696, 1312, 848),
];

/// Build a `SetDisplayConfiguration` (0x1d) message for a single virtual display.
///
/// The descriptor carries one display with a heterogeneous five-entry mode table
/// matching the native Screen Sharing.app handshake. When `dynamic` is true,
/// the dynamic-resolution flag is set and `display_type` is `4` (virtual
/// display), which is required to request in-band resizes. `hidpi_scale`
/// controls the backing:point ratio advertised in the mode table: `2.0` requests
/// a Retina-style virtual display, `1.0` requests a flat 1:1 display (lower
/// bandwidth for non-Retina clients).
pub fn build_set_display_configuration(
    width: u16,
    height: u16,
    dynamic: bool,
    hidpi_scale: f32,
) -> Vec<u8> {
    let mode_count: u16 = NATIVE_MODES.len() as u16;
    let descriptor_size =
        DISPLAY_DESCRIPTOR_HEADER_LEN + mode_count as usize * DISPLAY_MODE_ENTRY_LEN;
    let mode_table_size = mode_count as usize * DISPLAY_MODE_ENTRY_LEN;
    let message_size = 0x0c - 4 + descriptor_size; // body length after the 4-byte prefix

    let display_flags = if dynamic {
        protocol::apple::DISPLAY_FLAG_DYNAMIC
    } else {
        0
    };
    let display_type = if dynamic {
        protocol::apple::DISPLAY_TYPE_VIRTUAL
    } else {
        protocol::apple::DISPLAY_TYPE_PHYSICAL
    };
    // `reserved` at descriptor +0x96. The native client emits 7; earlier
    // reverse-engineering treated this as a rotations count and used 0, but
    // live captures show 7 on the standard console-user path.
    let reserved: u32 = 7;
    // Physical dimensions measured from native Screen Sharing.app traffic.
    // The exact f32 values are preserved for wire parity with the native client.
    #[allow(clippy::excessive_precision)]
    let physical_width_mm = 369.4545593261719_f32;
    #[allow(clippy::excessive_precision)]
    let physical_height_mm = 207.81817626953125_f32;
    // max_width/max_height bound the backing geometry; native advertises 4K.
    let max_width: u32 = 3840;
    let max_height: u32 = 2160;
    let current_mode_index: u16 = 0;
    let preferred_mode_index: u16 = 0;

    let mut msg = Vec::with_capacity(4 + message_size);
    msg.push(protocol::apple::SET_DISPLAY_CONFIGURATION);
    msg.push(0x00);
    msg.extend_from_slice(&(message_size as u16).to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // version
    msg.extend_from_slice(&1u16.to_be_bytes()); // display_count
    msg.extend_from_slice(&0u32.to_be_bytes()); // flags

    // Display descriptor.
    msg.extend_from_slice(&(descriptor_size as u16).to_be_bytes()); // display_info_size
                                                                    // display_info_region: 120 opaque bytes (D+0x02..=D+0x79), NUL at D+0x79.
    let info_region_start = msg.len();
    msg.resize(msg.len() + 120, 0);
    // Ensure the byte at D+0x79 is NUL (already zero from resize).
    debug_assert_eq!(msg.len() - info_region_start, 120);
    msg.extend_from_slice(&display_flags.to_be_bytes());
    msg.extend_from_slice(&display_type.to_be_bytes());
    msg.extend_from_slice(&physical_width_mm.to_be_bytes());
    msg.extend_from_slice(&physical_height_mm.to_be_bytes());
    msg.extend_from_slice(&max_width.to_be_bytes());
    msg.extend_from_slice(&max_height.to_be_bytes());
    msg.extend_from_slice(&current_mode_index.to_be_bytes());
    msg.extend_from_slice(&preferred_mode_index.to_be_bytes());
    msg.extend_from_slice(&reserved.to_be_bytes());
    msg.extend_from_slice(&mode_count.to_be_bytes());

    // Mode table entries, scaled to the requested logical size. `width`/`height`
    // are the logical (point) target; the pixel backing dims are multiplied by
    // `hidpi_scale`.
    let sx = if width > 0 {
        f64::from(width) / 1920.0
    } else {
        1.0
    };
    let sy = if height > 0 {
        f64::from(height) / 1080.0
    } else {
        1.0
    };
    let hidpi_scale = f64::from(hidpi_scale);
    let refresh_rate = 60.0_f64;
    let mode_flags: u32 = 0;

    for &(_pw, _ph, pt_w, pt_h) in NATIVE_MODES {
        let scaled_pt_w = (f64::from(pt_w) * sx + 0.5) as u32;
        let scaled_pt_h = (f64::from(pt_h) * sy + 0.5) as u32;
        let scaled_px_w = (f64::from(scaled_pt_w) * hidpi_scale + 0.5) as u32;
        let scaled_px_h = (f64::from(scaled_pt_h) * hidpi_scale + 0.5) as u32;
        msg.extend_from_slice(&scaled_px_w.to_be_bytes());
        msg.extend_from_slice(&scaled_px_h.to_be_bytes());
        msg.extend_from_slice(&scaled_pt_w.to_be_bytes());
        msg.extend_from_slice(&scaled_pt_h.to_be_bytes());
        msg.extend_from_slice(&refresh_rate.to_be_bytes());
        msg.extend_from_slice(&mode_flags.to_be_bytes());
    }

    // Sanity check: the size calculations must agree.
    debug_assert_eq!(msg.len(), 4 + message_size);
    debug_assert_eq!(mode_table_size, NATIVE_MODES.len() * DISPLAY_MODE_ENTRY_LEN);

    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn test_layer() -> AppleRecordLayer<Cursor<Vec<u8>>> {
        let inner = Cursor::new(Vec::new());
        let wrap_key = [0u8; 16];
        let key = [1u8; 16];
        let iv = [2u8; 16];
        AppleRecordLayer::new(inner, wrap_key, key, iv)
    }

    #[test]
    fn roundtrip_record() {
        let mut layer = test_layer();
        let msg = b"hello Apple HP record layer";
        layer.write_all(msg).unwrap();
        let written = layer.inner.into_inner();
        // Verify ciphertext length is a non-zero multiple of 16 and is prefixed by u16.
        let ct_len = u16::from_be_bytes([written[0], written[1]]) as usize;
        assert!(ct_len > 0 && ct_len.is_multiple_of(16));
        // Read it back from a fresh cursor.
        let read_cursor = Cursor::new(written);
        let mut layer2 = AppleRecordLayer::new(read_cursor, [0u8; 16], [1u8; 16], [2u8; 16]);
        let mut out = [0u8; 128];
        let n = layer2.read(&mut out).unwrap();
        assert_eq!(&out[..n], msg.as_slice());
    }

    #[test]
    fn rekey_updates_keys() {
        let mut layer = test_layer();
        // Rekey body: 4-byte generation + 16-byte enc_key + 16-byte enc_iv.
        // The enc_key/iv are the current key/iv encrypted under the current wrap key.
        // Since wrap_key is all zeros, the ECB-decrypt will invert the block.
        let mut rekey = vec![0u8; 36];
        rekey[4..20].copy_from_slice(&[1u8; 16]);
        rekey[20..36].copy_from_slice(&[2u8; 16]);
        layer.rekey(&rekey).unwrap();
        // After rekey, we can still encrypt and decrypt a record.
        layer.write_all(b"post-rekey").unwrap();
        let written = layer.inner.into_inner();
        let read_cursor = Cursor::new(written);
        let mut layer2 = AppleRecordLayer::new(read_cursor, [0u8; 16], [1u8; 16], [2u8; 16]);
        // layer2 must also rekey to the same new key before it can read.
        layer2.rekey(&rekey).unwrap();
        let mut out = [0u8; 32];
        let n = layer2.read(&mut out).unwrap();
        assert_eq!(&out[..n], b"post-rekey");
    }

    #[test]
    fn auto_framebuffer_update_format() {
        let msg =
            build_auto_framebuffer_update(protocol::apple::SELECTED_SCREEN_ALL, 0, 0, 1920, 1080);
        assert_eq!(msg.len(), 16);
        assert_eq!(msg[0], protocol::apple::AUTO_FRAMEBUFFER_UPDATE);
        assert_eq!(u16::from_be_bytes([msg[2], msg[3]]), 1); // version
        assert_eq!(
            u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]),
            protocol::apple::SELECTED_SCREEN_ALL
        );
        assert_eq!(u16::from_be_bytes([msg[8], msg[9]]), 0);
        assert_eq!(u16::from_be_bytes([msg[10], msg[11]]), 0);
        assert_eq!(u16::from_be_bytes([msg[12], msg[13]]), 1920);
        assert_eq!(u16::from_be_bytes([msg[14], msg[15]]), 1080);
    }

    #[test]
    fn set_display_configuration_format() {
        let msg = build_set_display_configuration(1920, 1080, true, 2.0);
        assert_eq!(msg[0], protocol::apple::SET_DISPLAY_CONFIGURATION);
        let message_size = u16::from_be_bytes([msg[2], msg[3]]) as usize;
        assert_eq!(msg.len(), 4 + message_size);
        assert_eq!(u16::from_be_bytes([msg[4], msg[5]]), 1); // version
        assert_eq!(u16::from_be_bytes([msg[6], msg[7]]), 1); // display_count
        assert_eq!(u32::from_be_bytes([msg[8], msg[9], msg[10], msg[11]]), 0); // flags

        // Display descriptor starts at offset 12.
        let descriptor_size = u16::from_be_bytes([msg[12], msg[13]]) as usize;
        assert_eq!(descriptor_size, 0x9c + 5 * DISPLAY_MODE_ENTRY_LEN);
        // display_info_region ends with a NUL at D+0x79 (offset 12 + 0x79).
        assert_eq!(msg[12 + 0x79], 0);
        // display_flags at D+0x7a.
        assert_eq!(
            u32::from_be_bytes([
                msg[12 + 0x7a],
                msg[12 + 0x7b],
                msg[12 + 0x7c],
                msg[12 + 0x7d]
            ]),
            protocol::apple::DISPLAY_FLAG_DYNAMIC
        );
        // display_type at D+0x7e.
        assert_eq!(
            u32::from_be_bytes([
                msg[12 + 0x7e],
                msg[12 + 0x7f],
                msg[12 + 0x80],
                msg[12 + 0x81]
            ]),
            protocol::apple::DISPLAY_TYPE_VIRTUAL
        );
        // reserved at D+0x96 — native Screen Sharing.app emits 7.
        assert_eq!(
            u32::from_be_bytes([
                msg[12 + 0x96],
                msg[12 + 0x97],
                msg[12 + 0x98],
                msg[12 + 0x99]
            ]),
            7
        );
        // mode_count at D+0x9a.
        assert_eq!(u16::from_be_bytes([msg[12 + 0x9a], msg[12 + 0x9b]]), 5);

        // Mode table entry 0 starts at D+0x9c. For 1920×1080 @ 2× scale this is
        // the first native template un-scaled.
        let mode_off = 12 + 0x9c;
        assert_eq!(
            u32::from_be_bytes([
                msg[mode_off],
                msg[mode_off + 1],
                msg[mode_off + 2],
                msg[mode_off + 3]
            ]),
            3840
        );
        assert_eq!(
            u32::from_be_bytes([
                msg[mode_off + 4],
                msg[mode_off + 5],
                msg[mode_off + 6],
                msg[mode_off + 7]
            ]),
            2160
        );
        assert_eq!(
            u32::from_be_bytes([
                msg[mode_off + 8],
                msg[mode_off + 9],
                msg[mode_off + 10],
                msg[mode_off + 11]
            ]),
            1920
        );
        assert_eq!(
            u32::from_be_bytes([
                msg[mode_off + 12],
                msg[mode_off + 13],
                msg[mode_off + 14],
                msg[mode_off + 15]
            ]),
            1080
        );
    }

    #[test]
    fn set_display_configuration_flat_session() {
        let msg = build_set_display_configuration(1280, 720, false, 1.0);
        let descriptor_size = u16::from_be_bytes([msg[12], msg[13]]) as usize;
        assert_eq!(descriptor_size, 0x9c + 5 * DISPLAY_MODE_ENTRY_LEN);
        assert_eq!(
            u32::from_be_bytes([
                msg[12 + 0x7a],
                msg[12 + 0x7b],
                msg[12 + 0x7c],
                msg[12 + 0x7d]
            ]),
            0
        );
        assert_eq!(
            u32::from_be_bytes([
                msg[12 + 0x7e],
                msg[12 + 0x7f],
                msg[12 + 0x80],
                msg[12 + 0x81]
            ]),
            protocol::apple::DISPLAY_TYPE_PHYSICAL
        );

        // Mode table entry 0 for 1280×720 @ 1× scale.
        let mode_off = 12 + 0x9c;
        assert_eq!(
            u32::from_be_bytes([
                msg[mode_off],
                msg[mode_off + 1],
                msg[mode_off + 2],
                msg[mode_off + 3]
            ]),
            1280
        );
        assert_eq!(
            u32::from_be_bytes([
                msg[mode_off + 4],
                msg[mode_off + 5],
                msg[mode_off + 6],
                msg[mode_off + 7]
            ]),
            720
        );
    }

    #[test]
    fn content_key_tracks_rekey() {
        let mut layer = test_layer();
        assert_eq!(layer.content_key, [1u8; 16]);
        let mut rekey = vec![0u8; 36];
        rekey[4..20].copy_from_slice(&[3u8; 16]);
        rekey[20..36].copy_from_slice(&[4u8; 16]);
        layer.rekey(&rekey).unwrap();
        // After rekey, the content key should be the unwrapped new key.
        assert_ne!(layer.content_key, [1u8; 16]);
    }

    #[test]
    fn encrypted_key_event_format() {
        let layer = test_layer();
        let msg = layer.build_encrypted_key_event(true, 0x61, 0, 0);
        assert_eq!(msg.len(), 18);
        assert_eq!(msg[0], protocol::apple::ENCRYPTED_INPUT_EVENT);
        assert_eq!(msg[1], 0x01); // subtype 1

        // Decrypt the 16-byte block with the content key (ECB).
        let cipher = Aes128::new_from_slice(&layer.content_key).unwrap();
        let mut block = Block::<Aes128>::clone_from_slice(&msg[2..18]);
        cipher.decrypt_block(&mut block);
        assert_eq!(block[0], 0);
        assert_eq!(block[1], 1); // down
        assert_eq!(
            u32::from_be_bytes([block[2], block[3], block[4], block[5]]),
            0x61
        );
        // bytes 6..11 left as zero, key_type and key_code zero.
        assert_eq!(u16::from_be_bytes([block[12], block[13]]), 0);
        assert_eq!(u16::from_be_bytes([block[14], block[15]]), 0);
    }

    #[test]
    fn encrypted_pointer_event_format() {
        let layer = test_layer();
        let msg = layer.build_encrypted_pointer_event(0x05, 100, 200);
        assert_eq!(msg.len(), 18);
        assert_eq!(msg[0], protocol::apple::ENCRYPTED_INPUT_EVENT);
        assert_eq!(msg[1], 0x03); // subtype 3

        let cipher = Aes128::new_from_slice(&layer.content_key).unwrap();
        let mut block = Block::<Aes128>::clone_from_slice(&msg[2..18]);
        cipher.decrypt_block(&mut block);
        assert_eq!(block[10], 0xff); // event marker
        assert_eq!(block[11], 0x05); // button mask
        assert_eq!(u16::from_be_bytes([block[12], block[13]]), 100);
        assert_eq!(u16::from_be_bytes([block[14], block[15]]), 200);
    }

    #[test]
    fn set_mode_format() {
        let msg = build_set_mode(1);
        assert_eq!(msg.len(), 4);
        assert_eq!(msg[0], protocol::apple::SET_MODE);
        assert_eq!(u16::from_be_bytes([msg[2], msg[3]]), 1);
    }

    #[test]
    fn scale_factor_format() {
        let msg = build_scale_factor(2.0);
        assert_eq!(msg.len(), 10);
        assert_eq!(msg[0], protocol::apple::SCALE_FACTOR);
        assert_eq!(f64::from_be_bytes(msg[2..10].try_into().unwrap()), 2.0);
    }

    #[test]
    fn set_display_message_format() {
        let msg = build_set_display_message(true, 0x12345678);
        assert_eq!(msg.len(), 8);
        assert_eq!(msg[0], protocol::apple::SET_DISPLAY_MESSAGE);
        assert_eq!(msg[1], 1);
        assert_eq!(u16::from_be_bytes([msg[2], msg[3]]), 0);
        assert_eq!(
            u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]),
            0x12345678
        );
    }

    #[test]
    fn auto_pasteboard_format() {
        let msg = build_auto_pasteboard(1);
        assert_eq!(msg.len(), 8);
        assert_eq!(msg[0], protocol::apple::AUTO_PASTEBOARD);
        assert_eq!(msg[4], 1);
    }

    #[test]
    fn set_keyboard_input_source_format() {
        let msg = build_set_keyboard_input_source("com.apple.keylayout.ABC");
        assert_eq!(msg[0], protocol::apple::SET_KEYBOARD_INPUT_SOURCE);
        let size = u16::from_be_bytes([msg[1], msg[2]]) as usize;
        assert_eq!(msg.len(), 3 + size);
        assert_eq!(u16::from_be_bytes([msg[3], msg[4]]), 1); // message_version
        assert_eq!(u16::from_be_bytes([msg[5], msg[6]]), 23); // id_len
        assert_eq!(&msg[7..], b"com.apple.keylayout.ABC");
    }

    #[test]
    fn clipboard_fetch_format() {
        let msg = build_clipboard_fetch();
        assert_eq!(msg.len(), 1);
        assert_eq!(msg[0], protocol::apple::CLIPBOARD_FETCH);
    }
}
