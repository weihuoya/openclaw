//! RSA-AES authentication and AES-CTR stream encryption.
//!
//! Shared implementation used by both `vnc-client` and `vnc-server` for RFB
//! Security Types 5 (RSA-AES) and 129 (RSA-AES-256).
//!
//! Handshake flow:
//! 1. Server generates an RSA key pair and sends the public key (ASN.1 DER,
//!    length-prefixed) to the client.
//! 2. The client generates an AES key and encrypts it with RSA-OAEP-SHA256.
//! 3. The client sends the encrypted key (length-prefixed) back.
//! 4. Both sides switch to AES-128-CTR or AES-256-CTR (zero IV) immediately
//!    after the client's encrypted session key has been sent. The server
//!    sends the security-result (0 = OK) as the first *encrypted* message;
//!    all subsequent traffic is encrypted as well. This matches the RA2
//!    behavior of TigerVNC (`CSecurityRSAAES::setCipher`) and neatvnc
//!    (`stream_upgrade_to_rsa_eas` in `src/auth/rsa-aes.c`), where the
//!    channel is encrypted from the moment the session keys are established.
//!
//! Security note: this implementation uses the same AES key and zero IV for both
//! directions, as specified by the RSA-AES VeNCrypt variant. This means both
//! directions share the same keystream, which is a known protocol limitation.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use aes::{Aes128, Aes256};
use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

use crate::error::ProtocolError;

/// Maximum encrypted AES key length accepted by the server-side receiver.
pub const MAX_ENCRYPTED_KEY_LEN: usize = 4096;

/// Maximum RSA public key (ASN.1 DER) length accepted by the client.
///
/// A 2048-bit RSA public key in DER form is about 294 bytes; TigerVNC accepts
/// RSA keys up to 8192 bits, so 4096 bytes is generous while preventing a
/// malicious server from forcing a multi-gigabyte allocation.
const MAX_PUBLIC_KEY_LEN: usize = 4096;

/// Parse a client→server encrypted-key frame (u32 BE length prefix + RSA
/// ciphertext) from a buffer starting at the length prefix.
///
/// Returns `None` when the buffer does not yet hold the complete frame; a
/// length above [`MAX_ENCRYPTED_KEY_LEN`] is a protocol error, not a
/// need-more-data signal. On success the returned slice borrows the
/// ciphertext (without the length prefix) from `buf`.
pub fn parse_encrypted_key_frame(buf: &[u8]) -> Option<Result<&[u8], ProtocolError>> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_ENCRYPTED_KEY_LEN {
        return Some(Err(ProtocolError::Protocol(format!(
            "encrypted AES key too large: {}",
            len
        ))));
    }
    if buf.len() < 4 + len {
        return None;
    }
    Some(Ok(&buf[4..4 + len]))
}

/// AES-CTR cipher that supports both AES-128 and AES-256.
enum AesCtr {
    Aes128(Box<ctr::Ctr128BE<Aes128>>),
    Aes256(Box<ctr::Ctr128BE<Aes256>>),
}

impl AesCtr {
    fn new(key: &[u8], iv: &[u8]) -> io::Result<Self> {
        match key.len() {
            16 => {
                let cipher = ctr::Ctr128BE::<Aes128>::new_from_slices(key, iv).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "failed to create AES-128 cipher",
                    )
                })?;
                Ok(Self::Aes128(Box::new(cipher)))
            }
            32 => {
                let cipher = ctr::Ctr128BE::<Aes256>::new_from_slices(key, iv).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "failed to create AES-256 cipher",
                    )
                })?;
                Ok(Self::Aes256(Box::new(cipher)))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "AES key must be 16 (AES-128) or 32 (AES-256) bytes",
            )),
        }
    }

    fn apply(&mut self, data: &mut [u8]) {
        match self {
            Self::Aes128(c) => c.apply_keystream(data),
            Self::Aes256(c) => c.apply_keystream(data),
        }
    }
}

/// AES-CTR encrypted stream wrapper.
///
/// Wraps an inner stream (a [`TcpStream`] in practice) and applies AES-CTR
/// encryption/decryption to all read/write operations. Separate cipher states
/// are maintained for each direction.
///
/// Plaintext passed to [`write`](Write::write) is buffered and encrypted on
/// [`flush`](Write::flush). The resulting ciphertext is queued internally and
/// written to the underlying stream incrementally: if the socket accepts only
/// part of the data (or fails, e.g. with [`io::ErrorKind::WouldBlock`] on a
/// non-blocking socket), the unwritten ciphertext stays queued and the CTR
/// counter stays in sync with the bytes actually sent. Retrying `flush()`
/// resumes exactly where the previous attempt stopped — no byte is lost or
/// sent twice.
pub struct AesCtrStream<S = TcpStream> {
    inner: S,
    read_cipher: AesCtr,
    write_cipher: AesCtr,
    /// Buffered plaintext waiting to be encrypted and sent.
    write_buffer: Vec<u8>,
    /// Ciphertext queued for the underlying stream.
    pending: Vec<u8>,
    /// Number of bytes of `pending` already written to the stream.
    pending_pos: usize,
}

impl<S: Read + Write> AesCtrStream<S> {
    /// Wrap a stream with AES-CTR encryption using the given key.
    pub fn new(inner: S, key: &[u8]) -> io::Result<Self> {
        let iv = vec![0u8; 16];
        Ok(Self {
            read_cipher: AesCtr::new(key, &iv)?,
            write_cipher: AesCtr::new(key, &iv)?,
            write_buffer: Vec::new(),
            pending: Vec::new(),
            pending_pos: 0,
            inner,
        })
    }

    /// Decrypt (in place) bytes that were read from the underlying stream
    /// *before* it was wrapped in AES-CTR — for example a pipelined message
    /// that arrived in the same TCP segment as the handshake and was pulled
    /// into an application read buffer ahead of the upgrade. The read cipher
    /// advances exactly as if the bytes had arrived via [`Read::read`], so
    /// subsequent reads stay in sync.
    pub fn decrypt_buffered(&mut self, data: &mut [u8]) {
        self.read_cipher.apply(data);
    }

    /// True when every plaintext and ciphertext byte queued for sending has
    /// been written to the underlying stream.
    pub fn is_write_idle(&self) -> bool {
        self.write_buffer.is_empty() && self.pending.is_empty()
    }

    /// Number of bytes queued for sending (buffered plaintext plus unwritten
    /// ciphertext).
    pub fn queued_bytes(&self) -> usize {
        self.write_buffer.len() + (self.pending.len() - self.pending_pos)
    }
}

impl AesCtrStream<TcpStream> {
    /// Return the peer address of the underlying TCP stream.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    /// Set the read timeout of the underlying TCP stream.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    /// Set the TCP_NODELAY option of the underlying TCP stream.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }
}

impl<S: Read + Write> Read for AesCtrStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.read_cipher.apply(&mut buf[..n]);
        }
        Ok(n)
    }
}

impl<S: Read + Write> Write for AesCtrStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Buffer plaintext; encryption is deferred to flush() so that
        // partial writes on the underlying stream cannot leave the CTR
        // counter out of sync.
        self.write_buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.write_buffer.is_empty() {
            // Encrypt the buffered plaintext and queue it behind any
            // ciphertext left over from an earlier partial flush. The cipher
            // counter advances exactly once per byte here; delivery of the
            // queued ciphertext is tracked separately below, so a failed
            // write can never lose data or desynchronize the stream.
            let mut encrypted = std::mem::take(&mut self.write_buffer);
            self.write_cipher.apply(&mut encrypted);
            self.pending.append(&mut encrypted);
        }
        while self.pending_pos < self.pending.len() {
            match self.inner.write(&self.pending[self.pending_pos..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write encrypted data",
                    ));
                }
                Ok(n) => self.pending_pos += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                // WouldBlock and other errors leave the unwritten ciphertext
                // queued so the caller can retry flush() later.
                Err(e) => return Err(e),
            }
        }
        self.pending.clear();
        self.pending_pos = 0;
        self.inner.flush()
    }
}

/// Client-side RSA-AES authentication handler.
///
/// Implements the client half of the RSA-AES handshake for RFB Security Types
/// 5 (RSA-AES) and 129 (RSA-AES-256).
pub struct RsaAesClientAuth {
    key_size: usize,
}

impl RsaAesClientAuth {
    /// Create a new RSA-AES (128-bit) authentication handler.
    pub fn new_128() -> Self {
        Self { key_size: 16 }
    }

    /// Create a new RSA-AES-256 (256-bit) authentication handler.
    pub fn new_256() -> Self {
        Self { key_size: 32 }
    }

    /// Perform the RSA-AES key exchange.
    ///
    /// Reads the server public key and sends the RSA-encrypted AES session
    /// key. Returns the AES key. The caller must immediately wrap the stream
    /// in [`AesCtrStream::new`] and then read the security result with
    /// [`RsaAesClientAuth::read_security_result`]: per the RA2 protocol the
    /// result is the first message the server sends on the encrypted channel.
    pub fn authenticate<S: Read + Write>(&self, stream: &mut S) -> io::Result<Vec<u8>> {
        // Read public key length.
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf)?;
        let key_len = u32::from_be_bytes(buf) as usize;
        if key_len > MAX_PUBLIC_KEY_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "server RSA public key too large",
            ));
        }

        // Read public key (ASN.1 DER).
        let mut key_data = vec![0u8; key_len];
        stream.read_exact(&mut key_data)?;

        // Parse RSA public key.
        let public_key = RsaPublicKey::from_public_key_der(&key_data).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid RSA public key: {}", e),
            )
        })?;

        // Generate AES key.
        let mut aes_key = vec![0u8; self.key_size];
        rand::thread_rng().fill_bytes(&mut aes_key);

        // Encrypt AES key with RSA-OAEP (SHA-256).
        let padding = Oaep::new::<Sha256>();
        let encrypted_key = public_key
            .encrypt(&mut OsRng, padding, &aes_key)
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, format!("{}", e)))?;

        // Send encrypted key length.
        stream.write_all(&(encrypted_key.len() as u32).to_be_bytes())?;
        // Send encrypted key.
        stream.write_all(&encrypted_key)?;
        stream.flush()?;

        Ok(aes_key)
    }

    /// Read and validate the 4-byte security result.
    ///
    /// `stream` must be the AES-CTR encrypted stream established right after
    /// [`RsaAesClientAuth::authenticate`]; the security result is the first
    /// message the server sends on that encrypted channel.
    pub fn read_security_result<R: Read>(stream: &mut R) -> io::Result<()> {
        let mut result = [0u8; 4];
        stream.read_exact(&mut result)?;
        let result = u32::from_be_bytes(result);

        if result != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("RSA-AES auth failed: status {}", result),
            ));
        }

        Ok(())
    }
}

/// Server-side RSA-AES authentication handler.
///
/// Implements the server half of the RSA-AES handshake for RFB Security Types
/// 5 (RSA-AES) and 129 (RSA-AES-256).
pub struct RsaAesServerAuth {
    private_key: RsaPrivateKey,
    key_size: usize,
}

impl RsaAesServerAuth {
    /// Create a new RSA-AES (128-bit) authentication handler.
    pub fn new_128() -> io::Result<Self> {
        Self::new(16)
    }

    /// Create a new RSA-AES-256 (256-bit) authentication handler.
    pub fn new_256() -> io::Result<Self> {
        Self::new(32)
    }

    fn new(key_size: usize) -> io::Result<Self> {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048)
            .map_err(|e| io::Error::other(format!("failed to generate RSA key: {}", e)))?;
        Ok(Self {
            private_key,
            key_size,
        })
    }

    /// Send the RSA public key (DER, length-prefixed) to the client.
    pub fn send_public_key<W: Write>(&self, stream: &mut W) -> io::Result<()> {
        let public_key_der = self
            .private_key
            .to_public_key()
            .to_public_key_der()
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to encode RSA public key: {}", e),
                )
            })?;
        let der_len = public_key_der.as_bytes().len();
        if der_len > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RSA public key too large",
            ));
        }
        stream.write_all(&(der_len as u32).to_be_bytes())?;
        stream.write_all(public_key_der.as_bytes())?;
        stream.flush()?;
        Ok(())
    }

    /// Read the encrypted AES key from the client and decrypt it.
    ///
    /// Reads the 4-byte big-endian length prefix followed by the RSA
    /// ciphertext from `stream`. Callers that already buffered the message
    /// (and consumed the length prefix themselves) should use
    /// [`RsaAesServerAuth::decrypt_encrypted_key`] instead so the length is
    /// read exactly once.
    pub fn receive_encrypted_key<R: Read>(&self, stream: &mut R) -> io::Result<Vec<u8>> {
        // Read encrypted AES key length.
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf)?;
        let encrypted_len = u32::from_be_bytes(buf) as usize;
        if encrypted_len > MAX_ENCRYPTED_KEY_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "encrypted AES key too large",
            ));
        }

        // Read encrypted AES key.
        let mut encrypted_key = vec![0u8; encrypted_len];
        stream.read_exact(&mut encrypted_key)?;

        self.decrypt_encrypted_key(&encrypted_key)
    }

    /// Decrypt an RSA-OAEP-SHA256 encrypted AES key received from the client.
    ///
    /// `encrypted_key` is the raw RSA ciphertext without the 4-byte length
    /// prefix.
    pub fn decrypt_encrypted_key(&self, encrypted_key: &[u8]) -> io::Result<Vec<u8>> {
        if encrypted_key.len() > MAX_ENCRYPTED_KEY_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "encrypted AES key too large",
            ));
        }

        // Decrypt with RSA-OAEP-SHA256.
        let padding = Oaep::new::<Sha256>();
        let aes_key = self
            .private_key
            .decrypt(padding, encrypted_key)
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, format!("{}", e)))?;

        if aes_key.len() != self.key_size {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "client sent wrong AES key size: expected {}, got {}",
                    self.key_size,
                    aes_key.len()
                ),
            ));
        }

        Ok(aes_key)
    }

    /// Send the 4-byte security result.
    ///
    /// `stream` must be the AES-CTR encrypted stream established right after
    /// [`RsaAesServerAuth::receive_encrypted_key`]; per the RA2 protocol the
    /// security result is the first message sent on the encrypted channel.
    pub fn send_security_result<W: Write>(stream: &mut W, ok: bool) -> io::Result<()> {
        let status: u32 = if ok { 0 } else { 1 };
        stream.write_all(&status.to_be_bytes())?;
        stream.flush()?;
        Ok(())
    }

    /// Run the server half of the RSA-AES key exchange in one call.
    ///
    /// Sends the public key and reads the client's encrypted AES key.
    /// `stream` must be the raw TCP stream. After this function returns
    /// successfully, the caller must wrap the stream in [`AesCtrStream::new`]
    /// and send the security result via
    /// [`RsaAesServerAuth::send_security_result`] as the first encrypted
    /// message.
    pub fn handshake<S: Read + Write>(&self, stream: &mut S) -> io::Result<Vec<u8>> {
        self.send_public_key(stream)?;
        self.receive_encrypted_key(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::io::Cursor;
    use std::rc::Rc;

    /// Bidirectional mock stream with separate read and write buffers.
    /// Used to exercise the RSA-AES handshake without a real network.
    struct MockStream {
        read: Cursor<Vec<u8>>,
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

    /// In-memory duplex stream endpoint. A pair of these is cross-connected
    /// so that bytes written to one endpoint can be read from the other,
    /// allowing the full client and server handshake halves to run against
    /// each other exactly as they do over TCP.
    struct Duplex {
        inbound: Rc<RefCell<VecDeque<u8>>>,
        outbound: Rc<RefCell<VecDeque<u8>>>,
    }

    fn duplex_pair() -> (Duplex, Duplex) {
        let a_to_b = Rc::new(RefCell::new(VecDeque::new()));
        let b_to_a = Rc::new(RefCell::new(VecDeque::new()));
        (
            Duplex {
                inbound: Rc::clone(&b_to_a),
                outbound: Rc::clone(&a_to_b),
            },
            Duplex {
                inbound: Rc::clone(&a_to_b),
                outbound: Rc::clone(&b_to_a),
            },
        )
    }

    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut inbound = self.inbound.borrow_mut();
            let n = buf.len().min(inbound.len());
            for slot in &mut buf[..n] {
                *slot = inbound.pop_front().expect("length checked above");
            }
            Ok(n)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.outbound.borrow_mut().extend(buf.iter().copied());
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Writer that allows only a limited number of bytes to be written before
    /// failing with `WouldBlock`, simulating a full non-blocking socket.
    struct FlakyStream {
        written: Vec<u8>,
        budget: Option<usize>,
    }

    impl Read for FlakyStream {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "no data"))
        }
    }

    impl Write for FlakyStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            match self.budget {
                Some(0) => Err(io::Error::new(io::ErrorKind::WouldBlock, "blocked")),
                Some(budget) => {
                    let n = buf.len().min(budget);
                    self.written.extend_from_slice(&buf[..n]);
                    self.budget = Some(budget - n);
                    Ok(n)
                }
                None => {
                    self.written.extend_from_slice(buf);
                    Ok(buf.len())
                }
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Drive the full client and server handshake halves against each other
    /// over an in-memory duplex, using the same call sequence that
    /// `vnc-client` (`authenticate` → `AesCtrStream::new` →
    /// `read_security_result`) and `vnc-server` (`send_public_key` →
    /// `receive_encrypted_key` → `AesCtrStream::new` → encrypted security
    /// result) use. Returns the two encrypted streams.
    fn run_handshake(
        client_auth: &RsaAesClientAuth,
        server_auth: &RsaAesServerAuth,
    ) -> (AesCtrStream<Duplex>, AesCtrStream<Duplex>) {
        let (mut client_end, mut server_end) = duplex_pair();

        server_auth.send_public_key(&mut server_end).unwrap();
        let client_key = client_auth.authenticate(&mut client_end).unwrap();
        let server_key = server_auth.receive_encrypted_key(&mut server_end).unwrap();
        assert_eq!(client_key, server_key);

        let mut server_stream = AesCtrStream::new(server_end, &server_key).unwrap();
        RsaAesServerAuth::send_security_result(&mut server_stream, true).unwrap();

        let mut client_stream = AesCtrStream::new(client_end, &client_key).unwrap();
        RsaAesClientAuth::read_security_result(&mut client_stream).unwrap();

        (client_stream, server_stream)
    }

    #[test]
    fn parse_encrypted_key_frame_valid() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&3u32.to_be_bytes());
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        assert_eq!(
            parse_encrypted_key_frame(&frame).unwrap().unwrap(),
            &[0xaa, 0xbb, 0xcc]
        );
        // Trailing bytes belong to the next message and are ignored.
        let mut with_trailer = frame.clone();
        with_trailer.extend_from_slice(b"TRAIL");
        assert_eq!(
            parse_encrypted_key_frame(&with_trailer).unwrap().unwrap(),
            &[0xaa, 0xbb, 0xcc]
        );
    }

    #[test]
    fn parse_encrypted_key_frame_truncated_is_none() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&4u32.to_be_bytes());
        frame.extend_from_slice(&[1, 2, 3, 4]);
        for len in 0..frame.len() {
            assert!(
                parse_encrypted_key_frame(&frame[..len]).is_none(),
                "len={}",
                len
            );
        }
    }

    #[test]
    fn parse_encrypted_key_frame_rejects_oversized_length() {
        let frame = ((MAX_ENCRYPTED_KEY_LEN as u32) + 1).to_be_bytes();
        match parse_encrypted_key_frame(&frame) {
            Some(Err(ProtocolError::Protocol(_))) => {}
            other => panic!(
                "expected protocol error, got {:?}",
                other.map(|r| r.map(|k| k.len()))
            ),
        }
    }

    #[test]
    fn aes_ctr_apply_roundtrip() {
        let key = [0xab; 16];
        let iv = [0x00; 16];
        let plaintext = b"hello, aes-ctr world!";

        // Two independent ciphers with the same key and IV emulate the read
        // and write directions of AesCtrStream.
        let mut encrypt = AesCtr::new(key.as_ref(), iv.as_ref()).unwrap();
        let mut decrypt = AesCtr::new(key.as_ref(), iv.as_ref()).unwrap();

        let mut ciphertext = plaintext.to_vec();
        encrypt.apply(&mut ciphertext);
        assert_ne!(ciphertext, plaintext);

        let mut recovered = ciphertext.clone();
        decrypt.apply(&mut recovered);
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn rsa_aes_handshake_roundtrip() {
        let server_auth = RsaAesServerAuth::new_128().unwrap();
        let client_auth = RsaAesClientAuth::new_128();
        let (mut client_stream, mut server_stream) = run_handshake(&client_auth, &server_auth);

        // Subsequent traffic in both directions stays in sync.
        client_stream.write_all(b"hello server").unwrap();
        client_stream.flush().unwrap();
        let mut buf = [0u8; 12];
        server_stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello server");

        server_stream.write_all(b"hello client").unwrap();
        server_stream.flush().unwrap();
        client_stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello client");
    }

    #[test]
    fn rsa_aes_handshake_roundtrip_256() {
        let server_auth = RsaAesServerAuth::new_256().unwrap();
        let client_auth = RsaAesClientAuth::new_256();
        let (mut client_stream, mut server_stream) = run_handshake(&client_auth, &server_auth);

        client_stream.write_all(b"ping").unwrap();
        client_stream.flush().unwrap();
        let mut buf = [0u8; 4];
        server_stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[test]
    fn rsa_aes_client_auth_rejects_failed_security_result() {
        let (mut client_end, mut server_end) = duplex_pair();

        let server_auth = RsaAesServerAuth::new_128().unwrap();
        server_auth.send_public_key(&mut server_end).unwrap();
        let client_auth = RsaAesClientAuth::new_128();
        let client_key = client_auth.authenticate(&mut client_end).unwrap();
        let server_key = server_auth.receive_encrypted_key(&mut server_end).unwrap();

        let mut server_stream = AesCtrStream::new(server_end, &server_key).unwrap();
        RsaAesServerAuth::send_security_result(&mut server_stream, false).unwrap();

        let mut client_stream = AesCtrStream::new(client_end, &client_key).unwrap();
        let err = RsaAesClientAuth::read_security_result(&mut client_stream).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("RSA-AES auth failed"));
    }

    #[test]
    fn rsa_aes_client_rejects_oversized_public_key() {
        // A server-controlled length of 4 GiB-1 must not turn into a huge
        // allocation; anything beyond MAX_PUBLIC_KEY_LEN is rejected.
        let mut response = Vec::new();
        response.extend_from_slice(&u32::MAX.to_be_bytes());

        let mut stream = MockStream {
            read: Cursor::new(response),
            written: Vec::new(),
        };
        let auth = RsaAesClientAuth::new_128();
        let err = auth.authenticate(&mut stream).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("public key too large"));
    }

    #[test]
    fn rsa_aes_receive_encrypted_key_reads_length_prefix_once() {
        let server_auth = RsaAesServerAuth::new_128().unwrap();

        // Let the client half produce the wire bytes (length + ciphertext).
        let mut server_to_client = Vec::new();
        server_auth.send_public_key(&mut server_to_client).unwrap();
        let mut client_stream = MockStream {
            read: Cursor::new(server_to_client),
            written: Vec::new(),
        };
        let client_auth = RsaAesClientAuth::new_128();
        let client_key = client_auth.authenticate(&mut client_stream).unwrap();

        let client_wire = client_stream.written;

        // Append trailing bytes: receive_encrypted_key must consume exactly
        // the length prefix and the ciphertext, no more, no less.
        let mut wire = client_wire.clone();
        wire.extend_from_slice(b"TRAIL");
        let mut cursor = Cursor::new(wire);
        let server_key = server_auth.receive_encrypted_key(&mut cursor).unwrap();
        assert_eq!(server_key, client_key);

        let mut rest = Vec::new();
        cursor.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"TRAIL");

        // The ciphertext without the length prefix must decrypt to the same
        // key via decrypt_encrypted_key (the entry point vnc-server uses for
        // its pre-buffered input path).
        let ciphertext = &client_wire[4..];
        let key = server_auth.decrypt_encrypted_key(ciphertext).unwrap();
        assert_eq!(key, client_key);
    }

    #[test]
    fn rsa_aes_server_auth_rejects_wrong_key_size() {
        let server_auth = RsaAesServerAuth::new_128().unwrap();
        let public_key_der = server_auth
            .private_key
            .to_public_key()
            .to_public_key_der()
            .unwrap();

        // Build a server response that lets the client complete its half:
        // DER length + DER.
        let mut response = Vec::new();
        response.extend_from_slice(&(public_key_der.as_bytes().len() as u32).to_be_bytes());
        response.extend_from_slice(public_key_der.as_bytes());

        let mut stream = MockStream {
            read: Cursor::new(response),
            written: Vec::new(),
        };
        let client_auth = RsaAesClientAuth::new_128();
        let aes_key = client_auth.authenticate(&mut stream).unwrap();

        // Pretend the server expected a 256-bit key.
        let server_auth_256 = RsaAesServerAuth {
            private_key: server_auth.private_key,
            key_size: 32,
        };
        let mut read_cursor = Cursor::new(stream.written.clone());
        let err = server_auth_256
            .receive_encrypted_key(&mut read_cursor)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("wrong AES key size"));

        // Also verify the decrypted key matches what the client sent.
        let server_auth_128 = RsaAesServerAuth {
            private_key: server_auth_256.private_key,
            key_size: 16,
        };
        let mut read_cursor = Cursor::new(stream.written);
        let decrypted = server_auth_128
            .receive_encrypted_key(&mut read_cursor)
            .unwrap();
        assert_eq!(decrypted, aes_key);
    }

    #[test]
    fn aes_ctr_flush_partial_write_is_retryable() {
        let key = [0x42u8; 16];
        let inner = FlakyStream {
            written: Vec::new(),
            budget: Some(5),
        };
        let mut stream = AesCtrStream::new(inner, &key).unwrap();

        stream.write_all(b"0123456789").unwrap();

        // The first flush writes only 5 bytes before the socket blocks.
        let err = stream.flush().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(stream.inner.written.len(), 5);

        // Writing more data before retrying must not disturb the queued bytes.
        stream.write_all(b"ab").unwrap();

        // Once the socket is writable again, flush resumes where it stopped:
        // no byte is lost or sent twice.
        stream.inner.budget = None;
        stream.flush().unwrap();
        assert_eq!(stream.inner.written.len(), 12);

        let mut ciphertext = stream.inner.written.clone();
        let mut decrypt = AesCtr::new(key.as_ref(), [0u8; 16].as_ref()).unwrap();
        decrypt.apply(&mut ciphertext);
        assert_eq!(&ciphertext, b"0123456789ab");
    }

    #[test]
    fn aes_ctr_flush_blocked_socket_keeps_all_state() {
        let key = [0x07u8; 16];
        let inner = FlakyStream {
            written: Vec::new(),
            budget: Some(0),
        };
        let mut stream = AesCtrStream::new(inner, &key).unwrap();

        stream.write_all(b"data").unwrap();
        // Nothing can be written; the error must leave all state intact.
        let err = stream.flush().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert!(stream.inner.written.is_empty());

        stream.inner.budget = None;
        stream.flush().unwrap();

        let mut ciphertext = stream.inner.written.clone();
        let mut decrypt = AesCtr::new(key.as_ref(), [0u8; 16].as_ref()).unwrap();
        decrypt.apply(&mut ciphertext);
        assert_eq!(&ciphertext, b"data");
    }

    #[test]
    fn aes_ctr_queued_bytes_and_write_idle_track_flush_state() {
        let key = [0x42u8; 16];
        let inner = FlakyStream {
            written: Vec::new(),
            budget: Some(0),
        };
        let mut stream = AesCtrStream::new(inner, &key).unwrap();
        assert!(stream.is_write_idle());
        assert_eq!(stream.queued_bytes(), 0);

        // Buffered plaintext counts as queued before any flush attempt.
        stream.write_all(b"data").unwrap();
        assert!(!stream.is_write_idle());
        assert_eq!(stream.queued_bytes(), 4);

        // A blocked flush keeps everything queued.
        let err = stream.flush().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert!(!stream.is_write_idle());
        assert_eq!(stream.queued_bytes(), 4);

        stream.inner.budget = None;
        stream.flush().unwrap();
        assert!(stream.is_write_idle());
        assert_eq!(stream.queued_bytes(), 0);
    }

    #[test]
    fn aes_ctr_decrypt_buffered_keeps_read_cipher_in_sync() {
        let key = [0x11u8; 16];
        let iv = [0u8; 16];

        // Produce one continuous keystream: "pipelined" (bytes the application
        // read before the upgrade) followed by "next" (bytes read afterwards).
        let mut encrypt = AesCtr::new(key.as_ref(), iv.as_ref()).unwrap();
        let mut pre = b"pipelined".to_vec();
        encrypt.apply(&mut pre);
        let mut post = b"next".to_vec();
        encrypt.apply(&mut post);

        let inner = MockStream {
            read: Cursor::new(post),
            written: Vec::new(),
        };
        let mut stream = AesCtrStream::new(inner, &key).unwrap();

        // Bytes buffered ahead of the upgrade decrypt correctly...
        let mut pre_plain = pre.clone();
        stream.decrypt_buffered(&mut pre_plain);
        assert_eq!(&pre_plain, b"pipelined");

        // ...and the regular read path continues the keystream seamlessly.
        let mut out = [0u8; 4];
        stream.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"next");
    }
}
