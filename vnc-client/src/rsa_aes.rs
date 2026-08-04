use std::io::{Read, Write};
use std::net::TcpStream;

use aes::{Aes128, Aes256};
use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::{pkcs8::DecodePublicKey, Oaep, RsaPublicKey};
use sha2::Sha256;

use crate::VncError;

/// RSA-AES authentication handler (VeNCrypt sub-type 26 / 27).
///
/// Protocol:
/// 1. Server sends RSA public key (ASN.1 DER, length-prefixed)
/// 2. Client generates AES key (128-bit for RSA-AES, 256-bit for RSA-AES-256)
/// 3. Client encrypts AES key with RSA-OAEP (SHA-256)
/// 4. Client sends encrypted key (length-prefixed)
/// 5. Server sends security result (4 bytes)
/// 6. All subsequent traffic encrypted with AES-CTR (TigerVNC/noVNC use CTR, not CFB)
///
/// Security note: the RSA-AES VeNCrypt variant uses the same AES key and a
/// zero IV for both read and write directions, so both directions share the
/// same keystream. This is a known limitation of the protocol variant; callers
/// should not rely on it for confidentiality against active attackers on the
/// network segment.
pub struct RsaAesAuth {
    key_size: usize,
}

impl RsaAesAuth {
    pub fn new_128() -> Self {
        Self { key_size: 16 }
    }

    pub fn new_256() -> Self {
        Self { key_size: 32 }
    }

    /// Perform RSA-AES handshake.
    /// Returns the AES key for subsequent encryption.
    pub fn authenticate(&self, stream: &mut dyn Stream) -> Result<Vec<u8>, VncError> {
        // Read public key length
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf)?;
        let key_len = u32::from_be_bytes(buf) as usize;

        // Read public key (ASN.1 DER)
        let mut key_data = vec![0u8; key_len];
        stream.read_exact(&mut key_data)?;

        // Parse RSA public key
        let public_key = RsaPublicKey::from_public_key_der(&key_data)
            .map_err(|e| VncError::Protocol(format!("Invalid RSA public key: {}", e)))?;

        // Generate AES key
        let mut aes_key = vec![0u8; self.key_size];
        rand::thread_rng().fill_bytes(&mut aes_key);

        // Encrypt AES key with RSA-OAEP (SHA-256)
        let padding = Oaep::new::<Sha256>();
        let encrypted_key = public_key
            .encrypt(&mut OsRng, padding, &aes_key)
            .map_err(|e| VncError::AuthFailed(format!("RSA encryption failed: {}", e)))?;

        // Send encrypted key length
        stream.write_all(&(encrypted_key.len() as u32).to_be_bytes())?;
        // Send encrypted key
        stream.write_all(&encrypted_key)?;

        // Read security result
        let mut result = [0u8; 4];
        stream.read_exact(&mut result)?;
        let result = u32::from_be_bytes(result);

        if result != 0 {
            return Err(VncError::AuthFailed(format!(
                "RSA-AES auth failed: status {}",
                result
            )));
        }

        Ok(aes_key)
    }
}

/// AES-CTR cipher that supports both AES-128 and AES-256.
enum AesCtr {
    Aes128(Box<ctr::Ctr128BE<Aes128>>),
    Aes256(Box<ctr::Ctr128BE<Aes256>>),
}

impl AesCtr {
    fn new(key: &[u8], iv: &[u8]) -> Result<Self, VncError> {
        match key.len() {
            16 => {
                let cipher = ctr::Ctr128BE::<Aes128>::new_from_slices(key, iv).map_err(|_| {
                    VncError::Protocol("Failed to create AES-128 cipher".to_string())
                })?;
                Ok(Self::Aes128(Box::new(cipher)))
            }
            32 => {
                let cipher = ctr::Ctr128BE::<Aes256>::new_from_slices(key, iv).map_err(|_| {
                    VncError::Protocol("Failed to create AES-256 cipher".to_string())
                })?;
                Ok(Self::Aes256(Box::new(cipher)))
            }
            _ => Err(VncError::Protocol(
                "AES key must be 16 (AES-128) or 32 (AES-256) bytes".to_string(),
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
/// Wraps a TCP stream and applies AES-CTR encryption/decryption
/// to all read/write operations. Separate cipher states for each direction.
///
/// Writes are buffered until `flush()` is called to ensure atomicity:
/// if a write fails mid-stream the cipher counter is not advanced,
/// so the next retry starts from the same counter value.
///
/// Security note: this implementation uses the same AES key and zero IV for
/// both directions, as specified by the RSA-AES VeNCrypt variant. This means
/// both directions share the same keystream, which is a known protocol
/// limitation.
pub struct AesCtrStream {
    inner: TcpStream,
    read_cipher: AesCtr,
    write_cipher: AesCtr,
    /// Buffered plaintext waiting to be encrypted and sent.
    write_buffer: Vec<u8>,
}

impl AesCtrStream {
    pub fn new(inner: TcpStream, key: &[u8]) -> Result<Self, VncError> {
        let iv = vec![0u8; 16];
        let read_cipher = AesCtr::new(key, &iv)?;
        let write_cipher = AesCtr::new(key, &iv)?;
        Ok(Self {
            inner,
            read_cipher,
            write_cipher,
            write_buffer: Vec::new(),
        })
    }

    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    pub fn set_nodelay(&self, nodelay: bool) -> std::io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }
}

impl Read for AesCtrStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.read_cipher.apply(&mut buf[..n]);
        }
        Ok(n)
    }
}

impl Write for AesCtrStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Buffer plaintext; encryption is deferred to flush() so that
        // partial TCP writes cannot leave the CTR counter out of sync.
        self.write_buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.write_buffer.is_empty() {
            let mut encrypted = std::mem::take(&mut self.write_buffer);
            self.write_cipher.apply(&mut encrypted);
            self.inner.write_all(&encrypted)?;
        }
        self.inner.flush()
    }
}

/// Trait alias for Read + Write.
pub trait Stream: Read + Write {}
impl<T: Read + Write> Stream for T {}
