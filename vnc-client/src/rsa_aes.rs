use std::io::{Read, Write};
use std::net::TcpStream;

use aes::Aes128;
use ctr::cipher::KeyIvInit;
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
/// 6. All subsequent traffic encrypted with AES-CFB
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

/// AES-128-CFB encrypt/decrypt helper.
#[derive(Clone)]
pub struct AesCfb {
    cipher: ctr::Ctr128BE<Aes128>,
}

/// AES-CTR encrypted stream wrapper.
///
/// Wraps a TCP stream and applies AES-128-CTR encryption/decryption
/// to all read/write operations. Separate cipher states for each direction.
pub struct AesCfbStream {
    inner: TcpStream,
    read_cipher: AesCfb,
    write_cipher: AesCfb,
}

impl AesCfbStream {
    pub fn new(inner: TcpStream, key: &[u8]) -> Result<Self, VncError> {
        let iv = vec![0u8; 16];
        let read_cipher = AesCfb::new(key, &iv)?;
        let write_cipher = AesCfb::new(key, &iv)?;
        Ok(Self {
            inner,
            read_cipher,
            write_cipher,
        })
    }

    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    pub fn set_nodelay(&self, nodelay: bool) -> std::io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }
}

impl Read for AesCfbStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.read_cipher.apply(&mut buf[..n]);
        }
        Ok(n)
    }
}

impl Write for AesCfbStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Encrypt the entire buffer into a temporary vec.
        // We must write all encrypted bytes or none, because a partial
        // write would advance the CTR state without the corresponding
        // bytes reaching the peer, desynchronising the stream.
        let mut encrypted = buf.to_vec();
        self.write_cipher.apply(&mut encrypted);
        self.inner.write_all(&encrypted)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl AesCfb {
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, VncError> {
        if key.len() != 16 || iv.len() != 16 {
            return Err(VncError::Protocol(
                "AES-128 requires 16-byte key and IV".to_string(),
            ));
        }
        let cipher = ctr::Ctr128BE::<Aes128>::new_from_slices(key, iv)
            .map_err(|_| VncError::Protocol("Failed to create AES cipher".to_string()))?;
        Ok(Self { cipher })
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        use ctr::cipher::StreamCipher;
        self.cipher.apply_keystream(data);
    }
}

/// Trait alias for Read + Write.
pub trait Stream: Read + Write {}
impl<T: Read + Write> Stream for T {}
