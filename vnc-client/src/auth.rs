use cipher::block::BlockCipherEncrypt;
use cipher::Block;
use des::Des;

use crate::VncError;
use des::cipher::KeyInit;

/// Authentication handler trait.
pub trait AuthHandler {
    /// Select a security type from the list offered by the server.
    fn select_security_type(&mut self, types: &[u8]) -> Result<u8, VncError>;

    /// Authenticate using VNC authentication (DES challenge-response).
    fn authenticate_vnc(&mut self, stream: &mut dyn Stream) -> Result<(), VncError>;

    /// Authenticate using a custom security type.
    fn authenticate(&mut self, _stream: &mut dyn Stream, _type: u8) -> Result<(), VncError> {
        Err(VncError::AuthFailed(format!(
            "Auth type {} not supported",
            _type
        )))
    }
}

/// Trait alias for stream types used in authentication.
pub trait Stream: std::io::Read + std::io::Write {}
impl<T: std::io::Read + std::io::Write> Stream for T {}

/// Result of authentication.
pub enum AuthResult {
    Success,
    Failure(String),
}

/// No authentication handler (accepts None auth only).
pub struct NoAuthHandler;

impl AuthHandler for NoAuthHandler {
    fn select_security_type(&mut self, types: &[u8]) -> Result<u8, VncError> {
        if types.contains(&1) {
            Ok(1) // None
        } else {
            Err(VncError::AuthFailed("No supported auth types".to_string()))
        }
    }

    fn authenticate_vnc(&mut self, _stream: &mut dyn Stream) -> Result<(), VncError> {
        Err(VncError::AuthFailed("VNC auth not supported".to_string()))
    }
}

/// Password-based VNC authentication handler.
pub struct PasswordAuthHandler {
    password: String,
}

impl PasswordAuthHandler {
    pub fn new(password: String) -> Self {
        Self { password }
    }
}

impl AuthHandler for PasswordAuthHandler {
    fn select_security_type(&mut self, types: &[u8]) -> Result<u8, VncError> {
        if types.contains(&2) {
            Ok(2) // VNC Auth
        } else if types.contains(&1) {
            Ok(1) // None
        } else {
            Err(VncError::AuthFailed("No supported auth types".to_string()))
        }
    }

    fn authenticate_vnc(&mut self, stream: &mut dyn Stream) -> Result<(), VncError> {
        // Read 16-byte challenge
        let mut challenge = [0u8; 16];
        stream.read_exact(&mut challenge)?;

        // Derive DES key from password
        let key = vnc_des_key(&self.password);

        // Encrypt challenge with DES-ECB (two independent 8-byte blocks)
        let response = des_encrypt(&key, &challenge);
        stream.write_all(&response)?;

        // Read security result
        let mut result = [0u8; 4];
        stream.read_exact(&mut result)?;
        let result = u32::from_be_bytes(result);
        if result != 0 {
            return Err(VncError::AuthFailed("Invalid password".to_string()));
        }

        Ok(())
    }
}

/// Derive a VNC DES key from a password.
/// Password is truncated/padded to 8 bytes, then each byte's bits are reversed.
fn vnc_des_key(password: &str) -> [u8; 8] {
    let mut key = [0u8; 8];
    let pw_bytes = password.as_bytes();
    let len = pw_bytes.len().min(8);
    key[..len].copy_from_slice(&pw_bytes[..len]);

    // VNC uses non-standard DES: reverse bits in each key byte
    for byte in key.iter_mut() {
        *byte = reverse_bits(*byte);
    }
    key
}

/// Reverse bits in a byte.
fn reverse_bits(mut b: u8) -> u8 {
    b = ((b & 0xF0) >> 4) | ((b & 0x0F) << 4);
    b = ((b & 0xCC) >> 2) | ((b & 0x33) << 2);
    b = ((b & 0xAA) >> 1) | ((b & 0x55) << 1);
    b
}

/// Encrypt two 8-byte blocks with DES-ECB using the given key.
fn des_encrypt(key: &[u8; 8], data: &[u8; 16]) -> [u8; 16] {
    let cipher = Des::new_from_slice(key).expect("DES key length is always valid");

    let mut result = [0u8; 16];

    let mut block1: Block<Des> = data[0..8].try_into().unwrap();
    cipher.encrypt_block(&mut block1);
    result[0..8].copy_from_slice(&block1);

    let mut block2: Block<Des> = data[8..16].try_into().unwrap();
    cipher.encrypt_block(&mut block2);
    result[8..16].copy_from_slice(&block2);

    result
}
