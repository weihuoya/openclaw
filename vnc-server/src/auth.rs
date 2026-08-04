//! VNC Authentication (VNC Auth - Security Type 2).
//!
//! Uses DES encryption with a challenge-response protocol.

use des::cipher::{Block, BlockCipherEncrypt, KeyInit};
use des::Des;

/// VNC Auth challenge size.
pub const CHALLENGE_SIZE: usize = 16;

/// Generate a 16-byte random challenge.
pub fn generate_challenge() -> [u8; CHALLENGE_SIZE] {
    use rand::Rng;
    let mut challenge = [0u8; CHALLENGE_SIZE];
    rand::thread_rng().fill(&mut challenge);
    challenge
}

/// Prepare a VNC password into an 8-byte DES key.
/// - Truncate/pad to 8 bytes
/// - Reverse bit order of each byte
fn prepare_key(password: &str) -> [u8; 8] {
    let mut key = [0u8; 8];
    let bytes = password.as_bytes();
    for i in 0..8 {
        if i < bytes.len() {
            key[i] = reverse_bits(bytes[i]);
        } else {
            key[i] = 0;
        }
    }
    key
}

/// Reverse the bits in a byte (VNC DES requirement).
fn reverse_bits(mut b: u8) -> u8 {
    b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
    b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
    b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
    b
}

/// Encrypt a VNC challenge using the password.
pub fn encrypt_challenge(challenge: &[u8; CHALLENGE_SIZE], password: &str) -> [u8; CHALLENGE_SIZE] {
    let key = prepare_key(password);
    let cipher = Des::new_from_slice(&key).expect("DES key size is correct");

    let mut encrypted = [0u8; CHALLENGE_SIZE];

    // DES ECB: encrypt each 8-byte block independently
    for i in 0..2 {
        let mut block = Block::<Des>::default();
        block.copy_from_slice(&challenge[i * 8..(i + 1) * 8]);
        cipher.encrypt_block(&mut block);
        encrypted[i * 8..(i + 1) * 8].copy_from_slice(&block);
    }

    encrypted
}

/// Verify client response against the expected challenge using constant-time comparison.
pub fn verify_response(
    challenge: &[u8; CHALLENGE_SIZE],
    response: &[u8; CHALLENGE_SIZE],
    password: &str,
) -> bool {
    let expected = encrypt_challenge(challenge, password);
    constant_time_eq(&expected, response)
}

/// Constant-time byte comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}
