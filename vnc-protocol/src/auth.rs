//! VNC password authentication helpers (security type 2, DES challenge-response).
//!
//! These primitives are shared between the client and server implementations so
//! the key derivation and encryption stay identical on both sides.

use des::cipher::{Block, BlockCipherEncrypt, KeyInit};
use des::Des;

use crate::ProtocolError;

/// VNC Auth challenge size.
pub const CHALLENGE_SIZE: usize = 16;

/// Generate a 16-byte random challenge.
pub fn generate_challenge() -> [u8; CHALLENGE_SIZE] {
    use rand::Rng;
    let mut challenge = [0u8; CHALLENGE_SIZE];
    rand::thread_rng().fill(&mut challenge);
    challenge
}

/// Reverse the bits in a byte (VNC DES requirement).
pub fn reverse_bits(mut b: u8) -> u8 {
    b = ((b & 0xF0) >> 4) | ((b & 0x0F) << 4);
    b = ((b & 0xCC) >> 2) | ((b & 0x33) << 2);
    b = ((b & 0xAA) >> 1) | ((b & 0x55) << 1);
    b
}

/// Derive a VNC DES key from a password.
///
/// The password is truncated/padded to 8 bytes, then each byte's bits are
/// reversed to match the non-standard VNC DES key format.
pub fn vnc_des_key(password: &str) -> [u8; 8] {
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

/// Encrypt a VNC challenge using the password.
///
/// DES-ECB is applied to two independent 8-byte blocks.
pub fn encrypt_challenge(
    challenge: &[u8; CHALLENGE_SIZE],
    password: &str,
) -> Result<[u8; CHALLENGE_SIZE], ProtocolError> {
    let key = vnc_des_key(password);
    let cipher = Des::new_from_slice(&key)
        .map_err(|e| ProtocolError::Protocol(format!("DES key: {}", e)))?;

    let mut encrypted = [0u8; CHALLENGE_SIZE];

    for i in 0..2 {
        let mut block = Block::<Des>::default();
        block.copy_from_slice(&challenge[i * 8..(i + 1) * 8]);
        cipher.encrypt_block(&mut block);
        encrypted[i * 8..(i + 1) * 8].copy_from_slice(&block);
    }

    Ok(encrypted)
}

/// Verify a client response against the expected challenge using constant-time
/// comparison.
pub fn verify_response(
    challenge: &[u8; CHALLENGE_SIZE],
    response: &[u8; CHALLENGE_SIZE],
    password: &str,
) -> bool {
    match encrypt_challenge(challenge, password) {
        Ok(expected) => constant_time_eq(&expected, response),
        Err(_) => false,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_bits_known_values() {
        assert_eq!(reverse_bits(0x00), 0x00);
        assert_eq!(reverse_bits(0xFF), 0xFF);
        assert_eq!(reverse_bits(0x01), 0x80);
        assert_eq!(reverse_bits(0x80), 0x01);
        assert_eq!(reverse_bits(0xAB), 0xD5);
        assert_eq!(reverse_bits(0x0F), 0xF0);
        // Involution: reversing twice is the identity.
        for b in [0x12u8, 0x34, 0x7E, 0xC3] {
            assert_eq!(reverse_bits(reverse_bits(b)), b);
        }
    }

    #[test]
    fn vnc_des_key_reverses_bits_and_pads() {
        // "password": each ASCII byte with its bits reversed.
        assert_eq!(
            vnc_des_key("password"),
            [0x0E, 0x86, 0xCE, 0xCE, 0xEE, 0xF6, 0x4E, 0x26]
        );
        // Short passwords are zero-padded to 8 bytes.
        assert_eq!(
            vnc_des_key("abc"),
            [
                reverse_bits(b'a'),
                reverse_bits(b'b'),
                reverse_bits(b'c'),
                0,
                0,
                0,
                0,
                0
            ]
        );
        // Empty password is the all-zero key.
        assert_eq!(vnc_des_key(""), [0u8; 8]);
        // Bytes past the eighth are ignored.
        assert_eq!(vnc_des_key("passwordXYZ"), vnc_des_key("password"));
    }

    #[test]
    fn challenge_response_roundtrip() {
        let challenge = generate_challenge();
        let response = encrypt_challenge(&challenge, "hunter2").unwrap();
        assert!(verify_response(&challenge, &response, "hunter2"));
    }

    #[test]
    fn encrypt_challenge_matches_known_plaintext() {
        // Deterministic encryption: a fixed challenge and password always
        // produce the same response, and the two 8-byte halves are encrypted
        // independently (all-zero halves encrypt identically).
        let challenge = [0u8; CHALLENGE_SIZE];
        let response = encrypt_challenge(&challenge, "password").unwrap();
        assert_eq!(response[..8], response[8..]);
        // DES-ECB of an all-zero block with the VNC key for "password".
        assert_eq!(
            response,
            [
                0xFF, 0x97, 0x50, 0x2E, 0x94, 0x22, 0xF0, 0x89, 0xFF, 0x97, 0x50, 0x2E, 0x94, 0x22,
                0xF0, 0x89
            ]
        );
    }

    #[test]
    fn verify_response_rejects_wrong_response() {
        let challenge = generate_challenge();
        let response = encrypt_challenge(&challenge, "right").unwrap();

        // Wrong password.
        assert!(!verify_response(&challenge, &response, "wrong"));
        // Corrupted response byte.
        let mut bad = response;
        bad[3] ^= 0x01;
        assert!(!verify_response(&challenge, &bad, "right"));
        // Response for a different challenge.
        let other = generate_challenge();
        if other != challenge {
            assert!(!verify_response(&other, &response, "right"));
        }
    }
}
