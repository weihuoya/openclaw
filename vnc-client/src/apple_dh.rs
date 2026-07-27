use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use num_bigint::{BigUint, RandBigInt};
use rand::rngs::ThreadRng;
use rand::RngCore;

use crate::auth::Stream;
use crate::VncError;

/// Apple Remote Desktop Diffie-Hellman authentication handler (RFB security type 30).
///
/// macOS Screen Sharing advertises this security type and expects the client to
/// perform a Diffie-Hellman key exchange, then send the username and password
/// encrypted with AES-128-ECB using an MD5-derived key from the shared secret.
///
/// Protocol reference:
/// - <https://www.tenable.com/blog/detecting-macos-high-sierra-root-account-without-authentication>
pub struct AppleDhAuth {
    username: String,
    password: String,
}

impl AppleDhAuth {
    /// Create a new Apple DH authenticator with the given credentials.
    pub fn new(username: String, password: String) -> Self {
        Self { username, password }
    }

    /// Perform the Apple DH authentication handshake.
    pub fn authenticate(&self, stream: &mut dyn Stream) -> Result<(), VncError> {
        let mut rng = rand::thread_rng();

        // Server sends: generator (2 bytes BE), key length (2 bytes BE),
        // prime modulus (key_length bytes), server public key (key_length bytes).
        let mut header = [0u8; 4];
        stream.read_exact(&mut header)?;
        let generator = u16::from_be_bytes([header[0], header[1]]) as u32;
        let key_length = u16::from_be_bytes([header[2], header[3]]) as usize;

        if key_length == 0 || key_length > 4096 {
            return Err(VncError::AuthFailed(format!(
                "Invalid Apple DH key length: {}",
                key_length
            )));
        }

        let mut prime_bytes = vec![0u8; key_length];
        stream.read_exact(&mut prime_bytes)?;
        let prime = BigUint::from_bytes_be(&prime_bytes);

        let mut server_public_bytes = vec![0u8; key_length];
        stream.read_exact(&mut server_public_bytes)?;
        let server_public = BigUint::from_bytes_be(&server_public_bytes);

        log::debug!(
            "Apple DH params: generator={}, key_length={}",
            generator,
            key_length
        );

        // Generate a private key in [1, p-1].
        let one = BigUint::from(1u8);
        let private_key = rng.gen_biguint_range(&one, &prime);

        let generator = BigUint::from(generator);
        let client_public = generator.modpow(&private_key, &prime);
        let shared_secret = server_public.modpow(&private_key, &prime);

        // AES key = MD5(shared secret). Match LibVNC by hashing the fixed-length,
        // big-endian representation including any leading zero bytes.
        let mut shared_bytes = shared_secret.to_bytes_be();
        if shared_bytes.len() < key_length {
            let mut padded = vec![0u8; key_length];
            padded[key_length - shared_bytes.len()..].copy_from_slice(&shared_bytes);
            shared_bytes = padded;
        }
        log::debug!(
            "Apple DH shared secret length: {} bytes (key_length={})",
            shared_bytes.len(),
            key_length
        );
        let aes_key = md5::compute(&shared_bytes);

        // Build 128-byte credential blob and encrypt it with AES-128-ECB.
        let mut blob = build_credential_blob(&self.username, &self.password, &mut rng);
        encrypt_aes128_ecb(&mut blob, &aes_key.0);

        stream.write_all(&blob)?;

        // Send our DH public key, padded to key_length bytes.
        let mut client_public_bytes = client_public.to_bytes_be();
        if client_public_bytes.len() < key_length {
            let mut padded = vec![0u8; key_length];
            padded[key_length - client_public_bytes.len()..].copy_from_slice(&client_public_bytes);
            client_public_bytes = padded;
        }
        stream.write_all(&client_public_bytes)?;

        // Read 4-byte security result.
        let mut result = [0u8; 4];
        stream.read_exact(&mut result)?;
        let result = u32::from_be_bytes(result);
        if result != 0 {
            return Err(VncError::AuthFailed(format!(
                "Apple DH authentication failed: status {}",
                result
            )));
        }

        log::debug!("Apple DH authentication succeeded");
        Ok(())
    }
}

/// Build the 128-byte credential blob used by Apple DH authentication.
///
/// Layout:
/// - Bytes 0..64: username, null-terminated, remainder filled with random bytes.
/// - Bytes 64..128: password, null-terminated, remainder filled with random bytes.
fn build_credential_blob(username: &str, password: &str, rng: &mut ThreadRng) -> [u8; 128] {
    let mut blob = [0u8; 128];

    let user_bytes = username.as_bytes();
    let user_len = user_bytes.len().min(63);
    blob[..user_len].copy_from_slice(&user_bytes[..user_len]);
    blob[user_len] = 0;
    rng.fill_bytes(&mut blob[user_len + 1..64]);

    let pw_bytes = password.as_bytes();
    let pw_len = pw_bytes.len().min(63);
    blob[64..64 + pw_len].copy_from_slice(&pw_bytes[..pw_len]);
    blob[64 + pw_len] = 0;
    rng.fill_bytes(&mut blob[64 + pw_len + 1..128]);

    blob
}

/// Encrypt data in-place using AES-128-ECB.
fn encrypt_aes128_ecb(data: &mut [u8; 128], key: &[u8; 16]) {
    let cipher = Aes128::new_from_slice(key).expect("AES-128 key is 16 bytes");
    for chunk in data.chunks_mut(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_blob_has_null_terminators() {
        let blob = build_credential_blob("admin", "secret", &mut rand::thread_rng());
        assert_eq!(blob.len(), 128);
        // Username and password are null-terminated within their 64-byte halves.
        assert_eq!(blob[5], 0);
        assert_eq!(blob[64 + 6], 0);
    }

    #[test]
    fn credential_blob_truncates_long_credentials() {
        let long = "a".repeat(100);
        let blob = build_credential_blob(&long, &long, &mut rand::thread_rng());
        assert_eq!(blob[63], 0);
        assert_eq!(blob[127], 0);
    }

    #[test]
    fn aes128_ecb_roundtrip() {
        let key = [0u8; 16];
        let mut data = [0xabu8; 128];
        encrypt_aes128_ecb(&mut data, &key);
        // AES-ECB with a constant key and constant plaintext must be deterministic.
        let mut data2 = [0xabu8; 128];
        encrypt_aes128_ecb(&mut data2, &key);
        assert_eq!(data, data2);
    }
}
