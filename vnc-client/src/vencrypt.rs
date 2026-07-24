use std::io::{Read, Write};

use crate::VncError;

/// VeNCrypt security type handler.
///
/// VeNCrypt protocol flow:
/// 1. Server sends VeNCrypt version (major.minor)
/// 2. Client replies with chosen version
/// 3. Server sends supported sub-types
/// 4. Client selects a sub-type
/// 5. Perform authentication per sub-type
/// 6. Server sends security result
///
/// Sub-types:
/// - 0:  None (no auth)
/// - 1:  VNC Auth (DES password)
/// - 2:  TLS
/// - 256: TLS + X509 certificate
/// - 257: TLS + X509 certificate with username
/// - 22: SASL
/// - 24: SASL + anon
/// - 26: RSA-AES
/// - 27: RSA-AES-256
/// - 30: Apple Diffie-Hellman
pub struct VencryptHandler;

impl VencryptHandler {
    pub fn negotiate(&self, stream: &mut dyn Stream) -> Result<VencryptResult, VncError> {
        // Read VeNCrypt version
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf)?;
        let major = buf[0];
        let minor = buf[1];

        if major != 0 || minor < 2 {
            return Err(VncError::Protocol(format!(
                "Unsupported VeNCrypt version: {}.{}",
                major, minor
            )));
        }

        // Reply with same version
        stream.write_all(&[0, 2])?;

        // Read number of sub-types
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf)?;
        let num_subtypes = buf[0] as usize;

        if num_subtypes == 0 {
            return Err(VncError::AuthFailed("Server rejected VeNCrypt".to_string()));
        }

        // Read sub-types
        let mut subtypes = vec![0u32; num_subtypes];
        for subtype in subtypes.iter_mut().take(num_subtypes) {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf)?;
            *subtype = u32::from_be_bytes(buf);
        }

        // Preference: TLS > RSA-AES-256 > RSA-AES > X509 > SASL > None > VNCAuth
        // Apple DH (30) is deliberately omitted because the implementation
        // is currently a placeholder that sends a zero public key and will
        // always fail. Do not place it ahead of working mechanisms.
        let preferred = [
            2u32, // TLS
            27,   // RSA-AES-256
            26,   // RSA-AES
            256,  // X509
            22,   // SASL
            0,    // None
            1,    // VNCAuth
        ];

        let selected = preferred
            .iter()
            .find(|&&p| subtypes.contains(&p))
            .copied()
            .ok_or_else(|| VncError::AuthFailed("No supported VeNCrypt sub-type".to_string()))?;

        // Send selected sub-type
        stream.write_all(&selected.to_be_bytes())?;

        match selected {
            2 => Ok(VencryptResult::Tls),
            256 => Ok(VencryptResult::X509),
            0 => Ok(VencryptResult::None),
            1 => Ok(VencryptResult::VncAuth),
            26 => Ok(VencryptResult::RsaAes),
            27 => Ok(VencryptResult::RsaAes256),
            30 => Ok(VencryptResult::AppleDh),
            22 => Ok(VencryptResult::Sasl),
            _ => Err(VncError::Protocol(format!(
                "Unknown VeNCrypt sub-type: {}",
                selected
            ))),
        }
    }
}

pub enum VencryptResult {
    Tls,
    X509,
    None,
    VncAuth,
    RsaAes,
    RsaAes256,
    AppleDh,
    Sasl,
}

/// Trait alias for Read + Write.
pub trait Stream: Read + Write {}
impl<T: Read + Write> Stream for T {}
