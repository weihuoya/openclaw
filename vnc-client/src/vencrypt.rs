//! VeNCrypt security type handler.
//!
//! The wire framing (version bytes, sub-type numbers, message layout) is
//! shared in [`vnc_protocol::vencrypt`]; this module keeps the client-side
//! negotiation policy (sub-type preference) and maps the selected sub-type
//! to a [`VencryptResult`].
//!
//! VeNCrypt protocol flow:
//! 1. Server sends VeNCrypt version (major.minor)
//! 2. Client replies with chosen version
//! 3. Server sends supported sub-types
//! 4. Client selects a sub-type
//! 5. Perform authentication per sub-type
//! 6. Server sends security result

use std::io::{Read, Write};

use vnc_protocol::vencrypt::{self, VeNCryptSubType};

use crate::VncError;

pub struct VencryptHandler;

impl VencryptHandler {
    pub fn negotiate(&self, stream: &mut dyn Stream) -> Result<VencryptResult, VncError> {
        // Read VeNCrypt version
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf)?;
        let (major, minor) = (buf[0], buf[1]);

        if !vencrypt::version_supported(major, minor) {
            return Err(VncError::Protocol(format!(
                "Unsupported VeNCrypt version: {}.{}",
                major, minor
            )));
        }

        // Reply with same version
        stream.write_all(&vencrypt::VERSION_0_2)?;

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

        // Preference: strongest first, weakest last.
        let preferred = [
            VeNCryptSubType::Tls,
            VeNCryptSubType::RsaAes256,
            VeNCryptSubType::RsaAes,
            VeNCryptSubType::X509,
            VeNCryptSubType::Sasl,
            // Apple DH is functional but uses ECB/MD5; kept as fallback.
            VeNCryptSubType::AppleDh,
            VeNCryptSubType::Plain,
            VeNCryptSubType::VncAuth,
        ];

        let selected = preferred
            .iter()
            .find(|p| subtypes.contains(&(**p as u32)))
            .copied()
            .ok_or_else(|| VncError::AuthFailed("No supported VeNCrypt sub-type".to_string()))?;

        // Send selected sub-type
        stream.write_all(&(selected as u32).to_be_bytes())?;

        match selected {
            VeNCryptSubType::Tls => Ok(VencryptResult::Tls),
            VeNCryptSubType::X509 => Ok(VencryptResult::X509),
            VeNCryptSubType::Plain => Ok(VencryptResult::None),
            VeNCryptSubType::VncAuth => Ok(VencryptResult::VncAuth),
            VeNCryptSubType::RsaAes => Ok(VencryptResult::RsaAes),
            VeNCryptSubType::RsaAes256 => Ok(VencryptResult::RsaAes256),
            VeNCryptSubType::AppleDh => Ok(VencryptResult::AppleDh),
            VeNCryptSubType::Sasl => Ok(VencryptResult::Sasl),
            other => Err(VncError::Protocol(format!(
                "Unknown VeNCrypt sub-type: {}",
                other as u32
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
