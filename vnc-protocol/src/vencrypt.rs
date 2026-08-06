//! VeNCrypt (RFB security type 19) handshake framing shared by `vnc-client`
//! and `vnc-server`.
//!
//! VeNCrypt version exchange:
//! 1. Server sends its version (2 bytes: major, minor).
//! 2. Client replies with the version it wants to use.
//! 3. Server sends the supported sub-types (u8 count + u32 BE list).
//! 4. Client selects one sub-type (u32 BE).
//!
//! Slice parsers follow the same convention as [`crate::framing`]: they take
//! a buffer that starts at the first byte of the message and return `None`
//! when the buffer does not yet hold a complete message.

/// VeNCrypt protocol major version implemented by both endpoints.
pub const VERSION_MAJOR: u8 = 0;
/// VeNCrypt protocol minor version implemented by both endpoints.
pub const VERSION_MINOR: u8 = 2;

/// The two version bytes sent on the wire for version 0.2.
pub const VERSION_0_2: [u8; 2] = [VERSION_MAJOR, VERSION_MINOR];

/// VeNCrypt sub-type numbers as used by `vnc-client` and `vnc-server`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VeNCryptSubType {
    /// No authentication.
    Plain = 0,
    /// VNC password authentication (DES challenge-response).
    VncAuth = 1,
    /// TLS encryption without further authentication.
    Tls = 2,
    /// SASL authentication.
    Sasl = 22,
    /// Anonymous SASL authentication.
    SaslAnonymous = 24,
    /// RSA-AES key exchange with AES-128-CTR stream encryption.
    RsaAes = 26,
    /// RSA-AES-256 key exchange with AES-128-CTR stream encryption (the
    /// derived 256-bit key is truncated to 16 bytes; see the `rsa_aes`
    /// module docs).
    RsaAes256 = 27,
    /// Apple Diffie-Hellman authentication.
    AppleDh = 30,
    /// TLS with X509 certificate verification.
    X509 = 256,
}

impl VeNCryptSubType {
    /// Map a wire sub-type number to a [`VeNCryptSubType`]; unknown values
    /// return `None`.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Plain),
            1 => Some(Self::VncAuth),
            2 => Some(Self::Tls),
            22 => Some(Self::Sasl),
            24 => Some(Self::SaslAnonymous),
            26 => Some(Self::RsaAes),
            27 => Some(Self::RsaAes256),
            30 => Some(Self::AppleDh),
            256 => Some(Self::X509),
            _ => None,
        }
    }
}

/// True when `major`.`minor` is a VeNCrypt version this implementation can
/// speak: the major version must be 0 and the minor version at least 2.
pub fn version_supported(major: u8, minor: u8) -> bool {
    major == VERSION_MAJOR && minor >= VERSION_MINOR
}

/// Append the VeNCrypt version (0.2) to `out`.
pub fn write_version(out: &mut Vec<u8>) {
    out.extend_from_slice(&VERSION_0_2);
}

/// Parse the peer's 2-byte VeNCrypt version reply from a buffer starting at
/// the major-version byte. Returns `None` when fewer than 2 bytes are
/// available. Use [`version_supported`] to validate the result.
pub fn parse_version_reply(buf: &[u8]) -> Option<(u8, u8)> {
    if buf.len() < 2 {
        return None;
    }
    Some((buf[0], buf[1]))
}

/// Append a VeNCrypt sub-type advertisement (u8 count + u32 BE list) to
/// `out`.
pub fn write_sub_types(out: &mut Vec<u8>, sub_types: &[u32]) {
    debug_assert!(sub_types.len() <= u8::MAX as usize);
    out.push(sub_types.len() as u8);
    for sub_type in sub_types {
        out.extend_from_slice(&sub_type.to_be_bytes());
    }
}

/// Parse the client's selected VeNCrypt sub-type (u32 BE) from a buffer
/// starting at the sub-type's first byte. Returns `None` when fewer than 4
/// bytes are available.
pub fn parse_sub_type(buf: &[u8]) -> Option<u32> {
    if buf.len() < 4 {
        return None;
    }
    Some(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_support_rules() {
        assert!(version_supported(0, 2));
        assert!(version_supported(0, 3));
        assert!(!version_supported(0, 1));
        assert!(!version_supported(0, 0));
        assert!(!version_supported(1, 2));
    }

    #[test]
    fn sub_type_roundtrip() {
        for (value, expected) in [
            (0, VeNCryptSubType::Plain),
            (1, VeNCryptSubType::VncAuth),
            (2, VeNCryptSubType::Tls),
            (22, VeNCryptSubType::Sasl),
            (24, VeNCryptSubType::SaslAnonymous),
            (26, VeNCryptSubType::RsaAes),
            (27, VeNCryptSubType::RsaAes256),
            (30, VeNCryptSubType::AppleDh),
            (256, VeNCryptSubType::X509),
        ] {
            assert_eq!(VeNCryptSubType::from_u32(value), Some(expected));
            assert_eq!(expected as u32, value);
        }
        assert_eq!(VeNCryptSubType::from_u32(3), None);
        assert_eq!(VeNCryptSubType::from_u32(255), None);
    }

    #[test]
    fn version_write_parse_roundtrip() {
        let mut out = Vec::new();
        write_version(&mut out);
        assert_eq!(out, [0x00, 0x02]);
        assert_eq!(parse_version_reply(&out), Some((0, 2)));
        assert!(version_supported(0, 2));
    }

    #[test]
    fn sub_types_write_parse_roundtrip() {
        let advertised = [
            VeNCryptSubType::Tls as u32,
            VeNCryptSubType::X509 as u32,
            VeNCryptSubType::RsaAes256 as u32,
            VeNCryptSubType::VncAuth as u32,
        ];
        let mut out = Vec::new();
        write_sub_types(&mut out, &advertised);
        assert_eq!(out[0], advertised.len() as u8);
        for (i, sub_type) in advertised.iter().enumerate() {
            assert_eq!(parse_sub_type(&out[1 + i * 4..]), Some(*sub_type));
        }
        // The client's selection is a bare u32 parsed with parse_sub_type.
        let selection = (VeNCryptSubType::RsaAes256 as u32).to_be_bytes();
        assert_eq!(
            parse_sub_type(&selection).and_then(VeNCryptSubType::from_u32),
            Some(VeNCryptSubType::RsaAes256)
        );
    }

    #[test]
    fn truncated_parsers_return_none() {
        assert_eq!(parse_version_reply(&[]), None);
        assert_eq!(parse_version_reply(&[0x00]), None);
        for len in 0..4 {
            assert_eq!(parse_sub_type(&[0u8; 4][..len]), None, "len={}", len);
        }
    }
}
