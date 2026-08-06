/// RFB security types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecurityType {
    Invalid = 0,
    None = 1,
    VncAuth = 2,
    RsaAes = 5,
    Tight = 16,
    VeNCrypt = 19,
    AppleDh = 30,
    RsaAes256 = 129,
}

impl SecurityType {
    /// Map a wire security-type byte to a [`SecurityType`]; unknown values
    /// return `None`.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Invalid),
            1 => Some(Self::None),
            2 => Some(Self::VncAuth),
            5 => Some(Self::RsaAes),
            16 => Some(Self::Tight),
            19 => Some(Self::VeNCrypt),
            30 => Some(Self::AppleDh),
            129 => Some(Self::RsaAes256),
            _ => None,
        }
    }
}

pub const SECURITY_NONE: u8 = SecurityType::None as u8;
pub const SECURITY_VNC_AUTH: u8 = SecurityType::VncAuth as u8;
pub const SECURITY_RSA_AES: u8 = SecurityType::RsaAes as u8;
pub const SECURITY_TIGHT: u8 = SecurityType::Tight as u8;
pub const SECURITY_VENCRYPT: u8 = SecurityType::VeNCrypt as u8;
pub const SECURITY_APPLE_DH: u8 = SecurityType::AppleDh as u8;
pub const SECURITY_RSA_AES256: u8 = SecurityType::RsaAes256 as u8;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_u8_roundtrip() {
        for value in [0u8, 1, 2, 5, 16, 19, 30, 129] {
            let security_type = SecurityType::from_u8(value).unwrap();
            assert_eq!(security_type as u8, value);
        }
        assert_eq!(SecurityType::from_u8(3), None);
        assert_eq!(SecurityType::from_u8(255), None);
    }

    #[test]
    fn constants_match_enum_values() {
        assert_eq!(SECURITY_NONE, SecurityType::None as u8);
        assert_eq!(SECURITY_VNC_AUTH, SecurityType::VncAuth as u8);
        assert_eq!(SECURITY_RSA_AES, SecurityType::RsaAes as u8);
        assert_eq!(SECURITY_TIGHT, SecurityType::Tight as u8);
        assert_eq!(SECURITY_VENCRYPT, SecurityType::VeNCrypt as u8);
        assert_eq!(SECURITY_APPLE_DH, SecurityType::AppleDh as u8);
        assert_eq!(SECURITY_RSA_AES256, SecurityType::RsaAes256 as u8);
    }

    #[test]
    fn from_u8_covers_every_variant() {
        for variant in [
            SecurityType::Invalid,
            SecurityType::None,
            SecurityType::VncAuth,
            SecurityType::RsaAes,
            SecurityType::Tight,
            SecurityType::VeNCrypt,
            SecurityType::AppleDh,
            SecurityType::RsaAes256,
        ] {
            assert_eq!(SecurityType::from_u8(variant as u8), Some(variant));
        }
    }
}
