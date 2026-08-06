//! RFB handshake framing: version banner parsing and failure-reason reads
//! shared by `vnc-client` and `vnc-server`.
//!
//! Slice parsers follow the same convention as [`crate::framing`]: they take
//! a buffer that starts at the first byte of the message and return `None`
//! when the buffer does not yet hold a complete message. `Read` helpers
//! serve endpoints with blocking stream reads.

use std::io::Read;

use byteorder::{BigEndian, ReadBytesExt};

use crate::server_init::MAX_REASON_LEN;
use crate::ProtocolError;

/// Wire length of the RFB version banner (`"RFB %03u.%03u\n"`).
pub const RFB_VERSION_BANNER_LEN: usize = 12;

/// Parse an RFB version banner (`"RFB %03u.%03u\n"`) from a buffer starting
/// at the banner's first byte.
///
/// Returns `None` when fewer than [`RFB_VERSION_BANNER_LEN`] bytes are
/// available; otherwise the parse result — a malformed banner is a
/// [`ProtocolError::Protocol`] error, not a need-more-data signal. Whether
/// the parsed version is acceptable is left to the caller (e.g. the client
/// additionally accepts `003.889` for Apple high-performance mode).
pub fn parse_rfb_version(buf: &[u8]) -> Option<Result<(u32, u32), ProtocolError>> {
    if buf.len() < RFB_VERSION_BANNER_LEN {
        return None;
    }
    let banner = &buf[..RFB_VERSION_BANNER_LEN];
    let invalid = || {
        ProtocolError::Protocol(format!(
            "invalid RFB version string: {}",
            String::from_utf8_lossy(banner).trim_end()
        ))
    };
    if !banner.starts_with(b"RFB ") || banner[7] != b'.' || banner[11] != b'\n' {
        return Some(Err(invalid()));
    }
    let digits = |slice: &[u8]| -> Option<u32> {
        if slice.iter().all(u8::is_ascii_digit) {
            std::str::from_utf8(slice).ok()?.parse().ok()
        } else {
            None
        }
    };
    match (digits(&banner[4..7]), digits(&banner[8..11])) {
        (Some(major), Some(minor)) => Some(Ok((major, minor))),
        _ => Some(Err(invalid())),
    }
}

/// Read a handshake failure reason string (u32 BE length + bytes) from a
/// blocking stream, capping the accepted length at [`MAX_REASON_LEN`].
///
/// The reason is a short human-readable string sent when the server offers
/// zero security types (RFB 3.8) or fails the security handshake; the cap
/// stops a hostile peer from forcing a giant allocation. The string is
/// decoded lossily.
pub fn read_failure_reason<R: Read>(r: &mut R) -> Result<String, ProtocolError> {
    let len = r.read_u32::<BigEndian>()? as usize;
    if len > MAX_REASON_LEN {
        return Err(ProtocolError::Protocol(format!(
            "handshake failure reason length {} exceeds limit",
            len
        )));
    }
    let mut reason = vec![0u8; len];
    r.read_exact(&mut reason)?;
    Ok(String::from_utf8_lossy(&reason).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rfb_version_valid() {
        for (banner, expected) in [
            (&b"RFB 003.008\n"[..], (3, 8)),
            (&b"RFB 003.003\n"[..], (3, 3)),
            (&b"RFB 003.889\n"[..], (3, 889)),
            // Trailing bytes belong to the next message and are ignored.
            (&b"RFB 003.008\nextra"[..], (3, 8)),
        ] {
            match parse_rfb_version(banner) {
                Some(Ok(version)) => assert_eq!(version, expected),
                other => panic!(
                    "expected Ok({:?}), got {:?}",
                    expected,
                    other.map(|r| r.ok())
                ),
            }
        }
    }

    #[test]
    fn parse_rfb_version_truncated_is_none() {
        for len in 0..RFB_VERSION_BANNER_LEN {
            assert!(
                parse_rfb_version(&b"RFB 003.008\n"[..len]).is_none(),
                "len={}",
                len
            );
        }
    }

    #[test]
    fn parse_rfb_version_invalid_format() {
        for case in [
            // Not RFB at all (e.g. port scanner / HTTP probe garbage).
            &b"GET / HTTP/1"[..],
            // Missing newline terminator.
            &b"RFB 003.008x"[..],
            // Non-digit version fields.
            &b"RFB 00a.008\n"[..],
            // Wrong field width.
            &b"RFB 003.08\n\n"[..],
        ] {
            let err = parse_rfb_version(case).unwrap().unwrap_err();
            assert!(matches!(err, ProtocolError::Protocol(_)));
        }
    }

    #[test]
    fn read_failure_reason_roundtrip() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u32.to_be_bytes());
        buf.extend_from_slice(b"nope!");
        let reason = read_failure_reason(&mut &buf[..]).unwrap();
        assert_eq!(reason, "nope!");
    }

    #[test]
    fn read_failure_reason_rejects_oversized_length() {
        let buf = ((MAX_REASON_LEN as u32) + 1).to_be_bytes();
        let err = read_failure_reason(&mut &buf[..]).unwrap_err();
        assert!(matches!(err, ProtocolError::Protocol(_)));
    }

    #[test]
    fn read_failure_reason_truncated_is_io_error() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&4u32.to_be_bytes());
        buf.extend_from_slice(b"ab");
        assert!(read_failure_reason(&mut &buf[..]).is_err());
    }
}
