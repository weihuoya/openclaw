use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

use crate::pixel_format::PixelFormat;
use crate::ProtocolError;

/// Maximum accepted desktop-name length in [`ServerInit::read`]. A hostile
/// or broken server could otherwise force a giant allocation.
pub const MAX_NAME_LEN: usize = 4096;

/// Server-init message payload.
#[derive(Debug, Clone)]
pub struct ServerInit {
    pub width: u16,
    pub height: u16,
    pub pixel_format: PixelFormat,
    pub name: String,
}

impl ServerInit {
    /// Read a ServerInit message from a blocking stream.
    ///
    /// The desktop name is decoded lossily and capped at [`MAX_NAME_LEN`]
    /// bytes; a larger advertised length is a [`ProtocolError::Protocol`]
    /// error.
    pub fn read<R: Read>(r: &mut R) -> Result<Self, ProtocolError> {
        let width = r.read_u16::<BigEndian>()?;
        let height = r.read_u16::<BigEndian>()?;
        let pixel_format = PixelFormat::read(r)?;
        let name_len = r.read_u32::<BigEndian>()? as usize;
        if name_len > MAX_NAME_LEN {
            return Err(ProtocolError::Protocol(format!(
                "ServerInit name length too large: {}",
                name_len
            )));
        }
        let mut name_buf = vec![0u8; name_len];
        r.read_exact(&mut name_buf)?;
        Ok(Self {
            width,
            height,
            pixel_format,
            name: String::from_utf8_lossy(&name_buf).to_string(),
        })
    }

    pub fn write<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_u16::<BigEndian>(self.width)?;
        w.write_u16::<BigEndian>(self.height)?;
        self.pixel_format.write(w)?;
        w.write_u32::<BigEndian>(self.name.len() as u32)?;
        w.write_all(self.name.as_bytes())?;
        Ok(())
    }
}

/// Security result codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SecurityResult {
    Ok = 0,
    Failed = 1,
}

/// Maximum accepted handshake failure-reason length in
/// [`read_security_result`]. The reason is a short human-readable string;
/// 64 KiB is far beyond any legitimate message and stops a hostile peer from
/// forcing a giant allocation.
pub const MAX_REASON_LEN: usize = 64 * 1024;

/// Append a security-result message to `out`: the u32 result code followed,
/// on failure, by a u32 length-prefixed reason string (RFB 3.8).
pub fn write_security_result(out: &mut Vec<u8>, result: SecurityResult, reason: Option<&str>) {
    out.extend_from_slice(&(result as u32).to_be_bytes());
    if result == SecurityResult::Failed {
        let reason = reason.unwrap_or("");
        out.extend_from_slice(&(reason.len() as u32).to_be_bytes());
        out.extend_from_slice(reason.as_bytes());
    }
}

/// Read a security-result message from a blocking stream. On failure the
/// trailing reason string is read as well (its length capped at
/// [`MAX_REASON_LEN`]); a result code other than 0/1 is a
/// [`ProtocolError::Protocol`] error.
pub fn read_security_result<R: Read>(
    r: &mut R,
) -> Result<(SecurityResult, Option<String>), ProtocolError> {
    let code = r.read_u32::<BigEndian>()?;
    match code {
        0 => Ok((SecurityResult::Ok, None)),
        1 => {
            let reason = crate::handshake::read_failure_reason(r)?;
            Ok((SecurityResult::Failed, Some(reason)))
        }
        other => Err(ProtocolError::Protocol(format!(
            "invalid security result code: {}",
            other
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_init_write_read_roundtrip() {
        let init = ServerInit {
            width: 1920,
            height: 1080,
            pixel_format: PixelFormat::bgra32(),
            name: "test desktop".to_string(),
        };
        let mut buf = Vec::new();
        init.write(&mut buf).unwrap();
        assert_eq!(buf.len(), 24 + "test desktop".len());

        let parsed = ServerInit::read(&mut &buf[..]).unwrap();
        assert_eq!(parsed.width, 1920);
        assert_eq!(parsed.height, 1080);
        assert_eq!(parsed.pixel_format, PixelFormat::bgra32());
        assert_eq!(parsed.name, "test desktop");
    }

    #[test]
    fn server_init_read_rejects_oversized_name() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1024u16.to_be_bytes());
        buf.extend_from_slice(&768u16.to_be_bytes());
        PixelFormat::rgba32().write(&mut buf).unwrap();
        buf.extend_from_slice(&((MAX_NAME_LEN as u32) + 1).to_be_bytes());
        let err = ServerInit::read(&mut &buf[..]).unwrap_err();
        assert!(matches!(err, ProtocolError::Protocol(_)));
    }

    #[test]
    fn server_init_read_rejects_invalid_pixel_format() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1024u16.to_be_bytes());
        buf.extend_from_slice(&768u16.to_be_bytes());
        buf.extend_from_slice(&[0u8; 16]); // bits-per-pixel 0: invalid
        buf.extend_from_slice(&0u32.to_be_bytes());
        assert!(ServerInit::read(&mut &buf[..]).is_err());
    }

    #[test]
    fn server_init_read_truncated_is_io_error() {
        let init = ServerInit {
            width: 800,
            height: 600,
            pixel_format: PixelFormat::rgba32(),
            name: "x".to_string(),
        };
        let mut buf = Vec::new();
        init.write(&mut buf).unwrap();
        for len in 0..buf.len() {
            assert!(ServerInit::read(&mut &buf[..len]).is_err(), "len={}", len);
        }
    }

    #[test]
    fn security_result_ok_roundtrip() {
        let mut buf = Vec::new();
        write_security_result(&mut buf, SecurityResult::Ok, None);
        assert_eq!(buf, 0u32.to_be_bytes());
        assert_eq!(
            read_security_result(&mut &buf[..]).unwrap(),
            (SecurityResult::Ok, None)
        );
        // A reason attached to Ok is not written.
        let mut buf = Vec::new();
        write_security_result(&mut buf, SecurityResult::Ok, Some("ignored"));
        assert_eq!(buf, 0u32.to_be_bytes());
    }

    #[test]
    fn security_result_failed_roundtrip() {
        let mut buf = Vec::new();
        write_security_result(&mut buf, SecurityResult::Failed, Some("bad password"));
        assert_eq!(buf[..4], 1u32.to_be_bytes());
        assert_eq!(
            read_security_result(&mut &buf[..]).unwrap(),
            (SecurityResult::Failed, Some("bad password".to_string()))
        );

        // A failure without a reason carries an empty reason string.
        let mut buf = Vec::new();
        write_security_result(&mut buf, SecurityResult::Failed, None);
        assert_eq!(
            read_security_result(&mut &buf[..]).unwrap(),
            (SecurityResult::Failed, Some(String::new()))
        );
    }

    #[test]
    fn read_security_result_rejects_unknown_code() {
        let buf = 7u32.to_be_bytes();
        let err = read_security_result(&mut &buf[..]).unwrap_err();
        assert!(matches!(err, ProtocolError::Protocol(_)));
    }

    #[test]
    fn read_security_result_rejects_oversized_reason() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&((MAX_REASON_LEN as u32) + 1).to_be_bytes());
        let err = read_security_result(&mut &buf[..]).unwrap_err();
        assert!(matches!(err, ProtocolError::Protocol(_)));
    }

    #[test]
    fn read_security_result_truncated_is_io_error() {
        let mut buf = Vec::new();
        write_security_result(&mut buf, SecurityResult::Failed, Some("denied"));
        for len in 0..buf.len() {
            assert!(
                read_security_result(&mut &buf[..len]).is_err(),
                "len={}",
                len
            );
        }
    }
}
