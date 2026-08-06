//! Shared error type for protocol-level encoders and decoders.
//!
//! `vnc-protocol` helpers that read from or write to byte streams return this
//! type instead of `std::io::Error` so that higher-level protocol errors (e.g.
//! invalid subencoding, malformed cursor data, decompressed size overflow) can be
//! distinguished from raw IO failures. The `vnc-client` and `vnc-server` crates
//! map it back to their own error types via `From` implementations.

use std::io;

/// Errors returned by shared protocol encoders/decoders.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Protocol error: {0}")]
    Protocol(String),
}

impl From<String> for ProtocolError {
    fn from(msg: String) -> Self {
        Self::Protocol(msg)
    }
}

impl From<&str> for ProtocolError {
    fn from(msg: &str) -> Self {
        Self::Protocol(msg.to_string())
    }
}

/// Convert back to `std::io::Error` for callers whose error type is
/// `io::Result` (e.g. the `vnc-server` per-client state machine). A wrapped
/// IO error is returned as-is; a protocol error becomes `InvalidData`.
impl From<ProtocolError> for io::Error {
    fn from(err: ProtocolError) -> Self {
        match err {
            ProtocolError::Io(e) => e,
            ProtocolError::Protocol(msg) => io::Error::new(io::ErrorKind::InvalidData, msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_io_error_wraps_io_variant() {
        let io_err = io::Error::new(io::ErrorKind::UnexpectedEof, "truncated");
        let err = ProtocolError::from(io_err);
        assert!(matches!(err, ProtocolError::Io(_)));
        assert_eq!(err.to_string(), "IO error: truncated");
    }

    #[test]
    fn from_string_and_str_build_protocol_variant() {
        let err = ProtocolError::from("bad rect".to_string());
        assert!(matches!(err, ProtocolError::Protocol(_)));
        assert_eq!(err.to_string(), "Protocol error: bad rect");

        let err = ProtocolError::from("bad rect");
        assert!(matches!(err, ProtocolError::Protocol(_)));
        assert_eq!(err.to_string(), "Protocol error: bad rect");
    }

    #[test]
    fn into_io_error_preserves_io_and_maps_protocol_to_invalid_data() {
        let io_err = io::Error::new(io::ErrorKind::UnexpectedEof, "truncated");
        let err: io::Error = ProtocolError::Io(io_err).into();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

        let err: io::Error = ProtocolError::Protocol("bad rect".to_string()).into();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("bad rect"));
    }
}
