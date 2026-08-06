//! Extended Clipboard message encode/decode.
//!
//! The implementation lives in the shared `vnc-protocol` crate; this module
//! re-exports it so the public `vnc_client::clipboard` API is unchanged.

pub use vnc_protocol::clipboard::{
    build_text_provide, build_text_request, decode_message, ClipboardFormat, ClipboardMessage,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: the re-exported builder and decoder round-trip text.
    #[test]
    fn reexported_text_provide_roundtrip() {
        let data = build_text_provide("smoke").unwrap();
        match decode_message(&data).unwrap() {
            ClipboardMessage::Provide { data } => {
                assert_eq!(data.len(), 1);
                assert_eq!(data[0].0, ClipboardFormat::Text);
                assert_eq!(data[0].1, b"smoke");
            }
            _ => panic!("expected Provide message"),
        }
    }
}
