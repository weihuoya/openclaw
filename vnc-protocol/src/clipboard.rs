//! Extended Clipboard pseudo-encoding (wire value `-1063131698`; QEMU-derived
//! servers use the alternate `-1063131699` — see `crate::encoding`).
//!
//! Supports multiple formats: text, RTF, HTML, DIB (bitmap), files.
//! Data is zlib-compressed.
//!
//! Message types:
//! - 1: Caps (capabilities advertisement)
//! - 2: Request
//! - 3: Peek
//! - 4: Notify
//! - 5: Provide (actual data)
//! - 6: N/A
//!
//! Format flags:
//! - 1 << 0: Text
//! - 1 << 1: RTF
//! - 1 << 2: HTML
//! - 1 << 5: DIB (Device Independent Bitmap)
//! - 1 << 8: Files

use std::io::Read;

use flate2::read::ZlibDecoder;

use crate::ProtocolError;

/// Maximum decompressed size of an extended clipboard payload. The compressed
/// input is already bounded by the caller's CutText length cap, but a
/// decompression bomb could expand it without limit. Clipboard payloads are
/// text/RTF/HTML or the occasional image; 64 MiB covers realistic clipboards
/// and stops bombs.
const MAX_DECOMPRESSED_LEN: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub enum ClipboardMessage {
    /// Server/client capabilities.
    Caps { formats: Vec<ClipboardFormat> },
    /// Request data for specific formats.
    Request { formats: Vec<ClipboardFormat> },
    /// Peek at clipboard (no data transfer).
    Peek { formats: Vec<ClipboardFormat> },
    /// Notify that data is available.
    Notify { formats: Vec<ClipboardFormat> },
    /// Provide actual clipboard data.
    Provide {
        data: Vec<(ClipboardFormat, Vec<u8>)>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardFormat {
    Text,
    Rtf,
    Html,
    Dib,
    Files,
    /// Raw format number for unknown formats.
    Raw(u32),
}

impl ClipboardFormat {
    pub fn from_flag(flag: u32) -> Self {
        match flag {
            1 => ClipboardFormat::Text,
            2 => ClipboardFormat::Rtf,
            4 => ClipboardFormat::Html,
            32 => ClipboardFormat::Dib,
            256 => ClipboardFormat::Files,
            n => ClipboardFormat::Raw(n),
        }
    }

    pub fn to_flag(&self) -> u32 {
        match self {
            ClipboardFormat::Text => 1,
            ClipboardFormat::Rtf => 2,
            ClipboardFormat::Html => 4,
            ClipboardFormat::Dib => 32,
            ClipboardFormat::Files => 256,
            ClipboardFormat::Raw(n) => *n,
        }
    }
}

/// Parse the u32 format-flag list carried by Caps/Request/Peek/Notify
/// messages. Trailing bytes that do not form a complete flag are ignored.
fn parse_format_list(payload: &[u8]) -> Vec<ClipboardFormat> {
    let mut formats = Vec::new();
    let mut offset = 0;
    while offset + 4 <= payload.len() {
        let flag = u32::from_be_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]);
        formats.push(ClipboardFormat::from_flag(flag));
        offset += 4;
    }
    formats
}

/// Decode an extended clipboard message from peer data.
pub fn decode_message(data: &[u8]) -> Result<ClipboardMessage, ProtocolError> {
    if data.len() < 4 {
        return Err(ProtocolError::Protocol(
            "Extended clipboard data too short".to_string(),
        ));
    }

    let flags = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let msg_type = (flags >> 24) & 0x0F;

    // Decompress if needed
    let payload = if (flags >> 24) & 0x80 != 0 {
        let decoder = ZlibDecoder::new(&data[4..]);
        let mut decompressed = Vec::new();
        decoder
            .take(MAX_DECOMPRESSED_LEN + 1)
            .read_to_end(&mut decompressed)?;
        if decompressed.len() as u64 > MAX_DECOMPRESSED_LEN {
            return Err(ProtocolError::Protocol(format!(
                "Extended clipboard payload exceeds {} byte decompression limit",
                MAX_DECOMPRESSED_LEN
            )));
        }
        decompressed
    } else {
        data[4..].to_vec()
    };

    match msg_type {
        1 => Ok(ClipboardMessage::Caps {
            formats: parse_format_list(&payload),
        }),
        2 => Ok(ClipboardMessage::Request {
            formats: parse_format_list(&payload),
        }),
        3 => Ok(ClipboardMessage::Peek {
            formats: parse_format_list(&payload),
        }),
        4 => Ok(ClipboardMessage::Notify {
            formats: parse_format_list(&payload),
        }),
        5 => {
            // Provide
            let mut data_entries = Vec::new();
            let mut offset = 0;
            while offset + 4 <= payload.len() {
                let flag = u32::from_be_bytes([
                    payload[offset],
                    payload[offset + 1],
                    payload[offset + 2],
                    payload[offset + 3],
                ]);
                let format = ClipboardFormat::from_flag(flag);
                offset += 4;

                if offset + 4 > payload.len() {
                    break;
                }
                let len = u32::from_be_bytes([
                    payload[offset],
                    payload[offset + 1],
                    payload[offset + 2],
                    payload[offset + 3],
                ]) as usize;
                offset += 4;

                if offset + len > payload.len() {
                    break;
                }
                let entry_data = payload[offset..offset + len].to_vec();
                offset += len;

                data_entries.push((format, entry_data));
            }
            Ok(ClipboardMessage::Provide { data: data_entries })
        }
        _ => Err(ProtocolError::Protocol(format!(
            "Unknown extended clipboard message type: {}",
            msg_type
        ))),
    }
}

/// Build a Provide message for text data.
pub fn build_text_provide(text: &str) -> std::io::Result<Vec<u8>> {
    let text_bytes = text.as_bytes();
    let mut payload = Vec::new();

    // Flags: type=5 (Provide) | compressed=0x80000000
    // The compression flag is bit 31 (high bit of the big-endian first byte).
    let flags = (5u32 << 24) | 0x80000000;
    payload.extend_from_slice(&flags.to_be_bytes());

    // Build uncompressed payload first
    let mut content = Vec::new();
    // Format: Text
    content.extend_from_slice(&ClipboardFormat::Text.to_flag().to_be_bytes());
    // Length
    content.extend_from_slice(&(text_bytes.len() as u32).to_be_bytes());
    // Data
    content.extend_from_slice(text_bytes);

    // Compress payload
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&content)?;
    let compressed = encoder.finish()?;

    payload.extend_from_slice(&compressed);
    Ok(payload)
}

/// Build a Request message for text.
pub fn build_text_request() -> Vec<u8> {
    let mut payload = Vec::new();
    // Flags: type=2 (Request) | compressed=0
    let flags = 2u32 << 24;
    payload.extend_from_slice(&flags.to_be_bytes());
    payload.extend_from_slice(&ClipboardFormat::Text.to_flag().to_be_bytes());
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_text_provide_sets_compressed_flag_in_first_byte() {
        let data = build_text_provide("hello").unwrap();
        let flags = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

        // Message type is 5 in lower nibble of first byte.
        assert_eq!((flags >> 24) & 0x0F, 5);
        // Compressed flag is high bit of first byte.
        assert_ne!(flags & 0x80000000, 0);
        // The old buggy code set bit 7 of the whole u32 (would appear in last byte).
        assert_eq!(flags & 0x80, 0);
    }

    #[test]
    fn decode_text_provide_roundtrip() {
        let data = build_text_provide("hello world").unwrap();
        let message = decode_message(&data).unwrap();
        match message {
            ClipboardMessage::Provide { data } => {
                assert_eq!(data.len(), 1);
                assert_eq!(data[0].0, ClipboardFormat::Text);
                assert_eq!(data[0].1, b"hello world");
            }
            _ => panic!("expected Provide message"),
        }
    }

    /// A compressed payload that inflates beyond the 64 MiB cap must be
    /// rejected instead of growing the buffer without bound.
    #[test]
    fn decode_message_rejects_decompression_bomb() {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&vec![0u8; 65 * 1024 * 1024]).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut data = Vec::new();
        // Type 1 (Caps) with the compression bit set.
        let flags = (1u32 << 24) | 0x80000000;
        data.extend_from_slice(&flags.to_be_bytes());
        data.extend_from_slice(&compressed);

        assert!(matches!(
            decode_message(&data),
            Err(ProtocolError::Protocol(_))
        ));
    }
}
