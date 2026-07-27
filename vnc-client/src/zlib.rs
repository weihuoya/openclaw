use std::io::Read;

use flate2::read::ZlibDecoder;

use crate::framebuffer::{Framebuffer, PixelFormat};
use crate::VncError;

/// Decode Zlib-encoded rectangle from the stream into the framebuffer.
///
/// Zlib encoding compresses raw pixel data. The format for each rectangle is:
/// - 4 bytes: big-endian length of the compressed data that follows
/// - N bytes: zlib-compressed raw pixel data
///
/// The zlib stream may be reset per-rectangle or maintained across the session.
/// When a fresh zlib header (0x78 0x9C or similar) is seen, the decompressor
/// is reset to handle servers that start a new stream per rectangle.
#[allow(clippy::too_many_arguments)]
pub fn decode<R: Read>(
    stream: &mut R,
    decompress: &mut Option<flate2::Decompress>,
    fb: &mut Framebuffer,
    rect_x: usize,
    rect_y: usize,
    rect_w: usize,
    rect_h: usize,
    pixel_format: &PixelFormat,
) -> Result<(), VncError> {
    let bpp = pixel_format.bytes_per_pixel();
    let row_size = rect_w * bpp;
    let total_size = row_size * rect_h;

    // Read compressed length (big-endian u32)
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let compressed_len = u32::from_be_bytes(len_buf) as usize;

    // Safety limit to prevent OOM from malicious servers
    const MAX_COMPRESSED_LEN: usize = 64 * 1024 * 1024; // 64MB
    if compressed_len > MAX_COMPRESSED_LEN {
        return Err(VncError::Protocol(format!(
            "Zlib compressed length {} exceeds safety limit",
            compressed_len
        )));
    }

    let mut compressed = vec![0u8; compressed_len];
    stream.read_exact(&mut compressed)?;

    // Some servers reset the zlib stream per rectangle (fresh header).
    // Others keep a single stream for the whole session.
    let has_zlib_header = compressed.len() >= 2
        && (compressed[0] & 0x0F) == 8
        && ((compressed[0] as u16) * 256 + (compressed[1] as u16)).trailing_zeros() >= 5;

    let data = if has_zlib_header || decompress.is_none() {
        // Reset / initialize decompressor
        *decompress = Some(flate2::Decompress::new(true));
        decompress_single(&compressed, total_size)?
    } else {
        // Continue with existing session-level decompressor
        decompress_with_session(decompress.as_mut().unwrap(), &compressed, total_size)?
    };

    // Write decompressed raw pixels to framebuffer
    fb.write_region(rect_x, rect_y, rect_w, rect_h, &data, pixel_format);

    Ok(())
}

/// Decompress a single self-contained zlib chunk (fresh stream).
fn decompress_single(compressed: &[u8], expected_size: usize) -> Result<Vec<u8>, VncError> {
    let mut decoder = ZlibDecoder::new(compressed);
    let mut output = Vec::with_capacity(expected_size);
    decoder
        .read_to_end(&mut output)
        .map_err(|e| VncError::Protocol(format!("Zlib decode error: {}", e)))?;
    Ok(output)
}

/// Decompress using a session-level decompressor (continuous stream).
fn decompress_with_session(
    decompress: &mut flate2::Decompress,
    compressed: &[u8],
    expected_size: usize,
) -> Result<Vec<u8>, VncError> {
    use flate2::FlushDecompress;

    let mut output = Vec::with_capacity(expected_size.max(compressed.len() * 4));
    let mut input_offset = 0;

    loop {
        let spare = output.capacity() - output.len();
        if spare < 4096 {
            output.reserve(4096.max(expected_size.saturating_sub(output.len())));
        }

        let status = decompress
            .decompress_vec(
                &compressed[input_offset..],
                &mut output,
                FlushDecompress::Sync,
            )
            .map_err(|e| VncError::Protocol(format!("Zlib session decode error: {}", e)))?;

        input_offset = decompress.total_in() as usize;

        if input_offset == compressed.len() {
            // Flush any remaining buffered output
            let mut prev_len = output.len();
            loop {
                let spare = output.capacity() - output.len();
                if spare < 4096 {
                    output.reserve(4096);
                }
                let _ = decompress.decompress_vec(&[], &mut output, FlushDecompress::Sync);
                if output.len() == prev_len {
                    break;
                }
                prev_len = output.len();
            }
            break;
        }

        if status == flate2::Status::StreamEnd {
            break;
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    #[test]
    fn decode_simple_raw_zlib() {
        // 2x2 RGBA raw pixels
        let raw = vec![
            0xff, 0x00, 0x00, 0xff, // red
            0x00, 0xff, 0x00, 0xff, // green
            0x00, 0x00, 0xff, 0xff, // blue
            0xff, 0xff, 0xff, 0xff, // white
        ];

        // Compress with zlib
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&raw).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut data = Vec::new();
        data.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
        data.extend_from_slice(&compressed);

        let mut fb = Framebuffer::new(2, 2);
        let mut decompress = None;
        decode(
            &mut Cursor::new(&data),
            &mut decompress,
            &mut fb,
            0,
            0,
            2,
            2,
            &PixelFormat::rgba32(),
        )
        .unwrap();

        assert_eq!(fb.data(), &raw);
    }
}
