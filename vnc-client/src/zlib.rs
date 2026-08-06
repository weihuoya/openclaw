//! Zlib encoding decoder (RFB encoding type 6).
//!
//! The decode logic (length-prefixed chunk + session zlib inflate) is shared
//! in [`vnc_protocol::zlib::decode`]; this module provides the client-specific
//! wrapper that targets a `Framebuffer`.

use std::io::Read;

use crate::framebuffer::{Framebuffer, PixelFormat};
use crate::VncError;

pub use vnc_protocol::zlib::SessionInflate;

/// Decode a Zlib-encoded rectangle from the stream into the framebuffer.
///
/// The zlib stream may be reset per-rectangle or maintained across the
/// session; `session` holds the persistent decompressor state.
#[allow(clippy::too_many_arguments)]
pub fn decode<R: Read>(
    stream: &mut R,
    session: &mut SessionInflate,
    fb: &mut Framebuffer,
    rect_x: usize,
    rect_y: usize,
    rect_w: usize,
    rect_h: usize,
    pixel_format: &PixelFormat,
) -> Result<(), VncError> {
    vnc_protocol::zlib::decode(
        stream,
        fb,
        session,
        rect_x,
        rect_y,
        rect_w,
        rect_h,
        pixel_format,
    )?;
    Ok(())
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

        let data = vnc_protocol::zlib::len_prefixed(&compressed);

        let mut fb = Framebuffer::new(2, 2);
        let mut session = SessionInflate::new();
        decode(
            &mut Cursor::new(&data),
            &mut session,
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
