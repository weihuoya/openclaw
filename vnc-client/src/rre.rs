//! RRE (Rise-and-Run-length Encoding) decoder, encoding type 2.
//!
//! The RRE decode logic is shared in [`vnc_protocol::rre::decode`]; this
//! module provides the client-specific wrapper that targets a `Framebuffer`.

use std::io::Read;

use crate::framebuffer::{Framebuffer, PixelFormat};
use crate::VncError;

/// Decode an RRE-encoded rectangle from the stream into the framebuffer.
#[allow(clippy::too_many_arguments)]
pub fn decode<R: Read>(
    stream: &mut R,
    framebuffer: &mut Framebuffer,
    x: usize,
    y: usize,
    width: usize,
    height: usize,
    pixel_format: &PixelFormat,
) -> Result<(), VncError> {
    vnc_protocol::rre::decode(stream, framebuffer, x, y, width, height, pixel_format)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn decode_zero_subrects() {
        let mut fb = Framebuffer::new(2, 2);
        // 0 subrects, then red background pixel in BGRA: [B, G, R, A] = [0, 0, 0xff, 0xff]
        let data = vec![
            0x00, 0x00, 0x00, 0x00, // num_subrects = 0
            0x00, 0x00, 0xff, 0xff, // background in BGRA → red in RGBA
        ];
        decode(
            &mut Cursor::new(&data),
            &mut fb,
            0,
            0,
            2,
            2,
            &PixelFormat::bgra32(),
        )
        .unwrap();

        // All pixels should be red (RGBA)
        let expected = vec![
            0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00,
            0x00, 0xff,
        ];
        assert_eq!(fb.data(), &expected);
    }

    #[test]
    fn decode_one_subrect() {
        let mut fb = Framebuffer::new(3, 2);
        // 1 subrect, white background, red foreground at (1,0) size 2x1
        // BGRA white: [0xff, 0xff, 0xff, 0xff] → RGBA white
        // BGRA red:  [0x00, 0x00, 0xff, 0xff] → RGBA red
        let data = vec![
            0x00, 0x00, 0x00, 0x01, // num_subrects = 1
            0xff, 0xff, 0xff, 0xff, // background: white (BGRA)
            0x00, 0x00, 0xff, 0xff, // foreground: red (BGRA)
            0x00, 0x01, // sx = 1
            0x00, 0x00, // sy = 0
            0x00, 0x02, // sw = 2
            0x00, 0x01, // sh = 1
        ];
        decode(
            &mut Cursor::new(&data),
            &mut fb,
            0,
            0,
            3,
            2,
            &PixelFormat::bgra32(),
        )
        .unwrap();

        // Row 0: white, red, red
        assert_eq!(fb.data()[0..4], [0xff, 0xff, 0xff, 0xff]); // white
        assert_eq!(fb.data()[4..8], [0xff, 0x00, 0x00, 0xff]); // red
        assert_eq!(fb.data()[8..12], [0xff, 0x00, 0x00, 0xff]); // red
                                                                // Row 1: all white
        assert_eq!(fb.data()[12..16], [0xff, 0xff, 0xff, 0xff]);
    }
}
