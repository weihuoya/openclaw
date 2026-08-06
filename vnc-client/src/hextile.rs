//! Hextile decoder, encoding type 5.
//!
//! Hextile divides the framebuffer into 16x16 tiles. The tile decoding logic
//! is shared in [`vnc_protocol::hextile::decode_tiles`]; this module only keeps
//! the client-specific session state (`HextileState`) and re-exports it.

use std::io::Read;

use crate::framebuffer::{Framebuffer, PixelFormat};
use crate::VncError;

pub use vnc_protocol::hextile::HextileState;

/// Decode a Hextile-encoded rectangle from the stream into the framebuffer.
#[allow(clippy::too_many_arguments)]
pub fn decode<R: Read>(
    stream: &mut R,
    fb: &mut Framebuffer,
    rect_x: usize,
    rect_y: usize,
    rect_w: usize,
    rect_h: usize,
    pixel_format: &PixelFormat,
    state: &mut HextileState,
) -> Result<(), VncError> {
    vnc_protocol::hextile::decode_tiles(
        stream,
        fb,
        rect_x,
        rect_y,
        rect_w,
        rect_h,
        pixel_format,
        state,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use vnc_protocol::hextile::flags;

    #[test]
    fn decode_raw_tile() {
        let mut fb = Framebuffer::new(2, 2);
        // Raw tile: 2x2 RGBA pixels
        let raw = vec![
            0xff, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
            0x00, 0xff,
        ];
        let mut data = vec![flags::RAW];
        data.extend_from_slice(&raw);
        decode(
            &mut Cursor::new(&data),
            &mut fb,
            0,
            0,
            2,
            2,
            &PixelFormat::rgba32(),
            &mut HextileState::new(),
        )
        .unwrap();
        assert_eq!(fb.data(), &raw);
    }

    #[test]
    fn decode_solid_tile() {
        let mut fb = Framebuffer::new(2, 2);
        // Background specified, no subrects
        let bg = vec![0x00, 0x00, 0xff, 0xff]; // blue in BGRA → red in RGBA
        let mut data = vec![flags::BACKGROUND_SPECIFIED];
        data.extend_from_slice(&bg);
        decode(
            &mut Cursor::new(&data),
            &mut fb,
            0,
            0,
            2,
            2,
            &PixelFormat::bgra32(),
            &mut HextileState::new(),
        )
        .unwrap();

        let expected = [0xff, 0x00, 0x00, 0xff]
            .iter()
            .cycle()
            .take(16)
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(fb.data(), &expected);
    }

    #[test]
    fn decode_single_subrect() {
        let mut fb = Framebuffer::new(2, 2);
        // Background: white, foreground: red, 1 subrect at (0,0) size 2x1
        let bg = vec![0xff, 0xff, 0xff, 0xff]; // white BGRA
        let fg = vec![0x00, 0x00, 0xff, 0xff]; // red BGRA
        let mut data =
            vec![flags::BACKGROUND_SPECIFIED | flags::FOREGROUND_SPECIFIED | flags::ANY_SUBRECTS];
        data.extend_from_slice(&bg);
        data.extend_from_slice(&fg);
        data.push(1); // 1 subrect
        data.push(0x00); // xy = 0x00: sx=0, sy=0
        data.push(0x11); // wh = 0x11: sw=2, sh=2
        decode(
            &mut Cursor::new(&data),
            &mut fb,
            0,
            0,
            2,
            2,
            &PixelFormat::bgra32(),
            &mut HextileState::new(),
        )
        .unwrap();

        // Row 0: all red (subrect covers both pixels)
        assert_eq!(fb.data()[0..4], [0xff, 0x00, 0x00, 0xff]);
        assert_eq!(fb.data()[4..8], [0xff, 0x00, 0x00, 0xff]);
        // Row 1: all red (subrect covers both pixels)
        assert_eq!(fb.data()[8..12], [0xff, 0x00, 0x00, 0xff]);
        assert_eq!(fb.data()[12..16], [0xff, 0x00, 0x00, 0xff]);
    }

    #[test]
    fn colors_carry_over_between_tiles_and_rects() {
        // A 32x16 rect = two 16x16 tiles side by side. Tile 1 specifies bg
        // (red) + fg (blue) with one subrect; tile 2 specifies nothing and
        // must inherit both colors. A second decode() call (later rectangle)
        // must still see the inherited colors.
        let mut state = HextileState::new();
        let mut fb = Framebuffer::new(32, 16);

        let mut data = Vec::new();
        // Tile 1: bg red, fg blue, 1 subrect covering the whole tile.
        data.push(flags::BACKGROUND_SPECIFIED | flags::FOREGROUND_SPECIFIED | flags::ANY_SUBRECTS);
        data.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]); // bg: red (BGRA)
        data.extend_from_slice(&[0xff, 0x00, 0x00, 0xff]); // fg: blue (BGRA)
        data.push(1); // 1 subrect
        data.push(0x00); // xy: sx=0, sy=0
        data.push(0xff); // wh: sw=16, sh=16
                         // Tile 2: no flags, no subrects → inherit bg (red) only.
        data.push(0x00);

        decode(
            &mut Cursor::new(&data),
            &mut fb,
            0,
            0,
            32,
            16,
            &PixelFormat::bgra32(),
            &mut state,
        )
        .unwrap();

        let red = [0xff, 0x00, 0x00, 0xff];
        let blue = [0x00, 0x00, 0xff, 0xff];
        // Tile 1 fully covered by the fg subrect → blue.
        assert_eq!(fb.data()[0..4], blue);
        // Tile 2 inherits bg → red.
        let tile2_start = (16 * 4) as usize;
        assert_eq!(fb.data()[tile2_start..tile2_start + 4], red);

        // Later rectangle relying on the inherited bg (no flags at all).
        let mut fb2 = Framebuffer::new(4, 4);
        let data2 = vec![0x00u8]; // no flags, no subrects
        decode(
            &mut Cursor::new(&data2),
            &mut fb2,
            0,
            0,
            4,
            4,
            &PixelFormat::bgra32(),
            &mut state,
        )
        .unwrap();
        assert_eq!(fb2.data()[0..4], red);
    }
}
