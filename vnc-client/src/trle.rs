//! TRLE (Tiled Run-Length Encoding) decoder, encoding type 15.
//!
//! TRLE uses exactly the same 64x64 tile format as ZRLE (subencodings 0 raw,
//! 1 solid, 2..=16 packed palette, 128 plain RLE, 129..=255 palette RLE); the
//! only difference is the transport: TRLE tiles are read directly from the
//! stream, while ZRLE wraps the tile stream in a zlib stream with a 4-byte
//! length prefix per rectangle. The tile decoding logic is shared with the
//! ZRLE decoder in [`vnc_protocol::zrle::decode_tiles`].

use std::io::Read;

use crate::framebuffer::{Framebuffer, PixelFormat};
use crate::VncError;

/// Decode a TRLE rectangle from the stream into the framebuffer.
pub fn decode<R: Read>(
    stream: &mut R,
    framebuffer: &mut Framebuffer,
    x: usize,
    y: usize,
    width: usize,
    height: usize,
    pixel_format: &PixelFormat,
) -> Result<(), VncError> {
    vnc_protocol::zrle::decode_tiles(stream, framebuffer, x, y, width, height, pixel_format)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn fmt() -> PixelFormat {
        PixelFormat::rgba32()
    }

    #[test]
    fn raw_tile_3_byte_cpixel() {
        // 2x1 raw tile: red, green CPIXELs (3 bytes each).
        let mut fb = Framebuffer::new(2, 1);
        let data = vec![0u8, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00];
        decode(&mut Cursor::new(&data), &mut fb, 0, 0, 2, 1, &fmt()).unwrap();
        assert_eq!(&fb.data()[0..4], &[0xff, 0x00, 0x00, 0xff]);
        assert_eq!(&fb.data()[4..8], &[0x00, 0xff, 0x00, 0xff]);
    }

    #[test]
    fn solid_tile() {
        let mut fb = Framebuffer::new(2, 2);
        let data = vec![1u8, 0xff, 0x00, 0x00];
        decode(&mut Cursor::new(&data), &mut fb, 0, 0, 2, 2, &fmt()).unwrap();
        for i in 0..4 {
            assert_eq!(&fb.data()[i * 4..i * 4 + 4], &[0xff, 0x00, 0x00, 0xff]);
        }
    }

    #[test]
    fn packed_palette_two_color_scanline_padding() {
        // 5x2 tile, 2 colours -> 1 bit per pixel, each scanline padded to a
        // whole byte. Row 0: R G R G R -> 0b01010xxx = 0x50.
        // Row 1: G R G R G -> 0b10101xxx = 0xa8.
        let red = [0xff, 0x00, 0x00];
        let green = [0x00, 0xff, 0x00];
        let mut data = vec![2u8]; // packed palette, 2 colours
        data.extend_from_slice(&red);
        data.extend_from_slice(&green);
        data.push(0x50);
        data.push(0xa8);

        let mut fb = Framebuffer::new(5, 2);
        decode(&mut Cursor::new(&data), &mut fb, 0, 0, 5, 2, &fmt()).unwrap();

        let px = |i: usize| &fb.data()[i * 4..i * 4 + 4];
        let r = [0xff, 0x00, 0x00, 0xff];
        let g = [0x00, 0xff, 0x00, 0xff];
        assert_eq!(px(0), &r);
        assert_eq!(px(1), &g);
        assert_eq!(px(2), &r);
        assert_eq!(px(3), &g);
        assert_eq!(px(4), &r);
        assert_eq!(px(5), &g);
        assert_eq!(px(6), &r);
        assert_eq!(px(7), &g);
        assert_eq!(px(8), &r);
        assert_eq!(px(9), &g);
    }

    #[test]
    fn plain_rle_run_length_continuation() {
        // 64x5 tile = 320 pixels: a run of 300 red pixels followed by a run of
        // 20 green pixels. Run length 300 -> 299 = 255 + 44 -> [255, 44];
        // run length 20 -> 19 -> [19].
        let red = [0xff, 0x00, 0x00];
        let green = [0x00, 0xff, 0x00];
        let mut data = vec![128u8]; // plain RLE
        data.extend_from_slice(&red);
        data.push(255);
        data.push(44);
        data.extend_from_slice(&green);
        data.push(19);

        let mut fb = Framebuffer::new(64, 5);
        decode(&mut Cursor::new(&data), &mut fb, 0, 0, 64, 5, &fmt()).unwrap();

        let r = [0xff, 0x00, 0x00, 0xff];
        let g = [0x00, 0xff, 0x00, 0xff];
        for i in 0..300 {
            assert_eq!(&fb.data()[i * 4..i * 4 + 4], &r, "pixel {}", i);
        }
        for i in 300..320 {
            assert_eq!(&fb.data()[i * 4..i * 4 + 4], &g, "pixel {}", i);
        }
    }

    #[test]
    fn palette_rle() {
        // Palette RLE with 2 colours (subencoding 130): 3 red then 1 green.
        let red = [0xff, 0x00, 0x00];
        let green = [0x00, 0xff, 0x00];
        let mut data = vec![130u8]; // 128 + palette size 2
        data.extend_from_slice(&red);
        data.extend_from_slice(&green);
        // Run of 3 red: index 0 with top bit set, length 3 -> [0x80, 2].
        data.push(0x80);
        data.push(2);
        // Single green: literal index 1.
        data.push(1);

        let mut fb = Framebuffer::new(4, 1);
        decode(&mut Cursor::new(&data), &mut fb, 0, 0, 4, 1, &fmt()).unwrap();
        assert_eq!(&fb.data()[0..4], &[0xff, 0x00, 0x00, 0xff]);
        assert_eq!(&fb.data()[4..8], &[0xff, 0x00, 0x00, 0xff]);
        assert_eq!(&fb.data()[8..12], &[0xff, 0x00, 0x00, 0xff]);
        assert_eq!(&fb.data()[12..16], &[0x00, 0xff, 0x00, 0xff]);
    }

    #[test]
    fn invalid_subencoding_is_rejected() {
        // Subencodings 17..=127 are invalid per the RFB spec.
        let mut fb = Framebuffer::new(1, 1);
        let data = vec![17u8];
        assert!(decode(&mut Cursor::new(&data), &mut fb, 0, 0, 1, 1, &fmt()).is_err());
    }
}
