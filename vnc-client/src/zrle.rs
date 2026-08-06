//! ZRLE (Zlib Run-Length Encoding) decoder, encoding type 16.
//!
//! ZRLE rectangles are zlib-compressed streams of 64x64 tiles. The tile format
//! is identical to TRLE (encoding 15); the shared tile decoder lives in
//! [`vnc_protocol::zrle::decode_tiles`], and the persistent zlib session
//! decompressor in [`vnc_protocol::zlib::SessionInflate`]. This module only
//! wires the two together.

use std::io::{Cursor, Read};

use vnc_protocol::zlib::{self, SessionInflate};
use vnc_protocol::zrle::TILE_SIZE;

use crate::framebuffer::{Framebuffer, PixelFormat};
use crate::VncError;

/// Decode a ZRLE-encoded rectangle from the stream into the framebuffer.
///
/// `decompress` is maintained across rectangles to support servers that keep a
/// single zlib stream open for the whole session (e.g. wayvnc/neatvnc). It is
/// reset whenever a fresh zlib header is seen at the start of a rectangle.
#[allow(clippy::too_many_arguments)]
pub fn decode<R: Read>(
    stream: &mut R,
    decompress: &mut Option<SessionInflate>,
    fb: &mut Framebuffer,
    rect_x: usize,
    rect_y: usize,
    rect_w: usize,
    rect_h: usize,
    pixel_format: &PixelFormat,
) -> Result<(), VncError> {
    let compressed = zlib::read_len_prefixed(stream, zlib::MAX_COMPRESSED_LEN)?;

    // Some servers (e.g. wayvnc) use a single zlib stream for all ZRLE
    // rectangles; others start a new zlib stream per rectangle. Reset the
    // decompressor whenever we see a fresh zlib header.
    if zlib::is_zlib_header(&compressed) {
        log::debug!("ZRLE detected fresh zlib header, resetting decompressor");
        *decompress = Some(SessionInflate::new());
    }

    let session = decompress
        .as_mut()
        .ok_or_else(|| VncError::Protocol("ZRLE decompressor not initialized".to_string()))?;

    let bpp = pixel_format.bytes_per_cpixel();
    let tile_count = rect_w.div_ceil(TILE_SIZE) * rect_h.div_ceil(TILE_SIZE);
    let max_output = rect_w * rect_h * (bpp + 1) + tile_count + 64;
    // `min_out` stays 0: a truncated tile stream is reported by
    // `decode_tiles` as an IO error, preserving the historical error variant.
    let data = session.feed(&compressed, 0, max_output)?;
    let mut cursor = Cursor::new(&data);

    vnc_protocol::zrle::decode_tiles(
        &mut cursor,
        fb,
        rect_x,
        rect_y,
        rect_w,
        rect_h,
        pixel_format,
    )?;

    let consumed = cursor.position() as usize;
    let remaining = data.len().saturating_sub(consumed);
    if remaining != 0 {
        log::warn!(
            "ZRLE rectangle {}x{}@({}, {}) has {} leftover decompressed bytes after tile decoding",
            rect_w,
            rect_h,
            rect_x,
            rect_y,
            remaining
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn compress(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn build_zrle_payload(compressed: &[u8]) -> Vec<u8> {
        zlib::len_prefixed(compressed)
    }

    #[test]
    fn solid_3_byte_cpixel() {
        // ZRLE solid tile with 3-byte CPIXEL (32-bit depth 24 little-endian).
        let fmt = PixelFormat::rgba32();
        let mut tile = vec![1u8]; // solid subencoding
        tile.extend_from_slice(&[0xff, 0x00, 0x00]); // red CPIXEL

        let mut fb = Framebuffer::new(2, 2);
        decode(
            &mut Cursor::new(&build_zrle_payload(&compress(&tile))),
            &mut None,
            &mut fb,
            0,
            0,
            2,
            2,
            &fmt,
        )
        .unwrap();

        for i in 0..4 {
            assert_eq!(&fb.data()[i * 4..i * 4 + 4], &[0xff, 0x00, 0x00, 0xff]);
        }
    }

    #[test]
    fn palette_rle_neatvnc_format() {
        // neatvnc style palette RLE: subencoding = 128 | palette_size.
        // 2-color palette, 3-byte CPIXELs, 4 pixels: red red red green.
        let fmt = PixelFormat::rgba32();
        let red = [0xff, 0x00, 0x00];
        let green = [0x00, 0xff, 0x00];

        let mut tile = vec![130u8]; // 128 | 2
        tile.extend_from_slice(&red);
        tile.extend_from_slice(&green);
        // Three red pixels: index 0 with high bit set, length 3 -> 0x80, 2
        tile.push(0x80);
        tile.push(2);
        // One green pixel: index 1 without high bit
        tile.push(1);

        let mut fb = Framebuffer::new(4, 1);
        decode(
            &mut Cursor::new(&build_zrle_payload(&compress(&tile))),
            &mut None,
            &mut fb,
            0,
            0,
            4,
            1,
            &fmt,
        )
        .unwrap();

        assert_eq!(&fb.data()[0..4], &[0xff, 0x00, 0x00, 0xff]);
        assert_eq!(&fb.data()[4..8], &[0xff, 0x00, 0x00, 0xff]);
        assert_eq!(&fb.data()[8..12], &[0xff, 0x00, 0x00, 0xff]);
        assert_eq!(&fb.data()[12..16], &[0x00, 0xff, 0x00, 0xff]);
    }

    #[test]
    fn plain_rle_3_byte_cpixel() {
        let fmt = PixelFormat::rgba32();
        let red = [0xff, 0x00, 0x00];
        let green = [0x00, 0xff, 0x00];

        let mut tile = vec![128u8]; // plain RLE
        tile.extend_from_slice(&red);
        tile.push(2); // run length 3
        tile.extend_from_slice(&green);
        tile.push(0); // run length 1

        let mut fb = Framebuffer::new(4, 1);
        decode(
            &mut Cursor::new(&build_zrle_payload(&compress(&tile))),
            &mut None,
            &mut fb,
            0,
            0,
            4,
            1,
            &fmt,
        )
        .unwrap();

        assert_eq!(&fb.data()[0..4], &[0xff, 0x00, 0x00, 0xff]);
        assert_eq!(&fb.data()[4..8], &[0xff, 0x00, 0x00, 0xff]);
        assert_eq!(&fb.data()[8..12], &[0xff, 0x00, 0x00, 0xff]);
        assert_eq!(&fb.data()[12..16], &[0x00, 0xff, 0x00, 0xff]);
    }

    #[test]
    fn packed_palette_4_color() {
        let fmt = PixelFormat::rgba32();
        let red = [0xff, 0x00, 0x00];
        let green = [0x00, 0xff, 0x00];
        let blue = [0x00, 0x00, 0xff];
        let white = [0xff, 0xff, 0xff];

        let mut tile = vec![4u8]; // 4 colors
        tile.extend_from_slice(&red);
        tile.extend_from_slice(&green);
        tile.extend_from_slice(&blue);
        tile.extend_from_slice(&white);
        // 4 pixels, 2 bits each: 00 01 10 11 = 0b00011011 = 0x1b
        tile.push(0x1b);

        let mut fb = Framebuffer::new(4, 1);
        decode(
            &mut Cursor::new(&build_zrle_payload(&compress(&tile))),
            &mut None,
            &mut fb,
            0,
            0,
            4,
            1,
            &fmt,
        )
        .unwrap();

        assert_eq!(&fb.data()[0..4], &[0xff, 0x00, 0x00, 0xff]);
        assert_eq!(&fb.data()[4..8], &[0x00, 0xff, 0x00, 0xff]);
        assert_eq!(&fb.data()[8..12], &[0x00, 0x00, 0xff, 0xff]);
        assert_eq!(&fb.data()[12..16], &[0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn packed_palette_two_color_scanline_padding() {
        // 5x2 tile, 2 colours -> 1 bit per pixel, each scanline padded to a
        // whole byte. Row 0: R G R G R -> 0b01010xxx = 0x50.
        // Row 1: G R G R G -> 0b10101xxx = 0xa8.
        let fmt = PixelFormat::rgba32();
        let red = [0xff, 0x00, 0x00];
        let green = [0x00, 0xff, 0x00];

        let mut tile = vec![2u8]; // packed palette, 2 colours
        tile.extend_from_slice(&red);
        tile.extend_from_slice(&green);
        tile.push(0x50);
        tile.push(0xa8);

        let mut fb = Framebuffer::new(5, 2);
        decode(
            &mut Cursor::new(&build_zrle_payload(&compress(&tile))),
            &mut None,
            &mut fb,
            0,
            0,
            5,
            2,
            &fmt,
        )
        .unwrap();

        let r = [0xff, 0x00, 0x00, 0xff];
        let g = [0x00, 0xff, 0x00, 0xff];
        let expected = [r, g, r, g, r, g, r, g, r, g];
        for (i, want) in expected.iter().enumerate() {
            assert_eq!(&fb.data()[i * 4..i * 4 + 4], want, "pixel {}", i);
        }
    }

    #[test]
    fn plain_rle_run_length_continuation() {
        // Run length 300 -> 299 = 255 + 44 -> [255, 44]; run length 20 -> [19].
        let fmt = PixelFormat::rgba32();
        let red = [0xff, 0x00, 0x00];
        let green = [0x00, 0xff, 0x00];

        let mut tile = vec![128u8]; // plain RLE
        tile.extend_from_slice(&red);
        tile.push(255);
        tile.push(44);
        tile.extend_from_slice(&green);
        tile.push(19);

        let mut fb = Framebuffer::new(64, 5); // 320 pixels
        decode(
            &mut Cursor::new(&build_zrle_payload(&compress(&tile))),
            &mut None,
            &mut fb,
            0,
            0,
            64,
            5,
            &fmt,
        )
        .unwrap();

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
    fn invalid_subencoding_is_rejected() {
        // Subencodings 17..=127 are invalid per the RFB spec.
        let fmt = PixelFormat::rgba32();
        let tile = vec![17u8];
        let mut fb = Framebuffer::new(1, 1);
        assert!(decode(
            &mut Cursor::new(&build_zrle_payload(&compress(&tile))),
            &mut None,
            &mut fb,
            0,
            0,
            1,
            1,
            &fmt,
        )
        .is_err());
    }

    #[test]
    fn decompression_bomb_is_rejected() {
        // A 2x2 rectangle can legitimately decode to only a handful of bytes;
        // data that inflates far beyond that must produce a clean error
        // instead of an unbounded allocation (or a reserve underflow panic).
        let fmt = PixelFormat::rgba32();
        let bomb = vec![0u8; 100_000];
        let mut fb = Framebuffer::new(2, 2);
        let err = decode(
            &mut Cursor::new(&build_zrle_payload(&compress(&bomb))),
            &mut None,
            &mut fb,
            0,
            0,
            2,
            2,
            &fmt,
        )
        .expect_err("oversized decompressed output must be rejected");
        assert!(matches!(err, VncError::Protocol(_)));
    }
}
