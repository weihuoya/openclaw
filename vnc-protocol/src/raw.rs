//! Raw encoding (encoding type 0).
//!
//! Simply sends the pixel data uncompressed, optionally converting from the
//! server's native XRGB8888 format to the client's requested pixel format.

use std::io::Read;

use crate::encoding::Encoding;
use crate::pixel_format::{xrgb_to_rgba, PixelFormat};
use crate::pixel_sink::{write_converted_region, PixelSink};
use crate::rect::FbRect;
use crate::ProtocolError;

/// Encode a region of framebuffer as raw pixels.
///
/// `src` is the full framebuffer in XRGB8888 format (4 bytes per pixel).
/// `src_stride` is the number of bytes per row.
/// `dst_format` is the client's requested pixel format.
pub fn encode_raw(
    src: &[u8],
    src_stride: usize,
    x: u16,
    y: u16,
    width: u16,
    height: u16,
    dst_format: &PixelFormat,
) -> FbRect {
    let bpp = dst_format.bytes_per_pixel();
    let rect_stride = width as usize * bpp;
    let mut data = Vec::with_capacity(rect_stride * height as usize);

    for row in 0..height as usize {
        let src_y = y as usize + row;
        let src_off = src_y * src_stride + x as usize * 4;
        for col in 0..width as usize {
            let pixel_off = src_off + col * 4;
            let pixel = &src[pixel_off..pixel_off + 4];
            dst_format.write_pixel(&mut data, xrgb_to_rgba(pixel));
        }
    }

    FbRect {
        x,
        y,
        width,
        height,
        encoding: Encoding::Raw,
        data,
    }
}

/// Decode a Raw-encoded rectangle from the stream into the pixel sink.
///
/// The wire format is simply `width * height` pixels in `pixel_format`
/// (PIXEL wire format, row-major), uncompressed.
pub fn decode<P: PixelSink, R: Read>(
    stream: &mut R,
    sink: &mut P,
    rect_x: usize,
    rect_y: usize,
    rect_w: usize,
    rect_h: usize,
    pixel_format: &PixelFormat,
) -> Result<(), ProtocolError> {
    let bpp = pixel_format.bytes_per_pixel();
    let mut data = vec![0u8; rect_w * rect_h * bpp];
    stream.read_exact(&mut data)?;
    write_converted_region(
        sink,
        rect_x,
        rect_y,
        rect_w,
        rect_h,
        &data,
        bpp,
        pixel_format,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pixel_sink::TestPixelSink;
    use std::io::Cursor;

    #[test]
    fn test_raw_bgra32() {
        // 1x2 framebuffer: blue then red
        let fb = vec![
            0xff, 0x00, 0x00, 0, // blue
            0x00, 0x00, 0xff, 0, // red
        ];
        let fmt = PixelFormat::bgra32();
        let rect = encode_raw(&fb, 4, 0, 0, 1, 2, &fmt);
        assert_eq!(rect.data, fb);
    }

    #[test]
    fn test_raw_rgb565() {
        let fb = vec![
            0xff, 0x00, 0x00, 0, // blue (R=0, G=0, B=255)
        ];
        let fmt = PixelFormat::rgb16();
        let rect = encode_raw(&fb, 4, 0, 0, 1, 1, &fmt);
        // RGB565: R=0, G=0, B=31 -> value = 0b00000_000000_11111 = 0x001f
        assert_eq!(rect.data, vec![0x1f, 0x00]); // little-endian
    }

    #[test]
    fn encode_decode_roundtrip_bgra32() {
        // 2x2 XRGB8888 source: red, green, blue, white.
        let fb = vec![
            0x00, 0x00, 0xff, 0, // red
            0x00, 0xff, 0x00, 0, // green
            0xff, 0x00, 0x00, 0, // blue
            0xff, 0xff, 0xff, 0, // white
        ];
        let fmt = PixelFormat::bgra32();
        let rect = encode_raw(&fb, 8, 0, 0, 2, 2, &fmt);

        let mut sink = TestPixelSink::new(2, 2);
        decode(
            &mut Cursor::new(&rect.data),
            &mut sink,
            rect.x as usize,
            rect.y as usize,
            rect.width as usize,
            rect.height as usize,
            &fmt,
        )
        .unwrap();

        let expected = vec![
            0xff, 0x00, 0x00, 0xff, // red
            0x00, 0xff, 0x00, 0xff, // green
            0x00, 0x00, 0xff, 0xff, // blue
            0xff, 0xff, 0xff, 0xff, // white
        ];
        assert_eq!(sink.pixels, expected);
    }

    #[test]
    fn encode_decode_roundtrip_rgb565() {
        // 2x1 XRGB8888 source: red, blue.
        let fb = vec![
            0x00, 0x00, 0xff, 0, // red
            0xff, 0x00, 0x00, 0, // blue
        ];
        let fmt = PixelFormat::rgb16();
        let rect = encode_raw(&fb, 8, 0, 0, 2, 1, &fmt);

        let mut sink = TestPixelSink::new(2, 1);
        decode(&mut Cursor::new(&rect.data), &mut sink, 0, 0, 2, 1, &fmt).unwrap();

        assert_eq!(sink.pixel(0, 0), Some(&[0xff, 0x00, 0x00, 0xff]));
        assert_eq!(sink.pixel(1, 0), Some(&[0x00, 0x00, 0xff, 0xff]));
    }

    #[test]
    fn decode_truncated_is_io_error() {
        let mut sink = TestPixelSink::new(2, 2);
        let data = vec![0u8; 8]; // far short of 2x2x4
        let err = decode(
            &mut Cursor::new(&data),
            &mut sink,
            0,
            0,
            2,
            2,
            &PixelFormat::rgba32(),
        )
        .unwrap_err();
        assert!(matches!(err, ProtocolError::Io(_)));
    }
}
