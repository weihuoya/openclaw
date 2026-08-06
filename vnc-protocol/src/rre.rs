//! RRE (Rise-and-Run-length Encoding) codec, encoding type 2.
//!
//! RRE encodes a rectangle as a background color followed by a list of
//! sub-rectangles that differ from the background. Pixel values are full PIXELs
//! in the client's negotiated pixel format. This module holds both the encoder
//! and the decoder.

use std::io::Read;

use byteorder::{BigEndian, WriteBytesExt};

use crate::encoding::Encoding;
use crate::pixel_format::{xrgb_to_rgba, PixelFormat};
use crate::pixel_sink::PixelSink;
use crate::rect::FbRect;
use crate::ProtocolError;

/// Encode a region of framebuffer using RRE.
///
/// `src` is the full framebuffer in XRGB8888 format (4 bytes per pixel).
/// `src_stride` is the number of bytes per row.
/// `dst_format` is the client's requested pixel format.
pub fn encode_rre(
    src: &[u8],
    src_stride: usize,
    x: u16,
    y: u16,
    width: u16,
    height: u16,
    dst_format: &PixelFormat,
) -> FbRect {
    let mut output = Vec::new();

    // Convert the rectangle's pixels to values in the client's format.
    let mut values = Vec::with_capacity(width as usize * height as usize);
    for row in 0..height as usize {
        let src_y = y as usize + row;
        let src_off = src_y * src_stride + x as usize * 4;
        for col in 0..width as usize {
            let off = src_off + col * 4;
            values.push(dst_format.from_rgba(xrgb_to_rgba(&src[off..off + 4])));
        }
    }

    let background = values[0];
    let subrects = find_subrects(&values, background, width, height);

    // Wire order per RFC 6143 §7.7.4: subrect count first, then the
    // background pixel, then the subrects.
    output
        .write_u32::<BigEndian>(subrects.len() as u32)
        .unwrap();
    dst_format.write_pixel_value(&mut output, background);

    for (value, sx, sy, sw, sh) in subrects {
        dst_format.write_pixel_value(&mut output, value);
        output.write_u16::<BigEndian>(sx).unwrap();
        output.write_u16::<BigEndian>(sy).unwrap();
        output.write_u16::<BigEndian>(sw).unwrap();
        output.write_u16::<BigEndian>(sh).unwrap();
    }

    FbRect {
        x,
        y,
        width,
        height,
        encoding: Encoding::Rre,
        data: output,
    }
}

/// Find sub-rectangles that differ from the background color.
///
/// Uses a simple greedy approach: scan rows, create runs of non-background
/// pixels, then extend them vertically as far as possible.
fn find_subrects(
    values: &[u32],
    background: u32,
    width: u16,
    height: u16,
) -> Vec<(u32, u16, u16, u16, u16)> {
    let w = width as usize;
    let h = height as usize;
    let mut visited = vec![false; w * h];
    let mut subrects = Vec::new();

    for py in 0..h {
        for px in 0..w {
            let idx = py * w + px;
            if visited[idx] || values[idx] == background {
                continue;
            }

            let color = values[idx];
            let mut max_x = px;
            let mut max_y = py;

            // Expand right while color matches and cells are unvisited
            while max_x + 1 < w
                && !visited[py * w + max_x + 1]
                && values[py * w + max_x + 1] == color
            {
                max_x += 1;
            }

            // Expand down while the whole row segment matches the color
            'expand_down: while max_y + 1 < h {
                for sx in px..=max_x {
                    let check_idx = (max_y + 1) * w + sx;
                    if visited[check_idx] || values[check_idx] != color {
                        break 'expand_down;
                    }
                }
                max_y += 1;
            }

            // Mark visited
            for sy in py..=max_y {
                for sx in px..=max_x {
                    visited[sy * w + sx] = true;
                }
            }

            subrects.push((
                color,
                px as u16,
                py as u16,
                (max_x - px + 1) as u16,
                (max_y - py + 1) as u16,
            ));
        }
    }

    subrects
}

/// Decode an RRE-encoded rectangle from the stream into the pixel sink.
#[allow(clippy::too_many_arguments)]
pub fn decode<P: PixelSink, R: Read>(
    stream: &mut R,
    sink: &mut P,
    x: usize,
    y: usize,
    width: usize,
    height: usize,
    pixel_format: &PixelFormat,
) -> Result<(), ProtocolError> {
    let bpp = pixel_format.bytes_per_pixel();

    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf)?;
    let num_subrects = u32::from_be_bytes(buf);

    // Read background pixel
    let mut bg_pixel = vec![0u8; bpp];
    stream.read_exact(&mut bg_pixel)?;
    let bg = pixel_format.to_rgba(&bg_pixel);

    // Fill entire rectangle with background
    for row in 0..height {
        for col in 0..width {
            sink.write_pixel(x + col, y + row, bg);
        }
    }

    // Read and draw sub-rectangles
    for _ in 0..num_subrects {
        let mut fg_pixel = vec![0u8; bpp];
        stream.read_exact(&mut fg_pixel)?;
        let fg = pixel_format.to_rgba(&fg_pixel);

        let mut rect_buf = [0u8; 8];
        stream.read_exact(&mut rect_buf)?;
        let sx = u16::from_be_bytes([rect_buf[0], rect_buf[1]]) as usize;
        let sy = u16::from_be_bytes([rect_buf[2], rect_buf[3]]) as usize;
        let sw = u16::from_be_bytes([rect_buf[4], rect_buf[5]]) as usize;
        let sh = u16::from_be_bytes([rect_buf[6], rect_buf[7]]) as usize;

        for row in 0..sh {
            for col in 0..sw {
                sink.write_pixel(x + sx + col, y + sy + row, fg);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn decode_zero_subrects() {
        let mut sink = crate::pixel_sink::TestPixelSink::new(2, 2);
        // 0 subrects, then red background pixel in BGRA: [B, G, R, A] = [0, 0, 0xff, 0xff]
        let data = vec![
            0x00, 0x00, 0x00, 0x00, // num_subrects = 0
            0x00, 0x00, 0xff, 0xff, // background in BGRA → red in RGBA
        ];
        decode(
            &mut Cursor::new(&data),
            &mut sink,
            0,
            0,
            2,
            2,
            &PixelFormat::bgra32(),
        )
        .unwrap();

        let expected = vec![
            0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00,
            0x00, 0xff,
        ];
        assert_eq!(sink.pixels, expected);
    }

    #[test]
    fn decode_one_subrect() {
        let mut sink = crate::pixel_sink::TestPixelSink::new(3, 2);
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
            &mut sink,
            0,
            0,
            3,
            2,
            &PixelFormat::bgra32(),
        )
        .unwrap();

        // Row 0: white, red, red
        assert_eq!(sink.pixel(0, 0), Some(&[0xff, 0xff, 0xff, 0xff])); // white
        assert_eq!(sink.pixel(1, 0), Some(&[0xff, 0x00, 0x00, 0xff])); // red
        assert_eq!(sink.pixel(2, 0), Some(&[0xff, 0x00, 0x00, 0xff])); // red
                                                                       // Row 1: all white
        assert_eq!(sink.pixel(0, 1), Some(&[0xff, 0xff, 0xff, 0xff]));
        assert_eq!(sink.pixel(1, 1), Some(&[0xff, 0xff, 0xff, 0xff]));
        assert_eq!(sink.pixel(2, 1), Some(&[0xff, 0xff, 0xff, 0xff]));
    }

    #[test]
    fn decode_respects_rectangle_offset() {
        let mut sink = crate::pixel_sink::TestPixelSink::new(4, 4);
        // 0 subrects, red background, at offset (1, 1), size 2x2.
        let data = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff];
        decode(
            &mut Cursor::new(&data),
            &mut sink,
            1,
            1,
            2,
            2,
            &PixelFormat::bgra32(),
        )
        .unwrap();

        assert_eq!(sink.pixel(0, 0), Some(&[0, 0, 0, 0]));
        assert_eq!(sink.pixel(1, 1), Some(&[0xff, 0x00, 0x00, 0xff]));
        assert_eq!(sink.pixel(2, 2), Some(&[0xff, 0x00, 0x00, 0xff]));
        assert_eq!(sink.pixel(3, 3), Some(&[0, 0, 0, 0]));
    }

    fn fmt() -> PixelFormat {
        PixelFormat::bgra32()
    }

    #[test]
    fn test_rre_solid() {
        let mut fb = vec![0u8; 4 * 4 * 4];
        fb[0..4].copy_from_slice(&[10, 20, 30, 0]);
        for x in 0..4 {
            for y in 0..4 {
                fb[(y * 4 + x) * 4..(y * 4 + x + 1) * 4].copy_from_slice(&[10, 20, 30, 0]);
            }
        }
        let rect = encode_rre(&fb, 16, 0, 0, 4, 4, &fmt());
        assert_eq!(rect.encoding, Encoding::Rre);
        assert_eq!(rect.data[0..4], [0, 0, 0, 0]); // 0 subrects
        assert_eq!(rect.data[4..8], [10, 20, 30, 0]); // background pixel
    }

    #[test]
    fn test_rre_one_subrect() {
        let mut fb = vec![0u8; 8 * 8 * 4];
        // fill with background
        for i in 0..(8 * 8) {
            fb[i * 4..i * 4 + 4].copy_from_slice(&[1, 2, 3, 0]);
        }
        // 2x2 subrect at (3,3) of different color
        for y in 3..5 {
            for x in 3..5 {
                let idx = (y * 8 + x) * 4;
                fb[idx..idx + 4].copy_from_slice(&[7, 8, 9, 0]);
            }
        }
        let rect = encode_rre(&fb, 32, 0, 0, 8, 8, &fmt());
        assert_eq!(
            u32::from_be_bytes([rect.data[0], rect.data[1], rect.data[2], rect.data[3]]),
            1
        );
        // background pixel
        assert_eq!(rect.data[4..8], [1, 2, 3, 0]);
        // subrect pixel
        assert_eq!(rect.data[8..12], [7, 8, 9, 0]);
        // x, y, w, h
        assert_eq!(rect.data[12..20], [0, 3, 0, 3, 0, 2, 0, 2]);
    }

    #[test]
    fn test_rre_solid_rgb565() {
        // 16bpp RGB565 little-endian client format: PIXELs are 2 bytes.
        let mut fb = vec![0u8; 4 * 4 * 4];
        for i in 0..(4 * 4) {
            fb[i * 4..i * 4 + 4].copy_from_slice(&[10, 20, 30, 0]);
        }
        let rect = encode_rre(&fb, 16, 0, 0, 4, 4, &PixelFormat::rgb16());
        // B=10 -> 1, G=20 -> 5, R=30 -> 4; value = (4<<11)|(5<<5)|1 = 0x20A1.
        assert_eq!(rect.data, vec![0, 0, 0, 0, 0xA1, 0x20]);
    }

    #[test]
    fn test_rre_one_subrect_rgb565() {
        let mut fb = vec![0u8; 8 * 8 * 4];
        // Background: pure blue -> RGB565 0x001F.
        for i in 0..(8 * 8) {
            fb[i * 4..i * 4 + 4].copy_from_slice(&[255, 0, 0, 0]);
        }
        // 2x2 subrect at (3,3): pure red -> RGB565 0xF800.
        for y in 3..5 {
            for x in 3..5 {
                let idx = (y * 8 + x) * 4;
                fb[idx..idx + 4].copy_from_slice(&[0, 0, 255, 0]);
            }
        }
        let rect = encode_rre(&fb, 32, 0, 0, 8, 8, &PixelFormat::rgb16());
        assert_eq!(
            rect.data,
            vec![
                0, 0, 0, 1, // 1 subrect
                0x1F, 0x00, // background 0x001F little-endian
                0x00, 0xF8, // subrect pixel 0xF800 little-endian
                0, 3, 0, 3, 0, 2, 0, 2, // x, y, w, h big-endian
            ]
        );
    }

    #[test]
    fn encode_decode_roundtrip() {
        // 8x8 XRGB8888 framebuffer: uniform background with a 2x2 subrect.
        let mut fb = vec![0u8; 8 * 8 * 4];
        for i in 0..(8 * 8) {
            fb[i * 4..i * 4 + 4].copy_from_slice(&[1, 2, 3, 0]);
        }
        for y in 3..5 {
            for x in 3..5 {
                let idx = (y * 8 + x) * 4;
                fb[idx..idx + 4].copy_from_slice(&[7, 8, 9, 0]);
            }
        }

        let rect = encode_rre(&fb, 32, 0, 0, 8, 8, &fmt());
        let mut sink = crate::pixel_sink::TestPixelSink::new(8, 8);
        decode(
            &mut Cursor::new(&rect.data),
            &mut sink,
            rect.x as usize,
            rect.y as usize,
            rect.width as usize,
            rect.height as usize,
            &fmt(),
        )
        .unwrap();

        for y in 0..8usize {
            for x in 0..8usize {
                let off = (y * 8 + x) * 4;
                let expected = xrgb_to_rgba(&fb[off..off + 4]);
                assert_eq!(sink.pixel(x, y), Some(&expected), "pixel ({}, {})", x, y);
            }
        }
    }
}
