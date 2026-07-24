use std::io::Read;

use crate::framebuffer::{Framebuffer, PixelFormat};
use crate::VncError;

/// Decode RRE (Rise-and-Run-length Encoding) rectangle.
///
/// Format:
/// - u32: number of sub-rectangles
/// - pixel_value: background pixel (bpp bytes)
/// - For each sub-rectangle:
///   - pixel_value: foreground pixel (bpp bytes)
///   - u16: x
///   - u16: y
///   - u16: width
///   - u16: height
pub fn decode<R: Read>(
    stream: &mut R,
    framebuffer: &mut Framebuffer,
    x: usize,
    y: usize,
    width: usize,
    height: usize,
    pixel_format: &PixelFormat,
) -> Result<(), VncError> {
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
            framebuffer.write_pixel(x + col, y + row, bg);
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
                framebuffer.write_pixel(x + sx + col, y + sy + row, fg);
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
