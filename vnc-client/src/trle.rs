use std::io::Read;

use crate::framebuffer::{Framebuffer, PixelFormat};
use crate::VncError;

const TILE_WIDTH: usize = 64;
const TILE_HEIGHT: usize = 64;

/// Decode TRLE (Tight Raw-Lite Encoding) rectangle.
///
/// TRLE is similar to ZRLE but uses Tight-style subencoding.
/// Each tile is 64x64 and uses one of these subencodings:
/// - 0: Raw
/// - 1: Solid
/// - 2..=17: Packed Palette (2-16 colors, 1/2/4/8 bits per pixel)
/// - 128: Plain RLE
/// - 129: Packed Palette RLE
///
/// Note: TRLE is rarely used in practice; ZRLE and Tight are preferred.
pub fn decode<R: Read>(
    stream: &mut R,
    framebuffer: &mut Framebuffer,
    x: usize,
    y: usize,
    width: usize,
    height: usize,
    pixel_format: &PixelFormat,
) -> Result<(), VncError> {
    let bpp = pixel_format.bytes_per_cpixel();
    let tiles_x = width.div_ceil(TILE_WIDTH);
    let tiles_y = height.div_ceil(TILE_HEIGHT);

    for ty in 0..tiles_y {
        for tx in 0..tiles_x {
            let tile_x = x + tx * TILE_WIDTH;
            let tile_y = y + ty * TILE_HEIGHT;
            let tile_w = (TILE_WIDTH).min(width - tx * TILE_WIDTH);
            let tile_h = (TILE_HEIGHT).min(height - ty * TILE_HEIGHT);

            decode_tile(
                stream,
                framebuffer,
                tile_x,
                tile_y,
                tile_w,
                tile_h,
                pixel_format,
                bpp,
            )?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn decode_tile<R: Read>(
    stream: &mut R,
    framebuffer: &mut Framebuffer,
    x: usize,
    y: usize,
    width: usize,
    height: usize,
    pixel_format: &PixelFormat,
    bpp: usize,
) -> Result<(), VncError> {
    let mut subencoding = [0u8; 1];
    stream.read_exact(&mut subencoding)?;

    match subencoding[0] {
        0 => {
            // TRLE raw tiles use CPIXELs. Decode pixel by pixel because
            // write_region expects PIXEL-sized bytes.
            let mut pixel = vec![0u8; bpp];
            for row in 0..height {
                for col in 0..width {
                    stream.read_exact(&mut pixel)?;
                    let rgba = pixel_format.to_rgba(&pixel);
                    framebuffer.write_pixel(x + col, y + row, rgba);
                }
            }
        }
        1 => {
            // Solid
            let mut pixel = vec![0u8; bpp];
            stream.read_exact(&mut pixel)?;
            let rgba = pixel_format.to_rgba(&pixel);
            for row in 0..height {
                for col in 0..width {
                    framebuffer.write_pixel(x + col, y + row, rgba);
                }
            }
        }
        2..=17 => {
            // Packed palette
            let num_colors = subencoding[0] as usize;
            let mut palette = vec![vec![0u8; bpp]; num_colors];
            for color in palette.iter_mut().take(num_colors) {
                stream.read_exact(color)?;
            }

            let palette_rgba: Vec<[u8; 4]> = palette
                .iter()
                .map(|entry| pixel_format.to_rgba(entry))
                .collect();

            let bits_per_pixel = if num_colors == 2 {
                1
            } else if num_colors <= 4 {
                2
            } else if num_colors <= 16 {
                4
            } else {
                8
            };
            let pixels_per_byte = 8 / bits_per_pixel;
            let row_bytes = width.div_ceil(pixels_per_byte);

            for row in 0..height {
                let mut row_data = vec![0u8; row_bytes];
                stream.read_exact(&mut row_data)?;
                for col in 0..width {
                    let byte_idx = col / pixels_per_byte;
                    let bit_shift = 8 - bits_per_pixel - (col % pixels_per_byte) * bits_per_pixel;
                    let mask = (1 << bits_per_pixel) - 1;
                    let idx = ((row_data[byte_idx] >> bit_shift) & mask) as usize;
                    if idx < num_colors {
                        framebuffer.write_pixel(x + col, y + row, palette_rgba[idx]);
                    }
                }
            }
        }
        128 => {
            // Plain RLE
            let mut pixel = vec![0u8; bpp];
            let mut col = 0;
            let mut row = 0;
            loop {
                stream.read_exact(&mut pixel)?;
                let rgba = pixel_format.to_rgba(&pixel);

                let mut run_length_buf = [0u8; 1];
                stream.read_exact(&mut run_length_buf)?;
                let mut run_length = run_length_buf[0] as usize;

                if run_length == 0 {
                    // End of tile marker
                    break;
                }

                if run_length == 255 {
                    // Extended run length
                    let mut ext_buf = [0u8; 2];
                    stream.read_exact(&mut ext_buf)?;
                    run_length = u16::from_be_bytes(ext_buf) as usize;
                }

                for _ in 0..run_length {
                    if row < height {
                        framebuffer.write_pixel(x + col, y + row, rgba);
                        col += 1;
                        if col >= width {
                            col = 0;
                            row += 1;
                        }
                    }
                }
            }
        }
        129 => {
            // Packed palette RLE
            // Similar to ZRLE palette RLE but with TRLE format
            // For simplicity, treat as unsupported and skip
            return Err(VncError::Protocol(
                "TRLE Packed Palette RLE not yet supported".to_string(),
            ));
        }
        _ => {
            return Err(VncError::Protocol(format!(
                "TRLE: unknown subencoding {}",
                subencoding[0]
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn plain_rle_end_of_tile_is_run_length_zero() {
        // Regression test: a black pixel should not terminate the tile.
        let mut fb = Framebuffer::new(3, 1);
        let mut data = vec![128u8]; // plain RLE subencoding

        // red pixel, run length 2
        data.extend_from_slice(&[0xff, 0x00, 0x00]);
        data.push(2);

        // black pixel, run length 1
        data.extend_from_slice(&[0x00, 0x00, 0x00]);
        data.push(1);

        // end-of-tile marker: any pixel followed by length 0
        data.extend_from_slice(&[0x00, 0x00, 0x00]);
        data.push(0);

        decode(
            &mut Cursor::new(&data),
            &mut fb,
            0,
            0,
            3,
            1,
            &PixelFormat::rgba32(),
        )
        .unwrap();

        assert_eq!(&fb.data()[0..4], &[0xff, 0x00, 0x00, 0xff]);
        assert_eq!(&fb.data()[4..8], &[0xff, 0x00, 0x00, 0xff]);
        assert_eq!(&fb.data()[8..12], &[0x00, 0x00, 0x00, 0xff]);
    }

    #[test]
    fn plain_rle_zero_pixel_is_drawn() {
        // A single black pixel should be drawn, not treated as end-of-tile.
        let mut fb = Framebuffer::new(1, 1);
        let mut data = vec![128u8];
        data.extend_from_slice(&[0x00, 0x00, 0x00]);
        data.push(1);
        data.extend_from_slice(&[0x00, 0x00, 0x00]);
        data.push(0);

        decode(
            &mut Cursor::new(&data),
            &mut fb,
            0,
            0,
            1,
            1,
            &PixelFormat::rgba32(),
        )
        .unwrap();
        assert_eq!(&fb.data()[0..4], &[0x00, 0x00, 0x00, 0xff]);
    }
}
