use std::io::Read;

use crate::framebuffer::{Framebuffer, PixelFormat};
use crate::VncError;

const HEX_TILE_WIDTH: usize = 16;
const HEX_TILE_HEIGHT: usize = 16;

const RAW: u8 = 1;
const BACKGROUND_SPECIFIED: u8 = 2;
const FOREGROUND_SPECIFIED: u8 = 4;
const ANY_SUBRECTS: u8 = 8;
const SUBRECTS_COLOURED: u8 = 16;

/// Decode Hextile-encoded rectangle from the stream into the framebuffer.
pub fn decode<R: Read>(
    stream: &mut R,
    fb: &mut Framebuffer,
    rect_x: usize,
    rect_y: usize,
    rect_w: usize,
    rect_h: usize,
    pixel_format: &PixelFormat,
) -> Result<(), VncError> {
    let bpp = pixel_format.bytes_per_pixel();
    let num_tiles_x = rect_w.div_ceil(HEX_TILE_WIDTH);
    let num_tiles_y = rect_h.div_ceil(HEX_TILE_HEIGHT);

    for tile_y in 0..num_tiles_y {
        for tile_x in 0..num_tiles_x {
            let tile_pixel_x = rect_x + tile_x * HEX_TILE_WIDTH;
            let tile_pixel_y = rect_y + tile_y * HEX_TILE_HEIGHT;
            let tile_w = HEX_TILE_WIDTH.min(rect_w - tile_x * HEX_TILE_WIDTH);
            let tile_h = HEX_TILE_HEIGHT.min(rect_h - tile_y * HEX_TILE_HEIGHT);

            let mut subencoding = [0u8; 1];
            stream.read_exact(&mut subencoding)?;
            let flags = subencoding[0];

            decode_tile(
                stream,
                fb,
                tile_pixel_x,
                tile_pixel_y,
                tile_w,
                tile_h,
                pixel_format,
                bpp,
                flags,
            )?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn decode_tile<R: Read>(
    stream: &mut R,
    fb: &mut Framebuffer,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    pixel_format: &PixelFormat,
    bpp: usize,
    flags: u8,
) -> Result<(), VncError> {
    if flags & RAW != 0 {
        // Raw tile: read all pixels directly
        let mut data = vec![0u8; w * h * bpp];
        stream.read_exact(&mut data)?;
        fb.write_region(x, y, w, h, &data, pixel_format);
        return Ok(());
    }

    // Background color
    let mut bg = [0u8; 4]; // RGBA
    if flags & BACKGROUND_SPECIFIED != 0 {
        let mut bg_bytes = vec![0u8; bpp];
        stream.read_exact(&mut bg_bytes)?;
        bg = pixel_format.to_rgba(&bg_bytes);
    }

    // Fill tile with background
    for row in 0..h {
        for col in 0..w {
            fb.write_pixel(x + col, y + row, bg);
        }
    }

    if flags & ANY_SUBRECTS == 0 {
        return Ok(());
    }

    // Foreground color (used if subrects are not individually coloured)
    let mut fg = bg;
    if flags & FOREGROUND_SPECIFIED != 0 {
        let mut fg_bytes = vec![0u8; bpp];
        stream.read_exact(&mut fg_bytes)?;
        fg = pixel_format.to_rgba(&fg_bytes);
    }

    let mut num_subrects = [0u8; 1];
    stream.read_exact(&mut num_subrects)?;
    let num_subrects = num_subrects[0] as usize;

    let coloured = flags & SUBRECTS_COLOURED != 0;

    for _ in 0..num_subrects {
        let mut subrect_pixel = fg;
        if coloured {
            let mut pixel_bytes = vec![0u8; bpp];
            stream.read_exact(&mut pixel_bytes)?;
            subrect_pixel = pixel_format.to_rgba(&pixel_bytes);
        }

        let mut xy = [0u8; 1];
        let mut wh = [0u8; 1];
        stream.read_exact(&mut xy)?;
        stream.read_exact(&mut wh)?;

        let sx = ((xy[0] >> 4) & 0x0f) as usize;
        let sy = (xy[0] & 0x0f) as usize;
        let sw = ((wh[0] >> 4) & 0x0f) as usize + 1;
        let sh = (wh[0] & 0x0f) as usize + 1;

        for row in 0..sh {
            for col in 0..sw {
                fb.write_pixel(x + sx + col, y + sy + row, subrect_pixel);
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
    fn decode_raw_tile() {
        let mut fb = Framebuffer::new(2, 2);
        // Raw tile: 2x2 RGBA pixels
        let raw = vec![
            0xff, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
            0x00, 0xff,
        ];
        let mut data = vec![RAW]; // raw flag
        data.extend_from_slice(&raw);
        decode(
            &mut Cursor::new(&data),
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

    #[test]
    fn decode_solid_tile() {
        let mut fb = Framebuffer::new(2, 2);
        // Background specified, no subrects
        let bg = vec![0x00, 0x00, 0xff, 0xff]; // blue in BGRA → red in RGBA
        let mut data = vec![BACKGROUND_SPECIFIED]; // background flag only
        data.extend_from_slice(&bg);
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
        let mut data = vec![BACKGROUND_SPECIFIED | FOREGROUND_SPECIFIED | ANY_SUBRECTS];
        data.extend_from_slice(&bg);
        data.extend_from_slice(&fg);
        data.push(1); // 1 subrect
                      // xy = 0x00: sx=0, sy=0; wh = 0x11: sw=2, sh=2
        data.push(0x00);
        data.push(0x11);
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

        // Row 0: all red (subrect covers both pixels)
        assert_eq!(fb.data()[0..4], [0xff, 0x00, 0x00, 0xff]);
        assert_eq!(fb.data()[4..8], [0xff, 0x00, 0x00, 0xff]);
        // Row 1: all white (subrect only covers row 0 — wait, 2x2 means sh=2, but tile is 2x2)
        // Actually wh=0x11 means sw=2, sh=2, so subrect covers the whole tile
        assert_eq!(fb.data()[8..12], [0xff, 0x00, 0x00, 0xff]);
        assert_eq!(fb.data()[12..16], [0xff, 0x00, 0x00, 0xff]);
    }
}
