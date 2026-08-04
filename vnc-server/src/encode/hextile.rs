//! Hextile encoding implementation (encoding type 5).
//!
//! Hextile divides the framebuffer into 16x16 tiles. Each tile is encoded
//! using one of several subencodings:
//! - Raw: uncompressed pixel data
//! - BackgroundSpecified: tile has a uniform background color
//! - ForegroundSpecified: tile has a uniform foreground color (used with mono)
//! - AnySubrects: tile contains sub-rectangles of either foreground or arbitrary colors
//!
//! Subencoding flags (1 byte):
//! - bit 0: Raw
//! - bit 1: BackgroundSpecified
//! - bit 2: ForegroundSpecified
//! - bit 3: AnySubrects
//! - bit 4: SubrectsColored (if AnySubrects is set)

use crate::protocol::FbRect;

const TILE_SIZE: u16 = 16;

/// Hextile subencoding flags.
#[allow(dead_code)]
mod flags {
    pub const RAW: u8 = 1 << 0;
    pub const BACKGROUND_SPECIFIED: u8 = 1 << 1;
    pub const FOREGROUND_SPECIFIED: u8 = 1 << 2;
    pub const ANY_SUBRECTS: u8 = 1 << 3;
    pub const SUBRECTS_COLORED: u8 = 1 << 4;
}

/// Encode a rectangle using Hextile encoding.
pub fn encode_hextile(
    fb_data: &[u8],
    stride: usize,
    x: u16,
    y: u16,
    width: u16,
    height: u16,
) -> FbRect {
    let mut output = Vec::new();

    let tiles_y = (height as usize).div_ceil(TILE_SIZE as usize);
    let tiles_x = (width as usize).div_ceil(TILE_SIZE as usize);

    for ty in 0..tiles_y {
        for tx in 0..tiles_x {
            let tile_x = x + tx as u16 * TILE_SIZE;
            let tile_y = y + ty as u16 * TILE_SIZE;
            let tile_w = TILE_SIZE.min(width - tx as u16 * TILE_SIZE);
            let tile_h = TILE_SIZE.min(height - ty as u16 * TILE_SIZE);

            encode_tile(fb_data, stride, tile_x, tile_y, tile_w, tile_h, &mut output);
        }
    }

    FbRect {
        x,
        y,
        width,
        height,
        encoding: crate::protocol::Encoding::Hextile,
        data: output,
    }
}

fn encode_tile(
    fb_data: &[u8],
    stride: usize,
    x: u16,
    y: u16,
    w: u16,
    h: u16,
    output: &mut Vec<u8>,
) {
    // Collect tile pixels
    let bpp = 4; // XRGB8888
    let mut pixels = Vec::with_capacity((w * h) as usize * bpp);
    for py in 0..h {
        for px in 0..w {
            let offset = (y + py) as usize * stride + (x + px) as usize * bpp;
            pixels.extend_from_slice(&fb_data[offset..offset + bpp]);
        }
    }

    // Check if entire tile is one color
    let first_pixel = &pixels[0..bpp];
    let is_solid = pixels.chunks(bpp).all(|p| p == first_pixel);

    if is_solid {
        // Solid tile: BackgroundSpecified + no subrects
        output.push(flags::BACKGROUND_SPECIFIED);
        output.extend_from_slice(first_pixel);
        return;
    }

    // For mixed tiles, use Raw subencoding (simplest fallback)
    // A full implementation would analyze subrectangles
    output.push(flags::RAW);
    output.extend_from_slice(&pixels);
}
