//! ZRLE encoding (encoding type 16).
//!
//! ZRLE (Zlib Run-Length Encoding) is a tile-based encoding. The framebuffer is
//! divided into 64x64 tiles. Each tile is encoded independently with one of
//! several sub-encodings. The encoder maintains a single zlib stream across the
//! whole connection, flushing a complete rectangle at a time.

use std::collections::HashMap;
use std::io::Write;

use flate2::write::ZlibEncoder;
use flate2::Compression;

use crate::protocol::FbRect;

const TILE_SIZE: usize = 64;

/// Persistent ZRLE encoder that keeps a single zlib stream per connection.
pub struct ZrleEncoder {
    encoder: ZlibEncoder<Vec<u8>>,
}

impl Default for ZrleEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ZrleEncoder {
    pub fn new() -> Self {
        Self {
            encoder: ZlibEncoder::new(Vec::new(), Compression::default()),
        }
    }

    /// Encode a region of framebuffer using ZRLE and return the compressed rectangle.
    pub fn encode_rect(
        &mut self,
        src: &[u8],
        src_stride: usize,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) -> FbRect {
        let tiles_x = (width as usize).div_ceil(TILE_SIZE) as u16;
        let tiles_y = (height as usize).div_ceil(TILE_SIZE) as u16;

        for ty in 0..tiles_y {
            for tx in 0..tiles_x {
                let tile_x = x + tx * TILE_SIZE as u16;
                let tile_y = y + ty * TILE_SIZE as u16;
                let tile_w = (TILE_SIZE as u16).min(width - tile_x);
                let tile_h = (TILE_SIZE as u16).min(height - tile_y);

                encode_tile(
                    &mut self.encoder,
                    src,
                    src_stride,
                    tile_x,
                    tile_y,
                    tile_w,
                    tile_h,
                );
            }
        }

        // Flush the zlib stream to a sync point so this rectangle can be decoded
        // independently, while keeping the stream open for subsequent rectangles.
        self.encoder.flush().ok();
        let data = self.encoder.get_mut().drain(..).collect();

        FbRect {
            x,
            y,
            width,
            height,
            encoding: crate::protocol::Encoding::Zrle,
            data,
        }
    }
}

fn encode_tile(
    encoder: &mut ZlibEncoder<Vec<u8>>,
    src: &[u8],
    src_stride: usize,
    tx: u16,
    ty: u16,
    tw: u16,
    th: u16,
) {
    // Collect pixel colors in this tile (memory order for XRGB8888 little-endian).
    let mut colors: Vec<[u8; 4]> = Vec::with_capacity((tw as usize) * (th as usize));
    for row in 0..th as usize {
        let src_y = ty as usize + row;
        for col in 0..tw as usize {
            let src_x = tx as usize + col;
            let off = src_y * src_stride + src_x * 4;
            let pixel = [src[off], src[off + 1], src[off + 2], src[off + 3]];
            colors.push(pixel);
        }
    }

    let unique: HashMap<u32, usize> = colors.iter().fold(HashMap::new(), |mut acc, c| {
        *acc.entry(u32::from_le_bytes(*c)).or_insert(0) += 1;
        acc
    });

    if unique.len() == 1 {
        // Solid tile
        let color = colors[0];
        encoder.write_all(&[0x01]).ok(); // subencoding: solid
        encoder.write_all(&color).ok();
    } else if unique.len() == 2 {
        // Palette RLE - 2 colors
        let palette: Vec<u32> = unique.keys().copied().collect();
        encoder.write_all(&[0x02]).ok(); // subencoding: palette RLE, 2 colors
        for c in &palette {
            encoder.write_all(&c.to_le_bytes()).ok();
        }
        encode_rle_pixels(encoder, &colors, &palette);
    } else if unique.len() <= 16 {
        // Palette tile
        let palette_len = unique.len().clamp(2, 16);
        let subenc = 0x10 | (palette_len as u8 - 1); // 0x10-0x1f
        encoder.write_all(&[subenc]).ok();
        let palette: Vec<u32> = unique.keys().copied().take(palette_len).collect();
        for c in &palette {
            encoder.write_all(&c.to_le_bytes()).ok();
        }
        encode_palette_pixels(encoder, &colors, &palette);
    } else {
        // Raw tile
        encoder.write_all(&[0x00]).ok(); // subencoding: raw
        for pixel in &colors {
            encoder.write_all(pixel).ok();
        }
    }
}

fn encode_rle_pixels(encoder: &mut ZlibEncoder<Vec<u8>>, colors: &[[u8; 4]], palette: &[u32]) {
    let mut i = 0;
    while i < colors.len() {
        let color = colors[i];
        let idx = palette
            .iter()
            .position(|&c| c == u32::from_le_bytes(color))
            .unwrap() as u8;

        let mut run = 1usize;
        while i + run < colors.len() && colors[i + run] == color && run < 255 {
            run += 1;
        }

        if run == 1 {
            encoder.write_all(&[idx]).ok();
        } else {
            encoder.write_all(&[idx | 0x80]).ok();
            encoder.write_all(&[run as u8]).ok();
        }

        i += run;
    }
}

fn encode_palette_pixels(encoder: &mut ZlibEncoder<Vec<u8>>, colors: &[[u8; 4]], palette: &[u32]) {
    let bits = match palette.len() {
        2 => 1,
        3..=4 => 2,
        5..=16 => 4,
        _ => 8,
    };

    let pixels_per_byte = 8 / bits;
    let mask = (1u8 << bits) - 1;

    let mut i = 0;
    while i < colors.len() {
        let mut byte = 0u8;
        for j in 0..pixels_per_byte {
            if i + j < colors.len() {
                let color = colors[i + j];
                let idx = palette
                    .iter()
                    .position(|&c| c == u32::from_le_bytes(color))
                    .unwrap_or(0) as u8;
                byte |= (idx & mask) << ((pixels_per_byte - 1 - j) * bits);
            }
        }
        encoder.write_all(&[byte]).ok();
        i += pixels_per_byte;
    }
}
