//! Tight encoding implementation (encoding type 7).
//!
//! Tight encoding divides the framebuffer into 16x16 tiles and compresses each
//! tile. The encoder maintains up to four zlib streams per connection; this
//! implementation uses stream 0 and resets it at the start of each rectangle.

use std::io::Write;

use flate2::write::ZlibEncoder;
use flate2::Compression;

use crate::protocol::FbRect;

const TILE_SIZE: u16 = 16;
const STREAM_ID: u8 = 0;
const RESET_FLAG: u8 = 0x80;

/// Tight compression control byte values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TightSubencoding {
    /// Basic zlib compression.
    Basic = 0,
    /// Fill (solid color).
    Fill = 1,
    /// JPEG (not implemented).
    #[allow(dead_code)]
    Jpeg = 2,
}

/// Persistent Tight encoder.
///
/// Keeps a single zlib stream for stream 0. The stream is reset at the start of
/// every rectangle, and individual tiles are flushed to sync points so that the
/// client can decode each tile chunk independently.
pub struct TightEncoder {
    encoder: ZlibEncoder<Vec<u8>>,
}

impl Default for TightEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl TightEncoder {
    pub fn new() -> Self {
        Self {
            encoder: ZlibEncoder::new(Vec::new(), Compression::default()),
        }
    }

    /// Encode a rectangle using Tight encoding.
    pub fn encode(
        &mut self,
        fb_data: &[u8],
        stride: usize,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) -> FbRect {
        let mut output = Vec::new();
        // Reset the zlib stream at the start of each rectangle. The first tile
        // will carry the reset flag so the client resets its decompressor too.
        self.encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        let mut first_tile = true;

        let tiles_y = height.div_ceil(TILE_SIZE);
        let tiles_x = width.div_ceil(TILE_SIZE);

        for ty in 0..tiles_y {
            for tx in 0..tiles_x {
                let tile_x = x + tx * TILE_SIZE;
                let tile_y = y + ty * TILE_SIZE;
                let tile_w = TILE_SIZE.min(width - tx * TILE_SIZE);
                let tile_h = TILE_SIZE.min(height - ty * TILE_SIZE);

                self.encode_tile(
                    fb_data,
                    stride,
                    tile_x,
                    tile_y,
                    tile_w,
                    tile_h,
                    &mut output,
                    &mut first_tile,
                );
            }
        }

        FbRect {
            x,
            y,
            width,
            height,
            encoding: crate::protocol::Encoding::Tight,
            data: output,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn encode_tile(
        &mut self,
        fb_data: &[u8],
        stride: usize,
        x: u16,
        y: u16,
        w: u16,
        h: u16,
        output: &mut Vec<u8>,
        first_tile: &mut bool,
    ) {
        // Check if tile is solid color
        let first_pixel = read_pixel(fb_data, stride, x, y);
        let mut is_solid = true;

        for py in 0..h {
            for px in 0..w {
                let pixel = read_pixel(fb_data, stride, x + px, y + py);
                if pixel != first_pixel {
                    is_solid = false;
                    break;
                }
            }
            if !is_solid {
                break;
            }
        }

        if is_solid {
            // Fill subencoding
            output.push(TightSubencoding::Fill as u8);
            output.extend_from_slice(&first_pixel);
            *first_tile = false;
            return;
        }

        // Basic subencoding with zlib stream 0
        let mut control = (TightSubencoding::Basic as u8) | STREAM_ID;
        if *first_tile {
            control |= RESET_FLAG;
        }
        *first_tile = false;

        // Collect tile pixels in memory order
        let mut tile_data = Vec::with_capacity((w * h * 4) as usize);
        for py in 0..h {
            for px in 0..w {
                let pixel = read_pixel(fb_data, stride, x + px, y + py);
                tile_data.extend_from_slice(&pixel);
            }
        }

        // Compress using the persistent encoder and flush to a sync point so the
        // tile can be decoded independently.
        self.encoder.write_all(&tile_data).unwrap();
        self.encoder.flush().unwrap();
        let compressed = self.encoder.get_mut().drain(..).collect::<Vec<u8>>();

        // Write compression control byte
        output.push(control);

        // Write length
        write_tight_length(output, compressed.len() as u32);

        // Write compressed data
        output.extend_from_slice(&compressed);
    }
}

/// Read a 4-byte pixel (XRGB8888) from framebuffer in memory order.
fn read_pixel(fb_data: &[u8], stride: usize, x: u16, y: u16) -> [u8; 4] {
    let offset = y as usize * stride + x as usize * 4;
    [
        fb_data[offset],
        fb_data[offset + 1],
        fb_data[offset + 2],
        fb_data[offset + 3],
    ]
}

/// Write a length value in Tight varint format.
fn write_tight_length(output: &mut Vec<u8>, length: u32) {
    if length < 128 {
        output.push(length as u8);
    } else if length < 16384 {
        output.push((length & 0x7F) as u8 | 0x80);
        output.push(((length >> 7) & 0x7F) as u8);
    } else {
        output.push((length & 0x7F) as u8 | 0x80);
        output.push(((length >> 7) & 0x7F) as u8 | 0x80);
        output.push(((length >> 14) & 0xFF) as u8);
    }
}
