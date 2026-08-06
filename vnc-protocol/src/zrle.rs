//! ZRLE/TRLE tile-stream primitives shared between client and server.
//!
//! ZRLE (encoding 16) and TRLE (encoding 15) share the same 64x64 tile
//! format; only the transport differs (ZRLE wraps the tile stream in zlib).
//! This module provides the wire primitives of that tile format: subencoding
//! constants, run-length coding, packed palette index coding, the tile-stream
//! encoder (TRLE proper, and the payload the ZRLE compression shell wraps),
//! and the tile decoder.

use crate::encoding::Encoding;
use crate::pixel_format::{xrgb_to_rgba, PixelFormat};
use crate::pixel_sink::PixelSink;
use crate::rect::{for_each_tile, try_for_each_tile, FbRect};
use crate::zlib::len_prefixed;
use crate::ProtocolError;
use flate2::write::ZlibEncoder as FlateZlibEncoder;
use flate2::Compression;
use std::io::{Read, Write};

/// ZRLE/TRLE tile width and height in pixels (tiles are always square).
pub const TILE_SIZE: usize = 64;

/// Tile subencoding: raw CPIXEL data (`width * height` CPIXELs).
pub const SUBENCODING_RAW: u8 = 0;
/// Tile subencoding: a solid tile (a single CPIXEL).
pub const SUBENCODING_SOLID: u8 = 1;
/// First packed-palette subencoding; the subencoding byte is the palette
/// size itself, in `SUBENCODING_PACKED_PALETTE_MIN..=SUBENCODING_PACKED_PALETTE_MAX`.
pub const SUBENCODING_PACKED_PALETTE_MIN: u8 = 2;
/// Last packed-palette subencoding.
pub const SUBENCODING_PACKED_PALETTE_MAX: u8 = 16;
/// Tile subencoding: plain RLE (CPIXEL + run length pairs).
pub const SUBENCODING_PLAIN_RLE: u8 = 128;
/// First palette-RLE subencoding; the palette size is
/// `subencoding - SUBENCODING_PLAIN_RLE`. Value 129 is marked unused by the
/// RFB spec (it would mean a single-colour palette RLE).
pub const SUBENCODING_PALETTE_RLE_BASE: u8 = 129;

/// Read an RLE run length as used by ZRLE/TRLE plain RLE and palette RLE.
///
/// The run length is encoded as 1 plus the sum of one or more bytes. Each
/// byte of 0xff adds 255 to the length; the final non-0xff byte is added
/// directly.
pub fn read_rle_length<R: Read>(reader: &mut R) -> Result<usize, ProtocolError> {
    let mut length = 1usize;
    loop {
        let mut byte_buf = [0u8; 1];
        reader.read_exact(&mut byte_buf)?;
        let byte = byte_buf[0] as usize;
        length += byte;
        if byte != 255 {
            break;
        }
    }
    Ok(length)
}

/// Write a run length per the RFB spec: the length is one more than the sum
/// of the bytes; a byte of 255 means the length continues in the next byte.
pub fn write_run_length(out: &mut Vec<u8>, run: usize) {
    let mut n = run - 1;
    while n >= 255 {
        out.push(255);
        n -= 255;
    }
    out.push(n as u8);
}

/// Number of bits per packed palette index for a given palette size
/// (RFB spec: 2 colours use 1-bit fields, 3-4 use 2-bit, 5-16 use 4-bit;
/// the Tight palette filter additionally uses 8-bit fields for 17-256).
///
/// Returns `None` for palette sizes outside 1..=256.
pub fn bits_per_index(palette_size: usize) -> Option<u8> {
    match palette_size {
        1..=2 => Some(1),
        3..=4 => Some(2),
        5..=16 => Some(4),
        17..=256 => Some(8),
        _ => None,
    }
}

/// Number of bytes one packed-index scanline of `width` pixels occupies at
/// `bits_per_index` bits per pixel (each scanline is padded to a whole byte).
pub fn row_bytes(width: usize, bits_per_index: u8) -> usize {
    width.div_ceil(8 / bits_per_index as usize)
}

/// Pack palette indices MSB-first at `bits_per_index` bits per index, with
/// each scanline of `row_width` indices padded to a whole byte.
///
/// `indices` must be row-major with exactly `row_width` indices per row.
pub fn pack_indices(out: &mut Vec<u8>, indices: &[u8], row_width: usize, bits_per_index: u8) {
    let per_byte = 8 / bits_per_index as usize;
    for row in indices.chunks(row_width) {
        for chunk in row.chunks(per_byte) {
            let mut byte = 0u8;
            for (j, &idx) in chunk.iter().enumerate() {
                byte |= idx << ((per_byte - 1 - j) * bits_per_index as usize);
            }
            out.push(byte);
        }
    }
}

/// Unpack palette indices packed MSB-first at `bits_per_index` bits per
/// index, with each scanline of `row_width` indices padded to a whole byte
/// (the inverse of [`pack_indices`]).
///
/// `data` must contain exactly `row_bytes(row_width, bits_per_index) * height`
/// bytes.
pub fn unpack_indices(data: &[u8], row_width: usize, height: usize, bits_per_index: u8) -> Vec<u8> {
    let bits = bits_per_index as usize;
    let per_byte = 8 / bits;
    let mask = ((1u16 << bits_per_index) - 1) as u8;
    let row_bytes = row_bytes(row_width, bits_per_index);

    let mut indices = Vec::with_capacity(row_width * height);
    for row in 0..height {
        let row_data = &data[row * row_bytes..(row + 1) * row_bytes];
        for col in 0..row_width {
            let byte = row_data[col / per_byte];
            let shift = 8 - bits - (col % per_byte) * bits;
            indices.push((byte >> shift) & mask);
        }
    }
    indices
}

/// Decode a stream of TRLE/ZRLE tiles covering the given rectangle.
///
/// The tile format is identical for TRLE and ZRLE; only the transport differs
/// (ZRLE wraps the tile stream in zlib). Tiles are 64x64, in left-to-right,
/// top-to-bottom order, with the last tile in each row/column clipped to the
/// rectangle bounds. The decoded RGBA pixels are written to `sink`.
#[allow(clippy::too_many_arguments)]
pub fn decode_tiles<P: PixelSink, R: Read>(
    stream: &mut R,
    sink: &mut P,
    rect_x: usize,
    rect_y: usize,
    rect_w: usize,
    rect_h: usize,
    pixel_format: &PixelFormat,
) -> Result<(), ProtocolError> {
    let bpp = pixel_format.bytes_per_cpixel();

    try_for_each_tile(rect_w, rect_h, TILE_SIZE, |tx, ty, w, h| {
        decode_tile(
            stream,
            sink,
            rect_x + tx,
            rect_y + ty,
            w,
            h,
            pixel_format,
            bpp,
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn decode_tile<P: PixelSink, R: Read>(
    cursor: &mut R,
    sink: &mut P,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    pixel_format: &PixelFormat,
    bpp: usize,
) -> Result<(), ProtocolError> {
    let mut subencoding = [0u8; 1];
    cursor.read_exact(&mut subencoding)?;

    match subencoding[0] {
        SUBENCODING_RAW => decode_raw_tile(cursor, sink, x, y, w, h, pixel_format, bpp),
        SUBENCODING_SOLID => decode_solid_tile(cursor, sink, x, y, w, h, pixel_format, bpp),
        SUBENCODING_PACKED_PALETTE_MIN..=SUBENCODING_PACKED_PALETTE_MAX => decode_palette_tile(
            cursor,
            sink,
            x,
            y,
            w,
            h,
            pixel_format,
            bpp,
            subencoding[0] as usize,
        ),
        17..=127 => Err(ProtocolError::Protocol(format!(
            "ZRLE/TRLE: invalid subencoding {}",
            subencoding[0]
        ))),
        SUBENCODING_PLAIN_RLE => decode_plain_rle_tile(cursor, sink, x, y, w, h, pixel_format, bpp),
        // 129 is marked unused by the RFB spec (it would mean palette RLE with
        // a single-colour palette); decode it leniently like 130..=255.
        _ => decode_palette_rle_tile(
            cursor,
            sink,
            x,
            y,
            w,
            h,
            pixel_format,
            bpp,
            subencoding[0] as usize - SUBENCODING_PLAIN_RLE as usize,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn decode_raw_tile<P: PixelSink, R: Read>(
    cursor: &mut R,
    sink: &mut P,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    pixel_format: &PixelFormat,
    bpp: usize,
) -> Result<(), ProtocolError> {
    // ZRLE raw tiles use CPIXELs. Convert each CPIXEL to RGBA and write it.
    let mut pixel = vec![0u8; bpp];
    for row in 0..h {
        for col in 0..w {
            cursor.read_exact(&mut pixel)?;
            let rgba = pixel_format.to_rgba(&pixel);
            sink.write_pixel(x + col, y + row, rgba);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn decode_solid_tile<P: PixelSink, R: Read>(
    cursor: &mut R,
    sink: &mut P,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    pixel_format: &PixelFormat,
    bpp: usize,
) -> Result<(), ProtocolError> {
    let mut pixel = vec![0u8; bpp];
    cursor.read_exact(&mut pixel)?;
    let rgba = pixel_format.to_rgba(&pixel);

    for row in 0..h {
        for col in 0..w {
            sink.write_pixel(x + col, y + row, rgba);
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn decode_palette_tile<P: PixelSink, R: Read>(
    cursor: &mut R,
    sink: &mut P,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    pixel_format: &PixelFormat,
    bpp: usize,
    palette_size: usize,
) -> Result<(), ProtocolError> {
    // Read palette
    let mut palette = vec![vec![0u8; bpp]; palette_size];
    for entry in &mut palette {
        cursor.read_exact(entry)?;
    }

    // Convert palette entries to RGBA once
    let palette_rgba: Vec<[u8; 4]> = palette
        .iter()
        .map(|entry| pixel_format.to_rgba(entry))
        .collect();

    // Determine bits per index based on palette size (RFB spec: paletteSize 2
    // uses 1-bit fields, 3-4 uses 2-bit fields, 5-16 uses 4-bit fields). The
    // match in decode_tile already restricts palette_size to 2..=16.
    let bits = match bits_per_index(palette_size).filter(|&b| b <= 4) {
        Some(bits) => bits,
        None => {
            return Err(ProtocolError::Protocol(format!(
                "Invalid ZRLE/TRLE palette size: {}",
                palette_size
            )))
        }
    };

    // Read and unpack the packed indices (each scanline padded to a whole
    // byte), then map them through the palette.
    let mut packed = vec![0u8; row_bytes(w, bits) * h];
    cursor.read_exact(&mut packed)?;
    let indices = unpack_indices(&packed, w, h, bits);

    for (i, &index) in indices.iter().enumerate() {
        let index = index as usize;
        let rgba = if index < palette_size {
            palette_rgba[index]
        } else {
            [0, 0, 0, 0xff]
        };
        sink.write_pixel(x + i % w, y + i / w, rgba);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn decode_plain_rle_tile<P: PixelSink, R: Read>(
    cursor: &mut R,
    sink: &mut P,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    pixel_format: &PixelFormat,
    bpp: usize,
) -> Result<(), ProtocolError> {
    let mut pixels_remaining = w * h;
    let mut current_x = x;
    let mut current_y = y;

    while pixels_remaining > 0 {
        let mut pixel = vec![0u8; bpp];
        cursor.read_exact(&mut pixel)?;
        let rgba = pixel_format.to_rgba(&pixel);

        let length = read_rle_length(cursor)?;
        let length = length.min(pixels_remaining);
        pixels_remaining -= length;

        for _ in 0..length {
            sink.write_pixel(current_x, current_y, rgba);
            current_x += 1;
            if current_x >= x + w {
                current_x = x;
                current_y += 1;
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn decode_palette_rle_tile<P: PixelSink, R: Read>(
    cursor: &mut R,
    sink: &mut P,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    pixel_format: &PixelFormat,
    bpp: usize,
    palette_size: usize,
) -> Result<(), ProtocolError> {
    // Read palette
    let mut palette = vec![vec![0u8; bpp]; palette_size];
    for entry in &mut palette {
        cursor.read_exact(entry)?;
    }

    // Convert palette entries to RGBA once
    let palette_rgba: Vec<[u8; 4]> = palette
        .iter()
        .map(|entry| pixel_format.to_rgba(entry))
        .collect();

    let mut pixels_remaining = w * h;
    let mut current_x = x;
    let mut current_y = y;

    while pixels_remaining > 0 {
        let mut index_buf = [0u8; 1];
        cursor.read_exact(&mut index_buf)?;
        let index_byte = index_buf[0];
        let index = (index_byte & 0x7f) as usize;

        let length = if index_byte & 0x80 != 0 {
            read_rle_length(cursor)?
        } else {
            1
        };

        let length = length.min(pixels_remaining);
        pixels_remaining -= length;

        let rgba = if index < palette_size {
            palette_rgba[index]
        } else {
            [0, 0, 0, 0xff]
        };

        for _ in 0..length {
            sink.write_pixel(current_x, current_y, rgba);
            current_x += 1;
            if current_x >= x + w {
                current_x = x;
                current_y += 1;
            }
        }
    }

    Ok(())
}

/// Encode a region of framebuffer using TRLE.
///
/// `src` is the full framebuffer in XRGB8888 format (4 bytes per pixel).
/// `src_stride` is the number of bytes per row.
/// `dst_format` is the client's requested pixel format.
pub fn encode_trle(
    src: &[u8],
    src_stride: usize,
    x: u16,
    y: u16,
    width: u16,
    height: u16,
    dst_format: &PixelFormat,
) -> FbRect {
    FbRect {
        x,
        y,
        width,
        height,
        encoding: Encoding::Trle,
        data: encode_tile_stream(src, src_stride, x, y, width, height, dst_format),
    }
}

/// Generate the TRLE/ZRLE tile stream for a rectangle, uncompressed.
///
/// Tiles are 64x64 in left-to-right, top-to-bottom order; the last tile in
/// each row/column is clipped to the rectangle bounds. Shared by the TRLE and
/// ZRLE encoders.
#[allow(clippy::too_many_arguments)]
pub fn encode_tile_stream(
    src: &[u8],
    src_stride: usize,
    x: u16,
    y: u16,
    width: u16,
    height: u16,
    dst_format: &PixelFormat,
) -> Vec<u8> {
    let mut out = Vec::new();

    for_each_tile(
        width as usize,
        height as usize,
        TILE_SIZE,
        |tx, ty, tw, th| {
            encode_tile(
                &mut out,
                src,
                src_stride,
                x as usize + tx,
                y as usize + ty,
                tw,
                th,
                dst_format,
            );
        },
    );

    out
}

#[allow(clippy::too_many_arguments)]
fn encode_tile(
    out: &mut Vec<u8>,
    src: &[u8],
    src_stride: usize,
    tx: usize,
    ty: usize,
    tw: usize,
    th: usize,
    dst_format: &PixelFormat,
) {
    // Pixel values in row-major order; palette in first-appearance order so
    // the output is deterministic.
    let mut values: Vec<u32> = Vec::with_capacity(tw * th);
    let mut palette: Vec<u32> = Vec::new();
    for row in 0..th {
        let src_off = (ty + row) * src_stride + tx * 4;
        for col in 0..tw {
            let off = src_off + col * 4;
            let value = dst_format.from_rgba(xrgb_to_rgba(&src[off..off + 4]));
            values.push(value);
            if !palette.contains(&value) {
                palette.push(value);
            }
        }
    }

    match palette.len() {
        1 => {
            // Solid tile
            out.push(SUBENCODING_SOLID);
            dst_format.write_cpixel(out, palette[0]);
        }
        2 => {
            // Palette RLE with 2 colours (subencoding 128 + palette size).
            out.push(SUBENCODING_PLAIN_RLE + 2);
            for c in &palette {
                dst_format.write_cpixel(out, *c);
            }
            encode_palette_rle(out, &values, &palette);
        }
        3..=16 => {
            // Packed palette; the subencoding is the palette size itself.
            out.push(palette.len() as u8);
            for c in &palette {
                dst_format.write_cpixel(out, *c);
            }
            encode_packed_palette(out, &values, &palette, tw);
        }
        _ => {
            // Raw tile
            out.push(SUBENCODING_RAW);
            for v in &values {
                dst_format.write_cpixel(out, *v);
            }
        }
    }
}

/// Encode pixels as palette RLE runs. Runs may cross scanline boundaries.
fn encode_palette_rle(out: &mut Vec<u8>, values: &[u32], palette: &[u32]) {
    let mut i = 0;
    while i < values.len() {
        let value = values[i];
        let idx = palette.iter().position(|&c| c == value).unwrap_or(0) as u8;

        let mut run = 1usize;
        while i + run < values.len() && values[i + run] == value {
            run += 1;
        }

        if run == 1 {
            out.push(idx);
        } else {
            out.push(idx | 0x80);
            write_run_length(out, run);
        }

        i += run;
    }
}

/// Encode pixels as packed palette indices, MSB-first, with each scanline
/// padded to a whole byte.
fn encode_packed_palette(out: &mut Vec<u8>, values: &[u32], palette: &[u32], tw: usize) {
    // Called for palettes of 3..=16 colours, which always map to 2 or 4 bits.
    let bits = bits_per_index(palette.len()).unwrap_or(4);
    let indices: Vec<u8> = values
        .iter()
        .map(|v| palette.iter().position(|c| c == v).unwrap_or(0) as u8)
        .collect();
    pack_indices(out, &indices, tw, bits);
}

/// Persistent ZRLE encoder that keeps a single zlib stream per connection.
///
/// ZRLE (encoding 16) wraps the shared TRLE tile stream ([`encode_tile_stream`])
/// in one zlib stream that lives for the whole connection. Each rectangle is
/// framed with [`len_prefixed`] and flushed to a sync point so rectangles can
/// be decoded independently while still benefiting from stream compression.
pub struct ZrleEncoder {
    encoder: FlateZlibEncoder<Vec<u8>>,
}

impl Default for ZrleEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ZrleEncoder {
    pub fn new() -> Self {
        Self {
            encoder: FlateZlibEncoder::new(Vec::new(), Compression::default()),
        }
    }

    /// Encode a region of framebuffer using ZRLE and return the rectangle,
    /// including the 4-byte big-endian compressed-length prefix.
    ///
    /// `src` is the full framebuffer in XRGB8888 format (4 bytes per pixel).
    /// `src_stride` is the number of bytes per row.
    /// `dst_format` is the client's requested pixel format.
    #[allow(clippy::too_many_arguments)]
    pub fn encode_rect(
        &mut self,
        src: &[u8],
        src_stride: usize,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        dst_format: &PixelFormat,
    ) -> FbRect {
        let tiles = encode_tile_stream(src, src_stride, x, y, width, height, dst_format);

        // Writing to a Vec cannot fail, and the sync flush makes this
        // rectangle decodable independently while keeping the stream open.
        let _ = self.encoder.write_all(&tiles);
        let _ = self.encoder.flush();
        let compressed: Vec<u8> = self.encoder.get_mut().drain(..).collect();

        let data = len_prefixed(&compressed);

        FbRect {
            x,
            y,
            width,
            height,
            encoding: Encoding::Zrle,
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn rle_length_roundtrip() {
        for run in [1usize, 2, 254, 255, 256, 300, 511, 512, 3796, 65536] {
            let mut out = Vec::new();
            write_run_length(&mut out, run);
            let decoded = read_rle_length(&mut Cursor::new(&out)).unwrap();
            assert_eq!(decoded, run, "run {}", run);
        }
    }

    #[test]
    fn rle_length_exact_bytes() {
        // Run 1 -> [0]; run 256 -> [255, 0]; run 511 -> [255, 255, 0];
        // run 300 -> 299 = 255 + 44 -> [255, 44].
        let mut out = Vec::new();
        write_run_length(&mut out, 1);
        assert_eq!(out, vec![0]);
        out.clear();
        write_run_length(&mut out, 256);
        assert_eq!(out, vec![255, 0]);
        out.clear();
        write_run_length(&mut out, 511);
        assert_eq!(out, vec![255, 255, 0]);
        out.clear();
        write_run_length(&mut out, 300);
        assert_eq!(out, vec![255, 44]);
    }

    #[test]
    fn bits_per_index_mapping() {
        assert_eq!(bits_per_index(1), Some(1));
        assert_eq!(bits_per_index(2), Some(1));
        assert_eq!(bits_per_index(3), Some(2));
        assert_eq!(bits_per_index(4), Some(2));
        assert_eq!(bits_per_index(5), Some(4));
        assert_eq!(bits_per_index(16), Some(4));
        assert_eq!(bits_per_index(17), Some(8));
        assert_eq!(bits_per_index(256), Some(8));
        assert_eq!(bits_per_index(0), None);
        assert_eq!(bits_per_index(257), None);
    }

    #[test]
    fn row_bytes_pads_to_whole_bytes() {
        assert_eq!(row_bytes(5, 1), 1);
        assert_eq!(row_bytes(9, 1), 2);
        assert_eq!(row_bytes(5, 2), 2);
        assert_eq!(row_bytes(3, 4), 2);
        assert_eq!(row_bytes(7, 8), 7);
    }

    #[test]
    fn pack_unpack_roundtrip() {
        for (bits, max_index) in [(1u8, 1u8), (2, 3), (4, 15), (8, 255)] {
            for width in [1usize, 3, 5, 8, 9, 16] {
                let indices: Vec<u8> = (0..width * 3)
                    .map(|i| (i * 7 + 1) as u8 & max_index)
                    .collect();
                let mut packed = Vec::new();
                pack_indices(&mut packed, &indices, width, bits);
                assert_eq!(packed.len(), row_bytes(width, bits) * 3);
                let unpacked = unpack_indices(&packed, width, 3, bits);
                assert_eq!(unpacked, indices, "bits {} width {}", bits, width);
            }
        }
    }

    #[test]
    fn pack_indices_exact_bytes_scanline_padding() {
        // 5x2 tile, 1 bit per index: row 0: 0 1 0 1 0 -> 0b01010xxx = 0x50;
        // row 1: 1 0 1 0 1 -> 0b10101xxx = 0xa8.
        let indices = [0, 1, 0, 1, 0, 1, 0, 1, 0, 1];
        let mut packed = Vec::new();
        pack_indices(&mut packed, &indices, 5, 1);
        assert_eq!(packed, vec![0x50, 0xa8]);

        // 5x2 tile, 2 bits per index, 4 pixels per byte: each 5-pixel
        // scanline takes 2 bytes (the second byte holds 1 index).
        // Row 0: 0,1,2,0 -> 0b00_01_10_00 = 0x18; 1 -> 0b01_000000 = 0x40.
        // Row 1: 2,0,1,2 -> 0b10_00_01_10 = 0x86; 0 -> 0x00.
        let indices = [0, 1, 2, 0, 1, 2, 0, 1, 2, 0];
        let mut packed = Vec::new();
        pack_indices(&mut packed, &indices, 5, 2);
        assert_eq!(packed, vec![0x18, 0x40, 0x86, 0x00]);
    }

    #[test]
    fn subencoding_values_match_spec() {
        assert_eq!(SUBENCODING_RAW, 0);
        assert_eq!(SUBENCODING_SOLID, 1);
        assert_eq!(SUBENCODING_PLAIN_RLE, 128);
        assert_eq!(SUBENCODING_PALETTE_RLE_BASE, 129);
        assert_eq!(SUBENCODING_PACKED_PALETTE_MIN, 2);
        assert_eq!(SUBENCODING_PACKED_PALETTE_MAX, 16);
    }

    #[test]
    fn decode_solid_tile() {
        let fmt = PixelFormat::rgba32();
        // 2x2 solid tile: red.
        let tile = vec![SUBENCODING_SOLID, 0xff, 0x00, 0x00];
        let mut sink = crate::pixel_sink::TestPixelSink::new(2, 2);
        decode_tiles(&mut Cursor::new(&tile), &mut sink, 0, 0, 2, 2, &fmt).unwrap();
        for i in 0..4 {
            assert_eq!(&sink.pixels[i * 4..i * 4 + 4], &[0xff, 0x00, 0x00, 0xff]);
        }
    }

    #[test]
    fn decode_raw_tile() {
        let fmt = PixelFormat::rgba32();
        // 2x1 raw tile: red, green CPIXELs (3 bytes each).
        let tile = vec![SUBENCODING_RAW, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00];
        let mut sink = crate::pixel_sink::TestPixelSink::new(2, 1);
        decode_tiles(&mut Cursor::new(&tile), &mut sink, 0, 0, 2, 1, &fmt).unwrap();
        assert_eq!(sink.pixel(0, 0), Some(&[0xff, 0x00, 0x00, 0xff]));
        assert_eq!(sink.pixel(1, 0), Some(&[0x00, 0xff, 0x00, 0xff]));
    }

    #[test]
    fn decode_packed_palette_two_color_scanline_padding() {
        let fmt = PixelFormat::rgba32();
        let red = [0xff, 0x00, 0x00];
        let green = [0x00, 0xff, 0x00];
        let mut tile = vec![2u8]; // packed palette, 2 colours
        tile.extend_from_slice(&red);
        tile.extend_from_slice(&green);
        tile.push(0x50); // row 0: R G R G R
        tile.push(0xa8); // row 1: G R G R G

        let mut sink = crate::pixel_sink::TestPixelSink::new(5, 2);
        decode_tiles(&mut Cursor::new(&tile), &mut sink, 0, 0, 5, 2, &fmt).unwrap();

        let r = [0xff, 0x00, 0x00, 0xff];
        let g = [0x00, 0xff, 0x00, 0xff];
        let expected = [r, g, r, g, r, g, r, g, r, g];
        for (i, want) in expected.iter().enumerate() {
            assert_eq!(sink.pixel(i % 5, i / 5), Some(want), "pixel {}", i);
        }
    }

    #[test]
    fn decode_plain_rle_run_length_continuation() {
        let fmt = PixelFormat::rgba32();
        let red = [0xff, 0x00, 0x00];
        let green = [0x00, 0xff, 0x00];
        // 64x5 tile = 320 pixels: 300 red then 20 green.
        let mut tile = vec![SUBENCODING_PLAIN_RLE];
        tile.extend_from_slice(&red);
        tile.push(255);
        tile.push(44); // run length 300
        tile.extend_from_slice(&green);
        tile.push(19); // run length 20

        let mut sink = crate::pixel_sink::TestPixelSink::new(64, 5);
        decode_tiles(&mut Cursor::new(&tile), &mut sink, 0, 0, 64, 5, &fmt).unwrap();

        let r = [0xff, 0x00, 0x00, 0xff];
        let g = [0x00, 0xff, 0x00, 0xff];
        for i in 0..300 {
            assert_eq!(sink.pixel(i % 64, i / 64), Some(&r), "pixel {}", i);
        }
        for i in 300..320 {
            assert_eq!(sink.pixel(i % 64, i / 64), Some(&g), "pixel {}", i);
        }
    }

    #[test]
    fn decode_palette_rle() {
        let fmt = PixelFormat::rgba32();
        let red = [0xff, 0x00, 0x00];
        let green = [0x00, 0xff, 0x00];
        // Palette RLE with 2 colours (subencoding 130): 3 red then 1 green.
        let mut tile = vec![130u8];
        tile.extend_from_slice(&red);
        tile.extend_from_slice(&green);
        tile.push(0x80);
        tile.push(2); // run of 3 red
        tile.push(1); // single green

        let mut sink = crate::pixel_sink::TestPixelSink::new(4, 1);
        decode_tiles(&mut Cursor::new(&tile), &mut sink, 0, 0, 4, 1, &fmt).unwrap();
        assert_eq!(sink.pixel(0, 0), Some(&[0xff, 0x00, 0x00, 0xff]));
        assert_eq!(sink.pixel(1, 0), Some(&[0xff, 0x00, 0x00, 0xff]));
        assert_eq!(sink.pixel(2, 0), Some(&[0xff, 0x00, 0x00, 0xff]));
        assert_eq!(sink.pixel(3, 0), Some(&[0x00, 0xff, 0x00, 0xff]));
    }

    #[test]
    fn decode_invalid_subencoding_is_rejected() {
        let fmt = PixelFormat::rgba32();
        let tile = vec![17u8];
        let mut sink = crate::pixel_sink::TestPixelSink::new(1, 1);
        assert!(decode_tiles(&mut Cursor::new(&tile), &mut sink, 0, 0, 1, 1, &fmt).is_err());
    }

    #[test]
    fn decode_respects_rectangle_offset() {
        let fmt = PixelFormat::rgba32();
        // 2x2 solid red tile at offset (1, 1) in a 4x4 sink.
        let tile = vec![SUBENCODING_SOLID, 0xff, 0x00, 0x00];
        let mut sink = crate::pixel_sink::TestPixelSink::new(4, 4);
        decode_tiles(&mut Cursor::new(&tile), &mut sink, 1, 1, 2, 2, &fmt).unwrap();
        assert_eq!(sink.pixel(0, 0), Some(&[0, 0, 0, 0]));
        assert_eq!(sink.pixel(1, 1), Some(&[0xff, 0x00, 0x00, 0xff]));
        assert_eq!(sink.pixel(2, 2), Some(&[0xff, 0x00, 0x00, 0xff]));
        assert_eq!(sink.pixel(3, 3), Some(&[0, 0, 0, 0]));
    }

    fn fmt() -> PixelFormat {
        PixelFormat::bgra32()
    }

    /// Build an XRGB8888 framebuffer from row-major [B, G, R] pixels.
    fn framebuffer(pixels: &[[u8; 3]], width: usize) -> (Vec<u8>, usize) {
        let stride = width * 4;
        let mut data = vec![0u8; stride * (pixels.len() / width)];
        for (i, p) in pixels.iter().enumerate() {
            data[i * 4] = p[0];
            data[i * 4 + 1] = p[1];
            data[i * 4 + 2] = p[2];
        }
        (data, stride)
    }

    #[test]
    fn solid_tile_uses_3_byte_cpixel() {
        let (fb, stride) = framebuffer(&[[10, 20, 30]; 16], 4);
        let rect = encode_trle(&fb, stride, 0, 0, 4, 4, &fmt());
        assert_eq!(rect.encoding, Encoding::Trle);
        // Subencoding 1 (solid) then a 3-byte CPIXEL (B, G, R for bgra32).
        assert_eq!(rect.data, vec![0x01, 10, 20, 30]);
    }

    #[test]
    fn solid_tile_rgb565_uses_2_byte_cpixel() {
        // 16bpp RGB565 little-endian client format: CPIXELs are 2 bytes.
        let (fb, stride) = framebuffer(&[[10, 20, 30]; 16], 4);
        let rect = encode_trle(&fb, stride, 0, 0, 4, 4, &PixelFormat::rgb16());
        // B=10 -> 1, G=20 -> 5, R=30 -> 4; value = (4<<11)|(5<<5)|1 = 0x20A1.
        assert_eq!(rect.data, vec![0x01, 0xA1, 0x20]);
    }

    #[test]
    fn two_color_tile_is_palette_rle() {
        // Row-major: A B B A. Runs: A x1 (literal), B x2 (run), A x1 (literal).
        let a = [1, 1, 1];
        let b = [2, 2, 2];
        let (fb, stride) = framebuffer(&[a, b, b, a], 2);
        let rect = encode_trle(&fb, stride, 0, 0, 2, 2, &fmt());
        assert_eq!(
            rect.data,
            vec![
                130, // 128 + palette size 2
                1, 1, 1, // palette[0] = A (first appearance)
                2, 2, 2,    // palette[1] = B
                0,    // literal A
                0x81, // run of B
                1,    // run length 2 -> 2 - 1 = 1
                0,    // literal A
            ]
        );
    }

    #[test]
    fn packed_palette_pads_each_scanline() {
        // 5x2 tile, 3 colours -> 2 bits per pixel, 4 pixels per byte, so each
        // 5-pixel scanline takes 2 bytes (the second byte holds 1 pixel).
        let a = [10, 0, 0];
        let b = [0, 10, 0];
        let c = [0, 0, 10];
        let (fb, stride) = framebuffer(&[a, b, c, a, b, c, a, b, c, a], 5);
        let rect = encode_trle(&fb, stride, 0, 0, 5, 2, &fmt());
        // Palette in first-appearance order: A=0, B=1, C=2.
        // Row 0: 0,1,2,0 -> 0b00_01_10_00 = 0x18; 1 -> 0b01_000000 = 0x40.
        // Row 1: 2,0,1,2 -> 0b10_00_01_10 -> 0x86; 0 -> 0x00.
        assert_eq!(
            rect.data,
            vec![
                3, // packed palette, 3 colours
                10, 0, 0, // A
                0, 10, 0, // B
                0, 0, 10, // C
                0x18, 0x40, 0x86, 0x00,
            ]
        );
    }

    #[test]
    fn raw_tile_for_many_colors() {
        // 17 distinct colours -> raw tile with 3-byte CPIXELs.
        let pixels: Vec<[u8; 3]> = (0..17).map(|i| [i, i, i]).collect();
        let (fb, stride) = framebuffer(&pixels, 17);
        let rect = encode_trle(&fb, stride, 0, 0, 17, 1, &fmt());
        let mut expected = vec![0u8]; // raw subencoding
        for p in &pixels {
            expected.extend_from_slice(p);
        }
        assert_eq!(rect.data, expected);
    }

    #[test]
    fn rect_at_nonzero_offset_does_not_underflow() {
        // Regression test: tile sizes must be computed from the tile index,
        // not the absolute coordinate (rect at x=64, width 64).
        let (fb, stride) = framebuffer(&[[7, 8, 9]; 192 * 64], 192);
        let rect = encode_trle(&fb, stride, 64, 0, 64, 64, &fmt());
        // A single solid 64x64 tile.
        assert_eq!(rect.data, vec![0x01, 7, 8, 9]);

        let rect = encode_trle(&fb, stride, 128, 0, 64, 64, &fmt());
        assert_eq!(rect.data, vec![0x01, 7, 8, 9]);
    }

    #[test]
    fn edge_tiles_smaller_than_64() {
        // 100x70 solid rect -> 4 tiles: 64x64, 36x64, 64x6, 36x6, all solid.
        let (fb, stride) = framebuffer(&[[7, 8, 9]; 100 * 70], 100);
        let rect = encode_trle(&fb, stride, 0, 0, 100, 70, &fmt());
        assert_eq!(rect.data, [0x01, 7, 8, 9].repeat(4));
    }

    #[test]
    fn long_runs_use_255_continuation_bytes() {
        // 64x64 two-colour tile: 300 pixels of A then 3796 of B.
        // Run 300 -> 299 = 255 + 44 -> [255, 44].
        // Run 3796 -> 3795 = 14 * 255 + 225 -> [255 x 14, 225].
        let a = [1, 1, 1];
        let b = [2, 2, 2];
        let mut pixels = vec![a; 300];
        pixels.resize(64 * 64, b);
        let (fb, stride) = framebuffer(&pixels, 64);
        let rect = encode_trle(&fb, stride, 0, 0, 64, 64, &fmt());

        let mut expected = vec![130, 1, 1, 1, 2, 2, 2, 0x80, 255, 44, 0x81];
        expected.extend([255; 14]);
        expected.push(225);
        assert_eq!(rect.data, expected);
    }

    #[test]
    fn tile_stream_encode_decode_roundtrip() {
        // 64x64 XRGB8888 framebuffer with four vertical bands exercising every
        // emitted tile subencoding: solid, palette RLE (2 colours), packed
        // palette (3 colours), and raw (>16 colours).
        let width = 64usize;
        let height = 64usize;
        let stride = width * 4;
        let mut fb = vec![0u8; stride * height];
        for y in 0..height {
            for x in 0..width {
                let (b, g, r) = if x < width / 4 {
                    (0, 0, 128)
                } else if x < width / 2 {
                    if (x + y) % 2 == 0 {
                        (255, 0, 0)
                    } else {
                        (0, 255, 0)
                    }
                } else if x < 3 * width / 4 {
                    match (x + y) % 3 {
                        0 => (255, 0, 0),
                        1 => (0, 255, 0),
                        _ => (0, 0, 255),
                    }
                } else {
                    ((x * 3) as u8, (y * 5) as u8, ((x + y) * 7) as u8)
                };
                let off = y * stride + x * 4;
                fb[off] = b;
                fb[off + 1] = g;
                fb[off + 2] = r;
            }
        }

        let stream = encode_tile_stream(&fb, stride, 0, 0, width as u16, height as u16, &fmt());
        let mut sink = crate::pixel_sink::TestPixelSink::new(width, height);
        decode_tiles(
            &mut Cursor::new(&stream),
            &mut sink,
            0,
            0,
            width,
            height,
            &fmt(),
        )
        .unwrap();

        for y in 0..height {
            for x in 0..width {
                let off = y * stride + x * 4;
                let expected = xrgb_to_rgba(&fb[off..off + 4]);
                assert_eq!(sink.pixel(x, y), Some(&expected), "pixel ({}, {})", x, y);
            }
        }
    }

    mod zrle_encoder {
        use super::*;
        use crate::pixel_sink::TestPixelSink;
        use crate::zlib::SessionInflate;
        use flate2::{Decompress, FlushDecompress};

        /// Build an XRGB8888 framebuffer from row-major [B, G, R] pixels.
        fn framebuffer(pixels: &[[u8; 3]], width: usize) -> (Vec<u8>, usize) {
            let stride = width * 4;
            let mut data = vec![0u8; stride * (pixels.len() / width)];
            for (i, p) in pixels.iter().enumerate() {
                data[i * 4] = p[0];
                data[i * 4 + 1] = p[1];
                data[i * 4 + 2] = p[2];
            }
            (data, stride)
        }

        fn inflate_all(chunks: &[&[u8]]) -> Vec<u8> {
            let mut decompress = Decompress::new(true);
            let mut out = Vec::new();
            for chunk in chunks {
                // decompress_vec writes into spare capacity; keep some available.
                if out.capacity() - out.len() < 4096 {
                    out.reserve(4096);
                }
                decompress
                    .decompress_vec(chunk, &mut out, FlushDecompress::Sync)
                    .unwrap();
            }
            out
        }

        #[test]
        fn rect_has_length_prefix_and_compressed_tile_stream() {
            let (fb, stride) = framebuffer(&[[10, 20, 30]; 16], 4);
            let mut encoder = ZrleEncoder::new();
            let rect = encoder.encode_rect(&fb, stride, 0, 0, 4, 4, &fmt());

            assert_eq!(rect.encoding, Encoding::Zrle);
            // First 4 bytes are the big-endian compressed length.
            let compressed_len =
                u32::from_be_bytes([rect.data[0], rect.data[1], rect.data[2], rect.data[3]])
                    as usize;
            assert_eq!(rect.data.len(), 4 + compressed_len);

            // The compressed payload decodes to the tile stream: a single solid
            // tile with a 3-byte CPIXEL.
            let decoded = inflate_all(&[&rect.data[4..]]);
            assert_eq!(decoded, vec![0x01, 10, 20, 30]);
        }

        #[test]
        fn rect_rgb565_uses_2_byte_cpixel() {
            // 16bpp RGB565 little-endian client format: CPIXELs are 2 bytes.
            let (fb, stride) = framebuffer(&[[10, 20, 30]; 16], 4);
            let mut encoder = ZrleEncoder::new();
            let rect = encoder.encode_rect(&fb, stride, 0, 0, 4, 4, &PixelFormat::rgb16());

            let compressed_len =
                u32::from_be_bytes([rect.data[0], rect.data[1], rect.data[2], rect.data[3]])
                    as usize;
            assert_eq!(rect.data.len(), 4 + compressed_len);

            // Solid tile; B=10 -> 1, G=20 -> 5, R=30 -> 4;
            // value = (4<<11)|(5<<5)|1 = 0x20A1, little-endian.
            let decoded = inflate_all(&[&rect.data[4..]]);
            assert_eq!(decoded, vec![0x01, 0xA1, 0x20]);
        }

        #[test]
        fn session_stream_continues_across_rects() {
            let (fb, stride) = framebuffer(&[[7, 8, 9]; 128 * 64], 128);
            let mut encoder = ZrleEncoder::new();
            let rect1 = encoder.encode_rect(&fb, stride, 0, 0, 64, 64, &fmt());
            // Rect at x=64, width 64: regression test for the tile-size
            // computation (must not underflow or produce 0-sized tiles).
            let rect2 = encoder.encode_rect(&fb, stride, 64, 0, 64, 64, &fmt());

            let decoded = inflate_all(&[&rect1.data[4..], &rect2.data[4..]]);
            // Two solid tiles.
            assert_eq!(decoded, vec![0x01, 7, 8, 9, 0x01, 7, 8, 9]);
        }

        /// Encode two frames with one `ZrleEncoder`, inflate both through one
        /// `SessionInflate`, and decode the tile streams: encoder and decoder
        /// session state must stay in sync across rectangles.
        #[test]
        fn encoder_decoder_roundtrip_across_frames() {
            let (fb1, stride1) = framebuffer(&[[10, 20, 30]; 16], 4);
            let (fb2, stride2) = framebuffer(&[[40, 50, 60]; 16], 4);

            let mut encoder = ZrleEncoder::new();
            let rect1 = encoder.encode_rect(&fb1, stride1, 0, 0, 4, 4, &fmt());
            let rect2 = encoder.encode_rect(&fb2, stride2, 0, 0, 4, 4, &fmt());

            let mut session = SessionInflate::new();
            let mut sink = TestPixelSink::new(4, 4);
            for rect in [&rect1, &rect2] {
                let tiles = session
                    .feed(&rect.data[4..], 0, crate::zlib::MAX_COMPRESSED_LEN)
                    .unwrap();
                decode_tiles(&mut Cursor::new(&tiles), &mut sink, 0, 0, 4, 4, &fmt()).unwrap();
            }

            // The sink holds the second frame: BGR source [40, 50, 60]
            // decodes to RGBA [60, 50, 40, 255].
            assert_eq!(sink.pixel(0, 0), Some(&[60, 50, 40, 255]));
            assert_eq!(sink.pixel(3, 3), Some(&[60, 50, 40, 255]));

            // The first frame alone decodes to its own pixels.
            let mut session1 = SessionInflate::new();
            let tiles1 = session1
                .feed(&rect1.data[4..], 0, crate::zlib::MAX_COMPRESSED_LEN)
                .unwrap();
            let mut sink1 = TestPixelSink::new(4, 4);
            decode_tiles(&mut Cursor::new(&tiles1), &mut sink1, 0, 0, 4, 4, &fmt()).unwrap();
            assert_eq!(sink1.pixel(1, 2), Some(&[30, 20, 10, 255]));
        }
    }
}
