use std::io::{Cursor, Read};

use flate2::{Decompress, FlushDecompress, Status};

use crate::framebuffer::{Framebuffer, PixelFormat};
use crate::VncError;

const TILE_WIDTH: usize = 64;
const TILE_HEIGHT: usize = 64;

/// Decode ZRLE-encoded rectangle from the stream into the framebuffer.
///
/// `decompress` is maintained across rectangles to support servers that keep a
/// single zlib stream open for the whole session (e.g. wayvnc/neatvnc). It is
/// reset whenever a fresh zlib header is seen at the start of a rectangle.
#[allow(clippy::too_many_arguments)]
pub fn decode<R: Read>(
    stream: &mut R,
    decompress: &mut Option<Decompress>,
    fb: &mut Framebuffer,
    rect_x: usize,
    rect_y: usize,
    rect_w: usize,
    rect_h: usize,
    pixel_format: &PixelFormat,
) -> Result<(), VncError> {
    let bpp = pixel_format.bytes_per_cpixel();

    // Read compressed length (big-endian u32)
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let compressed_len = u32::from_be_bytes(len_buf) as usize;

    // Read compressed data
    let mut compressed = vec![0u8; compressed_len];
    stream.read_exact(&mut compressed)?;

    log::debug!(
        "ZRLE decode rect={}x{}@({}, {}) bpp={} compressed_len={} expected_uncompressed={}",
        rect_w,
        rect_h,
        rect_x,
        rect_y,
        bpp,
        compressed_len,
        rect_w * rect_h * bpp
    );

    // Some servers (e.g. wayvnc) use a single zlib stream for all ZRLE
    // rectangles; others start a new zlib stream per rectangle. Reset the
    // decompressor whenever we see a fresh zlib header.
    if is_zlib_header(&compressed) {
        log::debug!("ZRLE detected fresh zlib header, resetting decompressor");
        *decompress = Some(Decompress::new(true));
    } else {
        log::debug!(
            "ZRLE no zlib header (first bytes: {:02x?}); continuing with existing decompressor",
            &compressed[..compressed.len().min(4)]
        );
    }

    let decompressor = decompress
        .as_mut()
        .ok_or_else(|| VncError::Protocol("ZRLE decompressor not initialized".to_string()))?;

    let data = decompress_chunk(&compressed, decompressor, rect_w * rect_h * bpp)?;

    let mut cursor = Cursor::new(&data);

    let tiles_x = rect_w.div_ceil(TILE_WIDTH);
    let tiles_y = rect_h.div_ceil(TILE_HEIGHT);
    log::debug!(
        "ZRLE decompressed {} bytes, tiles={}x{}",
        data.len(),
        tiles_x,
        tiles_y
    );

    for ty in 0..tiles_y {
        for tx in 0..tiles_x {
            let x = rect_x + tx * TILE_WIDTH;
            let y = rect_y + ty * TILE_HEIGHT;
            let w = TILE_WIDTH.min(rect_w - tx * TILE_WIDTH);
            let h = TILE_HEIGHT.min(rect_h - ty * TILE_HEIGHT);
            log::debug!("ZRLE tile@({}, {}) size={}x{}", x, y, w, h);

            decode_tile(&mut cursor, fb, x, y, w, h, pixel_format, bpp)?;
        }
    }

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
    log::debug!(
        "ZRLE decode done: consumed {} of {} decompressed bytes, remaining={}",
        consumed,
        data.len(),
        remaining
    );

    Ok(())
}

/// Returns true if the data starts with a valid zlib header.
fn is_zlib_header(compressed: &[u8]) -> bool {
    if compressed.len() < 2 {
        return false;
    }
    let cmf = compressed[0];
    let flg = compressed[1];
    // Deflate compression (CM == 8) and the header check bits must be valid.
    (cmf & 0x0f) == 8 && ((cmf as u16) * 256 + (flg as u16)).is_multiple_of(31)
}

/// Decompress one ZRLE rectangle using a continuous zlib stream.
///
/// The output buffer is grown as needed. Returns the decompressed bytes.
fn decompress_chunk(
    compressed: &[u8],
    decompress: &mut Decompress,
    min_output: usize,
) -> Result<Vec<u8>, VncError> {
    log::debug!(
        "ZRLE decompress_chunk: compressed_len={} min_output={}",
        compressed.len(),
        min_output
    );

    let mut output = Vec::with_capacity(min_output.max(compressed.len() * 4));
    let mut input_offset = 0;
    let mut iteration = 0;

    loop {
        iteration += 1;
        let output_len_before = output.len();

        // Ensure we have spare capacity for the next pass.
        let spare = output.capacity() - output.len();
        if spare < 4096 {
            output.reserve(4096.max(min_output - output.len()));
        }

        let total_in_before = decompress.total_in();
        log::debug!(
            "ZRLE decompress iter={}: input_offset={} remaining={} output_len={} spare={}",
            iteration,
            input_offset,
            compressed.len() - input_offset,
            output_len_before,
            output.capacity() - output_len_before
        );

        let status = decompress
            .decompress_vec(
                &compressed[input_offset..],
                &mut output,
                FlushDecompress::Sync,
            )
            .map_err(|e| VncError::Protocol(format!("ZRLE decompress error: {}", e)))?;
        let consumed = (decompress.total_in() - total_in_before) as usize;
        input_offset += consumed;

        log::debug!(
            "ZRLE decompress iter={} result: consumed={} total_in={} status={:?} output_len={} -> {}",
            iteration,
            consumed,
            input_offset,
            status,
            output_len_before,
            output.len()
        );

        if input_offset == compressed.len() {
            // Some zlib data may still be buffered inside the decompressor after
            // the last input chunk has been consumed. Keep flushing with empty input
            // until no more output is produced. This is needed for wayvnc's
            // continuous zlib stream, where the stream boundary is not aligned with a
            // deflate flush marker and the stream does not end with this rectangle.
            let mut prev_len = output.len();
            loop {
                let spare = output.capacity() - output.len();
                if spare < 4096 {
                    output.reserve(4096);
                }
                let _ = decompress.decompress_vec(&[], &mut output, FlushDecompress::Sync);
                if output.len() == prev_len {
                    break;
                }
                prev_len = output.len();
            }
            break;
        }

        if consumed == 0 && status == Status::Ok {
            // More output space is needed.
            if output.len() == output_len_before {
                log::debug!(
                    "ZRLE decompress iter={}: no progress (no input consumed, no output produced); retrying with more output space",
                    iteration
                );
            }
            continue;
        }

        let remaining = &compressed[input_offset..];
        log::error!(
            "ZRLE decompress stall: iter={} total_in={}/{} consumed_this_iter={} status={:?} \
             output_len={} min_output={} remaining_bytes={} remaining_hex={:02x?} \
             compressed_prefix={:02x?} compressed_suffix={:02x?}",
            iteration,
            input_offset,
            compressed.len(),
            consumed,
            status,
            output.len(),
            min_output,
            remaining.len(),
            &remaining[..remaining.len().min(16)],
            &compressed[..compressed.len().min(16)],
            &compressed[compressed.len().saturating_sub(16)..]
        );
        return Err(VncError::Protocol(format!(
            "ZRLE decompress stalled: consumed {} of {} bytes, status {:?}",
            input_offset,
            compressed.len(),
            status
        )));
    }

    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn decode_tile<R: Read>(
    cursor: &mut R,
    fb: &mut Framebuffer,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    pixel_format: &PixelFormat,
    bpp: usize,
) -> Result<(), VncError> {
    let mut subencoding = [0u8; 1];
    cursor.read_exact(&mut subencoding)?;
    log::debug!(
        "ZRLE tile@({}, {}) subencoding={} (palette_size={})",
        x,
        y,
        subencoding[0],
        if subencoding[0] >= 128 {
            subencoding[0] - 128
        } else {
            subencoding[0]
        }
    );

    match subencoding[0] {
        0 => decode_raw_tile(cursor, fb, x, y, w, h, pixel_format, bpp),
        1 => decode_solid_tile(cursor, fb, x, y, w, h, pixel_format, bpp),
        2..=127 => decode_palette_tile(
            cursor,
            fb,
            x,
            y,
            w,
            h,
            pixel_format,
            bpp,
            subencoding[0] as usize,
        ),
        128 => decode_plain_rle_tile(cursor, fb, x, y, w, h, pixel_format, bpp),
        129 => Err(VncError::Protocol(
            "ZRLE subencoding 129 is reserved".to_string(),
        )),
        130..=255 => decode_palette_rle_tile(
            cursor,
            fb,
            x,
            y,
            w,
            h,
            pixel_format,
            bpp,
            subencoding[0] as usize - 128,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn decode_raw_tile<R: Read>(
    cursor: &mut R,
    fb: &mut Framebuffer,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    pixel_format: &PixelFormat,
    bpp: usize,
) -> Result<(), VncError> {
    // ZRLE raw tiles use CPIXELs. write_region expects PIXEL-sized bytes, so we
    // convert each CPIXEL to RGBA and write it directly.
    let mut pixel = vec![0u8; bpp];
    for row in 0..h {
        for col in 0..w {
            cursor.read_exact(&mut pixel)?;
            let rgba = pixel_format.to_rgba(&pixel);
            fb.write_pixel(x + col, y + row, rgba);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn decode_solid_tile<R: Read>(
    cursor: &mut R,
    fb: &mut Framebuffer,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    pixel_format: &PixelFormat,
    bpp: usize,
) -> Result<(), VncError> {
    let mut pixel = vec![0u8; bpp];
    cursor.read_exact(&mut pixel)?;
    let rgba = pixel_format.to_rgba(&pixel);

    for row in 0..h {
        for col in 0..w {
            fb.write_pixel(x + col, y + row, rgba);
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn decode_palette_tile<R: Read>(
    cursor: &mut R,
    fb: &mut Framebuffer,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    pixel_format: &PixelFormat,
    bpp: usize,
    palette_size: usize,
) -> Result<(), VncError> {
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

    // Determine bits per index based on palette size
    let bits_per_index = match palette_size {
        2 => 1,
        3..=4 => 2,
        5..=16 => 4,
        17..=128 => 8,
        _ => {
            return Err(VncError::Protocol(format!(
                "Invalid ZRLE palette size: {}",
                palette_size
            )))
        }
    };

    let pixels_per_byte = 8 / bits_per_index;
    let row_bytes = w.div_ceil(pixels_per_byte);

    for row in 0..h {
        let mut row_data = vec![0u8; row_bytes];
        cursor.read_exact(&mut row_data)?;

        for col in 0..w {
            let byte_idx = col / pixels_per_byte;
            let bit_offset = 8 - bits_per_index - (col % pixels_per_byte) * bits_per_index;
            let mask = (1 << bits_per_index) - 1;
            let index = ((row_data[byte_idx] >> bit_offset) & mask) as usize;

            let rgba = if index < palette_size {
                palette_rgba[index]
            } else {
                [0, 0, 0, 0xff]
            };
            fb.write_pixel(x + col, y + row, rgba);
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn decode_plain_rle_tile<R: Read>(
    cursor: &mut R,
    fb: &mut Framebuffer,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    pixel_format: &PixelFormat,
    bpp: usize,
) -> Result<(), VncError> {
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
            fb.write_pixel(current_x, current_y, rgba);
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
fn decode_palette_rle_tile<R: Read>(
    cursor: &mut R,
    fb: &mut Framebuffer,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    pixel_format: &PixelFormat,
    bpp: usize,
    palette_size: usize,
) -> Result<(), VncError> {
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
            fb.write_pixel(current_x, current_y, rgba);
            current_x += 1;
            if current_x >= x + w {
                current_x = x;
                current_y += 1;
            }
        }
    }

    Ok(())
}

/// Read an RLE run length as used by ZRLE plain RLE and palette RLE.
///
/// The run length is encoded as 1 plus the sum of one or more bytes. Each byte
/// of 0xff adds 255 to the length; the final non-0xff byte is added directly.
fn read_rle_length<R: Read>(cursor: &mut R) -> Result<usize, VncError> {
    let mut length = 1usize;
    loop {
        let mut byte_buf = [0u8; 1];
        cursor.read_exact(&mut byte_buf)?;
        let byte = byte_buf[0] as usize;
        length += byte;
        if byte != 255 {
            break;
        }
    }
    Ok(length)
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
        let mut payload = Vec::new();
        payload.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
        payload.extend_from_slice(compressed);
        payload
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
}
