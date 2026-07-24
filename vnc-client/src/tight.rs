use std::io::{Cursor, Read};

use flate2::read::ZlibDecoder;

use crate::framebuffer::{Framebuffer, PixelFormat};
use crate::VncError;

/// Decode Tight-encoded rectangle.
pub fn decode<R: Read>(
    stream: &mut R,
    fb: &mut Framebuffer,
    rect_x: usize,
    rect_y: usize,
    rect_w: usize,
    rect_h: usize,
    pixel_format: &PixelFormat,
) -> Result<(), VncError> {
    let bpp = pixel_format.bytes_per_cpixel();

    let mut control = [0u8; 1];
    stream.read_exact(&mut control)?;
    let control = control[0];

    // Fill (solid color)
    if control & 0x20 != 0 {
        return decode_fill(
            stream,
            fb,
            rect_x,
            rect_y,
            rect_w,
            rect_h,
            pixel_format,
            bpp,
        );
    }

    // JPEG
    if control & 0x10 != 0 {
        return decode_jpeg(stream, fb, rect_x, rect_y, rect_w, rect_h);
    }

    // Basic encoding: filter id is in bits 7-6
    let filter = (control >> 6) & 0x03;
    let _stream_id = control & 0x0f;

    match filter {
        0 => decode_basic_copy(stream, fb, rect_x, rect_y, rect_w, rect_h, pixel_format),
        1 => decode_basic_palette(
            stream,
            fb,
            rect_x,
            rect_y,
            rect_w,
            rect_h,
            pixel_format,
            bpp,
        ),
        2 => decode_basic_gradient(
            stream,
            fb,
            rect_x,
            rect_y,
            rect_w,
            rect_h,
            pixel_format,
            bpp,
        ),
        _ => Err(VncError::Protocol(format!(
            "Unknown Tight filter: {}",
            filter
        ))),
    }
}

/// Read a "compact" length value from the stream.
fn read_compact_len<R: Read>(stream: &mut R) -> Result<usize, VncError> {
    let mut b0 = [0u8; 1];
    stream.read_exact(&mut b0)?;
    let b0 = b0[0] as usize;

    if (b0 & 0x80) == 0 {
        Ok(b0)
    } else {
        let mut b1 = [0u8; 1];
        stream.read_exact(&mut b1)?;
        let b1 = b1[0] as usize;

        if (b1 & 0x80) == 0 {
            Ok((b0 & 0x7f) | (b1 << 7))
        } else {
            let mut b2 = [0u8; 1];
            stream.read_exact(&mut b2)?;
            let b2 = b2[0] as usize;
            Ok((b0 & 0x7f) | ((b1 & 0x7f) << 7) | (b2 << 14))
        }
    }
}

/// Decode a solid-fill tile.
#[allow(clippy::too_many_arguments)]
fn decode_fill<R: Read>(
    stream: &mut R,
    fb: &mut Framebuffer,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    pixel_format: &PixelFormat,
    bpp: usize,
) -> Result<(), VncError> {
    let mut pixel = vec![0u8; bpp];
    stream.read_exact(&mut pixel)?;
    let rgba = pixel_format.to_rgba(&pixel);

    for row in 0..h {
        for col in 0..w {
            fb.write_pixel(x + col, y + row, rgba);
        }
    }
    Ok(())
}

/// Decode JPEG-compressed tile.
fn decode_jpeg<R: Read>(
    stream: &mut R,
    fb: &mut Framebuffer,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
) -> Result<(), VncError> {
    let len = read_compact_len(stream)?;
    let mut jpeg_data = vec![0u8; len];
    stream.read_exact(&mut jpeg_data)?;

    let mut decoder = jpeg_decoder::Decoder::new(Cursor::new(&jpeg_data));
    let pixels = decoder
        .decode()
        .map_err(|e| VncError::Protocol(format!("JPEG decode error: {}", e)))?;
    let info = decoder
        .info()
        .ok_or_else(|| VncError::Protocol("JPEG missing info".to_string()))?;

    // jpeg_decoder returns RGB data
    let jpeg_w = info.width as usize;
    let jpeg_h = info.height as usize;

    for row in 0..h.min(jpeg_h) {
        for col in 0..w.min(jpeg_w) {
            let src_idx = (row * jpeg_w + col) * 3;
            if src_idx + 2 < pixels.len() {
                let rgba = [
                    pixels[src_idx],
                    pixels[src_idx + 1],
                    pixels[src_idx + 2],
                    0xff,
                ];
                fb.write_pixel(x + col, y + row, rgba);
            }
        }
    }

    Ok(())
}

/// Decode basic copy (zlib-compressed raw pixels, no filter).
fn decode_basic_copy<R: Read>(
    stream: &mut R,
    fb: &mut Framebuffer,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    pixel_format: &PixelFormat,
) -> Result<(), VncError> {
    let bpp = pixel_format.bytes_per_cpixel();
    let len = read_compact_len(stream)?;
    let mut compressed = vec![0u8; len];
    stream.read_exact(&mut compressed)?;

    let mut decoder = ZlibDecoder::new(&compressed[..]);
    let mut data = vec![0u8; w * h * bpp];
    decoder.read_exact(&mut data)?;

    if bpp == pixel_format.bytes_per_pixel() {
        // CPIXEL is the same size as PIXEL; write_region can interpret the
        // data directly using the negotiated pixel format.
        fb.write_region(x, y, w, h, &data, pixel_format);
    } else {
        // Tight basic copy uses CPIXELs, which may be 3 bytes even when the
        // framebuffer PIXEL is 4 bytes (e.g. 32-bit depth 24). Convert each
        // CPIXEL to RGBA8888 and write with a matching RGBA format.
        let mut rgba = vec![0u8; w * h * 4];
        for i in 0..(w * h) {
            let pixel = &data[i * bpp..(i + 1) * bpp];
            let rgba_pixel = pixel_format.to_rgba(pixel);
            rgba[i * 4..(i + 1) * 4].copy_from_slice(&rgba_pixel);
        }
        fb.write_region(x, y, w, h, &rgba, &PixelFormat::rgba32());
    }
    Ok(())
}

/// Decode basic palette filter.
#[allow(clippy::too_many_arguments)]
fn decode_basic_palette<R: Read>(
    stream: &mut R,
    fb: &mut Framebuffer,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    pixel_format: &PixelFormat,
    bpp: usize,
) -> Result<(), VncError> {
    let len = read_compact_len(stream)?;
    let mut compressed = vec![0u8; len];
    stream.read_exact(&mut compressed)?;

    let mut decoder = ZlibDecoder::new(&compressed[..]);

    // Read number of colors in palette
    let mut palette_size_buf = [0u8; 1];
    decoder.read_exact(&mut palette_size_buf)?;
    let palette_size = (palette_size_buf[0] as usize) + 1; // 0 means 1 color, 255 means 256

    // Read palette entries
    let mut palette = vec![vec![0u8; bpp]; palette_size];
    for entry in &mut palette {
        decoder.read_exact(entry)?;
    }

    let palette_rgba: Vec<[u8; 4]> = palette
        .iter()
        .map(|entry| pixel_format.to_rgba(entry))
        .collect();

    // Determine bits per index
    let bits_per_index = if palette_size <= 2 {
        1
    } else if palette_size <= 4 {
        2
    } else if palette_size <= 16 {
        4
    } else {
        8
    };

    let pixels_per_byte = 8 / bits_per_index;
    let row_bytes = w.div_ceil(pixels_per_byte);

    for row in 0..h {
        let mut row_data = vec![0u8; row_bytes];
        decoder.read_exact(&mut row_data)?;

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

/// Decode basic gradient filter.
///
/// The gradient filter compresses by sending deltas from a predicted value
/// rather than raw pixel values. Prediction:
/// - Row 0, Col 0: raw pixel (no prediction)
/// - Row 0, Col > 0: delta from previous pixel in row
/// - Row > 0, Col 0: delta from pixel directly above
/// - Row > 0, Col > 0: delta from (above + left - above_left)
#[allow(clippy::too_many_arguments)]
fn decode_basic_gradient<R: Read>(
    stream: &mut R,
    fb: &mut Framebuffer,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    pixel_format: &PixelFormat,
    bpp: usize,
) -> Result<(), VncError> {
    let len = read_compact_len(stream)?;
    let mut compressed = vec![0u8; len];
    stream.read_exact(&mut compressed)?;

    let mut decoder = ZlibDecoder::new(&compressed[..]);

    // Read first pixel (raw)
    let mut pixel = vec![0u8; bpp];
    decoder.read_exact(&mut pixel)?;
    let first_rgba = pixel_format.to_rgba(&pixel);
    fb.write_pixel(x, y, first_rgba);

    // Keep the previous row's RGBA values for prediction
    let mut prev_row: Vec<[u8; 4]> = vec![first_rgba; w];
    let mut left: [u8; 4] = first_rgba;

    for row in 0..h {
        let mut current_row: Vec<[u8; 4]> = Vec::with_capacity(w);
        for col in 0..w {
            if row == 0 && col == 0 {
                current_row.push(first_rgba);
                continue;
            }

            let mut buf = [0u8; 3];
            decoder.read_exact(&mut buf)?;
            let dr = buf[0] as i8 as i16;
            let dg = buf[1] as i8 as i16;
            let db = buf[2] as i8 as i16;

            let predicted = if row == 0 {
                // First row: predict from previous pixel in row
                left
            } else if col == 0 {
                // First column: predict from pixel directly above
                prev_row[0]
            } else {
                // Interior: predict from above + left - above_left
                let above = prev_row[col];
                let above_left = prev_row[col - 1];
                [
                    (above[0] as i16 + left[0] as i16 - above_left[0] as i16).clamp(0, 255) as u8,
                    (above[1] as i16 + left[1] as i16 - above_left[1] as i16).clamp(0, 255) as u8,
                    (above[2] as i16 + left[2] as i16 - above_left[2] as i16).clamp(0, 255) as u8,
                    0xff,
                ]
            };

            let rgba = [
                (predicted[0] as i16 + dr).clamp(0, 255) as u8,
                (predicted[1] as i16 + dg).clamp(0, 255) as u8,
                (predicted[2] as i16 + db).clamp(0, 255) as u8,
                0xff,
            ];

            fb.write_pixel(x + col, y + row, rgba);
            current_row.push(rgba);
            left = rgba;
        }
        prev_row = current_row;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn decode_fill_tile() {
        let mut fb = Framebuffer::new(2, 2);
        // Fill control byte: bit 5 set
        let pixel = [0xff, 0x00, 0x00, 0xff]; // RGBA red
        let mut data = vec![0x20]; // fill flag
        data.extend_from_slice(&pixel);

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
        assert_eq!(
            fb.data(),
            &vec![255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255]
        );
    }

    #[test]
    fn decode_basic_copy_tile() {
        let mut fb = Framebuffer::new(2, 1);
        // RGBA32 Tight basic copy sends 3-byte CPIXELs (depth 24, bits_per_pixel 32).
        let cpixels = vec![0xff, 0x00, 0x00, 0x00, 0xff, 0x00];
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&cpixels).unwrap();
        let compressed = encoder.finish().unwrap();

        // Control byte: filter=0 (copy), stream id=0
        let mut data = vec![0x00, compressed.len() as u8];
        data.extend_from_slice(&compressed);

        decode(
            &mut Cursor::new(&data),
            &mut fb,
            0,
            0,
            2,
            1,
            &PixelFormat::rgba32(),
        )
        .unwrap();
        assert_eq!(&fb.data()[0..4], &[0xff, 0x00, 0x00, 0xff]);
        assert_eq!(&fb.data()[4..8], &[0x00, 0xff, 0x00, 0xff]);
    }

    #[test]
    fn filter_extracted_from_top_bits() {
        // Regression test: palette filter uses bits 7-6, not 5-4.
        // control = 0b01_0_0_0000 = 0x40 means filter=1 (palette), no fill, no jpeg
        let mut fb = Framebuffer::new(2, 1);
        // RGBA32 uses 3-byte CPIXELs in Tight (depth 24, bits_per_pixel 32).
        let red = [0xff, 0x00, 0x00];
        let green = [0x00, 0xff, 0x00];

        // Palette: 2 colors (size buf = 1 means 2 colors)
        let mut payload = vec![1u8]; // palette_size - 1
        payload.extend_from_slice(&red);
        payload.extend_from_slice(&green);
        // 2 pixels, 1 bit each, MSB first: index 0 then 1 -> bit pattern 0b01000000 = 0x40
        payload.push(0x40);

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&payload).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut data = vec![0x40, compressed.len() as u8];
        data.extend_from_slice(&compressed);

        decode(
            &mut Cursor::new(&data),
            &mut fb,
            0,
            0,
            2,
            1,
            &PixelFormat::rgba32(),
        )
        .unwrap();
        assert_eq!(&fb.data()[0..4], &[0xff, 0x00, 0x00, 0xff]);
        assert_eq!(&fb.data()[4..8], &[0x00, 0xff, 0x00, 0xff]);
    }

    #[test]
    fn decode_basic_copy_3_byte_cpixel() {
        // Tight basic copy on a 32-bit depth-24 format sends 3-byte CPIXELs.
        let mut fb = Framebuffer::new(2, 1);
        let cpixels = vec![0xff, 0x00, 0x00, 0x00, 0xff, 0x00]; // red, green
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&cpixels).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut data = vec![0x00, compressed.len() as u8]; // filter=0, copy
        data.extend_from_slice(&compressed);

        decode(
            &mut Cursor::new(&data),
            &mut fb,
            0,
            0,
            2,
            1,
            &PixelFormat::rgba32(),
        )
        .unwrap();
        assert_eq!(&fb.data()[0..4], &[0xff, 0x00, 0x00, 0xff]);
        assert_eq!(&fb.data()[4..8], &[0x00, 0xff, 0x00, 0xff]);
    }
}
