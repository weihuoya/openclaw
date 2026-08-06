//! Tight encoding helpers shared between client and server.
//!
//! Implements the real RFB Tight protocol:
//! - Control byte: `control & 0xF0` is [`CONTROL_FILL`] for Fill,
//!   [`CONTROL_JPEG`] for JPEG, [`CONTROL_PNG`] for PNG (rejected); a value
//!   with bit 7 clear is basic compression.
//! - Low nibble: reset flags for the four persistent zlib streams.
//! - Basic compression: control bits 5-4 select the zlib stream id, bit 6
//!   ([`CONTROL_EXPLICIT_FILTER`]) means an explicit filter id byte follows
//!   (0 = copy, 1 = palette, 2 = gradient); without it the filter is copy.
//! - Filter data smaller than [`MIN_TO_COMPRESS`] bytes (uncompressed)
//!   is sent raw; larger data is zlib-compressed through the persistent
//!   stream selected by the stream id.
//! - Pixels are CPIXELs: for 32bpp depth 24 this is 3 bytes, the lowest
//!   three bytes of the little-endian 4-byte pixel value.
//!
//! The decode side is [`decode`] + [`TightStreams`]; the encode side is
//! [`TightEncoder`], whose JPEG subencoding is compiled in only with the
//! `jpeg-encode` feature.

use std::io::{Read, Write};

use flate2::write::ZlibEncoder as FlateZlibEncoder;
use flate2::Compression;
#[cfg(feature = "jpeg-encode")]
use jpeg_encoder::{ColorType, Encoder as JpegEncoder};

use crate::encoding::Encoding;
use crate::pixel_format::{xrgb_to_rgba, PixelFormat};
use crate::pixel_sink::{write_converted_region, PixelSink};
use crate::rect::{for_each_tile, FbRect};
use crate::zlib::SessionInflate;
use crate::zrle::{bits_per_index, row_bytes, unpack_indices};
use crate::ProtocolError;

/// Control byte for the Fill subencoding (0x08 << 4).
pub const CONTROL_FILL: u8 = 0x80;
/// Control byte for the JPEG subencoding (0x09 << 4).
pub const CONTROL_JPEG: u8 = 0x90;
/// Control byte for the PNG subencoding (0x0A << 4).
pub const CONTROL_PNG: u8 = 0xA0;
/// Control bit (bit 6) marking that an explicit filter id byte follows.
pub const CONTROL_EXPLICIT_FILTER: u8 = 0x40;
/// Mask for the low nibble of the control byte: reset flags for the four
/// persistent zlib streams.
pub const CONTROL_RESET_MASK: u8 = 0x0F;

/// Basic compression filter id: copy (no filter).
pub const FILTER_COPY: u8 = 0;
/// Basic compression filter id: palette.
pub const FILTER_PALETTE: u8 = 1;
/// Basic compression filter id: gradient.
pub const FILTER_GRADIENT: u8 = 2;

/// Uncompressed data chunks smaller than this are sent raw, not zlib-compressed.
pub const MIN_TO_COMPRESS: usize = 12;

/// Read a "compact" length value from the stream.
///
/// Tight uses a variable-length integer: the high bit of each byte indicates
/// whether more bytes follow.
pub fn read_compact_len<R: Read>(stream: &mut R) -> Result<usize, ProtocolError> {
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

/// Write a length value in Tight compact/varint format.
pub fn write_compact_len(output: &mut Vec<u8>, length: u32) {
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

/// Persistent zlib state for the four Tight compression streams.
///
/// Tight servers keep up to four zlib streams open across rectangles and
/// framebuffer updates; the decoder must mirror that state and reset a stream
/// only when the server sets the corresponding reset bit in the low nibble of
/// the control byte.
pub struct TightStreams {
    streams: [SessionInflate; 4],
}

impl Default for TightStreams {
    fn default() -> Self {
        Self::new()
    }
}

impl TightStreams {
    pub fn new() -> Self {
        Self {
            streams: [
                SessionInflate::new(),
                SessionInflate::new(),
                SessionInflate::new(),
                SessionInflate::new(),
            ],
        }
    }

    /// Reset stream `index` (0..=3), as the control byte's reset bits request.
    pub fn reset(&mut self, index: usize) {
        self.streams[index].reset();
    }
}

/// Decode a Tight-encoded rectangle from the stream into the pixel sink.
#[allow(clippy::too_many_arguments)]
pub fn decode<P: PixelSink, R: Read>(
    stream: &mut R,
    streams: &mut TightStreams,
    sink: &mut P,
    rect_x: usize,
    rect_y: usize,
    rect_w: usize,
    rect_h: usize,
    pixel_format: &PixelFormat,
) -> Result<(), ProtocolError> {
    let mut control = [0u8; 1];
    stream.read_exact(&mut control)?;
    let control = control[0];

    // Low nibble: reset flags for the four persistent zlib streams.
    for i in 0..4 {
        if (control >> i) & 1 != 0 {
            streams.reset(i);
        }
    }

    // The low nibble carries only reset flags, so dispatch on the high nibble.
    match control & 0xF0 {
        CONTROL_FILL => decode_fill(stream, sink, rect_x, rect_y, rect_w, rect_h, pixel_format),
        #[cfg(feature = "jpeg")]
        CONTROL_JPEG => decode_jpeg(stream, sink, rect_x, rect_y, rect_w, rect_h),
        #[cfg(not(feature = "jpeg"))]
        CONTROL_JPEG => Err(ProtocolError::Protocol(
            "Tight JPEG subencoding requires the `jpeg` feature".to_string(),
        )),
        CONTROL_PNG => Err(ProtocolError::Protocol(
            "Tight PNG subencoding is not supported".to_string(),
        )),
        // Basic compression: control bit 7 is clear.
        _ if control & 0x80 == 0 => {
            let stream_id = ((control >> 4) & 0x03) as usize;
            let filter = if control & CONTROL_EXPLICIT_FILTER != 0 {
                let mut filter_id = [0u8; 1];
                stream.read_exact(&mut filter_id)?;
                filter_id[0]
            } else {
                FILTER_COPY
            };
            match filter {
                FILTER_COPY => decode_basic_copy(
                    stream,
                    streams,
                    stream_id,
                    sink,
                    rect_x,
                    rect_y,
                    rect_w,
                    rect_h,
                    pixel_format,
                ),
                FILTER_PALETTE => decode_basic_palette(
                    stream,
                    streams,
                    stream_id,
                    sink,
                    rect_x,
                    rect_y,
                    rect_w,
                    rect_h,
                    pixel_format,
                ),
                FILTER_GRADIENT => decode_basic_gradient(
                    stream, streams, stream_id, sink, rect_x, rect_y, rect_w, rect_h,
                ),
                _ => Err(ProtocolError::Protocol(format!(
                    "Unknown Tight filter: {}",
                    filter
                ))),
            }
        }
        _ => Err(ProtocolError::Protocol(format!(
            "Illegal Tight compression control: {:#04x}",
            control
        ))),
    }
}

/// Read `uncompressed_size` bytes of filter data.
///
/// Chunks smaller than [`MIN_TO_COMPRESS`] are sent raw; larger chunks
/// are prefixed with a compact length and zlib-compressed through the
/// persistent stream `stream_id`.
fn read_filtered_data<R: Read>(
    stream: &mut R,
    streams: &mut TightStreams,
    stream_id: usize,
    uncompressed_size: usize,
) -> Result<Vec<u8>, ProtocolError> {
    if uncompressed_size == 0 {
        return Ok(Vec::new());
    }
    if uncompressed_size < MIN_TO_COMPRESS {
        let mut data = vec![0u8; uncompressed_size];
        stream.read_exact(&mut data)?;
        return Ok(data);
    }

    let len = read_compact_len(stream)?;
    // A zlib stream that expands to `uncompressed_size` bytes never needs
    // more compressed bytes than that plus deflate/zlib overhead (deflate
    // grows incompressible data by at most ~0.03%); reject larger lengths
    // before allocating.
    let max_compressed = uncompressed_size + uncompressed_size / 1000 + 1024;
    if len > max_compressed {
        return Err(ProtocolError::Protocol(format!(
            "Tight compressed length {} exceeds bound {} for {} uncompressed bytes",
            len, max_compressed, uncompressed_size
        )));
    }
    let mut compressed = vec![0u8; len];
    stream.read_exact(&mut compressed)?;
    // The chunk must inflate to exactly the filter data size; anything else
    // means the persistent stream is out of sync with the server.
    streams.streams[stream_id].feed(&compressed, uncompressed_size, uncompressed_size)
}

/// Decode a solid-fill tile: the control byte is followed by one CPIXEL.
fn decode_fill<R: Read, P: PixelSink>(
    stream: &mut R,
    sink: &mut P,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    pixel_format: &PixelFormat,
) -> Result<(), ProtocolError> {
    let bpp = pixel_format.bytes_per_cpixel();
    let mut pixel = vec![0u8; bpp];
    stream.read_exact(&mut pixel)?;
    let rgba = pixel_format.to_rgba(&pixel);

    for row in 0..h {
        for col in 0..w {
            sink.write_pixel(x + col, y + row, rgba);
        }
    }
    Ok(())
}

/// Decode a JPEG-compressed tile: compact length followed by JPEG data.
#[cfg(feature = "jpeg")]
fn decode_jpeg<R: Read, P: PixelSink>(
    stream: &mut R,
    sink: &mut P,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
) -> Result<(), ProtocolError> {
    let len = read_compact_len(stream)?;
    let mut jpeg_data = vec![0u8; len];
    stream.read_exact(&mut jpeg_data)?;

    let mut decoder = jpeg_decoder::Decoder::new(std::io::Cursor::new(&jpeg_data));
    let pixels = decoder
        .decode()
        .map_err(|e| ProtocolError::Protocol(format!("JPEG decode error: {}", e)))?;
    let info = decoder
        .info()
        .ok_or_else(|| ProtocolError::Protocol("JPEG missing info".to_string()))?;

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
                sink.write_pixel(x + col, y + row, rgba);
            }
        }
    }

    Ok(())
}

/// Decode basic copy (raw or zlib-compressed CPIXELs, no filter).
#[allow(clippy::too_many_arguments)]
fn decode_basic_copy<R: Read, P: PixelSink>(
    stream: &mut R,
    streams: &mut TightStreams,
    stream_id: usize,
    sink: &mut P,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    pixel_format: &PixelFormat,
) -> Result<(), ProtocolError> {
    let bpp = pixel_format.bytes_per_cpixel();
    let data = read_filtered_data(stream, streams, stream_id, w * h * bpp)?;

    write_converted_region(sink, x, y, w, h, &data, bpp, pixel_format);
    Ok(())
}

/// Decode the basic palette filter.
///
/// The palette size byte (number of colors minus one) and the palette entries
/// (as CPIXELs) are sent uncompressed. They are followed by packed pixel
/// indices (raw or zlib-compressed per the usual size rule): 1 bit per pixel
/// for 2 colors, 2 bits for 3-4, 4 bits for 5-16 and 8 bits for 17-256; each
/// row starts on a byte boundary.
#[allow(clippy::too_many_arguments)]
fn decode_basic_palette<R: Read, P: PixelSink>(
    stream: &mut R,
    streams: &mut TightStreams,
    stream_id: usize,
    sink: &mut P,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    pixel_format: &PixelFormat,
) -> Result<(), ProtocolError> {
    let bpp = pixel_format.bytes_per_cpixel();

    // Palette header is sent uncompressed.
    let mut palette_size_buf = [0u8; 1];
    stream.read_exact(&mut palette_size_buf)?;
    let palette_size = (palette_size_buf[0] as usize) + 1;

    let mut palette_rgba = Vec::with_capacity(palette_size);
    for _ in 0..palette_size {
        let mut entry = vec![0u8; bpp];
        stream.read_exact(&mut entry)?;
        palette_rgba.push(pixel_format.to_rgba(&entry));
    }

    let bits = bits_per_index(palette_size).unwrap_or(8);
    let row_bytes = row_bytes(w, bits);

    let data = read_filtered_data(stream, streams, stream_id, row_bytes * h)?;
    let indices = unpack_indices(&data, w, h, bits);

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

/// Reconstruct RGB pixels from gradient-filter difference data.
///
/// The gradient filter is defined on TPIXELs (3 bytes, red/green/blue), so it
/// only applies to true-color formats with 24-bit depth. Each byte holds the
/// difference (mod 256) between the actual component value and a prediction:
/// the left pixel for the first row, otherwise
/// `left + upper - upper_left` clamped to 0-255, with `left` and `upper_left`
/// starting at zero for each row after the first.
///
/// `deltas` must hold exactly `width * height * 3` bytes; the result is the
/// reconstructed RGB pixels, row-major, 3 bytes per pixel.
pub fn reconstruct_gradient(
    deltas: &[u8],
    width: usize,
    height: usize,
) -> Result<Vec<u8>, ProtocolError> {
    if deltas.len() != width * height * 3 {
        return Err(ProtocolError::Protocol(format!(
            "Tight gradient data length {} does not match {}x{} TPIXELs",
            deltas.len(),
            width,
            height
        )));
    }

    let mut rgb = vec![0u8; width * height * 3];
    let mut pos = 0usize;

    // First row: predict from the left pixel (starting at zero).
    let mut left = [0u8; 3];
    for col in 0..width {
        for (c, item) in left.iter_mut().enumerate() {
            let value = deltas[pos].wrapping_add(*item);
            pos += 1;
            rgb[col * 3 + c] = value;
            *item = value;
        }
    }

    // Remaining rows: predict from left + upper - upper_left, clamped.
    for row in 1..height {
        let mut left = [0u8; 3];
        let mut upper_left = [0u8; 3];
        for col in 0..width {
            for c in 0..3 {
                let upper = rgb[(row - 1) * width * 3 + col * 3 + c];
                let prediction =
                    (left[c] as i16 + upper as i16 - upper_left[c] as i16).clamp(0, 255) as u8;
                let value = deltas[pos].wrapping_add(prediction);
                pos += 1;
                rgb[row * width * 3 + col * 3 + c] = value;
                upper_left[c] = upper;
                left[c] = value;
            }
        }
    }

    Ok(rgb)
}

/// Decode the basic gradient filter.
///
/// See [`reconstruct_gradient`] for the filter definition. The filtered data
/// is raw or zlib-compressed per the usual size rule.
#[allow(clippy::too_many_arguments)]
fn decode_basic_gradient<R: Read, P: PixelSink>(
    stream: &mut R,
    streams: &mut TightStreams,
    stream_id: usize,
    sink: &mut P,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
) -> Result<(), ProtocolError> {
    let data = read_filtered_data(stream, streams, stream_id, w * h * 3)?;
    let rgb = reconstruct_gradient(&data, w, h)?;

    // TPIXEL components are always red/green/blue, so write RGBA directly.
    let mut rgba = vec![0u8; w * h * 4];
    for i in 0..(w * h) {
        rgba[i * 4..i * 4 + 4].copy_from_slice(&[rgb[i * 3], rgb[i * 3 + 1], rgb[i * 3 + 2], 0xff]);
    }
    sink.write_region(x as u16, y as u16, w as u16, h as u16, &rgba);

    Ok(())
}

/// Tile width and height used by [`TightEncoder`] (tiles are always square).
const ENCODER_TILE_SIZE: u16 = 16;

/// Zlib stream id used for basic compression (control bits 5-4).
const STREAM_ID: u8 = 0;

/// Persistent Tight encoder.
///
/// Keeps a single zlib stream (stream 0). The stream is reset at the start of
/// every rectangle, and the first compressed tile of a rectangle carries the
/// reset flag so the client resets its decompressor too. Individual tiles are
/// flushed to sync points so the client can decode each tile chunk exactly.
pub struct TightEncoder {
    encoder: FlateZlibEncoder<Vec<u8>>,
    /// JPEG quality (1-100). Default 80.
    #[cfg(feature = "jpeg-encode")]
    jpeg_quality: u8,
}

impl Default for TightEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl TightEncoder {
    pub fn new() -> Self {
        Self {
            encoder: FlateZlibEncoder::new(Vec::new(), Compression::default()),
            #[cfg(feature = "jpeg-encode")]
            jpeg_quality: 80,
        }
    }

    /// Set the JPEG quality level (1-100).
    #[cfg(feature = "jpeg-encode")]
    #[allow(dead_code)]
    pub fn set_jpeg_quality(&mut self, quality: u8) {
        self.jpeg_quality = quality.clamp(1, 100);
    }

    /// Encode a rectangle using Tight encoding.
    ///
    /// `fb_data` is the full framebuffer in XRGB8888 format (4 bytes per
    /// pixel); `stride` is the number of bytes per row. `dst_format` is the
    /// client's negotiated pixel format; Fill and Basic tiles carry CPIXELs in
    /// this format.
    #[allow(clippy::too_many_arguments)]
    pub fn encode(
        &mut self,
        fb_data: &[u8],
        stride: usize,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        dst_format: &PixelFormat,
    ) -> FbRect {
        let mut output = Vec::new();
        // Reset the zlib stream at the start of each rectangle. The first
        // compressed tile will carry the reset flag for stream 0 so the client
        // resets its decompressor too. Fill and JPEG tiles do not use the zlib
        // stream, so the flag is only emitted on basic-compression tiles.
        self.encoder = FlateZlibEncoder::new(Vec::new(), Compression::default());
        let mut stream_fresh = true;

        for_each_tile(
            width as usize,
            height as usize,
            ENCODER_TILE_SIZE as usize,
            |tx, ty, tw, th| {
                self.encode_tile(
                    fb_data,
                    stride,
                    x + tx as u16,
                    y + ty as u16,
                    tw as u16,
                    th as u16,
                    &mut output,
                    &mut stream_fresh,
                    dst_format,
                );
            },
        );

        FbRect {
            x,
            y,
            width,
            height,
            encoding: Encoding::Tight,
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
        stream_fresh: &mut bool,
        dst_format: &PixelFormat,
    ) {
        // Collect tile pixel values in the client's negotiated format, emit
        // them as CPIXELs, and check for solid color.
        let cpb = dst_format.bytes_per_cpixel();
        let mut values = Vec::with_capacity((w * h) as usize);
        let mut cpixels = Vec::with_capacity((w * h) as usize * cpb);
        for py in 0..h {
            for px in 0..w {
                let rgba = xrgb_to_rgba(&read_pixel(fb_data, stride, x + px, y + py));
                let value = dst_format.from_rgba(rgba);
                values.push(value);
                dst_format.write_cpixel(&mut cpixels, value);
            }
        }
        let first_value = values[0];
        let is_solid = values.iter().all(|&v| v == first_value);

        if is_solid {
            output.push(CONTROL_FILL);
            dst_format.write_cpixel(output, first_value);
            return;
        }

        // Decide whether to use JPEG for this tile.
        #[cfg(feature = "jpeg-encode")]
        {
            let unique_colors = unique_color_count(&values);
            let area = (w as usize) * (h as usize);
            if area >= 64 && unique_colors > 64 {
                match encode_jpeg(fb_data, stride, x, y, w, h, self.jpeg_quality) {
                    Ok(jpeg_data) if !jpeg_data.is_empty() => {
                        output.push(CONTROL_JPEG);
                        write_compact_len(output, jpeg_data.len() as u32);
                        output.extend_from_slice(&jpeg_data);
                        return;
                    }
                    Ok(_) => {
                        log::debug!("JPEG encoder produced empty data; falling back to Basic");
                    }
                    Err(e) => {
                        log::debug!("JPEG encoding failed: {}; falling back to Basic", e);
                    }
                }
            }
        }

        // Basic compression with the copy filter (no explicit filter byte:
        // copy is the implicit filter when control bit 6 is clear).
        let mut control = STREAM_ID << 4;
        if cpixels.len() < MIN_TO_COMPRESS {
            // Small tiles are sent raw; they do not touch the zlib stream.
            output.push(control);
            output.extend_from_slice(&cpixels);
            return;
        }

        if *stream_fresh {
            control |= 1 << STREAM_ID;
            *stream_fresh = false;
        }

        // Compress using the persistent encoder and flush to a sync point so
        // the tile can be decoded independently.
        self.encoder.write_all(&cpixels).unwrap();
        self.encoder.flush().unwrap();
        let compressed = self.encoder.get_mut().drain(..).collect::<Vec<u8>>();

        output.push(control);
        write_compact_len(output, compressed.len() as u32);
        output.extend_from_slice(&compressed);
    }
}

/// Encode a tile as a JPEG image from the BGRA framebuffer.
#[cfg(feature = "jpeg-encode")]
fn encode_jpeg(
    fb_data: &[u8],
    stride: usize,
    x: u16,
    y: u16,
    w: u16,
    h: u16,
    quality: u8,
) -> std::io::Result<Vec<u8>> {
    let mut pixels = Vec::with_capacity((w * h * 4) as usize);
    for py in 0..h {
        for px in 0..w {
            pixels.extend_from_slice(&read_pixel(fb_data, stride, x + px, y + py));
        }
    }

    let mut output = Vec::new();
    let encoder = JpegEncoder::new(&mut output, quality);
    encoder
        .encode(&pixels, w, h, ColorType::Bgra)
        .map_err(std::io::Error::other)?;
    Ok(output)
}

/// Count the number of unique colors in a pixel value buffer.
#[cfg(feature = "jpeg-encode")]
fn unique_color_count(values: &[u32]) -> usize {
    let mut colors = std::collections::HashSet::new();
    for value in values {
        colors.insert(*value);
    }
    colors.len()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn compact_len_exact_bytes_at_boundaries() {
        let cases: &[(u32, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            // Largest 1-byte value.
            (127, &[0x7F]),
            // Smallest 2-byte value.
            (128, &[0x80, 0x01]),
            (255, &[0xFF, 0x01]),
            // Largest 2-byte value.
            (16383, &[0xFF, 0x7F]),
            // Smallest 3-byte value.
            (16384, &[0x80, 0x80, 0x01]),
            (4_000_000, &[0x80, 0x92, 0xF4]),
        ];
        for (value, expected) in cases {
            let mut buf = Vec::new();
            write_compact_len(&mut buf, *value);
            assert_eq!(&buf, expected, "value={}", value);
        }
    }

    #[test]
    fn compact_len_write_read_roundtrip() {
        for value in [
            0u32, 1, 127, 128, 255, 16383, 16384, 65535, 4_000_000,
            // Largest representable value (3 bytes, all bits set).
            0x3F_FFFF,
        ] {
            let mut buf = Vec::new();
            write_compact_len(&mut buf, value);
            let mut cursor = Cursor::new(&buf);
            let decoded = read_compact_len(&mut cursor).unwrap();
            assert_eq!(decoded, value as usize, "value={}", value);
            // The reader consumes exactly the encoded bytes.
            assert_eq!(cursor.position(), buf.len() as u64, "value={}", value);
        }
    }

    #[test]
    fn compact_len_truncated_is_error() {
        // Empty input.
        assert!(read_compact_len(&mut &[][..]).is_err());
        // Continuation bit set but the follow-up byte is missing.
        assert!(read_compact_len(&mut &[0x80][..]).is_err());
        assert!(read_compact_len(&mut &[0xFF][..]).is_err());
        // Two continuation bytes but the third is missing.
        assert!(read_compact_len(&mut &[0x80, 0x80][..]).is_err());
        assert!(read_compact_len(&mut &[0xFF, 0xFF][..]).is_err());
    }

    #[test]
    fn compact_len_never_reads_a_fourth_byte() {
        // The compact-length format is at most 3 bytes; trailing bytes belong
        // to the payload and must be left in the stream.
        let mut buf = Vec::new();
        write_compact_len(&mut buf, 16384);
        buf.extend_from_slice(&[0xAA, 0xBB]);
        let mut cursor = Cursor::new(&buf);
        assert_eq!(read_compact_len(&mut cursor).unwrap(), 16384);
        assert_eq!(cursor.position(), 3);
    }

    #[test]
    fn compact_len_third_byte_uses_all_eight_bits() {
        // The third byte's high bit is payload, not a continuation flag.
        let buf = [0x80, 0x80, 0xFF];
        assert_eq!(read_compact_len(&mut &buf[..]).unwrap(), 0xFF << 14);
    }

    mod decode {
        use super::*;
        use crate::pixel_sink::TestPixelSink;
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::{Cursor, Write};

        fn compress(data: &[u8]) -> Vec<u8> {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(data).unwrap();
            encoder.finish().unwrap()
        }

        /// Build a compact-length-prefixed compressed chunk.
        fn compressed_chunk(data: &[u8]) -> Vec<u8> {
            let compressed = compress(data);
            let mut out = Vec::new();
            write_compact_len(&mut out, compressed.len() as u32);
            out.extend_from_slice(&compressed);
            out
        }

        fn px(sink: &TestPixelSink, i: usize) -> &[u8] {
            &sink.pixels[i * 4..i * 4 + 4]
        }

        #[test]
        fn decode_fill_tile() {
            let mut sink = TestPixelSink::new(2, 2);
            // Fill control byte: 0x08 << 4 = 0x80, followed by one 3-byte CPIXEL.
            let mut data = vec![0x80];
            data.extend_from_slice(&[0xff, 0x00, 0x00]); // red CPIXEL

            decode(
                &mut Cursor::new(&data),
                &mut TightStreams::new(),
                &mut sink,
                0,
                0,
                2,
                2,
                &PixelFormat::rgba32(),
            )
            .unwrap();
            let red = [0xff, 0x00, 0x00, 0xff];
            for i in 0..4 {
                assert_eq!(px(&sink, i), &red);
            }
        }

        #[test]
        fn decode_basic_copy_explicit_stream_with_reset() {
            let mut sink = TestPixelSink::new(2, 2);
            // 2x2 tile = 12 bytes of 3-byte CPIXELs, so the data is compressed.
            let cpixels = vec![
                0xff, 0x00, 0x00, // red
                0x00, 0xff, 0x00, // green
                0x00, 0x00, 0xff, // blue
                0xff, 0xff, 0xff, // white
            ];
            let mut data = vec![0x01]; // stream id 0, reset bit for stream 0
            data.extend_from_slice(&compressed_chunk(&cpixels));

            decode(
                &mut Cursor::new(&data),
                &mut TightStreams::new(),
                &mut sink,
                0,
                0,
                2,
                2,
                &PixelFormat::rgba32(),
            )
            .unwrap();
            assert_eq!(px(&sink, 0), &[0xff, 0x00, 0x00, 0xff]);
            assert_eq!(px(&sink, 1), &[0x00, 0xff, 0x00, 0xff]);
            assert_eq!(px(&sink, 2), &[0x00, 0x00, 0xff, 0xff]);
            assert_eq!(px(&sink, 3), &[0xff, 0xff, 0xff, 0xff]);
        }

        #[test]
        fn decode_basic_copy_stream_id_2() {
            let mut sink = TestPixelSink::new(2, 2);
            let cpixels = vec![
                0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x01, 0x02, 0x03,
            ];
            // Stream id 2 in bits 5-4 (0x20) plus reset bit for stream 2 (0x04).
            let mut data = vec![0x24];
            data.extend_from_slice(&compressed_chunk(&cpixels));

            decode(
                &mut Cursor::new(&data),
                &mut TightStreams::new(),
                &mut sink,
                0,
                0,
                2,
                2,
                &PixelFormat::rgba32(),
            )
            .unwrap();
            assert_eq!(px(&sink, 0), &[0xff, 0x00, 0x00, 0xff]);
            assert_eq!(px(&sink, 3), &[0x01, 0x02, 0x03, 0xff]);
        }

        #[test]
        fn decode_basic_copy_explicit_filter_byte() {
            let mut sink = TestPixelSink::new(2, 2);
            let cpixels = vec![
                0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
            ];
            // Bit 6 set (0x40): an explicit filter id byte follows; 0x01 resets
            // stream 0.
            let mut data = vec![0x40 | 0x01, FILTER_COPY];
            data.extend_from_slice(&compressed_chunk(&cpixels));

            decode(
                &mut Cursor::new(&data),
                &mut TightStreams::new(),
                &mut sink,
                0,
                0,
                2,
                2,
                &PixelFormat::rgba32(),
            )
            .unwrap();
            assert_eq!(px(&sink, 0), &[0xff, 0x00, 0x00, 0xff]);
            assert_eq!(px(&sink, 1), &[0x00, 0xff, 0x00, 0xff]);
        }

        #[test]
        fn decode_basic_copy_small_tile_raw() {
            // 2x1 tile = 6 bytes < MIN_TO_COMPRESS: sent raw, no zlib.
            let mut sink = TestPixelSink::new(2, 1);
            let mut data = vec![0x00]; // stream id 0, no reset (no zlib data follows)
            data.extend_from_slice(&[0xff, 0x00, 0x00, 0x00, 0xff, 0x00]);

            decode(
                &mut Cursor::new(&data),
                &mut TightStreams::new(),
                &mut sink,
                0,
                0,
                2,
                1,
                &PixelFormat::rgba32(),
            )
            .unwrap();
            assert_eq!(px(&sink, 0), &[0xff, 0x00, 0x00, 0xff]);
            assert_eq!(px(&sink, 1), &[0x00, 0xff, 0x00, 0xff]);
        }

        #[test]
        fn decode_palette_2_colors_raw_indices() {
            let mut sink = TestPixelSink::new(2, 1);
            let red = [0xff, 0x00, 0x00];
            let green = [0x00, 0xff, 0x00];

            // Control: explicit filter bit (0x40) + reset stream 0; filter = palette.
            let mut data = vec![0x40 | 0x01, FILTER_PALETTE];
            data.push(1); // palette size minus 1 -> 2 colors
            data.extend_from_slice(&red);
            data.extend_from_slice(&green);
            // 2 pixels at 1 bit each = 1 byte (< 12, so raw): index 0 then 1,
            // MSB first -> 0b01000000.
            data.push(0x40);

            decode(
                &mut Cursor::new(&data),
                &mut TightStreams::new(),
                &mut sink,
                0,
                0,
                2,
                1,
                &PixelFormat::rgba32(),
            )
            .unwrap();
            assert_eq!(px(&sink, 0), &[0xff, 0x00, 0x00, 0xff]);
            assert_eq!(px(&sink, 1), &[0x00, 0xff, 0x00, 0xff]);
        }

        #[test]
        fn decode_palette_4_colors_compressed() {
            // 16x3 tile with 4 colors: 2 bits per index, 4 bytes per row,
            // 12 bytes total -> zlib-compressed.
            let mut sink = TestPixelSink::new(16, 3);
            let palette: [[u8; 3]; 4] = [
                [0xff, 0x00, 0x00],
                [0x00, 0xff, 0x00],
                [0x00, 0x00, 0xff],
                [0xff, 0xff, 0xff],
            ];

            // Indices per row: 0,1,2,3,0,1,2,3,... -> 0b00_01_10_11 = 0x1b repeated.
            let mut indices = Vec::new();
            for _ in 0..3 {
                indices.extend_from_slice(&[0x1b, 0x1b, 0x1b, 0x1b]);
            }

            let mut data = vec![0x40 | 0x01, FILTER_PALETTE];
            data.push(3); // palette size minus 1 -> 4 colors
            for entry in &palette {
                data.extend_from_slice(entry);
            }
            data.extend_from_slice(&compressed_chunk(&indices));

            decode(
                &mut Cursor::new(&data),
                &mut TightStreams::new(),
                &mut sink,
                0,
                0,
                16,
                3,
                &PixelFormat::rgba32(),
            )
            .unwrap();

            let expected: [[u8; 4]; 4] = [
                [0xff, 0x00, 0x00, 0xff],
                [0x00, 0xff, 0x00, 0xff],
                [0x00, 0x00, 0xff, 0xff],
                [0xff, 0xff, 0xff, 0xff],
            ];
            for i in 0..48 {
                assert_eq!(px(&sink, i), &expected[i % 4]);
            }
        }

        #[test]
        fn decode_gradient_compressed() {
            // 2x2 tile of TPIXEL deltas (12 bytes -> zlib-compressed).
            // Target pixels:
            //   row 0: (10, 20, 30), (15, 25, 30)
            //   row 1: (12, 22, 35), (20, 30, 40)
            // Deltas:
            //   (0,0): prediction 0            -> (10, 20, 30)
            //   (1,0): prediction left         -> (5, 5, 0)
            //   (0,1): prediction upper        -> (2, 2, 5)
            //   (1,1): prediction (17, 27, 35) -> (3, 3, 5)
            let deltas = vec![10, 20, 30, 5, 5, 0, 2, 2, 5, 3, 3, 5];

            let mut sink = TestPixelSink::new(2, 2);
            let mut data = vec![0x40 | 0x01, FILTER_GRADIENT];
            data.extend_from_slice(&compressed_chunk(&deltas));

            decode(
                &mut Cursor::new(&data),
                &mut TightStreams::new(),
                &mut sink,
                0,
                0,
                2,
                2,
                &PixelFormat::rgba32(),
            )
            .unwrap();
            assert_eq!(px(&sink, 0), &[10, 20, 30, 0xff]);
            assert_eq!(px(&sink, 1), &[15, 25, 30, 0xff]);
            assert_eq!(px(&sink, 2), &[12, 22, 35, 0xff]);
            assert_eq!(px(&sink, 3), &[20, 30, 40, 0xff]);
        }

        #[test]
        fn decode_rejects_png() {
            let mut sink = TestPixelSink::new(1, 1);
            let data = vec![0xA0]; // PNG subencoding
            let result = decode(
                &mut Cursor::new(&data),
                &mut TightStreams::new(),
                &mut sink,
                0,
                0,
                1,
                1,
                &PixelFormat::rgba32(),
            );
            assert!(matches!(result, Err(ProtocolError::Protocol(_))));
        }

        #[test]
        fn persistent_stream_across_rects() {
            // Two rectangles sharing zlib stream 0: the first carries the
            // reset bit, the second continues the same stream without a reset.
            let cpixels1 = vec![
                0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x01, 0x01, 0x01,
            ];
            let cpixels2 = vec![
                0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
            ];

            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&cpixels1).unwrap();
            encoder.flush().unwrap();
            let chunk1: Vec<u8> = encoder.get_mut().drain(..).collect();
            encoder.write_all(&cpixels2).unwrap();
            encoder.flush().unwrap();
            let chunk2: Vec<u8> = encoder.get_mut().drain(..).collect();

            let mut streams = TightStreams::new();
            let mut sink = TestPixelSink::new(4, 2);

            let mut data1 = vec![0x01]; // stream 0 + reset bit
            write_compact_len(&mut data1, chunk1.len() as u32);
            data1.extend_from_slice(&chunk1);
            decode(
                &mut Cursor::new(&data1),
                &mut streams,
                &mut sink,
                0,
                0,
                2,
                2,
                &PixelFormat::rgba32(),
            )
            .unwrap();

            let mut data2 = vec![0x00]; // stream 0, no reset: continue the stream
            write_compact_len(&mut data2, chunk2.len() as u32);
            data2.extend_from_slice(&chunk2);
            decode(
                &mut Cursor::new(&data2),
                &mut streams,
                &mut sink,
                2,
                0,
                2,
                2,
                &PixelFormat::rgba32(),
            )
            .unwrap();

            assert_eq!(px(&sink, 0), &[0xff, 0x00, 0x00, 0xff]);
            // First pixel of the second rect at (2, 0).
            assert_eq!(px(&sink, 2), &[0x10, 0x20, 0x30, 0xff]);
            // Last pixel of the second rect at (3, 1).
            assert_eq!(px(&sink, 7), &[0xa0, 0xb0, 0xc0, 0xff]);
        }

        #[test]
        fn compressed_chunk_wrong_size_is_rejected() {
            // The chunk inflates to 4 bytes but the rect expects 12: the
            // persistent stream would be out of sync, so this is an error.
            let mut sink = TestPixelSink::new(2, 2);
            let mut data = vec![0x01]; // stream 0 + reset
            data.extend_from_slice(&compressed_chunk(&[0xff, 0x00, 0x00, 0x00]));
            let result = decode(
                &mut Cursor::new(&data),
                &mut TightStreams::new(),
                &mut sink,
                0,
                0,
                2,
                2,
                &PixelFormat::rgba32(),
            );
            assert!(matches!(result, Err(ProtocolError::Protocol(_))));
        }

        #[test]
        fn reconstruct_gradient_known_values() {
            // Same fixture as decode_gradient_compressed, through the pure
            // function directly.
            let deltas = vec![10, 20, 30, 5, 5, 0, 2, 2, 5, 3, 3, 5];
            let rgb = reconstruct_gradient(&deltas, 2, 2).unwrap();
            assert_eq!(rgb, vec![10, 20, 30, 15, 25, 30, 12, 22, 35, 20, 30, 40]);
        }

        #[test]
        fn reconstruct_gradient_wrapping_and_clamping() {
            // (0,0): delta 250 -> 250. (1,0): prediction left=250, delta 10
            // wraps to 4 (mod 256).
            let rgb = reconstruct_gradient(&[250, 0, 0, 10, 0, 0], 2, 1).unwrap();
            assert_eq!(rgb, vec![250, 0, 0, 4, 0, 0]);

            // Row 1: prediction left + upper - upper_left can exceed 255 and
            // must clamp to 255 before the delta is added.
            // row 0: (200, 0, 0), (250, 0, 0) via deltas (200, 0, 0), (50, 0, 0).
            // row 1 col 0: prediction = upper(200), delta 50 -> left = 250.
            // row 1 col 1: prediction = left(250) + upper(250) - upper_left(200)
            //   = 300 -> clamped to 255; delta 0 -> 255.
            let deltas = vec![200, 0, 0, 50, 0, 0, 50, 0, 0, 0, 0, 0];
            let rgb = reconstruct_gradient(&deltas, 2, 2).unwrap();
            assert_eq!(rgb, vec![200, 0, 0, 250, 0, 0, 250, 0, 0, 255, 0, 0]);
        }

        #[test]
        fn reconstruct_gradient_rejects_wrong_length() {
            assert!(matches!(
                reconstruct_gradient(&[0; 5], 2, 2),
                Err(ProtocolError::Protocol(_))
            ));
            assert!(matches!(
                reconstruct_gradient(&[0; 13], 2, 2),
                Err(ProtocolError::Protocol(_))
            ));
        }
    }

    mod encoder {
        use super::*;
        use crate::pixel_sink::TestPixelSink;
        use flate2::{Decompress, FlushDecompress};

        fn fmt() -> PixelFormat {
            PixelFormat::bgra32()
        }

        /// Decode one compact-length value from the front of `data`, returning
        /// the length and the number of bytes consumed.
        fn read_tight_length(data: &[u8]) -> (usize, usize) {
            let mut cursor = std::io::Cursor::new(data);
            let len = read_compact_len(&mut cursor).unwrap();
            (len, cursor.position() as usize)
        }

        /// Inflate exactly `expected_len` bytes from a possibly unfinished
        /// (sync-flushed) zlib stream.
        fn inflate(compressed: &[u8], expected_len: usize) -> Vec<u8> {
            let mut decompress = Decompress::new(true);
            let mut output = vec![0u8; expected_len];
            let mut in_off = 0usize;
            let mut out_off = 0usize;
            while in_off < compressed.len() && out_off < expected_len {
                let before_in = decompress.total_in();
                let before_out = decompress.total_out();
                decompress
                    .decompress(
                        &compressed[in_off..],
                        &mut output[out_off..],
                        FlushDecompress::None,
                    )
                    .unwrap();
                in_off += (decompress.total_in() - before_in) as usize;
                out_off += (decompress.total_out() - before_out) as usize;
            }
            assert_eq!(out_off, expected_len);
            output
        }

        #[test]
        fn test_tight_solid_tile() {
            let mut fb = vec![0u8; 16 * 16 * 4];
            for i in 0..(16 * 16) {
                fb[i * 4..i * 4 + 4].copy_from_slice(&[10, 20, 30, 0]);
            }
            let mut enc = TightEncoder::new();
            let rect = enc.encode(&fb, 64, 0, 0, 16, 16, &fmt());
            // Fill control byte (0x08 << 4), then one 3-byte CPIXEL.
            assert_eq!(rect.data, vec![0x80, 10, 20, 30]);
        }

        #[test]
        fn test_tight_solid_tile_rgb565() {
            // 16bpp RGB565 little-endian client format: CPIXELs are 2 bytes.
            let mut fb = vec![0u8; 16 * 16 * 4];
            for i in 0..(16 * 16) {
                fb[i * 4..i * 4 + 4].copy_from_slice(&[10, 20, 30, 0]);
            }
            let mut enc = TightEncoder::new();
            let rect = enc.encode(&fb, 64, 0, 0, 16, 16, &PixelFormat::rgb16());
            // B=10 -> 1, G=20 -> 5, R=30 -> 4; value = (4<<11)|(5<<5)|1 = 0x20A1.
            assert_eq!(rect.data, vec![0x80, 0xA1, 0x20]);
        }

        #[test]
        fn test_tight_basic_tile_small_raw_rgb565() {
            // A 2x1 non-solid tile is 4 bytes of CPIXELs, below
            // MIN_TO_COMPRESS, so it is sent raw with no length prefix.
            let mut fb = vec![0u8; 2 * 4];
            fb[0..4].copy_from_slice(&[10, 20, 30, 0]);
            fb[4..8].copy_from_slice(&[255, 255, 255, 0]);
            let mut enc = TightEncoder::new();
            let rect = enc.encode(&fb, 8, 0, 0, 2, 1, &PixelFormat::rgb16());
            // Basic control byte (no reset flag), then two 2-byte CPIXELs:
            // 0x20A1 and 0xFFFF, little-endian.
            assert_eq!(rect.data, vec![0x00, 0xA1, 0x20, 0xFF, 0xFF]);
        }

        #[cfg(feature = "jpeg-encode")]
        #[test]
        fn test_tight_jpeg_tile() {
            let mut fb = vec![0u8; 16 * 16 * 4];
            for y in 0..16 {
                for x in 0..16 {
                    let i = (y * 16 + x) * 4;
                    // Make a colorful gradient so JPEG is chosen over Basic.
                    fb[i] = (x * 16) as u8;
                    fb[i + 1] = (y * 16) as u8;
                    fb[i + 2] = ((x + y) * 8) as u8;
                    fb[i + 3] = 0;
                }
            }
            let mut enc = TightEncoder::new();
            let rect = enc.encode(&fb, 64, 0, 0, 16, 16, &fmt());
            // First tile should be JPEG (control byte 0x09 << 4) because it has
            // many unique colors.
            assert_eq!(rect.data[0], CONTROL_JPEG);
            // After the control byte there is a 1-3 byte length followed by JPEG data.
            assert!(rect.data.len() > 4);
        }

        #[test]
        fn test_tight_basic_tile_compressed() {
            // Two colors in a 4x4 tile -> Basic, not JPEG; 48 bytes uncompressed,
            // so the tile data is zlib-compressed.
            let mut fb = vec![0u8; 4 * 4 * 4];
            for i in 0..(4 * 4) {
                if i % 2 == 0 {
                    fb[i * 4..i * 4 + 4].copy_from_slice(&[1, 1, 1, 0]);
                } else {
                    fb[i * 4..i * 4 + 4].copy_from_slice(&[2, 2, 2, 0]);
                }
            }
            let mut enc = TightEncoder::new();
            let rect = enc.encode(&fb, 16, 0, 0, 4, 4, &fmt());
            // Basic compression, stream 0, reset bit for stream 0 set (first
            // compressed tile of the rectangle).
            assert_eq!(rect.data[0], 0x01);

            let (len, hdr) = read_tight_length(&rect.data[1..]);
            let compressed = &rect.data[1 + hdr..1 + hdr + len];
            let cpixels = inflate(compressed, 4 * 4 * 3);
            assert_eq!(&cpixels[0..3], &[1, 1, 1]);
            assert_eq!(&cpixels[3..6], &[2, 2, 2]);
        }

        #[test]
        fn test_tight_basic_tile_small_raw() {
            // A 2x1 non-solid tile is 6 bytes uncompressed, below
            // MIN_TO_COMPRESS, so it is sent raw with no length prefix.
            let mut fb = vec![0u8; 2 * 4];
            fb[0..4].copy_from_slice(&[1, 2, 3, 0]);
            fb[4..8].copy_from_slice(&[4, 5, 6, 0]);
            let mut enc = TightEncoder::new();
            let rect = enc.encode(&fb, 8, 0, 0, 2, 1, &fmt());
            // Basic control byte without reset flag (no zlib data follows), then
            // the raw 3-byte CPIXELs.
            assert_eq!(rect.data, vec![0x00, 1, 2, 3, 4, 5, 6]);
        }

        #[test]
        fn test_tight_reset_flag_only_on_first_compressed_tile() {
            // 32x16 rect of two colors -> two 16x16 Basic tiles. Only the first
            // carries the reset bit for stream 0.
            let mut fb = vec![0u8; 32 * 16 * 4];
            for i in 0..(32 * 16) {
                if i % 2 == 0 {
                    fb[i * 4..i * 4 + 4].copy_from_slice(&[7, 7, 7, 0]);
                } else {
                    fb[i * 4..i * 4 + 4].copy_from_slice(&[8, 8, 8, 0]);
                }
            }
            let mut enc = TightEncoder::new();
            let rect = enc.encode(&fb, 128, 0, 0, 32, 16, &fmt());

            assert_eq!(rect.data[0], 0x01); // first tile: basic, stream 0, reset
            let (len, hdr) = read_tight_length(&rect.data[1..]);
            let next = 1 + hdr + len;
            assert_eq!(rect.data[next], 0x00); // second tile: basic, stream 0, no reset

            // Both tiles decode over one continuous zlib stream: the second chunk
            // continues after the first chunk's sync flush.
            let chunk1 = &rect.data[1 + hdr..1 + hdr + len];
            let (len2, hdr2) = read_tight_length(&rect.data[next + 1..]);
            let chunk2 = &rect.data[next + 1 + hdr2..next + 1 + hdr2 + len2];

            let mut decompress = Decompress::new(true);
            let mut cpixels = vec![0u8; 32 * 16 * 3];
            let mut out_off = 0usize;
            for chunk in [chunk1, chunk2] {
                let mut in_off = 0usize;
                while in_off < chunk.len() && out_off < cpixels.len() {
                    let before_in = decompress.total_in();
                    let before_out = decompress.total_out();
                    decompress
                        .decompress(
                            &chunk[in_off..],
                            &mut cpixels[out_off..],
                            FlushDecompress::None,
                        )
                        .unwrap();
                    in_off += (decompress.total_in() - before_in) as usize;
                    out_off += (decompress.total_out() - before_out) as usize;
                }
            }
            assert_eq!(out_off, 32 * 16 * 3);
            // Pixels alternate 7/8 within each tile.
            assert_eq!(&cpixels[0..3], &[7, 7, 7]);
            assert_eq!(&cpixels[3..6], &[8, 8, 8]);
            assert_eq!(&cpixels[16 * 16 * 3..16 * 16 * 3 + 3], &[7, 7, 7]);
        }

        /// Decode one encoded rectangle tile by tile (16x16, same layout the
        /// encoder used) into a fresh region of `sink`.
        fn decode_rect(
            rect: &FbRect,
            streams: &mut TightStreams,
            sink: &mut TestPixelSink,
            fmt: &PixelFormat,
        ) {
            let mut cursor = std::io::Cursor::new(&rect.data);
            for_each_tile(
                rect.width as usize,
                rect.height as usize,
                ENCODER_TILE_SIZE as usize,
                |tx, ty, tw, th| {
                    decode(
                        &mut cursor,
                        streams,
                        sink,
                        rect.x as usize + tx,
                        rect.y as usize + ty,
                        tw,
                        th,
                        fmt,
                    )
                    .unwrap();
                },
            );
            assert_eq!(cursor.position(), rect.data.len() as u64);
        }

        /// Fill + Basic-copy tiles through one `TightEncoder`/`TightStreams`
        /// pair across two frames: the reset semantics must keep both sides
        /// of the persistent zlib stream in sync.
        #[test]
        fn encoder_decoder_roundtrip_fill_and_basic() {
            // 32x16 framebuffer: left 16x16 tile solid, right 16x16 tile two
            // alternating colours (Basic, zlib-compressed).
            let build_fb = |solid: [u8; 3], a: [u8; 3], b: [u8; 3]| {
                let mut fb = vec![0u8; 32 * 16 * 4];
                for y in 0..16usize {
                    for x in 0..32usize {
                        let p = if x < 16 {
                            solid
                        } else if (x + y) % 2 == 0 {
                            a
                        } else {
                            b
                        };
                        let off = (y * 32 + x) * 4;
                        fb[off..off + 3].copy_from_slice(&p);
                    }
                }
                fb
            };

            let fmt = fmt();
            let mut enc = TightEncoder::new();
            let mut streams = TightStreams::new();
            let mut sink = TestPixelSink::new(32, 16);

            let fb1 = build_fb([10, 20, 30], [1, 1, 1], [2, 2, 2]);
            let rect1 = enc.encode(&fb1, 128, 0, 0, 32, 16, &fmt);
            decode_rect(&rect1, &mut streams, &mut sink, &fmt);
            assert_eq!(sink.pixel(0, 0), Some(&[30, 20, 10, 255]));
            assert_eq!(sink.pixel(16, 0), Some(&[1, 1, 1, 255]));
            assert_eq!(sink.pixel(17, 0), Some(&[2, 2, 2, 255]));

            // Second frame over the same session; the encoder resets stream 0
            // per rectangle and sets the reset bit, so the decoder follows.
            let fb2 = build_fb([40, 50, 60], [3, 3, 3], [4, 4, 4]);
            let rect2 = enc.encode(&fb2, 128, 0, 0, 32, 16, &fmt);
            decode_rect(&rect2, &mut streams, &mut sink, &fmt);
            assert_eq!(sink.pixel(0, 0), Some(&[60, 50, 40, 255]));
            assert_eq!(sink.pixel(16, 0), Some(&[3, 3, 3, 255]));
            assert_eq!(sink.pixel(17, 0), Some(&[4, 4, 4, 255]));
        }

        /// JPEG tile encoded with `jpeg-encode` decodes through the `jpeg`
        /// decoder path (lossy: compare with a tolerance).
        #[cfg(all(feature = "jpeg", feature = "jpeg-encode"))]
        #[test]
        fn encoder_decoder_roundtrip_jpeg() {
            let mut fb = vec![0u8; 16 * 16 * 4];
            for y in 0..16usize {
                for x in 0..16usize {
                    let i = (y * 16 + x) * 4;
                    // Smooth colourful gradient: many unique colours -> JPEG.
                    fb[i] = (x * 16) as u8;
                    fb[i + 1] = (y * 16) as u8;
                    fb[i + 2] = ((x + y) * 8) as u8;
                }
            }
            let mut enc = TightEncoder::new();
            let rect = enc.encode(&fb, 64, 0, 0, 16, 16, &fmt());
            assert_eq!(rect.data[0], CONTROL_JPEG);

            let mut sink = TestPixelSink::new(16, 16);
            decode(
                &mut std::io::Cursor::new(&rect.data),
                &mut TightStreams::new(),
                &mut sink,
                0,
                0,
                16,
                16,
                &fmt(),
            )
            .unwrap();

            // JPEG is lossy; a quality-80 encode of a smooth gradient lands
            // well within 32 per channel. Source pixel is BGR in memory.
            let p = sink.pixel(8, 8).unwrap();
            let src = [((8 + 8) * 8) as u8, (8 * 16) as u8, (8 * 16) as u8]; // B, G, R
            let rgba_expected = [src[2], src[1], src[0]];
            for (got, want) in p.iter().take(3).zip(rgba_expected.iter()) {
                let diff = (*got as i16 - *want as i16).abs();
                assert!(diff <= 32, "pixel {:?} vs {:?}", p, rgba_expected);
            }
            assert_eq!(p[3], 255);
        }
    }
}
