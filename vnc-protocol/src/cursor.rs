//! VNC Cursor pseudo-encoding (-239) helpers.
//!
//! The Cursor pseudo-encoding sends a cursor image and a 1-bit transparency mask
//! to the client, allowing the client to render the cursor locally. The wire
//! format for a Cursor rectangle is:
//!
//!   - Rectangle header: `x=hotspot_x`, `y=hotspot_y`, `width`, `height`, `encoding=-239`
//!   - Pixel data: `width * height * bytes_per_pixel` in the server's pixel format
//!   - Mask data: `ceil(width / 8) * height` bytes, MSB-first, 1=visible, 0=transparent
//!
//! Pixels are stored in this crate as RGBA8888 (little-endian, non-premultiplied)
//! with the alpha channel already derived from the mask. The 1-bit mask is kept
//! separately so that it can be re-encoded to the wire when the server sends the
//! cursor to a client with a different pixel format.

use crate::{Encoding, FbRect, PixelFormat, ProtocolError};

/// A VNC cursor shape.
///
/// `pixels` are stored as RGBA8888 (little-endian, non-premultiplied). The alpha
/// channel is taken from the mask during decoding: visible pixels are opaque and
/// transparent pixels are fully transparent. The `mask` is a 1-bit bitmap in the
/// RFB wire layout (MSB-first, packed row-major).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorShape {
    pub width: u16,
    pub height: u16,
    pub hotspot_x: u16,
    pub hotspot_y: u16,
    /// RGBA pixels (`width * height * 4` bytes), little-endian.
    pub pixels: Vec<u8>,
    /// 1-bit mask: 1 = visible, 0 = transparent. MSB-first, packed row-major.
    pub mask: Vec<u8>,
}

impl CursorShape {
    /// Total wire length of a Cursor pseudo-encoding payload: the pixel data
    /// (`width * height` pixels in `pixel_format`) followed by the 1-bit
    /// mask (`ceil(width / 8) * height` bytes).
    pub fn wire_len(width: u16, height: u16, pixel_format: &PixelFormat) -> usize {
        let pixel_data_size = width as usize * height as usize * pixel_format.bytes_per_pixel();
        let mask_size = (width as usize).div_ceil(8) * height as usize;
        pixel_data_size + mask_size
    }

    /// Decode a cursor shape from the RFB Cursor pseudo-encoding payload.
    ///
    /// `data` is the concatenation of the pixel data (in `pixel_format`) and the
    /// 1-bit mask. The returned shape stores RGBA pixels with alpha derived from
    /// the mask.
    pub fn decode(
        width: u16,
        height: u16,
        hotspot_x: u16,
        hotspot_y: u16,
        data: &[u8],
        pixel_format: &PixelFormat,
    ) -> Result<Self, ProtocolError> {
        let bpp = pixel_format.bytes_per_pixel();
        let pixel_data_size = width as usize * height as usize * bpp;
        let mask_row_bytes = (width as usize).div_ceil(8);
        let mask_size = mask_row_bytes * height as usize;

        if data.len() < pixel_data_size + mask_size {
            return Err(ProtocolError::Protocol(
                "Cursor encoding data too short".to_string(),
            ));
        }

        let pixel_data = &data[..pixel_data_size];
        let mask_data = &data[pixel_data_size..pixel_data_size + mask_size];

        let mut pixels = Vec::with_capacity(width as usize * height as usize * 4);
        for y in 0..height as usize {
            for x in 0..width as usize {
                let pixel_offset = (y * width as usize + x) * bpp;
                let pixel = &pixel_data[pixel_offset..pixel_offset + bpp];
                let mut rgba = pixel_format.to_rgba(pixel);

                let mask_byte_idx = y * mask_row_bytes + x / 8;
                let mask_bit = 7 - (x % 8); // MSB first
                let visible = if mask_data.len() > mask_byte_idx {
                    (mask_data[mask_byte_idx] >> mask_bit) & 1
                } else {
                    1
                };

                rgba[3] = if visible == 1 { 0xff } else { 0x00 };
                pixels.extend_from_slice(&rgba);
            }
        }

        Ok(Self {
            width,
            height,
            hotspot_x,
            hotspot_y,
            pixels,
            mask: mask_data.to_vec(),
        })
    }

    /// Encode the cursor shape to the RFB wire payload in the given pixel format.
    ///
    /// The returned bytes are: pixel data in `pixel_format` followed by the mask.
    pub fn to_wire(&self, pixel_format: &PixelFormat) -> Vec<u8> {
        let bpp = pixel_format.bytes_per_pixel();
        let mut data = Vec::with_capacity(self.pixels.len() / 4 * bpp + self.mask.len());
        for pixel in self.pixels.chunks_exact(4) {
            pixel_format.write_pixel(&mut data, [pixel[0], pixel[1], pixel[2], pixel[3]]);
        }
        data.extend_from_slice(&self.mask);
        data
    }

    /// Return the cursor pixels as RGBA8888.
    ///
    /// This is a convenience for client renderers that already work with the
    /// stored RGBA format. It returns a clone because the stored pixels may be
    /// consumed or transformed by the caller.
    pub fn to_rgba(&self) -> Vec<u8> {
        self.pixels.clone()
    }
}

/// Generate a simple default arrow cursor.
///
/// The shape is an 11x16 black arrow with a transparent background and the
/// hotspot at the top-left corner (0, 0).
pub fn default_cursor() -> CursorShape {
    const WIDTH: usize = 11;
    const HEIGHT: usize = 16;

    let mut pixels = Vec::with_capacity(WIDTH * HEIGHT * 4);
    let mut mask = Vec::with_capacity((WIDTH).div_ceil(8) * HEIGHT);

    for y in 0..HEIGHT {
        let mut mask_byte = 0u8;
        let mut bit_count = 0;
        for x in 0..WIDTH {
            let visible = is_default_cursor_pixel(x, y);
            // Black pixel for the arrow body, transparent otherwise.
            if visible {
                pixels.extend_from_slice(&[0x00, 0x00, 0x00, 0xff]); // RGBA black
            } else {
                pixels.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // transparent
            }

            mask_byte = (mask_byte << 1) | u8::from(visible);
            bit_count += 1;
            if bit_count == 8 {
                mask.push(mask_byte);
                mask_byte = 0;
                bit_count = 0;
            }
        }
        // Pad the last byte of each row if the row width is not a multiple of 8.
        if bit_count > 0 {
            mask_byte <<= 8 - bit_count;
            mask.push(mask_byte);
        }
    }

    CursorShape {
        width: WIDTH as u16,
        height: HEIGHT as u16,
        hotspot_x: 0,
        hotspot_y: 0,
        pixels,
        mask,
    }
}

fn is_default_cursor_pixel(x: usize, y: usize) -> bool {
    // Triangle arrow head.
    if y <= 10 && x <= y {
        return true;
    }
    // Arrow shaft.
    if y > 10 && (5..=9).contains(&x) {
        return true;
    }
    false
}

/// Encode a cursor shape into an `FbRect` with the Cursor pseudo-encoding.
pub fn encode_cursor(shape: &CursorShape, pixel_format: &PixelFormat) -> FbRect {
    FbRect {
        x: shape.hotspot_x,
        y: shape.hotspot_y,
        width: shape.width,
        height: shape.height,
        encoding: Encoding::Cursor,
        data: shape.to_wire(pixel_format),
    }
}

/// Encode a cursor position update into an `FbRect` with the CursorPos
/// pseudo-encoding. The rectangle carries no pixel data; the position is encoded
/// in the rectangle header (x, y, width=0, height=0).
pub fn encode_cursor_pos(x: u16, y: u16) -> FbRect {
    FbRect {
        x,
        y,
        width: 0,
        height: 0,
        encoding: Encoding::CursorPos,
        data: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_len_matches_decode_layout() {
        // 11x16 cursor: 4 bpp pixel data + 2 mask bytes per row.
        assert_eq!(
            CursorShape::wire_len(11, 16, &PixelFormat::bgra32()),
            11 * 16 * 4 + 2 * 16
        );
        // 2 bpp format halves the pixel section; mask layout is unchanged.
        assert_eq!(
            CursorShape::wire_len(11, 16, &PixelFormat::rgb16()),
            11 * 16 * 2 + 2 * 16
        );
        // Widths that are multiples of 8 need no mask padding.
        assert_eq!(
            CursorShape::wire_len(8, 1, &PixelFormat::rgba32()),
            8 * 4 + 1
        );
        let shape = default_cursor();
        let wire = shape.to_wire(&PixelFormat::bgra32());
        assert_eq!(
            CursorShape::wire_len(shape.width, shape.height, &PixelFormat::bgra32()),
            wire.len()
        );
    }

    #[test]
    fn test_default_cursor_mask_size() {
        let shape = default_cursor();
        assert_eq!(shape.width, 11);
        assert_eq!(shape.height, 16);
        assert_eq!(shape.pixels.len(), 11 * 16 * 4);
        assert_eq!(shape.mask.len(), 11_usize.div_ceil(8) * 16);
    }

    #[test]
    fn test_default_cursor_mask_bits_match_visibility() {
        let shape = default_cursor();
        let mask_row_bytes = 11_usize.div_ceil(8);
        for y in 0..shape.height as usize {
            for x in 0..shape.width as usize {
                let mask_byte_idx = y * mask_row_bytes + x / 8;
                let mask_bit = 7 - (x % 8);
                let visible = (shape.mask[mask_byte_idx] >> mask_bit) & 1;
                assert_eq!(visible == 1, is_default_cursor_pixel(x, y));

                let pixel_offset = (y * shape.width as usize + x) * 4;
                let alpha = shape.pixels[pixel_offset + 3];
                assert_eq!(alpha == 0xff, is_default_cursor_pixel(x, y));
            }
        }
    }

    #[test]
    fn test_cursor_wire_bgra32() {
        let shape = default_cursor();
        let wire = shape.to_wire(&PixelFormat::bgra32());
        let bpp = 4;
        let pixel_data_size = 11 * 16 * bpp;
        let mask_size = 11_usize.div_ceil(8) * 16;
        assert_eq!(wire.len(), pixel_data_size + mask_size);
    }

    #[test]
    fn test_cursor_wire_rgb16() {
        let shape = default_cursor();
        let wire = shape.to_wire(&PixelFormat::rgb16());
        let bpp = 2;
        let pixel_data_size = 11 * 16 * bpp;
        let mask_size = 11_usize.div_ceil(8) * 16;
        assert_eq!(wire.len(), pixel_data_size + mask_size);
    }

    #[test]
    fn test_cursor_roundtrip_bgra32() {
        let shape = default_cursor();
        let wire = shape.to_wire(&PixelFormat::bgra32());
        let decoded = CursorShape::decode(11, 16, 0, 0, &wire, &PixelFormat::bgra32()).unwrap();
        assert_eq!(decoded, shape);
    }

    #[test]
    fn test_cursor_roundtrip_rgb16() {
        let shape = default_cursor();
        let wire = shape.to_wire(&PixelFormat::rgb16());
        let decoded = CursorShape::decode(11, 16, 0, 0, &wire, &PixelFormat::rgb16()).unwrap();
        // RGB16 is lossy, so pixels differ, but the shape dimensions and mask
        // must survive the roundtrip.
        assert_eq!(decoded.width, shape.width);
        assert_eq!(decoded.height, shape.height);
        assert_eq!(decoded.hotspot_x, shape.hotspot_x);
        assert_eq!(decoded.hotspot_y, shape.hotspot_y);
        assert_eq!(decoded.mask, shape.mask);
    }

    #[test]
    fn test_cursor_roundtrip_rgba32() {
        let shape = default_cursor();
        let wire = shape.to_wire(&PixelFormat::rgba32());
        let decoded = CursorShape::decode(11, 16, 0, 0, &wire, &PixelFormat::rgba32()).unwrap();
        assert_eq!(decoded, shape);
    }

    #[test]
    fn test_encode_cursor_rect() {
        let shape = default_cursor();
        let rect = encode_cursor(&shape, &PixelFormat::bgra32());
        assert_eq!(rect.encoding, Encoding::Cursor);
        assert_eq!(rect.x, 0);
        assert_eq!(rect.y, 0);
        assert_eq!(rect.width, 11);
        assert_eq!(rect.height, 16);
    }

    #[test]
    fn test_encode_cursor_pos_rect() {
        let rect = encode_cursor_pos(123, 456);
        assert_eq!(rect.encoding, Encoding::CursorPos);
        assert_eq!(rect.x, 123);
        assert_eq!(rect.y, 456);
        assert_eq!(rect.width, 0);
        assert_eq!(rect.height, 0);
        assert!(rect.data.is_empty());
    }

    #[test]
    fn test_decode_too_short() {
        let err = CursorShape::decode(1, 1, 0, 0, &[], &PixelFormat::bgra32()).unwrap_err();
        assert!(matches!(err, ProtocolError::Protocol(_)));
    }
}
