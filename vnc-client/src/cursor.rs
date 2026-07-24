/// VNC cursor shape handling.
///
/// The Cursor pseudo-encoding (-239) sends cursor pixel data and a bitmask.
/// Pixel data is in the server's pixel format, followed by a 1-bit mask
/// where 1 = visible pixel, 0 = transparent.
#[derive(Debug, Clone)]
pub struct CursorShape {
    pub width: u16,
    pub height: u16,
    pub hotspot_x: u16,
    pub hotspot_y: u16,
    /// RGBA pixels (width * height * 4 bytes), pre-multiplied alpha.
    pub pixels: Vec<u8>,
}

impl CursorShape {
    /// Decode cursor data from the RFB wire format.
    ///
    /// `data` contains: [pixel_data...][mask_data...]
    /// Pixel data is in the server's pixel format.
    /// Mask is 1 bit per pixel, packed row-major.
    pub fn decode(
        width: u16,
        height: u16,
        hotspot_x: u16,
        hotspot_y: u16,
        data: &[u8],
        pixel_format: &crate::PixelFormat,
    ) -> Result<Self, crate::VncError> {
        let bpp = pixel_format.bytes_per_pixel();
        let pixel_data_size = width as usize * height as usize * bpp;
        let mask_row_bytes = (width as usize).div_ceil(8);
        let mask_size = mask_row_bytes * height as usize;

        if data.len() < pixel_data_size + mask_size {
            return Err(crate::VncError::Protocol(
                "Cursor encoding data too short".to_string(),
            ));
        }

        let pixel_data = &data[..pixel_data_size];
        let mask_data = &data[pixel_data_size..pixel_data_size + mask_size];

        // Convert pixel data to RGBA8888
        let mut pixels = Vec::with_capacity(width as usize * height as usize * 4);

        for y in 0..height as usize {
            for x in 0..width as usize {
                let pixel_offset = (y * width as usize + x) * bpp;
                let pixel = &pixel_data[pixel_offset..pixel_offset + bpp];
                let rgba = pixel_format.to_rgba(pixel);

                // Check mask bit
                let mask_byte_idx = y * mask_row_bytes + x / 8;
                let mask_bit = 7 - (x % 8); // MSB first
                let visible = if mask_data.len() > mask_byte_idx {
                    (mask_data[mask_byte_idx] >> mask_bit) & 1
                } else {
                    1
                };

                if visible == 1 {
                    pixels.extend_from_slice(&rgba);
                } else {
                    pixels.extend_from_slice(&[0, 0, 0, 0]); // transparent
                }
            }
        }

        Ok(Self {
            width,
            height,
            hotspot_x,
            hotspot_y,
            pixels,
        })
    }
}
