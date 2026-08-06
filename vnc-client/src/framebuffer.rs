/// Framebuffer transformation for rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Transform {
    #[default]
    None,
    Rotate90,
    Rotate180,
    Rotate270,
    FlipHorizontal,
    FlipVertical,
    FlipBoth,
}

impl Transform {
    /// Apply transform to coordinates (x, y) in a framebuffer of given size.
    /// Returns the source coordinates (src_x, src_y) in the original framebuffer.
    pub fn map_coords(&self, x: usize, y: usize, width: usize, height: usize) -> (usize, usize) {
        match self {
            Transform::None => (x, y),
            Transform::Rotate90 => (y, height - 1 - x),
            Transform::Rotate180 => (width - 1 - x, height - 1 - y),
            Transform::Rotate270 => (width - 1 - y, x),
            Transform::FlipHorizontal => (width - 1 - x, y),
            Transform::FlipVertical => (x, height - 1 - y),
            Transform::FlipBoth => (width - 1 - x, height - 1 - y),
        }
    }

    /// Whether the transform swaps width and height.
    pub fn swaps_dimensions(&self) -> bool {
        matches!(self, Transform::Rotate90 | Transform::Rotate270)
    }

    /// Effective width after transform.
    pub fn transformed_width(&self, width: usize, height: usize) -> usize {
        if self.swaps_dimensions() {
            height
        } else {
            width
        }
    }

    /// Effective height after transform.
    pub fn transformed_height(&self, width: usize, height: usize) -> usize {
        if self.swaps_dimensions() {
            width
        } else {
            height
        }
    }
}

pub use vnc_protocol::PixelFormat;

/// Framebuffer storage (always RGBA8888 internally).
pub struct Framebuffer {
    width: usize,
    height: usize,
    data: Vec<u8>,
    transform: Transform,
}

impl Framebuffer {
    pub fn new(width: usize, height: usize) -> Self {
        let data = vec![0u8; width * height * 4];
        Self {
            width,
            height,
            data,
            transform: Transform::None,
        }
    }

    pub fn from_raw(width: usize, height: usize, data: Vec<u8>) -> Self {
        Self {
            width,
            height,
            data,
            transform: Transform::None,
        }
    }

    pub fn resize(&mut self, width: usize, height: usize) {
        self.width = width;
        self.height = height;
        self.data.resize(width * height * 4, 0);
    }

    pub fn width(&self) -> usize {
        self.width
    }
    pub fn height(&self) -> usize {
        self.height
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn set_transform(&mut self, transform: Transform) {
        self.transform = transform;
    }

    pub fn transform(&self) -> Transform {
        self.transform
    }

    /// Read a pixel from the framebuffer, applying the current transform.
    pub fn read_pixel(&self, x: usize, y: usize) -> Option<[u8; 4]> {
        let disp_w = self.transform.transformed_width(self.width, self.height);
        let disp_h = self.transform.transformed_height(self.width, self.height);
        if x >= disp_w || y >= disp_h {
            return None;
        }
        let (src_x, src_y) = self.transform.map_coords(x, y, self.width, self.height);
        if src_x < self.width && src_y < self.height {
            let offset = (src_y * self.width + src_x) * 4;
            Some([
                self.data[offset],
                self.data[offset + 1],
                self.data[offset + 2],
                self.data[offset + 3],
            ])
        } else {
            None
        }
    }
    /// Write a region of pixels (source is in the server's pixel format).
    pub fn write_region(
        &mut self,
        x: usize,
        y: usize,
        width: usize,
        height: usize,
        src: &[u8],
        src_format: &PixelFormat,
    ) {
        let src_bpp = src_format.bytes_per_pixel();
        let src_row_size = width * src_bpp;

        // Fast path: source is already RGBA8888 little-endian.
        if *src_format == PixelFormat::rgba32() {
            for row in 0..height {
                let src_offset = row * src_row_size;
                let dst_offset = ((y + row) * self.width + x) * 4;
                let len = src_row_size
                    .min(src.len() - src_offset)
                    .min(self.data.len().saturating_sub(dst_offset));
                if dst_offset < self.data.len() && src_offset < src.len() {
                    self.data[dst_offset..dst_offset + len]
                        .copy_from_slice(&src[src_offset..src_offset + len]);
                }
            }
            return;
        }

        // Slow path: convert each pixel using the server's pixel format.
        for row in 0..height {
            for col in 0..width {
                let src_offset = row * src_row_size + col * src_bpp;
                let dst_offset = ((y + row) * self.width + x + col) * 4;
                if src_offset + src_bpp <= src.len() && dst_offset + 4 <= self.data.len() {
                    let rgba = src_format.to_rgba(&src[src_offset..src_offset + src_bpp]);
                    self.data[dst_offset..dst_offset + 4].copy_from_slice(&rgba);
                }
            }
        }
    }

    /// Write a single pixel (RGBA).
    pub fn write_pixel(&mut self, x: usize, y: usize, rgba: [u8; 4]) {
        if x < self.width && y < self.height {
            let offset = (y * self.width + x) * 4;
            self.data[offset..offset + 4].copy_from_slice(&rgba);
        }
    }
}

impl vnc_protocol::PixelSink for Framebuffer {
    fn write_pixel(&mut self, x: usize, y: usize, rgba: [u8; 4]) {
        Framebuffer::write_pixel(self, x, y, rgba);
    }

    fn write_region(&mut self, x: u16, y: u16, w: u16, h: u16, rgba: &[u8]) {
        // The sink receives RGBA8888, which hits the bulk-copy fast path.
        Framebuffer::write_region(
            self,
            x as usize,
            y as usize,
            w as usize,
            h as usize,
            rgba,
            &PixelFormat::rgba32(),
        );
    }
}

impl Framebuffer {
    /// Copy a rectangle from one location to another.
    pub fn copy_rect(
        &mut self,
        src_x: usize,
        src_y: usize,
        dst_x: usize,
        dst_y: usize,
        width: usize,
        height: usize,
    ) {
        let bytes_per_pixel = 4;
        let row_size = width * bytes_per_pixel;

        if src_y < dst_y || (src_y == dst_y && src_x < dst_x) {
            // Copy bottom-up to handle vertical overlap.
            for row in (0..height).rev() {
                let src_offset = ((src_y + row) * self.width + src_x) * bytes_per_pixel;
                let dst_offset = ((dst_y + row) * self.width + dst_x) * bytes_per_pixel;
                if src_offset + row_size <= self.data.len()
                    && dst_offset + row_size <= self.data.len()
                {
                    self.data
                        .copy_within(src_offset..src_offset + row_size, dst_offset);
                }
            }
        } else {
            for row in 0..height {
                let src_offset = ((src_y + row) * self.width + src_x) * bytes_per_pixel;
                let dst_offset = ((dst_y + row) * self.width + dst_x) * bytes_per_pixel;
                if src_offset + row_size <= self.data.len()
                    && dst_offset + row_size <= self.data.len()
                {
                    self.data
                        .copy_within(src_offset..src_offset + row_size, dst_offset);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_region_rgba_fast_path() {
        let mut fb = Framebuffer::new(2, 2);
        // RGBA little-endian: [R, G, B, A]
        let data = vec![
            0xff, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
            0x00, 0xff,
        ];
        fb.write_region(0, 0, 2, 2, &data, &PixelFormat::rgba32());
        assert_eq!(fb.data(), &data);
    }

    #[test]
    fn write_region_bgra_converts_to_rgba() {
        let mut fb = Framebuffer::new(2, 1);
        // BGRA little-endian: [B, G, R, A]
        let bgra = vec![0x00, 0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0xff];
        fb.write_region(0, 0, 2, 1, &bgra, &PixelFormat::bgra32());

        let expected = vec![
            0xff, 0x00, 0x00, 0xff, // red
            0x00, 0xff, 0x00, 0xff, // green
        ];
        assert_eq!(fb.data(), &expected);
    }

    #[test]
    fn copy_rect_overlapping_bottom_up() {
        let mut fb = Framebuffer::new(4, 2);
        // Row 0: red green blue white
        fb.write_pixel(0, 0, [255, 0, 0, 255]);
        fb.write_pixel(1, 0, [0, 255, 0, 255]);
        fb.write_pixel(2, 0, [0, 0, 255, 255]);
        fb.write_pixel(3, 0, [255, 255, 255, 255]);

        // Copy row 0 to row 1 (overlapping? no, different rows)
        fb.copy_rect(0, 0, 0, 1, 4, 1);

        let expected_row0 = vec![
            255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 255, 255,
        ];
        let expected_row1 = expected_row0.clone();
        assert_eq!(&fb.data()[0..16], &expected_row0[..]);
        assert_eq!(&fb.data()[16..32], &expected_row1[..]);
    }

    #[test]
    fn copy_rect_overlapping_forward() {
        // 3x2 framebuffer: rows have distinct colors.
        let mut fb = Framebuffer::new(2, 3);
        fb.write_pixel(0, 0, [0, 0, 0, 255]);
        fb.write_pixel(1, 0, [0, 0, 0, 255]);
        fb.write_pixel(0, 1, [1, 0, 0, 255]);
        fb.write_pixel(1, 1, [1, 0, 0, 255]);
        fb.write_pixel(0, 2, [2, 0, 0, 255]);
        fb.write_pixel(1, 2, [2, 0, 0, 255]);

        // Copy (0,0) 2x2 to (0,1) — src_y=0 < dst_y=1, so bottom-up copy is used.
        fb.copy_rect(0, 0, 0, 1, 2, 2);

        // Row 0 unchanged.
        assert_eq!(fb.data()[0..8], [0, 0, 0, 255, 0, 0, 0, 255]);
        // Row 1 got old row 0.
        assert_eq!(fb.data()[8..16], [0, 0, 0, 255, 0, 0, 0, 255]);
        // Row 2 got old row 1.
        assert_eq!(fb.data()[16..24], [1, 0, 0, 255, 1, 0, 0, 255]);
    }

    #[test]
    fn write_region_zero_size() {
        let mut fb = Framebuffer::new(2, 2);
        let data = vec![0xff, 0x00, 0x00, 0xff];
        // Zero width — should be a no-op
        fb.write_region(0, 0, 0, 2, &data, &PixelFormat::rgba32());
        assert_eq!(fb.data(), &vec![0u8; 16]);
    }

    #[test]
    fn write_region_out_of_bounds() {
        let mut fb = Framebuffer::new(2, 2);
        let data = vec![0xff; 16];
        // Write starting at (1, 1) with 2x2 data — should clamp to framebuffer bounds
        fb.write_region(1, 1, 2, 2, &data, &PixelFormat::rgba32());
        // Only pixel (1,1) should be written
        assert_eq!(fb.data()[12], 0xff);
        assert_eq!(fb.data()[13], 0xff);
        assert_eq!(fb.data()[14], 0xff);
        assert_eq!(fb.data()[15], 0xff);
        // Other pixels should remain zero
        assert_eq!(fb.data()[0], 0);
    }
}
