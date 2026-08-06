//! Pixel sink abstraction for shared decoders.
//!
//! Decoders in `vnc-protocol` do not depend on client-specific framebuffer
//! types. Instead, they write pixels through the [`PixelSink`] trait, which the
//! client implements for its `Framebuffer` and tests implement for in-memory
//! buffers.

use crate::pixel_format::PixelFormat;

/// A sink for RGBA pixels produced by shared decoders.
///
/// Implementors receive one RGBA pixel at a time. Coordinates are absolute
/// framebuffer coordinates (i.e., the rectangle offset has already been added).
pub trait PixelSink {
    /// Write a single RGBA8888 pixel at `(x, y)`.
    fn write_pixel(&mut self, x: usize, y: usize, rgba: [u8; 4]);

    /// Write a `w`x`h` region of RGBA8888 pixels (row-major, 4 bytes per
    /// pixel) with its top-left corner at `(x, y)`.
    ///
    /// The default implementation writes pixel by pixel; implementors backed
    /// by a contiguous buffer should override this with a bulk copy to avoid
    /// a per-pixel bottleneck on large rectangles.
    fn write_region(&mut self, x: u16, y: u16, w: u16, h: u16, rgba: &[u8]) {
        for row in 0..h as usize {
            for col in 0..w as usize {
                let offset = (row * w as usize + col) * 4;
                if offset + 4 <= rgba.len() {
                    let pixel = [
                        rgba[offset],
                        rgba[offset + 1],
                        rgba[offset + 2],
                        rgba[offset + 3],
                    ];
                    self.write_pixel(x as usize + col, y as usize + row, pixel);
                }
            }
        }
    }
}

/// A simple in-memory pixel sink for tests.
///
/// Stores pixels in RGBA8888 little-endian order, row-major, exactly like a
/// framebuffer of the given dimensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestPixelSink {
    pub width: usize,
    pub height: usize,
    pub pixels: Vec<u8>,
}

impl TestPixelSink {
    /// Create a new sink of the given size, filled with transparent black.
    pub fn new(width: usize, height: usize) -> Self {
        Self {
            width,
            height,
            pixels: vec![0; width * height * 4],
        }
    }

    /// Return a reference to the pixel at `(x, y)` as a 4-byte RGBA slice.
    pub fn pixel(&self, x: usize, y: usize) -> Option<&[u8; 4]> {
        if x < self.width && y < self.height {
            let offset = (y * self.width + x) * 4;
            self.pixels[offset..offset + 4].try_into().ok()
        } else {
            None
        }
    }
}

impl PixelSink for TestPixelSink {
    fn write_pixel(&mut self, x: usize, y: usize, rgba: [u8; 4]) {
        if x < self.width && y < self.height {
            let offset = (y * self.width + x) * 4;
            self.pixels[offset..offset + 4].copy_from_slice(&rgba);
        }
    }
}

/// Write a `w`x`h` region of wire-format pixels to `sink`, converting each
/// pixel to RGBA8888 with `pixel_format`.
///
/// `data` holds the pixels in row-major order, `bytes_per_pixel` bytes each
/// (PIXEL or CPIXEL wire format, as accepted by [`PixelFormat::to_rgba`]).
/// Short data leaves the tail pixels untouched. Coordinates are absolute
/// framebuffer coordinates and must fit the RFB wire range (`u16`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_converted_region<P: PixelSink>(
    sink: &mut P,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    data: &[u8],
    bytes_per_pixel: usize,
    pixel_format: &PixelFormat,
) {
    let expected = w * h * bytes_per_pixel;
    // Fast path: the data is already RGBA8888 little-endian.
    if *pixel_format == PixelFormat::rgba32() && bytes_per_pixel == 4 && data.len() >= expected {
        sink.write_region(x as u16, y as u16, w as u16, h as u16, &data[..expected]);
        return;
    }
    let mut rgba = vec![0u8; w * h * 4];
    for i in 0..w * h {
        let start = i * bytes_per_pixel;
        if start + bytes_per_pixel <= data.len() {
            rgba[i * 4..i * 4 + 4]
                .copy_from_slice(&pixel_format.to_rgba(&data[start..start + bytes_per_pixel]));
        }
    }
    sink.write_region(x as u16, y as u16, w as u16, h as u16, &rgba);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pixel_sink_writes_pixels() {
        let mut sink = TestPixelSink::new(2, 2);
        sink.write_pixel(0, 0, [1, 2, 3, 4]);
        sink.write_pixel(1, 1, [5, 6, 7, 8]);
        assert_eq!(sink.pixel(0, 0), Some(&[1, 2, 3, 4]));
        assert_eq!(sink.pixel(1, 1), Some(&[5, 6, 7, 8]));
        assert_eq!(sink.pixel(1, 0), Some(&[0, 0, 0, 0]));
        assert_eq!(sink.pixel(0, 1), Some(&[0, 0, 0, 0]));
    }

    #[test]
    fn test_pixel_sink_clamps_out_of_bounds() {
        let mut sink = TestPixelSink::new(1, 1);
        sink.write_pixel(2, 0, [1, 2, 3, 4]);
        sink.write_pixel(0, 2, [1, 2, 3, 4]);
        assert_eq!(sink.pixels, vec![0, 0, 0, 0]);
    }

    #[test]
    fn default_write_region_writes_row_major_rgba() {
        let mut sink = TestPixelSink::new(3, 2);
        let region: &[u8] = &[
            1, 2, 3, 4, 5, 6, 7, 8, // row 0: two pixels
            9, 10, 11, 12, 13, 14, 15, 16, // row 1: two pixels
        ];
        sink.write_region(1, 0, 2, 2, region);
        assert_eq!(sink.pixel(1, 0), Some(&[1, 2, 3, 4]));
        assert_eq!(sink.pixel(2, 0), Some(&[5, 6, 7, 8]));
        assert_eq!(sink.pixel(1, 1), Some(&[9, 10, 11, 12]));
        assert_eq!(sink.pixel(2, 1), Some(&[13, 14, 15, 16]));
        assert_eq!(sink.pixel(0, 0), Some(&[0, 0, 0, 0]));
    }
}
