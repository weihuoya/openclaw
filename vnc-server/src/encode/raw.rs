//! Raw encoding (encoding type 0).
//!
//! Simply sends the pixel data uncompressed.

use crate::protocol::FbRect;

/// Encode a region of framebuffer as raw pixels.
///
/// `src` is the full framebuffer in XRGB8888 format (4 bytes per pixel).
/// `src_stride` is the number of bytes per row.
pub fn encode_raw(
    src: &[u8],
    src_stride: usize,
    x: u16,
    y: u16,
    width: u16,
    height: u16,
) -> FbRect {
    let bpp = 4usize;
    let rect_stride = width as usize * bpp;
    let mut data = Vec::with_capacity(rect_stride * height as usize);

    for row in 0..height as usize {
        let src_y = y as usize + row;
        let src_off = src_y * src_stride + x as usize * bpp;
        data.extend_from_slice(&src[src_off..src_off + rect_stride]);
    }

    FbRect {
        x,
        y,
        width,
        height,
        encoding: crate::protocol::Encoding::Raw,
        data,
    }
}

/// Convert XRGB8888 pixels to the client's pixel format.
/// For now, assumes client wants XRGB8888 (no conversion needed).
pub fn convert_pixels(_src: &[u8], _dst_format: &crate::protocol::PixelFormat) -> Vec<u8> {
    // TODO: implement pixel format conversion for non-XRGB clients
    _src.to_vec()
}
