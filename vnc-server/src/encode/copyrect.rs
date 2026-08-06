//! CopyRect encoding (encoding type 1).
//!
//! CopyRect tells the client to copy a rectangle from one location in its
//! existing framebuffer to another. The rectangle data is just the source
//! coordinates: 16-bit big-endian x and y.

use crate::protocol::{CopyRectBody, Encoding, FbRect};

/// Encode a CopyRect rectangle.
///
/// The client will copy the rectangle of size `width`x`height` from
/// (`src_x`, `src_y`) to the destination position (`x`, `y`).
pub fn encode_copyrect(src_x: u16, src_y: u16, x: u16, y: u16, width: u16, height: u16) -> FbRect {
    let body = CopyRectBody { src_x, src_y };
    FbRect {
        x,
        y,
        width,
        height,
        encoding: Encoding::CopyRect,
        data: body.to_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_copyrect() {
        let rect = encode_copyrect(100, 200, 10, 20, 30, 40);
        assert_eq!(rect.encoding, Encoding::CopyRect);
        assert_eq!(rect.x, 10);
        assert_eq!(rect.y, 20);
        assert_eq!(rect.width, 30);
        assert_eq!(rect.height, 40);
        assert_eq!(rect.data, vec![0x00, 0x64, 0x00, 0xC8]);
    }
}
