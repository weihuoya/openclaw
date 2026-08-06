use std::io::Write;

use crate::encoding::Encoding;
use crate::framing::RectHeader;
use crate::ProtocolError;

/// Sanity limits on framebuffer and rectangle dimensions.
///
/// RFB carries dimensions as u16, so a hostile or broken peer can advertise
/// up to 65535x65535 (a ~17 GiB RGBA framebuffer) and force a giant
/// allocation. Legitimate displays are far smaller: 8K UHD is 7680x4320
/// (~33 Mpx) and Apple's high-performance virtual displays stay in the same
/// range. Allow up to 16384 per dimension and 64 M pixels in total (256 MiB
/// of RGBA), which covers two 6K displays side by side with headroom.
pub const MAX_DIMENSION: u32 = 16384;
/// Maximum accepted total pixel count; see [`MAX_DIMENSION`].
pub const MAX_PIXELS: u64 = 64 * 1024 * 1024;

/// Reject absurd framebuffer/rectangle dimensions before any allocation is
/// derived from them.
pub fn check_dimensions(width: u32, height: u32) -> Result<(), ProtocolError> {
    if width > MAX_DIMENSION || height > MAX_DIMENSION || width as u64 * height as u64 > MAX_PIXELS
    {
        return Err(ProtocolError::Protocol(format!(
            "Dimensions {}x{} exceed sanity limits (max {} per side, {} pixels total)",
            width, height, MAX_DIMENSION, MAX_PIXELS
        )));
    }
    Ok(())
}

/// A rectangle within a framebuffer update.
#[derive(Debug, Clone)]
pub struct FbRect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
    pub encoding: Encoding,
    pub data: Vec<u8>,
}

impl FbRect {
    /// Write the 12-byte wire header (position, size, encoding number).
    ///
    /// The byte layout lives in [`RectHeader`]; this adapts the `Encoding`
    /// enum field to the raw wire number.
    pub fn write_header<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        RectHeader {
            x: self.x,
            y: self.y,
            width: self.width,
            height: self.height,
            encoding: self.encoding.as_i32(),
        }
        .write_to_io(w)
    }
}

/// Iterate over the tiles covering a `width` x `height` rectangle, in
/// left-to-right, top-to-bottom order, invoking `f` with each tile's
/// rectangle `(x, y, w, h)` relative to the rectangle origin. The last tile
/// in each row/column is clipped to the rectangle bounds.
///
/// Used by the tiled encodings (ZRLE/TRLE with 64x64 tiles, Hextile and
/// Tight with 16x16 tiles).
pub fn for_each_tile<F>(width: usize, height: usize, tile_size: usize, mut f: F)
where
    F: FnMut(usize, usize, usize, usize),
{
    let _ = try_for_each_tile::<std::convert::Infallible, _>(
        width,
        height,
        tile_size,
        |tx, ty, tw, th| {
            f(tx, ty, tw, th);
            Ok(())
        },
    );
}

/// Fallible variant of [`for_each_tile`]: stops and returns the error as
/// soon as `f` fails.
pub fn try_for_each_tile<E, F>(
    width: usize,
    height: usize,
    tile_size: usize,
    mut f: F,
) -> Result<(), E>
where
    F: FnMut(usize, usize, usize, usize) -> Result<(), E>,
{
    let tiles_x = width.div_ceil(tile_size);
    let tiles_y = height.div_ceil(tile_size);

    for ty in 0..tiles_y {
        for tx in 0..tiles_x {
            let tw = tile_size.min(width - tx * tile_size);
            let th = tile_size.min(height - ty * tile_size);
            f(tx * tile_size, ty * tile_size, tw, th)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_header_matches_rect_header_layout() {
        let rect = FbRect {
            x: 1,
            y: 2,
            width: 640,
            height: 480,
            encoding: Encoding::ExtendedDesktopSize,
            data: Vec::new(),
        };
        let mut via_fb_rect = Vec::new();
        rect.write_header(&mut via_fb_rect).unwrap();

        let header = RectHeader {
            x: rect.x,
            y: rect.y,
            width: rect.width,
            height: rect.height,
            encoding: rect.encoding.as_i32(),
        };
        let mut via_rect_header = Vec::new();
        header.write_to(&mut via_rect_header);

        assert_eq!(via_fb_rect.len(), RectHeader::WIRE_LEN);
        assert_eq!(via_fb_rect, via_rect_header);
        assert_eq!(RectHeader::from_bytes(&via_fb_rect), header);
    }

    #[test]
    fn check_dimensions_accepts_legitimate_sizes() {
        assert!(check_dimensions(1920, 1080).is_ok());
        // 8K UHD and the boundary cases.
        assert!(check_dimensions(7680, 4320).is_ok());
        assert!(check_dimensions(16384, 4096).is_ok());
    }

    #[test]
    fn check_dimensions_rejects_absurd_sizes() {
        // Over the per-dimension cap.
        assert!(check_dimensions(16385, 1).is_err());
        assert!(check_dimensions(1, 65535).is_err());
        // Under the per-dimension cap but over the total-pixel cap.
        assert!(check_dimensions(16384, 16384).is_err());
    }

    #[test]
    fn tiles_cover_rect_in_order() {
        // 100x70 at tile size 64 -> 64x64, 36x64, 64x6, 36x6.
        let mut tiles = Vec::new();
        for_each_tile(100, 70, 64, |x, y, w, h| tiles.push((x, y, w, h)));
        assert_eq!(
            tiles,
            vec![
                (0, 0, 64, 64),
                (64, 0, 36, 64),
                (0, 64, 64, 6),
                (64, 64, 36, 6)
            ]
        );
    }

    #[test]
    fn exact_multiple_and_single_tile() {
        let mut tiles = Vec::new();
        for_each_tile(128, 64, 64, |x, y, w, h| tiles.push((x, y, w, h)));
        assert_eq!(tiles, vec![(0, 0, 64, 64), (64, 0, 64, 64)]);

        tiles.clear();
        for_each_tile(16, 16, 64, |x, y, w, h| tiles.push((x, y, w, h)));
        assert_eq!(tiles, vec![(0, 0, 16, 16)]);
    }

    #[test]
    fn empty_rect_produces_no_tiles() {
        let mut called = false;
        for_each_tile(0, 10, 64, |_, _, _, _| called = true);
        assert!(!called);
        for_each_tile(10, 0, 64, |_, _, _, _| called = true);
        assert!(!called);
    }

    #[test]
    fn try_variant_stops_on_error() {
        let mut visited = Vec::new();
        let result: Result<(), &str> = try_for_each_tile(128, 64, 64, |x, y, w, h| {
            if x == 64 {
                return Err("boom");
            }
            visited.push((x, y, w, h));
            Ok(())
        });
        assert_eq!(result, Err("boom"));
        assert_eq!(visited, vec![(0, 0, 64, 64)]);
    }
}
