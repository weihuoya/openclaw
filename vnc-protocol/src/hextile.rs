//! Hextile (encoding 5) subencoding flags, subrectangle byte packing, and
//! tile encoding/decoding, shared between client and server.

use std::io::Read;

use crate::encoding::Encoding;
use crate::pixel_format::{xrgb_to_rgba, PixelFormat};
use crate::pixel_sink::PixelSink;
use crate::rect::{for_each_tile, try_for_each_tile, FbRect};
use crate::ProtocolError;

const HEX_TILE_WIDTH: usize = 16;

/// Hextile subencoding flags (one byte per tile).
pub mod flags {
    /// Tile pixels follow as raw pixel data.
    pub const RAW: u8 = 1 << 0;
    /// A background colour follows; the tile is filled with it.
    pub const BACKGROUND_SPECIFIED: u8 = 1 << 1;
    /// A foreground colour follows, used for subrectangles that are not
    /// individually coloured.
    pub const FOREGROUND_SPECIFIED: u8 = 1 << 2;
    /// Subrectangles follow (a count byte, then the subrectangles).
    pub const ANY_SUBRECTS: u8 = 1 << 3;
    /// Each subrectangle carries its own colour; otherwise all use the
    /// foreground colour.
    pub const SUBRECTS_COLOURED: u8 = 1 << 4;
}

/// Pack subrectangle coordinates into the Hextile x/y byte (4 bits each).
pub fn pack_subrect_xy(x: u8, y: u8) -> u8 {
    (x << 4) | (y & 0x0f)
}

/// Unpack the Hextile x/y byte into subrectangle coordinates.
pub fn unpack_subrect_xy(byte: u8) -> (u8, u8) {
    ((byte >> 4) & 0x0f, byte & 0x0f)
}

/// Pack subrectangle dimensions into the Hextile w/h byte; width and height
/// are encoded as value minus one (4 bits each).
pub fn pack_subrect_wh(w: u8, h: u8) -> u8 {
    ((w - 1) << 4) | ((h - 1) & 0x0f)
}

/// Unpack the Hextile w/h byte into subrectangle dimensions (the inverse of
/// [`pack_subrect_wh`]).
pub fn unpack_subrect_wh(byte: u8) -> (u8, u8) {
    (((byte >> 4) & 0x0f) + 1, (byte & 0x0f) + 1)
}

/// Hextile decoder state.
///
/// Per the RFB spec, the background/foreground colors set by
/// `BackgroundSpecified`/`ForegroundSpecified` remain valid for subsequent
/// tiles — including tiles of later rectangles — until re-specified.
/// Encoders (e.g. RealVNC) rely on this to omit unchanged colors.
#[derive(Debug, Clone, Copy)]
pub struct HextileState {
    bg: [u8; 4],
    fg: [u8; 4],
}

impl Default for HextileState {
    fn default() -> Self {
        // Opaque black; only used if the server sends a tile relying on
        // inherited colors before ever specifying them (a protocol violation,
        // but opaque black is a safer fallback than transparent).
        Self {
            bg: [0, 0, 0, 255],
            fg: [0, 0, 0, 255],
        }
    }
}

impl HextileState {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Decode a Hextile-encoded rectangle from the stream into the pixel sink.
#[allow(clippy::too_many_arguments)]
pub fn decode_tiles<P: PixelSink, R: Read>(
    stream: &mut R,
    sink: &mut P,
    rect_x: usize,
    rect_y: usize,
    rect_w: usize,
    rect_h: usize,
    pixel_format: &PixelFormat,
    state: &mut HextileState,
) -> Result<(), ProtocolError> {
    let bpp = pixel_format.bytes_per_pixel();

    try_for_each_tile(rect_w, rect_h, HEX_TILE_WIDTH, |tx, ty, tile_w, tile_h| {
        let tile_pixel_x = rect_x + tx;
        let tile_pixel_y = rect_y + ty;

        let mut subencoding = [0u8; 1];
        stream.read_exact(&mut subencoding)?;
        let flags = subencoding[0];

        decode_tile(
            stream,
            sink,
            tile_pixel_x,
            tile_pixel_y,
            tile_w,
            tile_h,
            pixel_format,
            bpp,
            flags,
            state,
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn decode_tile<P: PixelSink, R: Read>(
    stream: &mut R,
    sink: &mut P,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    pixel_format: &PixelFormat,
    bpp: usize,
    flags: u8,
    state: &mut HextileState,
) -> Result<(), ProtocolError> {
    use flags::{ANY_SUBRECTS, BACKGROUND_SPECIFIED, FOREGROUND_SPECIFIED, RAW, SUBRECTS_COLOURED};

    if flags & RAW != 0 {
        // Raw tile: read all pixels directly
        let mut data = vec![0u8; w * h * bpp];
        stream.read_exact(&mut data)?;
        for row in 0..h {
            for col in 0..w {
                let offset = (row * w + col) * bpp;
                let rgba = pixel_format.to_rgba(&data[offset..offset + bpp]);
                sink.write_pixel(x + col, y + row, rgba);
            }
        }
        return Ok(());
    }

    // Background color: read when specified, otherwise inherit the color
    // carried over from previous tiles/rectangles.
    if flags & BACKGROUND_SPECIFIED != 0 {
        let mut bg_bytes = vec![0u8; bpp];
        stream.read_exact(&mut bg_bytes)?;
        state.bg = pixel_format.to_rgba(&bg_bytes);
    }
    let bg = state.bg;

    // Fill tile with background
    for row in 0..h {
        for col in 0..w {
            sink.write_pixel(x + col, y + row, bg);
        }
    }

    if flags & ANY_SUBRECTS == 0 {
        return Ok(());
    }

    // Foreground color (used if subrects are not individually coloured):
    // likewise inherited unless re-specified.
    if flags & FOREGROUND_SPECIFIED != 0 {
        let mut fg_bytes = vec![0u8; bpp];
        stream.read_exact(&mut fg_bytes)?;
        state.fg = pixel_format.to_rgba(&fg_bytes);
    }
    let fg = state.fg;

    let mut num_subrects = [0u8; 1];
    stream.read_exact(&mut num_subrects)?;
    let num_subrects = num_subrects[0] as usize;

    let coloured = flags & SUBRECTS_COLOURED != 0;

    for _ in 0..num_subrects {
        let mut subrect_pixel = fg;
        if coloured {
            let mut pixel_bytes = vec![0u8; bpp];
            stream.read_exact(&mut pixel_bytes)?;
            subrect_pixel = pixel_format.to_rgba(&pixel_bytes);
        }

        let mut xy = [0u8; 1];
        let mut wh = [0u8; 1];
        stream.read_exact(&mut xy)?;
        stream.read_exact(&mut wh)?;

        let (sx, sy) = unpack_subrect_xy(xy[0]);
        let (sw, sh) = unpack_subrect_wh(wh[0]);
        let (sx, sy, sw, sh) = (sx as usize, sy as usize, sw as usize, sh as usize);

        for row in 0..sh {
            for col in 0..sw {
                sink.write_pixel(x + sx + col, y + sy + row, subrect_pixel);
            }
        }
    }

    Ok(())
}

/// A single-colored rectangle inside a Hextile tile.
#[derive(Debug, Clone, Copy)]
struct SubRect {
    x: u8,
    y: u8,
    w: u8,
    h: u8,
    /// BGRA pixel in server-native format.
    color: [u8; 4],
}

/// Encode a rectangle using Hextile encoding.
///
/// `fb_data` is the full framebuffer in XRGB8888 format (4 bytes per pixel).
/// `stride` is the number of bytes per row.
/// `pixel_format` is the client's requested pixel format.
#[allow(clippy::too_many_arguments)]
pub fn encode_hextile(
    fb_data: &[u8],
    stride: usize,
    x: u16,
    y: u16,
    width: u16,
    height: u16,
    pixel_format: &PixelFormat,
) -> FbRect {
    let mut output = Vec::new();

    for_each_tile(
        width as usize,
        height as usize,
        HEX_TILE_WIDTH,
        |tx, ty, tw, th| {
            encode_tile(
                fb_data,
                stride,
                x + tx as u16,
                y + ty as u16,
                tw as u16,
                th as u16,
                pixel_format,
                &mut output,
            );
        },
    );

    FbRect {
        x,
        y,
        width,
        height,
        encoding: Encoding::Hextile,
        data: output,
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_tile(
    fb_data: &[u8],
    stride: usize,
    x: u16,
    y: u16,
    w: u16,
    h: u16,
    pixel_format: &PixelFormat,
    output: &mut Vec<u8>,
) {
    let bpp = 4; // server native XRGB8888
    let mut pixels = Vec::with_capacity((w * h) as usize * bpp);
    for py in 0..h {
        for px in 0..w {
            let offset = (y + py) as usize * stride + (x + px) as usize * bpp;
            pixels.extend_from_slice(&fb_data[offset..offset + bpp]);
        }
    }

    // Solid tile: BackgroundSpecified + no subrects.
    let first_pixel = &pixels[0..bpp];
    if pixels.chunks(bpp).all(|p| p == first_pixel) {
        output.push(flags::BACKGROUND_SPECIFIED);
        pixel_format.write_pixel(output, xrgb_to_rgba(first_pixel));
        return;
    }

    // Find the most common color and use it as background.
    let bg = most_common_color(&pixels);

    // Extract same-colored rectangles covering all non-background pixels.
    let subrects = extract_subrects(w as usize, h as usize, &pixels, bg);

    // Cost estimates (in bytes) for each possible representation.
    let pixel_bpp = pixel_format.bytes_per_pixel();
    let raw_cost = 1 + w as usize * h as usize * pixel_bpp;

    let all_same_fg = !subrects.is_empty() && subrects.iter().all(|r| r.color == subrects[0].color);
    let mono_cost = if all_same_fg {
        Some(1 + pixel_bpp + pixel_bpp + 1 + subrects.len() * 2)
    } else {
        None
    };
    let colored_cost = 1 + pixel_bpp + 1 + subrects.len() * (pixel_bpp + 2);

    // Choose the cheapest representation. If subrects are too expensive, fall back to raw.
    let use_mono = mono_cost.map(|c| c < raw_cost).unwrap_or(false);
    let use_colored = colored_cost < raw_cost;

    if !use_mono && !use_colored {
        // Raw fallback.
        output.push(flags::RAW);
        for chunk in pixels.chunks(bpp) {
            pixel_format.write_pixel(output, xrgb_to_rgba(chunk));
        }
        return;
    }

    if use_mono {
        let fg = subrects[0].color;
        output
            .push(flags::BACKGROUND_SPECIFIED | flags::FOREGROUND_SPECIFIED | flags::ANY_SUBRECTS);
        pixel_format.write_pixel(output, xrgb_to_rgba(&bg));
        pixel_format.write_pixel(output, xrgb_to_rgba(&fg));
        output.push(subrects.len() as u8);
        for r in subrects {
            write_subrect(output, r.x, r.y, r.w, r.h);
        }
    } else {
        output.push(flags::BACKGROUND_SPECIFIED | flags::ANY_SUBRECTS | flags::SUBRECTS_COLOURED);
        pixel_format.write_pixel(output, xrgb_to_rgba(&bg));
        output.push(subrects.len() as u8);
        for r in subrects {
            pixel_format.write_pixel(output, xrgb_to_rgba(&r.color));
            write_subrect(output, r.x, r.y, r.w, r.h);
        }
    }
}

/// Find the most common 4-byte color in a pixel array.
fn most_common_color(pixels: &[u8]) -> [u8; 4] {
    let mut counts: std::collections::HashMap<[u8; 4], usize> = std::collections::HashMap::new();
    for chunk in pixels.chunks(4) {
        let color = [chunk[0], chunk[1], chunk[2], chunk[3]];
        *counts.entry(color).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(color, _)| color)
        .unwrap_or([0, 0, 0, 0])
}

/// Extract a set of same-colored rectangles that cover every pixel which differs
/// from `bg`. Uses a greedy row-extension algorithm: each rectangle is extended
/// right then down as far as the color matches and pixels are uncovered.
fn extract_subrects(w: usize, h: usize, pixels: &[u8], bg: [u8; 4]) -> Vec<SubRect> {
    let mut covered = vec![false; w * h];
    let mut subrects = Vec::new();

    for y in 0..h {
        for x in 0..w {
            let idx = y * w + x;
            if covered[idx] {
                continue;
            }
            let color = pixel_at(pixels, w, x, y);
            if color == bg {
                continue;
            }

            // Extend right.
            let mut rect_w = 1usize;
            while x + rect_w < w
                && !covered[idx + rect_w]
                && pixel_at(pixels, w, x + rect_w, y) == color
            {
                rect_w += 1;
            }

            // Extend down.
            let mut rect_h = 1usize;
            'down: while y + rect_h < h {
                for dx in 0..rect_w {
                    let next_idx = (y + rect_h) * w + x + dx;
                    if covered[next_idx] || pixel_at(pixels, w, x + dx, y + rect_h) != color {
                        break 'down;
                    }
                }
                rect_h += 1;
            }

            // Mark covered and emit subrect.
            for dy in 0..rect_h {
                for dx in 0..rect_w {
                    covered[(y + dy) * w + x + dx] = true;
                }
            }
            subrects.push(SubRect {
                x: x as u8,
                y: y as u8,
                w: rect_w as u8,
                h: rect_h as u8,
                color,
            });
        }
    }

    subrects
}

fn pixel_at(pixels: &[u8], w: usize, x: usize, y: usize) -> [u8; 4] {
    let idx = (y * w + x) * 4;
    [
        pixels[idx],
        pixels[idx + 1],
        pixels[idx + 2],
        pixels[idx + 3],
    ]
}

fn write_subrect(out: &mut Vec<u8>, x: u8, y: u8, w: u8, h: u8) {
    // Hextile subrect coordinates are 4-bit values; width/height are encoded as value-1.
    out.push(pack_subrect_xy(x, y));
    out.push(pack_subrect_wh(w, h));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn flag_values_match_spec() {
        assert_eq!(flags::RAW, 1);
        assert_eq!(flags::BACKGROUND_SPECIFIED, 2);
        assert_eq!(flags::FOREGROUND_SPECIFIED, 4);
        assert_eq!(flags::ANY_SUBRECTS, 8);
        assert_eq!(flags::SUBRECTS_COLOURED, 16);
    }

    #[test]
    fn subrect_xy_roundtrip() {
        for x in 0..=15u8 {
            for y in 0..=15u8 {
                assert_eq!(unpack_subrect_xy(pack_subrect_xy(x, y)), (x, y));
            }
        }
    }

    #[test]
    fn subrect_wh_roundtrip() {
        for w in 1..=16u8 {
            for h in 1..=16u8 {
                assert_eq!(unpack_subrect_wh(pack_subrect_wh(w, h)), (w, h));
            }
        }
    }

    #[test]
    fn subrect_exact_bytes() {
        // Subrect at (0,0) size 2x1 => xy = 0x00, wh = 0x10.
        assert_eq!(pack_subrect_xy(0, 0), 0x00);
        assert_eq!(pack_subrect_wh(2, 1), 0x10);
        // Subrect at (3,5) size 16x16 => xy = 0x35, wh = 0xff.
        assert_eq!(pack_subrect_xy(3, 5), 0x35);
        assert_eq!(pack_subrect_wh(16, 16), 0xff);
        assert_eq!(unpack_subrect_xy(0x35), (3, 5));
        assert_eq!(unpack_subrect_wh(0xff), (16, 16));
    }

    #[test]
    fn decode_raw_tile() {
        let mut sink = crate::pixel_sink::TestPixelSink::new(2, 2);
        let raw = vec![
            0xff, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
            0x00, 0xff,
        ];
        let mut data = vec![flags::RAW];
        data.extend_from_slice(&raw);
        decode_tiles(
            &mut Cursor::new(&data),
            &mut sink,
            0,
            0,
            2,
            2,
            &PixelFormat::rgba32(),
            &mut HextileState::new(),
        )
        .unwrap();
        assert_eq!(sink.pixels, raw);
    }

    #[test]
    fn decode_solid_tile() {
        let mut sink = crate::pixel_sink::TestPixelSink::new(2, 2);
        // Background specified, no subrects
        let bg = vec![0x00, 0x00, 0xff, 0xff]; // blue in BGRA → red in RGBA
        let mut data = vec![flags::BACKGROUND_SPECIFIED];
        data.extend_from_slice(&bg);
        decode_tiles(
            &mut Cursor::new(&data),
            &mut sink,
            0,
            0,
            2,
            2,
            &PixelFormat::bgra32(),
            &mut HextileState::new(),
        )
        .unwrap();

        let expected = [0xff, 0x00, 0x00, 0xff]
            .iter()
            .cycle()
            .take(16)
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(sink.pixels, expected);
    }

    #[test]
    fn decode_single_subrect() {
        let mut sink = crate::pixel_sink::TestPixelSink::new(2, 2);
        // Background: white, foreground: red, 1 subrect at (0,0) size 2x2
        let bg = vec![0xff, 0xff, 0xff, 0xff]; // white BGRA
        let fg = vec![0x00, 0x00, 0xff, 0xff]; // red BGRA
        let mut data =
            vec![flags::BACKGROUND_SPECIFIED | flags::FOREGROUND_SPECIFIED | flags::ANY_SUBRECTS];
        data.extend_from_slice(&bg);
        data.extend_from_slice(&fg);
        data.push(1); // 1 subrect
        data.push(0x00); // xy: sx=0, sy=0
        data.push(0x11); // wh: sw=2, sh=2
        decode_tiles(
            &mut Cursor::new(&data),
            &mut sink,
            0,
            0,
            2,
            2,
            &PixelFormat::bgra32(),
            &mut HextileState::new(),
        )
        .unwrap();

        let red = [0xff, 0x00, 0x00, 0xff];
        for i in 0..4 {
            assert_eq!(sink.pixel(i % 2, i / 2), Some(&red));
        }
    }

    #[test]
    fn colors_carry_over_between_tiles_and_rects() {
        let mut state = HextileState::new();
        let mut sink = crate::pixel_sink::TestPixelSink::new(32, 16);

        let mut data = Vec::new();
        // Tile 1: bg red, fg blue, 1 subrect covering the whole tile.
        data.push(flags::BACKGROUND_SPECIFIED | flags::FOREGROUND_SPECIFIED | flags::ANY_SUBRECTS);
        data.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]); // bg: red (BGRA)
        data.extend_from_slice(&[0xff, 0x00, 0x00, 0xff]); // fg: blue (BGRA)
        data.push(1); // 1 subrect
        data.push(0x00); // xy: sx=0, sy=0
        data.push(0xff); // wh: sw=16, sh=16
                         // Tile 2: no flags, no subrects → inherit bg (red) only.
        data.push(0x00);

        decode_tiles(
            &mut Cursor::new(&data),
            &mut sink,
            0,
            0,
            32,
            16,
            &PixelFormat::bgra32(),
            &mut state,
        )
        .unwrap();

        let red = [0xff, 0x00, 0x00, 0xff];
        let blue = [0x00, 0x00, 0xff, 0xff];
        // Tile 1 fully covered by the fg subrect → blue.
        assert_eq!(sink.pixel(0, 0), Some(&blue));
        // Tile 2 inherits bg → red.
        assert_eq!(sink.pixel(16, 0), Some(&red));

        // Later rectangle relying on the inherited bg (no flags at all).
        let mut sink2 = crate::pixel_sink::TestPixelSink::new(4, 4);
        let data2 = vec![0x00u8]; // no flags, no subrects
        decode_tiles(
            &mut Cursor::new(&data2),
            &mut sink2,
            0,
            0,
            4,
            4,
            &PixelFormat::bgra32(),
            &mut state,
        )
        .unwrap();
        assert_eq!(sink2.pixel(0, 0), Some(&red));
    }

    fn make_solid_tile(color: [u8; 4]) -> Vec<u8> {
        let mut tile = Vec::with_capacity(16 * 16 * 4);
        for _ in 0..(16 * 16) {
            tile.extend_from_slice(&color);
        }
        tile
    }

    fn tile_to_fb(tile: &[u8], w: usize, h: usize) -> Vec<u8> {
        let stride = w * 4;
        let mut fb = vec![0u8; h * stride];
        for y in 0..h {
            for x in 0..w {
                let src = (y * w + x) * 4;
                let dst = y * stride + x * 4;
                fb[dst..dst + 4].copy_from_slice(&tile[src..src + 4]);
            }
        }
        fb
    }

    #[test]
    fn test_solid_tile_encoding() {
        let color = [0x12, 0x34, 0x56, 0x00]; // BGRA
        let fb = tile_to_fb(&make_solid_tile(color), 16, 16);
        let rect = encode_hextile(&fb, 16 * 4, 0, 0, 16, 16, &PixelFormat::bgra32());
        assert_eq!(rect.encoding, Encoding::Hextile);
        // 16x16 tiles = 1 tile. Flag + 4 bytes background = 5 bytes.
        assert_eq!(rect.data.len(), 5);
        assert_eq!(rect.data[0], flags::BACKGROUND_SPECIFIED);
        assert_eq!(&rect.data[1..5], &color);
    }

    #[test]
    fn test_raw_fallback_for_complex_tile() {
        // Use a tile where every pixel has a unique color so the colored
        // subrect representation is far larger than raw.
        let mut tile = Vec::with_capacity(16 * 16 * 4);
        for y in 0..16usize {
            for x in 0..16usize {
                tile.extend_from_slice(&[x as u8, y as u8, 0, 0]);
            }
        }
        let fb = tile_to_fb(&tile, 16, 16);
        let rect = encode_hextile(&fb, 16 * 4, 0, 0, 16, 16, &PixelFormat::bgra32());
        assert_eq!(rect.data[0], flags::RAW);
        // Raw data: 1 flag + 16*16*4 pixels.
        assert_eq!(rect.data.len(), 1 + 16 * 16 * 4);
    }

    #[test]
    fn test_mono_subrect_encoding() {
        // 4x4 tile: blue background with a 2x1 red strip at the top.
        let bg = [0xff, 0x00, 0x00, 0x00]; // blue in BGRA
        let fg = [0x00, 0x00, 0xff, 0x00]; // red in BGRA
        let mut tile = make_solid_tile(bg);
        for x in 0..2 {
            let idx = x * 4;
            tile[idx..idx + 4].copy_from_slice(&fg);
        }
        let fb = tile_to_fb(&tile, 4, 4);
        let rect = encode_hextile(&fb, 4 * 4, 0, 0, 4, 4, &PixelFormat::bgra32());

        // Should be BackgroundSpecified | ForegroundSpecified | AnySubrects.
        let flags = rect.data[0];
        assert_eq!(
            flags,
            flags::BACKGROUND_SPECIFIED | flags::FOREGROUND_SPECIFIED | flags::ANY_SUBRECTS
        );
        assert_eq!(&rect.data[1..5], &bg);
        assert_eq!(&rect.data[5..9], &fg);
        assert_eq!(rect.data[9], 1); // 1 subrect
                                     // Subrect at (0,0) size 2x1 => xy=0x00, wh=0x10
        assert_eq!(rect.data[10], 0x00);
        assert_eq!(rect.data[11], 0x10);
    }

    #[test]
    fn test_colored_subrect_encoding() {
        // 4x4 tile: blue background with a red pixel at (0,0) and green pixel at (1,1).
        let bg = [0xff, 0x00, 0x00, 0x00]; // blue
        let red = [0x00, 0x00, 0xff, 0x00];
        let green = [0x00, 0xff, 0x00, 0x00];
        let mut tile = make_solid_tile(bg);
        tile[0..4].copy_from_slice(&red);
        tile[(4 + 1) * 4..(4 + 1) * 4 + 4].copy_from_slice(&green);
        let fb = tile_to_fb(&tile, 4, 4);
        let rect = encode_hextile(&fb, 4 * 4, 0, 0, 4, 4, &PixelFormat::bgra32());

        let flags = rect.data[0];
        assert_eq!(
            flags,
            flags::BACKGROUND_SPECIFIED | flags::ANY_SUBRECTS | flags::SUBRECTS_COLOURED
        );
        assert_eq!(&rect.data[1..5], &bg);
        assert_eq!(rect.data[5], 2); // 2 subrects
                                     // Each subrect: 4 bytes color + 2 bytes xy/wh.
        assert_eq!(rect.data.len(), 1 + 4 + 1 + 2 * (4 + 2));
    }

    #[test]
    fn test_multi_tile_rect() {
        // 17x17 rectangle forces 4 tiles (2x2).
        let color = [0x12, 0x34, 0x56, 0x00];
        let mut tile = Vec::with_capacity(17 * 17 * 4);
        for _ in 0..(17 * 17) {
            tile.extend_from_slice(&color);
        }
        let fb = tile_to_fb(&tile, 17, 17);
        let rect = encode_hextile(&fb, 17 * 4, 0, 0, 17, 17, &PixelFormat::bgra32());
        // 4 tiles, each 5 bytes (flag + background) = 20 bytes.
        assert_eq!(rect.data.len(), 20);
    }

    #[test]
    fn encode_decode_roundtrip() {
        // 20x20 XRGB8888 framebuffer with three colours per tile: exercises
        // the coloured-subrects path across multiple tiles.
        let width = 20usize;
        let height = 20usize;
        let stride = width * 4;
        let mut fb = vec![0u8; stride * height];
        for y in 0..height {
            for x in 0..width {
                let pixel = match (x + y) % 3 {
                    0 => [0xff, 0x00, 0x00, 0], // blue (BGRA)
                    1 => [0x00, 0xff, 0x00, 0], // green
                    _ => [0x00, 0x00, 0xff, 0], // red
                };
                let off = y * stride + x * 4;
                fb[off..off + 4].copy_from_slice(&pixel);
            }
        }

        let rect = encode_hextile(
            &fb,
            stride,
            0,
            0,
            width as u16,
            height as u16,
            &PixelFormat::bgra32(),
        );
        let mut sink = crate::pixel_sink::TestPixelSink::new(width, height);
        decode_tiles(
            &mut Cursor::new(&rect.data),
            &mut sink,
            rect.x as usize,
            rect.y as usize,
            rect.width as usize,
            rect.height as usize,
            &PixelFormat::bgra32(),
            &mut HextileState::new(),
        )
        .unwrap();

        for y in 0..height {
            for x in 0..width {
                let off = y * stride + x * 4;
                let expected = xrgb_to_rgba(&fb[off..off + 4]);
                assert_eq!(sink.pixel(x, y), Some(&expected), "pixel ({}, {})", x, y);
            }
        }
    }
}
