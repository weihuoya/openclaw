//! Round-trip tests: encode framebuffers with the vnc-server ZRLE/TRLE
//! encoders and decode them with the vnc-client decoders, verifying both sides
//! agree on the RFB-spec wire format (3-byte CPIXELs, tile subencodings,
//! per-scanline packing, RLE run lengths, ZRLE length prefix).

use std::io::Cursor;

use vnc_client::framebuffer::{Framebuffer, PixelFormat};
use vnc_server::encode::rre::encode_rre;
use vnc_server::encode::trle::encode_trle;
use vnc_server::encode::zrle::ZrleEncoder;

/// Build an XRGB8888 framebuffer exercising every tile subencoding:
/// - a solid area,
/// - a two-colour area (palette RLE),
/// - a three-colour checkerboard (packed palette),
/// - a gradient with more than 16 colours (raw).
fn test_framebuffer(width: usize, height: usize) -> (Vec<u8>, usize) {
    let stride = width * 4;
    let mut data = vec![0u8; stride * height];
    for y in 0..height {
        for x in 0..width {
            let off = y * stride + x * 4;
            let (b, g, r) = if x < width / 4 {
                // Solid: dark red.
                (0, 0, 128)
            } else if x < width / 2 {
                // Two colours alternating.
                if (x + y) % 2 == 0 {
                    (255, 0, 0)
                } else {
                    (0, 255, 0)
                }
            } else if x < 3 * width / 4 {
                // Three colours in a repeating pattern.
                match (x + y) % 3 {
                    0 => (255, 0, 0),
                    1 => (0, 255, 0),
                    _ => (0, 0, 255),
                }
            } else {
                // Many distinct colours.
                ((x * 3) as u8, (y * 5) as u8, ((x + y) * 7) as u8)
            };
            data[off] = b;
            data[off + 1] = g;
            data[off + 2] = r;
        }
    }
    (data, stride)
}

/// Assert the decoded client framebuffer matches the XRGB8888 source pixels
/// inside the given rect.
fn assert_rect_matches(
    fb: &Framebuffer,
    src: &[u8],
    stride: usize,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
) {
    for row in 0..h {
        for col in 0..w {
            let src_off = (y + row) * stride + (x + col) * 4;
            let (b, g, r) = (src[src_off], src[src_off + 1], src[src_off + 2]);
            let px = fb.read_pixel(x + col, y + row).unwrap();
            assert_eq!(
                px,
                [r, g, b, 0xff],
                "pixel mismatch at ({}, {})",
                x + col,
                y + row
            );
        }
    }
}

#[test]
fn server_zrle_decodes_with_client() {
    let fmt = PixelFormat::bgra32();
    let (fb, stride) = test_framebuffer(200, 130);
    let mut encoder = ZrleEncoder::new();
    let mut decompress: Option<vnc_client::zlib::SessionInflate> = None;

    // Multiple rects share one persistent zlib stream; include a rect at a
    // non-zero x/y (regression for the server tile-size computation) and one
    // with edge tiles smaller than 64.
    let rects = [
        (0u16, 0u16, 64u16, 64u16),
        (64, 0, 64, 64),
        (128, 0, 72, 70),
        (0, 64, 136, 66),
    ];

    let mut client_fb = Framebuffer::new(200, 130);
    for &(x, y, w, h) in &rects {
        let rect = encoder.encode_rect(&fb, stride, x, y, w, h, &fmt);
        vnc_client::zrle::decode(
            &mut Cursor::new(&rect.data),
            &mut decompress,
            &mut client_fb,
            x as usize,
            y as usize,
            w as usize,
            h as usize,
            &fmt,
        )
        .unwrap();
        assert_rect_matches(
            &client_fb, &fb, stride, x as usize, y as usize, w as usize, h as usize,
        );
    }
}

#[test]
fn server_trle_decodes_with_client() {
    let fmt = PixelFormat::bgra32();
    let (fb, stride) = test_framebuffer(200, 130);

    let rects = [
        (0u16, 0u16, 64u16, 64u16),
        (64, 0, 64, 64),
        (128, 0, 72, 70),
        (0, 64, 136, 66),
    ];

    let mut client_fb = Framebuffer::new(200, 130);
    for &(x, y, w, h) in &rects {
        let rect = encode_trle(&fb, stride, x, y, w, h, &fmt);
        vnc_client::trle::decode(
            &mut Cursor::new(&rect.data),
            &mut client_fb,
            x as usize,
            y as usize,
            w as usize,
            h as usize,
            &fmt,
        )
        .unwrap();
        assert_rect_matches(
            &client_fb, &fb, stride, x as usize, y as usize, w as usize, h as usize,
        );
    }
}

#[test]
fn server_rre_decodes_with_client() {
    let fmt = PixelFormat::bgra32();
    // RRE works best with few colors; reuse the palette-friendly source.
    let (fb, stride) = test_framebuffer(32, 32);

    let mut client_fb = Framebuffer::new(32, 32);
    for &(x, y, w, h) in &[(0u16, 0u16, 32u16, 32u16), (16, 16, 16, 16)] {
        let rect = encode_rre(&fb, stride, x, y, w, h, &fmt);
        vnc_client::rre::decode(
            &mut Cursor::new(&rect.data),
            &mut client_fb,
            x as usize,
            y as usize,
            w as usize,
            h as usize,
            &fmt,
        )
        .unwrap();
        assert_rect_matches(
            &client_fb, &fb, stride, x as usize, y as usize, w as usize, h as usize,
        );
    }
}
