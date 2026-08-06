//! Tight encoding decoder (RFB encoding type 7).
//!
//! The Tight decode logic (control/filter dispatch, Fill, basic copy, palette,
//! gradient, and the JPEG subencoding) is shared in [`vnc_protocol::tight`];
//! this module provides the client-specific wrapper that targets a
//! `Framebuffer`.

use std::io::Read;

use crate::framebuffer::{Framebuffer, PixelFormat};
use crate::VncError;

pub use vnc_protocol::tight::TightStreams;

/// Decode a Tight-encoded rectangle from the stream into the framebuffer.
#[allow(clippy::too_many_arguments)]
pub fn decode<R: Read>(
    stream: &mut R,
    streams: &mut TightStreams,
    fb: &mut Framebuffer,
    rect_x: usize,
    rect_y: usize,
    rect_w: usize,
    rect_h: usize,
    pixel_format: &PixelFormat,
) -> Result<(), VncError> {
    vnc_protocol::tight::decode(
        stream,
        streams,
        fb,
        rect_x,
        rect_y,
        rect_w,
        rect_h,
        pixel_format,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::{Cursor, Write};

    #[test]
    fn decode_fill_tile() {
        let mut fb = Framebuffer::new(2, 2);
        // Fill control byte: 0x08 << 4 = 0x80, followed by one 3-byte CPIXEL.
        let mut data = vec![0x80];
        data.extend_from_slice(&[0xff, 0x00, 0x00]); // red CPIXEL

        decode(
            &mut Cursor::new(&data),
            &mut TightStreams::new(),
            &mut fb,
            0,
            0,
            2,
            2,
            &PixelFormat::rgba32(),
        )
        .unwrap();
        assert_eq!(
            fb.data(),
            &vec![255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255]
        );
    }

    /// Smoke test: two rectangles sharing one persistent zlib stream through
    /// the client wrapper (the full fixture matrix lives in vnc-protocol).
    #[test]
    fn persistent_stream_across_rects() {
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
        let mut fb = Framebuffer::new(4, 2);

        let mut data1 = vec![0x01]; // stream 0 + reset bit
        vnc_protocol::tight::write_compact_len(&mut data1, chunk1.len() as u32);
        data1.extend_from_slice(&chunk1);
        decode(
            &mut Cursor::new(&data1),
            &mut streams,
            &mut fb,
            0,
            0,
            2,
            2,
            &PixelFormat::rgba32(),
        )
        .unwrap();

        let mut data2 = vec![0x00]; // stream 0, no reset: continue the stream
        vnc_protocol::tight::write_compact_len(&mut data2, chunk2.len() as u32);
        data2.extend_from_slice(&chunk2);
        decode(
            &mut Cursor::new(&data2),
            &mut streams,
            &mut fb,
            2,
            0,
            2,
            2,
            &PixelFormat::rgba32(),
        )
        .unwrap();

        assert_eq!(&fb.data()[0..4], &[0xff, 0x00, 0x00, 0xff]);
        // First pixel of the second rect at (2, 0).
        assert_eq!(&fb.data()[8..12], &[0x10, 0x20, 0x30, 0xff]);
        // Last pixel of the second rect at (3, 1).
        assert_eq!(&fb.data()[28..32], &[0xa0, 0xb0, 0xc0, 0xff]);
    }
}
