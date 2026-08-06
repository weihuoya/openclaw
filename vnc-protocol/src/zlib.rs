//! Zlib stream helpers shared between client and server.
//!
//! Contains the session-spanning inflate/deflate machinery ([`SessionInflate`],
//! [`ZlibEncoder`]), the length-prefixed framing used by the Zlib and ZRLE
//! encodings, and the Zlib rectangle decoder.

use std::io::Read;
use std::io::Write;

use flate2::write::ZlibEncoder as FlateZlibEncoder;
use flate2::{Compression, Decompress, FlushDecompress, Status};

use crate::encoding::Encoding;
use crate::pixel_format::PixelFormat;
use crate::pixel_sink::{write_converted_region, PixelSink};
use crate::raw::encode_raw;
use crate::rect::FbRect;
use crate::ProtocolError;

/// Maximum compressed payload length accepted for a single rectangle. This
/// bounds memory allocation and protects against malicious length prefixes.
pub const MAX_COMPRESSED_LEN: usize = 64 * 1024 * 1024; // 64 MiB

/// Returns true if the data starts with a valid zlib header (deflate compression
/// with a valid header check bits).
pub fn is_zlib_header(compressed: &[u8]) -> bool {
    if compressed.len() < 2 {
        return false;
    }
    let cmf = compressed[0];
    let flg = compressed[1];
    // Deflate compression (CM == 8) and the header check bits must be valid.
    (cmf & 0x0f) == 8 && ((cmf as u16) * 256 + (flg as u16)).is_multiple_of(31)
}

/// Build a length-prefixed frame: a 4-byte big-endian length followed by
/// `data`. Used by the ZRLE and Zlib encodings, which wrap each rectangle's
/// compressed payload in such a frame.
pub fn len_prefixed(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Read a length-prefixed payload from a stream.
///
/// The wire format is a 4-byte big-endian length followed by that many bytes.
/// This is the inverse of [`len_prefixed`]. `max_len` protects against malicious
/// peers that claim an enormous payload size.
pub fn read_len_prefixed<R: Read>(
    stream: &mut R,
    max_len: usize,
) -> Result<Vec<u8>, ProtocolError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_len {
        return Err(ProtocolError::Protocol(format!(
            "length-prefixed payload length {} exceeds limit {}",
            len, max_len
        )));
    }
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data)?;
    Ok(data)
}

/// A persistent zlib decompressor for session-spanning streams.
///
/// The Zlib, ZRLE, and Tight encodings all let a server keep one zlib stream
/// open across rectangles (Tight keeps up to four). `SessionInflate` wraps a
/// single `flate2::Decompress` so all three decoders share one implementation
/// of "feed one chunk, recover the exact output". The reset policy stays with
/// the caller: Tight resets a stream when the control byte's reset bit is set,
/// Zlib/ZRLE reset when a fresh zlib header is detected ([`is_zlib_header`]).
pub struct SessionInflate {
    decompress: Decompress,
}

impl Default for SessionInflate {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionInflate {
    /// Create a session decompressor ready for the start of a zlib stream.
    pub fn new() -> Self {
        Self {
            decompress: Decompress::new(true),
        }
    }

    /// Reset the stream state, as if a new session had started.
    pub fn reset(&mut self) {
        self.decompress = Decompress::new(true);
    }

    /// Feed one chunk of the session stream and return its decompressed output.
    ///
    /// The whole chunk is consumed, including any trailing sync-flush bytes,
    /// and any output still buffered inside the decompressor is drained with
    /// empty input afterwards, so the stream stays aligned for the next chunk.
    ///
    /// The output must be at least `min_out` bytes (shorter is a protocol
    /// error; pass 0 when the caller performs its own length validation) and
    /// is capped at `max_out` bytes — exceeding the cap is treated as a
    /// decompression bomb and rejected.
    pub fn feed(
        &mut self,
        chunk: &[u8],
        min_out: usize,
        max_out: usize,
    ) -> Result<Vec<u8>, ProtocolError> {
        let mut output = Vec::with_capacity(min_out.max(chunk.len() * 4));
        let mut input_offset = 0;
        let mut iteration = 0;

        loop {
            iteration += 1;

            // Ensure we have spare capacity for the next pass.
            let spare = output.capacity() - output.len();
            if spare < 4096 {
                output.reserve(4096.max(min_out.saturating_sub(output.len())));
            }

            // total_in() is cumulative across the whole session, so track how
            // many bytes this call consumed instead of using it as an absolute
            // offset into the current chunk.
            let total_in_before = self.decompress.total_in();
            let status = self
                .decompress
                .decompress_vec(&chunk[input_offset..], &mut output, FlushDecompress::Sync)
                .map_err(|e| {
                    ProtocolError::Protocol(format!("zlib session decompress error: {}", e))
                })?;
            let consumed = (self.decompress.total_in() - total_in_before) as usize;
            input_offset += consumed;

            if output.len() > max_out {
                return Err(ProtocolError::Protocol(format!(
                    "decompressed size {} exceeds maximum {}",
                    output.len(),
                    max_out
                )));
            }

            if input_offset == chunk.len() {
                // Some zlib data may still be buffered inside the decompressor
                // after the last input chunk has been consumed. Keep flushing
                // with empty input until no more output is produced. This is
                // needed for continuous zlib streams (e.g. wayvnc), where the
                // stream boundary is not aligned with a deflate flush marker
                // and the stream does not end with this chunk.
                let mut prev_len = output.len();
                loop {
                    let spare = output.capacity() - output.len();
                    if spare < 4096 {
                        output.reserve(4096);
                    }
                    let _ = self
                        .decompress
                        .decompress_vec(&[], &mut output, FlushDecompress::Sync);
                    if output.len() > max_out {
                        return Err(ProtocolError::Protocol(format!(
                            "decompressed size {} exceeds maximum {}",
                            output.len(),
                            max_out
                        )));
                    }
                    if output.len() == prev_len {
                        break;
                    }
                    prev_len = output.len();
                }
                break;
            }

            if consumed == 0 && status == Status::Ok {
                // More output space is needed.
                continue;
            }

            if status == Status::StreamEnd {
                break;
            }

            let remaining = &chunk[input_offset..];
            log::error!(
                "zlib session decompress stall: iter={} total_in={}/{} consumed_this_iter={} \
                 status={:?} output_len={} min_out={} remaining_bytes={} \
                 remaining_hex={:02x?} compressed_prefix={:02x?} compressed_suffix={:02x?}",
                iteration,
                input_offset,
                chunk.len(),
                consumed,
                status,
                output.len(),
                min_out,
                remaining.len(),
                &remaining[..remaining.len().min(16)],
                &chunk[..chunk.len().min(16)],
                &chunk[chunk.len().saturating_sub(16)..]
            );
            return Err(ProtocolError::Protocol(format!(
                "zlib session decompress stalled: consumed {} of {} bytes, status {:?}",
                input_offset,
                chunk.len(),
                status
            )));
        }

        if output.len() < min_out {
            return Err(ProtocolError::Protocol(format!(
                "decompressed {} bytes, expected at least {}",
                output.len(),
                min_out
            )));
        }
        Ok(output)
    }
}

/// Decode a Zlib-encoded rectangle from the stream into the pixel sink.
///
/// The wire format per rectangle is a 4-byte big-endian length followed by
/// that many bytes of zlib-compressed raw pixels (in `pixel_format`). The zlib
/// stream may be reset per rectangle or maintained across the session; the
/// session is reset whenever a fresh zlib header is seen at the start of a
/// rectangle.
#[allow(clippy::too_many_arguments)]
pub fn decode<P: PixelSink, R: Read>(
    stream: &mut R,
    sink: &mut P,
    session: &mut SessionInflate,
    rect_x: usize,
    rect_y: usize,
    rect_w: usize,
    rect_h: usize,
    pixel_format: &PixelFormat,
) -> Result<(), ProtocolError> {
    let bpp = pixel_format.bytes_per_pixel();
    let total_size = rect_w * rect_h * bpp;

    let compressed = read_len_prefixed(stream, MAX_COMPRESSED_LEN)?;

    // Some servers reset the zlib stream per rectangle (fresh header).
    // Others keep a single stream for the whole session.
    if is_zlib_header(&compressed) {
        session.reset();
    }

    // The rectangle implies an exact output size; a small slack tolerates
    // servers that pad the stream, anything beyond is a decompression bomb.
    let data = session.feed(&compressed, 0, total_size + 64)?;

    write_converted_region(
        sink,
        rect_x,
        rect_y,
        rect_w,
        rect_h,
        &data,
        bpp,
        pixel_format,
    );
    Ok(())
}

/// Persistent Zlib encoder that maintains a single zlib stream per connection.
///
/// This is the encode-side counterpart of [`decode`]: each rectangle's raw
/// pixels (in the client's pixel format) are pushed through one long-lived
/// zlib stream, flushed to a sync point per rectangle, and framed with
/// [`len_prefixed`].
pub struct ZlibEncoder {
    encoder: FlateZlibEncoder<Vec<u8>>,
}

impl Default for ZlibEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ZlibEncoder {
    pub fn new() -> Self {
        Self {
            encoder: FlateZlibEncoder::new(Vec::new(), Compression::default()),
        }
    }

    /// Encode a region of framebuffer using Zlib compression.
    ///
    /// `src` is the full framebuffer in XRGB8888 format (4 bytes per pixel).
    /// `src_stride` is the number of bytes per row.
    /// `dst_format` is the client's requested pixel format.
    #[allow(clippy::too_many_arguments)]
    pub fn encode_rect(
        &mut self,
        src: &[u8],
        src_stride: usize,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        dst_format: &PixelFormat,
    ) -> FbRect {
        // Encode the raw pixels in the client's pixel format, then compress them
        // using the persistent zlib stream.
        let raw_rect = encode_raw(src, src_stride, x, y, width, height, dst_format);
        self.encoder.write_all(&raw_rect.data).unwrap();
        self.encoder.flush().unwrap();

        let compressed: Vec<u8> = self.encoder.get_mut().drain(..).collect();
        let data = len_prefixed(&compressed);

        FbRect {
            x,
            y,
            width,
            height,
            encoding: Encoding::Zlib,
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn len_prefixed_frame_layout() {
        let frame = len_prefixed(&[0xAA, 0xBB, 0xCC]);
        assert_eq!(frame, vec![0, 0, 0, 3, 0xAA, 0xBB, 0xCC]);
        assert_eq!(len_prefixed(&[]), vec![0, 0, 0, 0]);
    }

    #[test]
    fn read_len_prefixed_roundtrip() {
        let frame = len_prefixed(&[0xAA, 0xBB, 0xCC]);
        let decoded = read_len_prefixed(&mut Cursor::new(&frame), 1024).unwrap();
        assert_eq!(decoded, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn read_len_prefixed_empty_payload() {
        let frame = len_prefixed(&[]);
        let decoded = read_len_prefixed(&mut Cursor::new(&frame), 1024).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn read_len_prefixed_rejects_oversized_length() {
        let frame = len_prefixed(&[0xAA; 1024]);
        let err = read_len_prefixed(&mut Cursor::new(&frame), 512).unwrap_err();
        assert!(matches!(err, ProtocolError::Protocol(_)));
    }

    #[test]
    fn zlib_header_detection() {
        assert!(is_zlib_header(&[0x78, 0x9C]));
        assert!(is_zlib_header(&[0x78, 0x01]));
        assert!(!is_zlib_header(&[0x78, 0x9D])); // bad check bits
        assert!(!is_zlib_header(&[0x79, 0x9C])); // CM != 8
        assert!(!is_zlib_header(&[0x78])); // too short
        assert!(!is_zlib_header(&[]));
    }

    mod encoder {
        use super::*;
        use crate::pixel_sink::TestPixelSink;

        fn bgra32_framebuffer() -> (Vec<u8>, usize) {
            let width = 4;
            let height = 4;
            let stride = width * 4;
            let mut data = vec![0u8; stride * height];
            for y in 0..height {
                for x in 0..width {
                    let off = y * stride + x * 4;
                    data[off] = 0x12; // B
                    data[off + 1] = 0x34; // G
                    data[off + 2] = 0x56; // R
                    data[off + 3] = 0x00; // padding
                }
            }
            (data, stride)
        }

        #[test]
        fn test_zlib_rect_format() {
            let (fb, stride) = bgra32_framebuffer();
            let mut encoder = ZlibEncoder::new();
            let rect = encoder.encode_rect(&fb, stride, 0, 0, 4, 4, &PixelFormat::bgra32());

            assert_eq!(rect.encoding, Encoding::Zlib);
            assert_eq!(rect.width, 4);
            assert_eq!(rect.height, 4);
            // First 4 bytes are the compressed length prefix.
            let compressed_len =
                u32::from_be_bytes([rect.data[0], rect.data[1], rect.data[2], rect.data[3]])
                    as usize;
            assert_eq!(rect.data.len(), 4 + compressed_len);
            // Compressed payload must be non-empty and begin with a zlib header.
            let compressed = &rect.data[4..];
            assert!(!compressed.is_empty());
            assert!(compressed[0] == 0x78); // zlib header first byte
        }

        #[test]
        fn test_zlib_rect_roundtrip() {
            let (fb, stride) = bgra32_framebuffer();
            let mut encoder = ZlibEncoder::new();
            let rect = encoder.encode_rect(&fb, stride, 0, 0, 4, 4, &PixelFormat::bgra32());

            let compressed = &rect.data[4..];
            let mut decoder = flate2::read::ZlibDecoder::new(compressed);
            let mut decoded = Vec::new();
            decoder.read_to_end(&mut decoded).unwrap();

            // Raw data must match the source rectangle bytes.
            let raw_rect = encode_raw(&fb, stride, 0, 0, 4, 4, &PixelFormat::bgra32());
            assert_eq!(decoded, raw_rect.data);
        }

        #[test]
        fn test_zlib_session_stream_continues() {
            let (fb, stride) = bgra32_framebuffer();
            let mut encoder = ZlibEncoder::new();
            let rect1 = encoder.encode_rect(&fb, stride, 0, 0, 2, 2, &PixelFormat::bgra32());
            let rect2 = encoder.encode_rect(&fb, stride, 2, 2, 2, 2, &PixelFormat::bgra32());

            // Concatenate compressed payloads (skipping the 4-byte length prefixes) and
            // decode with a single session decompressor, matching how a VNC client handles
            // continuous Zlib encoding across rectangles.
            let mut compressed = Vec::new();
            compressed.extend_from_slice(&rect1.data[4..]);
            compressed.extend_from_slice(&rect2.data[4..]);

            let mut decompress = flate2::Decompress::new(true);
            let mut decoded = Vec::with_capacity(2 * 2 * 4 * 2);
            decompress
                .decompress_vec(&compressed, &mut decoded, FlushDecompress::Sync)
                .unwrap();

            let raw1 = encode_raw(&fb, stride, 0, 0, 2, 2, &PixelFormat::bgra32());
            let raw2 = encode_raw(&fb, stride, 2, 2, 2, 2, &PixelFormat::bgra32());
            assert_eq!(decoded.len(), raw1.data.len() + raw2.data.len());
            assert_eq!(&decoded[..raw1.data.len()], &raw1.data[..]);
            assert_eq!(&decoded[raw1.data.len()..], &raw2.data[..]);
        }

        /// Encode two frames with one `ZlibEncoder` and decode them through
        /// [`decode`] with one `SessionInflate`: the persistent compressor and
        /// the persistent decompressor must stay in sync across rectangles.
        #[test]
        fn encoder_decoder_roundtrip_across_frames() {
            let fmt = PixelFormat::bgra32();
            let (fb1, stride1) = bgra32_framebuffer();
            // Second frame with different pixels.
            let (mut fb2, stride2) = bgra32_framebuffer();
            for px in fb2.chunks_exact_mut(4) {
                px[0] = 0xAA;
                px[1] = 0xBB;
                px[2] = 0xCC;
            }

            let mut encoder = ZlibEncoder::new();
            let rect1 = encoder.encode_rect(&fb1, stride1, 0, 0, 4, 4, &fmt);
            let rect2 = encoder.encode_rect(&fb2, stride2, 0, 0, 4, 4, &fmt);

            let mut sink = TestPixelSink::new(4, 4);
            let mut session = SessionInflate::new();
            for rect in [&rect1, &rect2] {
                decode(
                    &mut Cursor::new(&rect.data),
                    &mut sink,
                    &mut session,
                    0,
                    0,
                    4,
                    4,
                    &fmt,
                )
                .unwrap();
            }

            // The sink holds the second frame: BGRA source [0xAA, 0xBB, 0xCC]
            // decodes to RGBA [0xCC, 0xBB, 0xAA, 0xFF].
            assert_eq!(
                sink.pixel(0, 0),
                Some(&[0xCC, 0xBB, 0xAA, 0xFF]),
                "second frame must decode over the continuing session stream"
            );
            assert_eq!(sink.pixel(3, 3), Some(&[0xCC, 0xBB, 0xAA, 0xFF]));

            // And the first frame alone decodes to its own pixels.
            let mut sink1 = TestPixelSink::new(4, 4);
            let mut session1 = SessionInflate::new();
            decode(
                &mut Cursor::new(&rect1.data),
                &mut sink1,
                &mut session1,
                0,
                0,
                4,
                4,
                &fmt,
            )
            .unwrap();
            assert_eq!(sink1.pixel(2, 1), Some(&[0x56, 0x34, 0x12, 0xFF]));
        }
    }

    mod session_inflate {
        use super::*;
        use crate::pixel_sink::TestPixelSink;
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;

        /// Compress `chunks` into a single continuous zlib stream, returning
        /// the per-chunk wire bytes (each boundary is a sync flush; the stream
        /// is left open, as in a real Zlib/ZRLE session).
        fn session_chunks(chunks: &[&[u8]]) -> Vec<Vec<u8>> {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            let mut out = Vec::new();
            let mut written = 0;
            for chunk in chunks {
                encoder.write_all(chunk).unwrap();
                encoder.flush().unwrap();
                let all = encoder.get_ref();
                out.push(all[written..].to_vec());
                written = all.len();
            }
            out
        }

        #[test]
        fn feed_decodes_consecutive_chunks_of_one_stream() {
            let raw1 = vec![0xaau8; 16];
            let raw2 = vec![0xbbu8; 8];
            let chunks = session_chunks(&[&raw1, &raw2]);
            assert!(!chunks[1].is_empty());

            let mut session = SessionInflate::new();
            assert_eq!(session.feed(&chunks[0], 0, 1024).unwrap(), raw1);
            assert_eq!(session.feed(&chunks[1], 0, 1024).unwrap(), raw2);
        }

        /// Regression test: feeding a second chunk must not slice past the end
        /// of that chunk's compressed data (`Decompress::total_in` is
        /// cumulative across the session, not an offset into the current
        /// chunk). A `total_in`-as-offset bug only shows up when the second
        /// chunk is shorter than the first chunk's compressed size.
        #[test]
        fn feed_second_chunk_is_not_misaligned_by_cumulative_total_in() {
            // First chunk compresses to more bytes than the second chunk has
            // in total, so indexing the second chunk by `total_in` would read
            // out of bounds or skip data.
            let raw1 = vec![0x01u8; 4096];
            let raw2 = vec![0x02u8; 3];
            let chunks = session_chunks(&[&raw1, &raw2]);
            assert!(chunks[0].len() > chunks[1].len());

            let mut session = SessionInflate::new();
            assert_eq!(session.feed(&chunks[0], 0, 8192).unwrap(), raw1);
            assert_eq!(session.feed(&chunks[1], 0, 8192).unwrap(), raw2);
        }

        #[test]
        fn feed_errors_when_min_out_not_met() {
            let chunks = session_chunks(&[&[0xaau8; 4]]);
            let mut session = SessionInflate::new();
            let err = session.feed(&chunks[0], 16, 1024).unwrap_err();
            assert!(matches!(err, ProtocolError::Protocol(_)));
        }

        #[test]
        fn feed_rejects_output_beyond_max_out() {
            let bomb = vec![0u8; 100_000];
            let chunks = session_chunks(&[&bomb]);
            let mut session = SessionInflate::new();
            let err = session.feed(&chunks[0], 0, 1024).unwrap_err();
            assert!(matches!(err, ProtocolError::Protocol(_)));
        }

        #[test]
        fn feed_rejects_garbage() {
            let mut session = SessionInflate::new();
            assert!(session.feed(&[0xde, 0xad, 0xbe, 0xef], 0, 1024).is_err());
        }

        #[test]
        fn reset_allows_reuse_with_a_fresh_stream() {
            let raw1 = vec![0xaau8; 32];
            let raw2 = vec![0xbbu8; 32];

            // Two independent, self-contained streams.
            let mut enc1 = ZlibEncoder::new(Vec::new(), Compression::default());
            enc1.write_all(&raw1).unwrap();
            let comp1 = enc1.finish().unwrap();
            let mut enc2 = ZlibEncoder::new(Vec::new(), Compression::default());
            enc2.write_all(&raw2).unwrap();
            let comp2 = enc2.finish().unwrap();

            let mut session = SessionInflate::new();
            assert_eq!(session.feed(&comp1, 32, 1024).unwrap(), raw1);
            // Feeding a fresh stream without reset cannot decode it: the old
            // stream state is still in place (flate2 may report this as an
            // error or as a stalled/ended stream producing no output).
            assert!(session.feed(&comp2, 32, 1024).is_err());
            session.reset();
            assert_eq!(session.feed(&comp2, 32, 1024).unwrap(), raw2);
        }

        #[test]
        fn decode_fresh_stream_per_rectangle() {
            // 2x2 RGBA pixels, compressed as a self-contained stream.
            let raw = vec![
                0xff, 0x00, 0x00, 0xff, // red
                0x00, 0xff, 0x00, 0xff, // green
                0x00, 0x00, 0xff, 0xff, // blue
                0xff, 0xff, 0xff, 0xff, // white
            ];
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&raw).unwrap();
            let frame = len_prefixed(&encoder.finish().unwrap());

            let mut sink = TestPixelSink::new(2, 2);
            let mut session = SessionInflate::new();
            decode(
                &mut Cursor::new(&frame),
                &mut sink,
                &mut session,
                0,
                0,
                2,
                2,
                &PixelFormat::rgba32(),
            )
            .unwrap();
            assert_eq!(sink.pixels, raw);
        }

        #[test]
        fn decode_session_stream_across_rectangles() {
            // RealVNC-style: one zlib stream for the whole session; the second
            // rectangle's chunk has no zlib header, so the session must not be
            // reset.
            let raw1 = vec![0x11u8; 16]; // 2x2 RGBA
            let raw2 = vec![0x22u8; 16];
            let chunks = session_chunks(&[&raw1, &raw2]);
            assert!(!is_zlib_header(&chunks[1]));

            let mut sink = TestPixelSink::new(4, 2);
            let mut session = SessionInflate::new();
            for (i, chunk) in chunks.iter().enumerate() {
                decode(
                    &mut Cursor::new(&len_prefixed(chunk)),
                    &mut sink,
                    &mut session,
                    i * 2,
                    0,
                    2,
                    2,
                    &PixelFormat::rgba32(),
                )
                .unwrap();
            }
            assert_eq!(&sink.pixels[0..8], &raw1[0..8]);
            assert_eq!(&sink.pixels[8..16], &raw2[0..8]);
            assert_eq!(&sink.pixels[16..24], &raw1[8..16]);
            assert_eq!(&sink.pixels[24..32], &raw2[8..16]);
        }

        #[test]
        fn decode_rejects_decompression_bomb() {
            let bomb = vec![0u8; 100_000];
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&bomb).unwrap();
            let frame = len_prefixed(&encoder.finish().unwrap());

            let mut sink = TestPixelSink::new(2, 2);
            let mut session = SessionInflate::new();
            let err = decode(
                &mut Cursor::new(&frame),
                &mut sink,
                &mut session,
                0,
                0,
                2,
                2,
                &PixelFormat::rgba32(),
            )
            .unwrap_err();
            assert!(matches!(err, ProtocolError::Protocol(_)));
        }
    }
}
