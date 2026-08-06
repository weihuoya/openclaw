use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

use crate::ProtocolError;

/// Convert one XRGB8888 little-endian pixel (`[B, G, R, X]`) to RGBA8888.
///
/// XRGB8888 is the native capture format of the wlr-screencopy-based server;
/// the encoders run this conversion before writing pixels in the client's
/// negotiated [`PixelFormat`].
pub fn xrgb_to_rgba(pixel: &[u8]) -> [u8; 4] {
    [pixel[2], pixel[1], pixel[0], 0xff]
}

/// RFB pixel format descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PixelFormat {
    pub bits_per_pixel: u8,
    pub depth: u8,
    pub big_endian: bool,
    pub true_colour: bool,
    pub red_max: u16,
    pub green_max: u16,
    pub blue_max: u16,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

impl Default for PixelFormat {
    fn default() -> Self {
        Self::rgba32()
    }
}

impl PixelFormat {
    /// Parse a pixel format from the 16-byte RFB wire descriptor.
    ///
    /// The descriptor is validated (see [`PixelFormat::validate`]); invalid
    /// formats are rejected with a [`ProtocolError::Protocol`] error instead
    /// of causing panics or overflows later during pixel conversion.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 16 {
            return Err(ProtocolError::Protocol(
                "Pixel format data too short".to_string(),
            ));
        }

        let format = Self {
            bits_per_pixel: data[0],
            depth: data[1],
            big_endian: data[2] != 0,
            true_colour: data[3] != 0,
            red_max: u16::from_be_bytes([data[4], data[5]]),
            green_max: u16::from_be_bytes([data[6], data[7]]),
            blue_max: u16::from_be_bytes([data[8], data[9]]),
            red_shift: data[10],
            green_shift: data[11],
            blue_shift: data[12],
        };
        format.validate()?;
        Ok(format)
    }

    /// Validate structural invariants of a peer-supplied pixel format.
    ///
    /// Rejects formats that would overflow or panic during pixel conversion:
    /// - `bits_per_pixel` must be 8, 16, or 32 (the values RFC 6143 §7.4
    ///   defines and the only ones the codecs in this workspace support);
    /// - `depth` must not exceed `bits_per_pixel`;
    /// - for true-colour formats each channel must fit inside a pixel:
    ///   `shift + bits(max) <= bits_per_pixel` and `shift < 32`, so the
    ///   `pixel >> shift` in [`PixelFormat::to_rgba`] is always well defined.
    ///
    /// Non-true-colour (colour-mapped) formats skip the channel checks; the
    /// max/shift fields are unused for those.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        let invalid = |msg: String| ProtocolError::Protocol(msg);

        if !matches!(self.bits_per_pixel, 8 | 16 | 32) {
            return Err(invalid(format!(
                "Unsupported bits-per-pixel: {} (expected 8, 16 or 32)",
                self.bits_per_pixel
            )));
        }
        if self.depth > self.bits_per_pixel {
            return Err(invalid(format!(
                "Pixel format depth {} exceeds bits-per-pixel {}",
                self.depth, self.bits_per_pixel
            )));
        }

        if self.true_colour {
            for (name, max, shift) in [
                ("red", self.red_max, self.red_shift),
                ("green", self.green_max, self.green_shift),
                ("blue", self.blue_max, self.blue_shift),
            ] {
                // Number of significant bits in `max` (0 for max == 0).
                let max_bits = u16::BITS - max.leading_zeros();
                if shift as u32 >= 32 || shift as u32 + max_bits > self.bits_per_pixel as u32 {
                    return Err(invalid(format!(
                        "Pixel format {} channel does not fit in {} bpp: max={} shift={}",
                        name, self.bits_per_pixel, max, shift
                    )));
                }
            }
        }
        Ok(())
    }

    /// Write the pixel format into a 16-byte buffer.
    ///
    /// The caller must ensure the buffer is at least 16 bytes and that the
    /// padding bytes (13..16) are already zero if desired.
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0] = self.bits_per_pixel;
        buf[1] = self.depth;
        buf[2] = if self.big_endian { 1 } else { 0 };
        buf[3] = if self.true_colour { 1 } else { 0 };
        buf[4..6].copy_from_slice(&self.red_max.to_be_bytes());
        buf[6..8].copy_from_slice(&self.green_max.to_be_bytes());
        buf[8..10].copy_from_slice(&self.blue_max.to_be_bytes());
        buf[10] = self.red_shift;
        buf[11] = self.green_shift;
        buf[12] = self.blue_shift;
        // buf[13..16] padding - caller must ensure zeros
    }

    /// Read a pixel format from a byte stream.
    ///
    /// Consumes the full 16-byte wire descriptor, including the 3 padding
    /// bytes, so the stream stays aligned for whatever follows. The format is
    /// validated (see [`PixelFormat::validate`]).
    pub fn read<R: Read>(r: &mut R) -> Result<Self, ProtocolError> {
        let format = Self {
            bits_per_pixel: r.read_u8()?,
            depth: r.read_u8()?,
            big_endian: r.read_u8()? != 0,
            true_colour: r.read_u8()? != 0,
            red_max: r.read_u16::<BigEndian>()?,
            green_max: r.read_u16::<BigEndian>()?,
            blue_max: r.read_u16::<BigEndian>()?,
            red_shift: r.read_u8()?,
            green_shift: r.read_u8()?,
            blue_shift: r.read_u8()?,
        };
        let mut padding = [0u8; 3];
        r.read_exact(&mut padding)?;
        format.validate()?;
        Ok(format)
    }

    /// Write a pixel format to a byte stream, including the 3-byte padding.
    pub fn write<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_u8(self.bits_per_pixel)?;
        w.write_u8(self.depth)?;
        w.write_u8(self.big_endian as u8)?;
        w.write_u8(self.true_colour as u8)?;
        w.write_u16::<BigEndian>(self.red_max)?;
        w.write_u16::<BigEndian>(self.green_max)?;
        w.write_u16::<BigEndian>(self.blue_max)?;
        w.write_u8(self.red_shift)?;
        w.write_u8(self.green_shift)?;
        w.write_u8(self.blue_shift)?;
        w.write_all(&[0; 3])?; // padding
        Ok(())
    }

    /// 32-bit little-endian RGBA.
    pub fn rgba32() -> Self {
        Self {
            bits_per_pixel: 32,
            depth: 24,
            big_endian: false,
            true_colour: true,
            red_max: 255,
            green_max: 255,
            blue_max: 255,
            red_shift: 0,
            green_shift: 8,
            blue_shift: 16,
        }
    }

    /// 32-bit little-endian BGRA (common VNC server default, also known as
    /// XRGB8888 little-endian on the wire).
    pub fn bgra32() -> Self {
        Self {
            bits_per_pixel: 32,
            depth: 24,
            big_endian: false,
            true_colour: true,
            red_max: 255,
            green_max: 255,
            blue_max: 255,
            red_shift: 16,
            green_shift: 8,
            blue_shift: 0,
        }
    }

    /// 16-bit RGB565 little-endian.
    pub fn rgb16() -> Self {
        Self {
            bits_per_pixel: 16,
            depth: 16,
            big_endian: false,
            true_colour: true,
            red_max: 31,
            green_max: 63,
            blue_max: 31,
            red_shift: 11,
            green_shift: 5,
            blue_shift: 0,
        }
    }

    pub fn bytes_per_pixel(&self) -> usize {
        (self.bits_per_pixel as usize).div_ceil(8)
    }

    /// Number of bytes in a colour pixel (CPIXEL) as used by ZRLE/TRLE/Tight
    /// encodings. For 32-bit formats, only the colour bytes are sent when the
    /// depth is 24 or less, so CPIXEL is 3 bytes; otherwise 4 bytes.
    pub fn bytes_per_cpixel(&self) -> usize {
        match self.bits_per_pixel {
            8 => 1,
            16 => 2,
            32 => {
                if self.depth <= 24 {
                    3
                } else {
                    4
                }
            }
            _ => self.bytes_per_pixel(),
        }
    }

    /// Convert a pixel from this format to RGBA8888 (little-endian: 0xAABBGGRR in memory).
    /// `src` must contain the pixel bytes in either the wire format (CPIXEL) or the full
    /// framebuffer format (PIXEL). Commonly this is 1, 2, 3, or 4 bytes.
    pub fn to_rgba(&self, src: &[u8]) -> [u8; 4] {
        let pixel = if self.big_endian {
            match src.len() {
                1 => src[0] as u32,
                2 => u16::from_be_bytes([src[0], src[1]]) as u32,
                3 => u32::from_be_bytes([0, src[0], src[1], src[2]]),
                4 => u32::from_be_bytes([src[0], src[1], src[2], src[3]]),
                _ => 0,
            }
        } else {
            match src.len() {
                1 => src[0] as u32,
                2 => u16::from_le_bytes([src[0], src[1]]) as u32,
                3 => u32::from_le_bytes([src[0], src[1], src[2], 0]),
                4 => u32::from_le_bytes([src[0], src[1], src[2], src[3]]),
                _ => 0,
            }
        };

        // Extract one colour channel. All intermediate math is done in u32:
        // `v * 255` with u16 operands overflows whenever max > 257, and a
        // peer-controlled shift >= 32 would panic a plain `>>` in debug
        // builds (invalid formats are rejected at parse time, but a
        // manually constructed `PixelFormat` can still reach here).
        let channel = |shift: u8, max: u16| -> u8 {
            if max == 0 {
                return 0;
            }
            let v = pixel.checked_shr(shift as u32).unwrap_or(0) & max as u32;
            ((v * 255 + max as u32 / 2) / max as u32) as u8
        };

        let r = channel(self.red_shift, self.red_max);
        let g = channel(self.green_shift, self.green_max);
        let b = channel(self.blue_shift, self.blue_max);

        [r, g, b, 0xff]
    }

    /// Convert an RGBA8888 pixel to a pixel value in this format: channels
    /// scaled to the format's maxima and shifted into place. The alpha byte
    /// is ignored (RFB pixel formats carry no alpha).
    ///
    /// This is the inverse of [`PixelFormat::to_rgba`], up to quantization:
    /// channels that do not fit exactly are rounded to the nearest
    /// representable value.
    pub fn from_rgba(&self, rgba: [u8; 4]) -> u32 {
        let scale = |v: u8, max: u16| -> u32 {
            if max > 0 {
                (v as u32 * max as u32 + 127) / 255
            } else {
                0
            }
        };
        (scale(rgba[0], self.red_max) << self.red_shift)
            | (scale(rgba[1], self.green_max) << self.green_shift)
            | (scale(rgba[2], self.blue_max) << self.blue_shift)
    }

    /// Convert an RGBA8888 pixel and append it in this format as a full PIXEL.
    pub fn write_pixel(&self, out: &mut Vec<u8>, rgba: [u8; 4]) {
        self.write_pixel_value(out, self.from_rgba(rgba));
    }

    /// Append a pixel value (already computed for this format, e.g. via
    /// [`PixelFormat::from_rgba`]) as a full PIXEL: `bits_per_pixel / 8` bytes
    /// in the negotiated endianness.
    pub fn write_pixel_value(&self, out: &mut Vec<u8>, value: u32) {
        match self.bits_per_pixel {
            8 => out.push(value as u8),
            16 => {
                if self.big_endian {
                    out.extend_from_slice(&(value as u16).to_be_bytes());
                } else {
                    out.extend_from_slice(&(value as u16).to_le_bytes());
                }
            }
            32 => {
                // For depth 32 the fourth byte is padding; write it as 0xff.
                // For 24-bit truecolour the four bytes contain the three
                // colour components in their shifted positions plus one
                // padding byte; write the full 32-bit value so the padding
                // lands in the unused byte for this endianness.
                let value = if self.depth > 24 {
                    value | (0xff << 24)
                } else {
                    value
                };
                if self.big_endian {
                    out.extend_from_slice(&value.to_be_bytes());
                } else {
                    out.extend_from_slice(&value.to_le_bytes());
                }
            }
            _ => {
                log::warn!(
                    "Unsupported bits_per_pixel {} for pixel conversion",
                    self.bits_per_pixel
                );
                // Fallback: write the value as 4 little-endian bytes (the peer
                // may not decode it correctly).
                out.extend_from_slice(&value.to_le_bytes());
            }
        }
    }

    /// Append a pixel value as a CPIXEL.
    ///
    /// For 32-bit formats with depth 24 or less, a CPIXEL is only 3 bytes
    /// long: the least significant 3 bytes of the pixel value, unless the
    /// colour bits only fit in the most significant 3 bytes. Otherwise a
    /// CPIXEL is a full PIXEL in this format.
    pub fn write_cpixel(&self, out: &mut Vec<u8>, value: u32) {
        let cpb = self.bytes_per_cpixel();
        let bytes = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };

        if self.bits_per_pixel == 32 && cpb == 3 {
            let min_shift = self.red_shift.min(self.green_shift).min(self.blue_shift);
            if min_shift >= 8 {
                // The colour bits live in the most significant 3 bytes.
                if self.big_endian {
                    out.extend_from_slice(&bytes[0..3]);
                } else {
                    out.extend_from_slice(&bytes[1..4]);
                }
            } else if self.big_endian {
                out.extend_from_slice(&bytes[1..4]);
            } else {
                out.extend_from_slice(&bytes[0..3]);
            }
        } else if self.big_endian {
            out.extend_from_slice(&bytes[4 - cpb..]);
        } else {
            out.extend_from_slice(&bytes[..cpb]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire_bytes(pf: &PixelFormat) -> Vec<u8> {
        let mut buf = vec![0u8; 16];
        pf.write_to(&mut buf);
        buf
    }

    #[test]
    fn from_bytes_accepts_standard_formats() {
        for pf in [
            PixelFormat::rgba32(),
            PixelFormat::bgra32(),
            PixelFormat::rgb16(),
        ] {
            let parsed = PixelFormat::from_bytes(&wire_bytes(&pf)).unwrap();
            assert_eq!(parsed, pf);
        }
    }

    #[test]
    fn from_bytes_rejects_unsupported_bits_per_pixel() {
        let mut pf = PixelFormat::rgba32();
        pf.bits_per_pixel = 24;
        assert!(PixelFormat::from_bytes(&wire_bytes(&pf)).is_err());
        pf.bits_per_pixel = 0;
        assert!(PixelFormat::from_bytes(&wire_bytes(&pf)).is_err());
    }

    #[test]
    fn from_bytes_rejects_depth_over_bpp() {
        let mut pf = PixelFormat::rgb16();
        pf.depth = 24;
        assert!(PixelFormat::from_bytes(&wire_bytes(&pf)).is_err());
    }

    #[test]
    fn from_bytes_rejects_channel_overflow() {
        // 8-bit channel at shift 16 does not fit in 16 bpp (16 + 8 > 16).
        let mut pf = PixelFormat::rgb16();
        pf.red_max = 255;
        pf.red_shift = 16;
        assert!(PixelFormat::from_bytes(&wire_bytes(&pf)).is_err());

        // Shift beyond the pixel width entirely.
        let mut pf = PixelFormat::rgba32();
        pf.green_shift = 32;
        assert!(PixelFormat::from_bytes(&wire_bytes(&pf)).is_err());

        let mut pf = PixelFormat::rgba32();
        pf.blue_shift = 200;
        assert!(PixelFormat::from_bytes(&wire_bytes(&pf)).is_err());
    }

    #[test]
    fn read_consumes_padding_bytes() {
        let mut wire = wire_bytes(&PixelFormat::rgba32());
        wire.extend_from_slice(&[0xAA, 0xBB]); // trailing bytes after the descriptor
        let mut cursor = std::io::Cursor::new(&wire);
        let pf = PixelFormat::read(&mut cursor).unwrap();
        assert_eq!(pf, PixelFormat::rgba32());
        // 16 bytes consumed (13 fields + 3 padding); trailing bytes remain.
        assert_eq!(cursor.position(), 16);
    }

    #[test]
    fn to_rgba_large_max_does_not_overflow() {
        // 16-bit channels inside a 32-bit pixel: max = 65535 is a valid
        // format (16 bits at shift 0). v * 255 would overflow u16 math.
        let pf = PixelFormat {
            bits_per_pixel: 32,
            depth: 32,
            big_endian: false,
            true_colour: true,
            red_max: 65535,
            green_max: 0,
            blue_max: 0,
            red_shift: 0,
            green_shift: 0,
            blue_shift: 0,
        };
        assert_eq!(pf.to_rgba(&0xffffu32.to_le_bytes())[0], 255);
        assert_eq!(pf.to_rgba(&0x8000u32.to_le_bytes())[0], 128);
    }

    #[test]
    fn to_rgba_max_zero_and_huge_shift_do_not_panic() {
        // Fields are pub, so an invalid format can be constructed directly;
        // conversion must still not panic.
        let pf = PixelFormat {
            bits_per_pixel: 32,
            depth: 24,
            big_endian: false,
            true_colour: true,
            red_max: 0,
            green_max: 255,
            blue_max: 255,
            red_shift: 40, // >= 32: would panic a plain u32 >>
            green_shift: 8,
            blue_shift: 16,
        };
        let rgba = pf.to_rgba(&[0xff, 0xff, 0xff, 0xff]);
        assert_eq!(rgba[0], 0); // max == 0 -> channel is 0
        assert_eq!(rgba[1], 255);
        assert_eq!(rgba[2], 255);
        assert_eq!(rgba[3], 0xff);
    }

    #[test]
    fn to_rgba_rgb16_matches_known_values() {
        let pf = PixelFormat::rgb16();
        // Pure red in RGB565 little-endian.
        let rgba = pf.to_rgba(&0xf800u16.to_le_bytes());
        assert_eq!(rgba, [255, 0, 0, 0xff]);
        // Pure green.
        let rgba = pf.to_rgba(&0x07e0u16.to_le_bytes());
        assert_eq!(rgba, [0, 255, 0, 0xff]);
    }

    /// RGB332 8-bit truecolour format.
    fn rgb8() -> PixelFormat {
        PixelFormat {
            bits_per_pixel: 8,
            depth: 8,
            big_endian: false,
            true_colour: true,
            red_max: 7,
            green_max: 7,
            blue_max: 3,
            red_shift: 5,
            green_shift: 2,
            blue_shift: 0,
        }
    }

    /// 32-bit depth-24 format whose colour bits live in the most significant
    /// three bytes (min shift 8), little-endian.
    fn xbgr32_min_shift_8() -> PixelFormat {
        PixelFormat {
            bits_per_pixel: 32,
            depth: 24,
            big_endian: false,
            true_colour: true,
            red_max: 255,
            green_max: 255,
            blue_max: 255,
            red_shift: 24,
            green_shift: 16,
            blue_shift: 8,
        }
    }

    /// 32-bit depth-32 big-endian format.
    fn be32_depth32() -> PixelFormat {
        PixelFormat {
            bits_per_pixel: 32,
            depth: 32,
            big_endian: true,
            true_colour: true,
            red_max: 255,
            green_max: 255,
            blue_max: 255,
            red_shift: 16,
            green_shift: 8,
            blue_shift: 0,
        }
    }

    /// 16-bit big-endian RGB565.
    fn rgb16_be() -> PixelFormat {
        PixelFormat {
            big_endian: true,
            ..PixelFormat::rgb16()
        }
    }

    /// Write `rgba` as a full PIXEL and read it back.
    fn pixel_roundtrip(pf: &PixelFormat, rgba: [u8; 4]) -> [u8; 4] {
        let mut out = Vec::new();
        pf.write_pixel(&mut out, rgba);
        assert_eq!(out.len(), pf.bytes_per_pixel());
        pf.to_rgba(&out)
    }

    #[test]
    fn write_pixel_roundtrips_exact_colors() {
        // Full-saturation colors survive every format exactly (each channel
        // maps to 0 or its max). Alpha is always opaque: RFB pixels carry no
        // alpha and to_rgba reports 0xff.
        let colors = [
            [0x00, 0x00, 0x00, 0xff],
            [0xff, 0x00, 0x00, 0xff],
            [0x00, 0xff, 0x00, 0xff],
            [0x00, 0x00, 0xff, 0xff],
            [0xff, 0xff, 0xff, 0xff],
        ];
        for pf in [
            PixelFormat::rgba32(),
            PixelFormat::bgra32(),
            PixelFormat::rgb16(),
            rgb16_be(),
            rgb8(),
            be32_depth32(),
        ] {
            for c in colors {
                assert_eq!(pixel_roundtrip(&pf, c), c, "format {:?} color {:?}", pf, c);
            }
        }
    }

    #[test]
    fn write_pixel_roundtrips_lossless_formats() {
        // 8-bit-channel formats are fully lossless for arbitrary colors.
        let colors = [
            [0x12, 0x34, 0x56, 0xff],
            [0xab, 0xcd, 0xef, 0xff],
            [0x01, 0xfe, 0x80, 0xff],
        ];
        for pf in [PixelFormat::rgba32(), PixelFormat::bgra32()] {
            for c in colors {
                assert_eq!(pixel_roundtrip(&pf, c), c, "format {:?} color {:?}", pf, c);
            }
        }
    }

    #[test]
    fn write_pixel_quantized_formats_are_idempotent() {
        // Lossy formats: writing the quantized color again must reproduce the
        // same wire bytes (write -> read -> write is a fixed point).
        let colors = [
            [0x12, 0x34, 0x56, 0xff],
            [0x80, 0x80, 0x80, 0xff],
            [0xff, 0x7f, 0x01, 0xff],
        ];
        for pf in [PixelFormat::rgb16(), rgb16_be(), rgb8()] {
            for c in colors {
                let once = pixel_roundtrip(&pf, c);
                let twice = pixel_roundtrip(&pf, once);
                assert_eq!(once, twice, "format {:?} color {:?}", pf, c);
            }
        }
    }

    #[test]
    fn from_rgba_scales_channels() {
        // RGB565: R=30 -> 4, G=20 -> 5, B=10 -> 1 (rounded);
        // value = (4 << 11) | (5 << 5) | 1 = 0x20A1.
        let pf = PixelFormat::rgb16();
        assert_eq!(pf.from_rgba([30, 20, 10, 0xff]), 0x20A1);
        // Max 0 channels always produce 0.
        let pf = PixelFormat {
            red_max: 0,
            ..PixelFormat::rgba32()
        };
        assert_eq!(
            pf.from_rgba([0xff, 0x80, 0x01, 0xff]),
            (0x80 << 8) | (0x01 << 16)
        );
    }

    #[test]
    fn write_pixel_value_depth32_sets_opaque_padding() {
        let pf = be32_depth32();
        let mut out = Vec::new();
        pf.write_pixel(&mut out, [0x12, 0x34, 0x56, 0xff]);
        // Big-endian: 0xff padding first, then R, G, B.
        assert_eq!(out, vec![0xff, 0x12, 0x34, 0x56]);
    }

    #[test]
    fn write_cpixel_roundtrips() {
        // CPIXEL write -> to_rgba round trip for the common CPIXEL shapes:
        // 3-byte little-endian (32bpp depth 24), 2-byte little- and
        // big-endian (16bpp), 1-byte (8bpp).
        let colors = [
            [0x00, 0x00, 0x00, 0xff],
            [0xff, 0x00, 0x00, 0xff],
            [0x00, 0xff, 0x00, 0xff],
            [0xff, 0xff, 0xff, 0xff],
        ];
        for pf in [
            PixelFormat::rgba32(),
            PixelFormat::bgra32(),
            PixelFormat::rgb16(),
            rgb16_be(),
            rgb8(),
        ] {
            for c in colors {
                let mut out = Vec::new();
                pf.write_cpixel(&mut out, pf.from_rgba(c));
                assert_eq!(out.len(), pf.bytes_per_cpixel());
                assert_eq!(pf.to_rgba(&out), c, "format {:?} color {:?}", pf, c);
            }
        }
    }

    #[test]
    fn write_cpixel_truncation_cases() {
        // 32bpp depth 24 little-endian, min shift < 8: the least significant
        // 3 bytes. bgra32 value for [R,G,B] = R<<16|G<<8|B -> LE [B, G, R].
        let pf = PixelFormat::bgra32();
        let mut out = Vec::new();
        pf.write_cpixel(&mut out, pf.from_rgba([0x12, 0x34, 0x56, 0xff]));
        assert_eq!(out, vec![0x56, 0x34, 0x12]);

        // 32bpp depth 24 little-endian, min shift >= 8: the most significant
        // 3 bytes. Value = R<<24|G<<16|B<<8 -> LE bytes [0, B, G, R],
        // written as bytes[1..4] = [B, G, R].
        let pf = xbgr32_min_shift_8();
        let mut out = Vec::new();
        pf.write_cpixel(&mut out, pf.from_rgba([0x12, 0x34, 0x56, 0xff]));
        assert_eq!(out, vec![0x56, 0x34, 0x12]);

        // 32bpp depth 24 big-endian, min shift < 8: BE bytes of
        // R<<16|G<<8|B are [0, R, G, B], written as bytes[1..4].
        let pf = PixelFormat {
            big_endian: true,
            red_shift: 16,
            green_shift: 8,
            blue_shift: 0,
            ..PixelFormat::bgra32()
        };
        let mut out = Vec::new();
        pf.write_cpixel(&mut out, pf.from_rgba([0x12, 0x34, 0x56, 0xff]));
        assert_eq!(out, vec![0x12, 0x34, 0x56]);

        // 32bpp depth 24 big-endian, min shift >= 8: BE bytes of
        // R<<24|G<<16|B<<8 are [R, G, B, 0], written as bytes[0..3].
        let pf = PixelFormat {
            big_endian: true,
            red_shift: 24,
            green_shift: 16,
            blue_shift: 8,
            ..PixelFormat::bgra32()
        };
        let mut out = Vec::new();
        pf.write_cpixel(&mut out, pf.from_rgba([0x12, 0x34, 0x56, 0xff]));
        assert_eq!(out, vec![0x12, 0x34, 0x56]);

        // Depth 32: CPIXEL is a full 4-byte PIXEL, written from the value
        // as-is (unlike write_pixel_value, no opaque padding is forced).
        let pf = be32_depth32();
        let mut out = Vec::new();
        pf.write_cpixel(&mut out, pf.from_rgba([0x12, 0x34, 0x56, 0xff]));
        assert_eq!(out, vec![0x00, 0x12, 0x34, 0x56]);
    }
}
