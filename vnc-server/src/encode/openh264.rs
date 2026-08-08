//! OpenH264 encoding (encoding type 50).
//!
//! Uses the Cisco OpenH264 library (via the `openh264` crate) to encode
//! framebuffer regions as H.264 video. This is useful for low-bandwidth
//! scenarios where software-encoded H.264 provides better compression than
//! traditional VNC encodings.
//!
//! The encoded data is sent as a single rectangle with encoding type 50
//! (OpenH264). The payload is a raw H.264 bitstream (Annex B format,
//! with start codes) that the client must decode.

use log::warn;
use vnc_protocol::encoding::Encoding;
use vnc_protocol::pixel_format::PixelFormat;
use vnc_protocol::rect::FbRect;

/// OpenH264 encoder wrapper.
///
/// Encapsulates the openh264 encoder and manages YUV conversion state.
pub struct OpenH264Encoder {
    width: u32,
    height: u32,
    #[cfg(feature = "openh264")]
    encoder: Option<openh264::encoder::Encoder>,
    #[cfg(feature = "openh264")]
    yuv_buffer: Vec<u8>,
}

impl OpenH264Encoder {
    /// Create a new OpenH264 encoder for the given dimensions.
    ///
    /// Returns `None` if the openh264 feature is disabled or encoder creation fails.
    pub fn new(width: u32, height: u32) -> Option<Self> {
        #[cfg(feature = "openh264")]
        {
            use openh264::encoder::{BitRate, EncoderConfig, FrameRate};
            let config = EncoderConfig::new()
                .bitrate(BitRate::from_bps(2_000_000))
                .max_frame_rate(FrameRate::from_hz(30.0));
            match openh264::encoder::Encoder::with_api_config(
                openh264::OpenH264API::from_source(),
                config,
            ) {
                Ok(encoder) => {
                    let yuv_size = (width * height) as usize * 3 / 2;
                    Some(Self {
                        width,
                        height,
                        encoder: Some(encoder),
                        yuv_buffer: vec![0u8; yuv_size],
                    })
                }
                Err(e) => {
                    warn!("Failed to create OpenH264 encoder: {}", e);
                    None
                }
            }
        }
        #[cfg(not(feature = "openh264"))]
        {
            let _ = width;
            let _ = height;
            None
        }
    }

    /// Encode a region of framebuffer as H.264.
    ///
    /// `src` is the full framebuffer in XRGB8888 format (4 bytes per pixel).
    /// `src_stride` is the number of bytes per row.
    ///
    /// Returns a rectangle containing the H.264 bitstream data.
    pub fn encode(
        &mut self,
        src: &[u8],
        src_stride: usize,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        _dst_format: &PixelFormat,
    ) -> FbRect {
        #[cfg(feature = "openh264")]
        {
            // For simplicity, encode the entire requested region as one frame.
            // Convert XRGB8888 -> I420 (YUV420 planar).
            self.convert_xrgb_to_i420(src, src_stride, x, y, width, height);

            let mut data = Vec::new();
            if let Some(ref mut encoder) = self.encoder {
                // Create a YUV source from our buffer.
                let y_size = (width as usize * height as usize) as usize;
                let uv_size = y_size / 4;
                let y = &self.yuv_buffer[0..y_size];
                let u = &self.yuv_buffer[y_size..y_size + uv_size];
                let v = &self.yuv_buffer[y_size + uv_size..y_size + uv_size + uv_size];

                match encode_yuv_frame(encoder, y, u, v, width, height) {
                    Ok(encoded) => {
                        data = encoded;
                    }
                    Err(e) => {
                        warn!("OpenH264 encode failed: {}", e);
                    }
                }
            }

            FbRect {
                x,
                y,
                width,
                height,
                encoding: Encoding::OpenH264,
                data,
            }
        }
        #[cfg(not(feature = "openh264"))]
        {
            // Fallback: return empty rectangle.
            let _ = src;
            let _ = src_stride;
            let _ = x;
            let _ = y;
            let _ = width;
            let _ = height;
            let _ = _dst_format;
            FbRect {
                x,
                y,
                width,
                height,
                encoding: Encoding::OpenH264,
                data: Vec::new(),
            }
        }
    }

    #[cfg(feature = "openh264")]
    fn convert_xrgb_to_i420(
        &mut self,
        src: &[u8],
        src_stride: usize,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) {
        let w = width as usize;
        let h = height as usize;
        let y_size = w * h;
        let uv_size = y_size / 4;

        // Clear buffers.
        self.yuv_buffer[0..y_size].fill(0);
        self.yuv_buffer[y_size..y_size + uv_size].fill(128);
        self.yuv_buffer[y_size + uv_size..y_size + uv_size + uv_size].fill(128);

        for row in 0..h {
            let src_y = y as usize + row;
            let src_off = src_y * src_stride + x as usize * 4;
            let dst_y = row * w;
            for col in 0..w {
                let pixel_off = src_off + col * 4;
                let b = src[pixel_off];
                let g = src[pixel_off + 1];
                let r = src[pixel_off + 2];

                // BT.601 conversion.
                let y_val = ((66 * r as i32 + 129 * g as i32 + 25 * b as i32 + 128) >> 8) + 16;
                self.yuv_buffer[dst_y + col] = y_val.clamp(0, 255) as u8;

                // Subsample U/V (4:2:0).
                if row % 2 == 0 && col % 2 == 0 {
                    let u_val =
                        ((-38 * r as i32 - 74 * g as i32 + 112 * b as i32 + 128) >> 8) + 128;
                    let v_val = ((112 * r as i32 - 94 * g as i32 - 18 * b as i32 + 128) >> 8) + 128;
                    let uv_row = row / 2;
                    let uv_col = col / 2;
                    let uv_off = uv_row * (w / 2) + uv_col;
                    self.yuv_buffer[y_size + uv_off] = u_val.clamp(0, 255) as u8;
                    self.yuv_buffer[y_size + uv_size + uv_off] = v_val.clamp(0, 255) as u8;
                }
            }
        }
    }
}

#[cfg(feature = "openh264")]
fn encode_yuv_frame(
    encoder: &mut openh264::encoder::Encoder,
    y: &[u8],
    u: &[u8],
    v: &[u8],
    width: u16,
    height: u16,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use openh264::formats::YUVSource;

    struct YuvFrame<'a> {
        y: &'a [u8],
        u: &'a [u8],
        v: &'a [u8],
        width: usize,
        height: usize,
    }

    impl<'a> YUVSource for YuvFrame<'a> {
        fn dimensions(&self) -> (usize, usize) {
            (self.width, self.height)
        }

        fn strides(&self) -> (usize, usize, usize) {
            (self.width, self.width / 2, self.width / 2)
        }

        fn y(&self) -> &[u8] {
            self.y
        }

        fn u(&self) -> &[u8] {
            self.u
        }

        fn v(&self) -> &[u8] {
            self.v
        }
    }

    let frame = YuvFrame {
        y,
        u,
        v,
        width: width as usize,
        height: height as usize,
    };

    let encoded = encoder.encode(&frame)?;
    let data = encoded.to_vec();
    Ok(data)
}
