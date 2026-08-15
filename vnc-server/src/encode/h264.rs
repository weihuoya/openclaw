//! H.264 encoder wrapper — selects hardware (V4L2 M2M) or software (rusty_h264).

use vnc_protocol::pixel_format::PixelFormat;
use vnc_protocol::rect::FbRect;

/// Unified H.264 encoder that prefers hardware acceleration.
pub enum H264Encoder {
    #[cfg(feature = "v4l2m2m")]
    V4l2M2m(super::v4l2m2m::V4l2M2mEncoder),
    #[cfg(feature = "rusty-h264")]
    Software(Box<super::rusty_h264::RustyH264Encoder>),
}

impl H264Encoder {
    /// Create a new H.264 encoder, preferring hardware if available.
    pub fn new(width: u32, height: u32) -> Option<Self> {
        #[cfg(feature = "v4l2m2m")]
        {
            if let Some(enc) = super::v4l2m2m::V4l2M2mEncoder::new(width, height) {
                return Some(Self::V4l2M2m(enc));
            }
        }
        #[cfg(feature = "rusty-h264")]
        {
            if let Some(enc) = super::rusty_h264::RustyH264Encoder::new(width, height) {
                return Some(Self::Software(Box::new(enc)));
            }
        }
        None
    }

    pub fn request_keyframe(&mut self) {
        match self {
            #[cfg(feature = "v4l2m2m")]
            Self::V4l2M2m(enc) => enc.request_keyframe(),
            #[cfg(feature = "rusty-h264")]
            Self::Software(enc) => enc.request_keyframe(),
        }
    }

    pub fn set_bandwidth(&mut self, bandwidth_bps: f64) {
        match self {
            #[cfg(feature = "v4l2m2m")]
            Self::V4l2M2m(enc) => enc.set_bandwidth(bandwidth_bps),
            #[cfg(feature = "rusty-h264")]
            Self::Software(enc) => enc.set_bandwidth(bandwidth_bps),
        }
    }

    pub fn reset(&mut self, width: u32, height: u32) {
        match self {
            #[cfg(feature = "v4l2m2m")]
            Self::V4l2M2m(enc) => enc.reset(width, height),
            #[cfg(feature = "rusty-h264")]
            Self::Software(enc) => enc.reset(width, height),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn encode(
        &mut self,
        src: &[u8],
        src_stride: usize,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        dst_format: &PixelFormat,
    ) -> FbRect {
        match self {
            #[cfg(feature = "v4l2m2m")]
            Self::V4l2M2m(enc) => enc.encode(src, src_stride, x, y, width, height, dst_format),
            #[cfg(feature = "rusty-h264")]
            Self::Software(enc) => enc.encode(src, src_stride, x, y, width, height, dst_format),
        }
    }
}
