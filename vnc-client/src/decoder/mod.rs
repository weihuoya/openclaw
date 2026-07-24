use crate::VncError;

/// Video decoder trait for H.264 frame decoding.
///
/// Platform implementations:
/// - Linux/GTK4: GStreamer (via `gstreamer-app`)
/// - Android: NdkMediaCodec (via `mediacodec` crate)
pub trait VideoDecoder: Send {
    /// Decode a single H.264 frame and return RGBA pixel data.
    ///
    /// The returned data dimensions match the negotiated video size.
    /// The caller must know the expected width/height to interpret the buffer.
    fn decode_frame(&self, data: &[u8]) -> Result<Vec<u8>, VncError>;

    /// Get the negotiated video dimensions from the decoder.
    fn video_size(&self) -> Option<(u16, u16)>;
}

#[cfg(not(target_os = "android"))]
pub mod gstreamer;

#[cfg(not(target_os = "android"))]
pub use self::gstreamer::GStreamerDecoder as DefaultDecoder;

#[cfg(target_os = "android")]
pub mod android;

#[cfg(target_os = "android")]
pub use self::android::MediaCodecDecoder as DefaultDecoder;
