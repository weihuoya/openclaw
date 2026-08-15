use crate::VncError;

/// Video codec selected for the Apple HP adaptive media stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// H.264 / AVC.
    H264,
    /// H.265 / HEVC.
    Hevc,
}

/// Video decoder trait for H.264/HEVC frame decoding.
///
/// Platform implementations:
/// - Linux/GTK4: GStreamer (via `gstreamer-app`)
/// - Android: NdkMediaCodec (via `mediacodec` crate)
pub trait VideoDecoder: Send {
    /// Decode a single compressed access unit and return RGBA pixel data.
    ///
    /// The returned data dimensions match the negotiated video size.
    /// The caller must know the expected width/height to interpret the buffer.
    fn decode_frame(&self, data: &[u8]) -> Result<Vec<u8>, VncError>;

    /// Get the negotiated video dimensions from the decoder.
    fn video_size(&self) -> Option<(u16, u16)>;

    /// Inform the decoder of the expected video dimensions before decoding.
    ///
    /// The default implementation is a no-op for decoders that auto-detect size.
    fn set_size(&self, _width: u16, _height: u16) {}

    /// Feed a single NAL/access unit and return a decoded frame if one is
    /// available.
    ///
    /// Some NAL units (SPS, PPS, SEI) do not produce a picture; the default
    /// implementation delegates to [`Self::decode_frame`] and always returns
    /// `Some`. Platform-specific implementations should override this to avoid
    /// treating non-picture NALs as decode errors.
    fn try_decode_frame(&self, data: &[u8]) -> Result<Option<Vec<u8>>, VncError> {
        Ok(Some(self.decode_frame(data)?))
    }

    /// Feed one complete access unit tagged with `pts`, returning the tag and
    /// RGBA pixels of a decoded picture when one becomes available.
    ///
    /// The tag round-trips to the output picture, which lets streaming callers
    /// associate decoded frames with the exact access unit that produced them
    /// (e.g. for multi-tile composition), even when the decoder drops or
    /// delays individual units. The default implementation ignores the tag and
    /// reports 0 for any output.
    fn decode_au(&self, data: &[u8], pts: u64) -> Result<Option<(u64, Vec<u8>)>, VncError> {
        let _ = pts;
        Ok(self.try_decode_frame(data)?.map(|rgba| (0, rgba)))
    }

    /// Poll for a decoded picture without feeding new input.
    ///
    /// Used by streaming receivers to drain the decoder between packet
    /// arrivals, so pictures delayed by the decoder pipeline are not held
    /// hostage to the next push. Returns the PTS tag and RGBA pixels.
    fn poll_decoded(&self) -> Result<Option<(u64, Vec<u8>)>, VncError> {
        Ok(None)
    }
}

#[cfg(not(target_os = "android"))]
pub mod gstreamer;

#[cfg(not(target_os = "android"))]
pub use self::gstreamer::GStreamerDecoder as DefaultDecoder;

#[cfg(not(target_os = "android"))]
pub use self::gstreamer::GStreamerDecoder;

#[cfg(target_os = "android")]
pub mod android;

#[cfg(target_os = "android")]
pub use self::android::MediaCodecDecoder as DefaultDecoder;
