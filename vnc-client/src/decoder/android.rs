use crate::{decoder::VideoDecoder, VncError};
use std::cell::{Cell, RefCell};
use std::time::Duration;

/// H.264 decoder using Android NdkMediaCodec.
///
/// Uses the `ndk` crate to bind to Android's `AMediaCodec` API.
/// This provides hardware-accelerated decoding on most Android devices.
///
/// The decoder expects Annex-B format H.264 NAL units (start codes 00 00 00 01).
/// SPS/PPS must be present before the first IDR frame.
pub struct MediaCodecDecoder {
    codec: ndk::media::media_codec::MediaCodec,
    width: Cell<u16>,
    height: Cell<u16>,
    /// Y-plane stride (may differ from width due to hardware alignment).
    stride: Cell<usize>,
    /// Internal RGBA buffer, reused across frames.
    rgba_buffer: RefCell<Vec<u8>>,
}

impl MediaCodecDecoder {
    pub fn new() -> Result<Self, VncError> {
        let codec = ndk::media::media_codec::MediaCodec::from_decoder_type("video/avc")
            .ok_or_else(|| VncError::Protocol("Failed to create MediaCodec decoder".to_string()))?;

        Ok(Self {
            codec,
            width: Cell::new(0),
            height: Cell::new(0),
            stride: Cell::new(0),
            rgba_buffer: RefCell::new(Vec::new()),
        })
    }

    fn configure(&self, width: u16, height: u16) -> Result<(), VncError> {
        if self.width.get() == width && self.height.get() == height {
            return Ok(());
        }

        let mut format = ndk::media::media_format::MediaFormat::new();
        format.set_str("mime", "video/avc");
        format.set_i32("width", width as i32);
        format.set_i32("height", height as i32);

        // Optional: request low-latency decoding for remote desktop
        format.set_i32("low-latency", 1);

        self.codec
            .configure(
                &format,
                None,
                ndk::media::media_codec::MediaCodecDirection::Decoder,
            )
            .map_err(|e| VncError::Protocol(format!("MediaCodec configure failed: {e:?}")))?;

        self.codec
            .start()
            .map_err(|e| VncError::Protocol(format!("MediaCodec start failed: {e:?}")))?;

        self.width.set(width);
        self.height.set(height);
        self.stride.set(width as usize);
        *self.rgba_buffer.borrow_mut() = vec![0u8; width as usize * height as usize * 4];

        Ok(())
    }

    /// Feed a NAL unit into the decoder and drain any available output frames.
    fn feed_and_drain(&self, nal_data: &[u8]) -> Result<(), VncError> {
        // Feed input
        match self.codec.dequeue_input_buffer(Duration::ZERO) {
            Ok(ndk::media::media_codec::DequeuedInputBufferResult::Buffer(mut buffer)) => {
                let mut buf = buffer.buffer_mut();
                let len = nal_data.len().min(buf.len());
                buf[..len].write_slice(nal_data);
                // Queue the buffer back to the codec.
                let _ = self.codec.queue_input_buffer(buffer, 0, len, 0, 0);
            }
            Ok(ndk::media::media_codec::DequeuedInputBufferResult::TryAgainLater) => {}
            Err(e) => {
                return Err(VncError::Protocol(format!(
                    "MediaCodec input dequeue: {e:?}"
                )))
            }
        }

        // Drain output
        loop {
            match self.codec.dequeue_output_buffer(Duration::ZERO) {
                Ok(ndk::media::media_codec::DequeuedOutputBufferInfoResult::Buffer(buffer)) => {
                    let yuv = buffer.buffer();
                    self.convert_nv12_to_rgba(yuv, self.width.get(), self.height.get());
                    let _ = self.codec.release_output_buffer(buffer, false);
                }
                Ok(ndk::media::media_codec::DequeuedOutputBufferInfoResult::TryAgainLater)
                | Ok(
                    ndk::media::media_codec::DequeuedOutputBufferInfoResult::OutputFormatChanged,
                )
                | Ok(
                    ndk::media::media_codec::DequeuedOutputBufferInfoResult::OutputBuffersChanged,
                ) => {
                    break;
                }
                Err(e) => {
                    return Err(VncError::Protocol(format!(
                        "MediaCodec output dequeue: {e:?}"
                    )));
                }
            }
        }

        Ok(())
    }

    /// Convert NV12 to RGBA.
    ///
    /// Uses the stored `stride` value which may differ from `width`
    /// due to hardware alignment padding. Falls back to `width` if
    /// the buffer is too small for the claimed stride.
    fn convert_nv12_to_rgba(&self, nv12: &[u8], width: u16, height: u16) {
        let w = width as usize;
        let h = height as usize;
        let stride = self.stride.get().max(w);
        let y_size = stride * h;
        let uv_size = stride * h / 2;
        if nv12.len() < y_size + uv_size {
            // Buffer too small for claimed stride; fall back to width==stride.
            let fallback_stride = w;
            let fallback_y_size = fallback_stride * h;
            let fallback_uv_size = fallback_stride * h / 2;
            if nv12.len() < fallback_y_size + fallback_uv_size {
                return;
            }
            return self.convert_nv12_to_rgba_inner(nv12, w, h, fallback_stride);
        }
        self.convert_nv12_to_rgba_inner(nv12, w, h, stride);
    }

    fn convert_nv12_to_rgba_inner(&self, nv12: &[u8], w: usize, h: usize, stride: usize) {
        let y_size = stride * h;
        let y_plane = &nv12[..y_size];
        let uv_plane = &nv12[y_size..];

        let mut rgba = self.rgba_buffer.borrow_mut();

        for row in 0..h {
            for col in 0..w {
                let y = y_plane[row * stride + col] as i32;
                let uv_idx = (row / 2) * stride + (col & !1);
                let u = uv_plane[uv_idx] as i32 - 128;
                let v = uv_plane[uv_idx + 1] as i32 - 128;

                // Fast integer YUV→RGB conversion
                let r = (y + ((v * 359) >> 8)).clamp(0, 255) as u8;
                let g = (y - ((u * 88) >> 8) - ((v * 183) >> 8)).clamp(0, 255) as u8;
                let b = (y + ((u * 454) >> 8)).clamp(0, 255) as u8;

                let idx = (row * w + col) * 4;
                rgba[idx] = r;
                rgba[idx + 1] = g;
                rgba[idx + 2] = b;
                rgba[idx + 3] = 0xff;
            }
        }
    }
}

impl VideoDecoder for MediaCodecDecoder {
    fn decode_frame(&self, data: &[u8]) -> Result<Vec<u8>, VncError> {
        if self.width.get() == 0 || self.height.get() == 0 {
            return Err(VncError::Protocol(
                "MediaCodec not configured with video size".to_string(),
            ));
        }

        self.feed_and_drain(data)?;
        Ok(self.rgba_buffer.borrow().clone())
    }

    fn video_size(&self) -> Option<(u16, u16)> {
        let w = self.width.get();
        let h = self.height.get();
        if w == 0 || h == 0 {
            None
        } else {
            Some((w, h))
        }
    }
}

// Safety: `MediaCodec` is thread-safe (AMediaCodec is refcounted), and we only
// call it from a single thread in the VNC client. Cell/RefCell handle interior
// mutability safely within one thread.
unsafe impl Send for MediaCodecDecoder {}
unsafe impl Sync for MediaCodecDecoder {}

// ─── Helper trait for writing into `MaybeUninit` slice ───

use std::mem::MaybeUninit;

trait WriteSlice {
    fn write_slice(&mut self, src: &[u8]);
}

impl WriteSlice for [MaybeUninit<u8>] {
    fn write_slice(&mut self, src: &[u8]) {
        let len = src.len().min(self.len());
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), self.as_mut_ptr().cast(), len);
        }
    }
}
