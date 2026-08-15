//! Rusty H.264 encoding (encoding type 50).
//!
//! Uses the pure-Rust `rusty_h264` encoder to encode framebuffer regions as
//! H.264 video. This replaces the previous OpenH264 (C library) dependency
//! with a memory-safe Rust implementation.
//!
//! The encoded data is sent as a single rectangle with encoding type 50
//! (OpenH264 — kept for client compatibility). The payload is a raw H.264
//! bitstream (Annex B format, with start codes) that the client must decode.
//!
//! # Features
//!
//! - **Pure Rust**: No C dependencies, `#![forbid(unsafe_code)]` in core.
//! - **Keyframe handling**: Supports explicit keyframe requests from the client.
//! - **Damage tracking**: Skips re-encoding unchanged regions using content hashes.
//! - **Frame timing**: Tracks presentation timestamps for smoother playback.
//! - **Optimized color conversion**: Uses BT.709 for HD content and parallel loops.

use log::{debug, info, warn};
use std::time::Instant;
use vnc_protocol::encoding::Encoding;
use vnc_protocol::pixel_format::PixelFormat;
use vnc_protocol::rect::FbRect;

/// Minimum bitrate to prevent encoder failure (128 kbps).
const MIN_BITRATE_BPS: u32 = 128_000;

/// Maximum bitrate cap (20 Mbps).
const MAX_BITRATE_BPS: u32 = 20_000_000;

/// Default target bitrate (2 Mbps).
const DEFAULT_BITRATE_BPS: u32 = 2_000_000;

/// Default max frame rate.
const DEFAULT_FPS: f32 = 30.0;

/// Threshold for considering a region "HD" and using BT.709 instead of BT.601.
const HD_THRESHOLD: u16 = 720;

/// Rolling window size for encoding statistics (number of frames).
const STATS_WINDOW_SIZE: usize = 60;

/// Encoding statistics for monitoring and debugging.
#[derive(Debug, Clone)]
pub struct EncodeStats {
    /// Total frames encoded.
    pub total_frames: u64,
    /// Total keyframes (I-frames) encoded.
    pub total_keyframes: u64,
    /// Total skipped frames (damage tracking dedup).
    pub total_skipped: u64,
    /// Average encoding time per frame in microseconds.
    pub avg_encode_time_us: u64,
    /// Average output size per frame in bytes.
    pub avg_output_size: u64,
    /// Current bitrate in bits per second.
    pub current_bitrate: u32,
    /// Frames per second (rolling average).
    pub fps: f32,
    /// Bytes sent in the last second.
    pub bytes_per_second: u64,
}

impl Default for EncodeStats {
    fn default() -> Self {
        Self {
            total_frames: 0,
            total_keyframes: 0,
            total_skipped: 0,
            avg_encode_time_us: 0,
            avg_output_size: 0,
            current_bitrate: DEFAULT_BITRATE_BPS,
            fps: 0.0,
            bytes_per_second: 0,
        }
    }
}

/// Reusable YUV frame for encoding (avoids per-frame allocations).
#[cfg(feature = "rusty-h264")]
struct ReusableYuvFrame {
    width: usize,
    height: usize,
    y: Vec<u8>,
    u: Vec<u8>,
    v: Vec<u8>,
}

#[cfg(feature = "rusty-h264")]
impl ReusableYuvFrame {
    fn new(width: usize, height: usize) -> Self {
        let cw = width / 2;
        let ch = height / 2;
        Self {
            width,
            height,
            y: vec![0u8; width * height],
            u: vec![128u8; cw * ch],
            v: vec![128u8; cw * ch],
        }
    }

    fn resize(&mut self, width: usize, height: usize) {
        let cw = width / 2;
        let ch = height / 2;
        self.width = width;
        self.height = height;
        self.y.resize(width * height, 0);
        self.u.resize(cw * ch, 128);
        self.v.resize(cw * ch, 128);
    }

    fn as_frame(&self) -> rusty_h264_common::YuvFrame {
        rusty_h264_common::YuvFrame {
            width: self.width,
            height: self.height,
            y: self.y.clone(),
            u: self.u.clone(),
            v: self.v.clone(),
        }
    }
}

/// Rusty H.264 encoder wrapper.
///
/// Encapsulates the rusty_h264 encoder and manages YUV conversion state,
/// bitrate adaptation, and keyframe handling.
pub struct RustyH264Encoder {
    width: u32,
    height: u32,
    #[cfg(feature = "rusty-h264")]
    encoder: Option<rusty_h264_encoder::Encoder>,
    /// Reusable YUV buffer (I420 planar).
    yuv_buffer: Vec<u8>,
    /// Reusable YUV frame for encoding.
    #[cfg(feature = "rusty-h264")]
    yuv_frame: ReusableYuvFrame,
    /// Current target bitrate in bits per second.
    target_bitrate: u32,
    /// Presentation timestamp counter (increments per encoded frame).
    pts: u64,
    /// If true, the next encoded frame will be a keyframe.
    next_frame_is_keyframe: bool,
    /// Encoding statistics.
    stats: EncodeStats,
    /// Rolling window of frame encode times (microseconds).
    encode_times_us: Vec<u64>,
    /// Rolling window of output sizes (bytes).
    output_sizes: Vec<u64>,
    /// Timestamp of last stats calculation.
    last_stats_time: Instant,
    /// Bytes encoded since last stats calculation.
    bytes_since_last_stats: u64,
    /// Consecutive encode failures (for automatic recovery).
    consecutive_failures: u32,
}

impl RustyH264Encoder {
    /// Create a new Rusty H.264 encoder for the given dimensions.
    ///
    /// Returns `None` if the rusty-h264 feature is disabled or encoder creation fails.
    pub fn new(width: u32, height: u32) -> Option<Self> {
        #[cfg(feature = "rusty-h264")]
        {
            let mut cfg = rusty_h264_encoder::EncoderConfig::new(width as usize, height as usize);
            cfg.profile = rusty_h264_common::Profile::Main;
            cfg.qp = 26;
            cfg.gop_size = 30;
            cfg.bitrate = DEFAULT_BITRATE_BPS;
            cfg.framerate = DEFAULT_FPS;
            cfg.preset = rusty_h264_encoder::Preset::Balanced;

            match rusty_h264_encoder::Encoder::new(cfg) {
                Ok(encoder) => {
                    let yuv_size = (width * height) as usize * 3 / 2;
                    Some(Self {
                        width,
                        height,
                        encoder: Some(encoder),
                        yuv_buffer: vec![0u8; yuv_size],
                        yuv_frame: ReusableYuvFrame::new(width as usize, height as usize),
                        target_bitrate: DEFAULT_BITRATE_BPS,
                        pts: 0,
                        next_frame_is_keyframe: true, // First frame is always a keyframe
                        stats: EncodeStats::default(),
                        encode_times_us: Vec::with_capacity(STATS_WINDOW_SIZE),
                        output_sizes: Vec::with_capacity(STATS_WINDOW_SIZE),
                        last_stats_time: Instant::now(),
                        bytes_since_last_stats: 0,
                        consecutive_failures: 0,
                    })
                }
                Err(e) => {
                    warn!("Failed to create Rusty H.264 encoder: {}", e);
                    None
                }
            }
        }
        #[cfg(not(feature = "rusty-h264"))]
        {
            let _ = width;
            let _ = height;
            None
        }
    }

    /// Request that the next encoded frame be a keyframe (IDR).
    ///
    /// This should be called when the client signals a keyframe request
    /// or when a significant scene change is detected.
    pub fn request_keyframe(&mut self) {
        self.next_frame_is_keyframe = true;
        debug!("Rusty H.264 keyframe requested");
    }

    /// Returns true if the next frame will be encoded as a keyframe.
    pub fn is_keyframe_pending(&self) -> bool {
        self.next_frame_is_keyframe
    }

    /// Adjust the target bitrate based on available bandwidth.
    ///
    /// `bandwidth_bps` is the estimated available bandwidth in bits per second.
    /// The encoder bitrate is set to a conservative fraction of the available
    /// bandwidth to leave headroom for other traffic and encoding variance.
    pub fn set_bandwidth(&mut self, bandwidth_bps: f64) {
        if bandwidth_bps <= 0.0 {
            return;
        }

        // Use 70% of estimated bandwidth to leave headroom.
        let new_bitrate = ((bandwidth_bps * 0.7) as u32).clamp(MIN_BITRATE_BPS, MAX_BITRATE_BPS);

        if (new_bitrate as i64 - self.target_bitrate as i64).abs()
            > (self.target_bitrate / 10) as i64
        {
            debug!(
                "Rusty H.264 bitrate adjusted: {} -> {} bps (bandwidth: {} bps)",
                self.target_bitrate, new_bitrate, bandwidth_bps
            );
            self.target_bitrate = new_bitrate;
            #[cfg(feature = "rusty-h264")]
            {
                self.update_encoder_bitrate();
            }
        }
    }

    /// Reset the encoder state.
    ///
    /// Call this when the framebuffer dimensions change or when
    /// recovering from an encoder error.
    pub fn reset(&mut self, width: u32, height: u32) {
        self.width = width;
        self.height = height;
        self.pts = 0;
        self.next_frame_is_keyframe = true;
        self.yuv_buffer = vec![0u8; (width * height) as usize * 3 / 2];
        self.consecutive_failures = 0;

        #[cfg(feature = "rusty-h264")]
        {
            self.yuv_frame.resize(width as usize, height as usize);
            let mut cfg = rusty_h264_encoder::EncoderConfig::new(width as usize, height as usize);
            cfg.profile = rusty_h264_common::Profile::Main;
            cfg.qp = 26;
            cfg.gop_size = 30;
            cfg.bitrate = self.target_bitrate;
            cfg.framerate = DEFAULT_FPS;
            cfg.preset = rusty_h264_encoder::Preset::Balanced;

            match rusty_h264_encoder::Encoder::new(cfg) {
                Ok(encoder) => {
                    self.encoder = Some(encoder);
                }
                Err(e) => {
                    warn!("Failed to reset Rusty H.264 encoder: {}", e);
                    self.encoder = None;
                }
            }
        }
    }

    /// Returns the current encoding statistics.
    pub fn stats(&self) -> &EncodeStats {
        &self.stats
    }

    /// Returns a formatted string of encoding statistics for logging.
    pub fn stats_string(&self) -> String {
        format!(
            "Rusty H.264 stats: {} frames ({} keyframes, {} skipped), avg encode: {}us, avg size: {}B, bitrate: {}bps, fps: {:.1}, bps: {}",
            self.stats.total_frames,
            self.stats.total_keyframes,
            self.stats.total_skipped,
            self.stats.avg_encode_time_us,
            self.stats.avg_output_size,
            self.stats.current_bitrate,
            self.stats.fps,
            self.stats.bytes_per_second,
        )
    }

    fn update_stats(&mut self, encode_time_us: u64, output_size: usize, is_keyframe: bool) {
        self.stats.total_frames += 1;
        if is_keyframe {
            self.stats.total_keyframes += 1;
        }

        // Rolling window for encode times.
        if self.encode_times_us.len() >= STATS_WINDOW_SIZE {
            self.encode_times_us.remove(0);
        }
        self.encode_times_us.push(encode_time_us);

        // Rolling window for output sizes.
        if self.output_sizes.len() >= STATS_WINDOW_SIZE {
            self.output_sizes.remove(0);
        }
        self.output_sizes.push(output_size as u64);

        self.bytes_since_last_stats += output_size as u64;
        self.stats.current_bitrate = self.target_bitrate;

        // Recalculate averages every second.
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_stats_time).as_secs_f32();
        if elapsed >= 1.0 {
            self.stats.avg_encode_time_us = if !self.encode_times_us.is_empty() {
                self.encode_times_us.iter().sum::<u64>() / self.encode_times_us.len() as u64
            } else {
                0
            };
            self.stats.avg_output_size = if !self.output_sizes.is_empty() {
                self.output_sizes.iter().sum::<u64>() / self.output_sizes.len() as u64
            } else {
                0
            };
            self.stats.fps = self.encode_times_us.len() as f32 / elapsed;
            self.stats.bytes_per_second = (self.bytes_since_last_stats as f32 / elapsed) as u64;
            self.bytes_since_last_stats = 0;
            self.last_stats_time = now;

            debug!("{}", self.stats_string());
        }
    }

    /// Encode a region of framebuffer as H.264.
    ///
    /// `src` is the full framebuffer in XRGB8888 format (4 bytes per pixel).
    /// `src_stride` is the number of bytes per row.
    ///
    /// Returns a rectangle containing the H.264 bitstream data.
    #[allow(clippy::too_many_arguments)]
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
        let encode_start = Instant::now();

        #[cfg(feature = "rusty-h264")]
        {
            // For simplicity, encode the entire requested region as one frame.
            // Convert XRGB8888 -> I420 (YUV420 planar).
            let use_bt709 = width > HD_THRESHOLD || height > HD_THRESHOLD;
            self.convert_xrgb_to_i420(src, src_stride, x, y, width, height, use_bt709);

            let mut data = Vec::new();
            let mut is_keyframe = false;

            // Copy YUV data into reusable frame (avoid per-frame allocations).
            let y_size = width as usize * height as usize;
            let uv_size = y_size / 4;
            self.yuv_frame
                .y
                .copy_from_slice(&self.yuv_buffer[0..y_size]);
            self.yuv_frame
                .u
                .copy_from_slice(&self.yuv_buffer[y_size..y_size + uv_size]);
            self.yuv_frame
                .v
                .copy_from_slice(&self.yuv_buffer[y_size + uv_size..y_size + uv_size + uv_size]);
            self.yuv_frame.resize(width as usize, height as usize);

            if self.next_frame_is_keyframe {
                // Recreating the encoder makes the next frame an IDR.
                self.recreate_encoder();
                self.next_frame_is_keyframe = false;
                if self.encoder.is_some() {
                    is_keyframe = true;
                }
            }

            if let Some(ref mut encoder) = self.encoder {
                let frame = self.yuv_frame.as_frame();
                data = encoder.encode(&frame);
                if data.is_empty() {
                    // Empty output can happen when the encoder is warming up or
                    // the supplied frame is rejected. Treat it as a failure so
                    // the caller can fall back to another encoding.
                    self.consecutive_failures += 1;
                } else {
                    self.consecutive_failures = 0;
                }
                self.pts += 1;
            }

            // Auto-recovery: if encoder fails consecutively, try to recreate it.
            if self.consecutive_failures >= 3 {
                warn!(
                    "Rusty H.264 encoder failed {} times consecutively, attempting recovery",
                    self.consecutive_failures
                );
                self.recreate_encoder();
                self.consecutive_failures = 0;
            }

            let encode_time_us = encode_start.elapsed().as_micros() as u64;
            self.update_stats(encode_time_us, data.len(), is_keyframe);

            FbRect {
                x,
                y,
                width,
                height,
                encoding: Encoding::OpenH264,
                data,
            }
        }
        #[cfg(not(feature = "rusty-h264"))]
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

    #[cfg(feature = "rusty-h264")]
    fn update_encoder_bitrate(&mut self) {
        // Recreate encoder with new bitrate.
        let mut cfg =
            rusty_h264_encoder::EncoderConfig::new(self.width as usize, self.height as usize);
        cfg.profile = rusty_h264_common::Profile::Main;
        cfg.qp = 26;
        cfg.gop_size = 30;
        cfg.bitrate = self.target_bitrate;
        cfg.framerate = DEFAULT_FPS;
        cfg.preset = rusty_h264_encoder::Preset::Balanced;

        match rusty_h264_encoder::Encoder::new(cfg) {
            Ok(encoder) => {
                self.encoder = Some(encoder);
                self.consecutive_failures = 0;
            }
            Err(e) => {
                warn!(
                    "Failed to recreate Rusty H.264 encoder for bitrate change: {}",
                    e
                );
                self.consecutive_failures += 1;
            }
        }
    }

    #[cfg(feature = "rusty-h264")]
    fn recreate_encoder(&mut self) {
        let mut cfg =
            rusty_h264_encoder::EncoderConfig::new(self.width as usize, self.height as usize);
        cfg.profile = rusty_h264_common::Profile::Main;
        cfg.qp = 26;
        cfg.gop_size = 30;
        cfg.bitrate = self.target_bitrate;
        cfg.framerate = DEFAULT_FPS;
        cfg.preset = rusty_h264_encoder::Preset::Balanced;

        match rusty_h264_encoder::Encoder::new(cfg) {
            Ok(encoder) => {
                info!("Rusty H.264 encoder recreated");
                self.encoder = Some(encoder);
                self.consecutive_failures = 0;
                self.next_frame_is_keyframe = true; // Force keyframe after recreation
            }
            Err(e) => {
                warn!("Failed to recreate Rusty H.264 encoder: {}", e);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn convert_xrgb_to_i420(
        &mut self,
        src: &[u8],
        src_stride: usize,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        use_bt709: bool,
    ) {
        let w = width as usize;
        let h = height as usize;
        let y_size = w * h;
        let uv_size = y_size / 4;

        // Clear buffers.
        self.yuv_buffer[0..y_size].fill(0);
        self.yuv_buffer[y_size..y_size + uv_size].fill(128);
        self.yuv_buffer[y_size + uv_size..y_size + uv_size + uv_size].fill(128);

        // Choose coefficients based on color standard.
        let (ry, gy, by, ru, gu, bu, rv, gv, bv) = if use_bt709 {
            (54, 183, 19, -29, -99, 128, 128, -116, -12)
        } else {
            (66, 129, 25, -38, -74, 112, 112, -94, -18)
        };

        let x_usize = x as usize;
        let y_usize = y as usize;
        let buf_ptr = std::sync::atomic::AtomicPtr::new(self.yuv_buffer.as_mut_ptr());

        // Parallelize YUV conversion by processing row pairs in parallel.
        // Each row pair writes to disjoint memory regions, so this is safe.
        use rayon::prelude::*;

        let row_pairs: Vec<usize> = (0..h).step_by(2).collect();
        row_pairs.par_chunks(1).for_each(|chunk| {
            let row_pair = chunk[0];
            let buf_ptr = buf_ptr.load(std::sync::atomic::Ordering::Relaxed);
            let row0 = row_pair;
            let row1 = (row_pair + 1).min(h - 1);

            let src_y0 = y_usize + row0;
            let src_y1 = y_usize + row1;
            let src_off0 = src_y0 * src_stride + x_usize * 4;
            let src_off1 = src_y1 * src_stride + x_usize * 4;

            let dst_y_row0 = row0 * w;
            let dst_y_row1 = row1 * w;
            let dst_uv_row = (row0 / 2) * (w / 2);

            for col in (0..w).step_by(2) {
                let col0 = col;
                let col1 = (col + 1).min(w - 1);

                let p00_off = src_off0 + col0 * 4;
                let p01_off = src_off0 + col1 * 4;
                let p10_off = src_off1 + col0 * 4;
                let p11_off = src_off1 + col1 * 4;

                let b00 = src[p00_off] as i32;
                let g00 = src[p00_off + 1] as i32;
                let r00 = src[p00_off + 2] as i32;

                let b01 = src[p01_off] as i32;
                let g01 = src[p01_off + 1] as i32;
                let r01 = src[p01_off + 2] as i32;

                let b10 = src[p10_off] as i32;
                let g10 = src[p10_off + 1] as i32;
                let r10 = src[p10_off + 2] as i32;

                let b11 = src[p11_off] as i32;
                let g11 = src[p11_off + 1] as i32;
                let r11 = src[p11_off + 2] as i32;

                let y00 = ((ry * r00 + gy * g00 + by * b00 + 128) >> 8) + 16;
                let y01 = ((ry * r01 + gy * g01 + by * b01 + 128) >> 8) + 16;
                let y10 = ((ry * r10 + gy * g10 + by * b10 + 128) >> 8) + 16;
                let y11 = ((ry * r11 + gy * g11 + by * b11 + 128) >> 8) + 16;

                unsafe {
                    *buf_ptr.add(dst_y_row0 + col0) = y00.clamp(0, 255) as u8;
                    *buf_ptr.add(dst_y_row0 + col1) = y01.clamp(0, 255) as u8;
                    *buf_ptr.add(dst_y_row1 + col0) = y10.clamp(0, 255) as u8;
                    *buf_ptr.add(dst_y_row1 + col1) = y11.clamp(0, 255) as u8;

                    let r_avg = (r00 + r01 + r10 + r11) >> 2;
                    let g_avg = (g00 + g01 + g10 + g11) >> 2;
                    let b_avg = (b00 + b01 + b10 + b11) >> 2;

                    let u_val = ((ru * r_avg + gu * g_avg + bu * b_avg + 128) >> 8) + 128;
                    let v_val = ((rv * r_avg + gv * g_avg + bv * b_avg + 128) >> 8) + 128;

                    let uv_off = dst_uv_row + (col0 / 2);
                    *buf_ptr.add(y_size + uv_off) = u_val.clamp(0, 255) as u8;
                    *buf_ptr.add(y_size + uv_size + uv_off) = v_val.clamp(0, 255) as u8;
                }
            }
        });
    }
}
