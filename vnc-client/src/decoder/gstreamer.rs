use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Arc, Mutex, Once};

use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::{AppSink, AppSrc, AppStreamType};
use gstreamer_video as gst_video;

use crate::decoder::{Codec, VideoDecoder};
use crate::VncError;

static GST_INIT: Once = Once::new();

/// Debug dump of every buffer pushed into the decoder. Each record is a
/// 4-byte big-endian length followed by the payload, so the exact push
/// boundaries (one per access unit in the Apple HP path) can be replayed
/// offline with `examples/hevc_replay.rs`.
fn debug_save_h264(data: &[u8]) {
    let Some(path) = std::env::var_os("OPENCLAW_H264_DEBUG") else {
        return;
    };
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = file.write_all(&(data.len() as u32).to_be_bytes());
        let _ = file.write_all(data);
    }
}

fn debug_clear_h264_dump() {
    let Some(path) = std::env::var_os("OPENCLAW_H264_DEBUG") else {
        return;
    };
    let _ = std::fs::remove_file(&path);
}

fn init_gstreamer() -> Result<(), VncError> {
    let mut result = Ok(());
    GST_INIT.call_once(|| {
        result =
            gst::init().map_err(|e| VncError::Protocol(format!("GStreamer init failed: {}", e)));
    });
    result
}

fn log_message(msg: &gst::Message) {
    use gstreamer::MessageView;
    match msg.view() {
        MessageView::Error(err) => {
            log::error!(
                "GStreamer pipeline error from {}: {} ({:?})",
                err.src().map(|s| s.path_string()).unwrap_or_default(),
                err.error(),
                err.debug()
            );
        }
        MessageView::Warning(warn) => {
            log::warn!(
                "GStreamer pipeline warning from {}: {} ({:?})",
                warn.src().map(|s| s.path_string()).unwrap_or_default(),
                warn.error(),
                warn.debug()
            );
        }
        MessageView::StateChanged(state)
            if state.src().map(|s| s.path_string()).unwrap_or_default() != "pipeline" =>
        {
            log::trace!(
                "GStreamer element {} state changed: {:?} -> {:?}",
                state.src().map(|s| s.path_string()).unwrap_or_default(),
                state.old(),
                state.current()
            );
        }
        _ => {}
    }
}

fn log_pipeline_elements(pipeline: &gst::Pipeline) {
    log::trace!("Pipeline elements:");
    for elem in pipeline.iterate_elements().into_iter().flatten() {
        let name = elem.path_string();
        let factory = elem.factory().map(|f| f.name().to_string());
        log::trace!("  {} (factory: {:?})", name, factory);
    }
}

/// Convert NV12 (BT.709 limited range) to RGBA.
fn nv12_to_rgba(
    data: &[u8],
    y_offset: usize,
    uv_offset: usize,
    y_stride: usize,
    uv_stride: usize,
    width: usize,
    height: usize,
) -> Vec<u8> {
    let mut rgba = vec![0u8; width * height * 4];

    for row in 0..height {
        for col in 0..width {
            let y = data[y_offset + row * y_stride + col] as f32;
            let uv_row = row / 2;
            let uv_col = col / 2;
            let u = data[uv_offset + uv_row * uv_stride + uv_col * 2] as f32;
            let v = data[uv_offset + uv_row * uv_stride + uv_col * 2 + 1] as f32;

            // BT.709 limited range -> RGB full range.
            let y = (y - 16.0) * 1.164383;
            let cb = u - 128.0;
            let cr = v - 128.0;

            let r = (y + 1.792741 * cr).clamp(0.0, 255.0) as u8;
            let g = (y - 0.532909 * cb - 0.213249 * cr).clamp(0.0, 255.0) as u8;
            let b = (y + 2.112402 * cb).clamp(0.0, 255.0) as u8;

            let idx = (row * width + col) * 4;
            rgba[idx] = r;
            rgba[idx + 1] = g;
            rgba[idx + 2] = b;
            rgba[idx + 3] = 255;
        }
    }

    rgba
}

fn build_decoder_pipeline(codec: Codec) -> Result<(gst::Pipeline, AppSrc, AppSink), VncError> {
    // H.264 and HEVC both run parser-less: the callers always push complete
    // access units (AU-aligned byte-stream), which avdec decodes immediately.
    // A parser element (h265parse) would additionally rewrite buffer
    // timestamps, breaking the AU tag round-trip the tile compositor relies
    // on, and hold back the final AU until the next one arrives.
    let (caps, decoder) = match codec {
        Codec::H264 => (
            "video/x-h264,stream-format=(string)byte-stream,alignment=(string)au,parsed=(boolean)true",
            "avdec_h264",
        ),
        Codec::Hevc => (
            "video/x-h265,stream-format=(string)byte-stream,alignment=(string)au,parsed=(boolean)true",
            // Single-threaded: frame threading would delay output by several
            // access units, and the tile compositor needs prompt 1:1 output.
            "avdec_h265 max-threads=1",
        ),
    };
    let pipeline_str = format!(
        "appsrc name=src format=bytes caps={} ! {} ! videoconvert ! appsink name=sink",
        caps, decoder
    );

    log::debug!("Creating GStreamer pipeline: {}", pipeline_str);

    let pipeline = gst::parse::launch(&pipeline_str)
        .map_err(|e| VncError::Protocol(format!("Pipeline creation failed: {}", e)))?
        .downcast::<gst::Pipeline>()
        .map_err(|_| VncError::Protocol("Failed to cast pipeline".to_string()))?;

    let bus = pipeline
        .bus()
        .ok_or_else(|| VncError::Protocol("Pipeline has no bus".to_string()))?;
    bus.set_sync_handler(|_, msg| {
        log_message(msg);
        gst::BusSyncReply::Pass
    });

    let appsrc = pipeline
        .by_name("src")
        .ok_or_else(|| VncError::Protocol("appsrc not found".to_string()))?
        .downcast::<AppSrc>()
        .map_err(|_| VncError::Protocol("Failed to cast appsrc".to_string()))?;

    // Configure appsrc as a live streaming source. This is required for the
    // h265parse element to output frames in real time: in byte-stream mode the
    // parser only flushes an access unit when it sees the start of the next AU
    // (or EOS). Treating the source as live with explicit timestamps lets it emit
    // frames as soon as the next frame begins arriving.
    appsrc.set_property("is-live", true);
    appsrc.set_property("stream-type", AppStreamType::Stream);
    appsrc.set_property("format", gst::Format::Time);
    // do-timestamp must stay off: the Apple HP tile path stamps every access
    // unit with an explicit PTS tag that has to round-trip to the decoded
    // sample, and appsrc would otherwise overwrite it with the running time.
    appsrc.set_property("do-timestamp", false);

    let appsink = pipeline
        .by_name("sink")
        .ok_or_else(|| VncError::Protocol("appsink not found".to_string()))?
        .downcast::<AppSink>()
        .map_err(|_| VncError::Protocol("Failed to cast appsink".to_string()))?;

    appsink.set_caps(Some(
        &gst::Caps::builder("video/x-raw")
            .field("format", gst::List::new([&"RGBA", &"NV12"]))
            .build(),
    ));

    appsink.set_property("emit-signals", false);
    appsink.set_property("max-buffers", 1u32);
    appsink.set_property("drop", true);
    appsink.set_property("sync", false);
    appsink.set_property("async", false);

    pipeline
        .set_state(gst::State::Playing)
        .map_err(|e| VncError::Protocol(format!("Failed to start pipeline: {}", e)))?;

    log_pipeline_elements(&pipeline);

    Ok((pipeline, appsrc, appsink))
}

struct DecoderState {
    pipeline: gst::Pipeline,
    appsrc: AppSrc,
    appsink: AppSink,
    first_frame_pending: bool,
    last_video_size: Option<(u16, u16)>,
}

/// H.264 / HEVC decoder using GStreamer.
///
/// Pipelines:
/// - H.264: `appsrc -> avdec_h264 -> videoconvert -> appsink`
/// - HEVC: `appsrc -> h265parse -> avdec_h265 -> videoconvert -> appsink`
///
/// H.264 uses `avdec_h264` directly with `parsed=true` because it can decode
/// each NAL-aligned buffer immediately. HEVC needs `h265parse` because
/// `avdec_h265` will not negotiate without a parser in byte-stream mode.
///
/// `h265parse` in byte-stream mode needs the next access unit (or EOS) to
/// flush the previous one when input is NAL-aligned. The Apple HP media path
/// avoids that latency entirely by buffering complete AUs per tile stream and
/// declaring `alignment=au`, so the parser forwards each buffer immediately.
/// `do-timestamp` stays off so explicit PTS tags stamped by the caller (Apple
/// HP tile composition) survive to the output.
pub struct GStreamerDecoder {
    state: Arc<Mutex<DecoderState>>,
}

impl GStreamerDecoder {
    pub fn new() -> Result<Self, VncError> {
        Self::for_codec(Codec::H264)
    }

    pub fn for_codec(codec: Codec) -> Result<Self, VncError> {
        init_gstreamer()?;
        debug_clear_h264_dump();

        let (pipeline, appsrc, appsink) = build_decoder_pipeline(codec)?;

        Ok(Self {
            state: Arc::new(Mutex::new(DecoderState {
                pipeline,
                appsrc,
                appsink,
                first_frame_pending: true,
                last_video_size: None,
            })),
        })
    }
}

impl VideoDecoder for GStreamerDecoder {
    fn decode_frame(&self, data: &[u8]) -> Result<Vec<u8>, VncError> {
        self.push(data)?;

        // Synchronous path (RFB OpenH264 rectangles): the caller expects the
        // decoded pixels right away, so block until the pipeline produces a
        // sample. The first frame gets a generous timeout while the decoder
        // negotiates caps.
        let is_first = {
            let state = self.state.lock().unwrap();
            state.first_frame_pending
        };
        let timeout_ns = if is_first {
            3_000 * 1_000_000u64
        } else {
            500 * 1_000_000u64
        };
        let sample = self.pull_sample(timeout_ns)?;
        let sample = sample
            .ok_or_else(|| VncError::Protocol("Video decode timeout or no output".to_string()))?;
        self.sample_to_rgba(sample)
    }

    fn try_decode_frame(&self, data: &[u8]) -> Result<Option<Vec<u8>>, VncError> {
        self.push(data)?;

        // Streaming path (Apple HP media stream): never block the caller. The
        // receiver thread feeds NAL units back-to-back and must stay
        // responsive to incoming UDP packets and RTCP feedback; a sample that
        // is not ready yet is picked up on a later call.
        let sample = self.pull_sample(0)?;
        match sample {
            Some(sample) => self.sample_to_rgba(sample).map(Some),
            None => Ok(None),
        }
    }

    fn decode_au(&self, data: &[u8], pts: u64) -> Result<Option<(u64, Vec<u8>)>, VncError> {
        self.push_tagged(data, Some(pts))?;

        // Non-blocking pull, same as try_decode_frame. The output sample
        // carries the PTS of the access unit it was decoded from (appsrc
        // do-timestamp is disabled, so our tag survives), letting the caller
        // map it back to the originating tile/access unit.
        let sample = self.pull_sample(0)?;
        match sample {
            Some(sample) => self.sample_to_tagged_rgba(sample).map(Some),
            None => Ok(None),
        }
    }

    fn poll_decoded(&self) -> Result<Option<(u64, Vec<u8>)>, VncError> {
        let sample = self.pull_sample(0)?;
        match sample {
            Some(sample) => self.sample_to_tagged_rgba(sample).map(Some),
            None => Ok(None),
        }
    }

    fn video_size(&self) -> Option<(u16, u16)> {
        let state = self.state.lock().unwrap();
        state.last_video_size
    }
}

impl GStreamerDecoder {
    /// Push a buffer into the pipeline.
    fn push(&self, data: &[u8]) -> Result<(), VncError> {
        self.push_tagged(data, None)
    }

    /// Push a buffer into the pipeline, optionally stamping it with an
    /// explicit PTS (nanoseconds; used as an opaque access-unit tag that
    /// round-trips to the decoded output sample).
    fn push_tagged(&self, data: &[u8], pts: Option<u64>) -> Result<(), VncError> {
        if data.is_empty() {
            return Err(VncError::Protocol("Empty video frame".to_string()));
        }

        let first_16: Vec<String> = data.iter().take(16).map(|b| format!("{:02x}", b)).collect();
        log::trace!(
            "Pushing video frame to GStreamer, {} bytes, first bytes: {}",
            data.len(),
            first_16.join(" ")
        );
        debug_save_h264(data);

        let state = self.state.lock().unwrap();
        let mut buffer = gst::Buffer::from_slice(data.to_vec());
        if let Some(pts) = pts {
            let buf = buffer
                .get_mut()
                .ok_or_else(|| VncError::Protocol("Failed to map buffer as mutable".to_string()))?;
            buf.set_pts(gst::ClockTime::from_nseconds(pts));
        }
        state
            .appsrc
            .push_buffer(buffer)
            .map_err(|e| VncError::Protocol(format!("Push buffer failed: {}", e)))?;
        Ok(())
    }

    /// Pull a decoded sample from the appsink, waiting at most `timeout_ns`
    /// nanoseconds (0 = non-blocking).
    fn pull_sample(&self, timeout_ns: u64) -> Result<Option<gst::Sample>, VncError> {
        let state = self.state.lock().unwrap();
        Ok(state
            .appsink
            .try_pull_sample(gst::ClockTime::from_nseconds(timeout_ns)))
    }

    /// Convert a decoded sample to its access-unit tag plus RGBA pixels.
    ///
    /// The tag round-trips through the buffer PTS (the pipeline has no parser
    /// element, so avdec passes the pushed PTS through to the output frame).
    fn sample_to_tagged_rgba(&self, sample: gst::Sample) -> Result<(u64, Vec<u8>), VncError> {
        let out_pts = sample
            .buffer()
            .and_then(|b| b.pts())
            .map(|t| t.nseconds())
            .unwrap_or(0);
        let rgba = self.sample_to_rgba(sample)?;
        Ok((out_pts, rgba))
    }

    /// Convert a decoded sample to RGBA and update the decoder state.
    fn sample_to_rgba(&self, sample: gst::Sample) -> Result<Vec<u8>, VncError> {
        {
            let mut state = self.state.lock().unwrap();
            state.first_frame_pending = false;
        }

        let buffer = sample
            .buffer()
            .ok_or_else(|| VncError::Protocol("No buffer in sample".to_string()))?;

        let caps = sample
            .caps()
            .ok_or_else(|| VncError::Protocol("No caps in sample".to_string()))?;
        let info = gst_video::VideoInfo::from_caps(caps)
            .map_err(|e| VncError::Protocol(format!("Failed to parse video caps: {}", e)))?;

        {
            let mut state = self.state.lock().unwrap();
            state.last_video_size = Some((info.width() as u16, info.height() as u16));
        }

        let rgba = match info.format() {
            gst_video::VideoFormat::Rgba => {
                log::trace!(
                    "GStreamer decoder produced RGBA {}x{}",
                    info.width(),
                    info.height()
                );
                let map = buffer
                    .map_readable()
                    .map_err(|_| VncError::Protocol("Failed to map buffer".to_string()))?;
                map.as_ref().to_vec()
            }
            gst_video::VideoFormat::Nv12 => {
                log::trace!(
                    "GStreamer decoder produced NV12 {}x{}; converting to RGBA",
                    info.width(),
                    info.height()
                );
                let map = buffer
                    .map_readable()
                    .map_err(|_| VncError::Protocol("Failed to map buffer".to_string()))?;
                let data = map.as_ref();
                let meta = buffer.meta::<gst_video::VideoMeta>().ok_or_else(|| {
                    VncError::Protocol("No video meta for NV12 buffer".to_string())
                })?;

                let offsets = meta.offset();
                let strides = meta.stride();
                if offsets.len() < 2 || strides.len() < 2 {
                    return Err(VncError::Protocol(
                        "Invalid NV12 plane metadata".to_string(),
                    ));
                }

                nv12_to_rgba(
                    data,
                    offsets[0],
                    offsets[1],
                    strides[0] as usize,
                    strides[1] as usize,
                    info.width() as usize,
                    info.height() as usize,
                )
            }
            format => {
                return Err(VncError::Protocol(format!(
                    "Unsupported decoded video format: {:?}",
                    format
                )))
            }
        };

        Ok(rgba)
    }
}

impl Drop for GStreamerDecoder {
    fn drop(&mut self) {
        let state = self.state.lock().unwrap();
        let _ = state.pipeline.set_state(gst::State::Null);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_fixture_h264_frame() {
        // Regression test for the H.264 decoding path. The fixture is a single
        // Annex-B IDR frame generated with GStreamer's x264enc so it does not
        // depend on /tmp state from a live VNC session.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("idr.h264");
        let data = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("failed to read fixture {}: {}", path.display(), e));
        let decoder = GStreamerDecoder::new().expect("create decoder");
        let rgba = decoder.decode_frame(&data).expect("decode frame");
        let (w, h) = decoder.video_size().expect("video size");
        assert_eq!(rgba.len(), (w as usize) * (h as usize) * 4);
        assert_eq!((w, h), (320, 240));
    }

    #[test]
    fn decode_fixture_hevc_frame() {
        // Regression test for the HEVC decoding path. The fixture is a single
        // Annex-B access unit (VPS + SPS + PPS + IDR) captured from an Apple HP
        // session. The input caps declare alignment=au (the media path always
        // pushes complete access units), so a single push decodes immediately;
        // poll a few times to absorb scheduling jitter.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("hevc_au.bin");
        let data = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("failed to read fixture {}: {}", path.display(), e));
        let decoder = GStreamerDecoder::for_codec(Codec::Hevc).expect("create decoder");
        let mut rgba = None;
        for _ in 0..200 {
            if let Some(frame) = decoder.try_decode_frame(&data).expect("push ok") {
                rgba = Some(frame);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let rgba = rgba.expect("decoder should emit a frame");
        let (w, h) = decoder.video_size().expect("video size");
        assert_eq!(rgba.len(), (w as usize) * (h as usize) * 4);
        assert_eq!((w, h), (1920, 272));
    }

    #[test]
    fn decode_au_pts_roundtrips_to_output() {
        // The Apple HP tile compositor relies on the PTS tag stamped on each
        // pushed access unit being carried through to the decoded sample.
        // Push the fixture AU with distinct tags; every output must carry one
        // of those tags.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("hevc_au.bin");
        let data = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("failed to read fixture {}: {}", path.display(), e));
        let decoder = GStreamerDecoder::for_codec(Codec::Hevc).expect("create decoder");
        let mut seen = None;
        for pts in 1..200u64 {
            if let Some((out_pts, rgba)) = decoder.decode_au(&data, pts).expect("push ok") {
                seen = Some((out_pts, rgba));
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let (out_pts, rgba) = seen.expect("decoder should emit a frame");
        assert!(out_pts >= 1 && out_pts < 200, "unexpected pts {}", out_pts);
        let (w, h) = decoder.video_size().expect("video size");
        assert_eq!(rgba.len(), (w as usize) * (h as usize) * 4);
    }
}
