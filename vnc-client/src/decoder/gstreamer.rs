use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Arc, Mutex, Once};

use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::{AppSink, AppSrc};
use gstreamer_video as gst_video;

use crate::{decoder::VideoDecoder, VncError};

static GST_INIT: Once = Once::new();

fn debug_save_h264(data: &[u8]) {
    let Some(path) = std::env::var_os("OPENCLAW_H264_DEBUG") else {
        return;
    };
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
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
            log::debug!(
                "GStreamer element {} state changed: {:?} -> {:?}",
                state.src().map(|s| s.path_string()).unwrap_or_default(),
                state.old(),
                state.current()
            );
        }
        _ => {}
    }
}

fn log_pipeline_state(pipeline: &gst::Pipeline) {
    let state = pipeline.current_state();
    let pending = pipeline.pending_state();
    log::debug!("Pipeline state: current={:?} pending={:?}", state, pending);

    for elem in pipeline.iterate_elements().into_iter().flatten() {
        let name = elem.path_string();
        let current = elem.current_state();
        let pending = elem.pending_state();
        log::debug!(
            "Element {} state: {:?} pending={:?}",
            name,
            current,
            pending
        );
    }
}

fn log_pipeline_elements(pipeline: &gst::Pipeline) {
    log::debug!("Pipeline elements:");
    for elem in pipeline.iterate_elements().into_iter().flatten() {
        let name = elem.path_string();
        let factory = elem.factory().map(|f| f.name().to_string());
        log::debug!("  {} (factory: {:?})", name, factory);
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

fn build_decoder_pipeline() -> Result<(gst::Pipeline, AppSrc, AppSink), VncError> {
    // Use avdec_h264 directly, bypassing h264parse. h264parse in byte-stream
    // mode requires a trailing start code (or EOS) to flush the last access
    // unit, which we cannot send after every live frame. By claiming the
    // input is parsed and NAL-aligned, avdec_h264 can decode each pushed
    // buffer immediately without needing an EOS.
    let pipeline_str = "appsrc name=src format=bytes \
        caps=video/x-h264,stream-format=(string)byte-stream,alignment=(string)nal,parsed=(boolean)true ! \
        avdec_h264 ! videoconvert ! appsink name=sink";

    log::debug!("Creating GStreamer pipeline: {}", pipeline_str);

    let pipeline = gst::parse::launch(pipeline_str)
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

/// H264 decoder using GStreamer.
///
/// Pipeline: appsrc -> avdec_h264 -> videoconvert -> appsink
///
/// `avdec_h264` is used directly because `h264parse` requires a trailing
/// start code or EOS to flush the final access unit, which is not available
/// when decoding a live stream one frame at a time.
pub struct GStreamerDecoder {
    state: Arc<Mutex<DecoderState>>,
}

impl GStreamerDecoder {
    pub fn new() -> Result<Self, VncError> {
        init_gstreamer()?;
        debug_clear_h264_dump();

        let (pipeline, appsrc, appsink) = build_decoder_pipeline()?;

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

    fn try_decode(&self, data: &[u8], timeout_ns: u64) -> Result<Option<gst::Sample>, VncError> {
        let state = self.state.lock().unwrap();
        let buffer = gst::Buffer::from_slice(data.to_vec());
        state
            .appsrc
            .push_buffer(buffer)
            .map_err(|e| VncError::Protocol(format!("Push buffer failed: {}", e)))?;

        let sample = state
            .appsink
            .try_pull_sample(gst::ClockTime::from_nseconds(timeout_ns));
        Ok(sample)
    }
}

impl VideoDecoder for GStreamerDecoder {
    fn decode_frame(&self, data: &[u8]) -> Result<Vec<u8>, VncError> {
        if data.is_empty() {
            return Err(VncError::Protocol("Empty H264 frame".to_string()));
        }

        let first_16: Vec<String> = data.iter().take(16).map(|b| format!("{:02x}", b)).collect();
        log::debug!(
            "Pushing H264 frame to GStreamer, {} bytes, first bytes: {}",
            data.len(),
            first_16.join(" ")
        );
        debug_save_h264(data);

        let is_first = {
            let state = self.state.lock().unwrap();
            state.first_frame_pending
        };
        let timeout_ns = if is_first {
            3_000 * 1_000_000u64
        } else {
            500 * 1_000_000u64
        };

        let sample = self.try_decode(data, timeout_ns)?;
        let sample = sample.ok_or_else(|| {
            let state = self.state.lock().unwrap();
            log_pipeline_state(&state.pipeline);
            VncError::Protocol("H264 decode timeout or no output".to_string())
        })?;

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
                log::debug!(
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
                log::debug!(
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

    fn video_size(&self) -> Option<(u16, u16)> {
        let state = self.state.lock().unwrap();
        state.last_video_size
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
}
