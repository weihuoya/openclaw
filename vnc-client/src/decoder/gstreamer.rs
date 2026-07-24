use std::sync::Once;

use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app::{AppSink, AppSrc};

use crate::{decoder::VideoDecoder, VncError};

static GST_INIT: Once = Once::new();

fn init_gstreamer() -> Result<(), VncError> {
    let mut result = Ok(());
    GST_INIT.call_once(|| {
        result =
            gst::init().map_err(|e| VncError::Protocol(format!("GStreamer init failed: {}", e)));
    });
    result
}

/// H264 decoder using GStreamer.
///
/// Pipeline: appsrc -> h264parse -> decodebin -> videoconvert -> appsink
///
/// On ROCKNIX with SM8550, `v4l2h264dec` uses the Venus hardware decoder.
/// Falls back to software decoding if hardware is unavailable.
pub struct GStreamerDecoder {
    pipeline: gst::Pipeline,
    appsrc: AppSrc,
    #[allow(dead_code)]
    appsink: AppSink,
}

impl GStreamerDecoder {
    pub fn new() -> Result<Self, VncError> {
        init_gstreamer()?;

        // Try hardware decoder first, then software fallback
        let pipeline_str = "appsrc name=src format=time ! h264parse ! decodebin ! videoconvert ! \
             video/x-raw,format=RGBA ! appsink name=sink";

        let pipeline = gst::parse::launch(pipeline_str)
            .map_err(|e| VncError::Protocol(format!("Pipeline creation failed: {}", e)))?
            .downcast::<gst::Pipeline>()
            .map_err(|_| VncError::Protocol("Failed to cast pipeline".to_string()))?;

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
                .field("format", "RGBA")
                .build(),
        ));

        // Use pull mode for synchronous frame extraction
        appsink.set_property("emit-signals", false);
        appsink.set_property("max-buffers", 1u32);
        appsink.set_property("drop", true);

        pipeline
            .set_state(gst::State::Playing)
            .map_err(|e| VncError::Protocol(format!("Failed to start pipeline: {}", e)))?;

        Ok(Self {
            pipeline,
            appsrc,
            appsink,
        })
    }
}

impl VideoDecoder for GStreamerDecoder {
    fn decode_frame(&self, data: &[u8]) -> Result<Vec<u8>, VncError> {
        // Push H264 NAL unit / frame to appsrc
        let buffer = gst::Buffer::from_slice(data.to_vec());
        self.appsrc
            .push_buffer(buffer)
            .map_err(|e| VncError::Protocol(format!("Push buffer failed: {}", e)))?;

        // Pull decoded frame from appsink (blocking with timeout)
        let timeout = 500 * 1_000_000u64; // 500ms in nanoseconds
        let sample = self
            .appsink
            .try_pull_sample(gst::ClockTime::from_nseconds(timeout))
            .ok_or_else(|| VncError::Protocol("H264 decode timeout or no output".to_string()))?;

        let buffer = sample
            .buffer()
            .ok_or_else(|| VncError::Protocol("No buffer in sample".to_string()))?;
        let map = buffer
            .map_readable()
            .map_err(|_| VncError::Protocol("Failed to map buffer".to_string()))?;

        Ok(map.as_ref().to_vec())
    }

    fn video_size(&self) -> Option<(u16, u16)> {
        let caps = self.appsink.caps()?;
        let structure = caps.structure(0)?;
        let width = structure.get::<i32>("width").ok()? as u16;
        let height = structure.get::<i32>("height").ok()? as u16;
        Some((width, height))
    }
}

impl Drop for GStreamerDecoder {
    fn drop(&mut self) {
        let _ = self.pipeline.set_state(gst::State::Null);
    }
}
