//! Performance counters for the VNC server.
//!
//! Tracks per-frame capture, encode, and send latencies, and periodically logs
//! a summary. A snapshot is also exposed via the control interface.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use log::info;
use serde::Serialize;

/// A snapshot of performance counters, suitable for JSON serialization.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct PerfSnapshot {
    /// Frames recorded since the last reset/summary.
    pub frames: u64,
    /// Total bytes sent in recorded frames.
    pub total_bytes: u64,
    /// Average frame size in bytes.
    pub avg_frame_bytes: u64,
    /// Average capture time in microseconds.
    pub avg_capture_us: u64,
    /// Average encode time in microseconds.
    pub avg_encode_us: u64,
    /// Average send time in microseconds.
    pub avg_send_us: u64,
    /// Effective frames per second over the sampling window.
    pub fps: f64,
    /// Length of the sampling window in seconds.
    pub window_seconds: f64,
}

/// Rolling performance statistics.
pub struct PerfStats {
    start: Instant,
    last_log: Instant,
    frames: u64,
    total_bytes: u64,
    total_capture_us: u64,
    total_encode_us: u64,
    total_send_us: u64,
    log_interval: Duration,
}

impl Default for PerfStats {
    fn default() -> Self {
        Self::new(Duration::from_secs(5))
    }
}

impl PerfStats {
    /// Create a new performance counter that logs a summary every `log_interval`.
    pub fn new(log_interval: Duration) -> Self {
        let now = Instant::now();
        Self {
            start: now,
            last_log: now,
            frames: 0,
            total_bytes: 0,
            total_capture_us: 0,
            total_encode_us: 0,
            total_send_us: 0,
            log_interval,
        }
    }

    /// Record one frame's timings.
    pub fn record_frame(&mut self, bytes: u64, capture_us: u64, encode_us: u64, send_us: u64) {
        self.frames += 1;
        self.total_bytes += bytes;
        self.total_capture_us += capture_us;
        self.total_encode_us += encode_us;
        self.total_send_us += send_us;
    }

    /// Return a snapshot of the current counters and reset them.
    pub fn snapshot(&mut self) -> PerfSnapshot {
        let elapsed = self.start.elapsed();
        let fps = if elapsed.as_secs_f64() > 0.0 {
            self.frames as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        let avg = |total: u64| total.checked_div(self.frames).unwrap_or(0);
        let snapshot = PerfSnapshot {
            frames: self.frames,
            total_bytes: self.total_bytes,
            avg_frame_bytes: avg(self.total_bytes),
            avg_capture_us: avg(self.total_capture_us),
            avg_encode_us: avg(self.total_encode_us),
            avg_send_us: avg(self.total_send_us),
            fps,
            window_seconds: elapsed.as_secs_f64(),
        };
        self.reset();
        snapshot
    }

    /// Reset counters and the sampling window.
    fn reset(&mut self) {
        let now = Instant::now();
        self.start = now;
        self.last_log = now;
        self.frames = 0;
        self.total_bytes = 0;
        self.total_capture_us = 0;
        self.total_encode_us = 0;
        self.total_send_us = 0;
    }

    /// If the log interval has passed, log a summary and return a snapshot.
    /// Otherwise, return the current running snapshot without resetting.
    pub fn maybe_log(&mut self) -> Option<PerfSnapshot> {
        if self.last_log.elapsed() >= self.log_interval {
            let snapshot = self.snapshot();
            info!(
                "Performance: {:.1} fps, avg frame {:.1} KB, capture {} us, encode {} us, send {} us",
                snapshot.fps,
                snapshot.avg_frame_bytes as f64 / 1024.0,
                snapshot.avg_capture_us,
                snapshot.avg_encode_us,
                snapshot.avg_send_us
            );
            Some(snapshot)
        } else {
            None
        }
    }

    /// Return a non-resetting snapshot of the current counters.
    pub fn current_snapshot(&self) -> PerfSnapshot {
        let elapsed = self.start.elapsed();
        let fps = if elapsed.as_secs_f64() > 0.0 {
            self.frames as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        let avg = |total: u64| total.checked_div(self.frames).unwrap_or(0);
        PerfSnapshot {
            frames: self.frames,
            total_bytes: self.total_bytes,
            avg_frame_bytes: avg(self.total_bytes),
            avg_capture_us: avg(self.total_capture_us),
            avg_encode_us: avg(self.total_encode_us),
            avg_send_us: avg(self.total_send_us),
            fps,
            window_seconds: elapsed.as_secs_f64(),
        }
    }
}

/// Shared performance snapshot, updated by the main loop.
#[derive(Debug, Clone, Default)]
pub struct PerfState {
    pub snapshot: Arc<Mutex<PerfSnapshot>>,
}

impl PerfState {
    pub fn new() -> Self {
        Self {
            snapshot: Arc::new(Mutex::new(PerfSnapshot::default())),
        }
    }

    pub fn update(&self, snapshot: PerfSnapshot) {
        if let Ok(mut guard) = self.snapshot.lock() {
            *guard = snapshot;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perf_record() {
        let mut perf = PerfStats::new(Duration::from_secs(60));
        perf.record_frame(1024, 100, 200, 50);
        perf.record_frame(2048, 150, 250, 75);
        let snap = perf.current_snapshot();
        assert_eq!(snap.frames, 2);
        assert_eq!(snap.total_bytes, 3072);
        assert_eq!(snap.avg_frame_bytes, 1536);
        assert_eq!(snap.avg_capture_us, 125);
        assert_eq!(snap.avg_encode_us, 225);
        assert_eq!(snap.avg_send_us, 62);
    }

    #[test]
    fn test_perf_snapshot_resets() {
        let mut perf = PerfStats::new(Duration::from_secs(60));
        perf.record_frame(1024, 100, 200, 50);
        let snap = perf.snapshot();
        assert_eq!(snap.frames, 1);
        let current = perf.current_snapshot();
        assert_eq!(current.frames, 0);
        assert_eq!(current.total_bytes, 0);
    }
}
