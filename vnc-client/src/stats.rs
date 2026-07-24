use std::time::Instant;

use crate::VncStream;

/// Snapshot of connection statistics.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConnectionStats {
    /// Desktop width in pixels.
    pub width: u16,
    /// Desktop height in pixels.
    pub height: u16,
    /// Human-readable name of the most recently used frame encoding.
    pub encoding: String,
    /// Frames per second since the last sample.
    pub fps: f32,
    /// Receive speed in bytes per second.
    pub rx_bytes_per_second: u64,
    /// Transmit speed in bytes per second.
    pub tx_bytes_per_second: u64,
}

/// Tracks internal counters and produces `ConnectionStats` snapshots.
#[derive(Debug)]
pub struct ConnectionStatsTracker {
    last_sample: Instant,
    frame_count: u32,
    last_bytes_read: u64,
    last_bytes_written: u64,
    last_encoding: i32,
}

impl ConnectionStatsTracker {
    pub fn new() -> Self {
        Self {
            last_sample: Instant::now(),
            frame_count: 0,
            last_bytes_read: 0,
            last_bytes_written: 0,
            last_encoding: -1,
        }
    }

    /// Record that one complete framebuffer update message has been processed.
    pub fn record_frame(&mut self, encoding: i32) {
        self.frame_count += 1;
        self.last_encoding = encoding;
    }

    /// Compute a snapshot of current statistics.
    ///
    /// This resets the frame counter and the byte counters, so it should be
    /// called from a single owner (usually the VNC thread) at a regular
    /// interval.
    pub fn sample(
        &mut self,
        width: u16,
        height: u16,
        stream: Option<&VncStream>,
    ) -> ConnectionStats {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_sample).as_secs_f32();

        let (bytes_read, bytes_written) = stream
            .map(|s| (s.bytes_read(), s.bytes_written()))
            .unwrap_or((0, 0));
        let rx_delta = bytes_read.saturating_sub(self.last_bytes_read);
        let tx_delta = bytes_written.saturating_sub(self.last_bytes_written);

        let rx_bps = if elapsed > 0.0 {
            (rx_delta as f32 / elapsed) as u64
        } else {
            0
        };
        let tx_bps = if elapsed > 0.0 {
            (tx_delta as f32 / elapsed) as u64
        } else {
            0
        };
        let fps = if elapsed > 0.0 {
            self.frame_count as f32 / elapsed
        } else {
            0.0
        };

        let encoding = crate::encodings::encoding_name(self.last_encoding).to_string();

        self.last_sample = now;
        self.frame_count = 0;
        self.last_bytes_read = bytes_read;
        self.last_bytes_written = bytes_written;

        ConnectionStats {
            width,
            height,
            encoding,
            fps,
            rx_bytes_per_second: rx_bps,
            tx_bytes_per_second: tx_bps,
        }
    }
}

impl Default for ConnectionStatsTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the most common encoding in a framebuffer update, ignoring
/// pseudo-encodings (negative values).
pub fn most_common_encoding(encodings: &[i32]) -> i32 {
    let mut counts = std::collections::HashMap::<i32, usize>::new();
    for &encoding in encodings {
        if encoding >= 0 {
            *counts.entry(encoding).or_insert(0) += 1;
        }
    }
    counts
        .into_iter()
        .max_by_key(|&(_, count)| count)
        .map(|(encoding, _)| encoding)
        .unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn most_common_ignores_pseudo_encodings() {
        let encodings = vec![16, 16, -239, 16, -240];
        assert_eq!(most_common_encoding(&encodings), 16);
    }

    #[test]
    fn most_common_empty_defaults_to_unknown() {
        assert_eq!(most_common_encoding(&[]), -1);
    }

    #[test]
    fn most_common_all_pseudo_defaults_to_unknown() {
        assert_eq!(most_common_encoding(&[-239, -240]), -1);
    }
}
