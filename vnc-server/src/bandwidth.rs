//! Bandwidth estimation for the VNC server.
//!
//! Uses Fence round-trip times (RTT) to estimate available bandwidth and
//! decides whether the server should send another frame based on the amount of
//! data currently in flight and a target latency budget.

use std::collections::VecDeque;

use serde::Serialize;

/// A snapshot of bandwidth estimator state, suitable for the control interface.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct BandwidthSnapshot {
    /// Estimated bandwidth in bits per second. Zero means not yet estimated.
    pub bandwidth_bps: f64,
    /// Last measured RTT in microseconds.
    pub rtt_us: u64,
    /// Bytes sent since the last echoed fence.
    pub bytes_inflight: u64,
    /// Target latency budget in microseconds.
    pub target_latency_us: u64,
}

struct Sample {
    bandwidth_bps: f64,
}

/// Conservative bandwidth estimator using a minimum filter over recent samples.
pub struct BandwidthEstimator {
    samples: VecDeque<Sample>,
    bandwidth_bps: f64,
    rtt_us: u64,
    target_latency_us: u64,
    max_samples: usize,
}

impl Default for BandwidthEstimator {
    fn default() -> Self {
        Self::new(50_000)
    }
}

impl BandwidthEstimator {
    /// Create a new estimator with the given target latency in microseconds.
    pub fn new(target_latency_us: u64) -> Self {
        Self {
            samples: VecDeque::new(),
            bandwidth_bps: 0.0,
            rtt_us: 0,
            target_latency_us,
            max_samples: 10,
        }
    }

    /// Update the target latency budget.
    pub fn set_target_latency(&mut self, latency_us: u64) {
        self.target_latency_us = latency_us;
    }

    /// Record a new RTT sample and the bytes that were sent during that window.
    pub fn record_sample(&mut self, bytes_sent: u64, rtt_us: u64) {
        if rtt_us == 0 {
            return;
        }
        let bps = (bytes_sent as f64 * 8.0) / (rtt_us as f64 / 1_000_000.0);
        self.rtt_us = rtt_us;
        self.samples.push_back(Sample { bandwidth_bps: bps });
        if self.samples.len() > self.max_samples {
            self.samples.pop_front();
        }
        // Conservative estimate: take the minimum bandwidth observed in the window.
        self.bandwidth_bps = self
            .samples
            .iter()
            .map(|s| s.bandwidth_bps)
            .fold(f64::MAX, f64::min);
    }

    /// Return true if sending more data is allowed given the current inflight bytes.
    ///
    /// If no bandwidth estimate is available, always allow sending.
    pub fn should_send(&self, bytes_inflight: u64) -> bool {
        if self.bandwidth_bps == 0.0 || bytes_inflight == 0 {
            return true;
        }
        let max_inflight = self.bandwidth_bps * (self.target_latency_us as f64) / 8.0 / 1_000_000.0;
        (bytes_inflight as f64) < max_inflight
    }

    /// Return the current bandwidth estimate in bits per second.
    pub fn bandwidth_bps(&self) -> f64 {
        self.bandwidth_bps
    }

    /// Return a snapshot of the current estimator state.
    pub fn snapshot(&self, bytes_inflight: u64) -> BandwidthSnapshot {
        BandwidthSnapshot {
            bandwidth_bps: self.bandwidth_bps,
            rtt_us: self.rtt_us,
            bytes_inflight,
            target_latency_us: self.target_latency_us,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_estimate_allows_send() {
        let est = BandwidthEstimator::new(50_000);
        assert!(est.should_send(1_000_000));
        assert!(est.should_send(0));
    }

    #[test]
    fn test_sample_and_threshold() {
        let mut est = BandwidthEstimator::new(50_000);
        // 100 KB in 10 ms -> 80 Mbps
        est.record_sample(100 * 1024, 10_000);
        let max_inflight = est.bandwidth_bps * 50_000.0 / 8.0 / 1_000_000.0;
        // Just below the threshold should be allowed.
        assert!(est.should_send((max_inflight * 0.9) as u64));
        // Above the threshold should be denied.
        assert!(!est.should_send((max_inflight * 1.1) as u64));
    }

    #[test]
    fn test_conservative_min_filter() {
        let mut est = BandwidthEstimator::new(50_000);
        // 100 KB in 10 ms -> 80 Mbps
        est.record_sample(100 * 1024, 10_000);
        // 50 KB in 10 ms -> 40 Mbps (lower, should become the estimate)
        est.record_sample(50 * 1024, 10_000);
        // 200 KB in 10 ms -> 160 Mbps (higher, ignored by min filter)
        est.record_sample(200 * 1024, 10_000);
        assert!((est.bandwidth_bps - 40_000_000.0).abs() < 1_000_000.0);
    }

    #[test]
    fn test_latency_update() {
        let mut est = BandwidthEstimator::new(50_000);
        est.record_sample(100 * 1024, 10_000);
        // 100 KB in 10 ms -> ~80 Mbps. At 50ms latency the max inflight is ~500 KB;
        // at 100ms latency it is ~1000 KB. Use 600 KB as the probe value.
        let allowed_50 = est.should_send(600 * 1024);
        est.set_target_latency(100_000);
        let allowed_100 = est.should_send(600 * 1024);
        assert!(!allowed_50);
        assert!(allowed_100);
    }
}
