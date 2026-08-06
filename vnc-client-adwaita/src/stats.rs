use vnc_client::ConnectionStats;

pub fn format_stats(stats: &ConnectionStats) -> String {
    format!(
        "{} | {}x{} | {:.1} FPS | RX {}/s | TX {}/s",
        stats.encoding,
        stats.width,
        stats.height,
        stats.fps,
        format_bytes(stats.rx_bytes_per_second),
        format_bytes(stats.tx_bytes_per_second)
    )
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024 * 1024 * 1024) as f64)
    } else if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024 * 1024) as f64)
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}
