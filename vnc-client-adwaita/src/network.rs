use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use gettextrs::gettext;
use gtk4::prelude::WidgetExt;

use crate::settings::HistoryEntry;
use vnc_client::tls::TlsStream;

/// Test whether the VNC server described by `entry` is reachable. For plain
/// TCP this only checks that a TCP connection can be established; for TLS it
/// also performs a TLS handshake.
pub fn test_vnc_reachable(entry: &HistoryEntry) -> bool {
    let timeout = Duration::from_secs(3);
    let addrs: Vec<_> = match format!("{}:{}", entry.host, entry.port).to_socket_addrs() {
        Ok(iter) => iter.collect(),
        Err(e) => {
            log::debug!("Failed to resolve {}: {}", entry.summary(), e);
            return false;
        }
    };
    if addrs.is_empty() {
        return false;
    }

    if entry.use_tls {
        match TcpStream::connect_timeout(&addrs[0], timeout) {
            Ok(tcp) => {
                if let Err(e) = tcp.set_read_timeout(Some(timeout)) {
                    log::debug!("Failed to set read timeout for {}: {}", entry.summary(), e);
                }
                match TlsStream::from_tcp(tcp, &entry.host) {
                    Ok(_) => true,
                    Err(e) => {
                        log::debug!("TLS handshake test failed for {}: {}", entry.summary(), e);
                        false
                    }
                }
            }
            Err(e) => {
                log::debug!("TCP connect test failed for {}: {}", entry.summary(), e);
                false
            }
        }
    } else {
        match TcpStream::connect_timeout(&addrs[0], timeout) {
            Ok(_) => true,
            Err(e) => {
                log::debug!("TCP connect test failed for {}: {}", entry.summary(), e);
                false
            }
        }
    }
}

/// Update the reachability indicator on a history row.
pub fn update_status_dot(dot: &gtk4::Box, reachable: bool) {
    dot.remove_css_class("vnc-status-unknown");
    if reachable {
        dot.remove_css_class("vnc-status-offline");
        dot.add_css_class("vnc-status-online");
        dot.set_tooltip_text(Some(&gettext("Online")));
    } else {
        dot.remove_css_class("vnc-status-online");
        dot.add_css_class("vnc-status-offline");
        dot.set_tooltip_text(Some(&gettext("Offline")));
    }
}
