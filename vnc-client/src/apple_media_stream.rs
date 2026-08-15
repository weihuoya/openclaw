#![cfg(not(target_os = "android"))]

//! Apple high-performance media stream receiver (H.264 / HEVC over UDP/SRTP).
//!
//! This module implements the UDP-side media path for Apple HP sessions:
//!
//! * SRTP decryption (AES-256-CTR + HMAC-SHA1-80, RFC 3711 KDF).
//! * SRTCP decryption of incoming RTCP and encryption of outgoing RTCP feedback.
//! * RTP H.264 depayload (single NAL, STAP-A, FU-A) and Apple-style HEVC
//!   depayload (single NAL, AP, FU with per-payload DONL) reassembled into
//!   Annex-B byte-stream NAL units.
//! * Feeding reassembled NAL units into a [`VideoDecoder`] and emitting decoded
//!   frames as [`MediaStreamEvent::Frame`].
//!
//! The module is only available on non-Android targets because the current
//! default decoder (`GStreamerDecoder`) is used for the video path. On Android,
//! Apple HP media is not wired yet.
//!
//! The public entry point is [`AppleMediaStream::start`], which spawns a
//! background thread that owns the UDP socket, the SRTP/SRTCP state, and the
//! decoder. The caller polls the channel through [`AppleMediaStream::try_recv`].
//!
//! The implementation is scoped to the tile layout requested by the `0x1c`
//! offer builder in `apple_media.rs` (HEVC 4-tile / H.264 single-tile). Each
//! tile arrives on its own consecutive SSRC; strips are reassembled per SSRC,
//! decoded with one shared decoder (tiles reference each other across the
//! DPB), and composited into a full-canvas frame. AAC audio is not decoded.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use aes::cipher::{Block, BlockEncrypt, KeyInit};
use aes::Aes256;
use hmac::{Hmac, Mac as HmacMac};
use sha1::Sha1;

use crate::apple_media::{MediaStreamInit, MediaStreamKeys, SRTP_KEY_BLOB_LEN};
use crate::decoder::{Codec, DefaultDecoder, VideoDecoder};
use crate::VncError;

const SRTP_MASTER_KEY_LEN: usize = 32;
const SRTP_MASTER_SALT_LEN: usize = 14;
const SRTP_AUTH_TAG_LEN: usize = 10;
const RTP_HEADER_MIN_LEN: usize = 12;

/// Events emitted by the Apple HP media stream receiver.
#[derive(Debug, Clone)]
pub enum MediaStreamEvent {
    /// A decoded H.264 frame in RGBA format.
    Frame {
        /// Negotiated video width in pixels.
        width: u16,
        /// Negotiated video height in pixels.
        height: u16,
        /// RGBA8888 pixel data, length = width * height * 4.
        rgba: Vec<u8>,
    },
    /// A non-fatal error reported by the receiver thread.
    Error(String),
}

/// Handle to a running Apple HP media stream receiver.
///
/// Dropping the handle stops the background thread and releases the UDP socket
/// and decoder.
pub struct AppleMediaStream {
    stop_tx: Sender<()>,
    handle: Option<JoinHandle<()>>,
    event_rx: Receiver<MediaStreamEvent>,
    resize_tx: Sender<(u16, u16)>,
    keyframe_tx: Sender<()>,
    video_packets: Arc<AtomicU64>,
}

impl AppleMediaStream {
    /// Start a media stream receiver for the H.264 or HEVC video path.
    ///
    /// `server_addr` is the address of the TCP control channel; the video UDP
    /// destination is derived from `init.base_udp_port + 1`. The receiver tries
    /// to bind a local UDP socket on that same port; if it is unavailable, it
    /// falls back to an ephemeral port and relies on the server learning the
    /// source port from our RTCP feedback.
    ///
    /// `canvas_width`/`canvas_height` are the initial video dimensions. The
    /// caller can update them later with [`Self::resize`] once the negotiated
    /// canvas is known from the `0x1c` answer. `codec` selects the RTP
    /// depayload and decoder.
    ///
    /// This function is only available on non-Android targets.
    pub fn start(
        keys: &MediaStreamKeys,
        init: MediaStreamInit,
        server_addr: SocketAddr,
        canvas_width: u16,
        canvas_height: u16,
        codec: Codec,
        decoder: Box<dyn VideoDecoder>,
    ) -> Result<Self, VncError> {
        let (event_tx, event_rx) = mpsc::channel();
        let (stop_tx, stop_rx) = mpsc::channel();
        let (resize_tx, resize_rx) = mpsc::channel();
        let (keyframe_tx, keyframe_rx) = mpsc::channel();
        let video_packets = Arc::new(AtomicU64::new(0));

        let mut worker = MediaStreamWorker::new(
            keys,
            init,
            server_addr,
            codec,
            decoder,
            event_tx,
            stop_rx,
            resize_rx,
            keyframe_rx,
            video_packets.clone(),
        )?;
        worker.set_decoder_size(canvas_width, canvas_height)?;

        let handle = thread::spawn(move || worker.run());

        Ok(Self {
            stop_tx,
            handle: Some(handle),
            event_rx,
            resize_tx,
            keyframe_tx,
            video_packets,
        })
    }

    /// Request a decoder resize at runtime. The worker applies the new size
    /// before feeding the next video frame.
    pub fn resize(&self, width: u16, height: u16) {
        let _ = self.resize_tx.send((width, height));
    }

    /// Ask the worker to request a fresh IDR from the server (FIR/PLI) and to
    /// forget previously seen parameter sets. Used after a `0x1c` re-offer
    /// following a display-layout change, where the encoder restarts its burst.
    pub fn request_keyframe(&self) {
        let _ = self.keyframe_tx.send(());
    }

    /// Number of video RTP packets received so far. Lets callers distinguish
    /// "server never started streaming" (re-offer) from "streaming but not
    /// decoding" (FIR/watchdog territory).
    pub fn video_packets(&self) -> u64 {
        self.video_packets.load(Ordering::Relaxed)
    }

    /// Try to receive the next media stream event without blocking.
    pub fn try_recv(&self) -> Option<MediaStreamEvent> {
        match self.event_rx.try_recv() {
            Ok(event) => Some(event),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => None,
        }
    }
}

impl Drop for AppleMediaStream {
    fn drop(&mut self) {
        let _ = self.stop_tx.send(());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Per-SSRC RTP receive state. Apple's 4-tile HEVC stream carries one
/// horizontal strip per SSRC; FU reassembly and DONL tracking must be
/// isolated per SSRC or fragments from different tiles corrupt each other.
struct TileStream {
    depacketizer: Depacketizer,
    /// Annex-B accumulation of the access unit currently being received.
    /// Flushed to the decoder when a packet with the RTP marker bit arrives.
    au_buf: Vec<u8>,
    /// DONL of the access unit being accumulated (for the LTR-ACK).
    au_donl: Option<u16>,
    last_seq: Option<u16>,
}

struct MediaStreamWorker {
    video_socket: UdpSocket,
    ctrl_socket: UdpSocket,
    server_addr: SocketAddr,
    ctrl_port: u16,
    srtp: SrtpDecryptor,
    srtp_audio_dec: SrtpDecryptor,
    srtcp_dec: SrtcpDecryptor,
    srtcp_enc: SrtcpEncryptor,
    srtp_audio_enc: SrtpEncryptor,
    codec: Codec,
    streams: HashMap<u32, TileStream>,
    /// Ordered tile SSRCs (ascending); the index is the tile/strip number.
    /// Starts with the first SSRC seen and grows to the full consecutive
    /// SSRC run once enough candidates have been observed.
    tile_ssrcs: Vec<u32>,
    /// SSRCs seen on the video socket that are not (yet) adopted as tiles,
    /// with their packet counts.
    candidate_ssrcs: HashMap<u32, u32>,
    server_sr: HashMap<u32, (u32, Instant)>,
    decoder: Box<dyn VideoDecoder>,
    event_tx: Sender<MediaStreamEvent>,
    stop_rx: Receiver<()>,
    resize_rx: Receiver<(u16, u16)>,
    keyframe_rx: Receiver<()>,
    video_ssrc: u32,
    /// Total video RTP packets received (shared with the stream handle).
    video_packets: Arc<AtomicU64>,
    remote_ssrc: Option<u32>,
    last_rtcp: Instant,
    rtcp_tick: u32,
    saw_vps: bool,
    saw_sps: bool,
    saw_pps: bool,
    saw_idr: bool,
    last_ltr_ack_donl: Option<u16>,
    fir_armed: bool,
    fir_last_sent: Option<Instant>,
    last_video_packet: Option<Instant>,
    /// Composition canvas (RGBA) the tile strips are written into.
    canvas: Vec<u8>,
    canvas_w: u32,
    canvas_h: u32,
    /// Canvas dimensions supplied by the caller (backing-store geometry).
    configured_canvas: (u16, u16),
    canvas_dirty: bool,
    last_emit: Instant,
    /// Monotonic access-unit counter, stamped on each AU pushed to the
    /// decoder as its PTS. The parser-less pipeline passes the PTS through
    /// unchanged, so the decoded sample's PTS identifies its access unit.
    au_counter: u64,
    /// PTS → (sender SSRC, DONL) lookup for decoded output frames. The tile
    /// index is resolved from the SSRC at composite time, so AUs pushed
    /// before their SSRC was adopted still land on the right strip.
    au_tags: HashMap<u64, (u32, Option<u16>)>,
    /// Per-tile count of composited strips (diagnostics).
    tile_frames: [u32; 4],
    /// Outputs whose PTS had no outstanding tag (decoder dropped AUs).
    tag_mismatches: u32,
    au_pushed: u32,
    last_stats_log: Instant,
    last_decode_out: Option<Instant>,
    last_decoder_restart: Option<Instant>,
    started: Instant,
    /// Frame-dump state for the OPENCLAW_FRAME_DUMP debug helper.
    dump_path: Option<String>,
    dump_probe_count: u32,
}

impl MediaStreamWorker {
    #[allow(clippy::too_many_arguments)]
    fn new(
        keys: &MediaStreamKeys,
        init: MediaStreamInit,
        server_addr: SocketAddr,
        codec: Codec,
        decoder: Box<dyn VideoDecoder>,
        event_tx: Sender<MediaStreamEvent>,
        stop_rx: Receiver<()>,
        resize_rx: Receiver<(u16, u16)>,
        keyframe_rx: Receiver<()>,
        video_packets: Arc<AtomicU64>,
    ) -> Result<Self, VncError> {
        let base_port = init.base_udp_port;
        let video_port = base_port.wrapping_add(1);

        // Apple rtcp-muxes the control/audio path onto the base UDP port and
        // sends video RTP to base+1. The reference client binds only these two
        // ports (e.g. 5900 for audio/RTCP and 5901 for video). There is no
        // listener on base+2, so do not bind a separate RTCP socket.
        let video_bind = SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), video_port);
        let video_socket = UdpSocket::bind(video_bind)
            .or_else(|_| {
                UdpSocket::bind(SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0))
            })
            .map_err(VncError::Io)?;
        video_socket
            .set_read_timeout(Some(Duration::from_millis(25)))
            .map_err(VncError::Io)?;

        let ctrl_bind = SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), base_port);
        let ctrl_socket = UdpSocket::bind(ctrl_bind)
            .or_else(|_| {
                UdpSocket::bind(SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0))
            })
            .map_err(VncError::Io)?;
        ctrl_socket
            .set_read_timeout(Some(Duration::from_millis(25)))
            .map_err(VncError::Io)?;

        // The 4-tile burst can exceed 200 KB in a few milliseconds; the
        // default UDP receive buffer (~208 KiB) drops packets under that
        // load, and a single lost fragment breaks the LTRP reference chain.
        // Raise both sockets to 4 MiB (the typical net.core.rmem_max).
        for socket in [&video_socket, &ctrl_socket] {
            let sock = socket2::SockRef::from(socket);
            if let Err(e) = sock.set_recv_buffer_size(4 * 1024 * 1024) {
                log::warn!("Apple media stream: failed to raise SO_RCVBUF: {}", e);
            }
        }

        let video_dest = SocketAddr::new(server_addr.ip(), video_port);
        let ctrl_dest = SocketAddr::new(server_addr.ip(), base_port);
        log::info!(
            "Apple media stream: bound local UDP video={:?} ctrl={:?}, \
             punching server video={} ctrl={}",
            video_socket.local_addr().ok(),
            ctrl_socket.local_addr().ok(),
            video_dest,
            ctrl_dest,
        );
        // Firewall-punch: send a zero-length UDP payload to both media ports
        // so NATs/firewalls learn our source address before RTP arrives.
        if let Err(e) = video_socket.send_to(&[0], video_dest) {
            log::warn!(
                "Apple media stream: firewall-punch to {} failed: {}",
                video_dest,
                e
            );
        }
        if let Err(e) = ctrl_socket.send_to(&[0], ctrl_dest) {
            log::warn!(
                "Apple media stream: firewall-punch to {} failed: {}",
                ctrl_dest,
                e
            );
        }

        Ok(Self {
            video_socket,
            ctrl_socket,
            server_addr,
            ctrl_port: base_port,
            srtp: SrtpDecryptor::from_blob(&keys.video_key_s),
            srtp_audio_dec: SrtpDecryptor::from_blob(&keys.audio_key_s),
            srtcp_dec: SrtcpDecryptor::from_blob(&keys.video_key_s),
            srtcp_enc: SrtcpEncryptor::from_blob(&keys.video_key_v),
            srtp_audio_enc: SrtpEncryptor::from_blob(&keys.audio_key_v, keys.audio_ssrc),
            codec,
            streams: HashMap::new(),
            tile_ssrcs: Vec::new(),
            candidate_ssrcs: HashMap::new(),
            decoder,
            event_tx,
            stop_rx,
            resize_rx,
            keyframe_rx,
            video_ssrc: keys.video_ssrc,
            video_packets,
            remote_ssrc: None,
            last_rtcp: Instant::now(),
            rtcp_tick: 0,
            server_sr: HashMap::new(),
            saw_vps: false,
            saw_sps: false,
            saw_pps: false,
            saw_idr: false,
            last_ltr_ack_donl: None,
            fir_armed: false,
            fir_last_sent: None,
            last_video_packet: None,
            canvas: Vec::new(),
            canvas_w: 0,
            canvas_h: 0,
            configured_canvas: (0, 0),
            canvas_dirty: false,
            last_emit: Instant::now(),
            au_counter: 0,
            au_tags: HashMap::new(),
            tile_frames: [0; 4],
            tag_mismatches: 0,
            au_pushed: 0,
            last_stats_log: Instant::now(),
            last_decode_out: None,
            last_decoder_restart: None,
            started: Instant::now(),
            dump_path: std::env::var("OPENCLAW_FRAME_DUMP")
                .ok()
                .filter(|p| !p.is_empty()),
            dump_probe_count: 0,
        })
    }

    fn set_decoder_size(&mut self, width: u16, height: u16) -> Result<(), VncError> {
        if width != 0 && height != 0 {
            self.configured_canvas = (width, height);
            self.decoder.set_size(width, height);
        }
        Ok(())
    }

    fn run(mut self) {
        let mut buf = [0u8; 65536];
        let rtcp_interval = Duration::from_millis(500);

        loop {
            if matches!(
                self.stop_rx.try_recv(),
                Ok(()) | Err(mpsc::TryRecvError::Disconnected)
            ) {
                break;
            }

            while let Ok((width, height)) = self.resize_rx.try_recv() {
                if width != 0 && height != 0 {
                    log::debug!(
                        "Apple media stream: resizing decoder to {}x{}",
                        width,
                        height
                    );
                    if let Err(e) = self.set_decoder_size(width, height) {
                        log::warn!("Apple media stream: resize failed: {}", e);
                    }
                }
            }

            // External keyframe request (e.g. after a 0x1c re-offer triggered
            // by a display-layout change): forget the old parameter sets/IDR
            // state and arm FIR so the restarted encoder burst gets an IDR
            // request immediately.
            while self.keyframe_rx.try_recv().is_ok() {
                log::debug!("Apple media stream: external keyframe request");
                self.saw_vps = false;
                self.saw_sps = false;
                self.saw_pps = false;
                self.saw_idr = false;
                self.fir_armed = true;
                self.fir_last_sent = None;
            }

            if self.last_rtcp.elapsed() >= rtcp_interval {
                self.send_audio_heartbeat();
                self.rtcp_tick = self.rtcp_tick.wrapping_add(1);
                self.send_rtcp_rr();
                self.send_fir_pli();
                self.last_rtcp = Instant::now();
            }
            // If FIR was just armed (param sets seen but no IDR), request the
            // keyframe immediately rather than waiting for the next 500 ms tick.
            if self.fir_armed && self.fir_last_sent.is_none() {
                self.send_fir_pli();
            }

            let mut packets: Vec<(Vec<u8>, SocketAddr, &'static str)> = Vec::new();
            for (socket, label) in [(&self.video_socket, "video"), (&self.ctrl_socket, "ctrl")] {
                match socket.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        packets.push((buf[..n].to_vec(), src, label));
                    }
                    Err(e) => {
                        if e.kind() != std::io::ErrorKind::WouldBlock
                            && e.kind() != std::io::ErrorKind::TimedOut
                        {
                            log::warn!("Apple media stream UDP recv error ({}): {}", label, e);
                        }
                    }
                }
            }
            let received = !packets.is_empty();
            for (pkt, src, label) in &packets {
                let prefix: Vec<String> = pkt[..pkt.len().min(16)]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();
                log::trace!(
                    "Apple media stream: received {} bytes from {} on local {:?} ({}) prefix=[{}]",
                    pkt.len(),
                    src,
                    match *label {
                        "video" => self.video_socket.local_addr(),
                        _ => self.ctrl_socket.local_addr(),
                    },
                    label,
                    prefix.join(" ")
                );
                self.process_packet(pkt, *label == "ctrl");
            }
            // Drain decoder output even when no AU was pushed this iteration:
            // avdec can hold a picture briefly, and the next push may be far
            // away (e.g. while a 50 KB tile strip is still arriving).
            loop {
                match self.decoder.poll_decoded() {
                    Ok(Some((pts, rgba))) => self.handle_decoded(pts, rgba),
                    Ok(None) => break,
                    Err(e) => {
                        log::trace!("Apple media stream decoder poll returned: {}", e);
                        break;
                    }
                }
            }
            // Emit the composed canvas at most ~30 times per second. Tiles
            // update the canvas progressively as their strips decode.
            if self.canvas_dirty
                && !self.canvas.is_empty()
                && self.last_emit.elapsed() >= Duration::from_millis(33)
            {
                self.dump_canvas_frame();
                let _ = self.event_tx.send(MediaStreamEvent::Frame {
                    width: self.canvas_w as u16,
                    height: self.canvas_h as u16,
                    rgba: self.canvas.clone(),
                });
                self.canvas_dirty = false;
                self.last_emit = Instant::now();
            }
            self.maybe_restart_decoder();
            // Rate-limited pipeline statistics for field diagnostics.
            if self.last_stats_log.elapsed() >= Duration::from_secs(2) {
                log::info!(
                    "Apple media stream stats: pushed={} decoded={} tiles={:?} tag_mismatch={} canvas={}x{}",
                    self.au_pushed,
                    self.tile_frames.iter().sum::<u32>(),
                    self.tile_frames,
                    self.tag_mismatches,
                    self.canvas_w,
                    self.canvas_h
                );
                self.last_stats_log = Instant::now();
            }
            if !received {
                // Both sockets timed out; short sleep to avoid busy-spinning
                // when the server is silent.
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    /// Restart the decoder when video packets keep arriving but no frame has
    /// been produced for a few seconds (decoder wedged on corrupted input),
    /// then request a fresh IDR. Suppressed while the server is idle (a
    /// static screen legitimately stops the encoder).
    fn maybe_restart_decoder(&mut self) {
        let Some(last_pkt) = self.last_video_packet else {
            return;
        };
        if last_pkt.elapsed() >= Duration::from_secs(2) {
            return;
        }
        let last_out = self.last_decode_out.unwrap_or(self.started);
        if last_out.elapsed() < Duration::from_secs(4) {
            return;
        }
        if self
            .last_decoder_restart
            .map(|t| t.elapsed() < Duration::from_secs(8))
            .unwrap_or(false)
        {
            return;
        }
        log::warn!(
            "Apple media stream: no decoded frame for {:?} while packets flow",
            last_out.elapsed()
        );
        self.restart_decoder("decode stall");
    }

    /// Track the SSRCs seen on the video socket and maintain the tile group.
    ///
    /// Apple allocates one SSRC per tile as a consecutive run; tile 0 is the
    /// smallest SSRC. The first SSRC seen becomes tile 0 immediately; once
    /// neighbouring SSRCs show up the full run is adopted. The server may
    /// also abandon the burst-time group and continue on a fresh one (e.g.
    /// after a 0x1c re-offer): when the current group stops producing decoded
    /// frames and a new consecutive run forms, switch to it. Adoption never
    /// restarts the decoder — the parameter sets are unchanged across group
    /// changes, so the shared DPB (and its long-term references) stays valid.
    fn note_ssrc(&mut self, ssrc: u32) {
        if self.tile_ssrcs.contains(&ssrc) {
            return;
        }
        if self.tile_ssrcs.is_empty() {
            log::info!("Apple media stream: tile 0 SSRC = 0x{:08x}", ssrc);
            self.tile_ssrcs.push(ssrc);
            return;
        }
        let count = {
            let c = self.candidate_ssrcs.entry(ssrc).or_insert(0);
            *c += 1;
            *c
        };
        if count < 3 {
            return;
        }

        let expected_tiles = match self.codec {
            Codec::Hevc => 4,
            Codec::H264 => 1,
        };
        let longest_run = |pool: &mut Vec<u32>| -> Vec<u32> {
            pool.sort_unstable();
            pool.dedup();
            let mut best: Vec<u32> = Vec::new();
            let mut run: Vec<u32> = Vec::new();
            for &s in pool.iter() {
                if run
                    .last()
                    .map(|&last| s.wrapping_sub(last) <= 1)
                    .unwrap_or(false)
                {
                    run.push(s);
                } else {
                    if run.len() > best.len() {
                        best = std::mem::take(&mut run);
                    }
                    run.push(s);
                }
            }
            if run.len() > best.len() {
                best = run;
            }
            best.truncate(expected_tiles);
            best
        };

        // Only ever adopt a *complete* run of `expected_tiles` consecutive
        // SSRCs (matching the negotiated tiles-per-frame); partial groups
        // would misplace strips and force pointless decoder restarts.
        let recent_decode = self
            .last_decode_out
            .map(|t| t.elapsed() < Duration::from_secs(2))
            .unwrap_or(false);

        let new_group = if self.tile_ssrcs.len() < expected_tiles {
            // Current group incomplete: try to complete it from current tiles
            // plus observed candidates.
            let mut pool = self.tile_ssrcs.clone();
            pool.extend(
                self.candidate_ssrcs
                    .iter()
                    .filter(|(_, &c)| c >= 3)
                    .map(|(&s, _)| s),
            );
            let run = longest_run(&mut pool);
            if run.len() == expected_tiles && run != self.tile_ssrcs {
                Some(run)
            } else {
                None
            }
        } else if !recent_decode {
            // Current group complete but starved: the server may have moved
            // to a new SSRC generation. Switch to a fresh complete run.
            let mut pool: Vec<u32> = self
                .candidate_ssrcs
                .iter()
                .filter(|(_, &c)| c >= 3)
                .map(|(&s, _)| s)
                .collect();
            let run = longest_run(&mut pool);
            if run.len() == expected_tiles && run != self.tile_ssrcs {
                Some(run)
            } else {
                None
            }
        } else {
            None
        };

        let Some(new_group) = new_group else {
            return;
        };
        log::info!(
            "Apple media stream: adopting {}-tile SSRC group {:08x?} (was {:08x?})",
            new_group.len(),
            new_group,
            self.tile_ssrcs
        );
        // Only the tile mapping changes. The decoder keeps running: the new
        // group is the same encoder stream (identical parameter sets,
        // continuous POCs), and every AU keeps being fed regardless of
        // adoption state, so the LTRP reference chain survives the switch.
        self.tile_ssrcs = new_group;
        self.candidate_ssrcs.clear();
        self.canvas_w = 0;
        self.canvas_h = 0;
        self.canvas.clear();
        self.canvas_dirty = false;
    }

    /// Recreate the decoder, drop all stream/composition state, and request
    /// fresh IDRs. Used when the stream generation changes (new SSRC group)
    /// or the decoder appears wedged.
    fn restart_decoder(&mut self, reason: &str) {
        log::warn!("Apple media stream: restarting decoder ({})", reason);
        match DefaultDecoder::for_codec(self.codec) {
            Ok(decoder) => {
                let (w, h) = self.configured_canvas;
                if w != 0 && h != 0 {
                    decoder.set_size(w, h);
                }
                self.decoder = Box::new(decoder);
            }
            Err(e) => {
                log::warn!("Apple media stream: decoder restart failed: {}", e);
            }
        }
        for stream in self.streams.values_mut() {
            stream.au_buf.clear();
            stream.au_donl = None;
        }
        self.au_tags.clear();
        self.canvas_w = 0;
        self.canvas_h = 0;
        self.canvas.clear();
        self.canvas_dirty = false;
        self.last_decode_out = None;
        self.last_decoder_restart = Some(Instant::now());
        self.saw_vps = false;
        self.saw_sps = false;
        self.saw_pps = false;
        self.saw_idr = false;
        self.fir_armed = true;
        self.fir_last_sent = None;
    }

    fn process_packet(&mut self, pkt: &[u8], from_ctrl: bool) {
        if pkt.len() < 2 {
            log::trace!(
                "Apple media stream: dropping short {}-byte packet",
                pkt.len()
            );
            return;
        }
        let pt = pkt[1] & 0x7f;
        // RFC 3550/AVPF: RTCP packet types are 200..207 on the wire (and the
        // obsolete RFC 2032 FIR/NACK types 192/193). Apple's muxed ctrl port
        // carries these as plaintext RTCP headers inside SRTCP; the video port
        // may also carry RTCP (e.g. LTR-ACK). Anything else is RTP.
        const RTCP_TYPES: [u8; 10] = [192, 193, 200, 201, 202, 203, 204, 205, 206, 207];
        if RTCP_TYPES.contains(&pt) {
            if let Some(decrypted) = self.srtcp_dec.unprotect(pkt) {
                log::trace!(
                    "Apple media stream: received RTCP {} bytes",
                    decrypted.len()
                );
                if let Some((ssrc, ntp_mid32)) = parse_rtcp_sr(&decrypted) {
                    self.server_sr.insert(ssrc, (ntp_mid32, Instant::now()));
                    log::debug!(
                        "Apple media stream: server SR ssrc=0x{:08x} ntp_mid32=0x{:08x}",
                        ssrc,
                        ntp_mid32
                    );
                }
            } else {
                log::trace!(
                    "Apple media stream: failed to decrypt SRTCP packet (pt={})",
                    pt
                );
            }
            return;
        }

        let decryptor = if from_ctrl {
            &mut self.srtp_audio_dec
        } else {
            &mut self.srtp
        };
        let Some((header, payload)) = decryptor.decrypt(pkt) else {
            log::trace!(
                "Apple media stream: failed to decrypt SRTP packet (pt={}, ctrl={})",
                pt,
                from_ctrl
            );
            return;
        };

        if header.len() < 12 {
            log::trace!(
                "Apple media stream: decrypted header too short ({} bytes)",
                header.len()
            );
            return;
        }
        let ssrc = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
        let seq = u16::from_be_bytes([header[2], header[3]]);
        let marker = (header[1] & 0x80) != 0;
        let payload_type = header[1] & 0x7f;
        if !from_ctrl {
            self.remote_ssrc = Some(ssrc);
        }
        if payload_type != 100 {
            // Apple uses payload type 100 for both H.264 and HEVC video.
            log::trace!(
                "Apple media stream: dropping non-video RTP packet pt={} ssrc={}",
                payload_type,
                ssrc
            );
            return;
        }
        self.last_video_packet = Some(Instant::now());
        self.video_packets.fetch_add(1, Ordering::Relaxed);
        self.note_ssrc(ssrc);

        // Reassemble this packet's NAL units with the per-SSRC depacketizer
        // and accumulate them into the stream's access-unit buffer. The AU is
        // complete when the packet with the RTP marker bit arrives (Apple
        // zeroes the RTP timestamp, so the marker is the only reliable AU
        // boundary). A sequence gap drops the partial AU: feeding a
        // fragment-missing AU to the shared decoder corrupts the DPB.
        //
        // Every completed AU is fed to the decoder, adopted group member or
        // not. The tile "generations" the daemon cycles through share one
        // encoder with continuous POCs, so AUs from a not-yet-adopted SSRC
        // are links in the reference chain; discarding them (or stashing only
        // the newest) breaks every later P-strip. The tile mapping is only
        // needed to place the decoded strip, which happens at composite time.
        let mut lost_seqs: Vec<u16> = Vec::new();
        let completed_au = {
            let stream = self.streams.entry(ssrc).or_insert_with(|| TileStream {
                depacketizer: Depacketizer::for_codec(self.codec),
                au_buf: Vec::new(),
                au_donl: None,
                last_seq: None,
            });
            if let Some(last) = stream.last_seq {
                let ahead = seq.wrapping_sub(last);
                if ahead != 1 {
                    if (2..=64).contains(&ahead) {
                        // Genuine loss: report every missing sequence number.
                        for missing in 1..ahead {
                            lost_seqs.push(last.wrapping_add(missing));
                        }
                    }
                    if !stream.au_buf.is_empty() {
                        log::debug!(
                            "Apple media stream: seq gap on ssrc=0x{:08x} ({} -> {}), dropping partial AU",
                            ssrc,
                            last,
                            seq
                        );
                        stream.au_buf.clear();
                        stream.au_donl = None;
                        stream.depacketizer.reset_stream();
                    }
                }
            }
            stream.last_seq = Some(seq);

            let mut nals: Vec<Vec<u8>> = Vec::new();
            stream
                .depacketizer
                .feed(&payload, &mut |nal| nals.push(nal.to_vec()));
            log::trace!(
                "Apple media stream: video RTP ssrc=0x{:08x} seq={} payload={} bytes -> {} NALs",
                ssrc,
                seq,
                payload.len(),
                nals.len()
            );
            for nal in &nals {
                stream.au_buf.extend_from_slice(&[0, 0, 0, 1]);
                stream.au_buf.extend_from_slice(nal);
            }
            if let Some(donl) = stream.depacketizer.last_donl() {
                stream.au_donl = Some(donl);
            }
            // Guard against an unbounded buffer if marker packets are lost.
            const MAX_AU_BUF: usize = 8 * 1024 * 1024;
            if stream.au_buf.len() > MAX_AU_BUF {
                log::warn!(
                    "Apple media stream: AU buffer on ssrc=0x{:08x} exceeds {} bytes, dropping",
                    ssrc,
                    MAX_AU_BUF
                );
                stream.au_buf.clear();
                stream.au_donl = None;
            }
            if marker && !stream.au_buf.is_empty() {
                Some((std::mem::take(&mut stream.au_buf), stream.au_donl.take()))
            } else {
                None
            }
        };
        if !lost_seqs.is_empty() {
            // Report the loss immediately: the daemon repairs subsequent
            // P-frames against the last LTR-ACKed picture, which avoids a
            // full IDR round-trip. This is the primary recovery channel.
            self.send_nack(ssrc, &lost_seqs);
        }
        if let Some((au, donl)) = completed_au {
            if let Err(e) = self.feed_au(&au, ssrc, donl) {
                log::warn!("Apple media stream video decode error: {}", e);
            }
        }
    }

    /// Feed one complete access unit (Annex-B, possibly including parameter
    /// sets) to the decoder and composite whatever picture comes out.
    ///
    /// Each AU is stamped with a monotonically increasing PTS tag; the decoded
    /// sample carries the same tag back, which identifies which tile strip the
    /// output picture belongs to — robust against the decoder dropping or
    /// delaying individual units.
    fn feed_au(&mut self, au: &[u8], ssrc: u32, donl: Option<u16>) -> Result<(), VncError> {
        // Scan the AU's NAL types for parameter-set / IDR tracking (the FIR
        // logic below). The buffer is built by us with 4-byte start codes.
        let mut has_param_set = false;
        let mut has_idr = false;
        let mut i = 0;
        while i + 5 <= au.len() {
            if au[i..i + 4] == [0, 0, 0, 1] {
                let first_byte = au[i + 4];
                let nal_type = match self.codec {
                    Codec::H264 => first_byte & 0x1f,
                    Codec::Hevc => (first_byte >> 1) & 0x3f,
                };
                match self.codec {
                    Codec::H264 => {
                        if nal_type == 7 {
                            self.saw_sps = true;
                            has_param_set = true;
                        }
                        if nal_type == 8 {
                            self.saw_pps = true;
                            has_param_set = true;
                        }
                        if nal_type == 5 {
                            has_idr = true;
                        }
                    }
                    Codec::Hevc => {
                        if nal_type == 32 {
                            self.saw_vps = true;
                            has_param_set = true;
                        }
                        if nal_type == 33 {
                            self.saw_sps = true;
                            has_param_set = true;
                        }
                        if nal_type == 34 {
                            self.saw_pps = true;
                            has_param_set = true;
                        }
                        if nal_type == 19 || nal_type == 20 {
                            has_idr = true;
                        }
                    }
                }
                i += 5;
            } else {
                i += 1;
            }
        }
        if has_param_set && !self.saw_idr && !self.fir_armed {
            log::debug!("Apple media stream: param set seen, arming FIR request");
            self.fir_armed = true;
            self.fir_last_sent = None;
        }
        if has_idr {
            log::debug!("Apple media stream: IDR received (ssrc 0x{:08x})", ssrc);
            self.saw_idr = true;
            self.fir_armed = false;
        }

        self.au_counter = self.au_counter.wrapping_add(1);
        let pts = self.au_counter;
        self.au_pushed = self.au_pushed.wrapping_add(1);
        self.au_tags.insert(pts, (ssrc, donl));
        // Bound the map; stale entries belong to AUs the decoder dropped.
        if self.au_tags.len() > 512 {
            self.au_tags.clear();
        }

        match self.decoder.decode_au(au, pts) {
            Ok(Some((out_pts, rgba))) => {
                self.handle_decoded(out_pts, rgba);
            }
            Ok(None) => {}
            Err(e) => {
                // Some decoders return errors for non-picture NALs (e.g. SPS/PPS).
                log::trace!("Apple media stream decoder feed returned: {}", e);
            }
        }
        Ok(())
    }

    /// Composite a freshly decoded picture into the canvas and queue the
    /// LTR-ACK for tile-0 access units.
    fn handle_decoded(&mut self, out_pts: u64, rgba: Vec<u8>) {
        self.last_decode_out = Some(Instant::now());
        let Some((ssrc, au_donl)) = self.au_tags.remove(&out_pts) else {
            // The decoder produced no output for some pushed AU earlier
            // (or the pipeline lost the tag); count and move on.
            self.tag_mismatches = self.tag_mismatches.wrapping_add(1);
            return;
        };
        // Resolve the tile from the SSRC *now*: adoption may have happened
        // between the AU push and the picture coming out.
        let Some(tile) = self.tile_ssrcs.iter().position(|&s| s == ssrc) else {
            log::trace!(
                "Apple media stream: decoded strip from unadopted ssrc=0x{:08x}, skipping",
                ssrc
            );
            return;
        };
        if tile < 4 {
            self.tile_frames[tile] = self.tile_frames[tile].wrapping_add(1);
        }
        log::trace!(
            "Apple media stream: decoded strip tile={} ({} bytes RGBA)",
            tile,
            rgba.len()
        );
        self.composite_strip(tile, &rgba);
        // For HEVC LTRP, acknowledge every decoded tile-0 frame immediately
        // (the reference client sends ~30 of these per second): the encoder
        // uses the last-acked LTR as the reference for future P-frames.
        if tile == 0 && self.codec == Codec::Hevc && self.last_ltr_ack_donl != au_donl {
            self.last_ltr_ack_donl = au_donl;
            if let Some(donl) = au_donl {
                self.send_ltr_ack(donl);
            }
        }
    }

    /// Send a transport-layer NACK (PT=205) for lost sequence numbers of one
    /// media SSRC, prefixed with an empty RR, on the ctrl port.
    fn send_nack(&mut self, media_ssrc: u32, lost: &[u16]) {
        let mut compound = build_rtcp_rr(self.video_ssrc, &[], None);
        compound.extend_from_slice(&build_rtcp_nack(self.video_ssrc, media_ssrc, lost));
        let encrypted = self.srtcp_enc.protect(&compound);
        let ctrl_dest = SocketAddr::new(self.server_addr.ip(), self.ctrl_port);
        if let Err(e) = self.ctrl_socket.send_to(&encrypted, ctrl_dest) {
            log::warn!(
                "Apple media stream NACK send error (ctrl {}): {}",
                ctrl_dest,
                e
            );
        } else {
            log::debug!(
                "Apple media stream: sent NACK ssrc=0x{:08x} lost={} pkts",
                media_ssrc,
                lost.len()
            );
        }
    }

    /// Send one RTCP APP LTR-ACK (PT=204, subtype 5) on the video port.
    fn send_ltr_ack(&mut self, donl: u16) {
        let pkt = build_rtcp_ltrp(self.video_ssrc, donl);
        let encrypted = self.srtcp_enc.protect(&pkt);
        // LTR-ACKs go on the video RTCP-mux port, unlike FIR/PLI/RR.
        let video_dest = SocketAddr::new(self.server_addr.ip(), self.ctrl_port.wrapping_add(1));
        if let Err(e) = self.video_socket.send_to(&encrypted, video_dest) {
            log::warn!(
                "Apple media stream LTR-ACK send error (video {}): {}",
                video_dest,
                e
            );
        } else {
            log::trace!("Apple media stream: sent LTR-ACK DONL={}", donl);
        }
    }

    /// Write a decoded tile strip into the composition canvas.
    ///
    /// Each tile decodes to a full-width strip whose height is the encoder's
    /// CTU-padded slot height (e.g. 544 for a 3840x2160 canvas split in four).
    /// Strips are stacked at `tile * strip_height`; the bottom CTU-padding
    /// rows of the last tile are cropped to the configured canvas height.
    fn composite_strip(&mut self, tile: usize, rgba: &[u8]) {
        let Some((sw, sh)) = self.decoder.video_size() else {
            return;
        };
        let (sw, sh) = (sw as u32, sh as u32);
        if sw == 0 || sh == 0 || rgba.len() < (sw * sh * 4) as usize {
            return;
        }
        let tiles = self.tile_ssrcs.len().max(1) as u32;
        let natural_h = sh * tiles;
        // Prefer the configured (backing-store) canvas height when it matches
        // the tiled geometry within one strip of CTU padding.
        let cfg_h = self.configured_canvas.1 as u32;
        let canvas_h = if cfg_h >= sh && cfg_h <= natural_h {
            cfg_h
        } else {
            natural_h
        };
        if self.canvas_w != sw
            || self.canvas_h != canvas_h
            || self.canvas.len() != (sw * canvas_h * 4) as usize
        {
            self.canvas_w = sw;
            self.canvas_h = canvas_h;
            self.canvas = vec![0u8; (sw * canvas_h * 4) as usize];
            log::info!(
                "Apple media stream: composition canvas {}x{} ({} tiles of {}x{})",
                sw,
                canvas_h,
                tiles,
                sw,
                sh
            );
        }
        let origin_y = tile as u32 * sh;
        if origin_y >= self.canvas_h {
            return;
        }
        let rows = sh.min(self.canvas_h - origin_y) as usize;
        let row_bytes = (sw * 4) as usize;
        for r in 0..rows {
            let dst = (origin_y as usize + r) * self.canvas_w as usize * 4;
            let src = r * row_bytes;
            self.canvas[dst..dst + row_bytes].copy_from_slice(&rgba[src..src + row_bytes]);
        }
        self.canvas_dirty = true;
    }

    /// Debug helper: when `OPENCLAW_FRAME_DUMP` is set, write the composed
    /// canvas to that file as raw RGBA roughly once per second. The file is
    /// prefixed with a 16-byte header: BE u32 width, BE u32 height, 8 bytes
    /// reserved.
    fn dump_canvas_frame(&mut self) {
        let Some(path) = self.dump_path.as_ref() else {
            return;
        };
        self.dump_probe_count = self.dump_probe_count.wrapping_add(1);
        if !self.dump_probe_count.is_multiple_of(30) {
            return;
        }
        let mut out = Vec::with_capacity(16 + self.canvas.len());
        out.extend_from_slice(&self.canvas_w.to_be_bytes());
        out.extend_from_slice(&self.canvas_h.to_be_bytes());
        out.extend_from_slice(&[0u8; 8]);
        out.extend_from_slice(&self.canvas);
        if let Err(e) = std::fs::write(path, &out) {
            log::warn!("Apple media stream: frame dump failed: {}", e);
        }
    }

    fn send_audio_heartbeat(&mut self) {
        const HEARTBEAT_PAYLOAD: &[u8] = &[0x00, 0x68, 0x34, 0x00];
        let pkt = self.srtp_audio_enc.encrypt(HEARTBEAT_PAYLOAD, 101);
        let ctrl_dest = SocketAddr::new(self.server_addr.ip(), self.ctrl_port);
        if let Err(e) = self.ctrl_socket.send_to(&pkt, ctrl_dest) {
            log::warn!(
                "Apple media stream heartbeat send error ({}): {}",
                ctrl_dest,
                e
            );
        }
    }

    fn send_rtcp_rr(&mut self) {
        // Collect stats for the current tile SSRCs. If we have not seen any
        // packets yet, fall back to an empty RR so the control channel stays
        // alive. Dead groups' SSRCs are intentionally excluded: reporting on
        // them confuses AVConference's picture of the receiver.
        let source_ssrcs: Vec<(u32, u32, u16)> = self
            .srtp
            .ssrc_stats()
            .into_iter()
            .filter(|(s, _, _)| self.tile_ssrcs.contains(s))
            .collect();
        // Echo the last server SR NTP timestamp if we have one for the source.
        let sr_data = self
            .remote_ssrc
            .and_then(|s| self.server_sr.get(&s).map(|&(ntp, t)| (s, ntp, t)));
        let mut compound = build_rtcp_rr(self.video_ssrc, &source_ssrcs, sr_data);
        // AVConference expects us to identify as a live sender with an empty SR
        // every few RTCP ticks; the empty SR also keeps the audio SSRC alive.
        if self.rtcp_tick.is_multiple_of(10) {
            let sr = build_rtcp_sr(self.video_ssrc);
            compound.splice(0..0, sr);
        }
        let encrypted = self.srtcp_enc.protect(&compound);
        // Apple rtcp-muxes control RTCP onto the base UDP port.
        let ctrl_dest = SocketAddr::new(self.server_addr.ip(), self.ctrl_port);
        if let Err(e) = self.ctrl_socket.send_to(&encrypted, ctrl_dest) {
            log::warn!(
                "Apple media stream RTCP send error (ctrl {}): {}",
                ctrl_dest,
                e
            );
        }
    }

    fn send_fir_pli(&mut self) {
        if !self.fir_armed {
            return;
        }
        // Request an IDR from tile 0's stream only: Apple emits IDRs on tile
        // 0 alone (cross-tile references re-root the others), and the
        // reference client fires FIR per affected tile. Blasting all four
        // SSRCs appears to get throttled by AVConference.
        let targets: Vec<u32> = if let Some(&first) = self.tile_ssrcs.first() {
            vec![first]
        } else {
            self.remote_ssrc.into_iter().collect()
        };
        if targets.is_empty() {
            return;
        }
        const FIR_INTERVAL: Duration = Duration::from_secs(2);
        if self
            .fir_last_sent
            .map(|t| t.elapsed() < FIR_INTERVAL)
            .unwrap_or(false)
        {
            return;
        }
        // Apple-idle suppression: when the encoder has paused (static
        // screen), a FIR is pointless and only adds churn.
        if self
            .last_video_packet
            .map(|t| t.elapsed() >= Duration::from_millis(1500))
            .unwrap_or(true)
        {
            return;
        }
        self.fir_last_sent = Some(Instant::now());

        // Match the reference client exactly: one SRTCP compound per tile,
        // prefixed with an EMPTY Receiver Report (some peers reject feedback
        // that does not start with SR/RR), then AVPF FIR + PLI + the legacy
        // RFC 2032 FIR that screensharingd reliably answers with an IDR.
        let seq = (self.rtcp_tick & 0xFF) as u8;
        for target_ssrc in &targets {
            let mut compound = build_rtcp_rr(self.video_ssrc, &[], None);
            compound.extend_from_slice(&build_rtcp_fir(self.video_ssrc, *target_ssrc, seq));
            compound.extend_from_slice(&build_rtcp_pli(self.video_ssrc, *target_ssrc));
            compound.extend_from_slice(&build_rtcp_fir_legacy(*target_ssrc));

            let encrypted = self.srtcp_enc.protect(&compound);
            let ctrl_dest = SocketAddr::new(self.server_addr.ip(), self.ctrl_port);
            if let Err(e) = self.ctrl_socket.send_to(&encrypted, ctrl_dest) {
                log::warn!(
                    "Apple media stream FIR/PLI send error (ctrl {}): {}",
                    ctrl_dest,
                    e
                );
            }
        }
        log::info!(
            "Apple media stream: sent FIR/PLI for ssrcs {:08x?} (seq={})",
            targets,
            seq
        );
    }
}

// -----------------------------------------------------------------------------
// SRTP / SRTCP crypto (RFC 3711)
// -----------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct SsrcState {
    roc: u32,
    max_seq: u16,
    initialized: bool,
}

struct SrtpDecryptor {
    cipher_key: [u8; SRTP_MASTER_KEY_LEN],
    auth_key: [u8; 20],
    _salt: [u8; SRTP_MASTER_SALT_LEN],
    salt_int: u128,
    states: HashMap<u32, SsrcState>,
}

impl SrtpDecryptor {
    fn from_blob(blob: &[u8; SRTP_KEY_BLOB_LEN]) -> Self {
        let (master_key, master_salt) = split_blob(blob);
        let cipher_key: [u8; SRTP_MASTER_KEY_LEN] =
            srtp_kdf(&master_key, &master_salt, 0, SRTP_MASTER_KEY_LEN)
                .try_into()
                .expect("SRTP KDF produced 32-byte cipher key");
        let auth_key: [u8; 20] = srtp_kdf(&master_key, &master_salt, 1, 20)
            .try_into()
            .expect("SRTP KDF produced 20-byte auth key");
        let derived_salt: [u8; SRTP_MASTER_SALT_LEN] =
            srtp_kdf(&master_key, &master_salt, 2, SRTP_MASTER_SALT_LEN)
                .try_into()
                .expect("SRTP KDF produced 14-byte salt");
        let salt_int = salt_int(&derived_salt);
        Self {
            cipher_key,
            auth_key,
            _salt: derived_salt,
            salt_int,
            states: HashMap::new(),
        }
    }

    fn decrypt(&mut self, pkt: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        if pkt.len() < RTP_HEADER_MIN_LEN + SRTP_AUTH_TAG_LEN {
            return None;
        }
        let body_len = pkt.len() - SRTP_AUTH_TAG_LEN;
        let seq = u16::from_be_bytes([pkt[2], pkt[3]]);
        let ssrc = u32::from_be_bytes([pkt[8], pkt[9], pkt[10], pkt[11]]);

        let state = self.states.get(&ssrc).copied();
        let roc_guess = if let Some(s) = state {
            let diff = (seq as i32).wrapping_sub(s.max_seq as i32);
            if diff > 0x7fff {
                s.roc.saturating_sub(1)
            } else if diff < -0x7fff {
                s.roc.saturating_add(1)
            } else {
                s.roc
            }
        } else {
            0
        };

        let current_roc = state.map(|s| s.roc).unwrap_or(0);
        let mut candidates = Vec::with_capacity(4);
        let mut push = |r: u32| {
            if !candidates.contains(&r) {
                candidates.push(r);
            }
        };
        push(roc_guess);
        push(current_roc);
        push(roc_guess.saturating_add(1));
        push(roc_guess.saturating_sub(1));

        for roc in candidates {
            if self.verify_auth(pkt, body_len, roc) {
                let header_len = Self::rtp_header_len(pkt, body_len)?;
                let header = pkt[..header_len].to_vec();
                let mut payload = pkt[header_len..body_len].to_vec();
                let index = ((roc as u128) << 16) | (seq as u128);
                let iv = self.salt_int ^ ((ssrc as u128) << 64) ^ (index << 16);
                aes_ctr_inplace(&self.cipher_key, &iv.to_be_bytes(), &mut payload);
                self.update_state(ssrc, roc, seq);
                return Some((header, payload));
            }
        }
        None
    }

    fn rtp_header_len(pkt: &[u8], body_len: usize) -> Option<usize> {
        if body_len < RTP_HEADER_MIN_LEN {
            return None;
        }
        let cc = (pkt[0] & 0x0f) as usize;
        let mut hdr_len = RTP_HEADER_MIN_LEN + cc * 4;
        if (pkt[0] >> 4) & 1 != 0 {
            if hdr_len + 4 > body_len {
                return None;
            }
            let ext_len = (pkt[hdr_len + 2] as usize) << 8 | pkt[hdr_len + 3] as usize;
            hdr_len += 4 + ext_len * 4;
        }
        if hdr_len > body_len {
            return None;
        }
        Some(hdr_len)
    }

    fn verify_auth(&self, pkt: &[u8], body_len: usize, roc: u32) -> bool {
        let mut auth_data = Vec::with_capacity(body_len + 4);
        auth_data.extend_from_slice(&pkt[..body_len]);
        auth_data.extend_from_slice(&roc.to_be_bytes());
        let tag = hmac_sha1_trunc(&self.auth_key, &auth_data, SRTP_AUTH_TAG_LEN);
        pkt[body_len..body_len + SRTP_AUTH_TAG_LEN] == tag[..]
    }

    fn update_state(&mut self, ssrc: u32, roc: u32, seq: u16) {
        let state = self.states.entry(ssrc).or_insert(SsrcState {
            roc: 0,
            max_seq: 0,
            initialized: false,
        });
        if !state.initialized {
            state.roc = roc;
            state.max_seq = seq;
            state.initialized = true;
            return;
        }
        let new_full = ((roc as u64) << 16) | (seq as u64);
        let cur_full = ((state.roc as u64) << 16) | (state.max_seq as u64);
        if new_full > cur_full {
            state.roc = roc;
            state.max_seq = seq;
        }
    }

    fn ssrc_stats(&self) -> Vec<(u32, u32, u16)> {
        self.states
            .iter()
            .map(|(&ssrc, state)| (ssrc, state.roc, state.max_seq))
            .collect()
    }
}

struct SrtcpDecryptor {
    cipher_key: [u8; SRTP_MASTER_KEY_LEN],
    auth_key: [u8; 20],
    salt: [u8; SRTP_MASTER_SALT_LEN],
}

impl SrtcpDecryptor {
    fn from_blob(blob: &[u8; SRTP_KEY_BLOB_LEN]) -> Self {
        let (master_key, master_salt) = split_blob(blob);
        let cipher_key: [u8; SRTP_MASTER_KEY_LEN] =
            srtp_kdf(&master_key, &master_salt, 3, SRTP_MASTER_KEY_LEN)
                .try_into()
                .expect("SRTCP KDF produced 32-byte cipher key");
        let auth_key: [u8; 20] = srtp_kdf(&master_key, &master_salt, 4, 20)
            .try_into()
            .expect("SRTCP KDF produced 20-byte auth key");
        let derived_salt: [u8; SRTP_MASTER_SALT_LEN] =
            srtp_kdf(&master_key, &master_salt, 5, SRTP_MASTER_SALT_LEN)
                .try_into()
                .expect("SRTCP KDF produced 14-byte salt");
        Self {
            cipher_key,
            auth_key,
            salt: derived_salt,
        }
    }

    fn unprotect(&self, pkt: &[u8]) -> Option<Vec<u8>> {
        if pkt.len() < 8 + 4 + SRTP_AUTH_TAG_LEN {
            return None;
        }
        let body_len = pkt.len() - SRTP_AUTH_TAG_LEN;
        let tag = &pkt[body_len..];
        let auth_data = &pkt[..body_len];
        let expected = hmac_sha1_trunc(&self.auth_key, auth_data, SRTP_AUTH_TAG_LEN);
        if tag != &expected[..] {
            return None;
        }
        let e_index = u32::from_be_bytes([
            pkt[body_len - 4],
            pkt[body_len - 3],
            pkt[body_len - 2],
            pkt[body_len - 1],
        ]);
        let encrypted = (e_index & 0x8000_0000) != 0;
        let index = e_index & 0x7fff_ffff;
        let hdr = &pkt[..8];
        let ciphertext = &pkt[8..body_len - 4];

        if !encrypted {
            let mut out = hdr.to_vec();
            out.extend_from_slice(ciphertext);
            return Some(out);
        }

        let ssrc = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(&self.salt);
        iv[4] ^= (ssrc >> 24) as u8;
        iv[5] ^= (ssrc >> 16) as u8;
        iv[6] ^= (ssrc >> 8) as u8;
        iv[7] ^= ssrc as u8;
        let idx_be = index.to_be_bytes();
        iv[10] ^= idx_be[0];
        iv[11] ^= idx_be[1];
        iv[12] ^= idx_be[2];
        iv[13] ^= idx_be[3];

        let mut plaintext = ciphertext.to_vec();
        aes_ctr_inplace(&self.cipher_key, &iv, &mut plaintext);
        let mut out = hdr.to_vec();
        out.extend_from_slice(&plaintext);
        Some(out)
    }
}

struct SrtcpEncryptor {
    cipher_key: [u8; SRTP_MASTER_KEY_LEN],
    auth_key: [u8; 20],
    salt: [u8; SRTP_MASTER_SALT_LEN],
    index: u32,
}

impl SrtcpEncryptor {
    fn from_blob(blob: &[u8; SRTP_KEY_BLOB_LEN]) -> Self {
        let (master_key, master_salt) = split_blob(blob);
        let cipher_key: [u8; SRTP_MASTER_KEY_LEN] =
            srtp_kdf(&master_key, &master_salt, 3, SRTP_MASTER_KEY_LEN)
                .try_into()
                .expect("SRTCP KDF produced 32-byte cipher key");
        let auth_key: [u8; 20] = srtp_kdf(&master_key, &master_salt, 4, 20)
            .try_into()
            .expect("SRTCP KDF produced 20-byte auth key");
        let derived_salt: [u8; SRTP_MASTER_SALT_LEN] =
            srtp_kdf(&master_key, &master_salt, 5, SRTP_MASTER_SALT_LEN)
                .try_into()
                .expect("SRTCP KDF produced 14-byte salt");
        Self {
            cipher_key,
            auth_key,
            salt: derived_salt,
            index: 0,
        }
    }

    fn protect(&mut self, rtcp_pkt: &[u8]) -> Vec<u8> {
        if rtcp_pkt.len() < 8 {
            return rtcp_pkt.to_vec();
        }
        let index = self.index;
        self.index = self.index.wrapping_add(1);

        let hdr = &rtcp_pkt[..8];
        let plaintext = &rtcp_pkt[8..];
        let ssrc = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);

        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(&self.salt);
        iv[4] ^= (ssrc >> 24) as u8;
        iv[5] ^= (ssrc >> 16) as u8;
        iv[6] ^= (ssrc >> 8) as u8;
        iv[7] ^= ssrc as u8;
        let idx_be = index.to_be_bytes();
        iv[10] ^= idx_be[0];
        iv[11] ^= idx_be[1];
        iv[12] ^= idx_be[2];
        iv[13] ^= idx_be[3];

        let mut ciphertext = plaintext.to_vec();
        aes_ctr_inplace(&self.cipher_key, &iv, &mut ciphertext);

        let e_index = (0x8000_0000 | index).to_be_bytes();
        let mut body = hdr.to_vec();
        body.extend_from_slice(&ciphertext);
        body.extend_from_slice(&e_index);
        let tag = hmac_sha1_trunc(&self.auth_key, &body, SRTP_AUTH_TAG_LEN);
        body.extend_from_slice(&tag);
        body
    }
}

struct SrtpEncryptor {
    cipher_key: [u8; SRTP_MASTER_KEY_LEN],
    auth_key: [u8; 20],
    salt_int: u128,
    ssrc: u32,
    seq: u16,
    roc: u32,
}

impl SrtpEncryptor {
    fn from_blob(blob: &[u8; SRTP_KEY_BLOB_LEN], ssrc: u32) -> Self {
        let (master_key, master_salt) = split_blob(blob);
        let cipher_key: [u8; SRTP_MASTER_KEY_LEN] =
            srtp_kdf(&master_key, &master_salt, 0, SRTP_MASTER_KEY_LEN)
                .try_into()
                .expect("SRTP KDF produced 32-byte cipher key");
        let auth_key: [u8; 20] = srtp_kdf(&master_key, &master_salt, 1, 20)
            .try_into()
            .expect("SRTP KDF produced 20-byte auth key");
        let derived_salt: [u8; SRTP_MASTER_SALT_LEN] =
            srtp_kdf(&master_key, &master_salt, 2, SRTP_MASTER_SALT_LEN)
                .try_into()
                .expect("SRTP KDF produced 14-byte salt");
        Self {
            cipher_key,
            auth_key,
            salt_int: salt_int(&derived_salt),
            ssrc,
            seq: 0,
            roc: 0,
        }
    }

    fn encrypt(&mut self, payload: &[u8], pt: u8) -> Vec<u8> {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        if self.seq == 0 {
            self.roc = self.roc.wrapping_add(1);
        }

        let mut header = Vec::with_capacity(12);
        header.push(0x80); // V=2, no CSRC/extension
        header.push(pt);
        header.extend_from_slice(&seq.to_be_bytes());
        header.extend_from_slice(&0u32.to_be_bytes()); // timestamp
        header.extend_from_slice(&self.ssrc.to_be_bytes());

        let index = ((self.roc as u128) << 16) | (seq as u128);
        let iv = self.salt_int ^ ((self.ssrc as u128) << 64) ^ (index << 16);
        let mut encrypted_payload = payload.to_vec();
        aes_ctr_inplace(&self.cipher_key, &iv.to_be_bytes(), &mut encrypted_payload);

        let mut auth_data = Vec::with_capacity(header.len() + encrypted_payload.len() + 4);
        auth_data.extend_from_slice(&header);
        auth_data.extend_from_slice(&encrypted_payload);
        auth_data.extend_from_slice(&self.roc.to_be_bytes());
        let tag = hmac_sha1_trunc(&self.auth_key, &auth_data, SRTP_AUTH_TAG_LEN);

        let mut pkt = header;
        pkt.extend_from_slice(&encrypted_payload);
        pkt.extend_from_slice(&tag);
        pkt
    }
}

fn split_blob(
    blob: &[u8; SRTP_KEY_BLOB_LEN],
) -> ([u8; SRTP_MASTER_KEY_LEN], [u8; SRTP_MASTER_SALT_LEN]) {
    let mut key = [0u8; SRTP_MASTER_KEY_LEN];
    let mut salt = [0u8; SRTP_MASTER_SALT_LEN];
    key.copy_from_slice(&blob[..SRTP_MASTER_KEY_LEN]);
    salt.copy_from_slice(&blob[SRTP_MASTER_KEY_LEN..SRTP_KEY_BLOB_LEN]);
    (key, salt)
}

fn salt_int(salt: &[u8; SRTP_MASTER_SALT_LEN]) -> u128 {
    let mut bytes = [0u8; 16];
    bytes[..14].copy_from_slice(salt);
    u128::from_be_bytes(bytes)
}

fn srtp_kdf(
    master_key: &[u8; SRTP_MASTER_KEY_LEN],
    master_salt: &[u8; SRTP_MASTER_SALT_LEN],
    label: u8,
    out_len: usize,
) -> Vec<u8> {
    let cipher = Aes256::new_from_slice(master_key).expect("valid 32-byte AES-256 key");
    let mut iv = [0u8; 16];
    iv[..7].copy_from_slice(&master_salt[..7]);
    iv[7] = master_salt[7] ^ label;
    iv[8..14].copy_from_slice(&master_salt[8..]);
    // iv[14..16] remain zero, matching the RFC 3711 salt padding.

    let mut out = Vec::with_capacity(out_len);
    let mut counter: u128 = 0;
    while out.len() < out_len {
        let mut block = iv;
        add_be_u128(&mut block, counter);
        let mut e = Block::<Aes256>::clone_from_slice(&block);
        cipher.encrypt_block(&mut e);
        out.extend_from_slice(&e);
        counter += 1;
    }
    out.truncate(out_len);
    out
}

fn add_be_u128(block: &mut [u8; 16], val: u128) {
    let mut carry = val;
    for i in (0..16).rev() {
        let sum = block[i] as u128 + carry;
        block[i] = sum as u8;
        carry = sum >> 8;
        if carry == 0 {
            break;
        }
    }
}

fn aes_ctr_inplace(key: &[u8; SRTP_MASTER_KEY_LEN], iv: &[u8; 16], data: &mut [u8]) {
    let cipher = Aes256::new_from_slice(key).expect("valid 32-byte AES-256 key");
    let mut counter = *iv;
    for chunk in data.chunks_mut(16) {
        let mut block = Block::<Aes256>::clone_from_slice(&counter);
        cipher.encrypt_block(&mut block);
        for i in 0..chunk.len() {
            chunk[i] ^= block[i];
        }
        increment_be(&mut counter);
    }
}

fn increment_be(block: &mut [u8; 16]) {
    for i in (0..16).rev() {
        block[i] = block[i].wrapping_add(1);
        if block[i] != 0 {
            break;
        }
    }
}

fn hmac_sha1_trunc(key: &[u8], data: &[u8], len: usize) -> Vec<u8> {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = <HmacSha1 as HmacMac>::new_from_slice(key).expect("HMAC key of any size");
    mac.update(data);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    bytes[..len.min(bytes.len())].to_vec()
}

fn build_rtcp_rr(
    sender_ssrc: u32,
    source_ssrcs: &[(u32, u32, u16)],
    sr_data: Option<(u32, u32, Instant)>,
) -> Vec<u8> {
    if source_ssrcs.is_empty() {
        let mut rr = Vec::with_capacity(8);
        rr.push(0x80); // V=2, RC=0
        rr.push(201); // PT=RR
        rr.extend_from_slice(&1u16.to_be_bytes()); // length in 32-bit words minus one
        rr.extend_from_slice(&sender_ssrc.to_be_bytes());
        return rr;
    }
    let rc = source_ssrcs.len().min(31) as u8;
    let length = 1 + source_ssrcs.len() as u16 * 6;
    let mut rr = Vec::with_capacity(8 + source_ssrcs.len() * 24);
    rr.push(0x80 | rc); // V=2, RC
    rr.push(201); // PT=RR
    rr.extend_from_slice(&length.to_be_bytes());
    rr.extend_from_slice(&sender_ssrc.to_be_bytes());
    for (ssrc, roc, max_seq) in source_ssrcs.iter().take(31) {
        let ext_seq = ((roc & 0xFFFF) << 16) | (*max_seq as u32);
        let (lsr, dlsr) = if let Some((needle, ntp_mid32, arrival)) = sr_data {
            if needle == *ssrc {
                let elapsed = arrival.elapsed().as_secs_f64();
                (
                    ntp_mid32,
                    (elapsed.clamp(0.0, (u32::MAX as f64) / 65536.0) * 65536.0) as u32,
                )
            } else {
                (0u32, 0u32)
            }
        } else {
            (0u32, 0u32)
        };
        rr.extend_from_slice(&ssrc.to_be_bytes()); // source SSRC
        rr.extend_from_slice(&0u32.to_be_bytes()); // fraction lost | cumulative lost
        rr.extend_from_slice(&ext_seq.to_be_bytes()); // extended highest seq
        rr.extend_from_slice(&0u32.to_be_bytes()); // jitter
        rr.extend_from_slice(&lsr.to_be_bytes()); // LSR
        rr.extend_from_slice(&dlsr.to_be_bytes()); // DLSR
    }
    rr
}

/// Parse an RTCP compound packet and return the NTP middle-32 bits from the
/// first Sender Report, along with the sender SSRC. AVConference expects the
/// receiver to echo this NTP in subsequent Receiver Reports.
fn parse_rtcp_sr(rtcp: &[u8]) -> Option<(u32, u32)> {
    let mut pos = 0;
    while pos + 4 <= rtcp.len() {
        let b0 = rtcp[pos];
        let pt = rtcp[pos + 1];
        let _rc = (b0 & 0x1f) as usize;
        let len_words = u16::from_be_bytes([rtcp[pos + 2], rtcp[pos + 3]]) as usize + 1;
        let pkt_len = len_words * 4;
        if pos + pkt_len > rtcp.len() {
            break;
        }
        if pt == 200 && pkt_len >= 28 {
            let ssrc =
                u32::from_be_bytes([rtcp[pos + 4], rtcp[pos + 5], rtcp[pos + 6], rtcp[pos + 7]]);
            let ntp_sec =
                u32::from_be_bytes([rtcp[pos + 8], rtcp[pos + 9], rtcp[pos + 10], rtcp[pos + 11]]);
            let ntp_frac = u32::from_be_bytes([
                rtcp[pos + 12],
                rtcp[pos + 13],
                rtcp[pos + 14],
                rtcp[pos + 15],
            ]);
            let ntp_mid32 = ((ntp_sec & 0xFFFF) << 16) | ((ntp_frac >> 16) & 0xFFFF);
            return Some((ssrc, ntp_mid32));
        }
        pos += pkt_len;
    }
    None
}

fn build_rtcp_sr(sender_ssrc: u32) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    // NTP timestamp: seconds since 1900-01-01.
    const NTP_EPOCH_DELTA: u64 = 2208988800;
    let ntp_sec = (now as u64) + NTP_EPOCH_DELTA;
    let ntp_frac = ((now - now.floor()) * (1u64 << 32) as f64) as u64;
    // RTP timestamp at 90 kHz (arbitrary origin; AVConference only cares that
    // it advances).
    let rtp_ts = (now * 90000.0) as u32;
    let mut sr = Vec::with_capacity(28);
    sr.push(0x80); // V=2, RC=0
    sr.push(200); // PT=SR
    sr.extend_from_slice(&6u16.to_be_bytes()); // length in 32-bit words minus one
    sr.extend_from_slice(&sender_ssrc.to_be_bytes());
    sr.extend_from_slice(&ntp_sec.to_be_bytes());
    sr.extend_from_slice(&ntp_frac.to_be_bytes());
    sr.extend_from_slice(&rtp_ts.to_be_bytes());
    sr.extend_from_slice(&0u32.to_be_bytes()); // packet count
    sr.extend_from_slice(&0u32.to_be_bytes()); // octet count
    sr
}

// -----------------------------------------------------------------------------
// RTCP feedback packet builders (RFC 2032 / RFC 4585 / RFC 5104 / Apple LTRP)
// -----------------------------------------------------------------------------

/// Legacy Full-INTRA-frame Request (RFC 2032 §5.2.1, PT=192).
/// Native Apple Screen Sharing viewer sends this; screensharingd answers it
/// with a fresh IDR more reliably than the AVPF PT=206 FIR.
fn build_rtcp_fir_legacy(target_ssrc: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.push(0x80); // V=2, RC=0
    out.push(192); // PT=FIR (legacy)
    out.extend_from_slice(&1u16.to_be_bytes()); // length in 32-bit words minus one
    out.extend_from_slice(&target_ssrc.to_be_bytes());
    out
}

/// AVPF Full Intra Request (RFC 5104 §4.3.1.1, PT=206, FMT=4).
fn build_rtcp_fir(sender_ssrc: u32, target_ssrc: u32, seq_nr: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.push(0x80 | 4); // V=2, RC=4
    out.push(206); // PT=PSFB
    out.extend_from_slice(&4u16.to_be_bytes()); // length in 32-bit words minus one
    out.extend_from_slice(&sender_ssrc.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes()); // media SSRC = 0
    out.extend_from_slice(&target_ssrc.to_be_bytes());
    out.push(seq_nr);
    out.extend_from_slice(&[0u8; 3]); // padding
    out
}

/// Picture Loss Indication (RFC 4585 §6.3.1, PT=206, FMT=1).
fn build_rtcp_pli(sender_ssrc: u32, media_ssrc: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.push(0x80 | 1); // V=2, RC=1
    out.push(206); // PT=PSFB
    out.extend_from_slice(&2u16.to_be_bytes()); // length in 32-bit words minus one
    out.extend_from_slice(&sender_ssrc.to_be_bytes());
    out.extend_from_slice(&media_ssrc.to_be_bytes());
    out
}

/// Generic NACK (RFC 4585 §6.2.1, PT=205 FMT=1), with consecutive losses
/// coalesced into PID/BLP entries. The daemon repairs the stream on loss
/// reports by referencing the last LTR-ACKed frame, so honest NACKs are the
/// primary loss-recovery channel (FIR is the backstop).
fn build_rtcp_nack(sender_ssrc: u32, media_ssrc: u32, lost_seqs: &[u16]) -> Vec<u8> {
    let mut fcis = Vec::new();
    let mut i = 0;
    while i < lost_seqs.len() {
        let pid = lost_seqs[i];
        let mut blp: u16 = 0;
        let mut j = i + 1;
        while j < lost_seqs.len() {
            let diff = lost_seqs[j].wrapping_sub(pid);
            if (1..=16).contains(&diff) {
                blp |= 1 << (diff - 1);
                j += 1;
            } else {
                break;
            }
        }
        fcis.extend_from_slice(&pid.to_be_bytes());
        fcis.extend_from_slice(&blp.to_be_bytes());
        i = j;
    }
    let n_fcis = fcis.len() / 4;
    let length_words = (2 + n_fcis) as u16;
    let mut out = Vec::with_capacity(12 + fcis.len());
    out.push(0x80 | 1); // V=2, FMT=1
    out.push(205); // PT=RTPFB (NACK)
    out.extend_from_slice(&length_words.to_be_bytes());
    out.extend_from_slice(&sender_ssrc.to_be_bytes());
    out.extend_from_slice(&media_ssrc.to_be_bytes());
    out.extend_from_slice(&fcis);
    out
}

/// Apple's RTCP APP LTR-ACK (PT=204, subtype 5).
/// Echoes the decoding-order number (DONL) of the last cleanly-decoded HEVC
/// access unit so the encoder can reference it as a long-term picture.
fn build_rtcp_ltrp(sender_ssrc: u32, donl: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.push(0x80); // V=2, RC=0
    out.push(204); // PT=APP
    out.extend_from_slice(&3u16.to_be_bytes()); // length in 32-bit words minus one
    out.extend_from_slice(&sender_ssrc.to_be_bytes());
    out.extend_from_slice(&5u32.to_be_bytes()); // subtype / "name"
    out.extend_from_slice(&(donl as u32).to_be_bytes());
    out
}

// -----------------------------------------------------------------------------
// RTP H.264 depayload (RFC 6184)
// -----------------------------------------------------------------------------

struct H264Depacketizer {
    fu_buffer: Vec<u8>,
    fu_nal_type: u8,
    fu_indicator: u8,
}

impl H264Depacketizer {
    fn new() -> Self {
        Self {
            fu_buffer: Vec::new(),
            fu_nal_type: 0,
            fu_indicator: 0,
        }
    }

    fn feed(&mut self, payload: &[u8], emit: &mut dyn FnMut(&[u8])) {
        if payload.is_empty() {
            return;
        }
        let nal_type = payload[0] & 0x1f;
        match nal_type {
            1..=23 => emit(payload),
            24 => self.stap_a(payload, emit),
            28 => self.fu_a(payload, emit),
            _ => {
                // Other NAL types (e.g. SEI, AUD) are passed through as-is.
                emit(payload);
            }
        }
    }

    fn stap_a(&mut self, payload: &[u8], emit: &mut dyn FnMut(&[u8])) {
        let mut pos = 1;
        while pos + 2 <= payload.len() {
            let len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
            pos += 2;
            if pos + len > payload.len() {
                break;
            }
            emit(&payload[pos..pos + len]);
            pos += len;
        }
    }

    fn fu_a(&mut self, payload: &[u8], emit: &mut dyn FnMut(&[u8])) {
        if payload.len() < 2 {
            return;
        }
        let indicator = payload[0];
        let fu_header = payload[1];
        let start = (fu_header & 0x80) != 0;
        let end = (fu_header & 0x40) != 0;
        let nal_type = fu_header & 0x1f;
        let frag = &payload[2..];

        if start {
            self.fu_indicator = indicator;
            self.fu_nal_type = nal_type;
            self.fu_buffer.clear();
            let reconstructed_nal = (indicator & 0x60) | nal_type;
            self.fu_buffer.push(reconstructed_nal);
        }

        if self.fu_nal_type == nal_type && !self.fu_buffer.is_empty() {
            self.fu_buffer.extend_from_slice(frag);
        }

        if end && !self.fu_buffer.is_empty() {
            emit(&self.fu_buffer);
            self.fu_buffer.clear();
        }
    }
}

// -----------------------------------------------------------------------------
// RTP H.265 / HEVC depayload (Apple variant with DONL)
// -----------------------------------------------------------------------------

/// HEVC RTP depayloader for Apple's adaptive media path.
///
/// Apple deviates from RFC 7798: every payload carries a 2-byte decoding-order
/// number (DONL) right after the (FU) NAL header, and there is no DOND between
/// aggregated sub-NALUs.
///
///   * Single NAL (outer type 0..47): `hdr(2) + DONL(2) + nal_data`
///   * Aggregation Packet (type 48):  `hdr(2) + DONL(2) + [size(2)+nal_data]...`
///   * Fragmentation Unit (type 49):  `hdr(2) + fu_hdr(1) + DONL(2) + frag_data`
///
/// The depayloader reassembles FUs into a single NAL unit and strips DONL from
/// single NALs and AP sub-NALUs. Multi-tile DONL ordering across SSRCs is not
/// implemented; this handles the single-tile path.
struct HevcDepacketizer {
    fu_buffer: Vec<u8>,
    fu_nal_type: u8,
    fu_active: bool,
    last_donl: Option<u16>,
}

impl HevcDepacketizer {
    fn new() -> Self {
        Self {
            fu_buffer: Vec::new(),
            fu_nal_type: 0,
            fu_active: false,
            last_donl: None,
        }
    }

    fn feed(&mut self, payload: &[u8], emit: &mut dyn FnMut(&[u8])) {
        if payload.len() < 2 {
            return;
        }
        let outer_type = (payload[0] >> 1) & 0x3f;
        match outer_type {
            0..=47 => self.single_nal(payload, emit),
            48 => self.ap(payload, emit),
            49 => self.fu(payload, emit),
            _ => {
                // Pass through other NAL types (e.g. SEI, AUD) as-is without DONL.
                self.single_nal(payload, emit);
            }
        }
    }

    fn single_nal(&mut self, payload: &[u8], emit: &mut dyn FnMut(&[u8])) {
        if payload.len() < 4 {
            return;
        }
        self.last_donl = Some(u16::from_be_bytes([payload[2], payload[3]]));
        // Reconstruct NAL unit without DONL.
        let mut nal = Vec::with_capacity(payload.len() - 2);
        nal.extend_from_slice(&payload[..2]);
        nal.extend_from_slice(&payload[4..]);
        emit(&nal);
    }

    fn ap(&mut self, payload: &[u8], emit: &mut dyn FnMut(&[u8])) {
        if payload.len() < 4 {
            return;
        }
        self.last_donl = Some(u16::from_be_bytes([payload[2], payload[3]]));
        let mut pos = 4;
        while pos + 2 <= payload.len() {
            let len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
            pos += 2;
            if pos + len > payload.len() {
                break;
            }
            emit(&payload[pos..pos + len]);
            pos += len;
        }
    }

    fn fu(&mut self, payload: &[u8], emit: &mut dyn FnMut(&[u8])) {
        if payload.len() < 6 {
            return;
        }
        let fu_header = payload[2];
        let start = (fu_header & 0x80) != 0;
        let end = (fu_header & 0x40) != 0;
        let nal_type = fu_header & 0x3f;
        let frag = &payload[5..];

        if start {
            self.last_donl = Some(u16::from_be_bytes([payload[3], payload[4]]));
            self.fu_active = true;
            self.fu_nal_type = nal_type;
            self.fu_buffer.clear();
            // Reconstruct the two-byte NAL header from the FU header's F and
            // type bits, preserving the layer ID and temporal ID from the outer
            // header.
            let hdr0 = (payload[0] & 0x81) | (nal_type << 1);
            self.fu_buffer.push(hdr0);
            self.fu_buffer.push(payload[1]);
            self.fu_buffer.extend_from_slice(frag);
        } else if self.fu_active {
            self.fu_buffer.extend_from_slice(frag);
        }

        if end && self.fu_active {
            emit(&self.fu_buffer);
            self.fu_buffer.clear();
            self.fu_active = false;
        }
    }

    fn last_donl(&self) -> Option<u16> {
        self.last_donl
    }
}

/// Codec-specific RTP depayloader.
enum Depacketizer {
    H264(H264Depacketizer),
    Hevc(HevcDepacketizer),
}

impl Depacketizer {
    fn for_codec(codec: Codec) -> Self {
        match codec {
            Codec::H264 => Self::H264(H264Depacketizer::new()),
            Codec::Hevc => Self::Hevc(HevcDepacketizer::new()),
        }
    }

    fn feed(&mut self, payload: &[u8], emit: &mut dyn FnMut(&[u8])) {
        match self {
            Self::H264(d) => d.feed(payload, emit),
            Self::Hevc(d) => d.feed(payload, emit),
        }
    }

    /// Drop any partially reassembled FU state. Called on an RTP sequence
    /// gap: fragments of the interrupted NAL must not bleed into the next one.
    fn reset_stream(&mut self) {
        match self {
            Self::H264(d) => {
                d.fu_buffer.clear();
                d.fu_nal_type = 0;
            }
            Self::Hevc(d) => {
                d.fu_buffer.clear();
                d.fu_active = false;
            }
        }
    }

    fn last_donl(&self) -> Option<u16> {
        match self {
            Self::H264(_) => None,
            Self::Hevc(d) => d.last_donl(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn aes_ctr_zero_key_iv_matches_aes256_zero_vector() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let mut plaintext = [0u8; 16];
        aes_ctr_inplace(&key, &iv, &mut plaintext);
        assert_eq!(
            plaintext,
            [
                0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89, 0xad, 0x48, 0xa2, 0x14, 0x92, 0x84,
                0x20, 0x87
            ]
        );
    }

    #[test]
    fn srtp_kdf_known_shape() {
        let key = [0xab; SRTP_MASTER_KEY_LEN];
        let salt = [0xcd; SRTP_MASTER_SALT_LEN];
        let cipher = srtp_kdf(&key, &salt, 0, 32);
        assert_eq!(cipher.len(), 32);
        let auth = srtp_kdf(&key, &salt, 1, 20);
        assert_eq!(auth.len(), 20);
    }

    #[test]
    fn srtp_roundtrip() {
        let mut rng = rand::thread_rng();
        let key = {
            let mut k = [0u8; SRTP_MASTER_KEY_LEN];
            rng.fill_bytes(&mut k);
            k
        };
        let salt = {
            let mut s = [0u8; SRTP_MASTER_SALT_LEN];
            rng.fill_bytes(&mut s);
            s
        };
        let ssrc = 0x12345678u32;
        let seq = 0xabcdu16;
        let payload = b"hello srtp";

        // Build an RTP packet manually (12-byte header).
        let mut pkt = Vec::new();
        pkt.push(0x80); // V=2
        pkt.push(100); // PT=100
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes()); // timestamp
        pkt.extend_from_slice(&ssrc.to_be_bytes());
        pkt.extend_from_slice(payload);

        let cipher_key: [u8; 32] = srtp_kdf(&key, &salt, 0, 32).try_into().unwrap();
        let auth_key: [u8; 20] = srtp_kdf(&key, &salt, 1, 20).try_into().unwrap();
        let salt_int = salt_int(&salt);
        let iv = salt_int ^ ((ssrc as u128) << 64) ^ ((seq as u128) << 16);
        let mut encrypted_payload = payload.to_vec();
        aes_ctr_inplace(&cipher_key, &iv.to_be_bytes(), &mut encrypted_payload);

        let mut full_pkt = pkt.clone();
        full_pkt.truncate(12);
        full_pkt.extend_from_slice(&encrypted_payload);
        let auth = hmac_sha1_trunc(
            &auth_key,
            &[&full_pkt[..], &0u32.to_be_bytes()].concat(),
            SRTP_AUTH_TAG_LEN,
        );
        full_pkt.extend_from_slice(&auth);

        let mut dec = SrtpDecryptor {
            cipher_key,
            auth_key,
            _salt: salt,
            salt_int,
            states: HashMap::new(),
        };
        let (header, decrypted) = dec.decrypt(&full_pkt).expect("decrypt");
        assert_eq!(header, &pkt[..12]);
        assert_eq!(&decrypted, payload);
    }

    #[test]
    fn srtcp_roundtrip() {
        let mut rng = rand::thread_rng();
        let key = {
            let mut k = [0u8; SRTP_MASTER_KEY_LEN];
            rng.fill_bytes(&mut k);
            k
        };
        let salt = {
            let mut s = [0u8; SRTP_MASTER_SALT_LEN];
            rng.fill_bytes(&mut s);
            s
        };
        // RTCP RR with sender SSRC 1 and no report blocks.
        let rr = build_rtcp_rr(1, &[], None);
        let mut enc = SrtcpEncryptor::from_blob(&concat_key(&key, &salt));
        let protected = enc.protect(&rr);
        let dec = SrtcpDecryptor::from_blob(&concat_key(&key, &salt));
        let decrypted = dec.unprotect(&protected).expect("unprotect");
        assert_eq!(decrypted, rr);
    }

    #[test]
    fn h264_single_nal_passed_through() {
        let mut dep = H264Depacketizer::new();
        let mut out = Vec::new();
        dep.feed(&[0x65, 0x88, 0x84], &mut |nal| out.push(nal.to_vec()));
        assert_eq!(out, vec![vec![0x65, 0x88, 0x84]]);
    }

    #[test]
    fn h264_fu_a_reassembly() {
        let mut dep = H264Depacketizer::new();
        let mut out = Vec::new();
        // FU-A start fragment for an IDR slice (nal type 5).
        dep.feed(&[0x7c, 0x85, 0x88, 0x84], &mut |nal| out.push(nal.to_vec()));
        assert!(out.is_empty());
        dep.feed(&[0x7c, 0x45, 0x12, 0x34], &mut |nal| out.push(nal.to_vec()));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], vec![0x65, 0x88, 0x84, 0x12, 0x34]);
    }

    #[test]
    fn h264_stap_a_emits_multiple_nals() {
        let mut dep = H264Depacketizer::new();
        let mut out = Vec::new();
        let mut pkt = vec![0x18]; // STAP-A header
        pkt.extend_from_slice(&0x0003u16.to_be_bytes());
        pkt.extend_from_slice(&[0x67, 0x42, 0x00]);
        pkt.extend_from_slice(&0x0002u16.to_be_bytes());
        pkt.extend_from_slice(&[0x68, 0xce]);
        dep.feed(&pkt, &mut |nal| out.push(nal.to_vec()));
        assert_eq!(out, vec![vec![0x67, 0x42, 0x00], vec![0x68, 0xce]]);
    }

    #[test]
    fn hevc_single_nal_strips_donl() {
        let mut dep = HevcDepacketizer::new();
        let mut out = Vec::new();
        // Outer type 19 (IDR_N_LP) => (0x26 >> 1) & 0x3f = 19
        // DONL = 0x0001, then NAL payload.
        let payload = [0x26, 0x01, 0x00, 0x01, 0xab, 0xcd, 0xef];
        dep.feed(&payload, &mut |nal| out.push(nal.to_vec()));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], vec![0x26, 0x01, 0xab, 0xcd, 0xef]);
    }

    #[test]
    fn hevc_ap_emits_sub_nals_without_donl() {
        let mut dep = HevcDepacketizer::new();
        let mut out = Vec::new();
        // AP header type 48: (0x60 >> 1) & 0x3f = 48
        // DONL = 0x0002
        // sub-NAL 1: size 3, [0x40, 0x01, 0x02]
        // sub-NAL 2: size 2, [0x42, 0x00]
        let payload = [
            0x60, 0x01, // AP header
            0x00, 0x02, // DONL
            0x00, 0x03, 0x40, 0x01, 0x02, // sub-NAL 1
            0x00, 0x02, 0x42, 0x00, // sub-NAL 2
        ];
        dep.feed(&payload, &mut |nal| out.push(nal.to_vec()));
        assert_eq!(out, vec![vec![0x40, 0x01, 0x02], vec![0x42, 0x00]]);
    }

    #[test]
    fn hevc_fu_reassembly() {
        let mut dep = HevcDepacketizer::new();
        let mut out = Vec::new();

        // FU start for an IDR_W_RADL slice (inner type 19).
        // Outer header: type 49 -> (0x7e >> 1) & 0x3f = 63? Wait, need type 49.
        // Type 49 = 0x62 -> (0x62 >> 1) & 0x3f = 49.
        // FU header: start=1, type=19 -> 0x93
        // DONL = 0x0005
        let start = [
            0x62, 0x01, // outer header (type 49)
            0x93, // FU header: start + type 19
            0x00, 0x05, // DONL
            0x88, 0x84, // fragment data
        ];

        // FU end.
        let end = [
            0x62, 0x01, // outer header
            0x53, // FU header: end + type 19
            0x00, 0x05, // DONL
            0x12, 0x34, // fragment data
        ];

        dep.feed(&start, &mut |nal| out.push(nal.to_vec()));
        assert!(out.is_empty());
        dep.feed(&end, &mut |nal| out.push(nal.to_vec()));
        assert_eq!(out.len(), 1);
        // Reconstructed NAL header: (0x62 & 0x81) | (19 << 1) = 0x26,
        // second byte preserved from outer header = 0x01.
        assert_eq!(out[0], vec![0x26, 0x01, 0x88, 0x84, 0x12, 0x34]);
    }

    /// Cross-check against the reference client (iShareScreen): the FIR
    /// compound and its SRTCP protection must be byte-identical, otherwise
    /// AVConference silently drops our keyframe requests. Expected values
    /// were produced by running isharescreen's rtcp.py + srtp.py with
    /// blob = bytes(range(46)), sender 0xAABBCCDD, target 0x11223344, seq 7.
    #[test]
    fn fir_compound_srtcp_matches_isharescreen() {
        let mut blob = [0u8; SRTP_KEY_BLOB_LEN];
        for (i, b) in blob.iter_mut().enumerate() {
            *b = i as u8;
        }
        let sender = 0xAABBCCDDu32;
        let target = 0x11223344u32;

        let mut compound = build_rtcp_rr(sender, &[], None);
        compound.extend_from_slice(&build_rtcp_fir(sender, target, 7));
        compound.extend_from_slice(&build_rtcp_pli(sender, target));
        compound.extend_from_slice(&build_rtcp_fir_legacy(target));

        let expected_plain: &[u8] = &[
            0x80, 0xc9, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0x84, 0xce, 0x00, 0x04, 0xaa, 0xbb,
            0xcc, 0xdd, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x07, 0x00, 0x00, 0x00,
            0x81, 0xce, 0x00, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x80, 0xc0,
            0x00, 0x01, 0x11, 0x22, 0x33, 0x44,
        ];
        assert_eq!(compound, expected_plain, "FIR compound plaintext mismatch");

        let idx0: &[u8] = &[
            0x80, 0xc9, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0x86, 0x0f, 0xab, 0xd9, 0x27, 0xbb,
            0xa6, 0xe2, 0x1f, 0x27, 0x70, 0x71, 0xb6, 0x1d, 0xd1, 0xbd, 0x43, 0xb5, 0x7f, 0x56,
            0x41, 0x68, 0x55, 0x35, 0x16, 0x65, 0xc2, 0x1c, 0xc4, 0x68, 0x70, 0xad, 0x29, 0x11,
            0xde, 0x79, 0x84, 0xff, 0xc7, 0xc1, 0x80, 0x00, 0x00, 0x00, 0xb9, 0x27, 0xaa, 0xeb,
            0x8d, 0x2d, 0xd9, 0x64, 0xab, 0x47,
        ];
        let idx1: &[u8] = &[
            0x80, 0xc9, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xd3, 0x90, 0x7c, 0x88, 0x4e, 0xa4,
            0xf3, 0x3d, 0xf1, 0x3d, 0x87, 0xa7, 0xbc, 0x14, 0x7f, 0xe8, 0x01, 0x96, 0x8c, 0x2a,
            0xf4, 0x1e, 0x4d, 0xbe, 0x3d, 0xce, 0x4c, 0x66, 0x22, 0x91, 0x04, 0x95, 0x32, 0xfa,
            0x85, 0xcc, 0x30, 0xb3, 0x08, 0x1f, 0x80, 0x00, 0x00, 0x01, 0x2b, 0xad, 0xee, 0x7f,
            0xe0, 0xb5, 0x24, 0xbc, 0x74, 0xff,
        ];
        let mut enc = SrtcpEncryptor::from_blob(&blob);
        assert_eq!(enc.protect(&compound), idx0, "SRTCP index 0 mismatch");
        assert_eq!(enc.protect(&compound), idx1, "SRTCP index 1 mismatch");
    }

    #[test]
    fn nack_coalesces_consecutive_losses() {
        // Lost 5,6,7 and 20: all fit in one FCI — pid=5 with BLP bits for
        // +1 (6), +2 (7) and +15 (20).
        let pkt = build_rtcp_nack(0xaaaa, 0xbbbb, &[5, 6, 7, 20]);
        assert_eq!(pkt[0], 0x81); // V=2, FMT=1
        assert_eq!(pkt[1], 205); // PT=RTPFB
        let len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        assert_eq!(pkt.len(), (len + 1) * 4);
        assert_eq!(&pkt[4..8], &0xaaaa_u32.to_be_bytes()); // sender
        assert_eq!(&pkt[8..12], &0xbbbb_u32.to_be_bytes()); // media ssrc
                                                            // FCI: pid=5, blp = 0x4003 (lost 6, 7 and 20)
        assert_eq!(&pkt[12..14], &5u16.to_be_bytes());
        assert_eq!(&pkt[14..16], &0x4003u16.to_be_bytes());
        assert_eq!(pkt.len(), 16);
    }

    fn concat_key(key: &[u8; 32], salt: &[u8; 14]) -> [u8; 46] {
        let mut blob = [0u8; 46];
        blob[..32].copy_from_slice(key);
        blob[32..].copy_from_slice(salt);
        blob
    }
}
