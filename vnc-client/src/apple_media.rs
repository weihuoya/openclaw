//! Apple high-performance media stream negotiation (H.264 / HEVC over UDP).
//!
//! This module provides the preliminary pieces needed for the Apple HP adaptive
//! media path:
//!
//! * `build_media_stream_options` — constructs the client→server `0x1c`
//!   MediaStreamOptions offer carrying SRTP master keys and compressed audio +
//!   a single HEVC video codec offer.
//! * `parse_media_stream_answer` — extracts the negotiated canvas dimensions and
//!   tile count from the server→client `0x1c` answer.
//! * `parse_media_stream_init` — extracts UDP port hints from the `0x3f2`
//!   media-init announcement rectangle.
//!
//! The module intentionally does **not** implement UDP socket binding, SRTP,
//! RTP depayload, or the video decoder itself. Those are application-level
//! concerns that build on the negotiated keys and port information exposed here.

use flate2::write::ZlibEncoder;
use flate2::Compression;
use rand::RngCore;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::decoder::Codec;

/// Length of a single SRTP master key blob: 32-byte cipher key + 14-byte salt.
pub const SRTP_KEY_BLOB_LEN: usize = 46;

/// SRTP master key blobs and negotiated SSRCs exchanged in the `0x1c`
/// MediaStreamOptions message.
#[derive(Debug, Clone)]
pub struct MediaStreamKeys {
    /// Audio, viewer → server (used to authenticate outgoing RTCP/SRTCP).
    pub audio_key_v: [u8; SRTP_KEY_BLOB_LEN],
    /// Audio, server → viewer (used to unprotect incoming audio).
    pub audio_key_s: [u8; SRTP_KEY_BLOB_LEN],
    /// Video, viewer → server.
    pub video_key_v: [u8; SRTP_KEY_BLOB_LEN],
    /// Video, server → viewer (used to unprotect incoming video).
    pub video_key_s: [u8; SRTP_KEY_BLOB_LEN],
    /// Audio stream SSRC negotiated in the offer (used for outgoing audio
    /// RTP keepalives).
    pub audio_ssrc: u32,
    /// Video stream SSRC negotiated in the offer (used as the RTCP sender SSRC).
    pub video_ssrc: u32,
}

impl MediaStreamKeys {
    /// Generate fresh random SRTP master key blobs and SSRCs.
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let mut gen = || {
            let mut out = [0u8; SRTP_KEY_BLOB_LEN];
            rng.fill_bytes(&mut out);
            out
        };
        Self {
            audio_key_v: gen(),
            audio_key_s: gen(),
            video_key_v: gen(),
            video_key_s: gen(),
            audio_ssrc: rng.next_u32(),
            video_ssrc: rng.next_u32(),
        }
    }
}

/// Negotiated media stream canvas information parsed from a `0x1c` answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaStreamAnswer {
    /// Video canvas width in luma samples.
    pub canvas_width: u32,
    /// Video canvas height in luma samples.
    pub canvas_height: u32,
    /// Number of tile/SSRC streams (typically 1 or 4).
    pub tile_count: u32,
    /// Selected video codec for the adaptive stream.
    pub codec: Codec,
}

/// Parsed `0x3f2` RFBMediaStreamMessage1 media-init announcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaStreamInit {
    /// Stage: `1` for stage-1 (base UDP port hint), `2` for stage-2 confirmation.
    pub stage: u8,
    /// Base UDP port announced by the server (roles may be swapped in the wild).
    pub base_udp_port: u16,
    /// Stream count reported in the announcement.
    pub stream_count: u16,
    /// Next stream port reported in the announcement.
    pub next_stream_port: u16,
}

/// Build a `0x1c` MediaStreamOptions offer with one audio stream and one video
/// stream.
///
/// `audio_enabled` controls whether the audio offer requests audible system
/// audio or a sub-floor bitrate that suppresses it. The audio section is still
/// present because the daemon treats an empty audio section as a degenerate
/// offer.
///
/// The video offer always advertises both a "HEVC" bank (codec constant 123)
/// and an "AVC" bank (codec constant 100); Apple selects the AVC bank to send
/// an HEVC 4:4:4 stream.
///
/// The returned bytes are the full `0x1c` message body (starting with message
/// type `0x1c`); the caller is responsible for sending it through the Apple HP
/// record layer.
pub fn build_media_stream_options(keys: &MediaStreamKeys, audio_enabled: bool) -> Vec<u8> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let call_id = random_uuid_string();

    let video_offer = build_video_offer(keys.video_ssrc, timestamp);
    let audio_offer = build_audio_offer(keys.audio_ssrc, timestamp, audio_enabled);

    let audio_size = audio_offer.len() as u16;
    let video_size = video_offer.len() as u16;

    // message_size = audio_size + video_size + 0xd8, which is the length from
    // the byte after message_size to the end of the message.
    let message_size = (audio_size as usize + video_size as usize + 0xd8) as u16;

    // Configuration flags. Bit 0 = 60fps stream 1, bit 1 = 60fps stream 2,
    // bit 2 = do not bake cursor into encoded frames. Match the reference
    // client's default console-user offer: bits 0, 1, and 2 are set (value 7).
    let config_flags: u32 = 7;

    let mut msg = Vec::with_capacity(4 + message_size as usize);
    msg.push(0x1c);
    msg.push(0x00);
    msg.extend_from_slice(&message_size.to_be_bytes());
    msg.extend_from_slice(&3u16.to_be_bytes()); // version
    msg.extend_from_slice(&config_flags.to_be_bytes());
    msg.extend_from_slice(&audio_size.to_be_bytes());
    msg.extend_from_slice(&video_size.to_be_bytes());
    msg.extend_from_slice(&[0u8; 6]); // reserved (six bytes matches reference client layout)
    msg.extend_from_slice(&uuid_bytes(&call_id));
    msg.extend_from_slice(&keys.audio_key_v);
    msg.extend_from_slice(&keys.audio_key_s);
    msg.extend_from_slice(&audio_offer);
    msg.extend_from_slice(&keys.video_key_v);
    msg.extend_from_slice(&keys.video_key_s);
    msg.extend_from_slice(&video_offer);

    msg
}

/// Parse the server-side `0x1c` answer and extract the negotiated canvas
/// dimensions and tile count.
///
/// The answer is a binary plist wrapped in a `0x1c` record body. The function
/// searches for `bplist00` markers, parses each candidate, and returns the
/// first one that contains a valid video MediaBlob with non-zero dimensions.
/// Returns `None` if the answer is degenerate (common immediately after a
/// server-side agent transition) or malformed.
pub fn parse_media_stream_answer(answer: &[u8]) -> Option<MediaStreamAnswer> {
    if answer.is_empty() {
        return None;
    }

    let mut idx = 0;
    // The server answer is a binary plist; it may be embedded in a larger record
    // payload, so search for the marker and parse progressively larger slices.
    while let Some(pos) = answer[idx..].windows(8).position(|w| w == b"bplist00") {
        let start = idx + pos;
        for end in (start + 8)..=answer.len() {
            if let Some(plist) = bplist::parse_dict(&answer[start..end]) {
                if let Some(bplist::Value::Data(blob)) =
                    plist.get("avcMediaStreamNegotiatorMediaBlob")
                {
                    let decompressed = zlib_decompress(blob)?;
                    if let Some((cw, ch, ct, codec)) = extract_video_answer_dims(&decompressed) {
                        if cw != 0 && ch != 0 {
                            return Some(MediaStreamAnswer {
                                canvas_width: cw,
                                canvas_height: ch,
                                tile_count: ct,
                                codec,
                            });
                        }
                    }
                }
            }
        }
        idx = start + 1;
    }

    None
}

/// Parse a `0x3f2` media-init announcement rectangle payload.
///
/// The RFB rectangle body has a `u16` length prefix, followed by a fixed
/// 14-byte header. The reference dissector (`mode_adaptive.py`) reads the
/// fields at these offsets relative to the start of the length-prefixed
/// payload (i.e. immediately after the `u16` length):
///
/// * bytes 0..2  — version (`1` for stage 1, `2` for stage 2; some macOS
///   builds emit `0` for the first announcement)
/// * bytes 2..4  — type (`1` for stage 1, `2` for stage 2; often `0` alongside
///   version `0`)
/// * bytes 4..6  — field6 (port hint in the version/type=0 variant)
/// * bytes 6..8  — field8 (stream count in the version/type=0 variant)
/// * bytes 8..10 — field10 (port hint in the version/type=1 stage-1 variant)
/// * bytes 10..14 — field12 (reserved u32)
pub fn parse_media_stream_init(payload: &[u8]) -> Option<MediaStreamInit> {
    if payload.len() < 2 {
        log::debug!(
            "parse_media_stream_init: payload too short ({} bytes)",
            payload.len()
        );
        return None;
    }
    let len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if payload.len() < 2 + len {
        log::debug!(
            "parse_media_stream_init: declared len {} exceeds {} bytes",
            len,
            payload.len() - 2
        );
        return None;
    }
    if len < 14 {
        log::debug!("parse_media_stream_init: body too short (len={})", len);
        return None;
    }
    let body = &payload[2..2 + len];

    let version = u16::from_be_bytes([body[0], body[1]]);
    let stage_type = u16::from_be_bytes([body[2], body[3]]);
    let field6 = u16::from_be_bytes([body[4], body[5]]);
    let field8 = u16::from_be_bytes([body[6], body[7]]);
    let field10 = u16::from_be_bytes([body[8], body[9]]);
    let field12 = u32::from_be_bytes([body[10], body[11], body[12], body[13]]);

    let (stage, base_udp_port, stream_count, next_stream_port) = match (version, stage_type) {
        (1, 1) => (1, field10, field8, field6),
        (2, 2) => (2, 0, field8, 0),
        (0, 0) => {
            // Recent macOS builds emit a (0,0) media-init announcement
            // before the stage-1/2 handshake. In this variant field6 carries
            // the UDP port and field10 the stream count.
            (1, field6, field10, field8)
        }
        _ => (0, 0, 0, 0),
    };

    log::trace!(
        "parse_media_stream_init: version={} type={} field6={} field8={} field10={} field12={} stage={}",
        version,
        stage_type,
        field6,
        field8,
        field10,
        field12,
        stage
    );

    Some(MediaStreamInit {
        stage,
        base_udp_port,
        stream_count,
        next_stream_port,
    })
}

// ---------------------------------------------------------------------------
// Protobuf helpers
// ---------------------------------------------------------------------------

mod protobuf {
    pub fn varint(v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut v = v;
        while v > 0x7F {
            out.push(((v & 0x7F) | 0x80) as u8);
            v >>= 7;
        }
        out.push(v as u8);
        out
    }

    pub fn field_varint(field: u32, value: u64) -> Vec<u8> {
        let tag = field << 3;
        let mut out = varint(tag as u64);
        out.extend(varint(value));
        out
    }

    pub fn field_bytes(field: u32, value: &[u8]) -> Vec<u8> {
        let tag = (field << 3) | 2;
        let mut out = varint(tag as u64);
        out.extend(varint(value.len() as u64));
        out.extend_from_slice(value);
        out
    }

    /// Parse a varint from `data` starting at `pos`. Returns (value, new_pos).
    pub fn read_varint(data: &[u8], pos: usize) -> Option<(u64, usize)> {
        let mut val = 0u64;
        let mut shift = 0u32;
        let mut p = pos;
        while p < data.len() {
            let b = data[p];
            p += 1;
            val |= ((b & 0x7F) as u64) << shift;
            if (b & 0x80) == 0 {
                return Some((val, p));
            }
            shift += 7;
            if shift > 63 {
                return None;
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// bplist helpers (minimal writer + parser for the media-stream shape)
// ---------------------------------------------------------------------------

mod bplist {
    use super::protobuf;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Value {
        Int(u64),
        Data(Vec<u8>),
        String(String),
    }

    /// Build a binary plist containing exactly the four media-negotiation keys
    /// and their values.
    pub fn build_dict(
        remote_endpoint_info: &[u8],
        mode: u64,
        media_blob: &[u8],
        call_id: &str,
    ) -> Vec<u8> {
        let objects: Vec<Vec<u8>> = vec![
            encode_data(remote_endpoint_info),
            encode_int(mode),
            encode_data(media_blob),
            encode_ascii_string(call_id),
            encode_ascii_string("avcMediaStreamOptionRemoteEndpointInfo"),
            encode_ascii_string("avcMediaStreamNegotiatorMode"),
            encode_ascii_string("avcMediaStreamNegotiatorMediaBlob"),
            encode_ascii_string("avcMediaStreamOptionCallID"),
            // Binary plist dict layout: all key refs first, then all value refs.
            encode_dict(4, &[4, 5, 6, 7, 0, 1, 2, 3]),
        ];

        let mut table = Vec::new();
        let mut offsets = Vec::new();
        for obj in &objects {
            // Offsets are absolute file positions, i.e. relative to the start of
            // the bplist00 header (8 bytes).
            offsets.push((8 + table.len()) as u64);
            table.extend_from_slice(obj);
        }

        let offset_table_offset = 8 + table.len();
        let max_offset = offset_table_offset.saturating_add(offsets.len()) as u64;
        let offset_size = (max_offset.checked_ilog2().unwrap_or(0) / 8 + 1) as u8;
        let ref_size = (objects.len().checked_ilog2().unwrap_or(0) / 8 + 1) as u8;
        let num_objects = objects.len() as u64;
        let top_object = 8u64;

        let mut out = Vec::with_capacity(offset_table_offset + offsets.len() + 32);
        out.extend_from_slice(b"bplist00");
        out.extend_from_slice(&table);
        for off in &offsets {
            out.extend_from_slice(&off.to_be_bytes()[(8 - offset_size as usize)..]);
        }
        // 32-byte trailer: 6 unused bytes, offset_size, ref_size, 8-byte counts.
        out.extend_from_slice(&[0u8; 6]);
        out.push(offset_size);
        out.push(ref_size);
        out.extend_from_slice(&num_objects.to_be_bytes());
        out.extend_from_slice(&top_object.to_be_bytes());
        out.extend_from_slice(&(offset_table_offset as u64).to_be_bytes());
        out
    }

    /// Parse a binary plist that is a flat dict with string keys and values
    /// that are either int, data, or ascii string. Returns a map from key to
    /// value. This is intentionally narrow: it only handles the shape produced
    /// by the server in the 0x1c answer.
    pub fn parse_dict(data: &[u8]) -> Option<std::collections::HashMap<String, Value>> {
        if data.len() < 40 || &data[0..8] != b"bplist00" {
            return None;
        }
        let trailer = &data[data.len() - 32..];
        let offset_size = trailer[6] as usize;
        let ref_size = trailer[7] as usize;
        let num_objects = u64::from_be_bytes([
            trailer[8],
            trailer[9],
            trailer[10],
            trailer[11],
            trailer[12],
            trailer[13],
            trailer[14],
            trailer[15],
        ]) as usize;
        let top_object = u64::from_be_bytes([
            trailer[16],
            trailer[17],
            trailer[18],
            trailer[19],
            trailer[20],
            trailer[21],
            trailer[22],
            trailer[23],
        ]) as usize;
        let offset_table_offset = u64::from_be_bytes([
            trailer[24],
            trailer[25],
            trailer[26],
            trailer[27],
            trailer[28],
            trailer[29],
            trailer[30],
            trailer[31],
        ]) as usize;

        if offset_size == 0 || offset_size > 8 || ref_size == 0 || ref_size > 8 {
            return None;
        }
        if offset_table_offset + num_objects * offset_size > data.len() - 32 {
            return None;
        }

        let mut offsets = Vec::with_capacity(num_objects);
        for i in 0..num_objects {
            let off = offset_table_offset + i * offset_size;
            let bytes = &data[off..off + offset_size];
            let mut buf = [0u8; 8];
            buf[8 - offset_size..].copy_from_slice(bytes);
            offsets.push(u64::from_be_bytes(buf) as usize);
        }

        let mut values: Vec<Option<Value>> = Vec::with_capacity(num_objects);
        for _ in 0..num_objects {
            values.push(None);
        }

        let mut result = std::collections::HashMap::new();

        fn read_int(data: &[u8], pos: usize, bytes: Option<usize>) -> Option<(u64, usize)> {
            let b = bytes.unwrap_or(1);
            if pos + b > data.len() {
                return None;
            }
            let mut buf = [0u8; 8];
            buf[8 - b..].copy_from_slice(&data[pos..pos + b]);
            Some((u64::from_be_bytes(buf), pos + b))
        }

        fn read_ref(data: &[u8], pos: usize, ref_size: usize) -> Option<u64> {
            if pos + ref_size > data.len() {
                return None;
            }
            let mut buf = [0u8; 8];
            buf[8 - ref_size..].copy_from_slice(&data[pos..pos + ref_size]);
            Some(u64::from_be_bytes(buf))
        }

        fn read_count(data: &[u8], pos: &mut usize) -> Option<usize> {
            let marker = data.get(*pos).copied()?;
            if (marker & 0xF0) != 0x10 {
                return None;
            }
            let bytes = 1usize << (marker & 0x0F);
            *pos += 1;
            let (v, p) = read_int(data, *pos, Some(bytes))?;
            *pos = p;
            Some(v as usize)
        }

        fn get_value(
            data: &[u8],
            idx: usize,
            offsets: &[usize],
            values: &mut [Option<Value>],
        ) -> Option<Value> {
            if idx >= values.len() {
                return None;
            }
            if let Some(v) = values[idx].clone() {
                return Some(v);
            }
            let off = offsets.get(idx).copied()?;
            if off >= data.len() {
                return None;
            }
            let marker = data[off];
            let kind = marker & 0xF0;
            let info = (marker & 0x0F) as usize;
            let mut pos = off + 1;
            let len = if info < 15 {
                info
            } else {
                read_count(data, &mut pos)?
            };

            let val: Option<Value> = match kind {
                0x10 => {
                    let bytes = 1usize << info;
                    let (v, _) = read_int(data, off + 1, Some(bytes))?;
                    Some(Value::Int(v))
                }
                0x40 => {
                    if pos + len > data.len() {
                        return None;
                    }
                    Some(Value::Data(data[pos..pos + len].to_vec()))
                }
                0x50 => {
                    if pos + len > data.len() {
                        return None;
                    }
                    Some(Value::String(
                        String::from_utf8(data[pos..pos + len].to_vec()).ok()?,
                    ))
                }
                _ => None,
            };
            if let Some(ref v) = val {
                values[idx] = Some(v.clone());
            }
            val
        }

        // The top object must be a dict. Parse it directly.
        if top_object >= num_objects {
            return None;
        }
        let top_offset = offsets[top_object];
        if top_offset >= data.len() {
            return None;
        }
        let marker = data[top_offset];
        if (marker & 0xF0) != 0xD0 {
            return None;
        }
        let info = (marker & 0x0F) as usize;
        let mut pos = top_offset + 1;
        let len = if info < 15 {
            info
        } else {
            read_count(data, &mut pos)?
        };
        // Binary-plist dict layout: all key refs come first, then all value refs.
        if pos + 2 * len * ref_size > data.len() {
            return None;
        }
        for i in 0..len {
            let key_ref = read_ref(data, pos + i * ref_size, ref_size)? as usize;
            let val_ref = read_ref(data, pos + (len + i) * ref_size, ref_size)? as usize;
            let key = match get_value(data, key_ref, &offsets, &mut values) {
                Some(Value::String(s)) => s,
                _ => continue,
            };
            let val = get_value(data, val_ref, &offsets, &mut values)?;
            result.insert(key, val);
        }

        Some(result)
    }

    fn encode_data(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + size_len(data.len()) + data.len());
        out.push(0x40 | len_nibble(data.len()));
        if data.len() >= 15 {
            out.extend(encode_int(data.len() as u64));
        }
        out.extend_from_slice(data);
        out
    }

    fn encode_ascii_string(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(1 + size_len(bytes.len()) + bytes.len());
        out.push(0x50 | len_nibble(bytes.len()));
        if bytes.len() >= 15 {
            out.extend(encode_int(bytes.len() as u64));
        }
        out.extend_from_slice(bytes);
        out
    }

    fn encode_int(v: u64) -> Vec<u8> {
        if v <= u8::MAX as u64 {
            vec![0x10, v as u8]
        } else if v <= u16::MAX as u64 {
            vec![0x11, (v >> 8) as u8, v as u8]
        } else if v <= u32::MAX as u64 {
            let mut out = vec![0x12];
            out.extend_from_slice(&v.to_be_bytes()[4..]);
            out
        } else {
            let mut out = vec![0x13];
            out.extend_from_slice(&v.to_be_bytes());
            out
        }
    }

    fn encode_dict(count: usize, refs: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + size_len(count) + refs.len());
        out.push(0xD0 | len_nibble(count));
        if count >= 15 {
            out.extend(protobuf::varint(count as u64));
        }
        out.extend_from_slice(refs);
        out
    }

    fn len_nibble(len: usize) -> u8 {
        if len < 15 {
            len as u8
        } else {
            0x0F
        }
    }

    fn size_len(len: usize) -> usize {
        if len < 15 {
            0
        } else {
            encode_int(len as u64).len()
        }
    }
}

// ---------------------------------------------------------------------------
// Offer construction
// ---------------------------------------------------------------------------

fn build_video_offer(session_id: u32, timestamp: u64) -> Vec<u8> {
    let tiles = 4u64; // Match Apple's native offer.

    let res_entry = build_resolution_entry(1);
    let res_entry_alt = build_resolution_entry(2);

    // Apple maps the bank labels inversely from the codec they request:
    //   * field1=123 with HEVC parameter string → server sends H.264 4:2:0
    //   * field1=100 with AVC parameter string  → server sends HEVC 4:4:4
    // The reference client advertises both banks (HEVC first); macOS then picks
    // its preferred HEVC 4:4:4 path.
    //
    // Note: the HEVC bank carries four resolution entries, the AVC bank only two.
    // Reversing this or using four entries for both produces a slightly larger
    // offer that the daemon rejects.
    let hevc_bank = build_bank(123, &res_entry, &res_entry_alt, HEVC_PARAMS_LTR, 1);
    let avc_bank = build_bank_two_entries(100, &res_entry, &res_entry_alt, AVC_PARAMS, 14);

    let mut codec_banks = protobuf::field_bytes(3, &hevc_bank);
    codec_banks.extend(protobuf::field_bytes(3, &avc_bank));

    // LTRP is enabled (field 2 and 7) because the preferred HEVC path supports
    // long-term reference pictures.
    let desc = [
        protobuf::field_varint(1, session_id as u64),
        protobuf::field_varint(2, 1),
        codec_banks,
        protobuf::field_varint(6, tiles),
        protobuf::field_varint(7, 1),
        protobuf::field_varint(8, 63),
        protobuf::field_varint(9, 1),
        protobuf::field_varint(12, 1),
    ]
    .concat();
    let desc_field = protobuf::field_bytes(5, &desc);

    let media_blob = build_top_level_mediablob(desc_field, timestamp);
    build_plist(7, &media_blob)
}

fn build_audio_offer(session_id: u32, timestamp: u64, audio_enabled: bool) -> Vec<u8> {
    // Apple sends 24191; a value below the server's tier floor suppresses audio.
    let bitrate = if audio_enabled { 24191 } else { 1000 };
    let desc = [
        protobuf::field_varint(1, session_id as u64),
        protobuf::field_varint(2, 0),
        protobuf::field_varint(3, 0),
        protobuf::field_varint(4, bitrate),
        protobuf::field_varint(5, 0),
        protobuf::field_varint(6, 0),
    ]
    .concat();
    let desc_field = protobuf::field_bytes(3, &desc);
    let media_blob = build_top_level_mediablob(desc_field, timestamp);
    build_plist(8, &media_blob)
}

fn build_top_level_mediablob(desc_field: Vec<u8>, timestamp: u64) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend(protobuf::field_varint(1, 1));
    msg.extend(protobuf::field_varint(2, 1));
    msg.extend(desc_field);
    msg.extend(protobuf::field_bytes(6, b"OpenClaw 0.1.0"));
    msg.extend(protobuf::field_varint(8, 0));
    msg.extend(build_audio_f9_tiers());
    msg.extend(protobuf::field_varint(13, timestamp));
    msg.extend(protobuf::field_varint(14, 2));
    msg.extend(protobuf::field_varint(16, 0));
    msg.extend(protobuf::field_varint(18, 1));
    zlib_compress(&msg)
}

fn build_resolution_entry(field2: u64) -> Vec<u8> {
    [
        protobuf::field_varint(1, 1),
        protobuf::field_varint(2, field2),
        protobuf::field_varint(3, 50115),
        protobuf::field_varint(4, 0),
    ]
    .concat()
}

fn build_bank(
    codec_constant: u64,
    res_entry: &[u8],
    res_entry_alt: &[u8],
    params: &[u8],
    field4: u64,
) -> Vec<u8> {
    let mut bank = Vec::new();
    bank.extend(protobuf::field_varint(1, codec_constant));
    bank.extend(protobuf::field_bytes(2, res_entry));
    bank.extend(protobuf::field_bytes(2, res_entry_alt));
    bank.extend(protobuf::field_bytes(2, res_entry));
    bank.extend(protobuf::field_bytes(2, res_entry_alt));
    bank.extend(protobuf::field_bytes(3, params));
    bank.extend(protobuf::field_varint(4, field4));
    bank
}

fn build_bank_two_entries(
    codec_constant: u64,
    res_entry: &[u8],
    res_entry_alt: &[u8],
    params: &[u8],
    field4: u64,
) -> Vec<u8> {
    let mut bank = Vec::new();
    bank.extend(protobuf::field_varint(1, codec_constant));
    bank.extend(protobuf::field_bytes(2, res_entry));
    bank.extend(protobuf::field_bytes(2, res_entry_alt));
    bank.extend(protobuf::field_bytes(3, params));
    bank.extend(protobuf::field_varint(4, field4));
    bank
}

fn build_audio_f9_tiers() -> Vec<u8> {
    const TIERS: &[(u64, u64, Option<u64>)] = &[
        (0, 40_000_000, Some(12288)),
        (0, 6_000_000, Some(131_072)),
        (4074, 0, Some(16_384)),
        (16, 4100, None),
        (0, 75_000_000, Some(524_288)),
        (0, 20_000_000, Some(98_304)),
        (4, 6500, None),
        (0, 60_000_000, Some(262_144)),
        (1, 299, None),
        (0, 100_000_000, Some(1_048_576)),
    ];

    let mut body = Vec::new();
    for &(f1, f2, f3) in TIERS {
        let mut entry = Vec::new();
        entry.extend(protobuf::field_varint(1, f1));
        entry.extend(protobuf::field_varint(2, f2));
        if let Some(f3) = f3 {
            entry.extend(protobuf::field_varint(3, f3));
        }
        body.extend(protobuf::field_bytes(9, &entry));
    }
    body
}

fn build_remote_endpoint_info() -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(b"\x08\x00"); // field 1 = 0
    info.extend_from_slice(b"\x10\x01"); // field 2 = 1
                                         // Match the reference client's RemoteEndpointInfo shape: capitalised OS name
                                         // and a real-looking build string. The daemon treats this as informational,
                                         // but lowercase/empty strings differ on the wire.
    let hw_model = format!(
        "{}-{}",
        capitalise_first(std::env::consts::OS),
        std::env::consts::ARCH
    );
    info.extend(protobuf_str_field(3, &hw_model));
    info.extend(protobuf_str_field(4, "1.0.0"));
    // Use the running kernel/build string instead of a hard-coded "0" so the
    // offer resembles a real viewer endpoint.
    let os_build = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "0".to_string());
    info.extend(protobuf_str_field(5, &os_build));
    info
}

fn capitalise_first(s: &str) -> String {
    if s.is_empty() {
        return s.to_string();
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap().to_uppercase().collect::<String>();
    first + chars.as_str()
}

fn protobuf_str_field(field: u32, s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let tag = (field << 3) | 2;
    let mut out = protobuf::varint(tag as u64);
    out.extend(protobuf::varint(bytes.len() as u64));
    out.extend_from_slice(bytes);
    out
}

fn build_plist(mode: u64, media_blob: &[u8]) -> Vec<u8> {
    bplist::build_dict(
        &build_remote_endpoint_info(),
        mode,
        media_blob,
        &random_uuid_string(),
    )
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

fn extract_video_answer_dims(blob: &[u8]) -> Option<(u32, u32, u32, Codec)> {
    let mut pos = 0;
    let mut canvas_w = 0u32;
    let mut canvas_h = 0u32;
    let mut tile_count = 0u32;
    let mut codec = None;
    while pos < blob.len() {
        let (tag, p) = protobuf::read_varint(blob, pos)?;
        pos = p;
        let field = tag >> 3;
        let wt = tag & 7;
        match wt {
            0 => {
                let (_, p) = protobuf::read_varint(blob, pos)?;
                pos = p;
            }
            2 => {
                let (len, p) = protobuf::read_varint(blob, pos)?;
                pos = p;
                if field == 5 {
                    let sub = &blob[pos..pos + len as usize];
                    let mut sp = 0;
                    while sp < sub.len() {
                        let (st, p2) = protobuf::read_varint(sub, sp)?;
                        sp = p2;
                        let sf = st >> 3;
                        let sw = st & 7;
                        match sw {
                            0 => {
                                let (v, p2) = protobuf::read_varint(sub, sp)?;
                                sp = p2;
                                match sf {
                                    4 => canvas_w = v as u32,
                                    5 => canvas_h = v as u32,
                                    6 => tile_count = v as u32,
                                    _ => {}
                                }
                            }
                            2 => {
                                let (l, p2) = protobuf::read_varint(sub, sp)?;
                                if sf == 3 && l as usize <= sub.len().saturating_sub(p2) {
                                    // The selected codec bank is a sub-message
                                    // whose field 1 contains the codec constant.
                                    // 123 -> H.264, 100 -> HEVC.
                                    codec = extract_selected_codec(&sub[p2..p2 + l as usize]);
                                }
                                sp = p2 + l as usize;
                            }
                            1 => sp += 8,
                            5 => sp += 4,
                            _ => break,
                        }
                    }
                }
                pos += len as usize;
            }
            1 => pos += 8,
            5 => pos += 4,
            _ => break,
        }
    }
    Some((canvas_w, canvas_h, tile_count, codec.unwrap_or(Codec::H264)))
}

fn extract_selected_codec(bank: &[u8]) -> Option<Codec> {
    let mut pos = 0;
    while pos < bank.len() {
        let (tag, p) = protobuf::read_varint(bank, pos)?;
        pos = p;
        let field = tag >> 3;
        let wt = tag & 7;
        if wt == 0 {
            let (v, p) = protobuf::read_varint(bank, pos)?;
            pos = p;
            if field == 1 {
                return match v {
                    123 => Some(Codec::H264),
                    100 => Some(Codec::Hevc),
                    _ => None,
                };
            }
        } else if wt == 2 {
            let (len, p) = protobuf::read_varint(bank, pos)?;
            pos = p + len as usize;
        } else {
            break;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Compression / decompression helpers
// ---------------------------------------------------------------------------

fn zlib_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    let _ = encoder.write_all(data);
    encoder.finish().unwrap_or_default()
}

pub(crate) fn zlib_decompress(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    let mut decoder = ZlibDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok().map(|_| out)
}

// ---------------------------------------------------------------------------
// UUID helpers
// ---------------------------------------------------------------------------

fn uuid_bytes(uuid: &str) -> [u8; 16] {
    let hex: Vec<u8> = uuid
        .bytes()
        .filter(|b| b.is_ascii_hexdigit())
        .map(|b| b.to_ascii_uppercase())
        .collect();
    if hex.len() != 32 {
        return [0u8; 16];
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = hex_to_nibble(hex[i * 2]);
        let lo = hex_to_nibble(hex[i * 2 + 1]);
        out[i] = (hi << 4) | lo;
    }
    out
}

fn random_uuid_string() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    // UUIDv4-ish layout: version=4, variant=10.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

fn hex_to_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'A'..=b'F' => b - b'A' + 10,
        b'a'..=b'f' => b - b'a' + 10,
        _ => 0,
    }
}

const AVC_PARAMS: &[u8] = b"FLS;LF:-1;POS:5;EOD:1;HTS:2;RR:3;POSE:4;AR:16/9,5/8;XR:16/9,5/8;";
const HEVC_PARAMS_LTR: &[u8] =
    b"FLS;MS:-1;LF:-1;LTR;CABAC;POS:0;EOD:1;HTS:2;RR:3;AR:16/9,5/8;XR:16/9,5/8;";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offer_has_expected_layout() {
        let keys = MediaStreamKeys::random();
        let msg = build_media_stream_options(&keys, true);
        assert_eq!(msg[0], 0x1c);
        assert_eq!(msg[1], 0x00);
        let message_size = u16::from_be_bytes([msg[2], msg[3]]) as usize;
        assert_eq!(msg.len(), 4 + message_size);
        assert_eq!(u16::from_be_bytes([msg[4], msg[5]]), 3); // version
        assert_eq!(u32::from_be_bytes([msg[6], msg[7], msg[8], msg[9]]), 7); // flags
        let audio_size = u16::from_be_bytes([msg[10], msg[11]]) as usize;
        let video_size = u16::from_be_bytes([msg[12], msg[13]]) as usize;
        assert!(audio_size > 0);
        assert!(video_size > 0);
    }

    #[test]
    fn offer_contains_hevc_bank_only() {
        let keys = MediaStreamKeys {
            audio_key_v: [0u8; SRTP_KEY_BLOB_LEN],
            audio_key_s: [0u8; SRTP_KEY_BLOB_LEN],
            video_key_v: [0u8; SRTP_KEY_BLOB_LEN],
            video_key_s: [0u8; SRTP_KEY_BLOB_LEN],
            audio_ssrc: 1,
            video_ssrc: 2,
        };
        let offer = build_media_stream_options(&keys, false);
        let codecs = extract_offer_codec_constants(&offer);
        assert_eq!(codecs, vec![123, 100]);
    }

    fn extract_offer_codec_constants(offer: &[u8]) -> Vec<u64> {
        // Header layout matches build_media_stream_options.
        let audio_size = u16::from_be_bytes([offer[10], offer[11]]) as usize;
        let video_size = u16::from_be_bytes([offer[12], offer[13]]) as usize;
        // Header is 14 bytes, followed by 6 reserved bytes, 16-byte UUID, both
        // audio keys, the audio offer, and then both video keys before the
        // video offer.
        let video_start = 14 + 6 + 16 + 92 + audio_size + 92;
        let video_offer = &offer[video_start..video_start + video_size];

        let plist = super::bplist::parse_dict(video_offer).expect("parse offer plist");
        let media_blob = match plist.get("avcMediaStreamNegotiatorMediaBlob") {
            Some(super::bplist::Value::Data(d)) => d,
            _ => return Vec::new(),
        };
        let decompressed = super::zlib_decompress(media_blob).expect("decompress media blob");

        // Top-level media blob: field 5 carries the video description.
        let desc = extract_field_2_bytes(&decompressed, 5).expect("video desc field");

        // Description: field 3 carries the codec banks (repeated).
        extract_repeated_field_2_bytes(desc, 3)
            .iter()
            .filter_map(|bank| extract_bank_codec_constant(bank))
            .collect()
    }

    fn extract_field_2_bytes(data: &[u8], target: u64) -> Option<&[u8]> {
        let mut pos = 0;
        while pos < data.len() {
            let (tag, p) = super::protobuf::read_varint(data, pos)?;
            pos = p;
            let field = tag >> 3;
            let wt = tag & 7;
            if field == target && wt == 2 {
                let (len, p) = super::protobuf::read_varint(data, pos)?;
                pos = p;
                return Some(&data[pos..pos + len as usize]);
            } else if wt == 2 {
                let (len, p) = super::protobuf::read_varint(data, pos)?;
                pos = p + len as usize;
            } else if wt == 0 {
                let (_, p) = super::protobuf::read_varint(data, pos)?;
                pos = p;
            } else if wt == 1 {
                pos += 8;
            } else if wt == 5 {
                pos += 4;
            } else {
                break;
            }
        }
        None
    }

    fn extract_repeated_field_2_bytes(data: &[u8], target: u64) -> Vec<&[u8]> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let Some((tag, p)) = super::protobuf::read_varint(data, pos) else {
                break;
            };
            pos = p;
            let field = tag >> 3;
            let wt = tag & 7;
            if field == target && wt == 2 {
                let Some((len, p)) = super::protobuf::read_varint(data, pos) else {
                    break;
                };
                pos = p;
                out.push(&data[pos..pos + len as usize]);
                pos += len as usize;
            } else if wt == 2 {
                let Some((len, p)) = super::protobuf::read_varint(data, pos) else {
                    break;
                };
                pos = p + len as usize;
            } else if wt == 0 {
                let Some((_, p)) = super::protobuf::read_varint(data, pos) else {
                    break;
                };
                pos = p;
            } else if wt == 1 {
                pos += 8;
            } else if wt == 5 {
                pos += 4;
            } else {
                break;
            }
        }
        out
    }

    fn extract_bank_codec_constant(bank: &[u8]) -> Option<u64> {
        let mut pos = 0;
        while pos < bank.len() {
            let (tag, p) = super::protobuf::read_varint(bank, pos)?;
            pos = p;
            let field = tag >> 3;
            let wt = tag & 7;
            if field == 1 && wt == 0 {
                let (v, _) = super::protobuf::read_varint(bank, pos)?;
                return Some(v);
            } else if wt == 2 {
                let (len, p) = super::protobuf::read_varint(bank, pos)?;
                pos = p + len as usize;
            } else if wt == 0 {
                let (_, p) = super::protobuf::read_varint(bank, pos)?;
                pos = p;
            } else if wt == 1 {
                pos += 8;
            } else if wt == 5 {
                pos += 4;
            } else {
                break;
            }
        }
        None
    }

    #[test]
    fn roundtrip_bplist_build_parse() {
        let plist = bplist::build_dict(
            b"\x01\x02",
            7,
            b"\x03\x04",
            "550E8400-E29B-41D4-A716-446655440000",
        );
        let dict = bplist::parse_dict(&plist).expect("parse own plist");
        assert_eq!(
            dict.get("avcMediaStreamNegotiatorMode"),
            Some(&bplist::Value::Int(7))
        );
        assert_eq!(
            dict.get("avcMediaStreamNegotiatorMediaBlob"),
            Some(&bplist::Value::Data(vec![0x03, 0x04]))
        );
        assert_eq!(
            dict.get("avcMediaStreamOptionCallID"),
            Some(&bplist::Value::String(
                "550E8400-E29B-41D4-A716-446655440000".to_string()
            ))
        );
    }

    #[test]
    fn parse_media_stream_answer_extracts_canvas_and_codec() {
        // Build a minimal video MediaBlob answer: a top-level field 5 sub-message
        // carries canvas width/height/tile count, plus a field-3 codec bank
        // selecting HEVC (codec constant 100).
        let mut bank = Vec::new();
        bank.extend(super::protobuf::field_varint(1, 100)); // HEVC selected
        bank.extend(super::protobuf::field_bytes(2, b"res"));
        bank.extend(super::protobuf::field_bytes(3, b"params"));

        let mut inner = Vec::new();
        inner.extend(super::protobuf::field_varint(4, 1920));
        inner.extend(super::protobuf::field_varint(5, 1080));
        inner.extend(super::protobuf::field_varint(6, 1));
        inner.extend(super::protobuf::field_bytes(3, &bank));
        let desc = super::protobuf::field_bytes(5, &inner);
        let media_blob = super::zlib_compress(&desc);
        let plist =
            super::bplist::build_dict(b"", 7, &media_blob, "00000000-0000-0000-0000-000000000000");
        let answer = parse_media_stream_answer(&plist).expect("parse answer");
        assert_eq!(answer.canvas_width, 1920);
        assert_eq!(answer.canvas_height, 1080);
        assert_eq!(answer.tile_count, 1);
        assert_eq!(answer.codec, super::super::decoder::Codec::Hevc);
    }

    #[test]
    fn parse_media_stream_answer_rejects_degenerate_blob() {
        let mut desc = Vec::new();
        desc.extend(super::protobuf::field_varint(4, 0));
        desc.extend(super::protobuf::field_varint(5, 0));
        let media_blob = super::zlib_compress(&desc);
        let plist =
            super::bplist::build_dict(b"", 7, &media_blob, "00000000-0000-0000-0000-000000000000");
        assert_eq!(parse_media_stream_answer(&plist), None);
    }
    #[test]
    fn parse_media_stream_init_stage1() {
        // Stage-1 announcement: u16 length prefix followed immediately by the
        // 14-byte fixed header (no leading padding).
        let payload = [
            0x00, 0x0e, // payload_len = 14
            0x00, 0x01, // version = 1
            0x00, 0x01, // type = 1 (stage 1)
            0x00, 0x02, // field6 = next stream port
            0x00, 0x03, // field8 = stream count
            0x12, 0x34, // field10 = base UDP port
            0x00, 0x00, 0x00, 0x00, // field12 = reserved
        ];
        let init = parse_media_stream_init(&payload).expect("parse init");
        assert_eq!(init.stage, 1);
        assert_eq!(init.base_udp_port, 0x1234);
        assert_eq!(init.stream_count, 0x0003);
        assert_eq!(init.next_stream_port, 0x0002);
    }

    #[test]
    fn parse_media_stream_init_stage2() {
        let payload = [
            0x00, 0x0e, // payload_len = 14
            0x00, 0x02, // version = 2
            0x00, 0x02, // type = 2 (stage 2)
            0x00, 0x00, // field6
            0x00, 0x01, // field8
            0x00, 0x00, // field10
            0x00, 0x00, 0x00, 0x00, // field12
        ];
        let init = parse_media_stream_init(&payload).expect("parse init");
        assert_eq!(init.stage, 2);
    }

    #[test]
    fn parse_media_stream_init_version_zero() {
        // Some macOS builds emit a (0,0) announcement as the first media-init
        // hint. In this variant field6 carries the base UDP port and field10
        // the stream count.
        let payload = [
            0x00, 0x0e, // payload_len = 14
            0x00, 0x00, // version = 0
            0x00, 0x00, // type = 0
            0x17, 0x0c, // field6 = 5900 base UDP port
            0x00, 0x00, // field8 = next stream port
            0x00, 0x01, // field10 = stream count
            0x17, 0x10, 0x17, 0x00, // field12 = 386727936
        ];
        let init = parse_media_stream_init(&payload).expect("parse init");
        assert_eq!(init.stage, 1);
        assert_eq!(init.base_udp_port, 5900);
        assert_eq!(init.stream_count, 1);
        assert_eq!(init.next_stream_port, 0);
    }
}
