//! Shared RFB protocol types and constants for `vnc-client` and `vnc-server`.
//!
//! This crate contains wire-agnostic data definitions: encodings, pixel formats,
//! message-type enums, security types, and common message structures. The goal
//! is to keep the two endpoint crates in sync and to enable future shared
//! utilities (encoding primitives, authentication helpers, round-trip tests, etc.).

pub mod auth;
pub mod clipboard;
pub mod cursor;
pub mod encoding;
pub mod error;
pub mod framing;
pub mod handshake;
pub mod hextile;
pub mod messages;
pub mod pixel_format;
pub mod pixel_sink;
pub mod qemu;
pub mod raw;
pub mod rect;
pub mod rre;
pub mod rsa_aes;
pub mod security;
pub mod server_init;
pub mod tight;
pub mod vencrypt;
pub mod zlib;
pub mod zrle;

pub use auth::{
    encrypt_challenge, generate_challenge, reverse_bits, verify_response, vnc_des_key,
    CHALLENGE_SIZE,
};
pub use cursor::{default_cursor, encode_cursor, encode_cursor_pos, CursorShape};
pub use encoding::{encoding_name, from_i32, Encoding};
pub use error::ProtocolError;
pub use framing::{
    build_set_encodings, build_set_pixel_format, parse_cut_text_header, parse_set_encodings,
    parse_set_pixel_format, read_cut_text_length, read_desktop_name_body, read_fb_update_header,
    read_screen_list, write_cut_text, write_desktop_name_body, write_fb_update_header,
    write_screen_list, write_set_color_map_entries, CopyRectBody, EnableContinuousUpdates, Fence,
    FramebufferUpdateRequest, KeyEvent, OpenH264Header, PointerEvent, QemuExtendedKeyEvent,
    RectHeader, Screen, SetDesktopSize, CUT_TEXT_HEADER_LEN, SET_PIXEL_FORMAT_WIRE_LEN,
};
pub use handshake::{parse_rfb_version, read_failure_reason, RFB_VERSION_BANNER_LEN};
pub use messages::{
    ClientMsgType, ServerMsgType, CLIENT_CUT_TEXT, CLIENT_ENABLE_CONTINUOUS_UPDATES, CLIENT_FENCE,
    CLIENT_FRAMEBUFFER_UPDATE_REQUEST, CLIENT_KEY_EVENT, CLIENT_POINTER_EVENT, CLIENT_QEMU,
    CLIENT_SET_DESKTOP_SIZE, CLIENT_SET_ENCODINGS, CLIENT_SET_PIXEL_FORMAT, FENCE_FLAG_BLOCK_AFTER,
    FENCE_FLAG_BLOCK_BEFORE, FENCE_FLAG_REQUEST, FENCE_FLAG_SYNC_NEXT, FENCE_MAX_PAYLOAD,
    MESSAGE_TYPE_FENCE, RFB_VERSION, SERVER_BELL, SERVER_END_OF_CONTINUOUS_UPDATES,
    SERVER_END_OF_CONTINUOUS_UPDATES_LEGACY, SERVER_FENCE_LEGACY, SERVER_FRAMEBUFFER_UPDATE,
    SERVER_SERVER_CUT_TEXT, SERVER_SET_COLOUR_MAP_ENTRIES,
};
pub use pixel_format::PixelFormat;
pub use pixel_sink::{PixelSink, TestPixelSink};
pub use rect::{check_dimensions, FbRect, MAX_DIMENSION, MAX_PIXELS};
pub use security::{
    SecurityType, SECURITY_APPLE_DH, SECURITY_NONE, SECURITY_RSA_AES, SECURITY_RSA_AES256,
    SECURITY_TIGHT, SECURITY_VENCRYPT, SECURITY_VNC_AUTH,
};
pub use server_init::{
    read_security_result, write_security_result, SecurityResult, ServerInit, MAX_REASON_LEN,
};
pub use vencrypt::VeNCryptSubType;
