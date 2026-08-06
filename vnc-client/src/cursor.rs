//! VNC cursor shape handling.
//!
//! This module is now a thin re-export of the shared implementation in
//! [`vnc_protocol::cursor`]. Client code should use [`vnc_protocol::cursor`] directly
//! for new work; the re-export here preserves existing imports such as
//! `vnc_client::cursor::CursorShape`.

pub use vnc_protocol::cursor::{default_cursor, encode_cursor, encode_cursor_pos, CursorShape};
