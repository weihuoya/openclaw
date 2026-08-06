//! VNC Cursor pseudo-encoding helpers (encoding type -239).
//!
//! This module is now a thin re-export of the shared implementation in
//! [`vnc_protocol::cursor`]. The server builds the default arrow cursor here and
//! encodes it into `FbRect` rectangles for transport.

pub use vnc_protocol::cursor::{default_cursor, encode_cursor, encode_cursor_pos, CursorShape};
