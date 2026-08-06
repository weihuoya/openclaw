//! ZRLE encoding (encoding type 16).
//!
//! The encoder itself lives in the shared `vnc-protocol` crate; this module
//! re-exports it to keep the `vnc_server::encode::zrle` path stable.

pub use vnc_protocol::zrle::ZrleEncoder;
