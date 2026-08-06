//! TRLE encoding (encoding type 15).
//!
//! The encoder itself lives in the shared `vnc-protocol` crate's `zrle`
//! module (ZRLE/TRLE share the same 64x64 tile format); this module
//! re-exports it to keep the `vnc_server::encode::trle` path stable.

pub use vnc_protocol::zrle::{encode_tile_stream, encode_trle};
