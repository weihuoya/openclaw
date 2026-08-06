//! Zlib encoding (encoding type 6).
//!
//! The encoder itself lives in the shared `vnc-protocol` crate; this module
//! re-exports it to keep the `vnc_server::encode::zlib` path stable.

pub use vnc_protocol::zlib::ZlibEncoder;
