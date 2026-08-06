//! Raw encoding (encoding type 0).
//!
//! The encoder itself lives in the shared `vnc-protocol` crate; this module
//! re-exports it to keep the `vnc_server::encode::raw` path stable.

pub use vnc_protocol::raw::encode_raw;
