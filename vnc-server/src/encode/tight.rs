//! Tight encoding (encoding type 7).
//!
//! The encoder itself lives in the shared `vnc-protocol` crate (with its JPEG
//! subencoding enabled via vnc-protocol's `jpeg-encode` feature); this module
//! re-exports it to keep the `vnc_server::encode::tight` path stable.

pub use vnc_protocol::tight::TightEncoder;
