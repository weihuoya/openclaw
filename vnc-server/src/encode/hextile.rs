//! Hextile encoding (encoding type 5).
//!
//! The encoder itself lives in the shared `vnc-protocol` crate (alongside the
//! Hextile decoder); this module re-exports it to keep the
//! `vnc_server::encode::hextile` path stable.

pub use vnc_protocol::hextile::encode_hextile;
