//! RRE encoding (encoding type 2).
//!
//! The encoder itself lives in the shared `vnc-protocol` crate (alongside the
//! RRE decoder); this module re-exports it to keep the
//! `vnc_server::encode::rre` path stable.

pub use vnc_protocol::rre::encode_rre;
