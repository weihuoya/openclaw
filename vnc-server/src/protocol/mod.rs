//! RFB protocol constants, types, and message structures.
//!
//! Re-exported from the shared `vnc-protocol` crate. Server-specific helpers
//! (e.g., `FbRect::write_header`, `ServerInit::write`) live in `vnc-protocol`
//! as well, because they are useful for any RFB endpoint implementation.

pub use vnc_protocol::*;
