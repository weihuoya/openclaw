//! Re-export of the shared RSA-AES implementation from `vnc-protocol`.
//!
//! The actual implementation has been moved to the protocol crate so both the
//! client and server can share a single, audited copy.

pub use vnc_protocol::rsa_aes::{AesCtrStream, RsaAesClientAuth as RsaAesAuth};
