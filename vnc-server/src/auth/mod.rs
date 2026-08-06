//! VNC Authentication (VNC Auth - Security Type 2).
//!
//! Uses DES encryption with a challenge-response protocol. The core primitives
//! are shared in `vnc-protocol::auth`.

pub use vnc_protocol::auth::{
    encrypt_challenge, generate_challenge, verify_response, CHALLENGE_SIZE,
};

pub mod rsa_aes;
