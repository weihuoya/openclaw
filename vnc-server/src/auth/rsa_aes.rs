//! Re-export of the shared RSA-AES implementation from `vnc-protocol`.
//!
//! The actual implementation has been moved to the protocol crate so both the
//! client and server can share a single, audited copy.

pub use vnc_protocol::rsa_aes::{AesCtrStream, RsaAesServerAuth};

#[cfg(test)]
mod tests {
    //! Exercises the RSA-AES handshake the way `server/client.rs` drives it:
    //! the server parses the 4-byte length prefix from its input buffer,
    //! decrypts the raw ciphertext with `decrypt_encrypted_key`, upgrades to
    //! AES-CTR, and sends the security result as the first encrypted message.
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::io::{self, Read, Write};
    use std::rc::Rc;
    use vnc_protocol::rsa_aes::RsaAesClientAuth;

    /// In-memory duplex endpoint; a pair is cross-connected like a TCP
    /// connection.
    struct Duplex {
        inbound: Rc<RefCell<VecDeque<u8>>>,
        outbound: Rc<RefCell<VecDeque<u8>>>,
    }

    fn duplex_pair() -> (Duplex, Duplex) {
        let a_to_b = Rc::new(RefCell::new(VecDeque::new()));
        let b_to_a = Rc::new(RefCell::new(VecDeque::new()));
        (
            Duplex {
                inbound: Rc::clone(&b_to_a),
                outbound: Rc::clone(&a_to_b),
            },
            Duplex {
                inbound: Rc::clone(&a_to_b),
                outbound: Rc::clone(&b_to_a),
            },
        )
    }

    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut inbound = self.inbound.borrow_mut();
            let n = buf.len().min(inbound.len());
            for slot in &mut buf[..n] {
                *slot = inbound.pop_front().expect("length checked above");
            }
            Ok(n)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.outbound.borrow_mut().extend(buf.iter().copied());
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn rsa_aes_handshake_matches_client() {
        let (mut client_end, mut server_end) = duplex_pair();

        // Server sends its public key (handle_security_type path).
        let auth = RsaAesServerAuth::new_128().unwrap();
        auth.send_public_key(&mut server_end).unwrap();

        // Client performs its half (vnc-client upgrade_to_aes_ctr path).
        let client_auth = RsaAesClientAuth::new_128();
        let client_key = client_auth.authenticate(&mut client_end).unwrap();

        // Server side, mirroring handle_rsa_aes: the frame is parsed from
        // the receive buffer, then the raw ciphertext is decrypted.
        let mut incoming = Vec::new();
        server_end.read_to_end(&mut incoming).unwrap();
        let ciphertext = vnc_protocol::rsa_aes::parse_encrypted_key_frame(&incoming)
            .expect("complete frame")
            .expect("length within limit");
        assert_eq!(incoming.len(), 4 + ciphertext.len());
        let aes_key = auth.decrypt_encrypted_key(ciphertext).unwrap();
        assert_eq!(aes_key, client_key);

        // Server upgrades to AES-CTR and sends the security result encrypted;
        // the client reads it from its encrypted stream.
        let mut server_stream = AesCtrStream::new(server_end, &aes_key).unwrap();
        RsaAesServerAuth::send_security_result(&mut server_stream, true).unwrap();

        let mut client_stream = AesCtrStream::new(client_end, &client_key).unwrap();
        RsaAesClientAuth::read_security_result(&mut client_stream).unwrap();

        // The encrypted channel works in both directions afterwards.
        client_stream.write_all(b"init").unwrap();
        client_stream.flush().unwrap();
        let mut buf = [0u8; 4];
        server_stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"init");
    }
}
