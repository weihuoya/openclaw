use num_bigint::{BigInt, Sign};
use pbkdf2::pbkdf2_hmac;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use sha2::{Digest, Sha256, Sha512};

use crate::VncError;

const SRP_HASH_LEN: usize = 64; // SHA-512
const SRP_MODULUS_LEN: usize = 512; // 4096 bits
const SRP_PBKDF2_DK_LEN: usize = 128;
const RSA_MODULUS_PAYLOAD_LEN: usize = 256; // RSA-2048 encrypted block

/// Apple Remote Desktop SRP authentication (RFB security type 33).
///
/// Implements RSA1/RSA-SRP using RFC 5054 4096-bit MODP, g=5, SHA-512,
/// and Apple's SALTED-SHA512-PBKDF2 password preprocessing. Returns the
/// 16-byte initial AES wrap key used by the Apple encrypted record layer.
pub struct AppleSrpAuth {
    username: String,
    password: String,
}

impl AppleSrpAuth {
    pub fn new(username: String, password: String) -> Self {
        Self { username, password }
    }

    pub fn authenticate(&self, stream: &mut dyn super::auth::Stream) -> Result<Vec<u8>, VncError> {
        let server_pub = self.rsa1_init(stream)?;
        self.send_srp_modulus(stream, &server_pub)?;
        let challenge = self.read_srp_challenge(stream)?;
        let proof = self.solve_srp(&challenge)?;
        self.send_srp_proof(stream, &challenge, &proof)?;
        self.read_srp_result(stream)?;

        let mut wrap_key = [0u8; 16];
        wrap_key.copy_from_slice(&Sha256::digest(&proof.k)[..16]);
        Ok(wrap_key.to_vec())
    }

    fn rsa1_init(&self, stream: &mut dyn super::auth::Stream) -> Result<RsaPublicKey, VncError> {
        // 15-byte RSA1 init: selector 0x21 + 14-byte RSA1 envelope.
        stream.write_all(b"\x21\x00\x00\x00\x0a\x01\x00RSA1\x00\x00\x00\x00")?;

        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf)?;
        let pkt_len = u32::from_be_bytes(buf) as usize;
        // The RSA1 init packet carries a DER RSA public key (a few hundred
        // bytes for RSA-2048/4096); 16 KiB is generous and stops a hostile
        // server from forcing a giant allocation.
        const MAX_RSA1_PKT_LEN: usize = 16 * 1024;
        if pkt_len > MAX_RSA1_PKT_LEN {
            return Err(VncError::AuthFailed(format!(
                "RSA1 init response length {} exceeds limit",
                pkt_len
            )));
        }
        let mut pkt = vec![0u8; pkt_len];
        stream.read_exact(&mut pkt)?;

        if pkt_len < 8 {
            return Err(VncError::AuthFailed(
                "RSA1 init response too short".to_string(),
            ));
        }
        let key_len = u32::from_be_bytes([pkt[2], pkt[3], pkt[4], pkt[5]]) as usize;
        if 6 + key_len > pkt_len {
            return Err(VncError::AuthFailed(
                "RSA1 init response key length exceeds packet".to_string(),
            ));
        }
        let server_pub = RsaPublicKey::from_public_key_der(&pkt[6..6 + key_len])
            .map_err(|e| VncError::Protocol(format!("Invalid RSA public key: {}", e)))?;
        log::debug!(
            "Apple SRP RSA1 init: server pubkey {} bits",
            server_pub.size() * 8
        );
        Ok(server_pub)
    }

    fn send_srp_modulus(
        &self,
        stream: &mut dyn super::auth::Stream,
        server_pub: &RsaPublicKey,
    ) -> Result<(), VncError> {
        let user_b = self.username.as_bytes();
        let mut inner = Vec::with_capacity(4 + user_b.len() + 3);
        inner.extend_from_slice(&(user_b.len() as u32).to_be_bytes());
        inner.extend_from_slice(user_b);
        inner.extend_from_slice(&[0, 0, 0]);

        let mut payload = Vec::with_capacity(4 + inner.len());
        payload.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        payload.extend_from_slice(&inner);

        let encrypted = server_pub
            .encrypt(&mut rsa::rand_core::OsRng, Pkcs1v15Encrypt, &payload)
            .map_err(|e| VncError::AuthFailed(format!("RSA encryption failed: {}", e)))?;
        if encrypted.len() != RSA_MODULUS_PAYLOAD_LEN {
            return Err(VncError::AuthFailed(format!(
                "expected {}B RSA block, got {}",
                RSA_MODULUS_PAYLOAD_LEN,
                encrypted.len()
            )));
        }

        let mut c2s1 = Vec::with_capacity(650);
        c2s1.extend_from_slice(&1u16.to_le_bytes()); // version = 1
        c2s1.extend_from_slice(b"RSA1");
        c2s1.extend_from_slice(&2u16.to_be_bytes()); // authtype = 2
        c2s1.extend_from_slice(&(RSA_MODULUS_PAYLOAD_LEN as u16).to_be_bytes());
        c2s1.extend_from_slice(&encrypted);
        c2s1.extend_from_slice(&[0u8; 384]);

        stream.write_all(&(c2s1.len() as u32).to_be_bytes())?;
        stream.write_all(&c2s1)?;
        Ok(())
    }

    fn read_srp_challenge(
        &self,
        stream: &mut dyn super::auth::Stream,
    ) -> Result<SrpChallenge, VncError> {
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf)?;
        let s2c1_len = u32::from_be_bytes(buf) as usize;
        if s2c1_len < 1000 {
            return Err(VncError::AuthFailed(format!(
                "SRP challenge too short ({}B); server fell back to non-SRP path",
                s2c1_len
            )));
        }
        // A real SRP challenge is ~1.2 KiB (512-byte modulus + small fields);
        // 16 KiB is generous and stops a hostile server from forcing a giant
        // allocation.
        const MAX_S2C1_LEN: usize = 16 * 1024;
        if s2c1_len > MAX_S2C1_LEN {
            return Err(VncError::AuthFailed(format!(
                "SRP challenge length {} exceeds limit",
                s2c1_len
            )));
        }
        let mut s2c1 = vec![0u8; s2c1_len];
        stream.read_exact(&mut s2c1)?;
        self.parse_apple_srp_challenge(&s2c1)
    }

    fn parse_apple_srp_challenge(&self, s2c1: &[u8]) -> Result<SrpChallenge, VncError> {
        let mut p = 12usize;
        if s2c1.len() <= p {
            return Err(VncError::AuthFailed(
                "SRP challenge too short for header".to_string(),
            ));
        }
        if s2c1[p] != 0 {
            return Err(VncError::AuthFailed(format!(
                "SRP parse: missing DER zero marker at offset 12, got {:#x}",
                s2c1[p]
            )));
        }
        p += 1;
        if p + SRP_MODULUS_LEN > s2c1.len() {
            return Err(VncError::AuthFailed(
                "SRP challenge too short for modulus".to_string(),
            ));
        }
        let nb = &s2c1[p..p + SRP_MODULUS_LEN];
        p += SRP_MODULUS_LEN;

        // Bounds-checked cursor over the remaining server-controlled fields.
        let take = |p: &mut usize, len: usize| -> Result<&[u8], VncError> {
            let end = p.checked_add(len).ok_or_else(|| {
                VncError::AuthFailed("SRP challenge field length overflow".into())
            })?;
            let field = s2c1.get(*p..end).ok_or_else(|| {
                VncError::AuthFailed(format!(
                    "SRP challenge truncated: need {} bytes at offset {}, have {}",
                    len,
                    *p,
                    s2c1.len().saturating_sub(*p)
                ))
            })?;
            *p = end;
            Ok(field)
        };

        let g_len_b = take(&mut p, 2)?;
        let g_len = u16::from_be_bytes([g_len_b[0], g_len_b[1]]) as usize;
        let g = BigInt::from_bytes_be(Sign::Plus, take(&mut p, g_len)?);

        let salt_len = take(&mut p, 1)?[0] as usize;
        let salt = take(&mut p, salt_len)?.to_vec();

        let b_len_b = take(&mut p, 2)?;
        let b_len = u16::from_be_bytes([b_len_b[0], b_len_b[1]]) as usize;
        let bb = take(&mut p, b_len)?.to_vec();

        let it_b = take(&mut p, 8)?;
        let iterations = u64::from_be_bytes([
            it_b[0], it_b[1], it_b[2], it_b[3], it_b[4], it_b[5], it_b[6], it_b[7],
        ]);

        let cap_len_b = take(&mut p, 2)?;
        let cap_len = u16::from_be_bytes([cap_len_b[0], cap_len_b[1]]) as usize;
        let cap = take(&mut p, cap_len)?.to_vec();

        if iterations > 1_000_000 {
            return Err(VncError::AuthFailed(format!(
                "SRP iteration count {} exceeds 1M cap",
                iterations
            )));
        }

        log::debug!(
            "Apple SRP challenge: N={}b g={} salt={}B iters={} cap={}",
            nb.len() * 8,
            g,
            salt.len(),
            iterations,
            String::from_utf8_lossy(&cap)
        );

        Ok(SrpChallenge {
            n: BigInt::from_bytes_be(Sign::Plus, nb),
            nb: nb.to_vec(),
            g,
            salt,
            b: BigInt::from_bytes_be(Sign::Plus, &bb),
            bb,
            iterations,
            cap,
        })
    }

    fn solve_srp(&self, challenge: &SrpChallenge) -> Result<SrpProof, VncError> {
        // A server-supplied modulus of 0 or 1 would cause a division-by-zero
        // panic in the modulo / modpow operations below.
        if challenge.n <= BigInt::from(1) {
            return Err(VncError::AuthFailed(format!(
                "SRP modulus N must be greater than 1, got {}",
                challenge.n
            )));
        }
        let kl = SRP_MODULUS_LEN;
        let g_padded = pad_bigint(&challenge.g, kl);

        let mut k_hasher = Sha512::new();
        k_hasher.update(&challenge.nb);
        k_hasher.update(&g_padded);
        let k = BigInt::from_bytes_be(Sign::Plus, &k_hasher.finalize());

        let a = {
            let mut a_bytes = [0u8; 64];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut a_bytes);
            let a_raw = BigInt::from_bytes_be(Sign::Plus, &a_bytes);
            (a_raw % (&challenge.n - 1)) + 1
        };
        let a_pub = challenge.g.modpow(&a, &challenge.n);
        let ab = pad_bigint(&a_pub, kl);

        let mut u_hasher = Sha512::new();
        u_hasher.update(&ab);
        u_hasher.update(&challenge.bb);
        let u = BigInt::from_bytes_be(Sign::Plus, &u_hasher.finalize());

        let x = self.derive_x(&challenge.salt, challenge.iterations, &self.password);
        let x = x % &challenge.n;

        let g_x = challenge.g.modpow(&x, &challenge.n);
        let base = (&challenge.b - (&k * &g_x)) % &challenge.n;
        let exp = &a + (&u * &x);
        let s = base.modpow(&exp, &challenge.n);
        let sb = pad_bigint(&s, kl);
        let k = Sha512::digest(&sb).to_vec();

        let h_n = Sha512::digest(&challenge.nb);
        let h_g = Sha512::digest(&g_padded);
        let h_i = Sha512::digest(b"");
        let m1 = Sha512::digest(
            h_n.iter()
                .zip(h_g.iter())
                .map(|(p, q)| p ^ q)
                .collect::<Vec<u8>>()
                .iter()
                .chain(h_i.iter())
                .chain(challenge.salt.iter())
                .chain(ab.iter())
                .chain(challenge.bb.iter())
                .chain(k.iter())
                .cloned()
                .collect::<Vec<u8>>(),
        )
        .to_vec();

        Ok(SrpProof { a_pub, ab, m1, k })
    }

    fn derive_x(&self, salt: &[u8], iterations: u64, password: &str) -> BigInt {
        let mut dk = [0u8; SRP_PBKDF2_DK_LEN];
        pbkdf2_hmac::<Sha512>(password.as_bytes(), salt, iterations as u32, &mut dk);
        let inner = Sha512::digest([b":".as_slice(), &dk].concat());
        BigInt::from_bytes_be(Sign::Plus, &Sha512::digest([salt, &inner].concat()))
    }

    fn send_srp_proof(
        &self,
        stream: &mut dyn super::auth::Stream,
        challenge: &SrpChallenge,
        proof: &SrpProof,
    ) -> Result<(), VncError> {
        let mut civ = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut civ);

        let mut sd = Vec::with_capacity(1076);
        sd.extend_from_slice(&(SRP_MODULUS_LEN as u16).to_be_bytes());
        sd.extend_from_slice(&proof.ab);
        sd.push(SRP_HASH_LEN as u8);
        sd.extend_from_slice(&proof.m1);
        sd.extend_from_slice(&(challenge.cap.len() as u16).to_be_bytes());
        sd.extend_from_slice(&challenge.cap);
        sd.push(16u8);
        sd.extend_from_slice(&civ);

        let mut pay = Vec::with_capacity(1076);
        pay.extend_from_slice(&1u16.to_le_bytes()); // version
        pay.extend_from_slice(b"RSA1");
        pay.extend_from_slice(&2u16.to_be_bytes()); // authtype
        pay.extend_from_slice(&((sd.len() + 4) as u16).to_be_bytes()); // aux = inner_len + 4
        pay.extend_from_slice(&(sd.len() as u32).to_be_bytes()); // inner_len
        pay.extend_from_slice(&sd);
        // The packet is zero-padded to 1076 bytes; a server-supplied cap
        // string longer than 464 bytes would make the payload exceed that
        // (and underflow the subtraction below).
        if pay.len() > 1076 {
            return Err(VncError::AuthFailed(format!(
                "SRP proof payload ({} bytes, cap_len={}) exceeds 1076-byte packet",
                pay.len(),
                challenge.cap.len()
            )));
        }
        pay.extend_from_slice(&vec![0u8; 1076 - pay.len()]);

        stream.write_all(&(pay.len() as u32).to_be_bytes())?;
        stream.write_all(&pay)?;
        Ok(())
    }

    fn read_srp_result(&self, stream: &mut dyn super::auth::Stream) -> Result<(), VncError> {
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf)?;
        let m2_len = u32::from_be_bytes(buf) as usize;
        // The SRP M2 proof is a single hash (64 bytes) inside a small
        // envelope; 16 KiB is generous and stops a hostile server from
        // forcing a giant allocation.
        const MAX_M2_LEN: usize = 16 * 1024;
        if m2_len > MAX_M2_LEN {
            return Err(VncError::AuthFailed(format!(
                "SRP result length {} exceeds limit",
                m2_len
            )));
        }
        let mut _m2 = vec![0u8; m2_len];
        stream.read_exact(&mut _m2)?;
        stream.read_exact(&mut buf)?;
        let result = u32::from_be_bytes(buf);
        if result != 0 {
            return Err(VncError::AuthFailed(format!(
                "Apple SRP auth rejected: result={}",
                result
            )));
        }
        Ok(())
    }
}

struct SrpChallenge {
    n: BigInt,
    nb: Vec<u8>,
    g: BigInt,
    salt: Vec<u8>,
    b: BigInt,
    bb: Vec<u8>,
    iterations: u64,
    cap: Vec<u8>,
}

struct SrpProof {
    #[allow(dead_code)]
    a_pub: BigInt,
    ab: Vec<u8>,
    m1: Vec<u8>,
    k: Vec<u8>,
}

fn pad_bigint(value: &BigInt, len: usize) -> Vec<u8> {
    let mut bytes = value.to_bytes_be().1;
    if bytes.len() < len {
        let mut padded = vec![0u8; len - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    } else if bytes.len() > len {
        bytes = bytes.split_off(bytes.len() - len);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_bigint_test() {
        let v = BigInt::from(1);
        let padded = pad_bigint(&v, 512);
        assert_eq!(padded.len(), 512);
        assert_eq!(padded[511], 1);
        assert!(padded[..511].iter().all(|&b| b == 0));
    }

    #[test]
    fn derive_x_matches_known_pattern() {
        // Sanity test: x derivation does not panic and produces a non-zero value.
        let auth = AppleSrpAuth::new("user".to_string(), "pass".to_string());
        let salt = [1u8; 32];
        let x = auth.derive_x(&salt, 1000, "pass");
        assert!(x > BigInt::from(0));
    }

    /// Build a well-formed SRP challenge buffer (s2c1) for parser tests.
    fn build_challenge() -> Vec<u8> {
        let mut buf = vec![0u8; 12]; // header
        buf.push(0); // DER zero marker
        let mut modulus = vec![0u8; SRP_MODULUS_LEN];
        modulus[SRP_MODULUS_LEN - 1] = 0xff; // N != 0
        buf.extend_from_slice(&modulus);
        buf.extend_from_slice(&1u16.to_be_bytes()); // g_len
        buf.push(5); // g = 5
        buf.push(4); // salt_len
        buf.extend_from_slice(&[1, 2, 3, 4]); // salt
        buf.extend_from_slice(&2u16.to_be_bytes()); // b_len
        buf.extend_from_slice(&[0xaa, 0xbb]); // B
        buf.extend_from_slice(&1000u64.to_be_bytes()); // iterations
        buf.extend_from_slice(&2u16.to_be_bytes()); // cap_len
        buf.extend_from_slice(b"GD"); // cap
        buf
    }

    #[test]
    fn parse_challenge_valid() {
        let auth = AppleSrpAuth::new("user".to_string(), "pass".to_string());
        let challenge = auth
            .parse_apple_srp_challenge(&build_challenge())
            .expect("well-formed challenge parses");
        assert_eq!(challenge.g, BigInt::from(5));
        assert_eq!(challenge.salt, vec![1, 2, 3, 4]);
        assert_eq!(challenge.iterations, 1000);
        assert_eq!(challenge.cap, b"GD");
    }

    #[test]
    fn parse_challenge_malformed_lengths_error_not_panic() {
        let auth = AppleSrpAuth::new("user".to_string(), "pass".to_string());
        let valid = build_challenge();
        let header_end = 12 + 1 + SRP_MODULUS_LEN; // offset of g_len

        // g_len larger than the remaining buffer.
        let mut bad = valid.clone();
        bad[header_end] = 0xff;
        bad[header_end + 1] = 0xff;
        assert!(auth.parse_apple_srp_challenge(&bad).is_err());

        // salt_len larger than the remaining buffer.
        let mut bad = valid.clone();
        bad[header_end + 3] = 200; // salt_len byte (after g_len + 1-byte g)
        assert!(auth.parse_apple_srp_challenge(&bad).is_err());

        // b_len larger than the remaining buffer.
        let mut bad = valid.clone();
        let b_len_off = header_end + 3 + 1 + 4; // after g field, salt_len, salt
        bad[b_len_off] = 0xff;
        bad[b_len_off + 1] = 0xff;
        assert!(auth.parse_apple_srp_challenge(&bad).is_err());

        // cap_len larger than the remaining buffer.
        let mut bad = valid.clone();
        let n = bad.len();
        bad[n - 4] = 0xff; // cap_len high byte (last 4 bytes: cap_len + "GD")
        bad[n - 3] = 0xff;
        assert!(auth.parse_apple_srp_challenge(&bad).is_err());

        // Buffer truncated in the middle of the iterations field.
        let truncated = &valid[..valid.len() - 10];
        assert!(auth.parse_apple_srp_challenge(truncated).is_err());
    }

    fn dummy_challenge(n: BigInt, cap_len: usize) -> SrpChallenge {
        SrpChallenge {
            n,
            nb: vec![0u8; SRP_MODULUS_LEN],
            g: BigInt::from(5),
            salt: vec![1, 2, 3, 4],
            b: BigInt::from(7),
            bb: vec![0, 7],
            iterations: 1000,
            cap: vec![0u8; cap_len],
        }
    }

    fn dummy_proof() -> SrpProof {
        SrpProof {
            a_pub: BigInt::from(1),
            ab: vec![0u8; SRP_MODULUS_LEN],
            m1: vec![0u8; SRP_HASH_LEN],
            k: vec![0u8; SRP_HASH_LEN],
        }
    }

    #[test]
    fn solve_srp_rejects_invalid_modulus() {
        let auth = AppleSrpAuth::new("user".to_string(), "pass".to_string());
        // N = 0 and N = 1 would cause a division-by-zero panic.
        assert!(auth
            .solve_srp(&dummy_challenge(BigInt::from(0), 2))
            .is_err());
        assert!(auth
            .solve_srp(&dummy_challenge(BigInt::from(1), 2))
            .is_err());
    }

    #[test]
    fn send_srp_proof_rejects_oversized_cap() {
        let auth = AppleSrpAuth::new("user".to_string(), "pass".to_string());
        // cap_len larger than 464 makes the payload exceed the 1076-byte
        // packet; the zero-padding subtraction would underflow.
        let challenge = dummy_challenge(BigInt::from(3), 600);
        let proof = dummy_proof();
        let mut stream = std::io::Cursor::new(Vec::new());
        assert!(auth
            .send_srp_proof(&mut stream, &challenge, &proof)
            .is_err());
    }
}
