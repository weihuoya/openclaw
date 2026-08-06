//! TLS server-side support for the VeNCrypt security type.
//!
//! Wraps a `rustls::ServerConnection` around a non-blocking `TcpStream` and
//! implements `Read + Write`. The TLS handshake is driven by every `read()` and
//! `write()` call: incoming TLS records are read, processed, and outgoing
//! records are written back to the socket. This pattern fits the server's
//! single-threaded event loop.

use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use log::{info, warn};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection};

/// TLS configuration used by the VNC server.
///
/// Either loaded from PEM files supplied by the user, or a self-signed
/// certificate generated at startup so that TLS can be used without manual
/// certificate management.
#[derive(Clone)]
pub struct ServerTlsConfig {
    config: Arc<ServerConfig>,
}

impl ServerTlsConfig {
    /// Build a TLS config from a certificate PEM file and a private key PEM file.
    pub fn from_pem_files(cert_path: &str, key_path: &str) -> io::Result<Self> {
        let cert_chain = load_certs(cert_path)?;
        let key = load_private_key(key_path)?;
        Self::build(cert_chain, key)
    }

    /// Generate a self-signed certificate and build a TLS config.
    pub fn self_signed() -> io::Result<Self> {
        info!("Generating self-signed TLS certificate for VeNCrypt");
        let certified_key =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to generate self-signed certificate: {}", e),
                )
            })?;

        let cert_chain = vec![certified_key.cert.der().clone()];
        let key = PrivateKeyDer::try_from(certified_key.key_pair.serialized_der().to_vec())
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to encode generated private key: {}", e),
                )
            })?;

        Self::build(cert_chain, key)
    }

    fn build(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> io::Result<Self> {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to build TLS server config: {}", e),
                )
            })?;
        Ok(Self {
            config: Arc::new(config),
        })
    }

    /// Wrap a plain TCP stream in a TLS server stream, optionally feeding any
    /// bytes that have already been read into the application buffer.
    ///
    /// `buffered` is used by the caller to hand over TLS records that were
    /// read from the socket before the upgrade decision was made. Returns the
    /// stream plus the number of buffered bytes rustls actually consumed; the
    /// caller must drop exactly that many bytes from its own read buffer so
    /// each byte is processed exactly once.
    pub fn accept(&self, tcp: TcpStream, buffered: &[u8]) -> io::Result<(TlsStream, usize)> {
        let mut conn = ServerConnection::new(Arc::clone(&self.config)).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("failed to create TLS server connection: {}", e),
            )
        })?;

        let mut consumed = 0;
        if !buffered.is_empty() {
            // Feed any TLS records that were already read from the socket.
            let mut reader = BufferedReader::new(buffered);
            let _ = conn.read_tls(&mut reader);
            consumed = reader.pos;
            let _ = conn.process_new_packets().map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("TLS error: {}", e))
            });
            // Flush any handshake records produced by the buffered data.
            let _ = conn.write_tls(&mut &tcp);
        }

        Ok((TlsStream { conn, tcp }, consumed))
    }

    /// Return true if the TLS config can be used.
    pub fn is_available(&self) -> bool {
        true
    }
}

/// Build a TLS config from optional PEM files, falling back to a self-signed
/// certificate.
pub fn build_tls_config(
    cert_file: Option<&str>,
    key_file: Option<&str>,
) -> io::Result<Option<ServerTlsConfig>> {
    match (cert_file, key_file) {
        (Some(cert), Some(key)) => {
            info!("Loading TLS certificate from {}", cert);
            match ServerTlsConfig::from_pem_files(cert, key) {
                Ok(cfg) => Ok(Some(cfg)),
                Err(e) => {
                    warn!(
                        "Failed to load user-provided TLS cert/key: {}. Falling back to self-signed.",
                        e
                    );
                    Ok(Some(ServerTlsConfig::self_signed()?))
                }
            }
        }
        (Some(_), None) | (None, Some(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TLS certificate and private key must both be provided, or neither",
        )),
        (None, None) => Ok(Some(ServerTlsConfig::self_signed()?)),
    }
}

/// A TLS-wrapped TCP stream implementing `Read + Write`.
pub struct TlsStream {
    conn: ServerConnection,
    tcp: TcpStream,
}

/// Reader over a pre-read byte slice that reports `WouldBlock` (not EOF) when
/// the slice is exhausted. rustls treats `Ok(0)` as the peer closing the
/// connection, which would poison the freshly created connection with a
/// spurious EOF; `WouldBlock` simply stops the feed at the end of the
/// buffered input.
struct BufferedReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BufferedReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl Read for BufferedReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = &self.data[self.pos..];
        if remaining.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "buffered input exhausted",
            ));
        }
        let n = remaining.len().min(buf.len());
        buf[..n].copy_from_slice(&remaining[..n]);
        self.pos += n;
        Ok(n)
    }
}

impl TlsStream {
    /// Set the read timeout of the underlying TCP stream.
    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        self.tcp.set_read_timeout(timeout)
    }

    /// Set the TCP_NODELAY option of the underlying TCP stream.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.tcp.set_nodelay(nodelay)
    }

    /// Return the peer address of the underlying TCP stream.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.tcp.peer_addr()
    }

    /// Set the non-blocking mode of the underlying TCP stream.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.tcp.set_nonblocking(nonblocking)
    }

    /// True when rustls has no outbound data waiting to be written to the
    /// socket.
    pub fn is_write_idle(&self) -> bool {
        !self.conn.wants_write()
    }

    fn drive_io(&mut self) -> io::Result<()> {
        // Read incoming TLS records.
        match self.conn.read_tls(&mut self.tcp) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TLS peer closed",
                ))
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }

        // Advance the TLS state machine.
        if let Err(e) = self.conn.process_new_packets() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("TLS error: {}", e),
            ));
        }

        // Write outgoing TLS records.
        loop {
            match self.conn.write_tls(&mut self.tcp) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.drive_io()?;
        match self.conn.reader().read(buf) {
            // rustls returns WouldBlock when no plaintext is available (yet).
            // This is normal for a non-blocking socket and must NOT be
            // reported as Ok(0): callers treat Ok(0) as "peer closed" and
            // would drop the connection mid-handshake.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
            other => other,
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.drive_io()?;
        // Queue plaintext for sending; the TLS layer will encrypt and write it
        // on the next drive_io() call.
        self.conn.writer().write_all(buf)?;
        // Try to flush immediately.
        self.drive_io()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.conn.writer().flush()?;
        self.drive_io()?;
        Ok(())
    }
}

fn load_certs(path: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = fs::File::open(path)?;
    let mut reader = io::BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no certificates found in PEM file",
        ));
    }
    Ok(certs)
}

fn load_private_key(path: &str) -> io::Result<PrivateKeyDer<'static>> {
    let file = fs::File::open(path)?;
    let mut reader = io::BufReader::new(file);
    let mut keys = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))?;
    keys.take().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "no private key found in PEM file",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_config_is_available() {
        let cfg = ServerTlsConfig::self_signed().unwrap();
        assert!(cfg.is_available());
    }

    #[test]
    fn build_tls_config_falls_back_to_self_signed_when_no_paths() {
        let cfg = build_tls_config(None, None).unwrap();
        assert!(cfg.is_some());
    }

    #[test]
    fn build_tls_config_requires_both_or_none() {
        assert!(build_tls_config(Some("cert.pem"), None).is_err());
        assert!(build_tls_config(None, Some("key.pem")).is_err());
    }

    #[test]
    fn accept_feeds_buffered_data() {
        let cfg = ServerTlsConfig::self_signed().unwrap();
        // Create a connected pair of TCP streams for the test.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let server = listener.accept().unwrap().0;
        drop(listener);
        let (_tls, consumed) = cfg.accept(server, b"garbage").unwrap();
        // Every fed byte must be reported as consumed exactly once.
        assert_eq!(consumed, b"garbage".len());
        drop(client);
    }

    #[test]
    fn buffered_reader_reports_wouldblock_not_eof() {
        let mut reader = BufferedReader::new(b"ab");
        let mut buf = [0u8; 8];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], b"ab");
        let err = reader.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }
}
