use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::Once;

use rustls::{ClientConfig, ClientConnection, StreamOwned};

use crate::VncError;

static RING_INIT: Once = Once::new();

/// A TLS-wrapped stream that implements Read + Write.
pub struct TlsStream {
    inner: StreamOwned<ClientConnection, TcpStream>,
}

impl TlsStream {
    pub fn connect(host: &str, port: u16) -> Result<Self, VncError> {
        let tcp_stream = TcpStream::connect((host, port))?;
        tcp_stream.set_nodelay(true)?;
        Self::upgrade(tcp_stream, host)
    }

    /// Upgrade an existing TCP connection to TLS.
    pub fn from_tcp(tcp_stream: TcpStream, host: &str) -> Result<Self, VncError> {
        tcp_stream.set_nodelay(true)?;
        Self::upgrade(tcp_stream, host)
    }

    fn upgrade(tcp_stream: TcpStream, host: &str) -> Result<Self, VncError> {
        RING_INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });

        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let server_name = host
            .to_string()
            .try_into()
            .map_err(|_| VncError::Protocol(format!("Invalid server name: {}", host)))?;

        let client = ClientConnection::new(Arc::new(config), server_name)
            .map_err(|e| VncError::Protocol(format!("TLS error: {}", e)))?;

        let stream = StreamOwned::new(client, tcp_stream);
        Ok(Self { inner: stream })
    }
}

impl TlsStream {
    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        self.inner.get_ref().set_read_timeout(timeout)
    }

    pub fn set_nodelay(&self, nodelay: bool) -> std::io::Result<()> {
        self.inner.get_ref().set_nodelay(nodelay)
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
