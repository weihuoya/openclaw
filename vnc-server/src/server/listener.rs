//! TCP listener and client accept loop.

use log::{info, warn};
use std::io;
use std::net::TcpListener;

use crate::server::client::VncClient;
use crate::server::tls::ServerTlsConfig;

pub struct VncListener {
    listener: TcpListener,
    password: Option<String>,
    auth_enabled: bool,
    rsa_aes_enabled: bool,
    vencrypt_enabled: bool,
    tls_config: Option<ServerTlsConfig>,
    width: u16,
    height: u16,
    name: String,
}

impl VncListener {
    #[allow(clippy::too_many_arguments)]
    pub fn bind(
        addr: &str,
        port: u16,
        password: Option<String>,
        auth_enabled: bool,
        rsa_aes_enabled: bool,
        vencrypt_enabled: bool,
        tls_config: Option<ServerTlsConfig>,
        width: u16,
        height: u16,
        name: String,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind((addr, port))?;
        listener.set_nonblocking(true)?;
        info!("VNC server listening on {}:{}", addr, port);
        Ok(Self {
            listener,
            password,
            auth_enabled,
            rsa_aes_enabled,
            vencrypt_enabled,
            tls_config,
            width,
            height,
            name,
        })
    }

    /// Update the password used for new clients.
    pub fn set_password(&mut self, password: Option<String>) {
        self.password = password;
    }

    /// Update the framebuffer dimensions used for new clients.
    pub fn set_dimensions(&mut self, width: u16, height: u16) {
        self.width = width;
        self.height = height;
    }

    /// Try to accept a new client connection. Returns None if no pending connection.
    pub fn try_accept(&self) -> io::Result<Option<VncClient>> {
        match self.listener.accept() {
            Ok((stream, addr)) => {
                info!("New VNC client from {}", addr);
                stream.set_nonblocking(true)?;
                let mut client = VncClient::new(
                    stream,
                    self.width,
                    self.height,
                    self.name.clone(),
                    self.password.clone(),
                    self.auth_enabled,
                    self.rsa_aes_enabled,
                    self.vencrypt_enabled,
                    self.tls_config.clone(),
                );
                // Start handshake
                if let Err(e) = client.send_version() {
                    warn!("Failed to send version: {}", e);
                    return Ok(None);
                }
                Ok(Some(client))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
}
