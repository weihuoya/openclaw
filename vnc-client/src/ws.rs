use std::io::{Read, Write};
use std::net::TcpStream;

use crate::VncError;
use tungstenite::protocol::WebSocket;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::Error as WsError;

/// A WebSocket stream that wraps a TCP/TLS connection and implements Read + Write
/// by buffering WebSocket messages into a local byte buffer.
pub struct WsStream {
    ws: WebSocket<MaybeTlsStream<TcpStream>>,
    read_buf: Vec<u8>,
    read_pos: usize,
    /// Write buffer to coalesce partial writes into a single WebSocket message.
    write_buf: Vec<u8>,
}

impl WsStream {
    pub fn connect(url: &str) -> Result<Self, VncError> {
        let (ws, _) = tungstenite::connect(url).map_err(|e| {
            VncError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("WebSocket handshake failed: {}", e),
            ))
        })?;

        Ok(Self {
            ws,
            read_buf: Vec::new(),
            read_pos: 0,
            write_buf: Vec::new(),
        })
    }

    fn fill_buffer(&mut self) -> std::io::Result<()> {
        loop {
            match self.ws.read() {
                Ok(tungstenite::Message::Binary(data)) => {
                    self.read_buf = data;
                    self.read_pos = 0;
                    return Ok(());
                }
                Ok(tungstenite::Message::Text(data)) => {
                    self.read_buf = data.into_bytes();
                    self.read_pos = 0;
                    return Ok(());
                }
                Ok(tungstenite::Message::Close(_)) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "WebSocket closed",
                    ));
                }
                Ok(tungstenite::Message::Ping(_)) | Ok(tungstenite::Message::Pong(_)) => {
                    continue;
                }
                Ok(tungstenite::Message::Frame(_)) => {
                    continue;
                }
                Err(WsError::Io(e)) => return Err(e),
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("WebSocket error: {}", e),
                    ));
                }
            }
        }
    }

    pub fn set_read_timeout(&self, _timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        // Not supported for WebSocket; underlying TCP stream is
        // abstracted by tungstenite. Users should rely on higher-level
        // timeout handling.
        Ok(())
    }

    pub fn set_nodelay(&self, _nodelay: bool) -> std::io::Result<()> {
        // Not directly supported for WebSocket.
        Ok(())
    }
}

impl Read for WsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.read_pos >= self.read_buf.len() {
            self.fill_buffer()?;
        }

        let remaining = self.read_buf.len() - self.read_pos;
        let to_read = buf.len().min(remaining);
        buf[..to_read].copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + to_read]);
        self.read_pos += to_read;
        Ok(to_read)
    }
}

impl Write for WsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Buffer writes locally so that multiple small writes can be
        // coalesced into a single WebSocket binary message on flush.
        self.write_buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.write_buf.is_empty() {
            self.ws
                .write(tungstenite::Message::Binary(self.write_buf.clone()))
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("WebSocket write error: {}", e),
                    )
                })?;
            self.write_buf.clear();
        }
        self.ws.flush().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("WebSocket flush error: {}", e),
            )
        })
    }
}
