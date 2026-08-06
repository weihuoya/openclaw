use crate::VncError;

use vnc_protocol::encrypt_challenge;

/// Authentication handler trait.
pub trait AuthHandler {
    /// Select a security type from the list offered by the server.
    fn select_security_type(&mut self, types: &[u8]) -> Result<u8, VncError>;

    /// Authenticate using VNC authentication (DES challenge-response).
    fn authenticate_vnc(&mut self, stream: &mut dyn Stream) -> Result<(), VncError>;

    /// Authenticate using a custom security type.
    fn authenticate(&mut self, _stream: &mut dyn Stream, _type: u8) -> Result<(), VncError> {
        Err(VncError::AuthFailed(format!(
            "Auth type {} not supported",
            _type
        )))
    }

    /// Optional post-authentication key material (e.g., Apple HP wrap key).
    fn session_key(&mut self) -> Option<Vec<u8>> {
        None
    }
}

/// Trait alias for stream types used in authentication.
pub trait Stream: std::io::Read + std::io::Write {}
impl<T: std::io::Read + std::io::Write> Stream for T {}

/// Result of authentication.
pub enum AuthResult {
    Success,
    Failure(String),
}

/// No authentication handler (accepts None auth only).
pub struct NoAuthHandler;

impl AuthHandler for NoAuthHandler {
    fn select_security_type(&mut self, types: &[u8]) -> Result<u8, VncError> {
        if types.contains(&1) {
            Ok(1) // None
        } else {
            Err(VncError::AuthFailed(format!(
                "No supported auth types (server offered {:?})",
                types
            )))
        }
    }

    fn authenticate_vnc(&mut self, _stream: &mut dyn Stream) -> Result<(), VncError> {
        Err(VncError::AuthFailed("VNC auth not supported".to_string()))
    }
}

/// Apple Remote Desktop authentication handler (RFB security type 30).
pub struct AppleDhAuthHandler {
    username: String,
    password: String,
    session_key: Option<Vec<u8>>,
}

impl AppleDhAuthHandler {
    pub fn new(username: String, password: String) -> Self {
        Self {
            username,
            password,
            session_key: None,
        }
    }
}

impl AuthHandler for AppleDhAuthHandler {
    fn select_security_type(&mut self, types: &[u8]) -> Result<u8, VncError> {
        if types.contains(&30) {
            Ok(30)
        } else {
            Err(VncError::AuthFailed(format!(
                "No supported auth types (server offered {:?})",
                types
            )))
        }
    }

    fn authenticate_vnc(&mut self, _stream: &mut dyn Stream) -> Result<(), VncError> {
        Err(VncError::AuthFailed(
            "Apple DH auth does not use VNC challenge-response".to_string(),
        ))
    }

    fn authenticate(&mut self, stream: &mut dyn Stream, _type: u8) -> Result<(), VncError> {
        let key = crate::apple_dh::AppleDhAuth::new(self.username.clone(), self.password.clone())
            .authenticate(stream)?;
        self.session_key = Some(key.to_vec());
        Ok(())
    }

    fn session_key(&mut self) -> Option<Vec<u8>> {
        self.session_key.take()
    }
}

/// Apple Screen Sharing authentication handler (RFB security type 33 RSA-SRP).
pub struct AppleSrpAuthHandler {
    username: String,
    password: String,
    session_key: Option<Vec<u8>>,
}

impl AppleSrpAuthHandler {
    pub fn new(username: String, password: String) -> Self {
        Self {
            username,
            password,
            session_key: None,
        }
    }
}

impl AuthHandler for AppleSrpAuthHandler {
    fn select_security_type(&mut self, types: &[u8]) -> Result<u8, VncError> {
        // Prefer type 33 (RSA-SRP) over type 30 (DH) when both are offered.
        if types.contains(&33) {
            Ok(33)
        } else if types.contains(&30) {
            Ok(30)
        } else {
            Err(VncError::AuthFailed(format!(
                "No supported auth types (server offered {:?})",
                types
            )))
        }
    }

    fn authenticate_vnc(&mut self, _stream: &mut dyn Stream) -> Result<(), VncError> {
        Err(VncError::AuthFailed(
            "Apple SRP auth does not use VNC challenge-response".to_string(),
        ))
    }

    fn authenticate(&mut self, stream: &mut dyn Stream, _type: u8) -> Result<(), VncError> {
        let key = crate::apple_srp::AppleSrpAuth::new(self.username.clone(), self.password.clone())
            .authenticate(stream)?;
        self.session_key = Some(key);
        Ok(())
    }

    fn session_key(&mut self) -> Option<Vec<u8>> {
        self.session_key.take()
    }
}

/// Password-based VNC authentication handler.
pub struct PasswordAuthHandler {
    password: String,
}

impl PasswordAuthHandler {
    pub fn new(password: String) -> Self {
        Self { password }
    }
}

impl AuthHandler for PasswordAuthHandler {
    fn select_security_type(&mut self, types: &[u8]) -> Result<u8, VncError> {
        if types.contains(&2) {
            Ok(2) // VNC Auth
        } else if types.contains(&1) {
            Ok(1) // None
        } else {
            Err(VncError::AuthFailed(format!(
                "No supported auth types (server offered {:?})",
                types
            )))
        }
    }

    fn authenticate_vnc(&mut self, stream: &mut dyn Stream) -> Result<(), VncError> {
        // Read 16-byte challenge
        let mut challenge = [0u8; 16];
        stream.read_exact(&mut challenge)?;

        // Encrypt challenge with DES-ECB (two independent 8-byte blocks)
        let response = encrypt_challenge(&challenge, &self.password)?;
        stream.write_all(&response)?;

        // Read security result
        let mut result = [0u8; 4];
        stream.read_exact(&mut result)?;
        let result = u32::from_be_bytes(result);
        if result != 0 {
            return Err(VncError::AuthFailed("Invalid password".to_string()));
        }

        Ok(())
    }
}
