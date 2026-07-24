use std::io::{Read, Write};

use sasl::client::Mechanism;
use sasl::common::Credentials;

use crate::VncError;

/// Trait alias for Read + Write.
pub trait Stream: Read + Write {}
impl<T: Read + Write> Stream for T {}

/// SASL authentication handler for VeNCrypt.
///
/// VNC SASL protocol:
/// 1. Server sends list of supported mechanisms (count + names)
/// 2. Client selects one mechanism and sends its name
/// 3. Client sends initial payload (if any)
/// 4. Server sends status (0=OK, 1=CONTINUE, 2=ERROR) + data
/// 5. Repeat 4 until OK or ERROR
pub struct SaslAuth {
    credentials: Credentials,
}

impl SaslAuth {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            credentials: Credentials::default()
                .with_username(username)
                .with_password(password),
        }
    }

    pub fn authenticate(&self, stream: &mut dyn Stream) -> Result<(), VncError> {
        // Read number of mechanisms
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf)?;
        let num_mechanisms = u32::from_be_bytes(buf) as usize;

        let mut mechanisms = Vec::with_capacity(num_mechanisms);
        for _ in 0..num_mechanisms {
            stream.read_exact(&mut buf)?;
            let len = u32::from_be_bytes(buf) as usize;
            let mut name = vec![0u8; len];
            stream.read_exact(&mut name)?;
            mechanisms.push(String::from_utf8_lossy(&name).to_string());
        }

        // Select SCRAM-SHA-256 if available, else SCRAM-SHA-1, else PLAIN, else first
        let selected = if mechanisms.contains(&"SCRAM-SHA-256".to_string()) {
            "SCRAM-SHA-256"
        } else if mechanisms.contains(&"SCRAM-SHA-1".to_string()) {
            "SCRAM-SHA-1"
        } else if mechanisms.contains(&"PLAIN".to_string()) {
            "PLAIN"
        } else if !mechanisms.is_empty() {
            &mechanisms[0]
        } else {
            return Err(VncError::AuthFailed(
                "No SASL mechanisms offered by server".to_string(),
            ));
        };

        // Send selected mechanism name
        let name_bytes = selected.as_bytes();
        stream.write_all(&(name_bytes.len() as u32).to_be_bytes())?;
        stream.write_all(name_bytes)?;

        // Initialize mechanism
        let mut mech: Box<dyn Mechanism> = match selected {
            "PLAIN" => Box::new(
                sasl::client::mechanisms::Plain::from_credentials(self.credentials.clone())
                    .map_err(|e| VncError::AuthFailed(format!("SASL PLAIN init: {}", e)))?,
            ),
            "SCRAM-SHA-1" => Box::new(
                sasl::client::mechanisms::Scram::<sasl::common::scram::Sha1>::from_credentials(
                    self.credentials.clone(),
                )
                .map_err(|e| VncError::AuthFailed(format!("SASL SCRAM-SHA-1 init: {}", e)))?,
            ),
            "SCRAM-SHA-256" => Box::new(
                sasl::client::mechanisms::Scram::<sasl::common::scram::Sha256>::from_credentials(
                    self.credentials.clone(),
                )
                .map_err(|e| VncError::AuthFailed(format!("SASL SCRAM-SHA-256 init: {}", e)))?,
            ),
            _ => {
                return Err(VncError::AuthFailed(format!(
                    "Unsupported SASL mechanism: {}",
                    selected
                )));
            }
        };

        // Send initial payload
        let initial = mech.initial();
        if !initial.is_empty() {
            stream.write_all(&(initial.len() as u32).to_be_bytes())?;
            stream.write_all(&initial)?;
        } else {
            stream.write_all(&0u32.to_be_bytes())?;
        }

        // Authentication loop
        loop {
            stream.read_exact(&mut buf)?;
            let status = u32::from_be_bytes(buf);
            stream.read_exact(&mut buf)?;
            let data_len = u32::from_be_bytes(buf) as usize;
            let mut data = vec![0u8; data_len];
            if data_len > 0 {
                stream.read_exact(&mut data)?;
            }

            match status {
                0 => {
                    // OK
                    if !data.is_empty() {
                        mech.success(&data).map_err(|e| {
                            VncError::AuthFailed(format!("SASL success verify: {}", e))
                        })?;
                    }
                    return Ok(());
                }
                1 => {
                    // CONTINUE
                    let response = mech
                        .response(&data)
                        .map_err(|e| VncError::AuthFailed(format!("SASL response: {}", e)))?;
                    stream.write_all(&(response.len() as u32).to_be_bytes())?;
                    stream.write_all(&response)?;
                }
                2 => {
                    return Err(VncError::AuthFailed(format!(
                        "SASL authentication failed: {}",
                        String::from_utf8_lossy(&data)
                    )));
                }
                _ => {
                    return Err(VncError::Protocol(format!(
                        "Unknown SASL status: {}",
                        status
                    )));
                }
            }
        }
    }
}
