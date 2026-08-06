//! Configuration file and command-line parsing.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use log::warn;

/// Server configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub address: String,
    pub port: u16,
    pub name: String,
    pub max_rate: u32,
    pub output: Option<String>,
    pub seat: Option<String>,
    pub disable_input: bool,
    pub overlay_cursor: bool,
    pub private_key_file: Option<String>,
    pub certificate_file: Option<String>,
    pub rsa_private_key_file: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub enable_auth: bool,
    pub enable_rsa_aes: bool,
    pub enable_vencrypt: bool,
    pub enable_encryption: bool,
    pub config_file: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            address: "127.0.0.1".to_string(),
            port: 5900,
            name: "wayvnc".to_string(),
            max_rate: 30,
            output: None,
            seat: None,
            disable_input: false,
            overlay_cursor: false,
            private_key_file: None,
            certificate_file: None,
            rsa_private_key_file: None,
            username: None,
            password: None,
            enable_auth: false,
            enable_rsa_aes: true,
            enable_vencrypt: false,
            enable_encryption: false,
            config_file: None,
        }
    }
}

/// Parse a simple INI-style config file.
///
/// Format:
/// ```ini
/// [vnc]
/// address = 127.0.0.1
/// port = 5900
/// name = wayvnc
///
/// [capture]
/// max_rate = 30
/// output = HDMI-A-1
/// ```
pub fn parse_file(path: &Path) -> Result<Config, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("Failed to read config file: {}", e))?;

    let mut config = Config::default();
    let mut current_section = String::new();

    for (line_no, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len() - 1].to_lowercase();
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            warn!("Config line {}: invalid syntax: {}", line_no + 1, line);
            continue;
        };

        let key = key.trim().to_lowercase();
        let value = value.trim();

        match (current_section.as_str(), key.as_str()) {
            ("vnc" | "", "address") => config.address = value.to_string(),
            ("vnc" | "", "port") => {
                config.port = value.parse().unwrap_or(5900);
            }
            ("vnc" | "", "name") => config.name = value.to_string(),
            ("capture" | "", "max_rate") | ("capture" | "", "max-rate") => {
                config.max_rate = value.parse().unwrap_or(30);
            }
            ("capture" | "", "output") => config.output = Some(value.to_string()),
            ("capture" | "", "seat") => config.seat = Some(value.to_string()),
            ("capture" | "", "overlay_cursor") | ("capture" | "", "overlay-cursor") => {
                config.overlay_cursor = value.parse().unwrap_or(false);
            }
            ("input" | "", "disable") => {
                config.disable_input = value.parse().unwrap_or(false);
            }
            ("auth" | "", "username") => config.username = Some(value.to_string()),
            ("auth" | "", "password") => config.password = Some(value.to_string()),
            ("auth" | "", "enable") => {
                config.enable_auth = value.parse().unwrap_or(false);
            }
            ("auth" | "", "rsa_aes") | ("auth" | "", "rsa-aes") => {
                config.enable_rsa_aes = value.parse().unwrap_or(true);
            }
            ("auth" | "", "vencrypt") => {
                config.enable_vencrypt = value.parse().unwrap_or(false);
            }
            ("auth" | "", "encryption") => {
                config.enable_encryption = value.parse().unwrap_or(false);
                config.enable_vencrypt = config.enable_vencrypt || config.enable_encryption;
            }
            ("tls" | "", "private_key") | ("tls" | "", "private-key") => {
                config.private_key_file = Some(value.to_string());
            }
            ("tls" | "", "certificate") => {
                config.certificate_file = Some(value.to_string());
            }
            ("tls" | "", "rsa_private_key") | ("tls" | "", "rsa-private-key") => {
                config.rsa_private_key_file = Some(value.to_string());
            }
            _ => {
                warn!("Unknown config option: [{}] {}", current_section, key);
            }
        }
    }

    Ok(config)
}

/// Merge config from file with command-line overrides.
///
/// `cli_explicit` names the CLI arguments that were explicitly provided on
/// the command line (keys: "address", "port", "name", "max_rate",
/// "rsa_aes", "vencrypt"). Only those valued fields override the config
/// file: a default value that the user did not type must not silently win
/// over the file, and an explicitly typed value must win even when it equals
/// the built-in default (e.g. `-p 5900` overrides `port = 6000` in the
/// file). Optional fields (`output`, `seat`, credentials, TLS files) and
/// enable-only flags override whenever they are set, since that already
/// means the user passed them.
pub fn merge_configs(
    file_config: Option<Config>,
    cli_config: Config,
    cli_explicit: &HashSet<&'static str>,
) -> Config {
    let mut base = file_config.unwrap_or_default();

    // CLI overrides file config, but only for arguments actually provided.
    if cli_explicit.contains("address") {
        base.address = cli_config.address;
    }
    if cli_explicit.contains("port") {
        base.port = cli_config.port;
    }
    if cli_explicit.contains("name") {
        base.name = cli_config.name;
    }
    if cli_explicit.contains("max_rate") {
        base.max_rate = cli_config.max_rate;
    }
    if cli_config.output.is_some() {
        base.output = cli_config.output;
    }
    if cli_config.seat.is_some() {
        base.seat = cli_config.seat;
    }
    if cli_config.disable_input {
        base.disable_input = true;
    }
    if cli_config.overlay_cursor {
        base.overlay_cursor = true;
    }
    if cli_config.username.is_some() {
        base.username = cli_config.username;
    }
    if cli_config.password.is_some() {
        base.password = cli_config.password;
    }
    if cli_config.enable_auth {
        base.enable_auth = true;
    }
    if cli_explicit.contains("rsa_aes") {
        base.enable_rsa_aes = cli_config.enable_rsa_aes;
    }
    if cli_explicit.contains("vencrypt") {
        base.enable_vencrypt = cli_config.enable_vencrypt;
    }
    if cli_config.enable_encryption {
        base.enable_encryption = true;
        base.enable_vencrypt = true;
    }
    if cli_config.private_key_file.is_some() {
        base.private_key_file = cli_config.private_key_file;
    }
    if cli_config.certificate_file.is_some() {
        base.certificate_file = cli_config.certificate_file;
    }
    if cli_config.rsa_private_key_file.is_some() {
        base.rsa_private_key_file = cli_config.rsa_private_key_file;
    }

    base
}

#[cfg(test)]
mod tests {
    use super::*;

    fn explicit(keys: &[&'static str]) -> HashSet<&'static str> {
        keys.iter().copied().collect()
    }

    #[test]
    fn cli_default_does_not_override_file() {
        // No CLI args provided: the file's port wins over the CLI default.
        let file = Config {
            port: 6000,
            max_rate: 60,
            ..Default::default()
        };
        let merged = merge_configs(Some(file), Config::default(), &explicit(&[]));
        assert_eq!(merged.port, 6000);
        assert_eq!(merged.max_rate, 60);
    }

    #[test]
    fn explicit_cli_value_overrides_file() {
        // `-p 5900` explicitly typed: overrides the file's port even though
        // it equals the built-in default.
        let file = Config {
            port: 6000,
            ..Default::default()
        };
        let merged = merge_configs(Some(file), Config::default(), &explicit(&["port"]));
        assert_eq!(merged.port, 5900);
    }

    #[test]
    fn explicit_disable_rsa_aes_overrides_file() {
        // File enables RSA-AES; `--disable-rsa-aes` must be able to turn it
        // off (the CLI default is `true`, so value comparison cannot tell).
        let file = Config {
            enable_rsa_aes: true,
            ..Default::default()
        };
        let cli = Config {
            enable_rsa_aes: false,
            ..Default::default()
        };
        let merged = merge_configs(Some(file), cli, &explicit(&["rsa_aes"]));
        assert!(!merged.enable_rsa_aes);
    }

    #[test]
    fn unset_rsa_aes_keeps_file_value() {
        let file = Config {
            enable_rsa_aes: false,
            ..Default::default()
        };
        let merged = merge_configs(Some(file), Config::default(), &explicit(&[]));
        assert!(!merged.enable_rsa_aes);
    }
}
