use gtk4::gio;
use gtk4::prelude::SettingsExtManual;
use serde::{Deserialize, Serialize};

const HISTORY_KEY: &str = "connection-history";

/// Single saved connection profile. Passwords are intentionally not stored.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub host: String,
    pub port: u32,
    pub username: String,
    pub auth_method: String,
    pub use_tls: bool,
    pub preferred_encoding: String,
    pub high_performance: bool,
    pub media_stream_h264: bool,
}

impl HistoryEntry {
    pub fn summary(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn detail(&self) -> String {
        let tls = if self.use_tls { "TLS" } else { "PLAIN" };
        format!(
            "{} | {} | {}",
            self.auth_method, tls, self.preferred_encoding
        )
    }
}

pub fn load_history(settings: &gio::Settings) -> Vec<HistoryEntry> {
    let strs = settings.strv(HISTORY_KEY);
    strs.iter()
        .filter_map(|s| serde_json::from_str(s.as_str()).ok())
        .collect()
}

pub fn save_history(settings: &gio::Settings, history: &[HistoryEntry]) {
    let strs: Vec<String> = history
        .iter()
        .map(|e| serde_json::to_string(e).unwrap_or_default())
        .collect();
    let _ = settings.set_strv(HISTORY_KEY, strs);
}

pub fn add_history_entry(settings: &gio::Settings, entry: HistoryEntry) {
    let mut history = load_history(settings);
    history.retain(|e| e.summary() != entry.summary());
    history.insert(0, entry);
    save_history(settings, &history);
}

pub fn remove_history_entry(settings: &gio::Settings, summary: &str) {
    let mut history = load_history(settings);
    history.retain(|e| e.summary() != summary);
    save_history(settings, &history);
}

/// Try to load the GSettings schema, preferring the system installation.
/// In debug builds, fall back to the schema compiled into `data/` by `build.rs`
/// so that `cargo run` works without installing or setting environment
/// variables.
pub fn load_settings(schema_id: &str) -> Option<gio::Settings> {
    if let Some(source) = gio::SettingsSchemaSource::default() {
        if source.lookup(schema_id, true).is_some() {
            return Some(gio::Settings::new(schema_id));
        }
    }

    if cfg!(debug_assertions) {
        let data_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data");
        if let Ok(source) = gio::SettingsSchemaSource::from_directory(&data_dir, None, false) {
            if let Some(schema) = source.lookup(schema_id, false) {
                return Some(gio::Settings::new_full(
                    &schema,
                    None::<&gio::SettingsBackend>,
                    None,
                ));
            }
        }
    }

    None
}
