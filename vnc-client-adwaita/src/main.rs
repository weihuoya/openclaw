use adw::prelude::*;
use gettextrs::{bindtextdomain, setlocale, textdomain, LocaleCategory};

mod encoding;
mod network;
mod settings;
mod stats;
mod ui;

const APP_ID: &str = "com.weiz.vnc-client-adwaita";

fn main() -> glib::ExitCode {
    env_logger::init();

    setlocale(LocaleCategory::LcAll, "");
    let locale_dir = std::env::var("VNC_LOCALE_DIR").unwrap_or_else(|_| {
        if cfg!(debug_assertions) {
            concat!(env!("CARGO_MANIFEST_DIR"), "/locale").to_string()
        } else {
            "/usr/share/locale".to_string()
        }
    });
    bindtextdomain("com.weiz.vnc-client-adwaita", &locale_dir).ok();
    textdomain("com.weiz.vnc-client-adwaita").ok();

    let app = adw::Application::new(Some(APP_ID), Default::default());
    app.connect_activate(ui::build_ui);
    app.run()
}
