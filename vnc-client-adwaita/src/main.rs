use adw::prelude::*;
use glib::clone;

use gtk4::{gio, glib};
use gtk4_vnc::HandshakeResult;
use gtk4_vnc::VncDisplay;
use vnc_client::auth::{NoAuthHandler, PasswordAuthHandler};
use vnc_client::encodings::Encoding;

use gettextrs::{bindtextdomain, gettext, setlocale, textdomain, LocaleCategory};

use std::process;

const APP_ID: &str = "com.weiz.vnc-client-adwaita";
const SCHEMA_ID: &str = "com.weiz.vnc-client-adwaita";

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
    app.connect_activate(build_ui);
    app.run()
}

/// Try to load the GSettings schema, preferring the system installation.
/// In debug builds, fall back to the schema compiled into `data/` by `build.rs`
/// so that `cargo run` works without installing or setting environment
/// variables.
fn load_settings(schema_id: &str) -> Option<gio::Settings> {
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

fn build_ui(app: &adw::Application) {
    let settings = load_settings(SCHEMA_ID).unwrap_or_else(|| {
        let msg = gettext("GSettings schema '{}' not found.");
        eprintln!("{}", msg.replacen("{}", SCHEMA_ID, 1));
        eprintln!(
            "{}",
            gettext("Compile it with: glib-compile-schemas vnc-client-adwaita/data/")
        );
        eprintln!("{}", gettext("Run with: GSETTINGS_SCHEMA_DIR=vnc-client-adwaita/data cargo run -p vnc-client-adwaita"));
        process::exit(1);
    });

    let window = adw::ApplicationWindow::new(app);
    window.set_title(Some(&gettext("VNC Client")));
    window.set_default_size(900, 700);

    let toast_overlay = adw::ToastOverlay::new();
    window.set_content(Some(&toast_overlay));

    let root_box = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    toast_overlay.set_child(Some(&root_box));

    let header = adw::HeaderBar::new();
    let title = adw::WindowTitle::new(&gettext("VNC Client"), "");
    header.set_title_widget(Some(&title));
    root_box.append(&header);

    // Display container with optional scroll
    let display_container = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    display_container.set_hexpand(true);
    display_container.set_vexpand(true);
    root_box.append(&display_container);

    let vnc_display = VncDisplay::new();
    vnc_display.set_hexpand(true);
    vnc_display.set_vexpand(true);

    // Stats overlay (hidden by default, toggled from the header bar)
    let stats_label = gtk4::Label::new(None);
    stats_label.set_halign(gtk4::Align::Start);
    stats_label.set_valign(gtk4::Align::Start);
    stats_label.set_margin_start(12);
    stats_label.set_margin_top(12);
    stats_label.add_css_class("stats-overlay");

    let stats_revealer = gtk4::Revealer::new();
    stats_revealer.set_child(Some(&stats_label));
    stats_revealer.set_transition_type(gtk4::RevealerTransitionType::SlideDown);
    stats_revealer.set_reveal_child(false);

    let display_overlay = gtk4::Overlay::new();
    display_overlay.set_child(Some(&vnc_display));
    display_overlay.add_overlay(&stats_revealer);
    display_container.append(&display_overlay);

    let update_scale_container = clone!(
        #[weak]
        display_container,
        #[weak]
        display_overlay,
        move |scale_to_fit: bool| {
            // Rebuild the container: either place the overlay directly (scale to
            // fit) or inside a ScrolledWindow (1:1 native resolution).
            while let Some(child) = display_container.first_child() {
                display_container.remove(&child);
            }
            if scale_to_fit {
                display_container.append(&display_overlay);
            } else {
                let scrolled = gtk4::ScrolledWindow::new();
                scrolled.set_hexpand(true);
                scrolled.set_vexpand(true);
                scrolled.set_child(Some(&display_overlay));
                display_container.append(&scrolled);
            }
        }
    );

    settings.connect_changed(
        Some("scale-to-fit"),
        clone!(
            #[strong]
            update_scale_container,
            move |settings, _key| {
                update_scale_container(settings.boolean("scale-to-fit"));
            }
        ),
    );
    update_scale_container(settings.boolean("scale-to-fit"));

    // Style for the stats overlay
    let provider = gtk4::CssProvider::new();
    provider.load_from_string(
        ".stats-overlay { background-color: rgba(0, 0, 0, 0.7); color: white; border-radius: 6px; padding: 6px 10px; font-family: monospace; }"
    );
    gtk4::style_context_add_provider_for_display(
        &gtk4::gdk::Display::default().expect("display"),
        &provider,
        gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );

    // Stats toggle button in the header bar
    let stats_toggle = gtk4::ToggleButton::new();
    stats_toggle.set_icon_name("utilities-system-monitor-symbolic");
    stats_toggle.set_tooltip_text(Some(&gettext("Show connection statistics")));
    stats_toggle.set_valign(gtk4::Align::Center);
    header.pack_end(&stats_toggle);

    stats_toggle.connect_toggled(clone!(
        #[weak]
        stats_revealer,
        move |btn| {
            stats_revealer.set_reveal_child(btn.is_active());
        }
    ));

    // Connect / Disconnect button in the header bar
    let connect_btn = gtk4::Button::with_label(&gettext("Connect"));
    connect_btn.set_valign(gtk4::Align::Center);
    connect_btn.add_css_class("suggested-action");
    header.pack_start(&connect_btn);

    // (Preferences were moved into the Connect dialog.)

    // Error callback
    vnc_display.set_error_callback(Box::new(clone!(
        #[weak]
        toast_overlay,
        #[weak]
        connect_btn,
        move |msg: String| {
            log::error!("VNC error: {}", msg);
            toast_overlay.add_toast(adw::Toast::new(&msg));
            connect_btn.set_sensitive(true);
            connect_btn.set_label(&gettext("Connect"));
        }
    )));

    // View-only
    let vnc_display_for_view_only = vnc_display.clone();
    settings.connect_changed(Some("view-only"), move |settings, _key| {
        vnc_display_for_view_only.set_view_only(settings.boolean("view-only"));
    });
    vnc_display.set_view_only(settings.boolean("view-only"));

    // Header button toggles between Connect and Disconnect
    connect_btn.connect_clicked(clone!(
        #[weak]
        window,
        #[weak]
        vnc_display,
        #[strong]
        settings,
        #[weak]
        toast_overlay,
        #[weak]
        connect_btn,
        move |_| {
            let label = connect_btn
                .label()
                .map(|l| l.to_string())
                .unwrap_or_default();
            if label == gettext("Disconnect") {
                show_disconnect_confirm_dialog(&window, &vnc_display, &connect_btn);
            } else {
                show_connect_dialog(
                    &window,
                    &vnc_display,
                    &settings,
                    &toast_overlay,
                    &connect_btn,
                );
            }
        }
    ));

    // Poll connection stats once per second and update the overlay.
    let vnc_display_weak = vnc_display.downgrade();
    let stats_label_weak = stats_label.downgrade();
    glib::source::timeout_add_local(std::time::Duration::from_secs(1), move || {
        let Some(vnc_display) = vnc_display_weak.upgrade() else {
            return glib::ControlFlow::Break;
        };
        let Some(stats_label) = stats_label_weak.upgrade() else {
            return glib::ControlFlow::Break;
        };
        let stats = vnc_display.stats();
        stats_label.set_text(&format_stats(&stats));
        glib::ControlFlow::Continue
    });

    window.present();
}

fn show_connect_dialog(
    parent: &adw::ApplicationWindow,
    vnc_display: &VncDisplay,
    settings: &gio::Settings,
    toast_overlay: &adw::ToastOverlay,
    connect_btn: &gtk4::Button,
) {
    // Server group
    let host_row = adw::EntryRow::new();
    host_row.set_title(&gettext("Host"));
    host_row.set_text(&settings.string("host"));
    host_row.set_activates_default(true);

    let port_row = adw::SpinRow::with_range(1.0, 65535.0, 1.0);
    port_row.set_title(&gettext("Port"));
    port_row.set_value(settings.uint("port") as f64);
    port_row.set_numeric(true);

    let user_row = adw::EntryRow::new();
    user_row.set_title(&gettext("Username"));
    user_row.set_text(&settings.string("username"));
    user_row.set_activates_default(true);

    let password_row = adw::PasswordEntryRow::new();
    password_row.set_title(&gettext("Password"));
    password_row.set_activates_default(true);

    // Username and password are only meaningful for password-based authentication.
    let auth_requires_credentials = settings.string("auth-method").as_str() == "password";
    user_row.set_visible(auth_requires_credentials);
    password_row.set_visible(auth_requires_credentials);
    settings.connect_changed(
        Some("auth-method"),
        clone!(
            #[weak]
            user_row,
            #[weak]
            password_row,
            move |settings, _key| {
                let visible = settings.string("auth-method").as_str() == "password";
                user_row.set_visible(visible);
                password_row.set_visible(visible);
            }
        ),
    );

    let server_group = adw::PreferencesGroup::new();
    server_group.set_title(&gettext("Server"));
    server_group.add(&host_row);
    server_group.add(&port_row);
    server_group.add(&user_row);
    server_group.add(&password_row);

    // Options group (previously in the Preferences window)
    let auth_row = combo_row_for_settings(
        &gettext("Authentication method"),
        &["none", "password"],
        &settings,
        "auth-method",
    );

    let enc_row = combo_row_for_settings(
        &gettext("Preferred encoding"),
        &[
            "zrle", "hextile", "raw", "copyrect", "trle", "rre", "tight", "openh264",
        ],
        &settings,
        "preferred-encoding",
    );

    let view_only_row = adw::SwitchRow::new();
    view_only_row.set_title(&gettext("View only"));
    settings.bind("view-only", &view_only_row, "active").build();

    let scale_row = adw::SwitchRow::new();
    scale_row.set_title(&gettext("Scale to fit"));
    settings.bind("scale-to-fit", &scale_row, "active").build();

    let options_group = adw::PreferencesGroup::new();
    options_group.set_title(&gettext("Options"));
    options_group.add(&auth_row);
    options_group.add(&enc_row);
    options_group.add(&view_only_row);
    options_group.add(&scale_row);

    let preferences_page = adw::PreferencesPage::new();
    preferences_page.add(&server_group);
    preferences_page.add(&options_group);

    // Bottom action buttons (same width)
    let cancel_btn = gtk4::Button::with_label(&gettext("Cancel"));
    cancel_btn.add_css_class("pill");
    let dialog_connect_btn = gtk4::Button::with_label(&gettext("Connect"));
    dialog_connect_btn.add_css_class("pill");
    dialog_connect_btn.add_css_class("suggested-action");

    let button_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 12);
    button_box.set_homogeneous(true);
    button_box.set_halign(gtk4::Align::Center);
    button_box.set_margin_end(12);
    button_box.set_margin_bottom(12);
    button_box.set_margin_start(12);
    button_box.append(&cancel_btn);
    button_box.append(&dialog_connect_btn);

    let toolbar_view = adw::ToolbarView::new();
    let header_bar = adw::HeaderBar::new();
    toolbar_view.add_top_bar(&header_bar);
    toolbar_view.set_content(Some(&preferences_page));
    toolbar_view.add_bottom_bar(&button_box);

    let dialog = adw::Dialog::builder()
        .title(&gettext("Connect to VNC server"))
        .child(&toolbar_view)
        .content_width(560)
        .content_height(640)
        .default_widget(&dialog_connect_btn)
        .build();

    // Handshake result: keep the dialog open until the server confirms the
    // connection. On failure, show a Toast and restrict the auth-method list to
    // the security types actually advertised by the server.
    vnc_display.set_handshake_callback(Box::new(clone!(
        #[weak]
        dialog,
        #[weak]
        auth_row,
        #[weak]
        toast_overlay,
        #[weak]
        connect_btn,
        #[weak]
        dialog_connect_btn,
        #[strong]
        settings,
        move |result: HandshakeResult| {
            if !result.success {
                dialog_connect_btn.set_sensitive(true);
                if let Some(error) = result.error {
                    log::error!("VNC handshake failed: {}", error);
                    toast_overlay.add_toast(adw::Toast::new(&error));
                }
                update_auth_row_from_supported_types(
                    &auth_row,
                    &result.supported_auth_types,
                    &settings,
                );
                return;
            }
            connect_btn.set_label(&gettext("Disconnect"));
            dialog.close();
        }
    )));

    cancel_btn.connect_clicked(clone!(
        #[weak]
        dialog,
        move |_| {
            dialog.close();
        }
    ));
    dialog_connect_btn.connect_clicked(clone!(
        #[weak]
        host_row,
        #[weak]
        port_row,
        #[weak]
        user_row,
        #[weak]
        password_row,
        #[weak]
        vnc_display,
        #[strong]
        settings,
        #[weak]
        toast_overlay,
        #[weak]
        dialog_connect_btn,
        move |_| {
            let host = host_row.text();
            if host.is_empty() {
                let msg = gettext("Host cannot be empty");
                log::error!("{}", msg);
                toast_overlay.add_toast(adw::Toast::new(&msg));
                return;
            }
            let port = port_row.value() as u16;
            let password = password_row.text();
            let username = user_row.text();

            let _ = settings.set_string("host", &host);
            let _ = settings.set_uint("port", port as u32);
            let _ = settings.set_string("username", &username);

            let auth_method = settings.string("auth-method");
            let auth: Box<dyn vnc_client::auth::AuthHandler + Send> =
                if auth_method.as_str() == "password" {
                    if password.is_empty() {
                        let msg = gettext("Password is required");
                        log::error!("{}", msg);
                        toast_overlay.add_toast(adw::Toast::new(&msg));
                        return;
                    }
                    Box::new(PasswordAuthHandler::new(password.to_string()))
                } else {
                    Box::new(NoAuthHandler)
                };

            let preferred = settings.string("preferred-encoding");
            let encodings = build_encoding_list(&preferred);

            match vnc_display.connect_with_options(&host, port, false, auth, &encodings) {
                Ok(()) => {
                    dialog_connect_btn.set_sensitive(false);
                    // Don't keep the password in memory longer than necessary.
                    password_row.set_text("");
                }
                Err(e) => {
                    log::error!("VNC connection failed: {}", e);
                    toast_overlay.add_toast(adw::Toast::new(&e));
                }
            }
        }
    ));

    dialog.present(Some(parent));
}

fn show_disconnect_confirm_dialog(
    parent: &adw::ApplicationWindow,
    vnc_display: &VncDisplay,
    connect_btn: &gtk4::Button,
) {
    let dialog = adw::AlertDialog::new(
        Some(&gettext("Disconnect?")),
        Some(&gettext(
            "Are you sure you want to disconnect from the current server?",
        )),
    );
    dialog.add_response("cancel", &gettext("Cancel"));
    dialog.add_response("disconnect", &gettext("Disconnect"));
    dialog.set_response_appearance("disconnect", adw::ResponseAppearance::Destructive);
    dialog.set_default_response(Some("cancel"));

    dialog.choose(
        Some(parent),
        None::<&gio::Cancellable>,
        clone!(
            #[weak]
            vnc_display,
            #[weak]
            connect_btn,
            move |response: glib::GString| {
                if response == "disconnect" {
                    vnc_display.disconnect();
                    connect_btn.set_label(&gettext("Connect"));
                }
            }
        ),
    );
}

fn update_auth_row_from_supported_types(
    auth_row: &adw::ComboRow,
    supported_types: &[u8],
    settings: &gio::Settings,
) {
    // Map the RFB security types supported by the UI to option IDs.
    let mut options: Vec<&str> = Vec::new();
    if supported_types.contains(&1) {
        options.push("none");
    }
    if supported_types.contains(&2) {
        options.push("password");
    }
    if options.is_empty() {
        // The server offered nothing we can use; leave a placeholder so the
        // row is not empty while we show the error to the user.
        options.push("none");
    }

    let model = gtk4::StringList::new(options.as_slice());
    auth_row.set_model(Some(&model));

    // Prefer the user's current setting if the server still supports it,
    // otherwise fall back to the first supported option.
    let current = settings.string("auth-method");
    if let Some(pos) = options.iter().position(|s| *s == current.as_str()) {
        auth_row.set_selected(pos as u32);
    } else {
        auth_row.set_selected(0);
        let _ = settings.set_string("auth-method", options[0]);
    }
}

fn combo_row_for_settings(
    title: &str,
    options: &[&str],
    settings: &gio::Settings,
    key: &str,
) -> adw::ComboRow {
    let row = adw::ComboRow::new();
    row.set_title(title);
    row.set_use_subtitle(false);

    let model = gtk4::StringList::new(options);
    row.set_model(Some(&model));

    let current = settings.string(key);
    let selected = options
        .iter()
        .position(|s| *s == current.as_str())
        .unwrap_or(0) as u32;
    row.set_selected(selected);

    let key = key.to_string();
    row.connect_selected_notify(clone!(
        #[strong]
        settings,
        move |row| {
            if let Some(item) = row.selected_item() {
                if let Some(obj) = item.downcast_ref::<gtk4::StringObject>() {
                    let _ = settings.set_string(&key, &obj.string());
                }
            }
        }
    ));

    row
}

fn build_encoding_list(preferred: &str) -> Vec<Encoding> {
    let preferred = preferred.to_lowercase();
    let mut encodings = Vec::new();

    match preferred.as_str() {
        "tight" => encodings.push(Encoding::Tight),
        "zrle" => encodings.push(Encoding::Zrle),
        "hextile" => encodings.push(Encoding::Hextile),
        "raw" => encodings.push(Encoding::Raw),
        "copyrect" => encodings.push(Encoding::CopyRect),
        "trle" => encodings.push(Encoding::Trle),
        "rre" => encodings.push(Encoding::Rre),
        "openh264" => encodings.push(Encoding::OpenH264),
        _ => encodings.push(Encoding::Tight),
    }

    // Fallback encodings (avoid Raw by default; servers tend to send it for
    // full-frame updates and it is sensitive to exact pixel-format matching).
    for enc in [
        Encoding::Zrle,
        Encoding::Hextile,
        Encoding::CopyRect,
        Encoding::OpenH264,
    ] {
        if !encodings.contains(&enc) {
            encodings.push(enc);
        }
    }

    encodings.push(Encoding::DesktopSize);
    encodings.push(Encoding::Cursor);
    encodings.push(Encoding::ContinuousUpdates);

    encodings
}

fn format_stats(stats: &vnc_client::ConnectionStats) -> String {
    format!(
        "{} | {}x{} | {:.1} FPS | RX {}/s | TX {}/s",
        stats.encoding,
        stats.width,
        stats.height,
        stats.fps,
        format_bytes(stats.rx_bytes_per_second),
        format_bytes(stats.tx_bytes_per_second)
    )
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024 * 1024 * 1024) as f64)
    } else if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024 * 1024) as f64)
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}
