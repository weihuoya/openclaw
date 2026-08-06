use std::rc::Rc;

use adw::prelude::*;
use glib::clone;
use gtk4::{gio, glib};
use gtk4_vnc::{HandshakeResult, VncDisplay};
use vnc_client::auth::{AppleDhAuthHandler, NoAuthHandler, PasswordAuthHandler};

use gettextrs::gettext;

use crate::encoding::build_encoding_list;
use crate::settings::{add_history_entry, HistoryEntry};
use crate::ui::{ConnectionVisibilityFn, RefreshHistoryFn};

#[allow(clippy::too_many_arguments)]
pub fn show_connect_dialog(
    parent: &adw::ApplicationWindow,
    vnc_display: &VncDisplay,
    settings: &gio::Settings,
    main_error_cb: &Rc<dyn Fn(String)>,
    connect_btn: &gtk4::Button,
    history_entry: Option<&HistoryEntry>,
    set_connection_visible: &ConnectionVisibilityFn,
    refresh_history: &RefreshHistoryFn,
) {
    // If a history entry was selected, populate the form with its values.
    if let Some(entry) = history_entry {
        let _ = settings.set_string("host", &entry.host);
        let _ = settings.set_uint("port", entry.port);
        let _ = settings.set_string("username", &entry.username);
        let _ = settings.set_string("auth-method", &entry.auth_method);
        let _ = settings.set_boolean("use-tls", entry.use_tls);
        let _ = settings.set_string("preferred-encoding", &entry.preferred_encoding);
    }

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

    // Username and password are required for VNC password auth and Apple DH.
    let auth_requires_credentials = matches!(
        settings.string("auth-method").as_str(),
        "password" | "apple-dh"
    );
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
                let visible = matches!(
                    settings.string("auth-method").as_str(),
                    "password" | "apple-dh"
                );
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
        &["none", "password", "apple-dh", "vencrypt"],
        settings,
        "auth-method",
    );

    let enc_row = combo_row_for_settings(
        &gettext("Preferred encoding"),
        &[
            "zrle", "hextile", "raw", "copyrect", "trle", "rre", "tight", "openh264",
        ],
        settings,
        "preferred-encoding",
    );

    let tls_row = adw::SwitchRow::new();
    tls_row.set_title(&gettext("Use TLS"));
    settings.bind("use-tls", &tls_row, "active").build();

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
    options_group.add(&tls_row);
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

    // Put a ToastOverlay inside the dialog so validation and connection errors
    // are visible above the dialog content rather than hidden behind the modal.
    let dialog_toast_overlay = adw::ToastOverlay::new();
    dialog_toast_overlay.set_child(Some(&toolbar_view));

    let dialog = adw::Dialog::builder()
        .title(gettext("Connect to VNC server"))
        .child(&dialog_toast_overlay)
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
        dialog_toast_overlay,
        #[weak]
        connect_btn,
        #[weak]
        dialog_connect_btn,
        #[strong]
        settings,
        #[strong]
        set_connection_visible,
        #[strong]
        refresh_history,
        move |result: HandshakeResult| {
            if !result.success {
                dialog_connect_btn.set_sensitive(true);
                if let Some(error) = result.error {
                    log::error!("VNC handshake failed: {}", error);
                    dialog_toast_overlay.add_toast(adw::Toast::new(&error));
                }
                update_auth_row_from_supported_types(
                    &auth_row,
                    &result.supported_auth_types,
                    &settings,
                );
                return;
            }
            connect_btn.set_label(&gettext("Disconnect"));
            set_connection_visible(true);
            let entry = HistoryEntry {
                host: settings.string("host").to_string(),
                port: settings.uint("port"),
                username: settings.string("username").to_string(),
                auth_method: settings.string("auth-method").to_string(),
                use_tls: settings.boolean("use-tls"),
                preferred_encoding: settings.string("preferred-encoding").to_string(),
            };
            add_history_entry(&settings, entry);
            refresh_history();
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

    // Route async runtime errors to the dialog's own toast overlay while it is
    // open. When the dialog closes, restore the callback that targets the main
    // window overlay.
    let dialog_error_cb: Rc<dyn Fn(String)> = Rc::new(clone!(
        #[weak]
        dialog_toast_overlay,
        #[weak]
        connect_btn,
        #[weak]
        dialog_connect_btn,
        #[strong]
        set_connection_visible,
        move |msg: String| {
            log::error!("VNC error: {}", msg);
            dialog_toast_overlay.add_toast(adw::Toast::new(&msg));
            connect_btn.set_sensitive(true);
            connect_btn.set_label(&gettext("Connect"));
            dialog_connect_btn.set_sensitive(true);
            set_connection_visible(false);
        }
    ));
    vnc_display.set_error_callback(Box::new({
        let cb = dialog_error_cb.clone();
        move |msg| cb(msg)
    }));

    dialog.connect_closed(clone!(
        #[weak]
        vnc_display,
        #[strong]
        main_error_cb,
        move |_| {
            vnc_display.set_error_callback(Box::new({
                let cb = main_error_cb.clone();
                move |msg| cb(msg)
            }));
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
        dialog_toast_overlay,
        #[weak]
        dialog_connect_btn,
        move |_| {
            let host = host_row.text();
            if host.is_empty() {
                let msg = gettext("Host cannot be empty");
                log::error!("{}", msg);
                dialog_toast_overlay.add_toast(adw::Toast::new(&msg));
                return;
            }
            let port = port_row.value() as u16;
            let password = password_row.text();
            let username = user_row.text();

            let _ = settings.set_string("host", &host);
            let _ = settings.set_uint("port", port as u32);
            let _ = settings.set_string("username", &username);

            let auth_method = settings.string("auth-method");
            let auth: Box<dyn vnc_client::auth::AuthHandler + Send> = match auth_method.as_str() {
                "password" => {
                    if password.is_empty() {
                        let msg = gettext("Password is required");
                        log::error!("{}", msg);
                        dialog_toast_overlay.add_toast(adw::Toast::new(&msg));
                        return;
                    }
                    Box::new(PasswordAuthHandler::new(password.to_string()))
                }
                "apple-dh" => {
                    if username.is_empty() {
                        let msg = gettext("Username is required for Apple Remote Desktop");
                        log::error!("{}", msg);
                        dialog_toast_overlay.add_toast(adw::Toast::new(&msg));
                        return;
                    }
                    if password.is_empty() {
                        let msg = gettext("Password is required for Apple Remote Desktop");
                        log::error!("{}", msg);
                        dialog_toast_overlay.add_toast(adw::Toast::new(&msg));
                        return;
                    }
                    Box::new(AppleDhAuthHandler::new(
                        username.to_string(),
                        password.to_string(),
                    ))
                }
                "none" => Box::new(NoAuthHandler),
                "vencrypt" => {
                    let msg = gettext("VeNCrypt authentication is not yet supported");
                    log::error!("{}", msg);
                    dialog_toast_overlay.add_toast(adw::Toast::new(&msg));
                    return;
                }
                _ => {
                    let msg = gettext("Unknown authentication method");
                    log::error!("{}: {}", msg, auth_method);
                    dialog_toast_overlay.add_toast(adw::Toast::new(&msg));
                    return;
                }
            };

            let use_tls = settings.boolean("use-tls");

            let preferred = settings.string("preferred-encoding");
            let encodings = build_encoding_list(&preferred);

            match vnc_display.connect_with_options(&host, port, use_tls, auth, &encodings) {
                Ok(()) => {
                    dialog_connect_btn.set_sensitive(false);
                }
                Err(e) => {
                    log::error!("VNC connection failed: {}", e);
                    dialog_toast_overlay.add_toast(adw::Toast::new(&e));
                }
            }
        }
    ));

    dialog.present(Some(parent));
}

pub fn show_disconnect_confirm_dialog(
    parent: &adw::ApplicationWindow,
    vnc_display: &VncDisplay,
    connect_btn: &gtk4::Button,
    set_connection_visible: &ConnectionVisibilityFn,
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
            #[strong]
            set_connection_visible,
            move |response: glib::GString| {
                if response == "disconnect" {
                    vnc_display.disconnect();
                    connect_btn.set_label(&gettext("Connect"));
                    set_connection_visible(false);
                }
            }
        ),
    );
}

pub fn update_auth_row_from_supported_types(
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
    if supported_types.contains(&30) {
        options.push("apple-dh");
    }
    if supported_types.contains(&19) {
        options.push("vencrypt");
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

pub fn combo_row_for_settings(
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
