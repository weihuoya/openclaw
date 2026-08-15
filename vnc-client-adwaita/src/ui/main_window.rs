use std::process;
use std::rc::Rc;
use std::time::Duration;

use adw::prelude::*;
use glib::clone;
use gtk4::glib;
use gtk4_vnc::VncDisplay;

use gettextrs::gettext;

use crate::settings::load_settings;
use crate::stats::format_stats;
use crate::ui::connect_dialog::{show_connect_dialog, show_disconnect_confirm_dialog};
use crate::ui::history::setup_history;
use crate::ui::{media_stream_error_message, ConnectionVisibilityFn};

const SCHEMA_ID: &str = "com.weiz.vnc-client-adwaita";

pub fn build_ui(app: &adw::Application) {
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
    title.set_subtitle(&gettext("Recent Connections"));
    header.set_title_widget(Some(&title));
    root_box.append(&header);

    // Display container with optional scroll. Hidden until a connection is
    // established; the recent-connections page is shown instead while disconnected.
    let display_container = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    display_container.set_hexpand(true);
    display_container.set_vexpand(true);
    display_container.set_visible(false);
    root_box.append(&display_container);

    let history_group = adw::PreferencesGroup::new();
    // The PreferencesPage provides the title and surrounding spacing, so keep
    // the group itself free of margins and title to avoid duplication.
    history_group.set_margin_top(0);
    history_group.set_margin_bottom(0);
    history_group.set_margin_start(0);
    history_group.set_margin_end(0);

    let preferences_page = adw::PreferencesPage::new();
    preferences_page.set_title(&gettext("Recent Connections"));
    preferences_page.set_icon_name(Some("document-open-recent-symbolic"));
    preferences_page.add(&history_group);
    preferences_page.set_hexpand(true);
    preferences_page.set_vexpand(true);
    root_box.append(&preferences_page);

    // Toggle between the VNC display and the recent-connections page.
    let set_connection_visible: ConnectionVisibilityFn = Rc::new(clone!(
        #[weak]
        display_container,
        #[weak]
        preferences_page,
        #[weak]
        title,
        move |connected: bool| {
            display_container.set_visible(connected);
            preferences_page.set_visible(!connected);
            let subtitle = if connected {
                String::new()
            } else {
                gettext("Recent Connections")
            };
            title.set_subtitle(&subtitle);
        }
    ));

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
    stats_revealer.set_halign(gtk4::Align::Start);
    stats_revealer.set_valign(gtk4::Align::Start);
    stats_revealer.set_can_target(false);

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
        ".stats-overlay { background-color: rgba(0, 0, 0, 0.7); color: white; border-radius: 6px; padding: 6px 10px; font-family: monospace; }\
        .vnc-status-dot { border-radius: 50%; min-width: 10px; min-height: 10px; margin: 0 12px; }\
        .vnc-status-unknown { background-color: #9a9a9a; }\
        .vnc-status-online { background-color: #2ec27e; }\
        .vnc-status-offline { background-color: #e01b24; }"
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

    // Error callback: route runtime errors to the main window toast overlay.
    // While the connect dialog is open, this callback is temporarily replaced
    // by one that targets the dialog's own overlay so errors are visible.
    let main_error_cb: Rc<dyn Fn(String)> = Rc::new(clone!(
        #[weak]
        toast_overlay,
        #[weak]
        connect_btn,
        #[strong]
        set_connection_visible,
        move |msg: String| {
            log::error!("VNC error: {}", msg);
            if let Some(media_msg) = media_stream_error_message(&msg) {
                // Media stream failures are non-fatal: keep the RFB connection
                // alive and only notify the user that H.264 mode is unavailable.
                toast_overlay.add_toast(adw::Toast::new(&media_msg));
                return;
            }
            toast_overlay.add_toast(adw::Toast::new(&msg));
            connect_btn.set_sensitive(true);
            connect_btn.set_label(&gettext("Connect"));
            set_connection_visible(false);
        }
    ));
    vnc_display.set_error_callback(Box::new({
        let cb = main_error_cb.clone();
        move |msg| cb(msg)
    }));

    let refresh_history = setup_history(
        &settings,
        &history_group,
        &window,
        &vnc_display,
        &main_error_cb,
        &connect_btn,
        &set_connection_visible,
    );
    refresh_history();

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
        connect_btn,
        move |_| {
            let label = connect_btn
                .label()
                .map(|l| l.to_string())
                .unwrap_or_default();
            if label == gettext("Disconnect") {
                show_disconnect_confirm_dialog(
                    &window,
                    &vnc_display,
                    &connect_btn,
                    &set_connection_visible,
                );
            } else {
                show_connect_dialog(
                    &window,
                    &vnc_display,
                    &settings,
                    &main_error_cb,
                    &connect_btn,
                    None,
                    &set_connection_visible,
                    &refresh_history,
                );
            }
        }
    ));

    // Poll connection stats once per second and update the overlay.
    let vnc_display_weak = vnc_display.downgrade();
    let stats_label_weak = stats_label.downgrade();
    glib::source::timeout_add_local(Duration::from_secs(1), move || {
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
