use gtk4::prelude::*;
use gtk4::{Application, ApplicationWindow, Box as GtkBox, Button, Entry, Label, Orientation};
use gtk4_vnc::VncDisplay;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn main() -> glib::ExitCode {
    let app = Application::builder()
        .application_id("com.example.gtk4-vnc")
        .build();
    app.connect_activate(build_ui);
    app.run()
}

fn build_ui(app: &Application) {
    let window = ApplicationWindow::builder()
        .application(app)
        .title("GTK4 VNC Viewer")
        .default_width(800)
        .default_height(600)
        .build();

    let vbox = GtkBox::new(Orientation::Vertical, 6);
    vbox.set_margin_top(12);
    vbox.set_margin_bottom(12);
    vbox.set_margin_start(12);
    vbox.set_margin_end(12);

    // Connection bar
    let hbox = GtkBox::new(Orientation::Horizontal, 6);
    let addr_entry = Entry::builder()
        .placeholder_text("127.0.0.1:5900")
        .text("127.0.0.1:5900")
        .hexpand(true)
        .build();
    let connect_btn = Button::with_label("Connect");
    let disconnect_btn = Button::with_label("Disconnect");
    disconnect_btn.set_sensitive(false);

    hbox.append(&Label::new(Some("Host:")));
    hbox.append(&addr_entry);
    hbox.append(&connect_btn);
    hbox.append(&disconnect_btn);
    vbox.append(&hbox);

    let status = Label::new(Some("Disconnected"));
    vbox.append(&status);

    let display = VncDisplay::new();
    display.set_vexpand(true);
    display.set_hexpand(true);
    vbox.append(&display);

    window.set_child(Some(&vbox));
    window.present();

    let running = Arc::new(AtomicBool::new(false));

    // Connect
    let running_conn = running.clone();
    let display_weak = display.downgrade();
    let status_weak = status.downgrade();
    let disc_weak = disconnect_btn.downgrade();
    let _conn_weak = connect_btn.downgrade();

    connect_btn.connect_clicked(move |btn| {
        let addr = addr_entry.text().to_string();
        let Some(display) = display_weak.upgrade() else {
            return;
        };
        let Some(status) = status_weak.upgrade() else {
            return;
        };
        let Some(disc_btn) = disc_weak.upgrade() else {
            return;
        };

        match display.connect_to_host(&addr, 5900) {
            Ok(()) => {
                btn.set_sensitive(false);
                disc_btn.set_sensitive(true);
                status.set_text(&format!("Connected to {}", addr));

                running_conn.store(true, Ordering::SeqCst);
            }
            Err(e) => {
                status.set_text(&format!("Connection failed: {}", e));
            }
        }
    });

    // Disconnect
    let running_disc = running.clone();
    let display_weak = display.downgrade();
    let status_weak = status.downgrade();
    let conn_weak = connect_btn.downgrade();
    disconnect_btn.connect_clicked(move |btn| {
        running_disc.store(false, Ordering::SeqCst);
        let Some(display) = display_weak.upgrade() else {
            return;
        };
        let Some(status) = status_weak.upgrade() else {
            return;
        };
        let Some(conn_btn) = conn_weak.upgrade() else {
            return;
        };

        display.disconnect();
        btn.set_sensitive(false);
        conn_btn.set_sensitive(true);
        status.set_text("Disconnected");
    });
}
