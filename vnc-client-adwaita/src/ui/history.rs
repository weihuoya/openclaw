use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use adw::prelude::*;
use glib::clone;
use gtk4::{gio, glib};
use gtk4_vnc::VncDisplay;

use gettextrs::gettext;

use crate::network::{test_vnc_reachable, update_status_dot};
use crate::settings::load_history;
use crate::ui::connect_dialog::show_connect_dialog;
use crate::ui::{
    ConnectionVisibilityFn, ReachabilityResultsQueue, RefreshHistoryFn, RefreshHistoryRef,
};

/// Build the recent-connections list, spawn reachability probes, and return a
/// callable refresh function that can later be invoked from dialogs.
#[allow(clippy::too_many_arguments)]
pub fn setup_history(
    settings: &gio::Settings,
    history_group: &adw::PreferencesGroup,
    window: &adw::ApplicationWindow,
    vnc_display: &VncDisplay,
    main_error_cb: &Rc<dyn Fn(String)>,
    connect_btn: &gtk4::Button,
    set_connection_visible: &ConnectionVisibilityFn,
) -> RefreshHistoryFn {
    let refresh_history_ref: RefreshHistoryRef = Rc::new(RefCell::new(None));
    let history_rows: Rc<RefCell<Vec<(adw::ActionRow, gtk4::Box)>>> =
        Rc::new(RefCell::new(Vec::new()));
    let test_results_queue: ReachabilityResultsQueue =
        Rc::new(RefCell::new(Arc::new(Mutex::new(Vec::new()))));

    let refresh_history: RefreshHistoryFn = Rc::new(clone!(
        #[strong]
        settings,
        #[weak]
        history_group,
        #[weak]
        window,
        #[weak]
        vnc_display,
        #[strong]
        main_error_cb,
        #[weak]
        connect_btn,
        #[strong]
        set_connection_visible,
        #[strong]
        refresh_history_ref,
        #[strong]
        history_rows,
        #[strong]
        test_results_queue,
        move || {
            let mut rows = history_rows.borrow_mut();
            for (row, _dot) in rows.drain(..) {
                history_group.remove(&row);
            }
            drop(rows);
            let history = load_history(&settings);
            if history.is_empty() {
                let empty_row = adw::ActionRow::new();
                empty_row.set_title(&gettext("No recent connections"));
                empty_row.set_subtitle(&gettext("Click Connect to add one"));
                history_group.add(&empty_row);
                history_rows
                    .borrow_mut()
                    .push((empty_row, gtk4::Box::new(gtk4::Orientation::Horizontal, 0)));
                return;
            }
            for entry in &history {
                let row = adw::ActionRow::new();
                row.set_title(&entry.summary());
                row.set_subtitle(&entry.detail());
                row.set_activatable(true);

                let status_dot = gtk4::Box::new(gtk4::Orientation::Horizontal, 0);
                status_dot.set_size_request(10, 10);
                status_dot.set_valign(gtk4::Align::Center);
                status_dot.set_tooltip_text(Some(&gettext("Checking reachability...")));
                status_dot.add_css_class("vnc-status-dot");
                status_dot.add_css_class("vnc-status-unknown");
                row.add_prefix(&status_dot);

                let delete_btn = gtk4::Button::from_icon_name("user-trash-symbolic");
                delete_btn.set_valign(gtk4::Align::Center);
                delete_btn.set_tooltip_text(Some(&gettext("Delete connection")));
                delete_btn.add_css_class("flat");
                row.add_suffix(&delete_btn);

                let entry_summary = entry.summary();
                delete_btn.connect_clicked(clone!(
                    #[weak]
                    window,
                    #[strong]
                    settings,
                    #[strong]
                    refresh_history_ref,
                    move |_| {
                        let settings = settings.clone();
                        let entry_summary = entry_summary.clone();
                        let refresh_history_ref = refresh_history_ref.clone();

                        let body = format!(
                            "{}: {}",
                            gettext("This will remove the following connection from the recent connections list"),
                            entry_summary
                        );
                        let dialog = adw::AlertDialog::new(
                            Some(&gettext("Delete connection?")),
                            Some(&body),
                        );
                        dialog.add_response("cancel", &gettext("Cancel"));
                        dialog.add_response("delete", &gettext("Delete"));
                        dialog.set_response_appearance(
                            "delete",
                            adw::ResponseAppearance::Destructive,
                        );
                        dialog.set_default_response(Some("cancel"));
                        dialog.set_close_response("cancel");

                        glib::MainContext::default().spawn_local(async move {
                            let response = dialog.choose_future(Some(&window)).await;
                            if response == "delete" {
                                crate::settings::remove_history_entry(&settings, &entry_summary);
                                if let Some(refresh_history) = refresh_history_ref.borrow().clone() {
                                    refresh_history();
                                }
                            }
                        });
                    }
                ));

                let entry_clone = entry.clone();
                row.connect_activated(clone!(
                    #[weak]
                    window,
                    #[weak]
                    vnc_display,
                    #[strong]
                    settings,
                    #[strong]
                    main_error_cb,
                    #[weak]
                    connect_btn,
                    #[strong]
                    set_connection_visible,
                    #[strong]
                    refresh_history_ref,
                    move |_| {
                        let Some(refresh_history) = refresh_history_ref.borrow().clone() else {
                            return;
                        };
                        show_connect_dialog(
                            &window,
                            &vnc_display,
                            &settings,
                            &main_error_cb,
                            &connect_btn,
                            Some(&entry_clone),
                            &set_connection_visible,
                            &refresh_history,
                        );
                    }
                ));
                history_group.add(&row);
                history_rows.borrow_mut().push((row, status_dot));
            }

            if !history.is_empty() {
                let new_results: Arc<Mutex<Vec<(usize, bool)>>> = Arc::new(Mutex::new(Vec::new()));
                test_results_queue.replace(new_results.clone());
                for (idx, entry) in history.iter().enumerate() {
                    let entry = entry.clone();
                    let results = new_results.clone();
                    std::thread::spawn(move || {
                        let reachable = test_vnc_reachable(&entry);
                        results.lock().unwrap().push((idx, reachable));
                    });
                }
            }
        }
    ));
    refresh_history_ref
        .borrow_mut()
        .replace(refresh_history.clone());

    // Poll reachability test results from background threads and update the
    // status dots on the history rows.
    let queue_for_timer = test_results_queue.clone();
    let rows_for_timer = history_rows.clone();
    glib::source::timeout_add_local(Duration::from_millis(300), move || {
        let queue = queue_for_timer.borrow().clone();
        let results: Vec<_> = queue.lock().unwrap().drain(..).collect();
        for (idx, reachable) in results {
            if let Some((_, dot)) = rows_for_timer.borrow().get(idx) {
                update_status_dot(dot, reachable);
            }
        }
        glib::ControlFlow::Continue
    });

    refresh_history
}
