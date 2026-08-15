use gtk4::glib::translate::IntoGlib;
use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use gtk4::{gdk, glib, graphene};

use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use vnc_client::auth::{AuthHandler, NoAuthHandler};
use vnc_client::cursor::CursorShape;
use vnc_client::encodings::Encoding;
use vnc_client::{ConnectionStats, VncClient, VncClientBuilder, VncEvent};

use vnc_client::apple_media::{MediaStreamAnswer, MediaStreamInit, MediaStreamKeys};
use vnc_client::decoder::Codec;

use super::paintable::VncPaintable;

/// Build a GTK4 cursor from a VNC cursor shape.
fn build_cursor(shape: &CursorShape) -> Option<gdk::Cursor> {
    if shape.width == 0 || shape.height == 0 {
        return None;
    }
    let expected = shape.width as usize * shape.height as usize * 4;
    if shape.pixels.len() != expected {
        log::warn!("Cursor shape pixel size mismatch");
        return None;
    }
    let bytes = glib::Bytes::from(&shape.pixels);
    let texture = gdk::MemoryTexture::new(
        shape.width as i32,
        shape.height as i32,
        gdk::MemoryFormat::R8g8b8a8,
        &bytes,
        (shape.width as usize) * 4,
    );
    Some(gdk::Cursor::from_texture(
        &texture,
        shape.hotspot_x as i32,
        shape.hotspot_y as i32,
        None::<&gdk::Cursor>,
    ))
}

/// Input events sent from the main thread to the background VNC thread.
#[derive(Debug, Clone, Copy)]
pub enum InputEvent {
    Pointer {
        button_mask: u8,
        x: u16,
        y: u16,
    },
    Key {
        down: bool,
        keysym: u32,
    },
    RequestUpdate {
        incremental: bool,
        x: u16,
        y: u16,
        w: u16,
        h: u16,
    },
}

/// Result delivered to the UI after a VNC handshake attempt.
#[derive(Debug, Clone)]
pub struct HandshakeResult {
    /// True when the VNC handshake and initialization completed successfully.
    pub success: bool,
    /// Error message when `success` is false.
    pub error: Option<String>,
    /// Security types advertised by the server during the handshake attempt.
    pub supported_auth_types: Vec<u8>,
}

/// Apple high-performance mode options for a connection.
///
/// When `high_performance` is false, all other fields are ignored and the
/// connection uses the standard RFB path.
#[derive(Debug, Clone, Copy, Default)]
pub struct HpOptions {
    /// Enable Apple HP protocol (RFB 003.889 + encrypted record layer).
    pub high_performance: bool,
    /// Request the HEVC adaptive media stream after the record layer is active.
    pub media_stream_h264: bool,
    /// Virtual display width sent in `SetDisplayConfiguration` (0x1d).
    pub display_width: u16,
    /// Virtual display height sent in `SetDisplayConfiguration` (0x1d).
    pub display_height: u16,
    /// Request a dynamic-resolution virtual display.
    pub display_dynamic: bool,
    /// HiDPI backing:point scale factor (1.0 = 1:1, 2.0 = Retina).
    pub hidpi_scale: f32,
}

/// Framebuffer update data received from the background thread.
#[derive(Debug, Clone)]
pub struct FrameData {
    pub width: i32,
    pub height: i32,
    pub pixels: Vec<u8>,
}

glib::wrapper! {
    /// A GTK4 widget that displays VNC remote desktop content.
    pub struct VncDisplay(ObjectSubclass<imp::VncDisplayImp>)
        @extends gtk4::Widget,
        @implements gtk4::Accessible, gtk4::Buildable, gtk4::ConstraintTarget;
}

mod imp {
    use super::*;

    type ErrorCallback = RefCell<Option<Box<dyn Fn(String)>>>;
    type HandshakeCallback = RefCell<Option<Box<dyn Fn(super::HandshakeResult)>>>;

    #[derive(Default)]
    pub struct VncDisplayImp {
        pub paintable: RefCell<Option<VncPaintable>>,
        pub width: Cell<i32>,
        pub height: Cell<i32>,

        // Background thread control
        pub running: RefCell<Option<Arc<AtomicBool>>>,
        pub input_tx: RefCell<Option<mpsc::Sender<InputEvent>>>,
        pub connected: RefCell<Arc<AtomicBool>>,
        pub frame_data: Arc<Mutex<Vec<FrameData>>>,
        pub cursor_data: Arc<Mutex<Vec<CursorShape>>>,
        pub error_queue: Arc<Mutex<Vec<String>>>,
        pub error_callback: ErrorCallback,
        pub handshake_queue: Arc<Mutex<Vec<HandshakeResult>>>,
        pub handshake_callback: HandshakeCallback,
        pub source_id: RefCell<Option<glib::SourceId>>,
        pub stats: Arc<Mutex<ConnectionStats>>,

        // Input state
        pub button_mask: Cell<u8>,
        pub view_only: Cell<bool>,
        pub last_x: Cell<f64>,
        pub last_y: Cell<f64>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for VncDisplayImp {
        const NAME: &'static str = "VncDisplay";
        type Type = super::VncDisplay;
        type ParentType = gtk4::Widget;
    }

    impl ObjectImpl for VncDisplayImp {
        fn constructed(&self) {
            self.parent_constructed();
            let obj = self.obj();
            obj.set_focusable(true);
            obj.set_sensitive(true);
            obj.set_can_target(true);

            // Motion controller for mouse movement
            let motion = gtk4::EventControllerMotion::new();
            motion.set_propagation_phase(gtk4::PropagationPhase::Capture);
            let obj_weak = obj.downgrade();
            motion.connect_motion(move |_, x, y| {
                if let Some(obj) = obj_weak.upgrade() {
                    obj.imp().on_motion(x, y);
                }
            });
            obj.add_controller(motion);

            // Gesture click for mouse buttons
            let gesture = gtk4::GestureClick::new();
            gesture.set_button(0);
            gesture.set_propagation_phase(gtk4::PropagationPhase::Capture);
            let obj_weak = obj.downgrade();
            gesture.connect_pressed(move |gesture, _n_press, x, y| {
                if let Some(obj) = obj_weak.upgrade() {
                    let btn = gesture.current_button() as u8;
                    obj.imp().on_button_press(btn, x, y);
                }
            });
            let obj_weak = obj.downgrade();
            gesture.connect_released(move |gesture, _n_press, x, y| {
                if let Some(obj) = obj_weak.upgrade() {
                    let btn = gesture.current_button() as u8;
                    obj.imp().on_button_release(btn, x, y);
                }
            });
            obj.add_controller(gesture);

            // Key controller for keyboard
            let key = gtk4::EventControllerKey::new();
            key.set_propagation_phase(gtk4::PropagationPhase::Capture);
            let obj_weak = obj.downgrade();
            key.connect_key_pressed(move |_, keyval, _keycode, _state| {
                if let Some(obj) = obj_weak.upgrade() {
                    obj.imp().on_key_press(keyval);
                }
                glib::Propagation::Proceed
            });
            let obj_weak = obj.downgrade();
            key.connect_key_released(move |_, keyval, _keycode, _state| {
                if let Some(obj) = obj_weak.upgrade() {
                    obj.imp().on_key_release(keyval);
                }
            });
            obj.add_controller(key);

            // Scroll controller for mouse wheel
            let scroll = gtk4::EventControllerScroll::new(
                gtk4::EventControllerScrollFlags::VERTICAL
                    | gtk4::EventControllerScrollFlags::HORIZONTAL
                    | gtk4::EventControllerScrollFlags::DISCRETE,
            );
            scroll.set_propagation_phase(gtk4::PropagationPhase::Capture);
            let obj_weak = obj.downgrade();
            scroll.connect_scroll(move |_, dx, dy| {
                if let Some(obj) = obj_weak.upgrade() {
                    obj.imp().on_scroll(dx, dy);
                }
                glib::Propagation::Proceed
            });
            obj.add_controller(scroll);
        }

        fn dispose(&self) {
            self.disconnect_internal();
        }
    }

    impl WidgetImpl for VncDisplayImp {
        fn measure(&self, orientation: gtk4::Orientation, _for_size: i32) -> (i32, i32, i32, i32) {
            let width = self.width.get().max(1);
            let height = self.height.get().max(1);
            // Minimum size is 1 so the widget can be allocated smaller than the
            // remote framebuffer when "scale to fit" is enabled. Natural size
            // remains the framebuffer size so 1:1 / scrolled mode still works.
            match orientation {
                gtk4::Orientation::Horizontal => (1, width, -1, -1),
                gtk4::Orientation::Vertical => (1, height, -1, -1),
                _ => (0, 0, -1, -1),
            }
        }

        fn snapshot(&self, snapshot: &gtk4::Snapshot) {
            let width = self.obj().width() as f64;
            let height = self.obj().height() as f64;

            let paintable_guard = self.paintable.borrow();
            let Some(paintable) = paintable_guard.as_ref() else {
                snapshot.append_color(
                    &gdk::RGBA::BLACK,
                    &graphene::Rect::new(0.0, 0.0, width as f32, height as f32),
                );
                return;
            };

            paintable.snapshot(snapshot, width, height);
        }
    }

    impl VncDisplayImp {
        fn scale_coords(&self, widget_x: f64, widget_y: f64) -> (u16, u16) {
            let widget_w = self.obj().width() as f64;
            let widget_h = self.obj().height() as f64;
            if widget_w <= 0.0 || widget_h <= 0.0 {
                return (0, 0);
            }

            let fb_w = self.width.get().max(1) as f64;
            let fb_h = self.height.get().max(1) as f64;

            let scale_x = widget_w / fb_w;
            let scale_y = widget_h / fb_h;
            let scale = scale_x.min(scale_y);

            let draw_w = fb_w * scale;
            let draw_h = fb_h * scale;
            let offset_x = (widget_w - draw_w) / 2.0;
            let offset_y = (widget_h - draw_h) / 2.0;

            let x = ((widget_x - offset_x) / scale).clamp(0.0, fb_w - 1.0) as u16;
            let y = ((widget_y - offset_y) / scale).clamp(0.0, fb_h - 1.0) as u16;
            (x, y)
        }

        pub fn send_input(&self, event: InputEvent) {
            if self.view_only.get() {
                log::debug!("input event dropped: view-only mode");
                return;
            }
            match *self.input_tx.borrow() {
                Some(ref tx) => {
                    let _ = tx.send(event);
                }
                None => {
                    log::debug!("input event dropped: no active connection");
                }
            }
        }

        fn on_motion(&self, x: f64, y: f64) {
            self.last_x.set(x);
            self.last_y.set(y);
            let (vx, vy) = self.scale_coords(x, y);
            self.send_input(InputEvent::Pointer {
                button_mask: self.button_mask.get(),
                x: vx,
                y: vy,
            });
        }

        fn on_button_press(&self, button: u8, x: f64, y: f64) {
            self.obj().grab_focus();
            let (vx, vy) = self.scale_coords(x, y);
            // RFC 6143 layout (bit1 = middle, bit2 = right); the client
            // applies the Apple HP right/middle swap itself when needed.
            let bit = match button {
                1 => 1 << 0,
                2 => 1 << 1,
                3 => 1 << 2,
                _ => 0,
            };
            let mask = self.button_mask.get() | bit;
            self.button_mask.set(mask);
            self.send_input(InputEvent::Pointer {
                button_mask: mask,
                x: vx,
                y: vy,
            });
        }

        fn on_button_release(&self, button: u8, x: f64, y: f64) {
            let (vx, vy) = self.scale_coords(x, y);
            let bit = match button {
                1 => 1 << 0,
                2 => 1 << 1,
                3 => 1 << 2,
                _ => 0,
            };
            let mask = self.button_mask.get() & !bit;
            self.button_mask.set(mask);
            self.send_input(InputEvent::Pointer {
                button_mask: mask,
                x: vx,
                y: vy,
            });
        }

        fn on_key_press(&self, keyval: gdk::Key) {
            let keysym = keyval.into_glib();
            self.send_input(InputEvent::Key { down: true, keysym });
        }

        fn on_key_release(&self, keyval: gdk::Key) {
            let keysym = keyval.into_glib();
            self.send_input(InputEvent::Key {
                down: false,
                keysym,
            });
        }

        fn on_scroll(&self, dx: f64, dy: f64) {
            // RFB pointer events encode wheel directions as transient button masks:
            // bit 3 = scroll up, bit 4 = scroll down, bit 5 = scroll left,
            // bit 6 = scroll right. Send a press followed by a release so the
            // server sees a single click of the wheel.
            let bit = if dy < 0.0 {
                1 << 3 // up
            } else if dy > 0.0 {
                1 << 4 // down
            } else if dx < 0.0 {
                1 << 5 // left
            } else if dx > 0.0 {
                1 << 6 // right
            } else {
                return;
            };
            let base_mask = self.button_mask.get();
            let (x, y) = self.scale_coords(self.last_x.get(), self.last_y.get());
            self.send_input(InputEvent::Pointer {
                button_mask: base_mask | bit,
                x,
                y,
            });
            self.send_input(InputEvent::Pointer {
                button_mask: base_mask,
                x,
                y,
            });
        }

        pub fn disconnect_internal(&self) {
            // Stop background thread
            if let Some(ref running) = *self.running.borrow() {
                running.store(false, Ordering::SeqCst);
            }
            self.connected.borrow().store(false, Ordering::SeqCst);
            *self.running.borrow_mut() = None;
            *self.input_tx.borrow_mut() = None;

            // Remove UI update source
            if let Some(id) = self.source_id.borrow_mut().take() {
                id.remove();
            }

            // Clear the paintable to release the last frame texture and any GL
            // resources, then drop it so the next snapshot paints black.
            if let Some(paintable) = self.paintable.borrow().as_ref() {
                paintable.clear();
            }
            *self.paintable.borrow_mut() = None;
            self.width.set(0);
            self.height.set(0);
            self.frame_data.lock().unwrap().clear();
            self.cursor_data.lock().unwrap().clear();
            self.error_queue.lock().unwrap().clear();
            self.handshake_queue.lock().unwrap().clear();
            *self.stats.lock().unwrap() = ConnectionStats::default();

            // Request a redraw so the widget actually shows black instead of the
            // previously rendered framebuffer.
            self.obj().queue_draw();
        }
    }
}

impl VncDisplay {
    pub fn new() -> Self {
        glib::Object::builder().build()
    }

    /// Set a callback that receives error messages from the background thread.
    ///
    /// The callback is always invoked on the main thread.
    pub fn set_error_callback(&self, callback: Box<dyn Fn(String)>) {
        *self.imp().error_callback.borrow_mut() = Some(callback);
    }

    /// Connect to a VNC server and start the background message loop.
    ///
    /// This is a convenience wrapper around [`Self::connect_with_options`] that uses
    /// no authentication and a default encoding set. Errors are logged but not
    /// surfaced to the caller.
    pub fn connect_to_host(&self, host: &str, port: u16) -> Result<(), String> {
        self.connect_with_options(
            host,
            port,
            false,
            Box::new(NoAuthHandler),
            &[
                Encoding::Tight,
                Encoding::Zrle,
                Encoding::Hextile,
                Encoding::CopyRect,
                Encoding::Raw,
                Encoding::DesktopSize,
                Encoding::DesktopName,
                Encoding::Cursor,
                Encoding::ContinuousUpdates,
                Encoding::ExtendedClipboard,
                Encoding::Fence,
            ],
        )?;
        Ok(())
    }

    /// Connect to a VNC server with explicit connection options and authentication.
    ///
    /// Errors from the background thread are delivered to the callback set with
    /// [`Self::set_error_callback`] on the main thread. This is a convenience
    /// wrapper around [`Self::connect_with_hp_options`] that uses standard RFB
    /// mode (Apple high-performance features are disabled).
    pub fn connect_with_options(
        &self,
        host: &str,
        port: u16,
        use_tls: bool,
        auth: Box<dyn AuthHandler + Send>,
        encodings: &[Encoding],
    ) -> Result<(), String> {
        self.connect_with_hp_options(host, port, use_tls, auth, encodings, HpOptions::default())
    }

    /// Connect to a VNC server with Apple high-performance options.
    ///
    /// When `hp_options.high_performance` is true, the client is built with
    /// [`VncClientBuilder`] and the Apple HP record layer is negotiated. If
    /// `hp_options.media_stream_h264` is also true, the `0x1c` media stream
    /// options are sent after the record layer is active and decoded
    /// [`VncEvent::MediaFrame`] frames are rendered just like framebuffer updates.
    ///
    /// Errors from the background thread are delivered to the callback set with
    /// [`Self::set_error_callback`] on the main thread.
    pub fn connect_with_hp_options(
        &self,
        host: &str,
        port: u16,
        use_tls: bool,
        auth: Box<dyn AuthHandler + Send>,
        encodings: &[Encoding],
        hp_options: HpOptions,
    ) -> Result<(), String> {
        let imp = self.imp();
        imp.disconnect_internal();

        let paintable = VncPaintable::new();
        *imp.paintable.borrow_mut() = Some(paintable);

        // Shared state
        let running = Arc::new(AtomicBool::new(true));
        let running_bg = running.clone();
        *imp.running.borrow_mut() = Some(running);
        let connected = Arc::new(AtomicBool::new(true));
        let connected_bg = connected.clone();
        *imp.connected.borrow_mut() = connected;

        let frame_data = imp.frame_data.clone();
        let cursor_data = imp.cursor_data.clone();
        let error_queue = imp.error_queue.clone();
        let handshake_queue = imp.handshake_queue.clone();
        // Reset stats from any previous connection.
        *imp.stats.lock().unwrap() = ConnectionStats::default();
        let stats = imp.stats.clone();
        let (input_tx, input_rx) = mpsc::channel::<InputEvent>();
        *imp.input_tx.borrow_mut() = Some(input_tx);

        let addr = format!("{}:{}", host, port);
        let host = host.to_string();
        let encodings = encodings.to_vec();
        log::debug!(
            "Connecting to {} with encodings: {:?}, hp_options: {:?}",
            addr,
            encodings,
            hp_options
        );

        // Background thread
        thread::spawn(move || {
            let encodings_empty = encodings.is_empty();

            let mut client = if hp_options.high_performance {
                let mut builder = VncClientBuilder::new()
                    .pixel_format(vnc_client::PixelFormat::bgra32())
                    .high_performance(true)
                    .apple_display_size(hp_options.display_width, hp_options.display_height)
                    .apple_display_dynamic(hp_options.display_dynamic)
                    .apple_hidpi_scale(hp_options.hidpi_scale)
                    .apple_media_stream_h264(hp_options.media_stream_h264);
                if !encodings_empty {
                    builder = builder.encodings(encodings.clone());
                }
                builder.build()
            } else {
                VncClient::new()
            };

            let connect_result = if use_tls {
                client.set_host(&host);
                client.connect_tls(&host, port)
            } else {
                client.connect(&addr)
            };
            if let Err(e) = connect_result {
                log::error!("VNC connection failed: {}", e);
                error_queue
                    .lock()
                    .unwrap()
                    .push(format!("Connection failed: {}", e));
                connected_bg.store(false, Ordering::SeqCst);
                running_bg.store(false, Ordering::SeqCst);
                return;
            }

            let mut auth = auth;
            if let Err(e) = client.handshake(&mut *auth) {
                log::error!("VNC handshake failed: {}", e);
                let supported = client.server_security_types().to_vec();
                error_queue
                    .lock()
                    .unwrap()
                    .push(format!("Handshake failed: {}", e));
                handshake_queue
                    .lock()
                    .unwrap()
                    .push(super::HandshakeResult {
                        success: false,
                        error: Some(e.to_string()),
                        supported_auth_types: supported,
                    });
                connected_bg.store(false, Ordering::SeqCst);
                running_bg.store(false, Ordering::SeqCst);
                return;
            }

            let supported = client.server_security_types().to_vec();
            handshake_queue
                .lock()
                .unwrap()
                .push(super::HandshakeResult {
                    success: true,
                    error: None,
                    supported_auth_types: supported,
                });

            // In standard RFB mode we still set the pixel format and encodings here
            // for compatibility with callers that use VncClient::new(). In Apple HP mode
            // the VncClientBuilder already configured these before the handshake.
            let cursor_data = cursor_data.clone();
            if !hp_options.high_performance {
                let server_format = *client.pixel_format();
                if let Err(e) = client.set_pixel_format(vnc_client::PixelFormat::bgra32()) {
                    log::warn!(
                        "Failed to set pixel format to BGRA32 ({}); using server format {:?}",
                        e,
                        server_format
                    );
                } else {
                    log::debug!("Pixel format set to BGRA32");
                }
                if !encodings_empty {
                    let _ = client.set_encodings(&encodings);
                }
            } else {
                log::debug!("Apple HP mode active; pixel format and encodings were set by builder");
            }

            let mut last_activity = Instant::now();
            let mut last_stats_sample = Instant::now();
            let mut last_update_request = Instant::now();
            let mut first_frame_received = false;
            #[cfg(not(target_os = "android"))]
            let mut media_stream_started = false;
            #[cfg(not(target_os = "android"))]
            let mut last_media_offer_time: Option<Instant> = None;

            // Negotiate the Apple HEVC media stream if requested. In Apple HP mode
            // the 0x1c offer is sent automatically during VncClient::handshake
            // immediately after the encrypted SetEncodings. Retrieve the keys the
            // handshake generated; fall back to sending the offer here if the
            // builder did not enable the media stream path.
            let mut media_keys: Option<MediaStreamKeys> = None;
            let mut media_answer: Option<MediaStreamAnswer> = None;
            #[cfg(not(target_os = "android"))]
            let mut bound_base_port: u16 = 0;
            #[cfg(not(target_os = "android"))]
            if hp_options.high_performance && hp_options.media_stream_h264 {
                if let Some(keys) = client.apple_media_stream_keys() {
                    log::debug!("Using Apple HP media stream keys from handshake");
                    media_keys = Some(keys.clone());
                    last_media_offer_time = Some(Instant::now());
                } else {
                    log::debug!("Sending Apple HP media stream options");
                    match client.send_hp_media_stream_options(true) {
                        Ok(keys) => {
                            log::debug!("Apple HP media stream keys generated");
                            media_keys = Some(keys);
                            last_media_offer_time = Some(Instant::now());
                        }
                        Err(e) => {
                            log::error!("Failed to send media stream options: {}", e);
                        }
                    }
                }

                // Pre-bind UDP sockets before the encoder burst. The reference
                // client binds ports 5900/5901 first, then sends the 0x1c offer;
                // Mac's RTP burst can land within ~100 ms of the answer and the
                // kernel drops early packets if nothing is listening.
                if let Some(keys) = media_keys.as_ref() {
                    let assumed_init = MediaStreamInit {
                        stage: 1,
                        base_udp_port: 5900,
                        stream_count: 1,
                        next_stream_port: 0,
                    };
                    let (fb_w, fb_h) = client.dimensions();
                    match client.start_media_stream(
                        keys.clone(),
                        assumed_init,
                        fb_w,
                        fb_h,
                        Codec::Hevc,
                    ) {
                        Ok(()) => {
                            log::info!(
                                "Apple HP media stream pre-bound on UDP {}/{} (assumed base 5900)",
                                5900,
                                5901
                            );
                            bound_base_port = 5900;
                            media_stream_started = true;
                        }
                        Err(e) => {
                            log::warn!("Failed to pre-bind Apple HP media stream sockets: {}", e);
                        }
                    }
                }
            }
            #[cfg(target_os = "android")]
            if hp_options.media_stream_h264 {
                log::warn!("Apple HP media stream is not supported on Android");
            }

            // Apple HP media mode changes the TCP-side update policy: video
            // flows over UDP, so the aggressive full-screen
            // FramebufferUpdateRequest polling below is replaced by a light
            // 1x1 cursor poll (see the loop). Full-screen requests during the
            // ~2 s media-burst window after a 0x1c offer make the daemon
            // answer with parameter-set-less updates and destabilise the RTP
            // stream.
            #[cfg(not(target_os = "android"))]
            let hp_media = hp_options.high_performance && hp_options.media_stream_h264;
            #[cfg(target_os = "android")]
            let hp_media = false;
            #[cfg(target_os = "android")]
            let last_media_offer_time: Option<Instant> = None;
            // Last geometry for which a 0x1c re-offer was sent (0x451
            // layout changes require a re-offer with the same keys).
            #[cfg(not(target_os = "android"))]
            let mut last_layout_dims: Option<(u16, u16)> = None;

            // Request initial full update. In Apple HP mode the handshake already
            // sent a non-incremental FramebufferUpdateRequest after the 0x1c offer;
            // this extra request is harmless and helps non-HP paths.
            let (w, h) = client.dimensions();
            let _ = client.request_update(false, 0, 0, w, h);

            // Note: Some servers (notably macOS Screen Sharing) close the
            // connection when they receive the EnableContinuousUpdates message,
            // even though we advertise the pseudo-encoding. Fall back to
            // periodic incremental update requests instead.
            let continuous_updates = false;
            if continuous_updates {
                let _ = client.enable_continuous_updates(true, 0, 0, w, h);
            }

            // Set read timeout so we can check input channel periodically
            let _ = client.set_read_timeout(Some(Duration::from_millis(50)));

            while running_bg.load(Ordering::SeqCst) {
                // Check for input events
                while let Ok(event) = input_rx.try_recv() {
                    last_activity = Instant::now();
                    match event {
                        InputEvent::Pointer { button_mask, x, y } => {
                            // Apple HP: pointer coordinates are in logical
                            // points (the 0x451 scaled geometry), while the
                            // widget tracks backing pixels. Convert here.
                            let (x, y) = if hp_options.high_performance {
                                match client.apple_scaled_size() {
                                    Some((sw, sh)) => {
                                        let (fw, fh) = client.dimensions();
                                        if fw > 0 && fh > 0 && (sw, sh) != (fw, fh) {
                                            (
                                                (x as u32 * sw as u32 / fw as u32) as u16,
                                                (y as u32 * sh as u32 / fh as u32) as u16,
                                            )
                                        } else {
                                            (x, y)
                                        }
                                    }
                                    None => (x, y),
                                }
                            } else {
                                (x, y)
                            };
                            // Apple HP: the stock client wraps every pointer
                            // event in the encrypted 0x10 message; plaintext
                            // 0x05 PointerEvent is a second-class path there
                            // (no cursor-tracker side effects).
                            let r = if hp_options.high_performance {
                                client.send_hp_pointer_event(button_mask, x, y)
                            } else {
                                client.send_pointer_event(button_mask, x, y)
                            };
                            if button_mask != 0 {
                                log::info!(
                                    "pointer input sent: mask={:#x} x={} y={} (err={:?})",
                                    button_mask,
                                    x,
                                    y,
                                    r.as_ref().err()
                                );
                            }
                        }
                        InputEvent::Key { down, keysym } => {
                            let r = client.send_key_event(down, keysym);
                            log::info!(
                                "key input sent: down={} keysym={:#x} (err={:?})",
                                down,
                                keysym,
                                r.as_ref().err()
                            );
                        }
                        InputEvent::RequestUpdate {
                            incremental,
                            x,
                            y,
                            w,
                            h,
                        } => {
                            let _ = client.request_update(incremental, x, y, w, h);
                        }
                    }
                }

                if hp_media {
                    // Apple HP media mode: video arrives over UDP; the TCP
                    // channel only needs a light 1x1 incremental poll (~2 Hz)
                    // to keep cursor pseudo-encodings flowing. Stay quiet
                    // during the media-burst window after each 0x1c offer:
                    // full-screen requests there make the daemon answer with
                    // parameter-set-less updates and destabilise the stream.
                    let in_burst_window = last_media_offer_time
                        .map(|t| t.elapsed() < Duration::from_millis(2500))
                        .unwrap_or(false);
                    if !in_burst_window
                        && last_update_request.elapsed() >= Duration::from_millis(500)
                    {
                        let _ = client.request_update(true, 0, 0, 1, 1);
                        last_update_request = Instant::now();
                        last_activity = Instant::now();
                    }
                } else {
                    // Heartbeat: request an incremental update every 5 seconds to keep the connection alive.
                    if last_activity.elapsed() >= Duration::from_secs(5) {
                        let (w, h) = client.dimensions();
                        let _ = client.request_update(true, 0, 0, w, h);
                        last_activity = Instant::now();
                    }

                    // Poll for updates when continuous updates are not enabled.
                    // Until the first full frame has been received, request a
                    // non-incremental update so the decoder always gets a key
                    // frame first. Some servers send a P-frame in response to an
                    // incremental request, which breaks H264 decoders that have not
                    // yet seen an IDR.
                    if !continuous_updates
                        && last_update_request.elapsed() >= Duration::from_millis(100)
                    {
                        let (w, h) = client.dimensions();
                        let incremental = first_frame_received;
                        let _ = client.request_update(incremental, 0, 0, w, h);
                        last_update_request = Instant::now();
                    }
                }

                // Read server messages (with timeout)
                match client.read_messages() {
                    Ok(events) => {
                        let mut updated = false;
                        let mut resized = false;
                        for event in events {
                            match event {
                                VncEvent::FramebufferUpdate { .. } => {
                                    updated = true;
                                    first_frame_received = true;
                                }
                                VncEvent::GeometryChanged { width, height } => {
                                    resized = true;
                                    // Apple HP: after a 0x451 layout change the
                                    // server expects a fresh 0x1c offer (same
                                    // SRTP keys); without it the server stops
                                    // emitting media. Re-offer once per distinct
                                    // geometry and request a keyframe for the
                                    // restarted encoder burst.
                                    #[cfg(not(target_os = "android"))]
                                    if hp_media && last_layout_dims != Some((width, height)) {
                                        last_layout_dims = Some((width, height));
                                        // Tell the media worker the backing-store
                                        // geometry so the tile composition canvas
                                        // crops CTU padding correctly.
                                        let _ = client.set_media_stream_size(width, height);
                                        if let Some(keys) = media_keys.as_ref() {
                                            log::info!(
                                                "Apple HP: re-offering media stream options after layout change to {}x{}",
                                                width,
                                                height
                                            );
                                            match client.send_hp_media_stream_options_with_keys(
                                                keys.clone(),
                                                true,
                                            ) {
                                                Ok(()) => {
                                                    last_media_offer_time = Some(Instant::now());
                                                    client.request_media_keyframe();
                                                }
                                                Err(e) => {
                                                    log::error!(
                                                        "Failed to re-offer media stream options: {}",
                                                        e
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                                VncEvent::CursorShape(shape) => {
                                    let mut queue = cursor_data.lock().unwrap();
                                    queue.push(shape);
                                }
                                VncEvent::EndOfContinuousUpdates => {
                                    // Server paused continuous updates. If we have
                                    // not yet received a full frame, request a
                                    // non-incremental refresh to force the server to
                                    // send a keyframe.
                                    let (w, h) = client.dimensions();
                                    let incremental = first_frame_received;
                                    let _ = client.request_update(incremental, 0, 0, w, h);
                                }
                                #[cfg(not(target_os = "android"))]
                                VncEvent::MediaStreamAnswer(answer) => {
                                    log::info!(
                                        "Apple HP media stream answer: {}x{}, tiles={}, codec={:?}",
                                        answer.canvas_width,
                                        answer.canvas_height,
                                        answer.tile_count,
                                        answer.codec
                                    );
                                    media_answer = Some(answer);
                                }
                                #[cfg(not(target_os = "android"))]
                                VncEvent::MediaStreamInit(init) => {
                                    // Stage-2 announcements arrive roughly once
                                    // per second; keep them out of the info log.
                                    if init.stage == 2 {
                                        log::trace!(
                                            "Apple HP media stream init: stage=2 (keepalive)"
                                        );
                                    } else {
                                        log::info!(
                                            "Apple HP media stream init: stage={} base_udp_port={}",
                                            init.stage,
                                            init.base_udp_port
                                        );
                                    }
                                    // Stage-2 announcements (port=0) are
                                    // keepalives/confirmations and must not tear
                                    // down already-bound sockets.
                                    if init.base_udp_port == 0 {
                                        continue;
                                    }
                                    if let Some(keys) = media_keys.as_ref() {
                                        let (fb_w, fb_h) = client.dimensions();
                                        let width = media_answer
                                            .map(|a| a.canvas_width as u16)
                                            .filter(|&v| v != 0)
                                            .unwrap_or(fb_w);
                                        let height = media_answer
                                            .map(|a| a.canvas_height as u16)
                                            .filter(|&v| v != 0)
                                            .unwrap_or(fb_h);
                                        if width == 0 || height == 0 {
                                            log::warn!(
                                                "Media stream has zero canvas dimensions, not starting"
                                            );
                                            continue;
                                        }
                                        let codec =
                                            media_answer.map(|a| a.codec).unwrap_or(Codec::Hevc);

                                        if init.base_udp_port != bound_base_port {
                                            // Server wants a different UDP port;
                                            // restart the receiver on the new one.
                                            client.stop_media_stream();
                                            match client.start_media_stream(
                                                keys.clone(),
                                                init,
                                                width,
                                                height,
                                                codec,
                                            ) {
                                                Ok(()) => {
                                                    log::info!(
                                                        "Apple HP media stream restarted on port {}",
                                                        init.base_udp_port
                                                    );
                                                    bound_base_port = init.base_udp_port;
                                                    media_stream_started = true;
                                                }
                                                Err(e) => {
                                                    let msg = format!(
                                                        "Failed to restart media stream: {}",
                                                        e
                                                    );
                                                    log::error!("{}", msg);
                                                    error_queue.lock().unwrap().push(msg);
                                                }
                                            }
                                        } else if media_stream_started {
                                            log::debug!(
                                                "Apple HP media stream already bound on port {}",
                                                bound_base_port
                                            );
                                        } else {
                                            match client.start_media_stream(
                                                keys.clone(),
                                                init,
                                                width,
                                                height,
                                                codec,
                                            ) {
                                                Ok(()) => {
                                                    log::info!(
                                                        "Apple HP media stream started: {}x{} on port {}",
                                                        width, height, init.base_udp_port
                                                    );
                                                    bound_base_port = init.base_udp_port;
                                                    media_stream_started = true;
                                                }
                                                Err(e) => {
                                                    let msg = format!(
                                                        "Failed to start media stream: {}",
                                                        e
                                                    );
                                                    log::error!("{}", msg);
                                                    error_queue.lock().unwrap().push(msg);
                                                }
                                            }
                                        }
                                    } else {
                                        log::warn!(
                                            "MediaStreamInit received but no keys available"
                                        );
                                    }
                                }
                                #[cfg(not(target_os = "android"))]
                                VncEvent::MediaFrame {
                                    width,
                                    height,
                                    rgba,
                                } => {
                                    log::trace!(
                                        "Apple HP media frame: {}x{} ({} bytes)",
                                        width,
                                        height,
                                        rgba.len()
                                    );
                                    let mut queue = frame_data.lock().unwrap();
                                    queue.clear();
                                    queue.push(FrameData {
                                        width: width as i32,
                                        height: height as i32,
                                        pixels: rgba,
                                    });
                                    // Do not set `updated`: the TCP framebuffer
                                    // did not change, and the post-batch block
                                    // would otherwise overwrite this media frame
                                    // with a stale TCP framebuffer snapshot.
                                }
                                _ => {}
                            }
                        }

                        // If the server is not pushing frames continuously, request
                        // the next update exactly once per message batch. Use
                        // incremental updates once the first full frame has been
                        // received; otherwise request a full refresh. In Apple HP
                        // media mode the 1x1 poll above handles re-arming and the
                        // TCP framebuffer carries no video, so skip this entirely.
                        if updated && !hp_media {
                            let (w, h) = client.dimensions();
                            let _ = client.request_update(first_frame_received, 0, 0, w, h);
                        }

                        if (updated && !hp_media) || resized {
                            let fb = client.framebuffer();
                            let data = FrameData {
                                width: fb.width() as i32,
                                height: fb.height() as i32,
                                pixels: fb.data().to_vec(),
                            };
                            let mut queue = frame_data.lock().unwrap();
                            // Only keep the most recent pending frame. The UI
                            // drains the queue at ~60 Hz and older frames are
                            // stale by the time they would be displayed.
                            queue.clear();
                            queue.push(data);
                        }
                    }
                    Err(vnc_client::VncError::Timeout) => {
                        // Timeout, loop back to check input channel
                    }
                    Err(e) => {
                        log::error!("VNC read error: {}", e);
                        error_queue
                            .lock()
                            .unwrap()
                            .push(format!("VNC read error: {}", e));
                        break;
                    }
                }

                // Note: no blind 0x1c re-offers here. A re-offer makes the
                // daemon restart the encoder on a fresh SSRC group, which
                // costs seconds of re-negotiation each time. The initial
                // offer (handshake) plus the 0x451-driven re-offer cover the
                // daemon's requirements; "packets flow but nothing decodes"
                // is handled by FIR and the decoder watchdog, not re-offers.

                // Sample connection stats once per second.
                if last_stats_sample.elapsed() >= Duration::from_secs(1) {
                    let snapshot = client.stats();
                    *stats.lock().unwrap() = snapshot;
                    last_stats_sample = Instant::now();
                }
            }
            connected_bg.store(false, Ordering::SeqCst);
            running_bg.store(false, Ordering::SeqCst);
        });

        // UI update timer (~60fps)
        let weak = self.downgrade();
        let frame_data = imp.frame_data.clone();
        let cursor_data = imp.cursor_data.clone();
        let source_id = glib::source::timeout_add_local(Duration::from_millis(16), move || {
            let Some(obj) = weak.upgrade() else {
                return glib::ControlFlow::Break;
            };
            let imp = obj.imp();

            let updates: Vec<FrameData> = {
                let mut queue = frame_data.lock().unwrap();
                queue.drain(..).collect()
            };

            let has_updates = !updates.is_empty();
            let mut size_changed = false;
            for data in updates {
                if imp.width.get() != data.width || imp.height.get() != data.height {
                    size_changed = true;
                }
                imp.width.set(data.width);
                imp.height.set(data.height);
                if let Some(ref paintable) = *imp.paintable.borrow() {
                    paintable.update_pixels(data.width, data.height, &data.pixels);
                }
            }

            if has_updates {
                obj.queue_draw();
            }
            if size_changed {
                obj.queue_resize();
            }

            // Process cursor updates
            let cursors: Vec<CursorShape> = {
                let mut queue = cursor_data.lock().unwrap();
                queue.drain(..).collect()
            };
            for cursor in cursors {
                if let Some(cursor) = build_cursor(&cursor) {
                    obj.set_cursor(Some(&cursor));
                }
            }

            // Deliver handshake completion to the UI callback on the main thread.
            let handshake_results: Vec<super::HandshakeResult> = {
                let mut queue = imp.handshake_queue.lock().unwrap();
                queue.drain(..).collect()
            };
            for result in handshake_results {
                if let Some(ref cb) = *imp.handshake_callback.borrow() {
                    cb(result);
                }
            }

            // Deliver errors to the UI callback on the main thread.
            let errors: Vec<String> = {
                let mut queue = imp.error_queue.lock().unwrap();
                queue.drain(..).collect()
            };
            for err in errors {
                if let Some(ref cb) = *imp.error_callback.borrow() {
                    cb(err);
                }
            }

            glib::ControlFlow::Continue
        });

        *imp.source_id.borrow_mut() = Some(source_id);

        Ok(())
    }

    /// Set a callback that receives the VNC handshake result from the background thread.
    ///
    /// The callback is always invoked on the main thread. When the handshake fails,
    /// [`HandshakeResult::supported_auth_types`] contains the security types advertised
    /// by the server, which can be used to update the UI's authentication options.
    pub fn set_handshake_callback(&self, callback: Box<dyn Fn(HandshakeResult)>) {
        *self.imp().handshake_callback.borrow_mut() = Some(callback);
    }

    /// Disconnect from the VNC server.
    pub fn disconnect(&self) {
        self.imp().disconnect_internal();
    }

    pub fn is_connected(&self) -> bool {
        let imp = self.imp();
        imp.connected.borrow().load(Ordering::SeqCst) && imp.running.borrow().is_some()
    }

    pub fn set_view_only(&self, view_only: bool) {
        self.imp().view_only.set(view_only);
    }

    pub fn is_view_only(&self) -> bool {
        self.imp().view_only.get()
    }

    pub fn framebuffer_size(&self) -> (i32, i32) {
        let imp = self.imp();
        (imp.width.get(), imp.height.get())
    }

    /// Get the latest connection statistics snapshot.
    pub fn stats(&self) -> ConnectionStats {
        self.imp().stats.lock().unwrap().clone()
    }

    /// Request a framebuffer update from the server.
    pub fn request_update(&self, incremental: bool, x: u16, y: u16, w: u16, h: u16) {
        self.imp().send_input(InputEvent::RequestUpdate {
            incremental,
            x,
            y,
            w,
            h,
        });
    }

    /// Get the paintable for embedding in other widgets.
    pub fn paintable(&self) -> Option<gdk::Paintable> {
        self.imp()
            .paintable
            .borrow()
            .as_ref()
            .map(|p| p.clone().upcast())
    }
}

impl Default for VncDisplay {
    fn default() -> Self {
        Self::new()
    }
}
