//! VNC Server binary entry point (pure Rust RFB implementation).

use std::collections::HashSet;
use std::env;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, error, info, warn};

use vnc_server::bandwidth::BandwidthSnapshot;
use vnc_server::config::{merge_configs, parse_file, Config};
use vnc_server::control::{ClientInfo, ControlServer, ControlState};
use vnc_server::damage::DamageTracker;
use vnc_server::encode::copyrect::encode_copyrect;
use vnc_server::encode::cursor::default_cursor;
use vnc_server::encode::hextile::encode_hextile;
use vnc_server::encode::raw::encode_raw;
use vnc_server::encode::rre::encode_rre;
use vnc_server::encode::trle::encode_trle;
use vnc_server::perf::PerfStats;
use vnc_server::protocol::{Encoding, FbRect};
use vnc_server::server::client::{ClientState, VncClient, MAX_OUTBOUND_QUEUE};
use vnc_server::server::listener::VncListener;
use vnc_server::server::tls::build_tls_config;
use vnc_server::signal;
use vnc_server::wayland::capture::CaptureManager;
use vnc_server::wayland::input::{axis as ptr_axis, button as ptr_button, VirtualPointer};
use vnc_server::wayland::keyboard::VirtualKeyboard;
use vnc_server::wayland::wayland_ctx::connect as connect_wayland;

fn print_usage() {
    println!("vnc-server [OPTIONS]");
    println!();
    println!("Options:");
    println!("  -a, --address <ADDR>     Listen address (default: 127.0.0.1)");
    println!("  -p, --port <PORT>        Listen port (default: 5900)");
    println!("  -n, --name <NAME>        Desktop name");
    println!("  -r, --max-rate <RATE>    Maximum frame rate (default: 30)");
    println!("  -d, --display <DISPLAY>  Wayland display to connect to");
    println!("  -o, --output <OUTPUT>    Output to capture (default: first available)");
    println!("  -c, --config <FILE>      Config file path");
    println!("  --disable-input          Disable virtual input");
    println!("  --overlay-cursor         Include cursor in capture");
    println!("  --enable-rsa-aes         Advertise RSA-AES security types (default: on if auth)");
    println!("  --disable-rsa-aes        Do not advertise RSA-AES security types");
    println!("  --enable-vencrypt        Advertise VeNCrypt security type (default: off)");
    println!("  --disable-vencrypt       Do not advertise VeNCrypt security type");
    println!("  --tls-cert <FILE>        TLS certificate PEM file (default: self-signed)");
    println!("  --tls-key <FILE>         TLS private key PEM file (default: self-signed)");
    println!("  -h, --help               Print this help");
}

fn parse_args() -> Option<(Config, Option<String>, HashSet<&'static str>)> {
    let mut config = Config::default();
    let mut display_name: Option<String> = None;
    // Names of valued CLI arguments explicitly provided, so that merging
    // with a config file can tell "user typed the default" apart from
    // "argument not given".
    let mut explicit: HashSet<&'static str> = HashSet::new();

    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "-a" | "--address" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    config.address = v.clone();
                    explicit.insert("address");
                }
            }
            "-p" | "--port" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    config.port = v.parse().unwrap_or(5900);
                    explicit.insert("port");
                }
            }
            "-n" | "--name" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    config.name = v.clone();
                    explicit.insert("name");
                }
            }
            "-r" | "--max-rate" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    config.max_rate = v.parse().unwrap_or(30);
                    explicit.insert("max_rate");
                }
            }
            "-d" | "--display" => {
                i += 1;
                display_name = args.get(i).cloned();
            }
            "-o" | "--output" => {
                i += 1;
                config.output = args.get(i).cloned();
            }
            "-c" | "--config" => {
                i += 1;
                config.config_file = args.get(i).cloned();
            }
            "--disable-input" => {
                config.disable_input = true;
            }
            "--overlay-cursor" => {
                config.overlay_cursor = true;
            }
            "--enable-rsa-aes" => {
                config.enable_rsa_aes = true;
                explicit.insert("rsa_aes");
            }
            "--disable-rsa-aes" => {
                config.enable_rsa_aes = false;
                explicit.insert("rsa_aes");
            }
            "--enable-vencrypt" => {
                config.enable_vencrypt = true;
                explicit.insert("vencrypt");
            }
            "--disable-vencrypt" => {
                config.enable_vencrypt = false;
                explicit.insert("vencrypt");
            }
            "--tls-cert" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    config.certificate_file = Some(v.clone());
                }
            }
            "--tls-key" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    config.private_key_file = Some(v.clone());
                }
            }
            "-h" | "--help" => {
                print_usage();
                return None;
            }
            _ => {}
        }
        i += 1;
    }

    Some((config, display_name, explicit))
}

fn main() {
    env_logger::init();

    let (cli_config, display_name, cli_explicit) = match parse_args() {
        Some(c) => c,
        None => return,
    };

    let config_path = cli_config.config_file.as_ref().cloned().or_else(|| {
        let default = PathBuf::from("/etc/vnc-server/config");
        if default.exists() {
            Some(default.to_string_lossy().to_string())
        } else {
            None
        }
    });

    let config_path_clone = config_path.clone();

    let file_config =
        config_path.and_then(|path| match parse_file(PathBuf::from(path).as_path()) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                log::warn!("Failed to load config file: {}", e);
                None
            }
        });

    let mut config = merge_configs(file_config, cli_config, &cli_explicit);

    info!(
        "Starting VNC server '{}' on {}:{}",
        config.name, config.address, config.port
    );

    let (conn, mut queue, mut wayland) = match connect_wayland(display_name.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to connect to Wayland: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = wayland.check_requirements(config.disable_input) {
        error!("Wayland compositor missing required protocols: {}", e);
        std::process::exit(1);
    }

    info!(
        "Connected to Wayland: {} output(s), {} seat(s)",
        wayland.outputs.len(),
        wayland.seats.len()
    );

    let output_info = match config.output.as_deref() {
        Some(name) => wayland.outputs.iter().find(|o| o.name == name).cloned(),
        None => wayland.outputs.first().cloned(),
    };

    let Some(ref info) = output_info else {
        error!("No output available for capture");
        std::process::exit(1);
    };

    let Some(ref output) = info.wl_output else {
        error!("Output proxy not available");
        std::process::exit(1);
    };

    let mut width = info.width.max(1) as u16;
    let mut height = info.height.max(1) as u16;

    info!("Capturing output '{}' at {}x{}", info.name, width, height);

    let tls_config = if config.enable_vencrypt {
        match build_tls_config(
            config.certificate_file.as_deref(),
            config.private_key_file.as_deref(),
        ) {
            Ok(cfg) => cfg,
            Err(e) => {
                warn!("Failed to build TLS config: {}. VeNCrypt disabled.", e);
                None
            }
        }
    } else {
        None
    };

    let mut listener = match VncListener::bind(
        &config.address,
        config.port,
        config.password.clone(),
        config.enable_auth && config.password.is_some(),
        config.enable_rsa_aes && config.password.is_some(),
        config.enable_vencrypt,
        tls_config,
        width,
        height,
        config.name.clone(),
    ) {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind VNC listener: {}", e);
            std::process::exit(1);
        }
    };

    let screencopy_mgr = match wayland.screencopy_manager.as_ref() {
        Some(mgr) => mgr.clone(),
        None => {
            error!("zwlr_screencopy_manager_v1 not available");
            std::process::exit(1);
        }
    };
    let shm = match wayland.shm.as_ref() {
        Some(shm) => shm.clone(),
        None => {
            error!("wl_shm not available");
            std::process::exit(1);
        }
    };
    let qh = queue.handle();

    let mut capture_mgr = match CaptureManager::new(
        &screencopy_mgr,
        output,
        &shm,
        width as u32,
        height as u32,
        &qh,
    ) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to create capture manager: {}", e);
            std::process::exit(1);
        }
    };

    // Setup virtual input devices
    let mut virtual_pointer: Option<VirtualPointer> = None;
    let mut virtual_keyboard: Option<
        Box<dyn vnc_server::wayland::keyboard::KeyboardBackend + Send>,
    > = None;

    if !config.disable_input {
        if let Some(vp_mgr) = wayland.virtual_pointer_manager.as_ref() {
            if let Some(seat) = wayland.seats.first() {
                virtual_pointer = Some(VirtualPointer::new(vp_mgr, &seat.wl_seat, &qh));
                info!("Virtual pointer created");
            }
        }
        // Try Wayland virtual keyboard first (no root required), then fall back to uinput.
        if let Some(vk_mgr) = wayland.virtual_keyboard_manager.as_ref() {
            if let Some(seat) = wayland.seats.first() {
                match vnc_server::wayland::virtual_keyboard_wayland::WaylandVirtualKeyboard::new(
                    vk_mgr,
                    &seat.wl_seat,
                    &qh,
                ) {
                    Ok(vk) => {
                        virtual_keyboard = Some(Box::new(vk));
                        info!("Wayland virtual keyboard created (no root required)");
                    }
                    Err(e) => {
                        warn!(
                            "Wayland virtual keyboard unavailable ({}), falling back to uinput",
                            e
                        );
                    }
                }
            }
        }
        if virtual_keyboard.is_none() {
            match VirtualKeyboard::new() {
                Ok(vk) => {
                    virtual_keyboard = Some(Box::new(vk));
                    info!("Virtual keyboard created (uinput)");
                }
                Err(e) => {
                    warn!("Failed to create virtual keyboard: {}", e);
                }
            }
        }
    }

    // Setup clipboard manager
    let mut clipboard_mgr: Option<vnc_server::clipboard::ClipboardManager> = None;
    if let Some(dc_mgr) = wayland.data_control_manager.as_ref() {
        if let Some(seat) = wayland.seats.first() {
            clipboard_mgr = Some(vnc_server::clipboard::ClipboardManager::new(
                dc_mgr,
                &seat.wl_seat,
                &qh,
            ));
            info!("Clipboard manager created");
        }
    }

    let mut damage_tracker = DamageTracker::new(width as u32, height as u32, width as usize * 4);

    let running = Arc::new(AtomicBool::new(true));
    signal::install(Arc::clone(&running));

    // Setup control interface
    let control_socket = match std::env::var("XDG_RUNTIME_DIR") {
        Ok(dir) => Some(PathBuf::from(dir).join("vnc-server.sock")),
        Err(_) => {
            warn!("XDG_RUNTIME_DIR not set, control interface disabled");
            None
        }
    };
    let control_state = ControlState::new(
        info.name.clone(),
        width,
        height,
        config.password.clone(),
        config.max_rate,
    );
    let control_server = match control_socket {
        Some(ref path) => match ControlServer::bind(path, control_state) {
            Ok(s) => {
                info!("Control interface at {}", path.display());
                Some(s)
            }
            Err(e) => {
                warn!("Failed to bind control socket: {}", e);
                None
            }
        },
        None => None,
    };
    let control_state_handle = control_server.as_ref().map(|s| s.state());

    let mut last_capture = Instant::now();
    let mut pending_capture = false;
    let mut clients: Vec<VncClient> = vec![];
    let mut perf_stats = PerfStats::new(Duration::from_secs(5));

    info!("VNC server running. Press Ctrl+C to stop.");

    while running.load(Ordering::SeqCst) {
        match listener.try_accept() {
            Ok(Some(client)) => {
                info!("Client connected, starting handshake");
                clients.push(client);
            }
            Ok(None) => {}
            Err(e) => {
                warn!("Accept error: {}", e);
            }
        }

        // Process client messages and input events
        clients.retain_mut(|client| {
            match client.process_messages() {
                Ok(true) => {
                    // Process input events
                    if let Some(ref vp) = virtual_pointer {
                        for (mask, x, y) in client.pointer_events.drain(..) {
                            let nx = x as f64 / width as f64;
                            let ny = y as f64 / height as f64;
                            vp.motion_normalized(nx, ny);

                            // Detect button changes per client
                            for btn in 0..8u8 {
                                let bit = 1 << btn;
                                let was_pressed = (client.prev_button_mask & bit) != 0;
                                let is_pressed = (mask & bit) != 0;
                                if was_pressed == is_pressed {
                                    continue;
                                }

                                match btn {
                                    0 => vp.button(ptr_button::LEFT, is_pressed),
                                    1 => vp.button(ptr_button::MIDDLE, is_pressed),
                                    2 => vp.button(ptr_button::RIGHT, is_pressed),
                                    3 => {
                                        // Wheel up: emit a discrete scroll step on press.
                                        if is_pressed {
                                            vp.scroll(ptr_axis::VERTICAL, -1);
                                        }
                                    }
                                    4 => {
                                        // Wheel down: emit a discrete scroll step on press.
                                        if is_pressed {
                                            vp.scroll(ptr_axis::VERTICAL, 1);
                                        }
                                    }
                                    5 => vp.button(ptr_button::BACK, is_pressed),
                                    6 => vp.button(ptr_button::FORWARD, is_pressed),
                                    _ => {}
                                }
                            }
                            client.prev_button_mask = mask;
                        }
                    }
                    if let Some(ref mut vk) = virtual_keyboard {
                        for (down, keysym) in client.key_events.drain(..) {
                            vk.keysym(keysym, down);
                        }
                        for (down, keycode) in client.keycode_events.drain(..) {
                            vk.key(keycode, down);
                        }
                    }
                    true
                }
                Ok(false) => {
                    info!("Client disconnected");
                    false
                }
                Err(e) => {
                    warn!("Client error: {}", e);
                    false
                }
            }
        });

        // Retry flushing queued outbound data for lagging clients. A client
        // whose queue exceeds the cap cannot keep up; disconnect it instead
        // of growing memory without bound. When a queued update finally
        // reaches the socket in full, its damage is cleared and the frame is
        // counted (see the deferred `update_in_flight` handling below).
        clients.retain_mut(|client| {
            if let Err(e) = client.flush_pending() {
                warn!(
                    "Client {} flush failed: {}; disconnecting",
                    client.peer_address(),
                    e
                );
                return false;
            }
            if client.outbound_queued() > MAX_OUTBOUND_QUEUE {
                warn!(
                    "Client {} too slow: {} bytes queued; disconnecting",
                    client.peer_address(),
                    client.outbound_queued()
                );
                return false;
            }
            if client.complete_update_if_flushed() && client.has_encoding(Encoding::Fence) {
                if let Err(e) = client.send_fence_ping() {
                    warn!("Failed to send fence ping: {}", e);
                } else if let Err(e) = client.flush_pending() {
                    warn!("Failed to flush fence ping: {}", e);
                }
            }
            true
        });

        // Handle client-requested desktop resizes (SetDesktopSize, RFB type 251).
        for client in &mut clients {
            if let Some((req_width, req_height)) = client.take_desktop_size_request() {
                if wayland.output_manager.is_some() {
                    if wayland.request_resize(&info.name, req_width as u32, req_height as u32, &qh)
                    {
                        info!(
                            "Requested resize to {}x{} via wlr_output_management",
                            req_width, req_height
                        );
                    } else {
                        warn!(
                            "Failed to request resize to {}x{} (head not found)",
                            req_width, req_height
                        );
                    }
                } else {
                    warn!("SetDesktopSize requested but wlr_output_manager is not available");
                }
            }
        }

        match queue.dispatch_pending(&mut wayland) {
            Ok(_) => {}
            Err(e) => {
                error!("Wayland dispatch error: {}", e);
                break;
            }
        }
        conn.flush().ok();

        // Apply a completed desktop resize: recreate the capture manager once
        // the compositor has changed the output mode to the requested size.
        if wayland.resize_result == Some(true) {
            if wayland.pending_resize.is_some() {
                if let Some(current_info) = wayland.find_output_by_name(&info.name) {
                    let new_width = current_info.width.max(1) as u16;
                    let new_height = current_info.height.max(1) as u16;
                    if new_width != width || new_height != height {
                        let Some(ref new_wl_output) = current_info.wl_output else {
                            warn!("Resize target output has no proxy");
                            wayland.pending_resize = None;
                            wayland.resize_result = None;
                            continue;
                        };
                        match CaptureManager::new(
                            &screencopy_mgr,
                            new_wl_output,
                            &shm,
                            new_width as u32,
                            new_height as u32,
                            &qh,
                        ) {
                            Ok(new_mgr) => {
                                capture_mgr = new_mgr;
                                damage_tracker = DamageTracker::new(
                                    new_width as u32,
                                    new_height as u32,
                                    new_width as usize * 4,
                                );
                                width = new_width;
                                height = new_height;
                                listener.set_dimensions(width, height);
                                info!("Resized capture to {}x{} via SetDesktopSize", width, height);

                                // Notify clients of the resize
                                for client in &mut clients {
                                    if client.state == ClientState::Ready {
                                        client.set_dimensions(width, height);
                                        if client.has_encoding(Encoding::ExtendedDesktopSize) {
                                            if let Err(e) =
                                                client.send_extended_desktop_size(width, height)
                                            {
                                                warn!(
                                                    "Failed to send extended desktop size: {}",
                                                    e
                                                );
                                            }
                                        } else if client.has_encoding(Encoding::DesktopSize) {
                                            if let Err(e) = client.send_desktop_size(width, height)
                                            {
                                                warn!("Failed to send desktop size: {}", e);
                                            }
                                        }
                                    }
                                }

                                if let Some(ref state) = control_state_handle {
                                    if let Ok(mut guard) = state.lock() {
                                        guard.width = width;
                                        guard.height = height;
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to create capture manager after resize: {}", e);
                            }
                        }
                        wayland.pending_resize = None;
                        wayland.resize_result = None;
                    }
                }
            }
        } else if wayland.resize_result == Some(false) {
            warn!("SetDesktopSize resize request failed or was cancelled");
            wayland.pending_resize = None;
            wayland.resize_result = None;
        }

        // Notify the capture manager about frame completion events from Wayland.
        if wayland.capture_buffer_done {
            capture_mgr.on_buffer_done();
            wayland.capture_buffer_done = false;
        }
        if wayland.capture_ready {
            capture_mgr.on_frame_ready();
            wayland.capture_ready = false;
        }
        if wayland.capture_failed {
            capture_mgr.on_frame_failed();
            wayland.capture_failed = false;
        }

        // Sync clipboard from VNC client to Wayland
        if let Some(ref cb) = clipboard_mgr {
            cb.sync_to_wayland(&qh);
        }

        // Sync clipboard from Wayland to VNC clients
        if let Ok(mut guard) = wayland.clipboard_text.lock() {
            if let Some(text) = guard.take() {
                for client in &mut clients {
                    if client.state == ClientState::Ready {
                        if let Err(e) = client.send_cut_text(&text) {
                            warn!("Failed to send clipboard to client: {}", e);
                        }
                    }
                }
            }
        }

        // Send cursor shape/position updates to clients that support the Cursor
        // or CursorPos pseudo-encodings. The cursor shape is sent once; position
        // updates are sent whenever this client has moved the cursor via pointer
        // events. This relies on the captured frame not containing the cursor
        // (overlay_cursor=false) so the client renders it locally.
        let cursor_shape = default_cursor();
        for client in &mut clients {
            if client.state != ClientState::Ready {
                continue;
            }

            if client.has_encoding(Encoding::Cursor) && !client.cursor_shape_sent {
                if let Err(e) = client.send_cursor_shape(&cursor_shape) {
                    warn!("Failed to send cursor shape to client: {}", e);
                }
            }

            if let Some((x, y)) = client.cursor_pos {
                if client.last_cursor_pos != Some((x, y))
                    && (client.has_encoding(Encoding::Cursor)
                        || client.has_encoding(Encoding::CursorPos))
                {
                    if let Err(e) = client.send_cursor_pos(x, y) {
                        warn!("Failed to send cursor position to client: {}", e);
                    }
                }
            }

            // Send the desktop name once if the client supports the DesktopName
            // pseudo-encoding. The name is taken from the server config/desktop name.
            if client.has_encoding(Encoding::DesktopName) && !client.desktop_name_sent {
                let name = client.name.clone();
                if let Err(e) = client.send_desktop_name(&name) {
                    warn!("Failed to send desktop name to client: {}", e);
                } else {
                    client.desktop_name_sent = true;
                }
            }
        }

        if pending_capture && capture_mgr.is_complete() {
            let capture_start = Instant::now();
            if let Some(fb) = capture_mgr.take_framebuffer() {
                let capture_us = capture_start.elapsed().as_micros() as u64;
                let stride = width as usize * 4;

                // Compute the changed regions and CopyRect candidates between
                // the last two captures.
                let (copy_rects, damage_rects) =
                    damage_tracker.compute_damage_with_copyrects(&fb.data);

                // Accumulate this frame's changes into every ready client's
                // per-client damage accumulator. Clients without a pending
                // update request still record the changes, so nothing is lost
                // when they ask for an update later.
                for client in &mut clients {
                    if client.state == ClientState::Ready {
                        client.record_frame_damage(&damage_rects, &copy_rects);
                    }
                }

                let bytes_before: u64 = clients.iter().map(|c| c.bytes_sent).sum();
                let mut encode_us: u64 = 0;
                let mut send_us: u64 = 0;

                for client in &mut clients {
                    if client.state != ClientState::Ready {
                        continue;
                    }
                    if !client.outbound_idle() {
                        // A previous update is still being flushed to the
                        // socket. Its damage is retained until it completes;
                        // queueing another update now would pile redundant
                        // bytes onto an already slow client.
                        continue;
                    }
                    if client.pending_requests == 0 && !client.continuous_updates {
                        continue;
                    }

                    if client.damage.is_empty() {
                        // Nothing new for this client; acknowledge incremental
                        // requests with an empty update.
                        if client.pending_requests > 0 {
                            let _ = client.send_fb_update_header(0);
                            let _ = client.flush();
                            client.frame_sent();
                        }
                        continue;
                    }

                    // CopyRect moves copy pixels inside the client's existing
                    // framebuffer, so they are only valid when that framebuffer
                    // matches the server's previous frame. record_frame_damage
                    // guarantees this only when the client's accumulator was
                    // empty at frame start; lagging clients (or clients that
                    // issued a non-incremental request) get the moved regions
                    // as ordinary pixel rectangles instead.
                    let use_copyrect =
                        client.allow_copyrect && client.has_encoding(Encoding::CopyRect);
                    let copy_rects_to_send = if use_copyrect {
                        copy_rects.clone()
                    } else {
                        Vec::new()
                    };
                    let damage_rects_to_send = if use_copyrect {
                        // The accumulator held exactly this frame's changed
                        // tiles; the CopyRect subset is sent as copy rects and
                        // the rest as damage rects.
                        damage_rects.clone()
                    } else {
                        client.damage.rects()
                    };

                    let use_tight = client.has_encoding(Encoding::Tight);
                    let use_zrle = client.has_encoding(Encoding::Zrle);
                    let use_hextile = client.has_encoding(Encoding::Hextile);
                    let use_trle = client.has_encoding(Encoding::Trle);
                    let use_zlib = client.has_encoding(Encoding::Zlib);
                    let use_rre = client.has_encoding(Encoding::Rre);
                    let use_openh264 = client.has_encoding(Encoding::OpenH264)
                        && client.openh264_encoder.is_some();

                    // OpenH264 is a full-frame video codec: encode the entire
                    // framebuffer as one rectangle. This also avoids a
                    // dimension mismatch between the encoder config (full
                    // screen) and per-damage-rect calls.
                    let mut openh264_rect: Option<FbRect> = None;
                    if use_openh264 {
                        if let Some(ref mut encoder) = client.openh264_encoder {
                            let full_rect = encoder.encode(
                                &fb.data,
                                stride,
                                0,
                                0,
                                client.width,
                                client.height,
                                &client.pixel_format,
                            );
                            if !full_rect.data.is_empty() {
                                openh264_rect = Some(full_rect);
                            }
                        }
                    }

                    let total_rects = if openh264_rect.is_some() {
                        1
                    } else {
                        copy_rects_to_send.len() + damage_rects_to_send.len()
                    };

                    if let Err(e) = client.send_fb_update_header(total_rects as u16) {
                        warn!("Send header failed: {}", e);
                        continue;
                    }

                    let encode_start = Instant::now();

                    let mut send_ok = true;
                    if let Some(rect) = openh264_rect {
                        // OpenH264 path: the whole frame is already encoded as one rect.
                        if let Err(e) = client.send_openh264_rect(&rect) {
                            warn!("Send OpenH264 rect failed: {}", e);
                            send_ok = false;
                        }
                    } else {
                        for copy_rect in &copy_rects_to_send {
                            let enc_rect = encode_copyrect(
                                copy_rect.src_x,
                                copy_rect.src_y,
                                copy_rect.x,
                                copy_rect.y,
                                copy_rect.width,
                                copy_rect.height,
                            );
                            if let Err(e) = client.send_copyrect_rect(&enc_rect) {
                                warn!("Send copyrect rect failed: {}", e);
                                send_ok = false;
                                break;
                            }
                        }

                        if send_ok {
                            for rect in &damage_rects_to_send {
                                let enc_rect = if use_tight {
                                    client.tight_encoder.encode(
                                        &fb.data,
                                        stride,
                                        rect.x,
                                        rect.y,
                                        rect.width,
                                        rect.height,
                                        &client.pixel_format,
                                    )
                                } else if use_zrle {
                                    client.zrle_encoder.encode_rect(
                                        &fb.data,
                                        stride,
                                        rect.x,
                                        rect.y,
                                        rect.width,
                                        rect.height,
                                        &client.pixel_format,
                                    )
                                } else if use_hextile {
                                    encode_hextile(
                                        &fb.data,
                                        stride,
                                        rect.x,
                                        rect.y,
                                        rect.width,
                                        rect.height,
                                        &client.pixel_format,
                                    )
                                } else if use_trle {
                                    encode_trle(
                                        &fb.data,
                                        stride,
                                        rect.x,
                                        rect.y,
                                        rect.width,
                                        rect.height,
                                        &client.pixel_format,
                                    )
                                } else if use_zlib {
                                    client.zlib_encoder.encode_rect(
                                        &fb.data,
                                        stride,
                                        rect.x,
                                        rect.y,
                                        rect.width,
                                        rect.height,
                                        &client.pixel_format,
                                    )
                                } else if use_rre {
                                    encode_rre(
                                        &fb.data,
                                        stride,
                                        rect.x,
                                        rect.y,
                                        rect.width,
                                        rect.height,
                                        &client.pixel_format,
                                    )
                                } else {
                                    encode_raw(
                                        &fb.data,
                                        stride,
                                        rect.x,
                                        rect.y,
                                        rect.width,
                                        rect.height,
                                        &client.pixel_format,
                                    )
                                };
                                let send_result = client.send_encoded_rect(&enc_rect);
                                if let Err(e) = send_result {
                                    warn!("Send rect failed: {}", e);
                                    send_ok = false;
                                    break;
                                }
                            }
                        }
                    }
                    encode_us += encode_start.elapsed().as_micros() as u64;

                    let send_start = Instant::now();
                    if send_ok {
                        if let Err(e) = client.flush() {
                            warn!("Flush failed: {}", e);
                            send_ok = false;
                        }
                    }
                    if !send_ok {
                        // Keep the accumulated damage (and the pending request)
                        // so the missed regions are resent with a later update
                        // instead of being silently dropped.
                        continue;
                    }
                    send_us += send_start.elapsed().as_micros() as u64;
                    // The whole update (header + all rects) is now queued in
                    // order. Damage is cleared and the frame counted only once
                    // every byte has actually been flushed to the socket;
                    // otherwise `update_in_flight` stays set and the flush
                    // retry at the top of the loop completes it later.
                    client.update_in_flight = true;
                    if client.complete_update_if_flushed() && client.has_encoding(Encoding::Fence) {
                        if let Err(e) = client.send_fence_ping() {
                            warn!("Failed to send fence ping: {}", e);
                        } else if let Err(e) = client.flush() {
                            warn!("Failed to flush fence ping: {}", e);
                        }
                    }
                    debug!(
                        "Sent {} rects to client (copyrect={}, tight={}, zrle={}, hextile={}, trle={}, zlib={}, rre={})",
                        total_rects,
                        use_copyrect,
                        use_tight,
                        use_zrle,
                        use_hextile,
                        use_trle,
                        use_zlib,
                        use_rre
                    );
                }

                let bytes_after: u64 = clients.iter().map(|c| c.bytes_sent).sum();
                let bytes_sent = bytes_after.saturating_sub(bytes_before);
                perf_stats.record_frame(bytes_sent, capture_us, encode_us, send_us);
            }
            pending_capture = false;
        }

        if let Some(ref state) = control_state_handle {
            if let Ok(guard) = state.lock() {
                let snapshot = perf_stats.current_snapshot();
                guard.perf.update(snapshot);
            }
        }

        if let Some(snapshot) = perf_stats.maybe_log() {
            if let Some(ref state) = control_state_handle {
                if let Ok(guard) = state.lock() {
                    guard.perf.update(snapshot);
                }
            }
        }

        // Process fence responses and update per-client bandwidth estimates.
        let mut any_bandwidth_constrained = false;
        for client in &mut clients {
            client.process_fence_events();
            client.recompute_inflight();
            if client.state == ClientState::Ready
                && !client
                    .bandwidth_estimator
                    .should_send(client.bytes_inflight)
            {
                any_bandwidth_constrained = true;
                debug!(
                    "Client {} bandwidth constrained: inflight={} bytes, bps={:.0}",
                    client.peer_address(),
                    client.bytes_inflight,
                    client.bandwidth_estimator.bandwidth_bps()
                );
            }
        }

        if !pending_capture
            && last_capture.elapsed() >= Duration::from_millis(1000 / config.max_rate.max(1) as u64)
            && !any_bandwidth_constrained
            && capture_mgr.start_capture(&qh, config.overlay_cursor)
        {
            pending_capture = true;
            last_capture = Instant::now();
        }

        // Poll control interface
        if let Some(ref cs) = control_server {
            cs.poll();
        }

        // Update control state with current stats, clients, and available outputs
        if let Some(ref state) = control_state_handle {
            if let Ok(mut guard) = state.lock() {
                guard.client_count = clients.len();
                guard.total_bytes_sent = clients.iter().map(|c| c.bytes_sent).sum();
                guard.total_bytes_received = clients.iter().map(|c| c.bytes_received).sum();
                guard.total_frames_sent = clients.iter().map(|c| c.frames_sent).sum();

                let client_infos: Vec<ClientInfo> = clients
                    .iter()
                    .enumerate()
                    .map(|(id, c)| ClientInfo {
                        id,
                        address: c.peer_address(),
                        connected_seconds: c.connected_at.elapsed().as_secs(),
                        bytes_sent: c.bytes_sent,
                        bytes_received: c.bytes_received,
                        frames_sent: c.frames_sent,
                    })
                    .collect();
                guard.set_clients(client_infos);

                let outputs: Vec<String> = wayland.outputs.iter().map(|o| o.name.clone()).collect();
                guard.set_outputs(outputs);

                // Aggregate bandwidth snapshot across all clients: take the most
                // conservative (lowest) estimate and sum inflight bytes.
                let mut bandwidth = BandwidthSnapshot::default();
                for client in &clients {
                    let snapshot = client.bandwidth_estimator.snapshot(client.bytes_inflight);
                    if bandwidth.bandwidth_bps == 0.0
                        || snapshot.bandwidth_bps < bandwidth.bandwidth_bps
                    {
                        bandwidth.bandwidth_bps = snapshot.bandwidth_bps;
                        bandwidth.rtt_us = snapshot.rtt_us;
                        bandwidth.target_latency_us = snapshot.target_latency_us;
                    }
                    bandwidth.bytes_inflight += snapshot.bytes_inflight;
                }
                if let Ok(mut b) = guard.bandwidth.lock() {
                    *b = bandwidth;
                }
            }
        }

        // Process control requests
        if let Some(ref state) = control_state_handle {
            let mut output_switch_request: Option<String> = None;
            let mut exit_requested = false;
            let mut disconnect_id: Option<usize> = None;
            let mut reload_config = false;
            let mut new_password: Option<Option<String>> = None;
            let mut new_rate: Option<u32> = None;
            let mut new_latency: Option<u64> = None;

            // Clone the inner request Arcs while holding the outer guard briefly,
            // then drop the outer guard before locking any inner mutex. This avoids
            // nested MutexGuard lifetimes that the borrow checker cannot prove are safe.
            let (
                disconnect_req,
                reload_req,
                password_req,
                rate_req,
                output_req,
                latency_req,
                exit_req,
            ) = {
                let guard = state.lock().unwrap_or_else(|e| e.into_inner());
                (
                    guard.disconnect_request.clone(),
                    guard.reload_config_request.clone(),
                    guard.set_password_request.clone(),
                    guard.set_rate_request.clone(),
                    guard.switch_output_request.clone(),
                    guard.set_latency_request.clone(),
                    guard.exit_request.clone(),
                )
            };

            if let Ok(mut req) = disconnect_req.lock() {
                disconnect_id = req.take();
            }

            if let Ok(mut req) = reload_req.lock() {
                reload_config = *req;
                if reload_config {
                    *req = false;
                }
            }

            if let Ok(mut req) = password_req.lock() {
                new_password = req.take();
            }

            if let Ok(mut req) = rate_req.lock() {
                new_rate = req.take();
            }

            if let Ok(mut req) = output_req.lock() {
                output_switch_request = req.take();
            }

            if let Ok(mut req) = latency_req.lock() {
                new_latency = req.take();
            }

            if let Ok(mut req) = exit_req.lock() {
                exit_requested = *req;
                if exit_requested {
                    *req = false;
                }
            }

            if let Some(id) = disconnect_id {
                if id < clients.len() {
                    info!("Control: disconnecting client {}", id);
                    clients.remove(id);
                }
            }

            if reload_config {
                info!("Control: reloading config");
                if let Some(ref path) = config_path_clone {
                    let path_buf = PathBuf::from(path);
                    if let Ok(new_config) = parse_file(&path_buf) {
                        config = merge_configs(Some(new_config), config, &cli_explicit);
                        info!("Config reloaded from {}", path);
                    } else {
                        warn!("Failed to reload config from {}", path);
                    }
                }
            }

            if let Some(password) = new_password {
                listener.set_password(password.clone());
                config.password = password.clone();
                info!(
                    "Control: password {}",
                    if password.is_some() { "set" } else { "cleared" }
                );
            }

            if let Some(rate) = new_rate {
                config.max_rate = rate;
                info!("Control: max rate set to {}", rate);
            }

            if let Some(latency_us) = new_latency {
                for client in &mut clients {
                    client.bandwidth_estimator.set_target_latency(latency_us);
                }
                info!("Control: target latency set to {} us", latency_us);
            }

            if exit_requested {
                info!("Control: exit requested");
                running.store(false, Ordering::SeqCst);
            }

            if let Some(new_output) = output_switch_request {
                if let Some(info) = wayland.find_output_by_name(&new_output).cloned() {
                    let new_width = info.width.max(1) as u16;
                    let new_height = info.height.max(1) as u16;
                    if let Some(ref new_wl_output) = info.wl_output {
                        match CaptureManager::new(
                            &screencopy_mgr,
                            new_wl_output,
                            &shm,
                            new_width as u32,
                            new_height as u32,
                            &qh,
                        ) {
                            Ok(new_mgr) => {
                                capture_mgr = new_mgr;
                                damage_tracker = DamageTracker::new(
                                    new_width as u32,
                                    new_height as u32,
                                    new_width as usize * 4,
                                );
                                width = new_width;
                                height = new_height;
                                listener.set_dimensions(width, height);
                                config.output = Some(new_output.clone());
                                info!(
                                    "Control: switched to output '{}' at {}x{}",
                                    new_output, width, height
                                );

                                // Notify clients of the resize
                                for client in &mut clients {
                                    if client.state == ClientState::Ready {
                                        client.set_dimensions(width, height);
                                        if client.has_encoding(Encoding::ExtendedDesktopSize) {
                                            if let Err(e) =
                                                client.send_extended_desktop_size(width, height)
                                            {
                                                warn!(
                                                    "Failed to send extended desktop size: {}",
                                                    e
                                                );
                                            }
                                        } else if client.has_encoding(Encoding::DesktopSize) {
                                            if let Err(e) = client.send_desktop_size(width, height)
                                            {
                                                warn!("Failed to send desktop size: {}", e);
                                            }
                                        }
                                    }
                                }

                                // Update control state
                                if let Ok(mut guard) = state.lock() {
                                    guard.output_name = new_output;
                                    guard.width = width;
                                    guard.height = height;
                                }
                            }
                            Err(e) => {
                                warn!("Control: failed to switch output: {}", e);
                            }
                        }
                    } else {
                        warn!("Control: output '{}' has no proxy", new_output);
                    }
                } else {
                    warn!("Control: output '{}' not found", new_output);
                }
            }
        }

        conn.flush().ok();
        std::thread::sleep(Duration::from_millis(5));
    }

    info!("VNC server shutting down.");
}
