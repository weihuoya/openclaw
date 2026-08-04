//! VNC Server binary entry point (pure Rust RFB implementation).

use std::env;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, error, info, warn};

use vnc_server::config::{merge_configs, parse_file, Config};
use vnc_server::control::{ControlServer, ControlState};
use vnc_server::damage::DamageTracker;
use vnc_server::encode::hextile::encode_hextile;
use vnc_server::encode::raw::encode_raw;
use vnc_server::protocol::Encoding;
use vnc_server::server::client::{ClientState, VncClient};
use vnc_server::server::listener::VncListener;
use vnc_server::signal;
use vnc_server::wayland::capture::CaptureManager;
use vnc_server::wayland::input::{button as ptr_button, VirtualPointer};
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
    println!("  -h, --help               Print this help");
}

fn parse_args() -> Option<(Config, Option<String>)> {
    let mut config = Config::default();
    let mut display_name: Option<String> = None;

    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "-a" | "--address" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    config.address = v.clone();
                }
            }
            "-p" | "--port" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    config.port = v.parse().unwrap_or(5900);
                }
            }
            "-n" | "--name" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    config.name = v.clone();
                }
            }
            "-r" | "--max-rate" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    config.max_rate = v.parse().unwrap_or(30);
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
            "-h" | "--help" => {
                print_usage();
                return None;
            }
            _ => {}
        }
        i += 1;
    }

    Some((config, display_name))
}

fn main() {
    env_logger::init();

    let (cli_config, display_name) = match parse_args() {
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

    let mut config = merge_configs(file_config, cli_config);

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

    let width = info.width.max(1) as u16;
    let height = info.height.max(1) as u16;

    info!("Capturing output '{}' at {}x{}", info.name, width, height);

    let mut listener = match VncListener::bind(
        &config.address,
        config.port,
        config.password.clone(),
        config.enable_auth && config.password.is_some(),
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

    let screencopy_mgr = wayland.screencopy_manager.as_ref().unwrap().clone();
    let shm = wayland.shm.as_ref().unwrap().clone();
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
    let mut virtual_keyboard: Option<VirtualKeyboard> = None;

    if !config.disable_input {
        if let Some(vp_mgr) = wayland.virtual_pointer_manager.as_ref() {
            if let Some(seat) = wayland.seats.first() {
                virtual_pointer = Some(VirtualPointer::new(vp_mgr, &seat.wl_seat, &qh));
                info!("Virtual pointer created");
            }
        }
        match VirtualKeyboard::new() {
            Ok(vk) => {
                virtual_keyboard = Some(vk);
                info!("Virtual keyboard created");
            }
            Err(e) => {
                warn!("Failed to create virtual keyboard: {}", e);
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
                                if was_pressed != is_pressed {
                                    let wl_btn = match btn {
                                        0 => ptr_button::LEFT,
                                        1 => ptr_button::MIDDLE,
                                        2 => ptr_button::RIGHT,
                                        _ => continue,
                                    };
                                    vp.button(wl_btn, is_pressed);
                                }
                            }
                            client.prev_button_mask = mask;
                        }
                    }
                    if let Some(ref mut vk) = virtual_keyboard {
                        for (down, keysym) in client.key_events.drain(..) {
                            vk.keysym(keysym, down);
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

        match queue.dispatch_pending(&mut wayland) {
            Ok(_) => {}
            Err(e) => {
                error!("Wayland dispatch error: {}", e);
                break;
            }
        }
        conn.flush().ok();

        // Notify the capture manager about frame completion events from Wayland.
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

        if pending_capture && capture_mgr.is_complete() {
            if let Some(fb) = capture_mgr.take_framebuffer() {
                let stride = width as usize * 4;

                // Compute damage regions
                let damage_rects = damage_tracker.compute_damage(&fb.data);
                let has_full_damage = client_has_full_damage(&clients);

                for client in &mut clients {
                    if client.state != ClientState::Ready {
                        continue;
                    }
                    if client.pending_requests == 0 && !client.continuous_updates {
                        continue;
                    }

                    let rects_to_send = if has_full_damage {
                        damage_tracker.force_full_damage()
                    } else {
                        damage_rects.clone()
                    };

                    if rects_to_send.is_empty() {
                        // Send empty update for incremental requests
                        if client.pending_requests > 0 {
                            let _ = client.send_fb_update_header(0);
                            let _ = client.flush();
                            client.frame_sent();
                        }
                        continue;
                    }

                    let use_tight = client.has_encoding(Encoding::Tight);
                    let use_zrle = client.has_encoding(Encoding::Zrle);
                    let use_hextile = client.has_encoding(Encoding::Hextile);
                    if let Err(e) = client.send_fb_update_header(rects_to_send.len() as u16) {
                        warn!("Send header failed: {}", e);
                        continue;
                    }

                    for rect in &rects_to_send {
                        let enc_rect = if use_tight {
                            client.tight_encoder.encode(
                                &fb.data,
                                stride,
                                rect.x,
                                rect.y,
                                rect.width,
                                rect.height,
                            )
                        } else if use_zrle {
                            client.zrle_encoder.encode_rect(
                                &fb.data,
                                stride,
                                rect.x,
                                rect.y,
                                rect.width,
                                rect.height,
                            )
                        } else if use_hextile {
                            encode_hextile(
                                &fb.data,
                                stride,
                                rect.x,
                                rect.y,
                                rect.width,
                                rect.height,
                            )
                        } else {
                            encode_raw(&fb.data, stride, rect.x, rect.y, rect.width, rect.height)
                        };
                        let send_result = if use_tight {
                            client.send_tight_rect(&enc_rect)
                        } else if use_zrle {
                            client.send_zrle_rect(&enc_rect)
                        } else if use_hextile {
                            client.send_hextile_rect(&enc_rect)
                        } else {
                            client.send_raw_rect(&enc_rect)
                        };
                        if let Err(e) = send_result {
                            warn!("Send rect failed: {}", e);
                            break;
                        }
                    }
                    if let Err(e) = client.flush() {
                        warn!("Flush failed: {}", e);
                        continue;
                    }
                    client.frame_sent();
                    debug!(
                        "Sent {} rects to client (tight={}, zrle={}, hextile={})",
                        rects_to_send.len(),
                        use_tight,
                        use_zrle,
                        use_hextile
                    );
                }
            }
            pending_capture = false;
        }

        if !pending_capture
            && last_capture.elapsed() >= Duration::from_millis(1000 / config.max_rate.max(1) as u64)
            && capture_mgr.start_capture(&qh, config.overlay_cursor)
        {
            pending_capture = true;
            last_capture = Instant::now();
        }

        // Poll control interface
        if let Some(ref cs) = control_server {
            cs.poll();
        }

        // Update control state with current stats
        if let Some(ref state) = control_state_handle {
            if let Ok(mut guard) = state.lock() {
                guard.client_count = clients.len();
                guard.total_bytes_sent = clients.iter().map(|c| c.bytes_sent).sum();
                guard.total_bytes_received = clients.iter().map(|c| c.bytes_received).sum();
                guard.total_frames_sent = clients.iter().map(|c| c.frames_sent).sum();
            }
        }

        // Process control requests
        if let Some(ref state) = control_state_handle {
            if let Ok(guard) = state.lock() {
                // Check for disconnect requests
                if let Ok(mut req) = guard.disconnect_request.lock() {
                    if let Some(id) = req.take() {
                        if id < clients.len() {
                            info!("Control: disconnecting client {}", id);
                            clients.remove(id);
                        }
                    }
                }

                // Check for reload config request
                if let Ok(mut req) = guard.reload_config_request.lock() {
                    if *req {
                        *req = false;
                        info!("Control: reloading config");
                        if let Some(ref path) = config_path_clone {
                            let path_buf = PathBuf::from(path);
                            if let Ok(new_config) = parse_file(&path_buf) {
                                config = merge_configs(Some(new_config), config);
                                info!("Config reloaded from {}", path);
                            } else {
                                warn!("Failed to reload config from {}", path);
                            }
                        }
                    }
                }

                // Check for password change request
                if let Ok(mut req) = guard.set_password_request.lock() {
                    if let Some(new_password) = req.take() {
                        listener.set_password(new_password.clone());
                        config.password = new_password.clone();
                        info!(
                            "Control: password {}",
                            if new_password.is_some() {
                                "set"
                            } else {
                                "cleared"
                            }
                        );
                    }
                }

                // Check for rate change request
                if let Ok(mut req) = guard.set_rate_request.lock() {
                    if let Some(new_rate) = req.take() {
                        config.max_rate = new_rate;
                        info!("Control: max rate set to {}", new_rate);
                    }
                }

                // Check for output switch request (takes effect on next restart)
                if let Ok(mut req) = guard.switch_output_request.lock() {
                    if let Some(new_output) = req.take() {
                        config.output = Some(new_output.clone());
                        info!(
                            "Control: output set to {} (will take effect on restart)",
                            new_output
                        );
                    }
                }
            }
        }

        conn.flush().ok();
        std::thread::sleep(Duration::from_millis(5));
    }

    info!("VNC server shutting down.");
}

fn client_has_full_damage(clients: &[VncClient]) -> bool {
    clients.iter().any(|c| {
        c.damage
            .iter()
            .any(|&(x, y, w, h)| x == 0 && y == 0 && w == c.width && h == c.height)
    })
}
