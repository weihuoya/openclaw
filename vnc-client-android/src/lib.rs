//! Android VNC client library.
//!
//! Provides an Android-native VNC viewer using:
//! - OpenGL ES 3 + EGL for Surface rendering
//! - NdkMediaCodec (via `vnc-client`) for hardware H.264 decoding

use std::ffi::{c_char, c_void, CStr, CString};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use ndk::native_window::NativeWindow;

pub use vnc_client::{PixelFormat, VncClient, VncError, VncEvent};

use vnc_client::auth::{AppleDhAuthHandler, NoAuthHandler, PasswordAuthHandler};

mod renderer;
use renderer::EglRenderer;

/// Android VNC display controller.
///
/// Owns the VNC client connection and renders decoded frames to an
/// Android [`Surface`] via OpenGL ES 3.
pub struct AndroidVncDisplay {
    client: VncClient,
    renderer: Option<EglRenderer>,
    frame_width: u32,
    frame_height: u32,
    auth_username: Option<String>,
    auth_password: Option<String>,
}

impl Default for AndroidVncDisplay {
    fn default() -> Self {
        Self::new()
    }
}

impl AndroidVncDisplay {
    pub fn new() -> Self {
        Self {
            client: VncClient::new(),
            renderer: None,
            frame_width: 0,
            frame_height: 0,
            auth_username: None,
            auth_password: None,
        }
    }

    /// Connect to a VNC server.
    pub fn connect(&mut self, host: &str, port: u16) -> Result<(), VncError> {
        self.client.set_host(host);
        self.client.connect((host, port))
    }

    /// Perform VNC handshake (must be called after `connect`).
    pub fn handshake(&mut self) -> Result<Vec<VncEvent>, VncError> {
        match (self.auth_username.as_ref(), self.auth_password.as_ref()) {
            (Some(username), Some(password)) => {
                let mut auth = AppleDhAuthHandler::new(username.clone(), password.clone());
                self.client.handshake(&mut auth)
            }
            (None, Some(password)) => {
                let mut auth = PasswordAuthHandler::new(password.clone());
                self.client.handshake(&mut auth)
            }
            _ => {
                let mut auth = NoAuthHandler;
                self.client.handshake(&mut auth)
            }
        }
    }

    /// Set the username for Apple Remote Desktop authentication.
    pub fn set_username(&mut self, username: String) {
        self.auth_username = Some(username);
    }

    /// Set the password for VNC or Apple Remote Desktop authentication.
    pub fn set_password(&mut self, password: String) {
        self.auth_password = Some(password);
    }

    /// Attach an Android [`NativeWindow`] for rendering.
    pub fn set_surface(&mut self, native_window: &NativeWindow) -> Result<(), String> {
        self.renderer = Some(EglRenderer::new(native_window)?);
        Ok(())
    }

    /// Resize the rendering viewport.
    pub fn resize(&mut self, width: i32, height: i32) {
        if let Some(r) = self.renderer.as_mut() {
            r.resize(width, height);
        }
    }

    /// Request a framebuffer update from the server.
    pub fn request_update(&mut self, incremental: bool) -> Result<(), VncError> {
        let (w, h) = (self.client.width(), self.client.height());
        self.client.request_update(incremental, 0, 0, w, h)
    }

    /// Read server messages and render any frame updates.
    pub fn read_and_render(&mut self) -> Result<Vec<VncEvent>, VncError> {
        let events = self.client.read_messages()?;

        // If framebuffer changed dimensions, update tracking
        let (w, h) = (self.client.width() as u32, self.client.height() as u32);
        if w != self.frame_width || h != self.frame_height {
            self.frame_width = w;
            self.frame_height = h;
        }

        // Render current framebuffer if we have a surface
        if w > 0 && h > 0 {
            let fb = self.client.framebuffer().data().to_vec();
            if let Some(renderer) = self.renderer.as_mut() {
                renderer.render_frame(&fb, w, h);
            }
        }

        Ok(events)
    }

    /// Send a pointer (touch) event.
    pub fn send_pointer(&mut self, button_mask: u8, x: u16, y: u16) -> Result<(), VncError> {
        self.client.send_pointer_event(button_mask, x, y)
    }

    /// Send a key event.
    pub fn send_key(&mut self, down: bool, keysym: u32) -> Result<(), VncError> {
        self.client.send_key_event(down, keysym)
    }
}

// ─── JNI exports ───────────────────────────────────────────────────

/// Opaque handle passed between Java/Kotlin and Rust.
pub struct VncDisplayHandle {
    display: Mutex<AndroidVncDisplay>,
    loop_running: AtomicBool,
    loop_handle: Mutex<Option<JoinHandle<()>>>,
}

/// Create a new display handle.
///
/// # Safety
/// Must be freed with `vnc_display_destroy`.
#[no_mangle]
pub unsafe extern "C" fn vnc_display_create() -> *mut VncDisplayHandle {
    let handle = Box::new(VncDisplayHandle {
        display: Mutex::new(AndroidVncDisplay::new()),
        loop_running: AtomicBool::new(false),
        loop_handle: Mutex::new(None),
    });
    Box::into_raw(handle)
}

/// Destroy a display handle.
///
/// # Safety
/// The caller must call `vnc_display_stop_loop` and wait for the background
/// loop to exit before calling this function, or undefined behavior may occur
/// when the loop thread accesses the freed handle.
#[no_mangle]
pub unsafe extern "C" fn vnc_display_destroy(handle: *mut VncDisplayHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// Connect to a VNC server.
#[no_mangle]
pub unsafe extern "C" fn vnc_display_connect(
    handle: *mut VncDisplayHandle,
    host: *const c_char,
    port: u16,
) -> i32 {
    if handle.is_null() || host.is_null() {
        return -1;
    }
    let host = match CStr::from_ptr(host).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let mut guard = (*handle).display.lock().unwrap();
    match guard.connect(host, port) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Perform VNC handshake.
#[no_mangle]
pub unsafe extern "C" fn vnc_display_handshake(handle: *mut VncDisplayHandle) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let mut guard = (*handle).display.lock().unwrap();
    match guard.handshake() {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Attach an Android surface for rendering.
/// `surface_ptr` must be a valid `ANativeWindow*` (obtained from `android.view.Surface`).
#[no_mangle]
pub unsafe extern "C" fn vnc_display_set_surface(
    handle: *mut VncDisplayHandle,
    surface_ptr: *mut c_void,
) -> i32 {
    if handle.is_null() || surface_ptr.is_null() {
        return -1;
    }
    let ptr = match std::ptr::NonNull::new(surface_ptr as *mut ndk_sys::ANativeWindow) {
        Some(p) => p,
        None => return -1,
    };
    // Acquire an additional reference to the borrowed ANativeWindow; the Java
    // caller remains responsible for releasing its own reference.
    let window = unsafe { NativeWindow::clone_from_ptr(ptr) };
    let mut guard = (*handle).display.lock().unwrap();
    match guard.set_surface(&window) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Resize the renderer viewport.
#[no_mangle]
pub unsafe extern "C" fn vnc_display_resize(
    handle: *mut VncDisplayHandle,
    width: i32,
    height: i32,
) {
    if handle.is_null() {
        return;
    }
    let mut guard = (*handle).display.lock().unwrap();
    guard.resize(width, height);
}

/// Read server messages and render.
#[no_mangle]
pub unsafe extern "C" fn vnc_display_read_and_render(handle: *mut VncDisplayHandle) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let mut guard = (*handle).display.lock().unwrap();
    match guard.read_and_render() {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Send a pointer (touch) event.
#[no_mangle]
pub unsafe extern "C" fn vnc_display_send_pointer(
    handle: *mut VncDisplayHandle,
    button_mask: u8,
    x: u16,
    y: u16,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let mut guard = (*handle).display.lock().unwrap();
    match guard.send_pointer(button_mask, x, y) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Set the username for Apple Remote Desktop authentication.
///
/// # Safety
/// `handle` must be a valid pointer returned by `vnc_display_create` and not
/// yet destroyed. `username` must be a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn vnc_display_set_username(
    handle: *mut VncDisplayHandle,
    username: *const c_char,
) -> i32 {
    if handle.is_null() || username.is_null() {
        return -1;
    }
    let username = match CStr::from_ptr(username).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };
    let mut guard = (*handle).display.lock().unwrap();
    guard.set_username(username);
    0
}

/// Set the password for VNC or Apple Remote Desktop authentication.
///
/// # Safety
/// `handle` must be a valid pointer returned by `vnc_display_create` and not
/// yet destroyed. `password` must be a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn vnc_display_set_password(
    handle: *mut VncDisplayHandle,
    password: *const c_char,
) -> i32 {
    if handle.is_null() || password.is_null() {
        return -1;
    }
    let password = match CStr::from_ptr(password).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };
    let mut guard = (*handle).display.lock().unwrap();
    guard.set_password(password);
    0
}

/// Send a key event.
///
/// # Safety
/// `handle` must be a valid pointer returned by `vnc_display_create` and not
/// yet destroyed.
#[no_mangle]
pub unsafe extern "C" fn vnc_display_send_key(
    handle: *mut VncDisplayHandle,
    down: u8,
    keysym: u32,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let mut guard = (*handle).display.lock().unwrap();
    match guard.send_key(down != 0, keysym) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Start a background thread that continuously reads server messages and
/// renders frames.
///
/// # Safety
/// `handle` must be a valid pointer returned by `vnc_display_create` and not
/// yet destroyed. The caller must pair every successful start with a later
/// `vnc_display_stop_loop` before destroying the handle.
#[no_mangle]
pub unsafe extern "C" fn vnc_display_start_loop(handle: *mut VncDisplayHandle) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let mut handle_guard = (*handle).loop_handle.lock().unwrap();
    if handle_guard.is_some() {
        return -1;
    }
    (*handle).loop_running.store(true, Ordering::SeqCst);
    let running = (*handle).loop_running.clone();
    let handle_ptr = handle;
    *handle_guard = Some(std::thread::spawn(move || {
        while running.load(Ordering::SeqCst) {
            // SAFETY: the caller contract guarantees `handle_ptr` remains valid
            // while the loop is running.
            if vnc_display_read_and_render(handle_ptr) != 0 {
                log::error!("VNC read/render loop failed");
                break;
            }
        }
        running.store(false, Ordering::SeqCst);
    }));
    0
}

/// Stop the background read/render loop and wait for the thread to exit.
///
/// # Safety
/// `handle` must be a valid pointer returned by `vnc_display_create` and not
/// yet destroyed.
#[no_mangle]
pub unsafe extern "C" fn vnc_display_stop_loop(handle: *mut VncDisplayHandle) -> i32 {
    if handle.is_null() {
        return -1;
    }
    (*handle).loop_running.store(false, Ordering::SeqCst);
    if let Some(join) = (*handle).loop_handle.lock().unwrap().take() {
        let _ = join.join();
    }
    0
}
