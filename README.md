# OpenClaw

A Rust VNC client library and display widgets implementing the RFB protocol.

## Architecture

```
openclaw/
├── vnc-client/         # Core VNC client library (RFB protocol)
├── vnc-server/         # Wayland VNC server (RFB protocol + wlr-screencopy)
├── vnc-widget-gtk4/    # GTK4 display widget
├── vnc-client-adwaita/ # Adwaita GTK4 desktop VNC client
└── vnc-client-android/ # Android display scaffold
```

## vnc-client

Pure Rust VNC client library implementing the RFB protocol.

### Features

- [x] TCP and TLS connection management
- [x] RFB protocol handshake (version 3.3, 3.7, 3.8)
- [x] Authentication: None, VNC password (DES challenge-response), Apple Remote Desktop (Diffie-Hellman + AES-128-ECB)
- [x] Apple high-performance mode (partial):
  - [x] RSA-SRP authentication (type 33)
  - [x] AES-128-CBC encrypted record layer with SHA-1 integrity
  - [x] Initial rekey and mid-session rekey
  - [ ] Virtual display configuration (`SetDisplayConfiguration` 0x1d)
  - [ ] Apple cursor cache/rendering (`0x450`)
  - [ ] Apple still-image codecs (`0x3ea`, `0x3f3`)
  - [ ] HEVC/UDP media negotiation (`0x1c`)
- [x] Framebuffer encodings: Raw, CopyRect, RRE, TRLE, Hextile, ZRLE, Tight
- [x] Input events: pointer and keyboard
- [x] Clipboard: legacy cut text and extended-clipboard provide/request
- [x] Continuous updates and `EndOfContinuousUpdates`
- [x] Cursor pseudo-encoding and desktop-size pseudo-encodings
- [ ] Zlib encoding
- [x] VeNCrypt security negotiation (subtypes 0/1/2/256/22/26/27/30 are wired; X509 is handled as TLS + certificate validation via rustls)
- [x] RSA-AES/RSA-AES-256 VeNCrypt sub-types (handshake + AES-CTR stream encryption)
- [x] OpenH264 decoding via GStreamer on Linux (client), with H.264 NALU parser and NdkMediaCodec scaffolding on Android

### Usage

```rust
use vnc_client::{VncClient, VncEvent, PixelFormat, encodings::Encoding};

let mut client = VncClient::new();
client.connect("192.168.1.100:5900")?;

// Handshake with no authentication
use vnc_client::auth::NoAuthHandler;
let mut auth = NoAuthHandler;
let events = client.handshake(&mut auth)?;

// Set preferred encodings
client.set_encodings(&[
    Encoding::Raw,
    Encoding::CopyRect,
    Encoding::DesktopSize,
])?;

// Request full update
let (width, height) = client.dimensions();
client.request_update(false, 0, 0, width, height)?;

// Read server messages
let events = client.read_messages()?;
for event in events {
    match event {
        VncEvent::FramebufferUpdate { x, y, width, height } => {
            println!("Update: {}x{} at ({}, {})", width, height, x, y);
        }
        _ => {}
    }
}
```

## vnc-server

Wayland-native VNC server built on `wlr-screencopy-unstable-v1` and `wlr-virtual-pointer`.

### Features

- [x] TCP listener and RFB 3.8 handshake (None + VNC password auth)
- [x] Raw, Hextile, Tight, ZRLE, Zlib, RRE, TRLE, CopyRect, and OpenH264 frame encoders
- [x] Wayland screen capture with tile-based damage tracking and CopyRect
- [x] Virtual pointer via `wlr-virtual-pointer`
- [x] Virtual keyboard via uinput (fallback) or `zwp-virtual-keyboard-v1` (preferred, no root required)
- [x] Continuous updates, desktop resize, and extended desktop size
- [x] Cursor pseudo-encoding (-239) and cursor position updates
- [x] Desktop name pseudo-encoding
- [x] Bidirectional clipboard via `wlr-data-control`
- [x] JSON Unix-socket control interface (`status`, `set-password`, `set-rate`, `set-output`, `disconnect-client`, `get-stats`, `set-latency`, ...)
- [x] TLS / VeNCrypt / RSA-AES security
- [x] Fence pseudo-encoding for bandwidth estimation

### Build

```bash
cargo build -p vnc-server
```

## vnc-widget-gtk4

GTK4 VNC display widget (`gtk4_vnc`).

### Features

- [x] `VncPaintable` (GdkPaintable implementation)
- [x] `VncDisplay` (GtkWidget subclass)
- [x] Background VNC thread with message loop
- [x] Mouse and keyboard input forwarding
- [x] Scaling and aspect-ratio preservation
- [x] GPU texture upload via `GdkGLTextureBuilder` with memory-texture fallback
- [ ] Touch/gesture support
- [ ] Fullscreen mode and toolbar overlay
- [x] Authentication UI path is provided by `vnc-client-adwaita` (the widget itself still exposes `connect_with_options` for custom auth handlers)

### Usage

```rust
use gtk4_vnc::VncDisplay;

let display = VncDisplay::new();
display.connect_to_host("192.168.1.100", 5900)?;

// The widget renders VNC framebuffer content.
// Embed it in your GTK4 application like any other widget.
```

## vnc-client-adwaita

Desktop VNC client using **libadwaita** / GTK4 and GSettings.

### Features

- [x] Adwaita-style GTK4 UI (header bar, toast overlay, preferences dialog)
- [x] Reuses `VncDisplay` from `vnc-widget-gtk4` for remote framebuffer rendering
- [x] Supports **no authentication**, **VNC password authentication**, and **Apple Remote Desktop authentication**
- [x] TLS toggle for `connect_with_options`
- [x] VeNCrypt security type advertised in the auth dropdown (selecting it shows a "not yet supported" message instead of silently downgrading)
- [x] Settings persisted to GSettings:
  - host, port, username, auth method, **use-tls**
  - preferred encoding, view-only, scale-to-fit
- [x] Multi-language UI via gettext (English, Simplified Chinese)
- [x] Desktop entry (`.desktop`) and application icon
- [ ] SASL/VeNCrypt authentication UI (core supports it; no dedicated UI yet)

### Build and run

Requires `libadwaita-1-dev` and `gettext`.

On Debian/Ubuntu:

```bash
sudo apt-get install -y libadwaita-1-dev gettext
```

Compile the GSettings schema, build the crate (this also generates the `.desktop`
file and compiles `po/*.po` into `locale/*.mo`), and run with local data
directories:

```bash
glib-compile-schemas vnc-client-adwaita/data/
cargo build -p vnc-client-adwaita
GSETTINGS_SCHEMA_DIR=vnc-client-adwaita/data \
  VNC_LOCALE_DIR=vnc-client-adwaita/locale \
  cargo run -p vnc-client-adwaita
```

See `vnc-client-adwaita/README.md` for system-wide installation and Arch Linux
packaging instructions.

## vnc-client-android

Android integration scaffold for `vnc-client`.

- [x] Re-exports the core `VncClient` API
- [x] `AndroidVncDisplay` connection helper with password / Apple Remote Desktop auth callbacks
- [x] OpenGL ES 3 + EGL renderer with VAO, persistent texture, and surface-size detection
- [x] Background read/render loop (`vnc_display_start_loop` / `vnc_display_stop_loop`)
- [x] C ABI exports for connection, surface, input, and keyboard events
- [ ] JNI bindings and Java/Kotlin lifecycle helpers
- [ ] Touch-to-mouse gesture mapping
- [ ] `MediaCodec` hardware decoding (scaffolding present; needs SPS/PPS plumbing)

## Development Plan

### Phase 1: Framework
- [x] Workspace and crate layout
- [x] Basic VNC client connection and handshake
- [x] Raw encoding and GTK4 widget shell
- [x] Input event forwarding

### Phase 2: Core Protocol
- [x] Wire ZRLE and Hextile into `handle_framebuffer_update`
- [ ] Zlib encoding support
- [ ] Complete VeNCrypt stream encryption
- [ ] Clipboard integration end-to-end in the GTK4 widget (server-side support is present; widget UI is not wired)

### Phase 3: Performance
- [ ] GPU texture upload via dmabuf/GL on supported platforms
- [ ] Dirty region tracking
- [ ] Adaptive quality and threaded decode

### Phase 4: Polish
- [ ] Touch/gesture support
- [ ] Fullscreen mode and toolbar overlay
- [x] Connection dialog and password prompt (provided by `vnc-client-adwaita`)
- [ ] Reconnection and error handling

## Apple High-Performance Mode

`vnc-client` has a partial implementation of Apple's macOS Screen Sharing
high-performance extension. See [`vnc-client/APPLE_HP.md`](vnc-client/APPLE_HP.md)
for the protocol details and current completion checklist.

## References

- [neatvnc](https://github.com/any1/neatvnc) - VNC server library reference
- [gst-plugins-rs](https://gitlab.freedesktop.org/gstreamer/gst-plugins-rs) - GStreamer GTK4 Sink & Paintable reference
- [RFB Protocol](https://vncdotool.readthedocs.io/en/0.8.0/rfbproto.html) - Protocol specification

## License

MIT OR Apache-2.0
