# OpenClaw

A Rust VNC client library and display widgets implementing the RFB protocol.

## Architecture

```
openclaw/
├── vnc-client/         # Core VNC client library (RFB protocol)
├── vnc-widget-gtk4/    # GTK4 display widget
├── vnc-client-adwaita/ # Adwaita GTK4 desktop VNC client
└── vnc-client-android/ # Android display scaffold
```

## vnc-client

Pure Rust VNC client library implementing the RFB protocol.

### Features

- [x] TCP and TLS connection management
- [x] RFB protocol handshake (version 3.3, 3.7, 3.8)
- [x] Authentication: None, VNC password (DES challenge-response)
- [x] Framebuffer encodings: Raw, CopyRect, RRE, TRLE, Hextile, ZRLE, Tight
- [x] Input events: pointer and keyboard
- [x] Clipboard: legacy cut text and extended-clipboard provide/request
- [x] Continuous updates and `EndOfContinuousUpdates`
- [x] Cursor pseudo-encoding and desktop-size pseudo-encodings
- [ ] Zlib encoding
- [ ] VeNCrypt stream encryption (subtypes negotiate; TLS/X509 not wired, RSA-AES/AES-256 handshakes but does not encrypt the stream)
- [ ] OpenH264/decoder hardware paths on Android

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

### Example

Run the GTK4 viewer:

```bash
cargo run --example gtk4_vnc_viewer -p vnc-widget-gtk4
```

## vnc-client-adwaita

Desktop VNC client using **libadwaita** / GTK4 and GSettings.

### Features

- [x] Adwaita-style GTK4 UI (header bar, toast overlay, preferences dialog)
- [x] Reuses `VncDisplay` from `vnc-widget-gtk4` for remote framebuffer rendering
- [x] Supports **no authentication** and **VNC password authentication**
- [x] Settings persisted to GSettings:
  - host, port, username, auth method
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
- [x] `AndroidVncDisplay` connection helper
- [ ] JNI bindings and `Surface`/`ANativeWindow` rendering
- [ ] Touch-to-mouse mapping
- [ ] `MediaCodec` hardware decoding

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

## References

- [neatvnc](https://github.com/any1/neatvnc) - VNC server library reference
- [gst-plugins-rs](https://gitlab.freedesktop.org/gstreamer/gst-plugins-rs) - GStreamer GTK4 Sink & Paintable reference
- [RFB Protocol](https://vncdotool.readthedocs.io/en/0.8.0/rfbproto.html) - Protocol specification

## License

MIT OR Apache-2.0
