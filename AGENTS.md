# OpenClaw Agent Guide

This document is a concise, accurate reference for AI coding agents working on the
OpenClaw repository. Read this first when you are about to change code, add
features, or debug tests.

## Project Overview

OpenClaw is a Rust workspace that implements a VNC client library and display
widgets using the RFB (Remote Framebuffer) protocol.

- **Core crate**: `vnc-client` — platform-agnostic VNC client library.
- **GTK4 widget**: `vnc-widget-gtk4` — `VncDisplay` / `VncPaintable` for GTK4
  applications.
- **Adwaita client**: `vnc-client-adwaita` — desktop VNC client using
  libadwaita, with GSettings-backed preferences.
- **Android scaffold**: `vnc-client-android` — OpenGL ES 3 renderer + JNI
  exports for Android.

License: MIT OR Apache-2.0. Rust edition: 2021. Minimum Rust version: 1.80.

## Technology Stack

| Layer | Technology |
|-------|------------|
| Language | Rust (edition 2021, rust-version 1.80) |
| Build system | Cargo workspace (`resolver = "2"`) |
| Error handling | `thiserror` |
| Logging | `log` |
| Compression | `flate2` (zlib) |
| Cryptography | `rustls`, `rsa`, `aes`, `ctr`, `des`, `sha2`, `rand` |
| VNC auth | `sasl` (SCRAM/PLAIN), custom DES challenge-response |
| WebSocket | `tungstenite` |
| JPEG decode | `jpeg-decoder` |
| H.264 decode (Linux) | `gstreamer`, `gstreamer-app` |
| H.264 decode (Android) | `ndk` (MediaCodec) |
| GTK4 | `gtk4` 0.9, `gdk4` 0.9, `glib` 0.20, `graphene-rs` 0.20 |
| Android rendering | `ndk`, `ndk-sys`, EGL/GLESv3 via raw FFI |
| OpenGL | libepoxy on GTK4; `EGL`/`GLESv3` on Android |

## Repository Structure

```
openclaw/
├── Cargo.toml                  # Workspace definition
├── Cargo.lock
├── README.md                   # User-facing overview and examples
├── vnc-client/
│   ├── Cargo.toml
│   ├── WAYVNC_COMPAT.md        # wayvnc/neatvnc feature matrix
│   ├── examples/vnc_viewer.rs
│   └── src/
│       ├── lib.rs              # VncClient, VncClientBuilder, VncStream, VncEvent
│       ├── auth.rs             # AuthHandler, NoAuthHandler, PasswordAuthHandler
│       ├── clipboard.rs         # Extended-clipboard encode/decode
│       ├── cursor.rs            # CursorShape decode
│       ├── encodings.rs         # RFB encoding enum / wire values
│       ├── framebuffer.rs       # Framebuffer, PixelFormat, Transform
│       ├── hextile.rs           # Hextile decoder
│       ├── protocol.rs          # RFB message constants
│       ├── rre.rs               # RRE decoder
│       ├── rsa_aes.rs           # RSA-AES auth + AES-CTR stream
│       ├── sasl.rs              # SASL auth for VeNCrypt
│       ├── tight.rs             # Tight decoder (Fill, JPEG, Basic Copy/Palette/Gradient)
│       ├── tls.rs               # rustls TLS stream wrapper
│       ├── trle.rs              # TRLE decoder
│       ├── vencrypt.rs          # VeNCrypt negotiation
│       ├── ws.rs                # WebSocket stream wrapper
│       ├── zrle.rs              # ZRLE decoder
│       ├── apple_dh.rs          # Apple Diffie-Hellman auth
│       └── decoder/
│           ├── mod.rs           # VideoDecoder trait + DefaultDecoder alias
│           ├── gstreamer.rs     # Linux GStreamer H.264 decoder
│           └── android.rs       # Android MediaCodec H.264 decoder
├── vnc-widget-gtk4/
│   ├── Cargo.toml
│   ├── examples/gtk4_vnc_viewer.rs
│   └── src/
│       ├── lib.rs               # Re-exports VncPaintable, VncDisplay
│       ├── paintable.rs         # GdkPaintable + GL texture upload
│       └── widget.rs            # VncDisplay GTK4 widget + background thread
├── vnc-client-adwaita/
│   ├── Cargo.toml
│   ├── README.md
│   ├── PKGBUILD
│   ├── .SRCINFO
│   ├── build.rs                 # Compiles po/*.po to locale/*.mo and desktop.in to .desktop
│   ├── data/
│   │   ├── com.weiz.vnc-client-adwaita.desktop.in
│   │   ├── com.weiz.vnc-client-adwaita.gschema.xml
│   │   └── icons/
│   │       └── hicolor/
│   │           └── 64x64/
│   │               └── apps/
│   │                   └── com.weiz.vnc-client-adwaita.svg
│   ├── po/
│   │   ├── LINGUAS              # Supported languages
│   │   ├── POTFILES.in          # Source files with translatable strings
│   │   ├── messages.pot         # Translation template
│   │   ├── en.po                # English strings
│   │   └── zh_CN.po             # Simplified Chinese strings
│   └── src/
│       └── main.rs              # AdwApplication + VncDisplay window + gettext setup
└── vnc-client-android/
    ├── Cargo.toml
    └── src/
        ├── lib.rs               # AndroidVncDisplay + C ABI exports
        └── renderer.rs          # OpenGL ES 3 / EGL renderer
```

## Build Commands

All commands are intended to be run from the repository root unless otherwise
noted.

### Core library

```bash
# Check
cargo check -p vnc-client

# Build
cargo build -p vnc-client

# Build with all features (no extra Cargo features are defined, but this is
# the command used in CI)
cargo build -p vnc-client --all-features
```

### GTK4 widget

Requires system packages: `libgtk-4-dev`, `libgstreamer1.0-dev`,
`libgstreamer-plugins-base1.0-dev`, `libepoxy-dev`.

```bash
# On Debian/Ubuntu
sudo apt-get install -y libgtk-4-dev libgstreamer1.0-dev \
  libgstreamer-plugins-base1.0-dev libepoxy-dev

# Build
cargo check -p vnc-widget-gtk4
cargo build -p vnc-widget-gtk4 --all-features

# Run the example viewer
cargo run --example gtk4_vnc_viewer -p vnc-widget-gtk4
```

### Adwaita client

Requires the GTK4 widget dependencies plus `libadwaita-1-dev` and `gettext`.

```bash
# On Debian/Ubuntu
sudo apt-get install -y libadwaita-1-dev gettext

# Compile the GSettings schema
glib-compile-schemas vnc-client-adwaita/data/

# Build (this also compiles po/*.po and generates the .desktop file)
cargo build -p vnc-client-adwaita --all-features

# Run with local schema and locale directories
GSETTINGS_SCHEMA_DIR=vnc-client-adwaita/data \
  VNC_LOCALE_DIR=vnc-client-adwaita/locale \
  cargo run -p vnc-client-adwaita
```

### Android library

Requires the Android NDK and the `cargo-ndk` helper.

```bash
# Install cargo-ndk
cargo install cargo-ndk

# Target aarch64 Android API 30
cargo ndk --target aarch64-linux-android --platform 30 check -p vnc-client
cargo ndk --target aarch64-linux-android --platform 30 check -p vnc-client-android
```

The CI currently installs NDK r25c via `nttld/setup-ndk@v1` and uses the
`aarch64-linux-android` target.

## Test Commands

```bash
# Core library unit + doc tests
cargo test -p vnc-client

# GTK4 library tests (skip examples, which need a display)
cargo test -p vnc-widget-gtk4 --all-features --lib

# All tests in the workspace (requires GTK4 + GStreamer system deps)
cargo test --all-features
```

As of the current tree, only `vnc-client` contains meaningful tests. The GTK4
and Android crates are mostly integration code without standalone unit tests.

## Code Organization and Architecture

### `vnc-client` (core library)

- `VncClient` in `src/lib.rs` is the main state machine. It manages a
  `VncStream`, handshake state, framebuffer, encodings, and H.264 decoder.
- `VncStream` wraps `TcpStream`, `TlsStream`, `AesCfbStream`, and
  `WsStream` behind a common `Read + Write` interface and tracks bytes read
  and written for transfer-speed statistics.
- `ConnectionStats` in `src/stats.rs` exposes encoding, resolution, FPS, and
  transfer speed. It is sampled by `VncClient::stats()` and can be consumed by
  any platform UI (GTK4, Android, etc.).
- Lifecycle: `new()` → `connect()`/`connect_tls()`/`connect_ws()` →
  `handshake(auth)` → `read_messages()` loop + input methods.
- `VncClientBuilder` provides a fluent configuration API; default encodings are
  set to Tight, ZRLE, Hextile, Raw, CopyRect, TRLE, OpenH264, and common
  pseudo-encodings.
- Encodings are dispatched in `handle_framebuffer_update` by their numeric
  RFB value (`Raw=0`, `CopyRect=1`, `RRE=2`, `Hextile=5`, `Tight=6`,
  `TRLE=15`, `ZRLE=16`, `OpenH264=50`, etc.).
- Pseudo-encodings handled include `DesktopSize`, `DesktopName`, `Cursor`,
  `CursorPos`, `ExtendedDesktopSize`, `ExtendedClipboard`, `Fence`, and
  `ContinuousUpdates`.
- Framebuffer is always stored as RGBA8888. `PixelFormat::to_rgba` converts
  server pixels to RGBA. `Framebuffer::write_region` has a fast path when the
  server already sends RGBA little-endian.
- `decoder` is a trait-based abstraction for H.264 decoding. On Linux the default
  is `GStreamerDecoder`; on Android it is `MediaCodecDecoder`.

### `vnc-widget-gtk4`

- `VncPaintable` is a `GdkPaintable` that uploads RGBA pixels to a GL texture
  via `GdkGLTextureBuilder` (libepoxy) and falls back to `GdkMemoryTexture`.
- `VncDisplay` is a `GtkWidget` subclass that owns a background thread:
  - Thread: connects, runs the VNC message loop, forwards input events from
    an `mpsc` channel, and pushes `FrameData` + `CursorShape` into shared
    `Mutex<Vec<_>>` queues.
  - UI: a `glib::timeout_add_local` (~60 Hz) drains the queues and updates the
    paintable.
- Input: motion, gesture-click, and key-event controllers translate GTK events
  into `InputEvent` values sent to the background thread.
- The example currently hardcodes `NoAuthHandler` and connects with `Zrle`,
  `Hextile`, `Raw`, `CopyRect`, and `DesktopSize`.

### `vnc-client-adwaita`

- `main.rs` creates an `AdwApplication` with a main window that embeds the
  `VncDisplay` widget from `vnc-widget-gtk4`.
- A toolbar lets the user enter the host, port, and password, and start or stop
  the connection. Passwords are not persisted; other settings are bound to
  GSettings (`host`, `port`, `username`, `auth-method`, `preferred-encoding`,
  `view-only`, `scale-to-fit`).
- `VncDisplay` exposes `connect_with_options` for supplying an authentication
  handler and encoding list, and `set_view_only` to suppress local input events.
- A `AdwPreferencesWindow` exposes the same settings.

### `vnc-client-android`

- `AndroidVncDisplay` wraps `VncClient` and an `EglRenderer`.
- `EglRenderer` creates an EGL + OpenGL ES 3 context from a `NativeWindow`,
  uploads RGBA frames to a 2D texture, and draws a fullscreen quad.
- C ABI exports (`vnc_display_create`, `vnc_display_connect`, etc.) are the
  intended JNI boundary. Java/Kotlin bindings are not yet written.

## Code Style and Conventions

- Follow the Rust style used in the existing code. The project does not use a
  custom `rustfmt` config; rely on `cargo fmt` defaults.
- Run `cargo fmt` before committing. Run `cargo clippy` to catch common issues.
- Keep `unsafe` blocks minimal and clearly documented with `// Safety:` comments.
- Use `thiserror` for error types. Avoid introducing new error crates.
- Module-level doc comments (`//!`) are used heavily in `lib.rs`, `ws.rs`,
  `decoder/android.rs`, `renderer.rs`, etc. Match that style for new modules.
- Naming:
  - RFB encoding modules are lowercase one-word files: `zrle.rs`, `tight.rs`,
    `hextile.rs`, `trle.rs`, `rre.rs`.
  - GTK4 types use PascalCase: `VncDisplay`, `VncPaintable`.
  - Android C ABI exports use `snake_case` and the `vnc_display_*` prefix.
- The project uses `log` for diagnostics, not `eprintln`, except for transient
  example/tool output. Prefer `log::debug!` / `log::warn!` in library code.
- Do not add `unwrap()` or `expect()` in production paths without a comment.
  Existing code uses `?` and `Result` propagation consistently.
- Be cautious with `gtk4`/`gdk4`/`glib` object lifetimes and weak references
  when modifying the GTK4 widget. The background thread must not hold strong
  references to GTK objects.

## Testing Guidelines

- Unit tests live in `#[cfg(test)] mod tests` inside each module.
- Encoding tests typically build a small synthetic byte stream (often using
  `Cursor` or `ZlibEncoder`) and assert framebuffer contents.
- When you change an encoding decoder, add a regression test that exercises
  the exact byte sequence you are fixing.
- Doc tests are present in `lib.rs` for `VncClient`, `VncClientBuilder`, and
  public methods. Keep them passing; they run as part of `cargo test`.
- The GTK4 crate requires a display and cannot be fully exercised in headless
  CI; use `--lib` to run only library tests.
- There are no integration tests yet; the `examples/` are the closest thing to
  end-to-end validation.

## Security Considerations

- TLS is implemented via `rustls` with `webpki-roots`. Hostname verification
  depends on `set_host()` being called before the TLS upgrade. If you add a
  public connect helper, make sure the hostname is set correctly.
- VNC password authentication uses a non-standard DES challenge-response. The
  implementation is in `auth.rs`; treat it as a legacy compatibility mechanism,
  not a strong authentication method.
- RSA-AES, RSA-AES-256, and Apple DH use AES-128-CTR for the stream. The
  256-bit variants truncate the derived key to 16 bytes for AES-128. This is
  noted in the code and in `WAYVNC_COMPAT.md`.
- WebSocket traffic is wrapped in `tungstenite` binary messages. Be aware that
  `WsStream` coalesces writes until `flush()`; this is a transport detail, not a
  security feature.
- The GTK4 example currently uses `NoAuthHandler` and connects to any host.
  Do not ship this example as-is without authentication.
- Clipboard and audio extensions parse server-provided byte lengths. Keep
  bounds checks in place to avoid out-of-bounds reads.

## Deployment and Release Process

- There is no automated release workflow yet. The project is at version
  `0.1.0` for all workspace crates.
- The `.github/workflows/ci.yml` runs on push/PR to `main` and builds/tests
  each crate independently:
  1. `vnc-client` build + test
  2. `vnc-widget-gtk4` build + lib tests
  3. `vnc-client-android` cross-compile check with `cargo-ndk`
- Before submitting a PR, verify:
  - `cargo fmt --check` passes
  - `cargo clippy --all-features` is clean for the crates you changed
  - `cargo test -p vnc-client` passes
  - `cargo build -p vnc-widget-gtk4 --all-features` passes if you have GTK4
    system deps installed
- The Android crate is compiled as `cdylib` + `staticlib` and is intended to be
  linked into an Android app via JNI. No packaging or publishing automation is in
  place.

## Platform Notes

### Linux / GTK4
- Requires GTK4 development headers, GStreamer development headers, and
  libepoxy. The CI uses `ubuntu-latest` with the packages listed above.
- `VncPaintable` uses `libepoxy` GL symbols directly. If you change the GL path,
  you may need to add more `extern "C"` declarations.

### Android
- Build only with `cargo-ndk`; plain `cargo build` for `vnc-client-android`
  will fail because it expects an Android NDK toolchain.
- The renderer expects OpenGL ES 3 and EGL. It does not handle runtime
  gracefully when these are unavailable.
- MediaCodec requires valid H.264 SPS/PPS before the first IDR frame. The
  OpenH264 VNC encoding path is experimental.

## Common Tasks

### Add a new encoding

1. Add the variant to `vnc-client/src/encodings.rs` and wire it to the correct
   RFB integer in `Encoding::as_i32`.
2. Add a decoder module under `vnc-client/src/` (e.g. `my_encoding.rs`).
3. Add the case in `VncClient::handle_framebuffer_update` in `src/lib.rs`.
4. Include it in `VncClientBuilder::new()` defaults if appropriate.
5. Add unit tests in the decoder module.

### Add a GTK4 feature or input gesture

1. Add the controller in `VncDisplayImp::constructed()` in
   `vnc-widget-gtk4/src/widget.rs`.
2. Extend `InputEvent` if the event needs to reach the background thread.
3. Handle the event in the background thread loop.
4. Keep the GTK4-side code single-threaded and the VNC thread isolated from
   GTK objects.

### Update the RFB protocol version or security type

- Modify `vnc-client/src/protocol.rs` for constants.
- Modify `VncClient::handshake_version` or `auth.rs` / `vencrypt.rs` for
  security handling.
- Update `README.md` and `WAYVNC_COMPAT.md` if behavior changes.

## References

- `README.md` — user-facing overview, feature checklist, and roadmap.
- `vnc-client/WAYVNC_COMPAT.md` — wayvnc/neatvnc compatibility matrix.
- RFB protocol reference: https://vncdotool.readthedocs.io/en/0.8.0/rfbproto.html
