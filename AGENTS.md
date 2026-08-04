# OpenClaw Agent Guide

This document is a concise, accurate reference for AI coding agents working on the
OpenClaw repository. Read this first when you are about to change code, add
features, or debug tests.

## Project Overview

OpenClaw is a Rust workspace that implements VNC client and server libraries using
the RFB (Remote Framebuffer) protocol, plus display widgets and desktop/Android
applications built on top of them.

- **Core client crate**: `vnc-client` — platform-agnostic VNC client library.
- **GTK4 widget**: `vnc-widget-gtk4` — `VncDisplay` / `VncPaintable` for GTK4
  applications.
- **Adwaita client**: `vnc-client-adwaita` — desktop VNC client using
  libadwaita, with GSettings-backed preferences.
- **Android scaffold**: `vnc-client-android` — OpenGL ES 3 renderer + JNI
  exports for Android.
- **Server crate**: `vnc-server` — pure Rust Wayland VNC server (RFB 3.8,
  wlr-screencopy, virtual input, clipboard sync, control socket).

License: MIT OR Apache-2.0. Rust edition: 2021. Workspace minimum Rust version: 1.92.

## Technology Stack

| Layer | Technology |
|-------|------------|
| Language | Rust (edition 2021, rust-version 1.92) |
| Build system | Cargo workspace (`resolver = "2"`) |
| Error handling | `thiserror` |
| Logging | `log`, `env_logger` |
| Compression | `flate2` (zlib) |
| Cryptography | `rustls`, `rsa`, `aes`, `ctr`, `des`, `sha2`, `sha1`, `hmac`, `pbkdf2`, `md5`, `cbc`, `ecb`, `rand` |
| VNC auth | `sasl` (SCRAM/PLAIN), custom DES challenge-response |
| WebSocket | `tungstenite` |
| JPEG decode | `jpeg-decoder` |
| H.264 decode (Linux) | `gstreamer`, `gstreamer-app`, `gstreamer-video` |
| H.264 decode (Android) | `ndk` (MediaCodec) |
| GTK4 | `gtk4` 0.11, `gdk4` 0.11, `glib` 0.22, `gio` 0.22, `graphene-rs` 0.22 |
| libadwaita | `libadwaita` 0.9 |
| Android | `ndk` 0.9, `ndk-sys` 0.6, EGL/GLESv3 via raw FFI |
| Wayland server | `wayland-client` 0.31, `wayland-protocols-wlr` 0.3, `evdev`, `nix` |
| OpenGL | libepoxy on GTK4; `EGL`/`GLESv3` on Android |

## Repository Structure

```
openclaw/
├── Cargo.toml                  # Workspace definition
├── Cargo.lock
├── README.md                   # User-facing overview and examples
├── VNC_SERVER_IMPLEMENTATION.md # vnc-server implementation status
├── vnc-client/
│   ├── Cargo.toml
│   ├── WAYVNC_COMPAT.md        # wayvnc/neatvnc feature matrix
│   ├── APPLE_HP.md             # Apple High-Performance VNC protocol notes
│   ├── reference/              # External reference materials (Apple HP spec + iShareScreen client)
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
│       ├── zlib.rs              # Zlib encoding decoder
│       ├── zrle.rs              # ZRLE decoder
│       ├── apple_dh.rs          # Apple Diffie-Hellman auth
│       ├── apple_srp.rs         # Apple HP SRP auth
│       ├── apple_record_layer.rs # Apple HP encrypted record layer
│       ├── stats.rs             # ConnectionStats transfer/encoding statistics
│       └── decoder/
│           ├── mod.rs           # VideoDecoder trait + DefaultDecoder alias
│           ├── gstreamer.rs     # Linux GStreamer H.264 decoder
│           └── android.rs       # Android MediaCodec H.264 decoder
├── vnc-widget-gtk4/
│   ├── Cargo.toml
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
│   │   └── icons/hicolor/64x64/apps/com.weiz.vnc-client-adwaita.svg
│   ├── po/                      # gettext translations (en, zh_CN)
│   └── src/
│       └── main.rs              # AdwApplication + VncDisplay window + gettext setup
├── vnc-client-android/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs               # AndroidVncDisplay + C ABI exports
│       └── renderer.rs          # OpenGL ES 3 / EGL renderer
└── vnc-server/
    ├── Cargo.toml
    ├── PLAN.md                  # Original Chinese development plan
    ├── src/
    │   ├── main.rs              # Binary entry point, CLI, event loop
    │   ├── lib.rs               # Module exports
    │   ├── auth.rs              # VNC password (DES challenge-response)
    │   ├── clipboard.rs         # Wayland clipboard sync
    │   ├── config.rs            # Config file + CLI parsing
    │   ├── control.rs           # Unix-socket control interface (JSON)
    │   ├── damage.rs             # Tile-based damage tracking
    │   ├── signal.rs             # Ctrl-C signal handling
    │   ├── server/
    │   │   ├── mod.rs
    │   │   ├── listener.rs      # TcpListener and accept loop
    │   │   └── client.rs        # Per-client RFB state machine
    │   ├── protocol/
    │   │   └── mod.rs           # RFB message types, pixel format, encodings
    │   ├── encode/
    │   │   ├── mod.rs
    │   │   ├── raw.rs           # Raw encoder
    │   │   ├── hextile.rs       # Hextile encoder
    │   │   ├── tight.rs         # Tight encoder
    │   │   └── zrle.rs         # ZRLE encoder
    │   └── wayland/
    │       ├── mod.rs           # Wayland state + registry
    │       ├── wayland_ctx.rs   # Connection and global discovery
    │       ├── capture.rs       # CaptureManager + SHM frame buffers
    │       ├── screencopy.rs    # wlr-screencopy dispatch
    │       ├── input.rs         # zwlr-virtual-pointer
    │       └── keyboard.rs      # uinput/evdev virtual keyboard
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

### VNC server

The server is a pure Rust implementation; it inherits workspace package fields
from `Cargo.toml` and has its own Wayland/input dependencies.

```bash
# Check
cargo check -p vnc-server

# Build
cargo build -p vnc-server

# Run (requires a Wayland compositor with wlr-screencopy and a seat)
cargo run -p vnc-server
```

Runtime CLI options include `-a/--address`, `-p/--port`, `-n/--name`,
`-r/--max-rate`, `-d/--display`, `-o/--output`, `-c/--config`,
`--disable-input`, and `--overlay-cursor`. Defaults to `127.0.0.1:5900` at
30 fps.

## Test Commands

```bash
# Formatting check (enforced in CI)
cargo fmt --check

# Core library unit + doc tests + clippy
cargo test -p vnc-client --all-features
cargo clippy -p vnc-client --all-features -- -D warnings

# GTK4 library tests (skip examples, which need a display)
cargo test -p vnc-widget-gtk4 --all-features --lib
cargo clippy -p vnc-widget-gtk4 --all-features -- -D warnings

# VNC server
cargo check -p vnc-server
cargo clippy -p vnc-server --all-features -- -D warnings

# All tests in the workspace (requires GTK4 + GStreamer system deps)
cargo test --all-features
```

As of the current tree, only `vnc-client` contains meaningful unit tests. The
GTK4, Android, and server crates are mostly integration code without standalone
unit tests.

## Code Organization and Architecture

### `vnc-client` (core library)

- `VncClient` in `src/lib.rs` is the main state machine. It manages a
  `VncStream`, handshake state, framebuffer, encodings, and H.264 decoder.
  When Apple High-Performance mode is negotiated, the stream is wrapped in
  `AppleRecordLayer` from `apple_record_layer.rs` for message framing and
  per-record AES-GCM encryption.
- `VncStream` wraps `TcpStream`, `TlsStream`, `AesCtrStream`, `WsStream`, and
  `AppleRecordLayer` behind a common `Read + Write` interface and tracks bytes
  read and written for transfer-speed statistics.
- `ConnectionStats` in `src/stats.rs` exposes encoding, resolution, FPS, and
  transfer speed. It is sampled by `VncClient::stats()` and can be consumed by
  any platform UI (GTK4, Android, etc.).
- Lifecycle: `new()` / `VncClientBuilder::build()` →
  `connect()`/`connect_tls()`/`connect_ws()` → `handshake(auth)` →
  `read_messages()` loop + input methods.
- `VncClientBuilder` provides a fluent configuration API; default encodings are
  set to Tight, ZRLE, Hextile, Zlib, Raw, CopyRect, TRLE, OpenH264, and common
  pseudo-encodings.
- Encodings are dispatched in `handle_framebuffer_update` by their numeric
  RFB value (`Raw=0`, `CopyRect=1`, `RRE=2`, `Hextile=5`, `Zlib=6`,
  `Tight=7`, `TRLE=15`, `ZRLE=16`, `OpenH264=50`, etc.).
- Pseudo-encodings handled include `DesktopSize`, `DesktopName`, `Cursor`,
  `CursorPos`, `ExtendedDesktopSize`, `ExtendedClipboard`, `Fence`,
  `ContinuousUpdates`, `JpegQuality`, and `AppleHp`.
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
- Input: motion, gesture-click, key-event, and scroll controllers translate GTK
  events into `InputEvent` values sent to the background thread.
- The example currently hardcodes `NoAuthHandler` and connects with `Zrle`,
  `Hextile`, `Raw`, `CopyRect`, and `DesktopSize`.

### `vnc-client-adwaita`

- `main.rs` creates an `AdwApplication` with a main window that embeds the
  `VncDisplay` widget from `vnc-widget-gtk4`.
- A connect dialog lets the user enter the host, port, username, and password,
  toggle TLS, and start or stop the connection. Passwords are not persisted;
  other settings are bound to GSettings (`host`, `port`, `username`, `auth-method`,
  `use-tls`, `preferred-encoding`, `view-only`, `scale-to-fit`).
- `VncDisplay` exposes `connect_with_options` for supplying an authentication
  handler and encoding list, and `set_view_only` to suppress local input events.
- A `AdwPreferencesWindow` exposes the same settings.

### `vnc-client-android`

- `AndroidVncDisplay` wraps `VncClient` and an `EglRenderer`.
- `EglRenderer` creates an EGL + OpenGL ES 3 context from a `NativeWindow`,
  uploads RGBA frames to a 2D texture, and draws a fullscreen quad.
- C ABI exports (`vnc_display_create`, `vnc_display_connect`, etc.) are the
  intended JNI boundary. Java/Kotlin bindings are not yet written.

### `vnc-server`

- `main.rs` runs a single-threaded event loop: accept TCP clients, dispatch
  Wayland events, capture frames, encode damaged regions, and send framebuffer
  updates.
- `server/client.rs` implements the per-client RFB state machine from version
  exchange through `Ready`.
- `wayland/capture.rs` manages `wlr-screencopy-unstable-v1` captures into SHM
  buffers backed by `memfd_create` + `mmap`.
- `encode/` provides Raw, Hextile, Tight, and ZRLE encoders; the server chooses
  the best encoder the client has advertised.
- `damage.rs` tracks tile-based (64x64) damage and falls back to full damage
  when a client requests a full update.
- `control.rs` binds a Unix domain socket and accepts JSON commands such as
  `status`, `disconnect-client`, `set-output`, `reload-config`, `set-password`,
  and `set-rate`.
- `clipboard.rs` syncs clipboard between Wayland (`wlr-data-control`) and VNC
  clients (`ClientCutText` / `ServerCutText`).
- `input.rs` and `keyboard.rs` forward VNC pointer and key events to the
  Wayland compositor via `zwlr-virtual-pointer-v1` and `uinput`/`evdev`.
- Supported server-side encodings: Raw, Hextile, Tight, ZRLE, DesktopSize,
  ExtendedDesktopSize, ExtendedClipboard, ContinuousUpdates, Fence. CopyRect,
  RRE, TRLE, and Cursor are not yet implemented.
- Supported security types: `None` and VNC password (DES challenge-response).
  TLS, VeNCrypt, and RSA-AES are not yet implemented.

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
    `hextile.rs`, `trle.rs`, `rre.rs`, `zlib.rs`.
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
  implementation is in `auth.rs` (client) and `vnc-server/src/auth.rs` (server);
  treat it as a legacy compatibility mechanism, not a strong authentication
  method.
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
- The `vnc-server` control socket is a Unix domain socket with no authentication
  beyond filesystem permissions. Keep it in a private runtime directory such
  as `$XDG_RUNTIME_DIR`.

## Deployment and Release Process

- There is no automated release workflow yet. The project is at version
  `0.1.0` for all workspace crates.
- The `.github/workflows/ci.yml` runs on push/PR to `main` and builds/tests
  three crates independently:
  1. `vnc-client` build + test
  2. `vnc-widget-gtk4` build + lib tests
  3. `vnc-client-android` cross-compile check with `cargo-ndk`
- `vnc-server` is not currently exercised in CI; verify it manually with
  `cargo check -p vnc-server` and `cargo build -p vnc-server`.
- Before submitting a PR, verify:
  - `cargo fmt --check` passes
  - `cargo clippy --all-features` is clean for the crates you changed
  - `cargo test -p vnc-client` passes
  - `cargo build -p vnc-widget-gtk4 --all-features` passes if you have GTK4
    system deps installed
  - `cargo check -p vnc-server` passes if you changed the server
- The Android crate is compiled as `cdylib` + `staticlib` and is intended to be
  linked into an Android app via JNI. No packaging or publishing automation is in
  place.
- The adwaita client includes a `PKGBUILD` and `.desktop` generation for Arch
  Linux packaging, but packaging is not automated in CI.

## Platform Notes

### Linux / GTK4
- Requires GTK4 development headers, GStreamer development headers, and
  libepoxy. The CI uses `ubuntu-latest` with the packages listed above.
- `VncPaintable` uses `libepoxy` GL symbols directly. If you change the GL path,
  you may need to add more `extern "C"` declarations.

### Linux / Wayland server (`vnc-server`)
- Requires a Wayland compositor that exposes `wlr-screencopy-unstable-v1`,
  `wl_output`, `wl_seat`, and (for input) `zwlr-virtual-pointer-v1`.
- Virtual keyboard uses `uinput`/`evdev` and requires appropriate permissions;
  the server logs a warning if it cannot be created.
- Clipboard sync requires `zwlr-data-control-v1`.
- The default address is `127.0.0.1:5900`; use `-a 0.0.0.0` to listen on all
  interfaces.

### Android
- Build only with `cargo-ndk`; plain `cargo build` for `vnc-client-android`
  will fail because it expects an Android NDK toolchain.
- The renderer expects OpenGL ES 3 and EGL. It does not handle runtime
  gracefully when these are unavailable.
- MediaCodec requires valid H.264 SPS/PPS before the first IDR frame. The
  OpenH264 VNC encoding path is experimental.

## Common Tasks

### Add a new client encoding

1. Add the variant to `vnc-client/src/encodings.rs` and wire it to the correct
   RFB integer in `Encoding::as_i32`.
2. Add a decoder module under `vnc-client/src/` (e.g. `my_encoding.rs`).
3. Add the case in `VncClient::handle_framebuffer_update` in `src/lib.rs`.
4. Include it in `VncClientBuilder::new()` defaults if appropriate.
5. Add unit tests in the decoder module.

### Add a new server encoding

1. Add the encoder module under `vnc-server/src/encode/` and export it from
   `encode/mod.rs`.
2. Add the encoding constant to `vnc-server/src/protocol/mod.rs`.
3. Wire the encoder into the client update loop in `vnc-server/src/main.rs`,
   similar to the existing `use_tight`/`use_zrle`/`use_hextile` branches.
4. Advertise the encoding in `vnc-server/src/server/client.rs` if clients
   should negotiate it.

### Add a GTK4 feature or input gesture

1. Add the controller in `VncDisplayImp::constructed()` in
   `vnc-widget-gtk4/src/widget.rs`.
2. Extend `InputEvent` if the event needs to reach the background thread.
3. Handle the event in the background thread loop.
4. Keep the GTK4-side code single-threaded and the VNC thread isolated from
   GTK objects.

### Update the RFB protocol version or security type

- Modify `vnc-client/src/protocol.rs` or `vnc-server/src/protocol/mod.rs` for
  constants.
- Modify `VncClient::handshake_version` or `auth.rs` / `vencrypt.rs` /
  `apple_srp.rs` (client) or `vnc-server/src/server/client.rs` (server) for
  security handling.
- Update `README.md` and `WAYVNC_COMPAT.md` (and `APPLE_HP.md` for Apple HP
  changes) if behavior changes.

### Update translations in the adwaita client

1. Add translatable strings to source files as usual; mark them with `gettext()`.
2. Update `vnc-client-adwaita/po/POTFILES.in` if new source files contain
   translatable strings.
3. Regenerate `messages.pot` and update `.po` files with the standard gettext
   tooling.
4. `build.rs` compiles `.po` files into `vnc-client-adwaita/locale/*.mo` during
   `cargo build`.

## References

- `README.md` — user-facing overview, feature checklist, and roadmap.
- `VNC_SERVER_IMPLEMENTATION.md` — current server implementation status and
  design decisions.
- `vnc-client/WAYVNC_COMPAT.md` — wayvnc/neatvnc client compatibility matrix.
- `vnc-client/APPLE_HP.md` — Apple High-Performance VNC protocol notes.
- `vnc-server/PLAN.md` — original server development plan (Chinese).
- RFB protocol reference: https://vncdotool.readthedocs.io/en/0.8.0/rfbproto.html
