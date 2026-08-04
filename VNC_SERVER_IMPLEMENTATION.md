# VNC Server Implementation Document

## Overview

This document tracks the implementation of a VNC server in Rust, based on the RFB (Remote Framebuffer) protocol version 3.8. The implementation references `neatvnc` and `wayvnc` for protocol details and Wayland integration patterns.

**Architecture Decision:** Pure Rust implementation of the RFB protocol stack, with no dependency on the `neatvnc` C library. Wayland integration (screencopy, virtual input) remains in Rust using `wayland-client`.

## RFB Protocol Implementation Status

### Phase 1: Core Protocol (Handshake & Session Management)
- [x] TCP listener and client connection handling
- [x] Protocol version exchange (`RFB 003.008\n`)
- [x] Security type negotiation (None, VNC Auth with DES challenge-response)
- [x] Client initialization (shared flag handling)
- [x] Server initialization (framebuffer dimensions, pixel format, desktop name)
- [x] Client state machine
  - `WaitingForVersion` -> `WaitingForSecurity` -> `WaitingForVncAuth` -> `WaitingForInit` -> `Ready`
- [x] Per-client statistics (bytes sent/received, frames sent, connection time)

### Phase 2: Client -> Server Messages
- [x] `SetPixelFormat` (type 0)
- [x] `SetEncodings` (type 2) — encoding negotiation
- [x] `FramebufferUpdateRequest` (type 3) — incremental/full updates
- [x] `KeyEvent` (type 4) — keysym-based input
- [x] `PointerEvent` (type 5) — mouse/absolute pointer
- [x] `ClientCutText` (type 6) — clipboard receive
- [x] `EnableContinuousUpdates` (type 150)
- [x] `Fence` (type 248)
- [ ] `QEMU Extended Key Event` (type 255, subtype 0)
- [ ] `SetDesktopSize` (type 251)

### Phase 3: Server -> Client Messages
- [x] `FramebufferUpdate` (type 0) — with rectangle headers
- [ ] `SetColorMapEntries` (type 1) — for palette modes
- [ ] `Bell` (type 2)
- [x] `ServerCutText` (type 3) — clipboard send
- [x] `EndOfContinuousUpdates` (type 150)
- [x] `Fence` (type 248) — for latency measurement

### Phase 4: Encodings
- [x] `Raw` (0) — baseline, uncompressed
- [ ] `CopyRect` (1) — copy existing framebuffer region
- [ ] `RRE` (2) — rise-and-run encoding
- [x] `Hextile` (5) — tiled encoding
- [x] `Tight` (7) — zlib-compressed tiles with Fill/Basic subencodings
- [x] `ZRLE` (16) — zlib-run-length encoding
- [ ] `TRLE` (15) — tiled RLE
- [ ] `Cursor` (-239) — pseudo-encoding for cursor shape (requires ext-image-copy-capture)
- [x] `DesktopSize` (-223) — desktop resize notification
- [x] `ExtendedDesktopSize` (-308) — multi-monitor layout
- [x] `ExtendedClipboard` (-1063131698) — bidirectional clipboard

### Phase 5: Wayland Integration
- [x] `wlr-screencopy-unstable-v1` — screen capture
- [x] `wl_output` / `wl_seat` discovery
- [x] `zwlr-virtual-pointer-v1` — virtual mouse input
- [x] `uinput` / `evdev` — virtual keyboard input
- [x] `zwlr-data-control-v1` — bidirectional clipboard sync
- [ ] `zwp-virtual-keyboard-v1` — Wayland virtual keyboard (alternative to uinput)

### Phase 6: Authentication & Security
- [x] Password-based VNC auth (DES challenge-response)
- [ ] RSA-AES key exchange
- [ ] TLS / VeNCrypt
- [ ] Username + password credentials

### Phase 7: Control Interface (wayvncctl equivalent)
- [x] Unix domain socket IPC
- [x] JSON command protocol
- [x] Commands: status, disconnect-client, set-output
- [x] Commands: reload-config, set-password, set-rate

### Phase 8: Performance & Features
- [x] Damage tracking (tile-based, 64x64)
- [x] Frame rate limiting
- [x] SHM capture with mmap synchronization
- [x] Per-client traffic statistics (bytes sent/received, frames)
- [x] Continuous updates mode
- [ ] Bandwidth estimation
- [ ] Multi-output / desktop capture switch at runtime
- [ ] Cursor overlay / independent cursor capture
- [ ] DMA-BUF zero-copy path (future)

## Pixel Format Support

Current target: `XRGB8888` (32-bit, 8 bits per channel, no alpha).

```
bits_per_pixel: 32
depth: 24
big_endian_flag: 0
true_colour_flag: 1
red_max: 255
green_max: 255
blue_max: 255
red_shift: 16
green_shift: 8
blue_shift: 0
```

## Module Structure

```
vnc-server/src/
├── main.rs           # Entry point, CLI, event loop
├── lib.rs            # Module exports
├── server/           # TCP server and client management
│   ├── mod.rs
│   ├── listener.rs   # TcpListener + accept loop
│   └── client.rs     # Per-client state machine (RFB protocol)
├── protocol/         # RFB protocol implementation
│   └── mod.rs        # Message types, pixel format, encodings, constants
├── encode/           # Frame encoders
│   ├── mod.rs
│   ├── raw.rs        # Raw encoding (encoding type 0)
│   ├── hextile.rs    # Hextile encoding (encoding type 5)
│   ├── tight.rs      # Tight encoding (encoding type 7)
│   └── zrle.rs       # ZRLE encoding (encoding type 16)
├── wayland/          # Wayland integration
│   ├── mod.rs
│   ├── wayland_ctx.rs # Connection + registry (WaylandState)
│   ├── capture.rs    # CaptureManager + FrameData
│   ├── screencopy.rs # wlr-screencopy dispatch
│   ├── input.rs      # Virtual pointer (wlr-virtual-pointer)
│   └── keyboard.rs   # Virtual keyboard (uinput/evdev)
├── clipboard.rs      # wlr-data-control stub
├── config.rs         # Config file + CLI parsing
└── signal.rs         # Signal handling
```

## Data Flow

```
Wayland Compositor
       |
       v
[wlr-screencopy] ---> CaptureBuffer (SHM memfd, mmap'd)
       |
       v
[CaptureManager::take_framebuffer] ---> FrameData { data: Vec<u8>, width, height, stride }
       |
       v
[encode::zrle::encode_zrle] ---> FbRect { encoding: Zrle, data: zlib-compressed }
       |
       v
[VncClient::send_fb_update_header + send_zrle_rect] ---> TcpStream
       |
       v
VNC Client
```

## Key Design Decisions

1. **Pure Rust RFB:** No dependency on `neatvnc` C library. All protocol handling is in Rust.
2. **Single-threaded event loop:** Wayland's `EventQueue` is `!Send/!Sync`, so the main loop runs in one thread with non-blocking TCP accept and client message processing.
3. **Sync polling:** `dispatch_pending` + `thread::sleep(5ms)` + frame rate limiting. No async runtime needed.
4. **SHM capture:** Uses `memfd_create` + `wl_shm_pool` + `mmap` for Wayland buffer allocation. Compositor writes directly to mmap'd memory.
5. **ZRLE encoding:** Tile-based zlib compression with solid/palette/raw subencodings. Significantly reduces bandwidth vs Raw.

## Known Issues / TODOs

- **Keyboard keysym mapping:** Simplified X11->Linux keycode mapping in `keyboard.rs`. Needs xkbcommon for full accuracy.
- **Cursor:** Not implemented. No cursor overlay or independent cursor capture.
- **Multi-output:** Can only capture one output at a time. No desktop switching.
- **RSA-AES / VeNCrypt / TLS:** Not implemented. Only None and VNC Auth security types are functional.
- **Control interface:** Implemented via JSON Unix socket; runtime `set-password`, `set-rate`, and `set-output` are wired.

## Compilation Status

- `cargo fmt --check` passes
- `cargo clippy -p vnc-server --all-features -- -D warnings` is clean
- `cargo check -p vnc-server` passes (0 warnings)
- `cargo build -p vnc-server` compiles

## Runtime Constraints

- Target: ROCKNIX (Wayland compositor like Sway/Gamescope)
- Default address: `127.0.0.1:5900`
- Frame rate cap: 30fps by default

## References

- **neatvnc** (protocol reference): `src/server.c`, `include/rfb-proto.h`
- **wayvnc** (integration pattern): `src/main.c`, `src/screencopy.c`
- **RFB Spec:** RFC 6143 (The Remote Framebuffer Protocol)

---

*Last updated: 2026-08-04*
