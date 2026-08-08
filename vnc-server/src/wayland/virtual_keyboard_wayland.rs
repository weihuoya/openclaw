//! Virtual keyboard input via Wayland zwp-virtual-keyboard-v1 protocol.
//!
//! This module provides keyboard input injection using the Wayland virtual
//! keyboard protocol, which does not require root access (unlike uinput).
//!
//! A keymap must be set before any key events can be sent. The implementation
//! first tries to load the system's default xkb keymap, and falls back to a
//! minimal built-in keymap if that fails.

use log::{debug, info};
use std::io::Write;
use std::os::fd::AsFd;

use wayland_client::protocol::wl_seat::WlSeat;
use wayland_client::QueueHandle;
use wayland_protocols_misc::zwp_virtual_keyboard_v1::client::zwp_virtual_keyboard_manager_v1::ZwpVirtualKeyboardManagerV1;
use wayland_protocols_misc::zwp_virtual_keyboard_v1::client::zwp_virtual_keyboard_v1::ZwpVirtualKeyboardV1;

use crate::wayland::keyboard::KeyboardBackend;
use crate::wayland::wayland_ctx::WaylandState;

/// A virtual keyboard using the Wayland zwp-virtual-keyboard-v1 protocol.
pub struct WaylandVirtualKeyboard {
    keyboard: Option<ZwpVirtualKeyboardV1>,
    /// Whether Shift is currently held on the host. Set by client Shift
    /// keysym events (and raw Shift keycodes from the QEMU extended key
    /// event); used to avoid synthesizing redundant Shift presses around
    /// shifted characters while the client already holds Shift.
    shift_held: bool,
}

impl WaylandVirtualKeyboard {
    /// Create a new virtual keyboard for the given seat.
    pub fn new(
        manager: &ZwpVirtualKeyboardManagerV1,
        seat: &WlSeat,
        qh: &QueueHandle<WaylandState>,
    ) -> Result<Self, String> {
        let keyboard = manager.create_virtual_keyboard(seat, qh, ());

        // Set a minimal keymap so the compositor accepts key events.
        if let Err(e) = set_keymap(&keyboard) {
            keyboard.destroy();
            return Err(format!("Failed to set keymap: {}", e));
        }

        info!("Wayland virtual keyboard created");
        Ok(Self {
            keyboard: Some(keyboard),
            shift_held: false,
        })
    }

    /// Send a key event using a Linux keycode.
    pub fn key(&mut self, keycode: u32, pressed: bool) {
        let Some(ref keyboard) = self.keyboard else {
            return;
        };

        if keycode == KEY_LEFTSHIFT as u32 || keycode == KEY_RIGHTSHIFT as u32 {
            self.shift_held = pressed;
        }

        let state = if pressed { 1 } else { 0 };
        // The virtual-keyboard protocol expects keycodes starting at 0,
        // while Linux keycodes start at 1. Subtract 1 to match.
        keyboard.key(0, keycode.saturating_sub(1), state);
    }

    /// Send a keysym (X11 keysym) event.
    ///
    /// This converts an X11 keysym to a Linux keycode, synthesizing Shift
    /// presses around keysyms that require Shift on a US layout.
    pub fn keysym(&mut self, keysym: u32, pressed: bool) {
        for (keycode, pressed) in keysym_events(&mut self.shift_held, keysym, pressed) {
            self.key(keycode as u32, pressed);
        }
    }
}

impl Drop for WaylandVirtualKeyboard {
    fn drop(&mut self) {
        if let Some(keyboard) = self.keyboard.take() {
            keyboard.destroy();
        }
        debug!("Wayland virtual keyboard destroyed");
    }
}

impl KeyboardBackend for WaylandVirtualKeyboard {
    fn key(&mut self, keycode: u32, pressed: bool) {
        self.key(keycode, pressed);
    }

    fn keysym(&mut self, keysym: u32, pressed: bool) {
        self.keysym(keysym, pressed);
    }
}

/// Linux keycode for the left Shift key (KEY_LEFTSHIFT).
const KEY_LEFTSHIFT: u16 = 42;
/// Linux keycode for the right Shift key (KEY_RIGHTSHIFT).
const KEY_RIGHTSHIFT: u16 = 54;

/// Set a keymap on the virtual keyboard.
///
/// First tries to load the system default xkb keymap, then falls back to a
/// minimal built-in keymap.
fn set_keymap(keyboard: &ZwpVirtualKeyboardV1) -> Result<(), String> {
    // Try the system default keymap first.
    if let Ok(keymap) = load_system_keymap() {
        return send_keymap(keyboard, &keymap);
    }

    // Fall back to the built-in minimal keymap.
    debug!("Using built-in minimal keymap");
    send_keymap(keyboard, MINIMAL_KEYMAP)
}

/// Load the system's default xkb keymap.
fn load_system_keymap() -> Result<String, std::io::Error> {
    // Try common system keymap locations.
    for path in [
        "/usr/share/X11/xkb/keymap/default",
        "/usr/share/X11/xkb/keymap/xkb_default",
        "/etc/default/keyboard",
    ] {
        if let Ok(content) = std::fs::read_to_string(path) {
            // /etc/default/keyboard is a shell script, not a keymap.
            if path.ends_with("/keyboard") && !content.starts_with("xkb_keymap") {
                continue;
            }
            debug!("Loaded system keymap from {}", path);
            return Ok(content);
        }
    }

    // Try running setxkbmap or xkbcomp.
    if let Ok(output) = std::process::Command::new("setxkbmap")
        .args(["-print"])
        .output()
    {
        if output.status.success() {
            let keymap = String::from_utf8_lossy(&output.stdout).to_string();
            if keymap.contains("xkb_keymap") {
                debug!("Loaded keymap from setxkbmap -print");
                return Ok(keymap);
            }
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "no system keymap found",
    ))
}

/// Send a keymap to the virtual keyboard via a memfd.
fn send_keymap(keyboard: &ZwpVirtualKeyboardV1, keymap: &str) -> Result<(), String> {
    let size = keymap.len();

    // Create a memfd to hold the keymap data.
    let fd = nix::sys::memfd::memfd_create(c"vnc-keymap", nix::sys::memfd::MFdFlags::MFD_CLOEXEC)
        .map_err(|e| format!("memfd_create failed: {}", e))?;

    nix::unistd::ftruncate(&fd, size as i64).map_err(|e| format!("ftruncate failed: {}", e))?;

    {
        let mut file = std::fs::File::from(fd.try_clone().map_err(|e| format!("clone fd: {}", e))?);
        file.write_all(keymap.as_bytes())
            .map_err(|e| format!("write keymap: {}", e))?;
    }

    // XKB keymap format = 1 (xkb_v1)
    keyboard.keymap(1, fd.as_fd(), size as u32);

    debug!("Sent keymap ({} bytes)", size);
    Ok(())
}

/// Compute the sequence of (keycode, pressed) events to inject for a keysym
/// event, updating `shift_held` (whether Shift is currently held on the host).
///
/// This is identical to the logic in `keyboard.rs`.
fn keysym_events(shift_held: &mut bool, keysym: u32, pressed: bool) -> Vec<(u16, bool)> {
    let keycode = keysym_to_keycode(keysym);
    if keycode == 0 {
        return Vec::new();
    }
    let keycode = keycode as u16;

    if keycode == KEY_LEFTSHIFT || keycode == KEY_RIGHTSHIFT {
        *shift_held = pressed;
        return vec![(keycode, pressed)];
    }

    if !keysym_needs_shift(keysym) || *shift_held {
        return vec![(keycode, pressed)];
    }

    if pressed {
        vec![(KEY_LEFTSHIFT, true), (keycode, true)]
    } else {
        vec![(keycode, false), (KEY_LEFTSHIFT, false)]
    }
}

/// Whether a keysym requires Shift on a US keyboard layout.
fn keysym_needs_shift(keysym: u32) -> bool {
    matches!(keysym,
        // A-Z
        0x0041..=0x005a
        // ! " # $ % & ( ) * +
        | 0x0021..=0x0026 | 0x0028..=0x002b
        // : < > ?
        | 0x003a | 0x003c..=0x003f
        // @ ^ _
        | 0x0040 | 0x005e | 0x005f
        // { | } ~
        | 0x007b..=0x007e)
}

/// Convert X11 keysym to Linux keycode.
fn keysym_to_keycode(keysym: u32) -> u32 {
    // Based on linux/input-event-codes.h and X11 keysym definitions.
    match keysym {
        // ASCII letters (a-z, A-Z)
        0x0061..=0x007a => keysym - 0x0061 + 30,
        0x0041..=0x005a => keysym - 0x0041 + 30,

        // ASCII digits
        0x0030..=0x0039 => keysym - 0x0030 + 11,

        // ASCII punctuation and symbols
        0x0020 => 57, // space
        0x0021 => 2,  // exclam -> KEY_1 with shift
        0x0022 => 40, // quotedbl -> KEY_APOSTROPHE with shift
        0x0023 => 4,  // numbersign -> KEY_3 with shift
        0x0024 => 5,  // dollar -> KEY_4 with shift
        0x0025 => 6,  // percent -> KEY_5 with shift
        0x0026 => 8,  // ampersand -> KEY_7 with shift
        0x0027 => 40, // apostrophe
        0x0028 => 10, // parenleft -> KEY_9 with shift
        0x0029 => 11, // parenright -> KEY_0 with shift
        0x002a => 9,  // asterisk -> KEY_8 with shift
        0x002b => 13, // plus -> KEY_EQUAL with shift
        0x002c => 51, // comma
        0x002d => 12, // minus
        0x002e => 52, // period
        0x002f => 53, // slash
        0x003a => 39, // colon -> KEY_SEMICOLON with shift
        0x003b => 39, // semicolon
        0x003c => 86, // less -> KEY_102ND with shift
        0x003d => 13, // equal
        0x003e => 86, // greater -> KEY_102ND with shift
        0x003f => 53, // question -> KEY_SLASH with shift
        0x0040 => 3,  // at -> KEY_2 with shift
        0x005b => 26, // bracketleft
        0x005c => 43, // backslash
        0x005d => 27, // bracketright
        0x005e => 7,  // asciicircum -> KEY_6 with shift
        0x005f => 12, // underscore -> KEY_MINUS with shift
        0x0060 => 41, // grave
        0x007b => 26, // braceleft -> KEY_LEFTBRACE with shift
        0x007c => 43, // bar -> KEY_BACKSLASH with shift
        0x007d => 27, // braceright -> KEY_RIGHTBRACE with shift
        0x007e => 41, // asciitilde -> KEY_GRAVE with shift

        // Special keys
        0xFF08 => 14,  // BackSpace
        0xFF09 => 15,  // Tab
        0xFF0D => 28,  // Return
        0xFF1B => 1,   // Escape
        0xFF50 => 102, // Home
        0xFF51 => 105, // Left
        0xFF52 => 103, // Up
        0xFF53 => 106, // Right
        0xFF54 => 108, // Down
        0xFF55 => 104, // Page_Up
        0xFF56 => 109, // Page_Down
        0xFF57 => 107, // End
        0xFF63 => 110, // Insert
        0xFFFF => 111, // Delete

        // Modifiers
        0xFFE1 => 42,  // Shift_L
        0xFFE2 => 54,  // Shift_R
        0xFFE3 => 29,  // Control_L
        0xFFE4 => 97,  // Control_R
        0xFFE5 => 58,  // Caps_Lock
        0xFFE7 => 56,  // Meta_L (same as Alt)
        0xFFE8 => 100, // Meta_R
        0xFFE9 => 56,  // Alt_L
        0xFFEA => 100, // Alt_R
        0xFFEB => 125, // Super_L
        0xFFEC => 126, // Super_R
        0xFFED => 127, // Hyper_L
        0xFFEE => 128, // Hyper_R

        // Function keys (F1-F12)
        0xFFBE => 59,  // F1
        0xFFBF => 60,  // F2
        0xFFC0 => 61,  // F3
        0xFFC1 => 62,  // F4
        0xFFC2 => 63,  // F5
        0xFFC3 => 64,  // F6
        0xFFC4 => 65,  // F7
        0xFFC5 => 66,  // F8
        0xFFC6 => 67,  // F9
        0xFFC7 => 68,  // F10
        0xFFC8 => 87,  // F11
        0xFFC9 => 88,  // F12
        0xFFCA => 183, // F13
        0xFFCB => 184, // F14
        0xFFCC => 185, // F15
        0xFFCD => 186, // F16
        0xFFCE => 187, // F17
        0xFFCF => 188, // F18
        0xFFD0 => 189, // F19
        0xFFD1 => 190, // F20
        0xFFD2 => 191, // F21
        0xFFD3 => 192, // F22
        0xFFD4 => 193, // F23
        0xFFD5 => 194, // F24

        // Numpad
        0xFF95 => 79,                            // KP_Home (KP_7)
        0xFF96 => 80,                            // KP_Left (KP_4)
        0xFF97 => 81,                            // KP_Up (KP_8)
        0xFF98 => 82,                            // KP_Right (KP_6)
        0xFF99 => 83,                            // KP_Down (KP_2)
        0xFF9A => 84,                            // KP_Prior / KP_Page_Up (KP_9)
        0xFF9B => 85,                            // KP_Next / KP_Page_Down (KP_3)
        0xFF9C => 87,                            // KP_End (KP_1)
        0xFF9D => 88,                            // KP_Begin (KP_5)
        0xFF9E => 89,                            // KP_Insert (KP_0)
        0xFF9F => 90,                            // KP_Delete (KP_Decimal)
        0xFFAA => 55,                            // KP_Multiply
        0xFFAB => 78,                            // KP_Add
        0xFFAC => 74,                            // KP_Separator
        0xFFAD => 74,                            // KP_Subtract
        0xFFAE => 83,                            // KP_Decimal
        0xFFAF => 112,                           // KP_Divide
        0xFFB0..=0xFFB9 => keysym - 0xFFB0 + 82, // KP_0-KP_9

        // Media keys
        0xE010 => 116, // XF86AudioMute
        0xE022 => 114, // XF86AudioLowerVolume
        0xE030 => 115, // XF86AudioRaiseVolume
        0xE06D => 164, // XF86AudioPlay
        0xE038 => 165, // XF86AudioStop
        0xE019 => 163, // XF86AudioNext
        0xE05D => 142, // XF86Sleep
        0xE05E => 143, // XF86WakeUp

        _ => {
            debug!("Unmapped keysym: 0x{:x}", keysym);
            0
        }
    }
}

/// A minimal built-in xkb keymap that covers the basic US layout.
/// This is used when the system does not provide a keymap.
const MINIMAL_KEYMAP: &str = r#"xkb_keymap {
  xkb_keycodes "minimal" {
    minimum = 8;
    maximum = 255;
    <ESC> = 1;
    <AE01> = 2; <AE02> = 3; <AE03> = 4; <AE04> = 5;
    <AE05> = 6; <AE06> = 7; <AE07> = 8; <AE08> = 9;
    <AE09> = 10; <AE10> = 11; <AE11> = 12; <AE12> = 13;
    <BKSP> = 14; <TAB> = 15;
    <AD01> = 16; <AD02> = 17; <AD03> = 18; <AD04> = 19;
    <AD05> = 20; <AD06> = 21; <AD07> = 22; <AD08> = 23;
    <AD09> = 24; <AD10> = 25; <AD11> = 26; <AD12> = 27;
    <RTRN> = 28; <LCTL> = 29;
    <AC01> = 30; <AC02> = 31; <AC03> = 32; <AC04> = 33;
    <AC05> = 34; <AC06> = 35; <AC07> = 36; <AC08> = 37;
    <AC09> = 38; <AC10> = 39; <AC11> = 40; <TLDE> = 41;
    <LFSH> = 42; <BKSL> = 43;
    <AB01> = 44; <AB02> = 45; <AB03> = 46; <AB04> = 47;
    <AB05> = 48; <AB06> = 49; <AB07> = 50; <AB08> = 51;
    <AB09> = 52; <AB10> = 53;
    <RTSH> = 54; <KPMU> = 55; <LALT> = 56; <SPCE> = 57;
    <CAPS> = 58; <FK01> = 59; <FK02> = 60; <FK03> = 61;
    <FK04> = 62; <FK05> = 63; <FK06> = 64; <FK07> = 65;
    <FK08> = 66; <FK09> = 67; <FK10> = 68; <NMLK> = 69;
    <SCLK> = 70; <KP7> = 71; <KP8> = 72; <KP9> = 73;
    <KPSU> = 74; <KP4> = 75; <KP5> = 76; <KP6> = 77;
    <KPPL> = 78; <KP1> = 79; <KP2> = 80; <KP3> = 81;
    <KP0> = 82; <KPDL> = 83; <LVL3> = 84; <LSGT> = 86;
    <FK11> = 87; <FK12> = 88; <AB11> = 89; <KATA> = 90;
    <HIRU> = 91; <HENK> = 92; <HKTG> = 93; <MUHE> = 94;
    <KPEN> = 96; <RCTL> = 97; <KPDV> = 98; <PRSC> = 99;
    <RALT> = 100; <HOME> = 102; <UP> = 103; <PGUP> = 104;
    <LEFT> = 105; <RGHT> = 106; <END> = 107; <DOWN> = 108;
    <PGDN> = 109; <INS> = 110; <DELE> = 111; <PAUS> = 119;
    <LWIN> = 125; <RWIN> = 126; <COMP> = 127;
    <MUTE> = 113; <VOL-> = 114; <VOL+> = 115;
    <NEXT> = 163; <PLAY> = 164; <PREV> = 165;
  };
  xkb_types "minimal" {
    type "ONE_LEVEL" {
      modifiers= none;
      map[none]= 1;
      level_name[1]= "Any";
    };
    type "TWO_LEVEL" {
      modifiers= Shift;
      map[Shift]= 2;
      level_name[1]= "Base";
      level_name[2]= "Shift";
    };
  };
  xkb_compat "minimal" {
  };
  xkb_symbols "minimal" {
    key <ESC> { [ Escape ] };
    key <AE01> { [ 1, exclam ] };
    key <AE02> { [ 2, at ] };
    key <AE03> { [ 3, numbersign ] };
    key <AE04> { [ 4, dollar ] };
    key <AE05> { [ 5, percent ] };
    key <AE06> { [ 6, asciicircum ] };
    key <AE07> { [ 7, ampersand ] };
    key <AE08> { [ 8, asterisk ] };
    key <AE09> { [ 9, parenleft ] };
    key <AE10> { [ 0, parenright ] };
    key <AE11> { [ minus, underscore ] };
    key <AE12> { [ equal, plus ] };
    key <BKSP> { [ BackSpace ] };
    key <TAB> { [ Tab ] };
    key <AD01> { [ q, Q ] };
    key <AD02> { [ w, W ] };
    key <AD03> { [ e, E ] };
    key <AD04> { [ r, R ] };
    key <AD05> { [ t, T ] };
    key <AD06> { [ y, Y ] };
    key <AD07> { [ u, U ] };
    key <AD08> { [ i, I ] };
    key <AD09> { [ o, O ] };
    key <AD10> { [ p, P ] };
    key <AD11> { [ bracketleft, braceleft ] };
    key <AD12> { [ bracketright, braceright ] };
    key <RTRN> { [ Return ] };
    key <LCTL> { [ Control_L ] };
    key <AC01> { [ a, A ] };
    key <AC02> { [ s, S ] };
    key <AC03> { [ d, D ] };
    key <AC04> { [ f, F ] };
    key <AC05> { [ g, G ] };
    key <AC06> { [ h, H ] };
    key <AC07> { [ j, J ] };
    key <AC08> { [ k, K ] };
    key <AC09> { [ l, L ] };
    key <AC10> { [ semicolon, colon ] };
    key <AC11> { [ apostrophe, quotedbl ] };
    key <TLDE> { [ grave, asciitilde ] };
    key <LFSH> { [ Shift_L ] };
    key <BKSL> { [ backslash, bar ] };
    key <AB01> { [ z, Z ] };
    key <AB02> { [ x, X ] };
    key <AB03> { [ c, C ] };
    key <AB04> { [ v, V ] };
    key <AB05> { [ b, B ] };
    key <AB06> { [ n, N ] };
    key <AB07> { [ m, M ] };
    key <AB08> { [ comma, less ] };
    key <AB09> { [ period, greater ] };
    key <AB10> { [ slash, question ] };
    key <RTSH> { [ Shift_R ] };
    key <KPMU> { [ KP_Multiply ] };
    key <LALT> { [ Alt_L ] };
    key <SPCE> { [ space ] };
    key <CAPS> { [ Caps_Lock ] };
    key <FK01> { [ F1 ] };
    key <FK02> { [ F2 ] };
    key <FK03> { [ F3 ] };
    key <FK04> { [ F4 ] };
    key <FK05> { [ F5 ] };
    key <FK06> { [ F6 ] };
    key <FK07> { [ F7 ] };
    key <FK08> { [ F8 ] };
    key <FK09> { [ F9 ] };
    key <FK10> { [ F10 ] };
    key <NMLK> { [ Num_Lock ] };
    key <SCLK> { [ Scroll_Lock ] };
    key <KP7> { [ KP_Home ] };
    key <KP8> { [ KP_Up ] };
    key <KP9> { [ KP_Prior ] };
    key <KPSU> { [ KP_Subtract ] };
    key <KP4> { [ KP_Left ] };
    key <KP5> { [ KP_Begin ] };
    key <KP6> { [ KP_Right ] };
    key <KPPL> { [ KP_Add ] };
    key <KP1> { [ KP_End ] };
    key <KP2> { [ KP_Down ] };
    key <KP3> { [ KP_Next ] };
    key <KP0> { [ KP_Insert ] };
    key <KPDL> { [ KP_Delete ] };
    key <LVL3> { [ ISO_Level3_Shift ] };
    key <LSGT> { [ less, greater ] };
    key <FK11> { [ F11 ] };
    key <FK12> { [ F12 ] };
    key <AB11> { [ backslash, bar ] };
    key <KATA> { [ Katakana ] };
    key <HIRU> { [ Hiragana ] };
    key <HENK> { [ Henkan ] };
    key <HKTG> { [ Hiragana_Katakana ] };
    key <MUHE> { [ Muhenkan ] };
    key <KPEN> { [ KP_Enter ] };
    key <RCTL> { [ Control_R ] };
    key <KPDV> { [ KP_Divide ] };
    key <PRSC> { [ Print ] };
    key <RALT> { [ Alt_R ] };
    key <HOME> { [ Home ] };
    key <UP> { [ Up ] };
    key <PGUP> { [ Prior ] };
    key <LEFT> { [ Left ] };
    key <RGHT> { [ Right ] };
    key <END> { [ End ] };
    key <DOWN> { [ Down ] };
    key <PGDN> { [ Next ] };
    key <INS> { [ Insert ] };
    key <DELE> { [ Delete ] };
    key <PAUS> { [ Pause ] };
    key <LWIN> { [ Super_L ] };
    key <RWIN> { [ Super_R ] };
    key <COMP> { [ Menu ] };
    key <MUTE> { [ XF86AudioMute ] };
    key <VOL-> { [ XF86AudioLowerVolume ] };
    key <VOL+> { [ XF86AudioRaiseVolume ] };
    key <NEXT> { [ XF86AudioNext ] };
    key <PLAY> { [ XF86AudioPlay ] };
    key <PREV> { [ XF86AudioPrev ] };
  };
};"#;
