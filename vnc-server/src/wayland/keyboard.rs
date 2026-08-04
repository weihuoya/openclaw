//! Virtual keyboard input via Linux uinput.
//!
//! This module provides keyboard input injection using the Linux uinput
//! subsystem, which works independently of the Wayland compositor.

use log::{debug, error};

/// A virtual keyboard device using uinput.
pub struct VirtualKeyboard {
    device: Option<evdev::uinput::VirtualDevice>,
}

impl VirtualKeyboard {
    /// Create a new virtual keyboard device.
    pub fn new() -> Result<Self, String> {
        use evdev::AttributeSet;

        let mut keys = AttributeSet::new();
        for code in 1..=255u16 {
            keys.insert(evdev::KeyCode(code));
        }

        let device = evdev::uinput::VirtualDevice::builder()
            .map_err(|e| format!("Failed to create uinput builder: {}", e))?
            .name("vnc-server virtual keyboard")
            .with_keys(&keys)
            .map_err(|e| format!("Failed to set keys: {}", e))?
            .build()
            .map_err(|e| format!("Failed to create virtual device: {}", e))?;

        debug!("Virtual keyboard created");
        Ok(Self {
            device: Some(device),
        })
    }

    /// Send a key event.
    pub fn key(&mut self, keycode: u32, pressed: bool) {
        let Some(ref mut device) = self.device else {
            return;
        };

        let value = if pressed { 1 } else { 0 };
        let event = evdev::InputEvent::new(evdev::EventType::KEY.0, keycode as u16, value);

        if let Err(e) = device.emit(&[event]) {
            error!("Failed to emit key event: {}", e);
        }
    }

    /// Send a keysym (X11 keysym) event.
    ///
    /// This converts an X11 keysym to a Linux keycode.
    pub fn keysym(&mut self, keysym: u32, pressed: bool) {
        let keycode = keysym_to_keycode(keysym);
        if keycode > 0 {
            self.key(keycode, pressed);
        }
    }
}

/// Convert X11 keysym to Linux keycode.
fn keysym_to_keycode(keysym: u32) -> u32 {
    // Based on linux/input-event-codes.h and X11 keysym definitions.
    match keysym {
        // ASCII letters (a-z, A-Z)
        0x0061..=0x007a => keysym - 0x0061 + 30, // a-z -> KEY_A (30) to KEY_Z (45)
        0x0041..=0x005a => keysym - 0x0041 + 30, // A-Z

        // ASCII digits
        0x0030..=0x0039 => keysym - 0x0030 + 11, // 0-9 -> KEY_0 (11) to KEY_9 (20)

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

impl Drop for VirtualKeyboard {
    fn drop(&mut self) {
        debug!("Virtual keyboard destroyed");
    }
}
