/// Extended Clipboard pseudo-encoding wire value advertised by this crate in
/// `SetEncodings` (the LibVNCServer/UltraVNC convention).
pub const EXTENDED_CLIPBOARD: i32 = -1063131698;

/// Alternate Extended Clipboard wire value sent by QEMU-derived servers.
///
/// Both values exist in the wild; a client that supports extended clipboard
/// must recognize rectangles carrying either value.
pub const EXTENDED_CLIPBOARD_ALT: i32 = -1063131699;

/// RFB encoding types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Raw,
    CopyRect,
    Rre,
    Hextile,
    Zlib,
    Tight,
    Zrle,
    Trle,
    /// JPEG quality level (pseudo-encoding)
    JpegQuality(i32),
    /// Desktop size pseudo-encoding
    DesktopSize,
    DesktopName,
    /// Cursor pseudo-encoding
    Cursor,
    /// Cursor position pseudo-encoding
    CursorPos,
    /// OpenH264 encoding
    OpenH264,
    /// Apple high-performance encoding with a raw wire value.
    AppleHp(i32),
    /// Fence pseudo-encoding
    Fence,
    /// ContinuousUpdates pseudo-encoding
    ContinuousUpdates,
    ExtendedClipboard,
    /// ExtendedDesktopSize pseudo-encoding
    ExtendedDesktopSize,
    /// QEMU extended mouse buttons pseudo-encoding
    ExtMouseButtons,
    /// QEMU extended key event pseudo-encoding
    QemuExtKeyEvent,
}

impl Encoding {
    /// Return the wire encoding value.
    pub fn as_i32(&self) -> i32 {
        match *self {
            Encoding::Raw => 0,
            Encoding::CopyRect => 1,
            Encoding::Rre => 2,
            Encoding::Hextile => 5,
            Encoding::Zlib => 6,
            Encoding::Tight => 7,
            Encoding::Zrle => 16,
            Encoding::Trle => 15,
            Encoding::JpegQuality(level) => -32 + level,
            Encoding::DesktopSize => -223,
            Encoding::DesktopName => -307,
            Encoding::Cursor => -239,
            Encoding::CursorPos => -240,
            Encoding::OpenH264 => 50,
            Encoding::AppleHp(value) => value,
            Encoding::Fence => -312,
            Encoding::ContinuousUpdates => -313,
            Encoding::ExtendedClipboard => EXTENDED_CLIPBOARD,
            Encoding::ExtendedDesktopSize => -308,
            Encoding::ExtMouseButtons => -316,
            Encoding::QemuExtKeyEvent => -258,
        }
    }
}

/// Return a human-readable name for the given RFB encoding value.
pub fn encoding_name(value: i32) -> &'static str {
    match value {
        0 => "Raw",
        1 => "CopyRect",
        2 => "RRE",
        5 => "Hextile",
        6 => "Zlib",
        7 => "Tight",
        15 => "TRLE",
        16 => "ZRLE",
        50 => "OpenH264",
        -223 => "DesktopSize",
        -307 => "DesktopName",
        -239 => "Cursor",
        -240 => "CursorPos",
        -312 => "Fence",
        -313 => "ContinuousUpdates",
        -308 => "ExtendedDesktopSize",
        -316 => "ExtMouseButtons",
        -258 => "QemuExtKeyEvent",
        -1063131698 => "ExtendedClipboard",
        _ if value >= 0x3e8
            || value == 1100
            || value == 1101
            || value == 1104
            || value == 1105
            || value == 1107
            || value == 1109
            || value == 1110 =>
        {
            "AppleHp"
        }
        _ => "Unknown",
    }
}

/// Parse an encoding value from the RFB wire format into an `Encoding` variant.
///
/// Useful when decoding server rectangles. Known wire values map to their
/// dedicated variants; every other value is preserved as
/// [`Encoding::AppleHp`] with the raw wire value. It is not a strict inverse
/// of [`Encoding::as_i32`]: unknown values round-trip through
/// [`Encoding::AppleHp`], keeping the raw value rather than failing.
pub fn from_i32(value: i32) -> Encoding {
    match value {
        0 => Encoding::Raw,
        1 => Encoding::CopyRect,
        2 => Encoding::Rre,
        5 => Encoding::Hextile,
        6 => Encoding::Zlib,
        7 => Encoding::Tight,
        15 => Encoding::Trle,
        16 => Encoding::Zrle,
        50 => Encoding::OpenH264,
        -223 => Encoding::DesktopSize,
        -307 => Encoding::DesktopName,
        -239 => Encoding::Cursor,
        -240 => Encoding::CursorPos,
        -312 => Encoding::Fence,
        -313 => Encoding::ContinuousUpdates,
        -308 => Encoding::ExtendedDesktopSize,
        -316 => Encoding::ExtMouseButtons,
        -258 => Encoding::QemuExtKeyEvent,
        EXTENDED_CLIPBOARD | EXTENDED_CLIPBOARD_ALT => Encoding::ExtendedClipboard,
        _ => Encoding::AppleHp(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extended_clipboard_both_wire_values_are_recognized() {
        // The crate advertises the LibVNCServer/UltraVNC value, but
        // QEMU-derived servers send the alternate value; both must decode to
        // the same variant.
        assert_eq!(from_i32(EXTENDED_CLIPBOARD), Encoding::ExtendedClipboard);
        assert_eq!(
            from_i32(EXTENDED_CLIPBOARD_ALT),
            Encoding::ExtendedClipboard
        );
        // The advertised value stays the canonical one.
        assert_eq!(Encoding::ExtendedClipboard.as_i32(), EXTENDED_CLIPBOARD);
    }

    #[test]
    fn unknown_values_round_trip_through_apple_hp() {
        assert_eq!(from_i32(12345), Encoding::AppleHp(12345));
        assert_eq!(Encoding::AppleHp(12345).as_i32(), 12345);
    }
}
