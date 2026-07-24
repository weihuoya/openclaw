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
    /// Fence pseudo-encoding
    Fence,
    /// ContinuousUpdates pseudo-encoding
    ContinuousUpdates,
    ExtendedClipboard,
    /// ExtendedDesktopSize pseudo-encoding
    ExtendedDesktopSize,
}

impl Encoding {
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
            Encoding::Fence => -312,
            Encoding::ContinuousUpdates => -313,
            Encoding::ExtendedClipboard => -1063131698,
            Encoding::ExtendedDesktopSize => -308,
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
        -1063131698 => "ExtendedClipboard",
        _ => "Unknown",
    }
}

/// Parse an encoding value from the RFB wire format into an `Encoding` variant.
///
/// This is the inverse of [`Encoding::as_i32`] and is useful when decoding
/// server rectangles.
pub fn from_i32(value: i32) -> Option<Encoding> {
    match value {
        0 => Some(Encoding::Raw),
        1 => Some(Encoding::CopyRect),
        2 => Some(Encoding::Rre),
        5 => Some(Encoding::Hextile),
        6 => Some(Encoding::Zlib),
        7 => Some(Encoding::Tight),
        15 => Some(Encoding::Trle),
        16 => Some(Encoding::Zrle),
        50 => Some(Encoding::OpenH264),
        -223 => Some(Encoding::DesktopSize),
        -307 => Some(Encoding::DesktopName),
        -239 => Some(Encoding::Cursor),
        -240 => Some(Encoding::CursorPos),
        -312 => Some(Encoding::Fence),
        -313 => Some(Encoding::ContinuousUpdates),
        -308 => Some(Encoding::ExtendedDesktopSize),
        -1063131698 => Some(Encoding::ExtendedClipboard),
        _ => None,
    }
}
