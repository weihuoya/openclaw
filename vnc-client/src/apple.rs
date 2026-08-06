//! Apple high-performance protocol constants.

/// Protocol version banner for Apple HP sessions.
pub const PROTOCOL_VERSION: &[u8] = b"RFB 003.889\n";

/// ClientInit shared byte that requests the Apple HP session class.
pub const CLIENT_INIT_SHARED: u8 = 0xC1;

/// Legacy Apple Remote Desktop (type 30, non-HP) ClientInit shared byte.
pub const CLIENT_INIT_SHARED_LEGACY_ARD: u8 = 0x1C;

// Apple client-to-server control message opcodes.
pub const VIEWER_INFO: u8 = 0x21;
pub const SET_ENCRYPTION: u8 = 0x12;
pub const SET_MODE: u8 = 0x0a;
pub const AUTO_FRAMEBUFFER_UPDATE: u8 = 0x09;
pub const SET_DISPLAY_CONFIGURATION: u8 = 0x1d;
pub const MEDIA_STREAM_OPTIONS: u8 = 0x1c;
pub const SET_KEYBOARD_INPUT_SOURCE: u8 = 0x1a;
pub const SET_DISPLAY_MESSAGE: u8 = 0x0d;
pub const SCALE_FACTOR: u8 = 0x08;
pub const ENCRYPTED_INPUT_EVENT: u8 = 0x10;
pub const AUTO_PASTEBOARD: u8 = 0x15;
pub const CLIPBOARD_FETCH: u8 = 0x0b;

// Apple server-to-client control message opcodes.
pub const MISC_STATUS: u8 = 0x14;
pub const CLIPBOARD_SEND: u8 = 0x1f;

// Apple security types.
pub const SECURITY_DH: u8 = 30;
pub const SECURITY_RSA_SRP: u8 = 33;
pub const SECURITY_KERBEROS: u8 = 35;
pub const SECURITY_DIRECT_SRP: u8 = 36;

// Apple framebuffer-update encodings and pseudo-encodings.
pub const ENC_REKEY: i32 = 0x44f;
pub const ENC_CURSOR: i32 = 0x450;
pub const ENC_DISPLAY_LAYOUT: i32 = 0x451;
pub const ENC_VENDOR_KEYSYMS: i32 = 0x453;
pub const ENC_KEYBOARD_INPUT_SOURCE: i32 = 0x455;
pub const ENC_DEVICE_INFO: i32 = 0x456;
pub const ENC_MEDIA_STREAM: i32 = 0x3f2;
pub const ENC_LOW_QUALITY: i32 = 0x3e8;
pub const ENC_MEDIUM_QUALITY: i32 = 0x3e9;
pub const ENC_HIGH_QUALITY: i32 = 0x3ea;
pub const ENC_MULTI_VARIANT_SCALED: i32 = 0x3f3;

// Sub-command values for SetEncryption (0x12).
pub const SET_ENCRYPTION_COMMAND_START: u16 = 1;
pub const SET_ENCRYPTION_COMMAND_STOP: u16 = 2;

// Mode values for SetMode (0x0a).
pub const SET_MODE_OBSERVE: u16 = 0;
pub const SET_MODE_CONTROL: u16 = 1;

// Display configuration descriptor flags.
pub const DISPLAY_FLAG_DYNAMIC: u32 = 0x01;

// Display configuration descriptor types.
pub const DISPLAY_TYPE_PHYSICAL: u32 = 0;
pub const DISPLAY_TYPE_VIRTUAL: u32 = 4;

// Sentinel for "all/main displays" in AutoFrameBufferUpdate.
pub const SELECTED_SCREEN_ALL: u32 = 0xffffffff;
