//! RFB protocol message types and constants.

// Client to server message types
pub const CLIENT_SET_PIXEL_FORMAT: u8 = 0;
pub const CLIENT_SET_ENCODINGS: u8 = 2;
pub const CLIENT_FRAMEBUFFER_UPDATE_REQUEST: u8 = 3;
pub const CLIENT_KEY_EVENT: u8 = 4;
pub const CLIENT_POINTER_EVENT: u8 = 5;
pub const CLIENT_CUT_TEXT: u8 = 6;
pub const CLIENT_ENABLE_CONTINUOUS_UPDATES: u8 = 150;
pub const CLIENT_FENCE: u8 = 248;

// Server to client message types
pub const SERVER_FRAMEBUFFER_UPDATE: u8 = 0;
pub const SERVER_SET_COLOUR_MAP_ENTRIES: u8 = 1;
pub const SERVER_BELL: u8 = 2;
pub const SERVER_SERVER_CUT_TEXT: u8 = 3;
pub const SERVER_END_OF_CONTINUOUS_UPDATES: u8 = 150;

// Security types
pub const SECURITY_NONE: u8 = 1;
pub const SECURITY_VNC_AUTH: u8 = 2;
