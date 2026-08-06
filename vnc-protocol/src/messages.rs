//! RFB message-type enums and numeric constants.

/// Client-to-server RFB message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClientMsgType {
    SetPixelFormat = 0,
    SetEncodings = 2,
    FramebufferUpdateRequest = 3,
    KeyEvent = 4,
    PointerEvent = 5,
    CutText = 6,
    EnableContinuousUpdates = 150,
    Ntp = 160,
    Fence = 248,
    SetDesktopSize = 251,
    Qemu = 255,
}

/// Server-to-client RFB message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ServerMsgType {
    FramebufferUpdate = 0,
    SetColorMapEntries = 1,
    Bell = 2,
    ServerCutText = 3,
    EndOfContinuousUpdates = 150,
    Ntp = 160,
    Fence = 248,
}

// Numeric constants for ergonomic use.
pub const CLIENT_SET_PIXEL_FORMAT: u8 = ClientMsgType::SetPixelFormat as u8;
pub const CLIENT_SET_ENCODINGS: u8 = ClientMsgType::SetEncodings as u8;
pub const CLIENT_FRAMEBUFFER_UPDATE_REQUEST: u8 = ClientMsgType::FramebufferUpdateRequest as u8;
pub const CLIENT_KEY_EVENT: u8 = ClientMsgType::KeyEvent as u8;
pub const CLIENT_POINTER_EVENT: u8 = ClientMsgType::PointerEvent as u8;
pub const CLIENT_CUT_TEXT: u8 = ClientMsgType::CutText as u8;
pub const CLIENT_ENABLE_CONTINUOUS_UPDATES: u8 = ClientMsgType::EnableContinuousUpdates as u8;
/// Message-type value of both ClientFence and ServerFence: RFB 7.5.10 and
/// 7.6.7 share the same value (248) in both directions, so a single neutral
/// constant names it. [`CLIENT_FENCE`] is kept as a direction-specific alias.
pub const MESSAGE_TYPE_FENCE: u8 = ClientMsgType::Fence as u8;
pub const CLIENT_FENCE: u8 = MESSAGE_TYPE_FENCE;
pub const CLIENT_SET_DESKTOP_SIZE: u8 = ClientMsgType::SetDesktopSize as u8;
pub const CLIENT_QEMU: u8 = ClientMsgType::Qemu as u8;

pub const SERVER_FRAMEBUFFER_UPDATE: u8 = ServerMsgType::FramebufferUpdate as u8;
pub const SERVER_SET_COLOUR_MAP_ENTRIES: u8 = ServerMsgType::SetColorMapEntries as u8;
pub const SERVER_BELL: u8 = ServerMsgType::Bell as u8;
pub const SERVER_SERVER_CUT_TEXT: u8 = ServerMsgType::ServerCutText as u8;
pub const SERVER_END_OF_CONTINUOUS_UPDATES: u8 = ServerMsgType::EndOfContinuousUpdates as u8;

/// Legacy server-to-client message type for EndOfContinuousUpdates, still
/// sent by some servers (the standard value is
/// [`SERVER_END_OF_CONTINUOUS_UPDATES`]).
pub const SERVER_END_OF_CONTINUOUS_UPDATES_LEGACY: u8 = 4;
/// Legacy server-to-client message type for ServerFence, still sent by some
/// servers (the standard value is 248, shared with ClientFence).
pub const SERVER_FENCE_LEGACY: u8 = 5;

/// Standard RFB version banner.
pub const RFB_VERSION: &[u8] = b"RFB 003.008\n";

// Fence flags (RFB 7.5.10 ServerFence / 7.6.7 ClientFence).
/// All messages preceding the fence must have finished processing and taken
/// effect before the response is sent.
pub const FENCE_FLAG_BLOCK_BEFORE: u32 = 0x0000_0001;
/// All messages following the fence must not start processing until the
/// response is sent.
pub const FENCE_FLAG_BLOCK_AFTER: u32 = 0x0000_0002;
/// The message following the fence must be executed in an atomic manner with
/// respect to the fence response.
pub const FENCE_FLAG_SYNC_NEXT: u32 = 0x0000_0004;
/// The sender requests the peer to send a fence back. Cleared in responses.
pub const FENCE_FLAG_REQUEST: u32 = 0x8000_0000;
/// Maximum fence payload size recommended by the RFB specification. The wire
/// format allows up to 255 bytes (length is a U8).
pub const FENCE_MAX_PAYLOAD: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_constants_match_enum_values() {
        assert_eq!(CLIENT_SET_PIXEL_FORMAT, ClientMsgType::SetPixelFormat as u8);
        assert_eq!(CLIENT_SET_ENCODINGS, ClientMsgType::SetEncodings as u8);
        assert_eq!(
            CLIENT_FRAMEBUFFER_UPDATE_REQUEST,
            ClientMsgType::FramebufferUpdateRequest as u8
        );
        assert_eq!(CLIENT_KEY_EVENT, ClientMsgType::KeyEvent as u8);
        assert_eq!(CLIENT_POINTER_EVENT, ClientMsgType::PointerEvent as u8);
        assert_eq!(CLIENT_CUT_TEXT, ClientMsgType::CutText as u8);
        assert_eq!(
            CLIENT_ENABLE_CONTINUOUS_UPDATES,
            ClientMsgType::EnableContinuousUpdates as u8
        );
        assert_eq!(CLIENT_FENCE, ClientMsgType::Fence as u8);
        assert_eq!(CLIENT_SET_DESKTOP_SIZE, ClientMsgType::SetDesktopSize as u8);
        assert_eq!(CLIENT_QEMU, ClientMsgType::Qemu as u8);
    }

    #[test]
    fn server_constants_match_enum_values() {
        assert_eq!(
            SERVER_FRAMEBUFFER_UPDATE,
            ServerMsgType::FramebufferUpdate as u8
        );
        assert_eq!(
            SERVER_SET_COLOUR_MAP_ENTRIES,
            ServerMsgType::SetColorMapEntries as u8
        );
        assert_eq!(SERVER_BELL, ServerMsgType::Bell as u8);
        assert_eq!(SERVER_SERVER_CUT_TEXT, ServerMsgType::ServerCutText as u8);
        assert_eq!(
            SERVER_END_OF_CONTINUOUS_UPDATES,
            ServerMsgType::EndOfContinuousUpdates as u8
        );
    }

    #[test]
    fn fence_message_type_is_shared_by_both_directions() {
        // ClientFence and ServerFence use the same wire value (248).
        assert_eq!(MESSAGE_TYPE_FENCE, 248);
        assert_eq!(MESSAGE_TYPE_FENCE, ClientMsgType::Fence as u8);
        assert_eq!(MESSAGE_TYPE_FENCE, ServerMsgType::Fence as u8);
        assert_eq!(CLIENT_FENCE, MESSAGE_TYPE_FENCE);
        // The legacy aliases are distinct from the standard value.
        assert_ne!(SERVER_FENCE_LEGACY, MESSAGE_TYPE_FENCE);
        assert_ne!(
            SERVER_END_OF_CONTINUOUS_UPDATES_LEGACY,
            SERVER_END_OF_CONTINUOUS_UPDATES
        );
    }

    #[test]
    fn rfb_version_banner_is_well_formed() {
        assert_eq!(RFB_VERSION, b"RFB 003.008\n");
        assert_eq!(RFB_VERSION.len(), 12);
    }
}
