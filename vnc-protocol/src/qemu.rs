//! QEMU RFB extension constants and parsers (message type 255).
//!
//! QEMU carries its extensions (extended key events, keyboard LED state,
//! audio) in messages with type 255 in both directions, discriminated by a
//! sub-type byte. Only the parts an endpoint of this workspace actually
//! sends or parses are defined here.

/// Message type used for QEMU extension messages in both directions.
pub const MESSAGE_TYPE: u8 = crate::messages::CLIENT_QEMU;

/// Sub-type: QEMU extended key event (client → server). The body is parsed
/// by [`crate::framing::QemuExtendedKeyEvent`].
pub const SUB_TYPE_EXTENDED_KEY_EVENT: u8 = 0;
/// Sub-type: keyboard LED state (server → client), one payload byte.
pub const SUB_TYPE_LED_STATE: u8 = 1;
/// Sub-type: audio (server → client), an operation byte followed by
/// operation-specific data.
pub const SUB_TYPE_AUDIO: u8 = 2;

/// LED state bit: Scroll Lock.
pub const LED_SCROLL_LOCK: u8 = 0x01;
/// LED state bit: Num Lock.
pub const LED_NUM_LOCK: u8 = 0x02;
/// LED state bit: Caps Lock.
pub const LED_CAPS_LOCK: u8 = 0x04;

/// Parsed keyboard LED state (QEMU LED State sub-type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedState {
    pub scroll_lock: bool,
    pub num_lock: bool,
    pub caps_lock: bool,
}

/// Parse the single payload byte of a QEMU LED State message.
pub fn parse_led_state(state: u8) -> LedState {
    LedState {
        scroll_lock: state & LED_SCROLL_LOCK != 0,
        num_lock: state & LED_NUM_LOCK != 0,
        caps_lock: state & LED_CAPS_LOCK != 0,
    }
}

/// Audio operation: stop playback (no further data).
pub const AUDIO_OP_STOP: u8 = 0;
/// Audio operation: start playback; carries an [`AudioFormatHeader`] followed
/// by `data_len` bytes of sample data.
pub const AUDIO_OP_START: u8 = 1;
/// Audio operation: sample data in the previously announced format; a U32
/// length followed by that many bytes of sample data.
pub const AUDIO_OP_DATA: u8 = 2;

/// Header of a QEMU audio Start operation: sample format plus the length of
/// the sample data that follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioFormatHeader {
    pub sample_rate: u32,
    pub channels: u8,
    pub bits_per_sample: u8,
    /// Length of the sample data following the header, in bytes.
    pub data_len: u32,
}

impl AudioFormatHeader {
    /// Wire length of the header.
    pub const WIRE_LEN: usize = 10;

    /// Parse from the first [`Self::WIRE_LEN`] bytes of `buf`. Returns `None`
    /// when fewer bytes are available.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::WIRE_LEN {
            return None;
        }
        Some(Self {
            sample_rate: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            channels: buf[4],
            bits_per_sample: buf[5],
            data_len: u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]),
        })
    }

    /// Serialize to the 10-byte wire header.
    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut out = [0u8; Self::WIRE_LEN];
        out[0..4].copy_from_slice(&self.sample_rate.to_be_bytes());
        out[4] = self.channels;
        out[5] = self.bits_per_sample;
        out[6..10].copy_from_slice(&self.data_len.to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn led_state_bits() {
        assert_eq!(
            parse_led_state(0),
            LedState {
                scroll_lock: false,
                num_lock: false,
                caps_lock: false,
            }
        );
        assert_eq!(
            parse_led_state(LED_SCROLL_LOCK | LED_CAPS_LOCK),
            LedState {
                scroll_lock: true,
                num_lock: false,
                caps_lock: true,
            }
        );
        assert_eq!(
            parse_led_state(0xff),
            LedState {
                scroll_lock: true,
                num_lock: true,
                caps_lock: true,
            }
        );
    }

    #[test]
    fn audio_format_header_exact_bytes_and_roundtrip() {
        let header = AudioFormatHeader {
            sample_rate: 48_000,
            channels: 2,
            bits_per_sample: 16,
            data_len: 4096,
        };
        let bytes = header.to_bytes();
        assert_eq!(bytes, [0, 0, 0xbb, 0x80, 2, 16, 0, 0, 0x10, 0x00]);
        assert_eq!(AudioFormatHeader::parse(&bytes), Some(header));
        for len in 0..AudioFormatHeader::WIRE_LEN {
            assert!(
                AudioFormatHeader::parse(&bytes[..len]).is_none(),
                "len={}",
                len
            );
        }
    }
}
