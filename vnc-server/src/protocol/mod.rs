//! RFB protocol constants, types, and message structures.

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

pub const RFB_VERSION: &[u8] = b"RFB 003.008\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecurityType {
    Invalid = 0,
    None = 1,
    VncAuth = 2,
    RsaAes = 5,
    Tight = 16,
    VeNCrypt = 19,
    AppleDh = 30,
    RsaAes256 = 129,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Encoding {
    Raw = 0,
    CopyRect = 1,
    Rre = 2,
    Hextile = 5,
    Tight = 7,
    Trle = 15,
    Zrle = 16,
    OpenH264 = 50,
    Cursor = -239i32 as u32,
    DesktopSize = -223i32 as u32,
    DesktopName = -307i32 as u32,
    ExtendedDesktopSize = -308i32 as u32,
    Fence = -312i32 as u32,
    ContinuousUpdates = -313i32 as u32,
    ExtMouseButtons = -316i32 as u32,
    QemuExtKeyEvent = -258i32 as u32,
    ExtendedClipboard = -1063131698i32 as u32,
}

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

/// RFB pixel format descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PixelFormat {
    pub bits_per_pixel: u8,
    pub depth: u8,
    pub big_endian: bool,
    pub true_colour: bool,
    pub red_max: u16,
    pub green_max: u16,
    pub blue_max: u16,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

impl Default for PixelFormat {
    fn default() -> Self {
        // XRGB8888 / little-endian
        Self {
            bits_per_pixel: 32,
            depth: 24,
            big_endian: false,
            true_colour: true,
            red_max: 255,
            green_max: 255,
            blue_max: 255,
            red_shift: 16,
            green_shift: 8,
            blue_shift: 0,
        }
    }
}

impl PixelFormat {
    pub fn read<R: Read>(r: &mut R) -> std::io::Result<Self> {
        Ok(Self {
            bits_per_pixel: r.read_u8()?,
            depth: r.read_u8()?,
            big_endian: r.read_u8()? != 0,
            true_colour: r.read_u8()? != 0,
            red_max: r.read_u16::<BigEndian>()?,
            green_max: r.read_u16::<BigEndian>()?,
            blue_max: r.read_u16::<BigEndian>()?,
            red_shift: r.read_u8()?,
            green_shift: r.read_u8()?,
            blue_shift: r.read_u8()?,
        })
    }

    pub fn write<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_u8(self.bits_per_pixel)?;
        w.write_u8(self.depth)?;
        w.write_u8(self.big_endian as u8)?;
        w.write_u8(self.true_colour as u8)?;
        w.write_u16::<BigEndian>(self.red_max)?;
        w.write_u16::<BigEndian>(self.green_max)?;
        w.write_u16::<BigEndian>(self.blue_max)?;
        w.write_u8(self.red_shift)?;
        w.write_u8(self.green_shift)?;
        w.write_u8(self.blue_shift)?;
        w.write_all(&[0; 3])?; // padding
        Ok(())
    }

    pub fn bytes_per_pixel(&self) -> usize {
        (self.bits_per_pixel as usize).div_ceil(8)
    }
}

/// A rectangle within a framebuffer update.
#[derive(Debug, Clone)]
pub struct FbRect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
    pub encoding: Encoding,
    pub data: Vec<u8>,
}

impl FbRect {
    pub fn write_header<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_u16::<BigEndian>(self.x)?;
        w.write_u16::<BigEndian>(self.y)?;
        w.write_u16::<BigEndian>(self.width)?;
        w.write_u16::<BigEndian>(self.height)?;
        w.write_i32::<BigEndian>(self.encoding as i32)?;
        Ok(())
    }
}

/// Server-init message payload.
pub struct ServerInit {
    pub width: u16,
    pub height: u16,
    pub pixel_format: PixelFormat,
    pub name: String,
}

impl ServerInit {
    pub fn write<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_u16::<BigEndian>(self.width)?;
        w.write_u16::<BigEndian>(self.height)?;
        self.pixel_format.write(w)?;
        w.write_u32::<BigEndian>(self.name.len() as u32)?;
        w.write_all(self.name.as_bytes())?;
        Ok(())
    }
}

/// Security result codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SecurityResult {
    Ok = 0,
    Failed = 1,
}
