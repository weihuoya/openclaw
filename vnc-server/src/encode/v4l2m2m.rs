//! V4L2 M2M hardware H.264 encoder (Adreno GPU via venus driver).
//!
//! Uses the Linux V4L2 Memory-to-Memory API to offload H.264 encoding to
//! hardware. Designed for Qualcomm Adreno GPUs on ROCKNIX (SM8550/SM8650)
//! where the encoder is exposed via the `venus` V4L2 driver.

// Low-level V4L2 ioctl wrappers have many positional arguments and repeatedly
// build ioctl structs field-by-field; suppress the corresponding style lints.
#![allow(clippy::field_reassign_with_default, clippy::too_many_arguments)]

use log::{info, warn};
use nix::errno::Errno;
use nix::sys::mman::{mmap, munmap, MapFlags, ProtFlags};
use nix::{ioctl_readwrite, ioctl_write_ptr_bad};
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::fd::{IntoRawFd, RawFd};
use vnc_protocol::encoding::Encoding;
use vnc_protocol::pixel_format::PixelFormat;
use vnc_protocol::rect::FbRect;

// V4L2 constants
const V4L2_CAP_VIDEO_M2M_MPLANE: u32 = 0x0000_8000;
const V4L2_CAP_DEVICE_CAPS: u32 = 0x8000_0000;

const V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE: u32 = 10;
const V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE: u32 = 12;
const V4L2_MEMORY_MMAP: u32 = 1;

const V4L2_PIX_FMT_NV12: u32 = 0x3231_564e;
const V4L2_PIX_FMT_H264: u32 = 0x3436_4831;
const V4L2_PIX_FMT_XRGB32: u32 = 0x4252_5848;
const V4L2_PIX_FMT_RGB32: u32 = 0x4247_5248;

const V4L2_FIELD_NONE: u32 = 1;

const V4L2_CID_MPEG_VIDEO_FORCE_KEY_FRAME: u32 = 0x0099_0907;
const V4L2_CID_MPEG_VIDEO_BITRATE: u32 = 0x0099_0901;

// V4L2 structures
#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
struct V4l2Capability {
    driver: [u8; 16],
    card: [u8; 32],
    bus_info: [u8; 32],
    version: u32,
    capabilities: u32,
    device_caps: u32,
    reserved: [u32; 3],
}

#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
struct V4l2PlanePixFormat {
    sizeimage: u32,
    bytesperline: u32,
    reserved: [u16; 6],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct V4l2PixFormatMplane {
    width: u32,
    height: u32,
    pixelformat: u32,
    field: u32,
    colorspace: u32,
    plane_fmt: [V4l2PlanePixFormat; 4],
    num_planes: u8,
    flags: u8,
    _union: [u8; 4],
    quantization: u8,
    xfer_func: u8,
    reserved: [u8; 7],
}

impl Default for V4l2PixFormatMplane {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
union V4l2FormatUnion {
    pix_mp: std::mem::ManuallyDrop<V4l2PixFormatMplane>,
    _raw: [u8; 200],
}

impl std::fmt::Debug for V4l2FormatUnion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V4l2FormatUnion").finish()
    }
}

impl Default for V4l2FormatUnion {
    fn default() -> Self {
        Self { _raw: [0; 200] }
    }
}

#[repr(C)]
#[derive(Default, Debug)]
struct V4l2Format {
    type_: u32,
    fmt: V4l2FormatUnion,
}

#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
struct V4l2Requestbuffers {
    count: u32,
    type_: u32,
    memory: u32,
    capabilities: u32,
    reserved: [u8; 1],
}

#[repr(C)]
union V4l2PlaneMemory {
    mem_offset: u32,
    userptr: u64,
    fd: i32,
    _reserved: [u8; 8],
}

impl std::fmt::Debug for V4l2PlaneMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V4l2PlaneMemory").finish()
    }
}

impl Clone for V4l2PlaneMemory {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for V4l2PlaneMemory {}

impl Default for V4l2PlaneMemory {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
struct V4l2Plane {
    bytesused: u32,
    length: u32,
    m: V4l2PlaneMemory,
    data_offset: u32,
    reserved: [u32; 11],
}

#[repr(C)]
union V4l2BufferMemory {
    offset: u32,
    userptr: u64,
    planes: *mut V4l2Plane,
    fd: i32,
    _reserved: [u8; 8],
}

impl std::fmt::Debug for V4l2BufferMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V4l2BufferMemory").finish()
    }
}

impl Clone for V4l2BufferMemory {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for V4l2BufferMemory {}

impl Default for V4l2BufferMemory {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
struct V4l2Timecode {
    type_: u32,
    flags: u32,
    frames: u8,
    seconds: u8,
    minutes: u8,
    hours: u8,
    userbits: [u8; 4],
}

#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
struct V4l2Buffer {
    index: u32,
    type_: u32,
    bytesused: u32,
    flags: u32,
    field: u32,
    timestamp: libc::timeval,
    timecode: V4l2Timecode,
    sequence: u32,
    memory: u32,
    m: V4l2BufferMemory,
    length: u32,
    reserved2: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
struct V4l2Control {
    id: u32,
    value: i32,
    _reserved: [u32; 2],
}

#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
struct V4l2EncoderCmd {
    cmd: u32,
    flags: u32,
    _raw: [u8; 8],
}

#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
struct V4l2Fmtdesc {
    index: u32,
    type_: u32,
    flags: u32,
    description: [u8; 32],
    pixelformat: u32,
    mbus_code: u32,
    reserved: [u32; 3],
}

// ioctl definitions
ioctl_readwrite!(vidioc_querycap, b'V', 0, V4l2Capability);
ioctl_readwrite!(vidioc_enum_fmt, b'V', 2, V4l2Fmtdesc);
ioctl_readwrite!(vidioc_g_fmt, b'V', 4, V4l2Format);
ioctl_readwrite!(vidioc_s_fmt, b'V', 5, V4l2Format);
ioctl_readwrite!(vidioc_reqbufs, b'V', 8, V4l2Requestbuffers);
ioctl_readwrite!(vidioc_querybuf, b'V', 9, V4l2Buffer);
ioctl_readwrite!(vidioc_qbuf, b'V', 15, V4l2Buffer);
ioctl_readwrite!(vidioc_dqbuf, b'V', 17, V4l2Buffer);
ioctl_write_ptr_bad!(vidioc_streamon, 18, u32);
ioctl_write_ptr_bad!(vidioc_streamoff, 19, u32);
ioctl_readwrite!(vidioc_s_ctrl, b'V', 28, V4l2Control);
ioctl_readwrite!(vidioc_encoder_cmd, b'V', 45, V4l2EncoderCmd);

const N_SRC_BUFS: usize = 3;
const N_DST_BUFS: usize = 3;
const HD_THRESHOLD: u16 = 720;

struct MmapPlane {
    ptr: std::ptr::NonNull<libc::c_void>,
    length: usize,
}

struct MmapBuffer {
    index: u32,
    type_: u32,
    memory: u32,
    n_planes: usize,
    planes: Vec<MmapPlane>,
    v4l2_planes: Vec<V4l2Plane>,
}

pub struct V4l2M2mEncoder {
    fd: RawFd,
    src_type: u32,
    dst_type: u32,
    src_pixfmt: u32,
    src_buffers: Vec<MmapBuffer>,
    dst_buffers: Vec<MmapBuffer>,
    nv12_buffer: Vec<u8>,
    free_src_bufs: VecDeque<usize>,
    pts: u64,
    next_frame_is_keyframe: bool,
    target_bitrate: u32,
}

impl Drop for V4l2M2mEncoder {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl V4l2M2mEncoder {
    pub fn new(width: u32, height: u32) -> Option<Self> {
        let device = Self::probe_device()?;
        Self::new_with_device(width, height, &device)
    }

    fn probe_device() -> Option<String> {
        for i in 0..64 {
            let path = format!("/dev/video{}", i);
            let cpath = CString::new(path.clone()).unwrap();
            let fd = match nix::fcntl::open(
                cpath.as_c_str(),
                nix::fcntl::OFlag::O_RDWR | nix::fcntl::OFlag::O_NONBLOCK,
                nix::sys::stat::Mode::empty(),
            ) {
                Ok(fd) => fd.into_raw_fd(),
                Err(_) => continue,
            };

            let mut cap = V4l2Capability::default();
            let rc = unsafe { vidioc_querycap(fd, &mut cap) };
            if rc.is_ok() {
                let caps = if cap.capabilities & V4L2_CAP_DEVICE_CAPS != 0 {
                    cap.device_caps
                } else {
                    cap.capabilities
                };

                if caps & V4L2_CAP_VIDEO_M2M_MPLANE != 0 {
                    let driver = String::from_utf8_lossy(&cap.driver);
                    let card = String::from_utf8_lossy(&cap.card);
                    info!(
                        "Found V4L2 M2M device: {} (driver={}, card={})",
                        path,
                        driver.trim_end_matches('\0'),
                        card.trim_end_matches('\0')
                    );
                    let _ = nix::unistd::close(fd);
                    return Some(path);
                }
            }
            let _ = nix::unistd::close(fd);
        }
        None
    }

    fn new_with_device(width: u32, height: u32, device: &str) -> Option<Self> {
        let cdevice = CString::new(device.to_string()).unwrap();
        let fd = match nix::fcntl::open(
            cdevice.as_c_str(),
            nix::fcntl::OFlag::O_RDWR | nix::fcntl::OFlag::O_NONBLOCK,
            nix::sys::stat::Mode::empty(),
        ) {
            Ok(fd) => fd.into_raw_fd(),
            Err(e) => {
                warn!("Failed to open {}: {}", device, e);
                return None;
            }
        };

        let src_type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
        let dst_type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;

        let src_pixfmt = match Self::select_src_format(fd, src_type, width, height) {
            Some(fmt) => fmt,
            None => {
                warn!("No suitable source format for V4L2 M2M encoder");
                let _ = nix::unistd::close(fd);
                return None;
            }
        };

        if let Err(e) = Self::set_dst_format(fd, dst_type, width, height) {
            warn!("Failed to set V4L2 M2M destination format: {}", e);
            let _ = nix::unistd::close(fd);
            return None;
        }

        let src_buffers = match Self::alloc_src_buffers(fd, src_type, src_pixfmt, width, height) {
            Ok(buffers) => buffers,
            Err(e) => {
                warn!("Failed to allocate V4L2 M2M source buffers: {}", e);
                let _ = nix::unistd::close(fd);
                return None;
            }
        };

        let dst_buffers = match Self::alloc_dst_buffers(fd, dst_type) {
            Ok(buffers) => buffers,
            Err(e) => {
                warn!("Failed to allocate V4L2 M2M destination buffers: {}", e);
                let _ = nix::unistd::close(fd);
                return None;
            }
        };

        // Queue all destination buffers.
        for buf in &dst_buffers {
            let mut v4l2_buf = V4l2Buffer::default();
            v4l2_buf.index = buf.index;
            v4l2_buf.type_ = buf.type_;
            v4l2_buf.memory = buf.memory;
            v4l2_buf.length = buf.n_planes as u32;
            if !buf.v4l2_planes.is_empty() {
                v4l2_buf.m = V4l2BufferMemory {
                    planes: buf.v4l2_planes.as_ptr() as *mut V4l2Plane,
                };
            }
            if let Err(e) = unsafe { vidioc_qbuf(fd, &mut v4l2_buf) } {
                warn!("Failed to queue dst buffer {}: {}", buf.index, e);
            }
        }

        if let Err(e) = unsafe { vidioc_streamon(fd, &src_type) } {
            warn!("VIDIOC_STREAMON (src) failed: {}", e);
        }
        if let Err(e) = unsafe { vidioc_streamon(fd, &dst_type) } {
            warn!("VIDIOC_STREAMON (dst) failed: {}", e);
        }

        let nv12_size = (width as usize * height as usize * 3) / 2;
        let mut free_src_bufs = VecDeque::new();
        for i in 0..src_buffers.len() {
            free_src_bufs.push_back(i);
        }

        info!(
            "V4L2 M2M encoder ready: {}x{} -> {} ({} src bufs, {} dst bufs)",
            width,
            height,
            device,
            src_buffers.len(),
            dst_buffers.len()
        );

        Some(Self {
            fd,
            src_type,
            dst_type,
            src_pixfmt,
            src_buffers,
            dst_buffers,
            nv12_buffer: vec![0u8; nv12_size],
            free_src_bufs,
            pts: 0,
            next_frame_is_keyframe: true,
            target_bitrate: 2_000_000,
        })
    }

    fn select_src_format(fd: RawFd, src_type: u32, width: u32, height: u32) -> Option<u32> {
        let mut formats = Vec::new();
        for i in 0..256 {
            let mut fmtdesc = V4l2Fmtdesc::default();
            fmtdesc.index = i;
            fmtdesc.type_ = src_type;
            if unsafe { vidioc_enum_fmt(fd, &mut fmtdesc) }.is_err() {
                break;
            }
            formats.push(fmtdesc.pixelformat);
        }

        // NV12 is the only currently implemented source path; prefer it over
        // direct XRGB/RGB32 until the direct path is wired up.
        if formats.contains(&V4L2_PIX_FMT_NV12)
            && Self::set_src_format(fd, src_type, V4L2_PIX_FMT_NV12, width, height).is_ok()
        {
            info!("V4L2 M2M using NV12 source format (CPU conversion required)");
            return Some(V4L2_PIX_FMT_NV12);
        }

        let direct_fmts = [V4L2_PIX_FMT_XRGB32, V4L2_PIX_FMT_RGB32];
        for &fmt in &direct_fmts {
            if formats.contains(&fmt)
                && Self::set_src_format(fd, src_type, fmt, width, height).is_ok()
            {
                info!("V4L2 M2M using direct source format: {:#010x}", fmt);
                return Some(fmt);
            }
        }

        None
    }

    fn set_src_format(
        fd: RawFd,
        src_type: u32,
        pixfmt: u32,
        width: u32,
        height: u32,
    ) -> Result<(), nix::Error> {
        let mut fmt = V4l2Format::default();
        fmt.type_ = src_type;
        unsafe { vidioc_g_fmt(fd, &mut fmt)? };

        unsafe {
            (*fmt.fmt.pix_mp).width = width;
            (*fmt.fmt.pix_mp).height = height;
            (*fmt.fmt.pix_mp).pixelformat = pixfmt;
            (*fmt.fmt.pix_mp).field = V4L2_FIELD_NONE;
        }

        unsafe { vidioc_s_fmt(fd, &mut fmt)? };
        Ok(())
    }

    fn set_dst_format(fd: RawFd, dst_type: u32, width: u32, height: u32) -> Result<(), nix::Error> {
        let mut fmt = V4l2Format::default();
        fmt.type_ = dst_type;
        unsafe { vidioc_g_fmt(fd, &mut fmt)? };

        unsafe {
            (*fmt.fmt.pix_mp).width = width;
            (*fmt.fmt.pix_mp).height = height;
            (*fmt.fmt.pix_mp).pixelformat = V4L2_PIX_FMT_H264;
            (*fmt.fmt.pix_mp).field = V4L2_FIELD_NONE;
        }

        unsafe { vidioc_s_fmt(fd, &mut fmt)? };
        Ok(())
    }

    fn alloc_src_buffers(
        fd: RawFd,
        src_type: u32,
        pixfmt: u32,
        _width: u32,
        _height: u32,
    ) -> Result<Vec<MmapBuffer>, nix::Error> {
        let mut req = V4l2Requestbuffers::default();
        req.count = N_SRC_BUFS as u32;
        req.type_ = src_type;
        req.memory = V4L2_MEMORY_MMAP;
        unsafe { vidioc_reqbufs(fd, &mut req)? };

        let n_planes = if pixfmt == V4L2_PIX_FMT_NV12 { 2 } else { 1 };
        let mut buffers = Vec::with_capacity(req.count as usize);

        for i in 0..req.count {
            let mut v4l2_planes = vec![V4l2Plane::default(); n_planes];
            let mut buf = V4l2Buffer::default();
            buf.index = i;
            buf.type_ = src_type;
            buf.memory = V4L2_MEMORY_MMAP;
            buf.length = n_planes as u32;
            buf.m = V4l2BufferMemory {
                planes: v4l2_planes.as_mut_ptr(),
            };

            unsafe { vidioc_querybuf(fd, &mut buf)? };

            let mut planes = Vec::with_capacity(n_planes);
            for plane in v4l2_planes.iter_mut().take(n_planes) {
                let len = plane.length as usize;
                if len == 0 {
                    return Err(nix::Error::from(Errno::EINVAL));
                }
                let len_nonzero =
                    std::num::NonZero::new(len).ok_or_else(|| nix::Error::from(Errno::EINVAL))?;
                let offset = unsafe { plane.m.mem_offset };
                let ptr = unsafe {
                    mmap(
                        None,
                        len_nonzero,
                        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                        MapFlags::MAP_SHARED,
                        std::os::fd::BorrowedFd::borrow_raw(fd),
                        offset as libc::off_t,
                    )?
                };
                planes.push(MmapPlane { ptr, length: len });
            }

            buffers.push(MmapBuffer {
                index: i,
                type_: src_type,
                memory: V4L2_MEMORY_MMAP,
                n_planes,
                planes,
                v4l2_planes,
            });
        }

        Ok(buffers)
    }

    fn alloc_dst_buffers(fd: RawFd, dst_type: u32) -> Result<Vec<MmapBuffer>, nix::Error> {
        let mut req = V4l2Requestbuffers::default();
        req.count = N_DST_BUFS as u32;
        req.type_ = dst_type;
        req.memory = V4L2_MEMORY_MMAP;
        unsafe { vidioc_reqbufs(fd, &mut req)? };

        let mut buffers = Vec::with_capacity(req.count as usize);

        for i in 0..req.count {
            let mut v4l2_planes = vec![V4l2Plane::default(); 1];
            let mut buf = V4l2Buffer::default();
            buf.index = i;
            buf.type_ = dst_type;
            buf.memory = V4L2_MEMORY_MMAP;
            buf.length = 1;
            buf.m = V4l2BufferMemory {
                planes: v4l2_planes.as_mut_ptr(),
            };

            unsafe { vidioc_querybuf(fd, &mut buf)? };

            let len = v4l2_planes[0].length as usize;
            if len == 0 {
                return Err(nix::Error::from(Errno::EINVAL));
            }
            let len_nonzero =
                std::num::NonZero::new(len).ok_or_else(|| nix::Error::from(Errno::EINVAL))?;
            let offset = unsafe { v4l2_planes[0].m.mem_offset };
            let ptr = unsafe {
                mmap(
                    None,
                    len_nonzero,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    MapFlags::MAP_SHARED,
                    std::os::fd::BorrowedFd::borrow_raw(fd),
                    offset as libc::off_t,
                )?
            };

            buffers.push(MmapBuffer {
                index: i,
                type_: dst_type,
                memory: V4L2_MEMORY_MMAP,
                n_planes: 1,
                planes: vec![MmapPlane { ptr, length: len }],
                v4l2_planes,
            });
        }

        Ok(buffers)
    }

    pub fn request_keyframe(&mut self) {
        self.next_frame_is_keyframe = true;
    }

    pub fn set_bandwidth(&mut self, bandwidth_bps: f64) {
        if bandwidth_bps <= 0.0 {
            return;
        }
        let new_bitrate = ((bandwidth_bps * 0.7) as u32).clamp(128_000, 20_000_000);
        if (new_bitrate as i64 - self.target_bitrate as i64).abs()
            > (self.target_bitrate / 10) as i64
        {
            self.target_bitrate = new_bitrate;
            let mut ctrl = V4l2Control::default();
            ctrl.id = V4L2_CID_MPEG_VIDEO_BITRATE;
            ctrl.value = self.target_bitrate as i32;
            if let Err(e) = unsafe { vidioc_s_ctrl(self.fd, &mut ctrl) } {
                warn!("Failed to set V4L2 bitrate: {}", e);
            }
        }
    }

    pub fn reset(&mut self, width: u32, height: u32) {
        self.shutdown();
        // If encoder recreation fails, leave fd invalid so subsequent encode()
        // calls return empty instead of using a closed descriptor.
        self.fd = -1;
        if let Some(new) = Self::new(width, height) {
            *self = new;
        }
    }

    fn shutdown(&mut self) {
        let _ = unsafe { vidioc_streamoff(self.fd, &self.src_type) };
        let _ = unsafe { vidioc_streamoff(self.fd, &self.dst_type) };

        for buf in &self.src_buffers {
            for plane in &buf.planes {
                let _ = unsafe { munmap(plane.ptr, plane.length) };
            }
        }
        for buf in &self.dst_buffers {
            for plane in &buf.planes {
                let _ = unsafe { munmap(plane.ptr, plane.length) };
            }
        }

        let mut req = V4l2Requestbuffers::default();
        req.count = 0;
        req.type_ = self.src_type;
        req.memory = V4L2_MEMORY_MMAP;
        let _ = unsafe { vidioc_reqbufs(self.fd, &mut req) };

        req.type_ = self.dst_type;
        let _ = unsafe { vidioc_reqbufs(self.fd, &mut req) };

        let _ = nix::unistd::close(self.fd);
    }

    pub fn encode(
        &mut self,
        src: &[u8],
        src_stride: usize,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        _dst_format: &PixelFormat,
    ) -> FbRect {
        if self.fd < 0 {
            warn!("V4L2 M2M: encode called with invalid fd");
            return FbRect {
                x,
                y,
                width,
                height,
                encoding: Encoding::OpenH264,
                data: Vec::new(),
            };
        }

        let src_buf_idx = match self.free_src_bufs.pop_front() {
            Some(idx) => idx,
            None => {
                self.reclaim_src_buffers();
                match self.free_src_bufs.pop_front() {
                    Some(idx) => idx,
                    None => {
                        warn!("V4L2 M2M: no free source buffers, dropping frame");
                        return FbRect {
                            x,
                            y,
                            width,
                            height,
                            encoding: Encoding::OpenH264,
                            data: Vec::new(),
                        };
                    }
                }
            }
        };

        if self.src_pixfmt == V4L2_PIX_FMT_NV12 {
            self.convert_xrgb_to_nv12(src, src_stride, x, y, width, height);
        }

        let src_buf = &mut self.src_buffers[src_buf_idx];
        if self.src_pixfmt == V4L2_PIX_FMT_NV12 {
            let y_size = width as usize * height as usize;
            let uv_size = y_size / 2;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    self.nv12_buffer.as_ptr(),
                    src_buf.planes[0].ptr.as_ptr() as *mut u8,
                    y_size,
                );
                if src_buf.n_planes > 1 {
                    std::ptr::copy_nonoverlapping(
                        self.nv12_buffer.as_ptr().add(y_size),
                        src_buf.planes[1].ptr.as_ptr() as *mut u8,
                        uv_size,
                    );
                } else {
                    std::ptr::copy_nonoverlapping(
                        self.nv12_buffer.as_ptr().add(y_size),
                        (src_buf.planes[0].ptr.as_ptr() as *mut u8).add(y_size),
                        uv_size,
                    );
                }
            }
            src_buf.v4l2_planes[0].bytesused = y_size as u32;
            if src_buf.n_planes > 1 {
                src_buf.v4l2_planes[1].bytesused = uv_size as u32;
            }
        } else {
            warn!("V4L2 M2M: direct XRGB path not implemented");
        }

        if self.next_frame_is_keyframe {
            let mut ctrl = V4l2Control::default();
            ctrl.id = V4L2_CID_MPEG_VIDEO_FORCE_KEY_FRAME;
            ctrl.value = 1;
            let _ = unsafe { vidioc_s_ctrl(self.fd, &mut ctrl) };
            self.next_frame_is_keyframe = false;
        }

        let mut buf = V4l2Buffer::default();
        buf.index = src_buf.index;
        buf.type_ = src_buf.type_;
        buf.memory = src_buf.memory;
        buf.length = src_buf.n_planes as u32;
        buf.m = V4l2BufferMemory {
            planes: src_buf.v4l2_planes.as_mut_ptr(),
        };
        buf.timestamp = libc::timeval {
            tv_sec: (self.pts / 1_000_000) as libc::time_t,
            tv_usec: (self.pts % 1_000_000) as libc::suseconds_t,
        };

        if let Err(e) = unsafe { vidioc_qbuf(self.fd, &mut buf) } {
            warn!("V4L2 M2M: QBUF src failed: {}", e);
            self.free_src_bufs.push_back(src_buf_idx);
            return FbRect {
                x,
                y,
                width,
                height,
                encoding: Encoding::OpenH264,
                data: Vec::new(),
            };
        }

        self.pts += 1;

        let mut data = Vec::new();
        let mut pollfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // Non-blocking poll: the server main loop is single-threaded, so a
        // blocking wait here would stall all other clients and Wayland events.
        // If the encoded frame is not ready yet we return empty and the caller
        // can retry on the next iteration.
        let rc = unsafe { libc::poll(&mut pollfd, 1, 0) };
        if rc > 0 && pollfd.revents & libc::POLLIN != 0 {
            let mut plane = V4l2Plane::default();
            let mut dst_buf = V4l2Buffer::default();
            dst_buf.type_ = self.dst_type;
            dst_buf.memory = V4L2_MEMORY_MMAP;
            dst_buf.length = 1;
            dst_buf.m = V4l2BufferMemory { planes: &mut plane };

            if unsafe { vidioc_dqbuf(self.fd, &mut dst_buf) }.is_ok() {
                let size = plane.bytesused as usize;
                if size > 0 {
                    let dst_buf_ref = &self.dst_buffers[dst_buf.index as usize];
                    data = unsafe {
                        std::slice::from_raw_parts(
                            dst_buf_ref.planes[0].ptr.as_ptr() as *const u8,
                            size,
                        )
                    }
                    .to_vec();
                }

                let mut requeue = V4l2Buffer::default();
                requeue.index = dst_buf.index;
                requeue.type_ = self.dst_type;
                requeue.memory = V4L2_MEMORY_MMAP;
                requeue.length = 1;
                requeue.m = V4l2BufferMemory { planes: &mut plane };
                let _ = unsafe { vidioc_qbuf(self.fd, &mut requeue) };
            }
        }

        self.reclaim_src_buffers();

        FbRect {
            x,
            y,
            width,
            height,
            encoding: Encoding::OpenH264,
            data,
        }
    }

    fn reclaim_src_buffers(&mut self) {
        loop {
            let mut planes = [V4l2Plane::default(); 4];
            let mut buf = V4l2Buffer::default();
            buf.type_ = self.src_type;
            buf.memory = V4L2_MEMORY_MMAP;
            buf.length = 4;
            buf.m = V4l2BufferMemory {
                planes: planes.as_mut_ptr(),
            };

            match unsafe { vidioc_dqbuf(self.fd, &mut buf) } {
                Ok(_) => {
                    self.free_src_bufs.push_back(buf.index as usize);
                }
                Err(_) => break,
            }
        }
    }

    fn convert_xrgb_to_nv12(
        &mut self,
        src: &[u8],
        src_stride: usize,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) {
        let w = width as usize;
        let h = height as usize;
        let y_size = w * h;
        let uv_size = y_size / 2;

        self.nv12_buffer[0..y_size].fill(0);
        self.nv12_buffer[y_size..y_size + uv_size].fill(128);

        let use_bt709 = width > HD_THRESHOLD || height > HD_THRESHOLD;
        let (ry, gy, by, ru, gu, bu, rv, gv, bv) = if use_bt709 {
            (54, 183, 19, -29, -99, 128, 128, -116, -12)
        } else {
            (66, 129, 25, -38, -74, 112, 112, -94, -18)
        };

        let x_usize = x as usize;
        let y_usize = y as usize;

        for row in (0..h).step_by(2) {
            let row0 = row;
            let row1 = (row + 1).min(h - 1);

            let src_y0 = y_usize + row0;
            let src_y1 = y_usize + row1;
            let src_off0 = src_y0 * src_stride + x_usize * 4;
            let src_off1 = src_y1 * src_stride + x_usize * 4;

            let dst_y_row0 = row0 * w;
            let dst_y_row1 = row1 * w;
            let dst_uv_row = (row0 / 2) * w;

            for col in (0..w).step_by(2) {
                let col0 = col;
                let col1 = (col + 1).min(w - 1);

                let p00_off = src_off0 + col0 * 4;
                let p01_off = src_off0 + col1 * 4;
                let p10_off = src_off1 + col0 * 4;
                let p11_off = src_off1 + col1 * 4;

                let b00 = src[p00_off] as i32;
                let g00 = src[p00_off + 1] as i32;
                let r00 = src[p00_off + 2] as i32;
                let b01 = src[p01_off] as i32;
                let g01 = src[p01_off + 1] as i32;
                let r01 = src[p01_off + 2] as i32;
                let b10 = src[p10_off] as i32;
                let g10 = src[p10_off + 1] as i32;
                let r10 = src[p10_off + 2] as i32;
                let b11 = src[p11_off] as i32;
                let g11 = src[p11_off + 1] as i32;
                let r11 = src[p11_off + 2] as i32;

                let y00 = ((ry * r00 + gy * g00 + by * b00 + 128) >> 8) + 16;
                let y01 = ((ry * r01 + gy * g01 + by * b01 + 128) >> 8) + 16;
                let y10 = ((ry * r10 + gy * g10 + by * b10 + 128) >> 8) + 16;
                let y11 = ((ry * r11 + gy * g11 + by * b11 + 128) >> 8) + 16;

                self.nv12_buffer[dst_y_row0 + col0] = y00.clamp(0, 255) as u8;
                self.nv12_buffer[dst_y_row0 + col1] = y01.clamp(0, 255) as u8;
                self.nv12_buffer[dst_y_row1 + col0] = y10.clamp(0, 255) as u8;
                self.nv12_buffer[dst_y_row1 + col1] = y11.clamp(0, 255) as u8;

                let r_avg = (r00 + r01 + r10 + r11) >> 2;
                let g_avg = (g00 + g01 + g10 + g11) >> 2;
                let b_avg = (b00 + b01 + b10 + b11) >> 2;

                let u_val = ((ru * r_avg + gu * g_avg + bu * b_avg + 128) >> 8) + 128;
                let v_val = ((rv * r_avg + gv * g_avg + bv * b_avg + 128) >> 8) + 128;

                let uv_off = dst_uv_row + col0;
                self.nv12_buffer[y_size + uv_off] = u_val.clamp(0, 255) as u8;
                self.nv12_buffer[y_size + uv_off + 1] = v_val.clamp(0, 255) as u8;
            }
        }
    }
}
