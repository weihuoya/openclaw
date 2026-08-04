//! Frame capture and feed loop.

use std::num::NonZero;
use std::os::fd::{AsFd, OwnedFd};
use std::ptr::NonNull;

use log::{debug, error, info, warn};
#[allow(deprecated)]
use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use nix::sys::mman::{mmap, munmap, MapFlags, ProtFlags};
use nix::unistd::ftruncate;
use wayland_client::protocol::wl_buffer::WlBuffer;
use wayland_client::protocol::wl_output::WlOutput;
use wayland_client::protocol::wl_shm::Format;
use wayland_client::protocol::wl_shm::WlShm;
use wayland_client::protocol::wl_shm_pool::WlShmPool;
use wayland_client::{Connection, EventQueue, QueueHandle};
use wayland_protocols_wlr::screencopy::v1::client::zwlr_screencopy_frame_v1::ZwlrScreencopyFrameV1;
use wayland_protocols_wlr::screencopy::v1::client::zwlr_screencopy_manager_v1::ZwlrScreencopyManagerV1;

use crate::wayland::wayland_ctx::WaylandState;

/// Captured framebuffer data.
pub struct FrameData {
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: u32, // DRM fourcc
}

/// State for a single capture buffer with mmap-backed SHM.
struct CaptureBuffer {
    #[allow(dead_code)]
    buffer: WlBuffer,
    #[allow(dead_code)]
    pool: WlShmPool,
    mmap_ptr: *mut u8,
    size: usize,
    #[allow(dead_code)]
    width: u32,
    #[allow(dead_code)]
    height: u32,
    #[allow(dead_code)]
    stride: u32,
    in_use: bool,
}

impl CaptureBuffer {
    fn new(
        shm: &WlShm,
        width: u32,
        height: u32,
        stride: u32,
        format: Format,
        qh: &QueueHandle<WaylandState>,
    ) -> Result<Self, String> {
        let size = (stride * height) as usize;

        let fd = create_memfd(size)?;

        let pool = shm.create_pool(fd.as_fd(), size as i32, qh, ());
        let buffer = pool.create_buffer(
            0,
            width as i32,
            height as i32,
            stride as i32,
            format,
            qh,
            (),
        );

        // mmap the memfd so compositor writes are visible to us
        let mmap_ptr = unsafe {
            let ptr = mmap(
                None,
                NonZero::new(size).unwrap(),
                ProtFlags::PROT_READ,
                MapFlags::MAP_SHARED,
                &fd,
                0,
            )
            .map_err(|e| format!("mmap failed: {}", e))?;
            ptr.as_ptr() as *mut u8
        };

        Ok(Self {
            buffer,
            pool,
            mmap_ptr,
            size,
            width,
            height,
            stride,
            in_use: false,
        })
    }

    /// Copy frame data from mmap to a Vec<u8> for VNC encoding.
    fn read_data(&self) -> Vec<u8> {
        unsafe { std::slice::from_raw_parts(self.mmap_ptr, self.size).to_vec() }
    }
}

impl Drop for CaptureBuffer {
    fn drop(&mut self) {
        if !self.mmap_ptr.is_null() {
            unsafe {
                let ptr = NonNull::new(self.mmap_ptr as *mut std::ffi::c_void).unwrap();
                munmap(ptr, self.size).ok();
            }
        }
    }
}

#[allow(deprecated)]
fn create_memfd(size: usize) -> Result<OwnedFd, String> {
    let fd = memfd_create(
        c"vnc-server-shm",
        MemFdCreateFlag::MFD_CLOEXEC | MemFdCreateFlag::MFD_ALLOW_SEALING,
    )
    .map_err(|e| format!("Failed to create memfd: {}", e))?;

    ftruncate(&fd, size as i64).map_err(|e| format!("Failed to truncate memfd: {}", e))?;

    Ok(fd)
}

/// Frame capture manager.
pub struct CaptureManager {
    manager: ZwlrScreencopyManagerV1,
    output: WlOutput,
    #[allow(dead_code)]
    shm: WlShm,
    buffers: Vec<CaptureBuffer>,
    current_capture: Option<CurrentCapture>,
    width: u32,
    height: u32,
    stride: u32,
}

struct CurrentCapture {
    buffer_idx: usize,
    #[allow(dead_code)]
    frame: ZwlrScreencopyFrameV1,
    ready: bool,
    failed: bool,
}

impl CaptureManager {
    pub fn new(
        manager: &ZwlrScreencopyManagerV1,
        output: &WlOutput,
        shm: &WlShm,
        width: u32,
        height: u32,
        qh: &QueueHandle<WaylandState>,
    ) -> Result<Self, String> {
        let stride = width * 4;
        let mut buffers = Vec::with_capacity(2);
        for _ in 0..2 {
            buffers.push(CaptureBuffer::new(
                shm,
                width,
                height,
                stride,
                Format::Xrgb8888,
                qh,
            )?);
        }

        Ok(Self {
            manager: manager.clone(),
            output: output.clone(),
            shm: shm.clone(),
            buffers,
            current_capture: None,
            width,
            height,
            stride,
        })
    }

    /// Start a new frame capture if one isn't already in progress.
    pub fn start_capture(&mut self, qh: &QueueHandle<WaylandState>, overlay_cursor: bool) -> bool {
        if self.current_capture.is_some() {
            return false;
        }

        let idx = match self.buffers.iter().position(|b| !b.in_use) {
            Some(i) => i,
            None => {
                warn!("No free capture buffers");
                return false;
            }
        };

        let buf = &mut self.buffers[idx];
        buf.in_use = true;

        let frame =
            self.manager
                .capture_output(if overlay_cursor { 1 } else { 0 }, &self.output, qh, ());

        frame.copy(&buf.buffer);

        self.current_capture = Some(CurrentCapture {
            buffer_idx: idx,
            frame,
            ready: false,
            failed: false,
        });

        true
    }

    /// Called when a frame capture succeeds.
    pub fn on_frame_ready(&mut self) {
        if let Some(ref mut cap) = self.current_capture {
            cap.ready = true;
        }
    }

    /// Called when a frame capture fails.
    pub fn on_frame_failed(&mut self) {
        if let Some(ref mut cap) = self.current_capture {
            cap.failed = true;
        }
    }

    /// Check if the current capture is complete.
    pub fn is_complete(&self) -> bool {
        self.current_capture
            .as_ref()
            .is_some_and(|c| c.ready || c.failed)
    }

    /// Take the completed framebuffer if ready.
    pub fn take_framebuffer(&mut self) -> Option<FrameData> {
        let cap = self.current_capture.take()?;
        let buf = &mut self.buffers[cap.buffer_idx];
        buf.in_use = false;

        if cap.failed {
            return None;
        }

        // Read from mmap'd memory (compositor has written here)
        let data = buf.read_data();

        Some(FrameData {
            data,
            width: self.width,
            height: self.height,
            stride: self.stride,
            format: 0x34325258, // DRM_FORMAT_XRGB8888
        })
    }
}

/// Run the capture loop feeding frames to a callback.
#[allow(dead_code)]
pub fn run_capture_loop<F>(
    conn: &Connection,
    queue: &mut EventQueue<WaylandState>,
    state: &mut WaylandState,
    output_name: Option<&str>,
    max_rate: u32,
    overlay_cursor: bool,
    mut on_frame: F,
) where
    F: FnMut(&FrameData),
{
    use std::time::{Duration, Instant};
    let Some(ref screencopy_mgr) = state.screencopy_manager else {
        error!("No screencopy manager available");
        return;
    };
    let Some(ref shm) = state.shm else {
        error!("No SHM available");
        return;
    };

    let output_info = match output_name {
        Some(name) => state.outputs.iter().find(|o| o.name == name).cloned(),
        None => state.outputs.first().cloned(),
    };

    let Some(ref info) = output_info else {
        error!("No output available for capture");
        return;
    };

    let Some(ref output) = info.wl_output else {
        error!("Output proxy not available");
        return;
    };

    let width = info.width.max(1) as u32;
    let height = info.height.max(1) as u32;

    info!("Capturing output '{}' at {}x{}", info.name, width, height);

    let mut capture_mgr =
        match CaptureManager::new(screencopy_mgr, output, shm, width, height, &queue.handle()) {
            Ok(m) => m,
            Err(e) => {
                error!("Failed to create capture manager: {}", e);
                return;
            }
        };

    let frame_interval = Duration::from_millis(1000 / max_rate.max(1) as u64);
    let mut last_capture = Instant::now();
    let mut pending = false;

    while *state.running.lock().unwrap() {
        match queue.dispatch_pending(state) {
            Ok(_) => {}
            Err(e) => {
                error!("Wayland dispatch error: {}", e);
                break;
            }
        }

        if queue.prepare_read().is_some() {
            conn.flush().ok();
        }

        if pending && capture_mgr.is_complete() {
            if let Some(fb) = capture_mgr.take_framebuffer() {
                on_frame(&fb);
                debug!("Fed frame {}x{}", width, height);
            }
            pending = false;
        }

        if !pending
            && last_capture.elapsed() >= frame_interval
            && capture_mgr.start_capture(&queue.handle(), overlay_cursor)
        {
            pending = true;
            last_capture = Instant::now();
        }

        std::thread::sleep(Duration::from_millis(5));
    }

    info!("Capture loop stopped");
}
