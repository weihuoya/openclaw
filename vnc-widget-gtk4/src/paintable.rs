use gtk4::prelude::*;
use gtk4::subclass::prelude::*;
use gtk4::{gdk, glib, graphene};

use std::cell::{Cell, RefCell};
use std::ffi::c_void;

glib::wrapper! {
    /// A GdkPaintable that renders VNC framebuffer content.
    ///
    /// Attempts to use a persistent GL texture for zero-copy GPU rendering,
    /// falling back to GdkMemoryTexture if GL is unavailable.
    pub struct VncPaintable(ObjectSubclass<imp::VncPaintableImp>)
        @implements gdk::Paintable;
}

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct VncPaintableImp {
        pub texture: RefCell<Option<gdk::Texture>>,
        pub width: Cell<i32>,
        pub height: Cell<i32>,

        // GPU path state
        pub gl_context: RefCell<Option<gdk::GLContext>>,
        pub gl_texture_id: Cell<u32>,
        pub use_gpu: Cell<bool>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for VncPaintableImp {
        const NAME: &'static str = "VncPaintable";
        type Type = super::VncPaintable;
        type Interfaces = (gdk::Paintable,);
    }

    impl ObjectImpl for VncPaintableImp {}

    impl PaintableImpl for VncPaintableImp {
        fn intrinsic_height(&self) -> i32 {
            self.height.get()
        }

        fn intrinsic_width(&self) -> i32 {
            self.width.get()
        }

        fn intrinsic_aspect_ratio(&self) -> f64 {
            let w = self.width.get() as f64;
            let h = self.height.get() as f64;
            if h > 0.0 {
                w / h
            } else {
                0.0
            }
        }

        fn snapshot(&self, snapshot: &gdk::Snapshot, width: f64, height: f64) {
            let Some(snapshot) = snapshot.downcast_ref::<gtk4::Snapshot>() else {
                return;
            };

            let texture_guard = self.texture.borrow();
            let Some(texture) = texture_guard.as_ref() else {
                snapshot.append_color(
                    &gdk::RGBA::BLACK,
                    &graphene::Rect::new(0.0, 0.0, width as f32, height as f32),
                );
                return;
            };

            let tex_width = texture.width() as f64;
            let tex_height = texture.height() as f64;
            if tex_width <= 0.0 || tex_height <= 0.0 {
                return;
            }

            let scale_x = width / tex_width;
            let scale_y = height / tex_height;
            let scale = scale_x.min(scale_y);

            let draw_width = tex_width * scale;
            let draw_height = tex_height * scale;
            let x = (width - draw_width) / 2.0;
            let y = (height - draw_height) / 2.0;

            let bounds =
                graphene::Rect::new(x as f32, y as f32, draw_width as f32, draw_height as f32);
            snapshot.append_texture(texture, &bounds);
        }
    }
}

impl VncPaintable {
    pub fn new() -> Self {
        glib::Object::builder().build()
    }

    /// Update with new pixel data (RGBA, width * height * 4 bytes).
    pub fn update_pixels(&self, width: i32, height: i32, data: &[u8]) {
        let imp = self.imp();

        if width <= 0 || height <= 0 {
            return;
        }

        let expected = (width as usize) * (height as usize) * 4;
        if data.len() != expected {
            log::warn!(
                "VncPaintable: received {} bytes for {}x{} (expected {}), ignoring",
                data.len(),
                width,
                height,
                expected
            );
            return;
        }

        let size_changed = imp.width.get() != width || imp.height.get() != height;

        // Try GPU path on first update or when size changes
        if !imp.use_gpu.get() || size_changed {
            if let Err(e) = self.try_init_gpu(width, height) {
                log::debug!("GPU texture init failed ({}), using MemoryTexture", e);
                imp.use_gpu.set(false);
            }
        }

        if imp.use_gpu.get() {
            if let Err(e) = self.update_gpu_texture(width, height, data) {
                log::debug!(
                    "GPU texture update failed ({}), falling back to MemoryTexture",
                    e
                );
                imp.use_gpu.set(false);
                self.update_memory_texture(width, height, data);
            }
        } else {
            self.update_memory_texture(width, height, data);
        }

        imp.width.set(width);
        imp.height.set(height);

        if size_changed {
            self.invalidate_size();
        }
        self.invalidate_contents();
    }

    fn try_init_gpu(&self, width: i32, height: i32) -> Result<(), String> {
        let imp = self.imp();

        // Release any previous GPU resources before creating new ones.
        self.cleanup_gpu();

        // Get default display and create GL context
        let display = gdk::Display::default().ok_or("No display")?;
        let context = display.create_gl_context().map_err(|e| e.to_string())?;

        context.realize().map_err(|e| e.to_string())?;
        context.make_current();

        // Create GL texture
        let mut texture_id = 0u32;
        unsafe {
            glGenTextures(1, &mut texture_id);
            if texture_id == 0 {
                return Err("glGenTextures failed".to_string());
            }
            glBindTexture(GL_TEXTURE_2D, texture_id);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
            glTexImage2D(
                GL_TEXTURE_2D,
                0,
                GL_RGBA8 as i32,
                width,
                height,
                0,
                GL_RGBA,
                GL_UNSIGNED_BYTE,
                std::ptr::null(),
            );
            glBindTexture(GL_TEXTURE_2D, 0);
        }

        *imp.gl_context.borrow_mut() = Some(context);
        imp.gl_texture_id.set(texture_id);
        imp.use_gpu.set(true);

        // Build initial GdkTexture from GL texture
        self.build_gl_texture(width, height, texture_id)?;

        Ok(())
    }

    fn build_gl_texture(&self, width: i32, height: i32, texture_id: u32) -> Result<(), String> {
        let imp = self.imp();
        let context = imp.gl_context.borrow();
        let context = context.as_ref().ok_or("No GL context")?;

        let builder = gdk::GLTextureBuilder::new()
            .set_id(texture_id)
            .set_width(width)
            .set_height(height)
            .set_format(gdk::MemoryFormat::R8g8b8a8)
            .set_context(Some(context));

        let texture = unsafe { builder.build() };

        *imp.texture.borrow_mut() = Some(texture.upcast());
        Ok(())
    }

    fn update_gpu_texture(&self, width: i32, height: i32, data: &[u8]) -> Result<(), String> {
        let imp = self.imp();
        let texture_id = imp.gl_texture_id.get();

        let context = imp.gl_context.borrow();
        let context = context.as_ref().ok_or("No GL context")?;
        context.make_current();
        unsafe {
            glBindTexture(GL_TEXTURE_2D, texture_id);
            glTexSubImage2D(
                GL_TEXTURE_2D,
                0,
                0,
                0,
                width,
                height,
                GL_RGBA,
                GL_UNSIGNED_BYTE,
                data.as_ptr() as *const c_void,
            );
            glBindTexture(GL_TEXTURE_2D, 0);
        }

        // Re-create the GdkTexture so GTK sees the updated content. Reusing the
        // same GdkTexture object after updating the GL texture may render stale
        // pixels because GTK can cache the texture snapshot.
        self.build_gl_texture(width, height, texture_id)
    }

    fn update_memory_texture(&self, width: i32, height: i32, data: &[u8]) {
        let imp = self.imp();
        let bytes = glib::Bytes::from(data);
        let texture = gdk::MemoryTexture::new(
            width,
            height,
            gdk::MemoryFormat::R8g8b8a8,
            &bytes,
            (width as usize) * 4,
        );
        *imp.texture.borrow_mut() = Some(texture.upcast());
    }

    /// Release any GL context and texture owned by the paintable.
    fn cleanup_gpu(&self) {
        let imp = self.imp();
        if let Some(context) = imp.gl_context.borrow_mut().take() {
            let id = imp.gl_texture_id.get();
            if id != 0 {
                context.make_current();
                unsafe {
                    glDeleteTextures(1, &id);
                }
            }
        }
        imp.gl_texture_id.set(0);
        imp.use_gpu.set(false);
    }

    /// Clear the paintable (show black).
    pub fn clear(&self) {
        let imp = self.imp();
        *imp.texture.borrow_mut() = None;
        imp.width.set(0);
        imp.height.set(0);
        self.cleanup_gpu();
        self.invalidate_size();
        self.invalidate_contents();
    }
}

impl Default for VncPaintable {
    fn default() -> Self {
        Self::new()
    }
}

// Raw GL function pointers from libepoxy. libepoxy exports these as global
// function-pointer variables with an `epoxy_` prefix, not as plain functions.
// In Rust they must be declared as `static` function pointers and dereferenced
// before calling. Calling them as if they were functions directly jumps to the
// address of the variable itself, which contains the function pointer, causing
// a SIGSEGV when that data is interpreted as machine code.
#[link(name = "epoxy")]
extern "C" {
    #[link_name = "epoxy_glGenTextures"]
    static glGenTextures: unsafe extern "C" fn(i32, *mut u32);
    #[link_name = "epoxy_glBindTexture"]
    static glBindTexture: unsafe extern "C" fn(u32, u32);
    #[link_name = "epoxy_glTexImage2D"]
    static glTexImage2D:
        unsafe extern "C" fn(u32, i32, i32, i32, i32, i32, u32, u32, *const c_void);
    #[link_name = "epoxy_glTexSubImage2D"]
    static glTexSubImage2D:
        unsafe extern "C" fn(u32, i32, i32, i32, i32, i32, u32, u32, *const c_void);
    #[link_name = "epoxy_glTexParameteri"]
    static glTexParameteri: unsafe extern "C" fn(u32, u32, i32);
    #[link_name = "epoxy_glDeleteTextures"]
    static glDeleteTextures: unsafe extern "C" fn(i32, *const u32);
}

const GL_TEXTURE_2D: u32 = 0x0DE1;
const GL_RGBA: u32 = 0x1908;
const GL_RGBA8: u32 = 0x8058;
const GL_UNSIGNED_BYTE: u32 = 0x1401;
const GL_TEXTURE_MIN_FILTER: u32 = 0x2801;
const GL_TEXTURE_MAG_FILTER: u32 = 0x2800;
const GL_LINEAR: i32 = 0x2601;
