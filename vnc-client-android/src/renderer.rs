//! OpenGL ES 3 renderer for Android VNC display.
//!
//! Manages EGL context, compiles a simple texture shader, and renders
//! RGBA pixel data to an Android [`ANativeWindow`].

use std::ffi::{c_char, c_void, CString};
use std::ptr;

use ndk::native_window::NativeWindow;

// ─── EGL FFI ───────────────────────────────────────────────────────

type EGLDisplay = *mut c_void;
type EGLConfig = *mut c_void;
type EGLSurface = *mut c_void;
type EGLContext = *mut c_void;
type EGLClientBuffer = *mut c_void;
type EGLint = i32;
type EGLBoolean = u32;

const EGL_DEFAULT_DISPLAY: EGLint = 0;
const EGL_NO_CONTEXT: EGLContext = ptr::null_mut();
const EGL_NO_DISPLAY: EGLDisplay = ptr::null_mut();
const EGL_NO_SURFACE: EGLSurface = ptr::null_mut();
const EGL_FALSE: EGLBoolean = 0;
const EGL_TRUE: EGLBoolean = 1;
const EGL_NONE: EGLint = 0x3038;
const EGL_RENDERABLE_TYPE: EGLint = 0x3040;
const EGL_OPENGL_ES3_BIT: EGLint = 0x0040;
const EGL_SURFACE_TYPE: EGLint = 0x3033;
const EGL_WINDOW_BIT: EGLint = 0x0004;
const EGL_BLUE_SIZE: EGLint = 0x3022;
const EGL_GREEN_SIZE: EGLint = 0x3021;
const EGL_RED_SIZE: EGLint = 0x3020;
const EGL_DEPTH_SIZE: EGLint = 0x3025;
const EGL_CONTEXT_CLIENT_VERSION: EGLint = 0x3098;

#[link(name = "EGL")]
extern "C" {
    fn eglGetDisplay(display_id: EGLint) -> EGLDisplay;
    fn eglInitialize(dpy: EGLDisplay, major: *mut EGLint, minor: *mut EGLint) -> EGLBoolean;
    fn eglChooseConfig(
        dpy: EGLDisplay,
        attrib_list: *const EGLint,
        configs: *mut EGLConfig,
        config_size: EGLint,
        num_config: *mut EGLint,
    ) -> EGLBoolean;
    fn eglCreateContext(
        dpy: EGLDisplay,
        config: EGLConfig,
        share_context: EGLContext,
        attrib_list: *const EGLint,
    ) -> EGLContext;
    fn eglCreateWindowSurface(
        dpy: EGLDisplay,
        config: EGLConfig,
        win: *mut c_void,
        attrib_list: *const EGLint,
    ) -> EGLSurface;
    fn eglMakeCurrent(
        dpy: EGLDisplay,
        draw: EGLSurface,
        read: EGLSurface,
        ctx: EGLContext,
    ) -> EGLBoolean;
    fn eglSwapBuffers(dpy: EGLDisplay, surface: EGLSurface) -> EGLBoolean;
    fn eglGetError() -> EGLint;
    fn eglDestroyContext(dpy: EGLDisplay, ctx: EGLContext) -> EGLBoolean;
    fn eglDestroySurface(dpy: EGLDisplay, surface: EGLSurface) -> EGLBoolean;
    fn eglTerminate(dpy: EGLDisplay) -> EGLBoolean;
}

// ─── OpenGL ES 3 FFI ───────────────────────────────────────────────

type GLenum = u32;
type GLint = i32;
type GLuint = u32;
type GLsizei = i32;
type GLfloat = f32;
type GLboolean = u8;
type GLbitfield = u32;

const GL_VERTEX_SHADER: GLenum = 0x8B31;
const GL_FRAGMENT_SHADER: GLenum = 0x8B30;
const GL_COMPILE_STATUS: GLenum = 0x8B81;
const GL_LINK_STATUS: GLenum = 0x8B82;
const GL_INFO_LOG_LENGTH: GLenum = 0x8B84;
const GL_TEXTURE_2D: GLenum = 0x0DE1;
const GL_TEXTURE_MIN_FILTER: GLenum = 0x2801;
const GL_TEXTURE_MAG_FILTER: GLenum = 0x2800;
const GL_LINEAR: GLint = 0x2601;
const GL_RGBA: GLenum = 0x1908;
const GL_UNSIGNED_BYTE: GLenum = 0x1401;
const GL_FLOAT: GLenum = 0x1406;
const GL_ARRAY_BUFFER: GLenum = 0x8892;
const GL_STATIC_DRAW: GLenum = 0x88E4;
const GL_TRIANGLE_STRIP: GLenum = 0x0005;
const GL_COLOR_BUFFER_BIT: GLbitfield = 0x00004000;
const GL_VERSION: GLenum = 0x1F02;

#[link(name = "GLESv3")]
extern "C" {
    fn glCreateShader(type_: GLenum) -> GLuint;
    fn glShaderSource(
        shader: GLuint,
        count: GLsizei,
        string: *const *const c_char,
        length: *const GLint,
    );
    fn glCompileShader(shader: GLuint);
    fn glGetShaderiv(shader: GLuint, pname: GLenum, params: *mut GLint);
    fn glGetShaderInfoLog(
        shader: GLuint,
        buf_size: GLsizei,
        length: *mut GLsizei,
        info_log: *mut c_char,
    );
    fn glCreateProgram() -> GLuint;
    fn glAttachShader(program: GLuint, shader: GLuint);
    fn glLinkProgram(program: GLuint);
    fn glGetProgramiv(program: GLuint, pname: GLenum, params: *mut GLint);
    fn glGetProgramInfoLog(
        program: GLuint,
        buf_size: GLsizei,
        length: *mut GLsizei,
        info_log: *mut c_char,
    );
    fn glUseProgram(program: GLuint);
    fn glDeleteShader(shader: GLuint);
    fn glGetAttribLocation(program: GLuint, name: *const c_char) -> GLint;
    fn glGetUniformLocation(program: GLuint, name: *const c_char) -> GLint;
    fn glEnableVertexAttribArray(index: GLuint);
    fn glVertexAttribPointer(
        index: GLuint,
        size: GLint,
        type_: GLenum,
        normalized: GLboolean,
        stride: GLsizei,
        pointer: *const c_void,
    );
    fn glUniform1i(location: GLint, v0: GLint);
    fn glGenTextures(n: GLsizei, textures: *mut GLuint);
    fn glBindTexture(target: GLenum, texture: GLuint);
    fn glTexImage2D(
        target: GLenum,
        level: GLint,
        internalformat: GLint,
        width: GLsizei,
        height: GLsizei,
        border: GLint,
        format: GLenum,
        type_: GLenum,
        pixels: *const c_void,
    );
    fn glTexSubImage2D(
        target: GLenum,
        level: GLint,
        xoffset: GLint,
        yoffset: GLint,
        width: GLsizei,
        height: GLsizei,
        format: GLenum,
        type_: GLenum,
        pixels: *const c_void,
    );
    fn glTexParameteri(target: GLenum, pname: GLenum, param: GLint);
    fn glViewport(x: GLint, y: GLint, width: GLsizei, height: GLsizei);
    fn glClear(mask: GLbitfield);
    fn glClearColor(red: GLfloat, green: GLfloat, blue: GLfloat, alpha: GLfloat);
    fn glDrawArrays(mode: GLenum, first: GLint, count: GLsizei);
    fn glGenBuffers(n: GLsizei, buffers: *mut GLuint);
    fn glBindBuffer(target: GLenum, buffer: GLuint);
    fn glBufferData(target: GLenum, size: isize, data: *const c_void, usage: GLenum);
    fn glGetString(name: GLenum) -> *const c_char;
    fn glDeleteTextures(n: GLsizei, textures: *const GLuint);
    fn glDeleteBuffers(n: GLsizei, buffers: *const GLuint);
    fn glDeleteProgram(program: GLuint);
}

// ─── Shader sources ────────────────────────────────────────────────

const VERTEX_SHADER: &str = r#"#version 300 es
in vec2 a_position;
in vec2 a_texcoord;
out vec2 v_texcoord;
void main() {
    gl_Position = vec4(a_position, 0.0, 1.0);
    v_texcoord = a_texcoord;
}
"#;

const FRAGMENT_SHADER: &str = r#"#version 300 es
precision mediump float;
in vec2 v_texcoord;
uniform sampler2D u_texture;
out vec4 frag_color;
void main() {
    frag_color = texture(u_texture, v_texcoord);
}
"#;

// Fullscreen quad: positions (x, y) + texcoords (u, v)
#[rustfmt::skip]
const QUAD_VERTICES: [f32; 16] = [
    // pos      // texcoord
    -1.0, -1.0, 0.0, 0.0,
     1.0, -1.0, 1.0, 0.0,
    -1.0,  1.0, 0.0, 1.0,
     1.0,  1.0, 1.0, 1.0,
];

// ─── Renderer ──────────────────────────────────────────────────────

/// OpenGL ES 3 renderer backed by EGL.
pub struct EglRenderer {
    display: EGLDisplay,
    surface: EGLSurface,
    context: EGLContext,
    program: GLuint,
    texture: GLuint,
    vbo: GLuint,
    width: i32,
    height: i32,
}

impl EglRenderer {
    /// Create a new renderer for the given Android [`NativeWindow`].
    pub fn new(native_window: &NativeWindow) -> Result<Self, String> {
        unsafe {
            // 1. EGL display
            let display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
            if display == EGL_NO_DISPLAY {
                return Err("eglGetDisplay failed".to_string());
            }
            if eglInitialize(display, ptr::null_mut(), ptr::null_mut()) == EGL_FALSE {
                return Err("eglInitialize failed".to_string());
            }

            // 2. Choose config (OpenGL ES 3, window surface, RGB888)
            let attribs = [
                EGL_RENDERABLE_TYPE,
                EGL_OPENGL_ES3_BIT,
                EGL_SURFACE_TYPE,
                EGL_WINDOW_BIT,
                EGL_RED_SIZE,
                8,
                EGL_GREEN_SIZE,
                8,
                EGL_BLUE_SIZE,
                8,
                EGL_DEPTH_SIZE,
                0,
                EGL_NONE,
            ];
            let mut config: EGLConfig = ptr::null_mut();
            let mut num_configs: EGLint = 0;
            if eglChooseConfig(display, attribs.as_ptr(), &mut config, 1, &mut num_configs)
                == EGL_FALSE
                || num_configs == 0
            {
                return Err("eglChooseConfig failed".to_string());
            }

            // 3. Create EGL context (ES 3.0)
            let ctx_attribs = [EGL_CONTEXT_CLIENT_VERSION, 3, EGL_NONE];
            let context = eglCreateContext(display, config, EGL_NO_CONTEXT, ctx_attribs.as_ptr());
            if context == EGL_NO_CONTEXT {
                return Err("eglCreateContext failed".to_string());
            }

            // 4. Create window surface from ANativeWindow
            let surface = eglCreateWindowSurface(
                display,
                config,
                native_window.ptr().as_ptr().cast(),
                ptr::null(),
            );
            if surface == EGL_NO_SURFACE {
                return Err("eglCreateWindowSurface failed".to_string());
            }

            // 5. Make current
            if eglMakeCurrent(display, surface, surface, context) == EGL_FALSE {
                return Err("eglMakeCurrent failed".to_string());
            }

            // 6. Compile shaders and link program
            let program = compile_program(VERTEX_SHADER, FRAGMENT_SHADER)?;

            // 7. Upload vertex data
            let mut vbo: GLuint = 0;
            glGenBuffers(1, &mut vbo);
            glBindBuffer(GL_ARRAY_BUFFER, vbo);
            glBufferData(
                GL_ARRAY_BUFFER,
                (QUAD_VERTICES.len() * std::mem::size_of::<f32>()) as isize,
                QUAD_VERTICES.as_ptr().cast(),
                GL_STATIC_DRAW,
            );

            // Bind attributes
            let pos_loc =
                glGetAttribLocation(program, CString::new("a_position").unwrap().as_ptr());
            let tex_loc =
                glGetAttribLocation(program, CString::new("a_texcoord").unwrap().as_ptr());

            glEnableVertexAttribArray(pos_loc as GLuint);
            glVertexAttribPointer(
                pos_loc as GLuint,
                2,
                GL_FLOAT,
                0,
                4 * std::mem::size_of::<f32>() as GLsizei,
                ptr::null(),
            );
            glEnableVertexAttribArray(tex_loc as GLuint);
            glVertexAttribPointer(
                tex_loc as GLuint,
                2,
                GL_FLOAT,
                0,
                4 * std::mem::size_of::<f32>() as GLsizei,
                (2 * std::mem::size_of::<f32>()) as *const c_void,
            );

            // 8. Create texture
            let mut texture: GLuint = 0;
            glGenTextures(1, &mut texture);
            glBindTexture(GL_TEXTURE_2D, texture);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);

            // 9. Set uniform sampler
            glUseProgram(program);
            let sampler_loc =
                glGetUniformLocation(program, CString::new("u_texture").unwrap().as_ptr());
            glUniform1i(sampler_loc, 0);

            let width = native_window.width();
            let height = native_window.height();
            glViewport(0, 0, width, height);

            Ok(Self {
                display,
                surface,
                context,
                program,
                texture,
                vbo,
                width,
                height,
            })
        }
    }

    /// Upload RGBA pixel data and draw a fullscreen quad.
    pub fn render_frame(&mut self, rgba: &[u8], width: u32, height: u32) {
        unsafe {
            glClearColor(0.0, 0.0, 0.0, 1.0);
            glClear(GL_COLOR_BUFFER_BIT);

            glBindTexture(GL_TEXTURE_2D, self.texture);
            glTexImage2D(
                GL_TEXTURE_2D,
                0,
                GL_RGBA as GLint,
                width as GLsizei,
                height as GLsizei,
                0,
                GL_RGBA,
                GL_UNSIGNED_BYTE,
                rgba.as_ptr().cast(),
            );

            glUseProgram(self.program);
            glBindBuffer(GL_ARRAY_BUFFER, self.vbo);
            glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);

            eglSwapBuffers(self.display, self.surface);
        }
    }

    /// Resize the viewport when the surface size changes.
    pub fn resize(&mut self, width: i32, height: i32) {
        self.width = width;
        self.height = height;
        unsafe {
            glViewport(0, 0, width, height);
        }
    }
}

impl Drop for EglRenderer {
    fn drop(&mut self) {
        unsafe {
            glDeleteProgram(self.program);
            glDeleteTextures(1, &self.texture);
            glDeleteBuffers(1, &self.vbo);
            eglMakeCurrent(self.display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
            eglDestroySurface(self.display, self.surface);
            eglDestroyContext(self.display, self.context);
            eglTerminate(self.display);
        }
    }
}

// ─── Shader helpers ────────────────────────────────────────────────

unsafe fn compile_shader(source: &str, type_: GLenum) -> Result<GLuint, String> {
    let shader = glCreateShader(type_);
    let c_source = CString::new(source).unwrap();
    let sources = [c_source.as_ptr()];
    let lengths = [source.len() as GLint];
    glShaderSource(shader, 1, sources.as_ptr(), lengths.as_ptr());
    glCompileShader(shader);

    let mut status: GLint = 0;
    glGetShaderiv(shader, GL_COMPILE_STATUS, &mut status);
    if status == 0 {
        let mut len: GLsizei = 0;
        glGetShaderiv(shader, GL_INFO_LOG_LENGTH, &mut len);
        let mut buf = vec![0u8; len as usize];
        glGetShaderInfoLog(shader, len, ptr::null_mut(), buf.as_mut_ptr().cast());
        let log = String::from_utf8_lossy(&buf);
        return Err(format!("Shader compile error: {log}"));
    }
    Ok(shader)
}

unsafe fn compile_program(vs: &str, fs: &str) -> Result<GLuint, String> {
    let vs_id = compile_shader(vs, GL_VERTEX_SHADER)?;
    let fs_id = compile_shader(fs, GL_FRAGMENT_SHADER)?;
    let program = glCreateProgram();
    glAttachShader(program, vs_id);
    glAttachShader(program, fs_id);
    glLinkProgram(program);

    let mut status: GLint = 0;
    glGetProgramiv(program, GL_LINK_STATUS, &mut status);
    if status == 0 {
        let mut len: GLsizei = 0;
        glGetProgramiv(program, GL_INFO_LOG_LENGTH, &mut len);
        let mut buf = vec![0u8; len as usize];
        glGetProgramInfoLog(program, len, ptr::null_mut(), buf.as_mut_ptr().cast());
        let log = String::from_utf8_lossy(&buf);
        return Err(format!("Program link error: {log}"));
    }

    glDeleteShader(vs_id);
    glDeleteShader(fs_id);
    Ok(program)
}
