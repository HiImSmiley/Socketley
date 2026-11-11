//! Socketley's runtimes inside a Rust program.
//!
//! ```no_run
//! let engine = socketley::Engine::new()?;
//! let mut tools = engine.runtime("mcp", "tools", "-p 9600 --anonymous")?;
//! tools.tool("hello", "Says hello.", None, |call| call.reply("hello"))?;
//! tools.start()?;
//! # Ok::<(), socketley::Error>(())
//! ```
//!
//! A runtime takes the flags `socketley create` takes.  A tool's closure runs on the engine's thread, so it must return
//! quickly: for work that takes time, move the [`ToolCall`] to a thread or task of your own and reply from there.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::fmt;
use std::ptr;
use std::sync::Arc;

#[repr(C)]
struct RawEngine {
    _private: [u8; 0],
}
#[repr(C)]
struct RawRuntime {
    _private: [u8; 0],
}
#[repr(C)]
struct RawCall {
    _private: [u8; 0],
}
#[repr(C)]
struct RawRequest {
    _private: [u8; 0],
}

type RawTool = extern "C" fn(*mut c_void, *mut RawCall, *const c_char, *const c_char);
type RawConnection = extern "C" fn(*mut c_void, u64);
type RawMessage = extern "C" fn(*mut c_void, u64, *const c_char, usize);
type RawWeb = extern "C" fn(*mut c_void, *mut RawRequest, *const c_char, *const c_char, *const c_char, *const c_char, *const c_char, usize);

extern "C" {
    fn skl_version() -> *const c_char;
    fn skl_free(text: *mut c_char);
    fn skl_engine_new(err: *mut *mut c_char) -> *mut RawEngine;
    fn skl_engine_free(engine: *mut RawEngine);
    fn skl_runtime_create(
        engine: *mut RawEngine,
        kind: *const c_char,
        name: *const c_char,
        flags: *const c_char,
        err: *mut *mut c_char,
    ) -> *mut RawRuntime;
    fn skl_runtime_start(runtime: *mut RawRuntime, err: *mut *mut c_char) -> c_int;
    fn skl_runtime_stop(runtime: *mut RawRuntime) -> c_int;
    fn skl_runtime_stats(runtime: *mut RawRuntime) -> *mut c_char;
    fn skl_runtime_free(runtime: *mut RawRuntime);
    fn skl_mcp_tool(
        runtime: *mut RawRuntime,
        name: *const c_char,
        description: *const c_char,
        input_schema_json: *const c_char,
        f: RawTool,
        user: *mut c_void,
        err: *mut *mut c_char,
    ) -> c_int;
    fn skl_mcp_reply(call: *mut RawCall, text: *const c_char, is_error: c_int);
    fn skl_on_connect(runtime: *mut RawRuntime, f: RawConnection, user: *mut c_void, err: *mut *mut c_char) -> c_int;
    fn skl_on_disconnect(runtime: *mut RawRuntime, f: RawConnection, user: *mut c_void, err: *mut *mut c_char) -> c_int;
    fn skl_on_message(runtime: *mut RawRuntime, f: RawMessage, user: *mut c_void, err: *mut *mut c_char) -> c_int;
    fn skl_send(runtime: *mut RawRuntime, connection: u64, data: *const c_char, length: usize) -> c_int;
    fn skl_cache_command(runtime: *mut RawRuntime, line: *const c_char, err: *mut *mut c_char) -> *mut c_char;
    fn skl_web_handler(runtime: *mut RawRuntime, prefix: *const c_char, f: RawWeb, user: *mut c_void, err: *mut *mut c_char) -> c_int;
    fn skl_web_reply(request: *mut RawRequest, status: c_int, headers: *const c_char, body: *const c_char, length: usize);
}

/// Why socketley refused: the sentence the CLI would have printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}

fn c(s: &str) -> Result<CString, Error> {
    CString::new(s).map_err(|_| Error(format!("a NUL byte in {s:?}")))
}

unsafe fn taken(err: *mut c_char) -> Error {
    if err.is_null() {
        return Error("refused, without a reason".into());
    }
    let text = CStr::from_ptr(err).to_string_lossy().into_owned();
    skl_free(err);
    Error(text)
}

/// The version of socketley this links against.
pub fn version() -> String {
    unsafe { CStr::from_ptr(skl_version()) }.to_string_lossy().into_owned()
}

struct EngineHandle(*mut RawEngine);
// The C interface takes calls from any thread.
unsafe impl Send for EngineHandle {}
unsafe impl Sync for EngineHandle {}
impl Drop for EngineHandle {
    fn drop(&mut self) {
        unsafe { skl_engine_free(self.0) }
    }
}

/// One thread with one io_uring ring, on which its runtimes run.  It ends when it and its runtimes are dropped.
#[derive(Clone)]
pub struct Engine {
    handle: Arc<EngineHandle>,
}

impl Engine {
    pub fn new() -> Result<Self, Error> {
        let mut err = ptr::null_mut();
        let raw = unsafe { skl_engine_new(&mut err) };
        if raw.is_null() {
            return Err(unsafe { taken(err) });
        }
        Ok(Engine { handle: Arc::new(EngineHandle(raw)) })
    }

    /// A runtime of a type, with the flags `socketley create` takes.  It is not started.
    pub fn runtime(&self, kind: &str, name: &str, flags: &str) -> Result<Runtime, Error> {
        let (k, n, f) = (c(kind)?, c(name)?, c(flags)?);
        let mut err = ptr::null_mut();
        let raw = unsafe { skl_runtime_create(self.handle.0, k.as_ptr(), n.as_ptr(), f.as_ptr(), &mut err) };
        if raw.is_null() {
            return Err(unsafe { taken(err) });
        }
        Ok(Runtime { raw, tools: Vec::new(), hooks: Vec::new(), _engine: self.handle.clone() })
    }
}

type ToolFn = dyn Fn(ToolCall) + Send + Sync + 'static;

/// A runtime on an engine.  Dropping it stops and removes it.
pub struct Runtime {
    raw: *mut RawRuntime,
    // Declared so they outlive the C runtime, which Drop frees first and which is what calls them.
    tools: Vec<Box<Box<ToolFn>>>,
    hooks: Vec<Box<dyn std::any::Any + Send + Sync>>,
    _engine: Arc<EngineHandle>,
}
unsafe impl Send for Runtime {}
unsafe impl Sync for Runtime {}

impl Runtime {
    pub fn start(&self) -> Result<(), Error> {
        let mut err = ptr::null_mut();
        if unsafe { skl_runtime_start(self.raw, &mut err) } != 0 {
            return Err(unsafe { taken(err) });
        }
        Ok(())
    }

    /// False when it was not running.
    pub fn stop(&self) -> bool {
        unsafe { skl_runtime_stop(self.raw) == 0 }
    }

    /// The runtime's figures, one `name:value` a line.
    pub fn stats(&self) -> String {
        let p = unsafe { skl_runtime_stats(self.raw) };
        if p.is_null() {
            return String::new();
        }
        let text = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
        unsafe { skl_free(p) };
        text
    }

    /// A connection came, on a runtime of type `server` or `client`.  Runs on the engine's thread, as do the two below.
    pub fn on_connect<F: Fn(u64) + Send + Sync + 'static>(&mut self, f: F) -> Result<(), Error> {
        self.connection_hook(skl_on_connect, f)
    }

    /// A connection went.
    pub fn on_disconnect<F: Fn(u64) + Send + Sync + 'static>(&mut self, f: F) -> Result<(), Error> {
        self.connection_hook(skl_on_disconnect, f)
    }

    fn connection_hook<F: Fn(u64) + Send + Sync + 'static>(
        &mut self,
        set: unsafe extern "C" fn(*mut RawRuntime, RawConnection, *mut c_void, *mut *mut c_char) -> c_int,
        f: F,
    ) -> Result<(), Error> {
        extern "C" fn call<F: Fn(u64)>(user: *mut c_void, connection: u64) {
            let f = unsafe { &*user.cast::<F>() };
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(connection)));
        }
        let boxed = Box::new(f);
        let mut err = ptr::null_mut();
        if unsafe { set(self.raw, call::<F>, (&*boxed as *const F).cast_mut().cast(), &mut err) } != 0 {
            return Err(unsafe { taken(err) });
        }
        self.hooks.push(boxed);
        Ok(())
    }

    /// A message arrived on a connection.
    pub fn on_message<F: Fn(u64, &[u8]) + Send + Sync + 'static>(&mut self, f: F) -> Result<(), Error> {
        extern "C" fn call<F: Fn(u64, &[u8])>(user: *mut c_void, connection: u64, data: *const c_char, length: usize) {
            let f = unsafe { &*user.cast::<F>() };
            let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), length) };
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(connection, bytes)));
        }
        let boxed = Box::new(f);
        let mut err = ptr::null_mut();
        if unsafe { skl_on_message(self.raw, call::<F>, (&*boxed as *const F).cast_mut().cast(), &mut err) } != 0 {
            return Err(unsafe { taken(err) });
        }
        self.hooks.push(boxed);
        Ok(())
    }

    /// Sends a line on a connection, from any thread.  False once the engine has ended.
    pub fn send(&self, connection: u64, data: &[u8]) -> bool {
        unsafe { skl_send(self.raw, connection, data.as_ptr().cast(), data.len()) == 0 }
    }

    /// One command of a runtime of type `cache`, in its text protocol.
    pub fn command(&self, line: &str) -> Result<String, Error> {
        let l = c(line)?;
        let mut err = ptr::null_mut();
        let p = unsafe { skl_cache_command(self.raw, l.as_ptr(), &mut err) };
        if p.is_null() {
            return Err(unsafe { taken(err) });
        }
        let text = unsafe { CStr::from_ptr(p) }.to_string_lossy().trim_end().to_owned();
        unsafe { skl_free(p) };
        Ok(text)
    }

    /// `prefix` and every path under it, on a runtime of type `web`, go to `f` before any file does.
    pub fn handle<F>(&mut self, prefix: &str, f: F) -> Result<(), Error>
    where
        F: Fn(WebRequest) + Send + Sync + 'static,
    {
        extern "C" fn call<F: Fn(WebRequest)>(
            user: *mut c_void,
            request: *mut RawRequest,
            method: *const c_char,
            path: *const c_char,
            query: *const c_char,
            headers: *const c_char,
            body: *const c_char,
            length: usize,
        ) {
            let text = |p: *const c_char| unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
            let req = WebRequest {
                raw: request,
                method: text(method),
                path: text(path),
                query: text(query),
                headers: text(headers),
                body: if length == 0 { Vec::new() } else { unsafe { std::slice::from_raw_parts(body.cast::<u8>(), length) }.to_vec() },
            };
            let f = unsafe { &*user.cast::<F>() };
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(req)));
        }
        let p = c(prefix)?;
        let boxed = Box::new(f);
        let mut err = ptr::null_mut();
        if unsafe { skl_web_handler(self.raw, p.as_ptr(), call::<F>, (&*boxed as *const F).cast_mut().cast(), &mut err) } != 0 {
            return Err(unsafe { taken(err) });
        }
        self.hooks.push(boxed);
        Ok(())
    }

    /// An MCP tool on a runtime of type `mcp`; `input_schema` is a JSON Schema object as text.
    pub fn tool<F>(&mut self, name: &str, description: &str, input_schema: Option<&str>, f: F) -> Result<(), Error>
    where
        F: Fn(ToolCall) + Send + Sync + 'static,
    {
        let (n, d) = (c(name)?, c(description)?);
        let schema = input_schema.map(c).transpose()?;
        let mut boxed: Box<Box<ToolFn>> = Box::new(Box::new(f));
        let user = (&mut *boxed as *mut Box<ToolFn>).cast::<c_void>();
        let mut err = ptr::null_mut();
        let rc = unsafe {
            skl_mcp_tool(
                self.raw,
                n.as_ptr(),
                d.as_ptr(),
                schema.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
                trampoline,
                user,
                &mut err,
            )
        };
        if rc != 0 {
            return Err(unsafe { taken(err) });
        }
        self.tools.push(boxed);
        Ok(())
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        unsafe { skl_runtime_free(self.raw) }
    }
}

extern "C" fn trampoline(user: *mut c_void, call: *mut RawCall, args: *const c_char, caller: *const c_char) {
    let call = ToolCall {
        raw: call,
        args: unsafe { CStr::from_ptr(args) }.to_string_lossy().into_owned(),
        caller: unsafe { CStr::from_ptr(caller) }.to_string_lossy().into_owned(),
    };
    let f = unsafe { &*user.cast::<Box<ToolFn>>() };
    // A panic must not unwind into the engine's thread; the dropped ToolCall answers for it.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(call)));
}

/// One call of a tool.  It answers exactly once: with [`reply`](ToolCall::reply) or [`fail`](ToolCall::fail), or as
/// failed when it is dropped unanswered.  It may be moved to another thread.
pub struct ToolCall {
    raw: *mut RawCall,
    args: String,
    caller: String,
}
unsafe impl Send for ToolCall {}

impl ToolCall {
    /// The arguments as JSON text.
    pub fn args(&self) -> &str {
        &self.args
    }

    /// The name of the key that asked, empty for none.
    pub fn caller(&self) -> &str {
        &self.caller
    }

    pub fn reply(mut self, text: &str) {
        self.answer(text, false);
    }

    /// A failure of the tool, which the model reads.
    pub fn fail(mut self, text: &str) {
        self.answer(text, true);
    }

    fn answer(&mut self, text: &str, failed: bool) {
        if self.raw.is_null() {
            return;
        }
        let body = CString::new(text.replace('\0', "")).unwrap_or_default();
        unsafe { skl_mcp_reply(self.raw, body.as_ptr(), c_int::from(failed)) };
        self.raw = ptr::null_mut();
    }
}

impl Drop for ToolCall {
    fn drop(&mut self) {
        self.answer("the tool did not answer", true);
    }
}

/// One HTTP request of a web runtime.  It answers exactly once, or with a 500 when it is dropped unanswered, and may be
/// moved to another thread.
pub struct WebRequest {
    raw: *mut RawRequest,
    pub method: String,
    pub path: String,
    pub query: String,
    /// One `Name: value` a line.
    pub headers: String,
    pub body: Vec<u8>,
}
unsafe impl Send for WebRequest {}

impl WebRequest {
    /// `headers` is one `Name: value` a line, empty for none.
    pub fn reply(mut self, status: u16, headers: &str, body: &[u8]) {
        self.answer(status, headers, body);
    }

    fn answer(&mut self, status: u16, headers: &str, body: &[u8]) {
        if self.raw.is_null() {
            return;
        }
        let h = CString::new(headers.replace('\0', "")).unwrap_or_default();
        unsafe { skl_web_reply(self.raw, c_int::from(status), h.as_ptr(), body.as_ptr().cast(), body.len()) };
        self.raw = ptr::null_mut();
    }
}

impl Drop for WebRequest {
    fn drop(&mut self) {
        self.answer(500, "Content-Type: text/plain", b"the handler did not answer\n");
    }
}
