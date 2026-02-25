use core::{
    ffi::c_void,
    mem::{transmute},
    ptr::{null, null_mut},
};

use alloc::string::{String, ToString};
use alloc::{vec::Vec};

use crate::{
    get_instance,
    libs::{ldrapi::ldr_function, ntdef::UnicodeString},
};


type WinHttpOpen = unsafe extern "system" fn(
    pszagentw: *const u16,
    dwaccesstype: u32,
    pszproxyw: *const u16,
    pszproxybypassw: *const u16,
    dwflags: u32,
) -> *mut c_void;

type WinHttpConnect = unsafe extern "system" fn(
    hsession: *mut c_void,
    pswzservername: *const u16,
    nserverport: u16,
    dwreserved: u32,
) -> *mut c_void;

type WinHttpCloseHandle = unsafe extern "system" fn(hinternet: *mut c_void) -> bool;

type WinHttpSendRequest = unsafe extern "system" fn(
    hrequest: *mut c_void,
    lpszheaders: *const u16,
    dwheaderslength: u32,
    lpoptional: *const c_void,
    dwoptionallength: u32,
    dwtotallength: u32,
    dwcontext: usize,
) -> bool;

type WinHttpOpenRequest = unsafe extern "system" fn(
    hconnect: *mut c_void,
    pwszverb: *const u16,
    pwszobjectname: *const u16,
    pwszversion: *const u16,
    pwszreferrer: *const u16,
    ppwszaccepttypes: *const *const u16,
    dwflags: u32,
) -> *mut c_void;

type WinHttpReceiveResponse =
    unsafe extern "system" fn(hrequest: *mut c_void, lpreserved: *mut c_void) -> bool;

type WinHttpReadData = unsafe extern "system" fn(
    hrequest: *mut c_void,
    lpbuffer: *mut c_void,
    dwnumberofbytestoread: u32,
    lpdwnumberofbytesread: *mut u32,
) -> bool;

type WinHttpAddRequestHeaders = unsafe extern "system" fn(
    hrequest: *mut c_void,
    lpszheaders: *const u16,
    dwheaderslength: u32,
    dwmodifiers: u32,
) -> bool;

type WinHttpQueryDataAvailable = unsafe extern "system" fn(
    hrequest: *mut c_void,
    lpdwnumberofbytesavailable: *mut u32,
) -> bool;

type WinHttpSetOption = unsafe extern "system" fn(
    hinternet: *mut c_void,
    dwoption: u32,
    lpbuffer: *const c_void,
    dwbufferlength: u32,
) -> bool;

pub struct Winhttp {
    pub open: WinHttpOpen,
    pub connect: WinHttpConnect,
    pub close_handle: WinHttpCloseHandle,
    pub send_request: WinHttpSendRequest,
    pub open_request: WinHttpOpenRequest,
    pub receive_response: WinHttpReceiveResponse,
    pub read_data: WinHttpReadData,
    pub add_request_headers: WinHttpAddRequestHeaders,
    pub query_data_available: WinHttpQueryDataAvailable,
    pub set_option: WinHttpSetOption,
}

impl Winhttp {
    pub fn new() -> Self {
        Winhttp {
            open: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            connect: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            close_handle: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            send_request: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            open_request: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            receive_response: unsafe {
                core::mem::transmute(core::ptr::null::<core::ffi::c_void>())
            },
            read_data: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            add_request_headers: unsafe {
                core::mem::transmute(core::ptr::null::<core::ffi::c_void>())
            },
            query_data_available: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            set_option: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
        }
    }
}

pub fn init_winhttp_funcs() {
    unsafe {
        let mut winhttp_dll_unicode = UnicodeString::new();
        let utf16_string: Vec<u16> = "Winhttp.dll".encode_utf16().chain(Some(0)).collect();
        winhttp_dll_unicode.init(utf16_string.as_ptr());

        let mut winhttp_handle: *mut c_void = null_mut();

        if let Some(instance) = get_instance() {
            (instance.ntdll.ldr_load_dll)(
                null_mut(),
                null_mut(),
                winhttp_dll_unicode,
                &mut winhttp_handle as *mut _ as *mut c_void,
            );

            if winhttp_handle.is_null() {
                return;
            }

            let winhttp_module = winhttp_handle as *mut u8;

            let open_addr = ldr_function(winhttp_module, 0x613eace5);
            instance.winhttp.open = transmute(open_addr);

            let connect_addr = ldr_function(winhttp_module, 0x81e0c81d);
            instance.winhttp.connect = transmute(connect_addr);
            let close_handle_addr = ldr_function(winhttp_module, 0xa7355f15);
            instance.winhttp.close_handle = transmute(close_handle_addr);
            let send_request_addr = ldr_function(winhttp_module, 0x7739d0e6);
            instance.winhttp.send_request = transmute(send_request_addr);
            let open_request_addr = ldr_function(winhttp_module, 0xb06d900e);
            instance.winhttp.open_request = transmute(open_request_addr);
            let receive_response_addr = ldr_function(winhttp_module, 0xae351ae5);
            instance.winhttp.receive_response = transmute(receive_response_addr);
            let read_data_addr = ldr_function(winhttp_module, 0x75064b89);
            instance.winhttp.read_data = transmute(read_data_addr);
            let add_request_headers_addr = ldr_function(winhttp_module, 0xa2c0b0e1);
            instance.winhttp.add_request_headers = transmute(add_request_headers_addr);
            let query_data_available_addr = ldr_function(winhttp_module, 0x1c701c04);
            instance.winhttp.query_data_available = transmute(query_data_available_addr);

            let set_option_addr = ldr_function(winhttp_module, 0x5b6ad378);
            instance.winhttp.set_option = transmute(set_option_addr);
        }
    }
}

pub struct HttpClient {
    pub headers: Option<String>,
}

impl HttpClient {
    /// Create a new HTTP client
    pub fn new() -> Result<Self, u32> {
        if unsafe { get_instance().is_none() } {
            return Err(0x80004005);
        }
        Ok(HttpClient { headers: None })
    }

    /// Perform an HTTP GET request
    pub fn get(&self, host: &str, port: u16, path: &str, secure: bool) -> Result<Vec<u8>, u32> {
        self.send("GET", host, port, path, secure, None)
    }
    pub fn post(
        &self,
        host: &str,
        port: u16,
        path: &str,
        secure: bool,
        body: &str,
    ) -> Result<Vec<u8>, u32> {
        self.send("POST", host, port, path, secure, Some(body))
    }

    pub fn send(
        &self,
        method: &str,
        host: &str,
        port: u16,
        path: &str,
        secure: bool,
        body: Option<&str>,
    ) -> Result<Vec<u8>, u32> {
        unsafe {
            let instance = get_instance().unwrap();

            // Open a WinHTTP session
            let session = (instance.winhttp.open)(
                null(),
                0, // WINHTTP_ACCESS_TYPE_DEFAULT_PROXY
                null(),
                null(),
                0,
            );
            if session.is_null() {
                return Err((instance.k32.get_last_error)());
            }

            // Define host and port (for simplicity; URL parsing required for real cases)
            //let host = "example.com\0"; // Replace with parsed host
            let host_utf16: Vec<u16> = host.encode_utf16().chain(Some(0)).collect();

            let connection =
                (instance.winhttp.connect)(session, host_utf16.as_ptr() as *const _, port, 0);
            if connection.is_null() {
                let err = (instance.k32.get_last_error)();
                (instance.winhttp.close_handle)(session);
                return Err(err);
            }

            // Define path
            //let path = "/\0"; // Replace with parsed path

            //let method = "GET";
            let method_utf16: Vec<u16> = method.encode_utf16().chain(Some(0)).collect();

            //let path = "/";
            let path_utf16: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
            let request_flags = if secure { 0x00800000 } else { 0 };

            let request = (instance.winhttp.open_request)(
                connection,
                method_utf16.as_ptr() as *const _, // HTTP method
                path_utf16.as_ptr() as *const _,
                null(),
                null(),
                null(),
                request_flags,
            );

            if request.is_null() {
                let err = (instance.k32.get_last_error)();
                (instance.winhttp.close_handle)(connection);
                (instance.winhttp.close_handle)(session);
                return Err(err);
            }

            // Ignore certificate errors for HTTPS
            if secure {
                // WINHTTP_OPTION_SECURITY_FLAGS = 31
                // SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                // SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE
                let security_flags: u32 = 0x00003300;
                (instance.winhttp.set_option)(
                    request,
                    31, // WINHTTP_OPTION_SECURITY_FLAGS
                    &security_flags as *const u32 as *const c_void,
                    core::mem::size_of::<u32>() as u32,
                );
            }

            // Send the HTTP request
            let (req_body, body_len) = match body {
                Some(data) => (data.as_ptr() as *const c_void, data.len() as u32),
                None => (null(), 0),
            };

            let headers_utf16: Vec<u16>;
            let mut headers_len = 0;
            let headers_ptr = if let Some(headers_str) = &self.headers {
                headers_utf16 = headers_str.encode_utf16().chain(Some(0)).collect();
                headers_len = headers_utf16.len();
                headers_utf16.as_ptr()
            } else {
                null()
            };

            let sent = (instance.winhttp.send_request)(
                request,
                headers_ptr,
                0,
                req_body,
                body_len,
                body_len,
                0,
            );
            if !sent {
                let err = (instance.k32.get_last_error)();
                (instance.winhttp.close_handle)(request);
                (instance.winhttp.close_handle)(connection);
                (instance.winhttp.close_handle)(session);
                return Err(err);
            }

            // Receive the HTTP response
            let received = (instance.winhttp.receive_response)(request, null_mut());
            if !received {
                let err = (instance.k32.get_last_error)();
                (instance.winhttp.close_handle)(request);
                (instance.winhttp.close_handle)(connection);
                (instance.winhttp.close_handle)(session);
                return Err(err);
            }

            // Read the HTTP response data
            let mut buffer = [0u8; 4096];
            let mut response = Vec::new();

            loop {
                let mut bytes_read = 0;
                let read = (instance.winhttp.read_data)(
                    request,
                    buffer.as_mut_ptr() as *mut _,
                    buffer.len() as u32,
                    &mut bytes_read,
                );
                if !read || bytes_read == 0 {
                    break;
                }
                response.extend_from_slice(&buffer[..bytes_read as usize]);
            }

            // Cleanup handles
            (instance.winhttp.close_handle)(request);
            (instance.winhttp.close_handle)(connection);
            (instance.winhttp.close_handle)(session);

            Ok(response)
        }
    }
}


pub fn split_url(url: &str) -> (String, String) {
    let link_parts: Vec<&str> = url.split("/").filter(|&x| x != "").collect();
    let mut addr_position = 0;
    if link_parts[0].starts_with("http") {
        addr_position = 1
    }
    let mut addr = link_parts[addr_position].to_string();
    let mut path = String::from("/");
    path.push_str(&link_parts[addr_position + 1..].join("/"));
    (addr, path)
}
