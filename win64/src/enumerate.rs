use crate::{
    get_instance,
    libs::k32::PROCESSENTRY32W,
    libs::ntdef::PROCESS_BASIC_INFORMATION,
};
use alloc::{string::String, vec::Vec};
use core::ffi::c_void;
use core::mem::{zeroed, size_of};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub image: String,
    pub cmdline: Option<String>,
}

pub fn list_procs() -> Vec<ProcessInfo> {
    let mut process_info: Vec<ProcessInfo> = Vec::new();

    let snapshot = unsafe {
        (get_instance().unwrap().k32.create_toolhelp_32_snapshot)(
            0x2, //TH32CS_SNAPPROCESS
            0,
        )
    };

    let mut process_entry: PROCESSENTRY32W = unsafe { zeroed() };
    process_entry.dw_size = size_of::<PROCESSENTRY32W>() as u32;

    if !unsafe { (get_instance().unwrap().k32.process_32_first)(snapshot, &mut process_entry) } {
        unsafe { (get_instance().unwrap().k32.close_handle)(snapshot) };
        return process_info;
    };

    loop {
        let h_proc = unsafe {
            (get_instance().unwrap().k32.open_process)(
                0x0010 |  // PROCESS_VM_READ
                0x0400 |  // PROCESS_QUERY_INFORMATION
                0x0800, // PROCESS_QUERY_LIMITED_INFORMATION
                false,
                process_entry.th32_process_id,
            )
        };

        if !h_proc.is_null() {
            let pbi = get_process_basic_info(h_proc);
            if let Some(peb_addr) = pbi {
                let cmdline = read_process_parameters(h_proc, peb_addr);
                process_info.push(ProcessInfo {
                    pid: process_entry.th32_process_id,
                    ppid: process_entry.th32_parent_process_id,
                    image: {
                        let end = process_entry.sz_exe_file.iter().position(|&c| c == 0).unwrap_or(process_entry.sz_exe_file.len());
                        String::from_utf16_lossy(&process_entry.sz_exe_file[..end])
                    },
                    cmdline,
                });
            }
            unsafe { (get_instance().unwrap().k32.close_handle)(h_proc) };
        }

        if !unsafe { (get_instance().unwrap().k32.process_32_next)(snapshot, &mut process_entry) } {
            break;
        }
    }

    unsafe { (get_instance().unwrap().k32.close_handle)(snapshot) };
    return process_info;
}

fn get_process_basic_info(handle: *mut c_void) -> Option<usize> {
    let mut info: PROCESS_BASIC_INFORMATION = unsafe { zeroed() };
    let mut return_length = 0;

    if unsafe {
        (get_instance().unwrap().ntdll.nt_query_information_process)(
            handle,
            0,
            &mut info as *mut _ as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length,
        )
    } == 0
    {
        Some(info.peb_base_address as usize)
    } else {
        None
    }
}

fn read_process_parameters(handle: *mut c_void, peb_addr: usize) -> Option<String> {
    let mut peb: PEB = unsafe { zeroed() };
    let mut bytes_read = 0;

    if !unsafe {
        (get_instance().unwrap().k32.read_process_memory)(
            handle,
            peb_addr as *const c_void,
            &mut peb as *mut _ as *mut c_void,
            size_of::<PEB>(),
            &mut bytes_read,
        )
    } {
        return None;
    }

    let mut params: RTL_USER_PROCESS_PARAMETERS = unsafe { zeroed() };
    if !unsafe {
        (get_instance().unwrap().k32.read_process_memory)(
            handle,
            peb.process_parameters as *const c_void,
            &mut params as *mut _ as *mut c_void,
            size_of::<RTL_USER_PROCESS_PARAMETERS>(),
            &mut bytes_read,
        )
    } {
        //todo: return proc name if this doesn't work?

        return None;
    }

    let mut cmdline: Vec<u16> = Vec::with_capacity(params.command_line.length as usize);
    cmdline.resize(params.command_line.length as usize, 0);

    if !unsafe {
        (get_instance().unwrap().k32.read_process_memory)(
            handle,
            params.command_line.buffer as *const c_void,
            cmdline.as_mut_ptr() as *mut c_void,
            params.command_line.length as usize,
            &mut bytes_read,
        )
    } {
        None
    } else {
        cmdline.retain(|&x| x != 0);
        Some(String::from_utf16_lossy(&cmdline))
    }
}




#[repr(C)]
struct PEB {
    reserved1: [u8; 2],
    being_debugged: u8,
    reserved2: u8,
    reserved3: [*mut c_void; 2],
    ldr: *mut c_void,
    process_parameters: *mut RTL_USER_PROCESS_PARAMETERS,
    pub reserved4: [*mut c_void; 3],
    pub atl_thunk_slist_ptr: *mut c_void,
    pub reserved5: *mut c_void,
    pub reserved6: u32,
    pub reserved7: *mut c_void,
    pub reserved8: u32,
    pub atl_thunk_slist_ptr32: u32,
    pub reserved9: [*mut c_void; 45],
    pub reserved10: [u8; 96],
    pub post_process_init_routine: PPS_POST_PROCESS_INIT_ROUTINE,
    pub reserved11: [u8; 128],
    pub reserved12: [*mut c_void; 1],
    pub session_id: u32,
}

#[repr(C)]
struct RTL_USER_PROCESS_PARAMETERS {
    reserved1: [u8; 16],
    reserved2: [*mut c_void; 10],
    image_path_name: UNICODE_STRING,
    command_line: UNICODE_STRING,
}

#[repr(C)]
struct UNICODE_STRING {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

pub type PPS_POST_PROCESS_INIT_ROUTINE = Option<unsafe extern "system" fn()>;

// ============================================================================
// Port Scanner (requires network feature)
// ============================================================================

#[cfg(feature = "network")]
#[derive(Serialize, Deserialize)]
pub struct PortscanResult {
    pub host: String,
    pub port: u16,
    pub open: bool,
}

#[cfg(feature = "network")]
use crate::libs::winsock::{
    init_winsock, SockAddrIn, SOCKET, WSAPOLLFD, POLLOUT, FIONBIO,
};
#[cfg(feature = "network")]
use crate::libs::utils::{parse_hosts, parse_ports, ipv4_to_string, Host, PortRange};

#[cfg(feature = "network")]
const MAX_NUM_SOCKETS: usize = 128;
#[cfg(feature = "network")]
const CONN_TIMEOUT: i32 = 100;
#[cfg(feature = "network")]
const INVALID_SOCKET: SOCKET = !0;
#[cfg(feature = "network")]
const SOCKET_ERROR: i32 = -1;

/// Create a non-blocking TCP socket
#[cfg(feature = "network")]
fn create_tcp_socket() -> Option<SOCKET> {
    unsafe {
        let sock = (get_instance().unwrap().winsock.socket)(2, 1, 6); // AF_INET, SOCK_STREAM, IPPROTO_TCP
        if sock == INVALID_SOCKET {
            return None;
        }

        // Set socket to non-blocking mode
        let mut mode: u32 = 1;
        if (get_instance().unwrap().winsock.ioctlsocket)(sock, FIONBIO, &mut mode) != 0 {
            (get_instance().unwrap().winsock.closesocket)(sock);
            return None;
        }

        Some(sock)
    }
}

/// Connect TCP socket (non-blocking, returns true if connection initiated)
#[cfg(feature = "network")]
fn connect_tcp_socket(sock: SOCKET, ip: u32, port: u16) -> bool {
    unsafe {
        let mut server: SockAddrIn = core::mem::zeroed();
        server.sin_family = 2; // AF_INET
        server.sin_port = port.to_be();
        server.sin_addr.s_addr = ip.to_be(); // Convert to network byte order

        let result = (get_instance().unwrap().winsock.connect)(
            sock,
            &server as *const SockAddrIn as *const _,
            core::mem::size_of::<SockAddrIn>() as i32,
        );

        if result == SOCKET_ERROR {
            // WSAEWOULDBLOCK (10035) means connection in progress - that's expected for non-blocking
            let err = (get_instance().unwrap().winsock.wsa_get_last_error)();
            return err == 10035; // WSAEWOULDBLOCK
        }

        true
    }
}

/// Close all sockets in the array
#[cfg(feature = "network")]
fn close_all_sockets(sockets: &mut Vec<SOCKET>) {
    unsafe {
        for &sock in sockets.iter() {
            (get_instance().unwrap().winsock.closesocket)(sock);
        }
    }
    sockets.clear();
}

/// Poll sockets for connection completion
#[cfg(feature = "network")]
fn connect_or_timeout(
    sockets: &[SOCKET],
    ip: u32,
    ports: &[u16],
    results: &mut Vec<PortscanResult>,
) {
    if sockets.is_empty() {
        return;
    }

    let num_sockets = sockets.len();
    let mut poll_fds: Vec<WSAPOLLFD> = Vec::with_capacity(num_sockets);

    // Initialize poll array for connection check
    for &sock in sockets.iter() {
        poll_fds.push(WSAPOLLFD {
            fd: sock,
            events: POLLOUT,
            revents: 0,
        });
    }

    unsafe {
        // Poll for connection completion
        let result = (get_instance().unwrap().winsock.wsa_poll)(
            poll_fds.as_mut_ptr(),
            num_sockets as u32,
            CONN_TIMEOUT,
        );

        let ip_str = ipv4_to_string(ip);

        // Always report results after poll (even if result <= 0, ports are closed)
        for (i, pfd) in poll_fds.iter().enumerate() {
            // POLLOUT set means connection succeeded
            let open = result > 0 && (pfd.revents & POLLOUT != 0);

            results.push(PortscanResult {
                host: ip_str.clone(),
                port: ports[i],
                open,
            });
        }
    }
}

/// Test all ports on a single IP
#[cfg(feature = "network")]
fn test_ports_on_ip(ip: u32, port_ranges: &[PortRange], results: &mut Vec<PortscanResult>) {
    let mut sockets: Vec<SOCKET> = Vec::with_capacity(MAX_NUM_SOCKETS);
    let mut ports: Vec<u16> = Vec::with_capacity(MAX_NUM_SOCKETS);

    for range in port_ranges {
        let mut port = range.start;
        while port <= range.end {
            // Create TCP socket
            let sock = match create_tcp_socket() {
                Some(s) => s,
                None => {
                    close_all_sockets(&mut sockets);
                    return;
                }
            };

            // Initiate connection
            if !connect_tcp_socket(sock, ip, port) {
                unsafe {
                    (get_instance().unwrap().winsock.closesocket)(sock);
                }
            } else {
                sockets.push(sock);
                ports.push(port);
            }

            // If we've filled the batch, poll and reset
            if sockets.len() >= MAX_NUM_SOCKETS {
                connect_or_timeout(&sockets, ip, &ports, results);
                close_all_sockets(&mut sockets);
                ports.clear();
            }

            port = port.wrapping_add(1);
            if port == 0 {
                break; // Wrapped around, we're done
            }
        }
    }

    // Process remaining sockets
    if !sockets.is_empty() {
        connect_or_timeout(&sockets, ip, &ports, results);
        close_all_sockets(&mut sockets);
    }
}

/// Main portscan function
/// targets: comma-separated hosts (IPs, ranges, CIDRs, hostnames)
/// ports_str: comma-separated ports or port ranges (e.g., "80,443,8000-8100")
#[cfg(feature = "network")]
pub fn portscan(targets: &str, ports_str: &str) -> Result<Vec<PortscanResult>, u32> {
    let hosts = parse_hosts(targets).map_err(|_| 0x80070057u32)?;
    let port_ranges = parse_ports(ports_str).map_err(|_| 0x80070057u32)?;

    init_winsock();

    let mut results: Vec<PortscanResult> = Vec::new();

    for host in &hosts {
        match host {
            Host::Range(range) => {
                let mut ip = range.start;
                loop {
                    test_ports_on_ip(ip, &port_ranges, &mut results);

                    if ip >= range.end {
                        break;
                    }
                    ip = ip.wrapping_add(1);
                }
            }
            Host::Single(iphost) => {
                test_ports_on_ip(iphost.addr, &port_ranges, &mut results);
            }
        }
    }

    unsafe {
        (get_instance().unwrap().winsock.wsa_cleanup)();
    }

    Ok(results)
}

/// Serialize portscan results (only open ports) as postcard bytes
#[cfg(feature = "network")]
pub fn serialize_portscan_results(results: &[PortscanResult]) -> Vec<u8> {
    let open: Vec<&PortscanResult> = results.iter().filter(|r| r.open).collect();
    postcard::to_allocvec(&open).unwrap_or_default()
}
