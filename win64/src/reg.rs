use core::{
    ffi::c_void,
    ptr::{null, null_mut}
};

use alloc::{string::String, vec::Vec};

use crate::get_instance;

pub fn reg_create_key(key_path: &str) -> Result<*mut c_void, u32> {
    let (root_key, subkey) = get_root_key(key_path)?;

    let subkey_w: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();

    let mut hkey: *mut c_void = null_mut();
    let mut disposition: u32 = 0;

    let result = unsafe {
        (get_instance().unwrap().advapi.reg_create_key_ex_w)(
            root_key,
            subkey_w.as_ptr(),
            0,
            null_mut(),
            0,
            0x20006,
            null_mut(),
            &mut hkey,
            &mut disposition,
        )
    };

    if result != 0 {
        return Err(result as u32);
    }

    Ok(hkey)
}

pub fn reg_delete_key(key_path:&str) -> Result<(), u32> {
    let (root_key, subkey) = get_root_key(key_path)?;
    let subkey_w: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();
    unsafe{(get_instance().unwrap().advapi.reg_delete_key_w)(
        root_key,
        subkey_w.as_ptr(),
    )};
    Ok(())

}

///returns a rootkey/subkey
fn get_root_key(key_path: &str) -> Result<(*mut c_void, String), u32> {
    let key_str = key_path.to_ascii_uppercase();
    let mut root_key = null_mut();

    if key_str.starts_with("HKCR") || key_str.starts_with("HKEY_CLASSES_ROOT") {
        root_key = HKEY_CLASSES_ROOT;
    } else if key_str.starts_with("HKCU") || key_str.starts_with("HKEY_CURRENT_USER") {
        root_key = HKEY_CURRENT_USER;
    } else if key_str.starts_with("HKLM") || key_str.starts_with("HKEY_LOCAL_MACHINE") {
        root_key = HKEY_LOCAL_MACHINE;
    } else if key_str.starts_with("HKU") || key_str.starts_with("HKEY_USERS") {
        root_key = HKEY_USERS;
    } else if key_str.starts_with("HKCC") || key_str.starts_with("HKEY_CURRENT_CONFIG") {
        root_key = HKEY_CURRENT_CONFIG;
    } else {
        return Err(0x80070057);
    }

    let mut subkey = &key_path.split("\\").collect::<Vec<&str>>()[1..].join("\\");

    Ok((root_key, String::from(subkey)))
}



const HKEY_CLASSES_ROOT: *mut c_void = 0x80000000 as *mut c_void;
const HKEY_CURRENT_USER: *mut c_void = 0x80000001 as *mut c_void;
const HKEY_LOCAL_MACHINE: *mut c_void = 0x80000002 as *mut c_void;
const HKEY_USERS: *mut c_void = 0x80000003 as *mut c_void;
const HKEY_CURRENT_CONFIG: *mut c_void = 0x80000005 as *mut c_void;

// Registry value types
const REG_NONE: u32 = 0x00000000;
const REG_SZ: u32 = 0x00000001;
const REG_EXPAND_SZ: u32 = 0x00000002;
const REG_BINARY: u32 = 0x00000003;
const REG_DWORD: u32 = 0x00000004;
const REG_DWORD_BIG_ENDIAN: u32 = 0x00000005;
const REG_LINK: u32 = 0x00000006;
const REG_MULTI_SZ: u32 = 0x00000007;
const REG_RESOURCE_LIST: u32 = 0x00000008;
const REG_QWORD: u32 = 0x0000000B;

/// Parse registry value type from string
fn parse_reg_type(type_str: &str) -> Option<u32> {
    match type_str.to_ascii_uppercase().as_str() {
        "REG_NONE" => Some(REG_NONE),
        "REG_SZ" => Some(REG_SZ),
        "REG_EXPAND_SZ" => Some(REG_EXPAND_SZ),
        "REG_BINARY" => Some(REG_BINARY),
        "REG_DWORD" | "REG_DWORD_LITTLE_ENDIAN" => Some(REG_DWORD),
        "REG_DWORD_BIG_ENDIAN" => Some(REG_DWORD_BIG_ENDIAN),
        "REG_LINK" => Some(REG_LINK),
        "REG_MULTI_SZ" => Some(REG_MULTI_SZ),
        "REG_RESOURCE_LIST" => Some(REG_RESOURCE_LIST),
        "REG_QWORD" | "REG_QWORD_LITTLE_ENDIAN" => Some(REG_QWORD),
        _ => None,
    }
}

/// Set a registry value
/// key_path: Full path like "HKLM\SOFTWARE\MyApp"
/// value_name: Name of the value (empty string for default)
/// value_type: Type string like "REG_SZ", "REG_DWORD", "REG_BINARY"
/// value: Raw bytes of the value
pub fn reg_set_value(key_path: &str, value_name: &str, value_type: &str, value: &[u8]) -> Result<(), u32> {
    let dw_type = parse_reg_type(value_type).ok_or(0x80070057u32)?;

    // Create/open the key
    let hkey = reg_create_key(key_path)?;

    let value_name_w: Vec<u16> = value_name.encode_utf16().chain(Some(0)).collect();

    // For string types, convert UTF-8 value to UTF-16LE for the W API
    let wide_buf: Vec<u8> = if dw_type == REG_SZ || dw_type == REG_EXPAND_SZ {
        let value_str = String::from_utf8_lossy(value);
        let value_w: Vec<u16> = value_str.encode_utf16().chain(Some(0)).collect();
        value_w.iter().flat_map(|w| w.to_le_bytes()).collect()
    } else {
        Vec::new()
    };
    let (data_ptr, data_len) = if !wide_buf.is_empty() {
        (wide_buf.as_ptr(), wide_buf.len() as u32)
    } else {
        (value.as_ptr(), value.len() as u32)
    };

    let result = unsafe {
        (get_instance().unwrap().advapi.reg_set_value_ex_w)(
            hkey,
            value_name_w.as_ptr(),
            0,
            dw_type,
            data_ptr,
            data_len,
        )
    };

    // Close the key
    unsafe { (get_instance().unwrap().advapi.reg_close_key)(hkey) };

    if result != 0 {
        return Err(result as u32);
    }

    Ok(())
}

/// Query a registry value
/// key_path: Full path like "HKLM\SOFTWARE\MyApp"
/// value_name: Name of the value (empty string for default)
/// Returns: (type, data) tuple
pub fn reg_query_value(key_path: &str, value_name: &str) -> Result<Vec<u8>, u32> {
    let (root_key, subkey) = get_root_key(key_path)?;
    let subkey_w: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();

    let mut hkey: *mut c_void = null_mut();

    // Open the key with read access
    let result = unsafe {
        (get_instance().unwrap().advapi.reg_open_key_ex_w)(
            root_key,
            subkey_w.as_ptr(),
            0,
            0x20019, // KEY_READ
            &mut hkey,
        )
    };

    if result != 0 {
        return Err(result as u32);
    }

    let value_name_w: Vec<u16> = value_name.encode_utf16().chain(Some(0)).collect();

    // First call to get the size
    let mut data_type: u32 = 0;
    let mut data_size: u32 = 0;

    let result = unsafe {
        (get_instance().unwrap().advapi.reg_query_value_ex_w)(
            hkey,
            value_name_w.as_ptr(),
            null(),
            &mut data_type,
            null_mut(),
            &mut data_size,
        )
    };

    if result != 0 {
        unsafe { (get_instance().unwrap().advapi.reg_close_key)(hkey) };
        return Err(result as u32);
    }

    // Allocate buffer and get the data
    let mut data: Vec<u8> = Vec::with_capacity(data_size as usize);
    data.resize(data_size as usize, 0);

    let result = unsafe {
        (get_instance().unwrap().advapi.reg_query_value_ex_w)(
            hkey,
            value_name_w.as_ptr(),
            null(),
            &mut data_type,
            data.as_mut_ptr(),
            &mut data_size,
        )
    };

    unsafe { (get_instance().unwrap().advapi.reg_close_key)(hkey) };

    if result != 0 {
        return Err(result as u32);
    }

    // Truncate to actual size
    data.truncate(data_size as usize);

    // For string types, convert UTF-16LE back to UTF-8
    if data_type == REG_SZ || data_type == REG_EXPAND_SZ {
        let mut u16_buf: Vec<u16> = Vec::with_capacity(data.len() / 2);
        let mut i = 0;
        while i + 1 < data.len() {
            let w = (data[i] as u16) | ((data[i + 1] as u16) << 8);
            if w == 0 { break; }
            u16_buf.push(w);
            i += 2;
        }
        let s = String::from_utf16_lossy(&u16_buf);
        return Ok(s.into_bytes());
    }

    Ok(data)
}
