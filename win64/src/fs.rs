use core::{ffi::c_void, ptr::null_mut};

use alloc::string::String;
use alloc::vec::Vec;

use crate::get_instance;

pub fn get_cwd() -> Result<String, u32> {
    const MAX_PATH: usize = 260;
    let mut buffer: Vec<u16> = Vec::with_capacity(MAX_PATH);
    buffer.resize(MAX_PATH, 0);

    let len = unsafe {
        (get_instance().unwrap().k32.get_current_directory_w)(
            MAX_PATH as u32,
            buffer.as_mut_ptr(),
        )
    };

    if len == 0 {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    // Truncate to actual length and convert to String
    buffer.truncate(len as usize);
    Ok(String::from_utf16_lossy(&buffer))
}

pub fn write_file(path: &str, buf: Vec<u8>) -> Result<(), u32> {
    let mut path_w: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();

    let h_file = unsafe {
        (get_instance().unwrap().k32.create_file_w)(
            path_w.as_mut_ptr(),
            0x40000000, //GENERIC_WRITE
            1,
            null_mut(),
            2,
            0x80,
            null_mut(),
        )
    };

    let mut bytes_written = 0;
    if h_file.is_null() || h_file == 0xffffffffffffffff as *mut c_void {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }
    if !unsafe {
        (get_instance().unwrap().k32.write_file)(
            h_file,
            buf.as_ptr() as *mut c_void,
            buf.len() as u32,
            &mut bytes_written,
            null_mut(),
        )
    } {
        unsafe { (get_instance().unwrap().k32.close_handle)(h_file) };
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    unsafe { (get_instance().unwrap().k32.close_handle)(h_file) };
    Ok(())
}

pub fn read_file(path: &str) -> Result<Vec<u8>, u32> {
    let path_w: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let h_file = unsafe {
        (get_instance().unwrap().k32.create_file_w)(
            path_w.as_ptr(),
            0x80000000, //GENERIC_READ
            4 | 1 | 2,  //delete | read|write
            null_mut(),
            3,
            0x80,
            null_mut(),
        )
    };
    if h_file.is_null() || h_file == 0xffffffffffffffff as *mut c_void {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }
    let mut size_high = 0u32;
    let size_low = unsafe { (get_instance().unwrap().k32.get_file_size)(h_file, &mut size_high) };

    let total_size = ((size_high as u64) << 32) | (size_low as u64);
    let mut buffer = Vec::with_capacity(total_size as usize);
    buffer.resize(total_size as usize, 0);

    let mut bytes_read = 0;
    let read_result = unsafe {
        (get_instance().unwrap().k32.read_file)(
            h_file,
            buffer.as_mut_ptr(),
            total_size as u32,
            &mut bytes_read,
            null_mut(),
        )
    };

    unsafe { (get_instance().unwrap().k32.close_handle)(h_file) };
    Ok(buffer)
}

pub fn delete_file(path: &str) -> Result<(), u32> {
    let path_w: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();

    if !unsafe { (get_instance().unwrap().k32.delete_file_w)(path_w.as_ptr()) } {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    Ok(())
}
