use core::{
    ffi::c_void,
    ptr::{null, null_mut},
    slice::from_raw_parts,
};

use alloc::{
    collections::btree_map::BTreeMap, string::{String, ToString}, vec::Vec
};

use crate::{
    get_instance,
    libs::{
        advapi::ACL,
        netapi32::{LOCALGROUP_MEMBERS_INFO_3, USER_INFO_1003},
        ntdef::{ACCESS_ALLOWED_ACE, ACE_HEADER},
    },
};

pub fn set_user_password(
    server_name: Option<&str>,
    username: &str,
    password: &str,
) -> Result<(), u32> {
    // Lazy init netapi32 if not loaded
    if unsafe { get_instance().unwrap().netapi.module_base.is_null() } {
        crate::libs::netapi32::init_netapi32_funcs();
    }

    let server_name_w = server_name.map(|s| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>());
    //.map_or(null(), |s| s.as_ptr());
    let server_name_ptr = server_name_w.as_ref().map_or(null(), |vec| vec.as_ptr());
    let username_w = username.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let mut new_password_w = password.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();

    let mut user_info = USER_INFO_1003 {
        usri1003_password: new_password_w.as_mut_ptr(),
    };

    let set_info_res = unsafe {
        (get_instance().unwrap().netapi.net_user_set_info)(
            server_name_ptr,
            username_w.as_ptr(),
            1003,
            &mut user_info as *mut _ as *mut u8,
            null_mut(),
        )
    };
    if set_info_res != 0 {
        return Err(set_info_res as u32);
    }
    Ok(())
}

pub fn add_user_to_localgroup(
    server_name: Option<&str>,
    group_name: &str,
    username: &str,
) -> Result<(), u32> {
    // Lazy init netapi32 if not loaded
    if unsafe { get_instance().unwrap().netapi.module_base.is_null() } {
        crate::libs::netapi32::init_netapi32_funcs();
    }

    let server_name_w = server_name.map(|s| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>());
    let server_name_ptr = server_name_w.as_ref().map_or(null(), |vec| vec.as_ptr());

    let group_name_w: Vec<u16> = group_name.encode_utf16().chain(Some(0)).collect();
    let mut username_w: Vec<u16> = username.encode_utf16().chain(Some(0)).collect();

    // Prepare the LOCALGROUP_MEMBERS_INFO_3 structure
    let member_info = LOCALGROUP_MEMBERS_INFO_3 {
        lgrmi3_domainandname: username_w.as_mut_ptr(),
    };

    // Call NetLocalGroupAddMembers
    let res = unsafe {
        (get_instance().unwrap().netapi.net_localgroup_add_members)(
            server_name_ptr,
            group_name_w.as_ptr(),
            3, // Level 3 for LOCALGROUP_MEMBERS_INFO_3
            &member_info as *const _ as *mut _,
            1, // Number of entries
        )
    };

    if res != 0 {
        return Err(res as u32);
    }

    Ok(())
}

pub fn remove_user_from_localgroup(
    server_name: Option<&str>,
    group_name: &str,
    username: &str,
) -> Result<(), u32> {
    // Lazy init netapi32 if not loaded
    if unsafe { get_instance().unwrap().netapi.module_base.is_null() } {
        crate::libs::netapi32::init_netapi32_funcs();
    }

    let server_name_w = server_name.map(|s| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>());
    let server_name_ptr = server_name_w.as_ref().map_or(null(), |vec| vec.as_ptr());

    let group_name_w: Vec<u16> = group_name.encode_utf16().chain(Some(0)).collect();
    let mut username_w: Vec<u16> = username.encode_utf16().chain(Some(0)).collect();

    // Prepare the LOCALGROUP_MEMBERS_INFO_3 structure
    let member_info = LOCALGROUP_MEMBERS_INFO_3 {
        lgrmi3_domainandname: username_w.as_mut_ptr(),
    };

    let mut members = [member_info];
    // Call NetLocalGroupAddMembers
    let res = unsafe {
        (get_instance().unwrap().netapi.net_localgroup_del_members)(
            server_name_ptr,
            group_name_w.as_ptr(),
            3, // Level 3 for LOCALGROUP_MEMBERS_INFO_3
            members.as_mut_ptr() as *mut _,
            1, // Number of entries
        )
    };

    if res != 0 {
        return Err(res as u32);
    }

    Ok(())
}

pub fn get_user_sid(server_name: Option<&str>, username: &str) -> Result<String, u32> {
    let server_name_w = server_name.map(|s| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>());
    let server_name_ptr = server_name_w.as_ref().map_or(null(), |vec| vec.as_ptr());

    let mut username_w: Vec<u16> = username.encode_utf16().chain(Some(0)).collect();

    let mut sid_len = 0;
    let mut dom_len = 0;
    let mut name_use: *mut i32 = null_mut();

    if !unsafe {
        (get_instance().unwrap().advapi.lookup_account_name_w)(
            server_name_ptr,
            username_w.as_ptr(),
            null_mut(),
            &mut sid_len,
            null_mut(),
            &mut dom_len,
            &mut name_use as *mut _ as *mut *mut i32,
        )
    } {
        let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
        if err != 0x7a {
            return Err(err);
        }
    }

    let mut sid: Vec<u8> = Vec::with_capacity(sid_len as usize);
    let mut dom: Vec<u16> = Vec::with_capacity(dom_len as usize);

    if !unsafe {
        (get_instance().unwrap().advapi.lookup_account_name_w)(
            server_name_ptr,
            username_w.as_ptr(),
            sid.as_mut_ptr() as *mut _ as *mut c_void,
            &mut sid_len,
            dom.as_mut_ptr(),
            &mut dom_len,
            &mut name_use as *mut _ as *mut *mut i32,
        )
    } {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    let sid_string = convert_sid_to_string(&mut sid)?;

    Ok(sid_string)
}

pub fn add_user_to_group(
    server_name: &str,
    group_name: &str,
    username: &str,
) -> Result<(), u32> {
    // Lazy init netapi32 if not loaded
    if unsafe { get_instance().unwrap().netapi.module_base.is_null() } {
        crate::libs::netapi32::init_netapi32_funcs();
    }

    let mut server_name_w = server_name
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<u16>>();
    let mut group_name_w: Vec<u16> = group_name.encode_utf16().chain(Some(0)).collect();
    let mut username_w: Vec<u16> = username.encode_utf16().chain(Some(0)).collect();
    let ret = unsafe {
        (get_instance().unwrap().netapi.net_group_add_user)(
            server_name_w.as_mut_ptr(),
            group_name_w.as_mut_ptr(),
            username_w.as_mut_ptr(),
        )
    };

    if ret != 0 {
        return Err(ret as u32);
    }
    Ok(())
}

pub fn remove_user_from_group(
    server_name: &str,
    group_name: &str,
    username: &str,
) -> Result<(), u32> {
    // Lazy init netapi32 if not loaded
    if unsafe { get_instance().unwrap().netapi.module_base.is_null() } {
        crate::libs::netapi32::init_netapi32_funcs();
    }

    let mut server_name_w = server_name
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<u16>>();
    let mut group_name_w: Vec<u16> = group_name.encode_utf16().chain(Some(0)).collect();
    let mut username_w: Vec<u16> = username.encode_utf16().chain(Some(0)).collect();
    let ret = unsafe {
        (get_instance().unwrap().netapi.net_group_del_user)(
            server_name_w.as_mut_ptr(),
            group_name_w.as_mut_ptr(),
            username_w.as_mut_ptr(),
        )
    };

    if ret != 0 {
        return Err(ret as u32);
    }
    Ok(())
}

pub fn convert_sid_to_string(sid: &mut Vec<u8>) -> Result<String, u32> {
    let mut sid_string_ptr: *mut u16 = null_mut();
    if !unsafe {
        (get_instance().unwrap().advapi.convert_sid_to_string_sid_w)(
            sid.as_mut_ptr() as *mut c_void,
            &mut sid_string_ptr,
        )
    } {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }
    let sid_string = unsafe {
        let len = (0..)
            .take_while(|&i| *sid_string_ptr.offset(i) != 0)
            .count();
        String::from_utf16_lossy(from_raw_parts(sid_string_ptr, len))
    };
    Ok(sid_string)
}

pub fn create_rbcd_ace(sid: Vec<u8>) -> Result<Vec<u8>, u32> {

    let mut security_descriptor: [u8; 0x14] = [0; 0x14]; // SECURITY_DESCRIPTOR size is 20 bytes
    if !unsafe {
        (get_instance()
            .unwrap()
            .advapi
            .initialize_security_descriptor)(
            security_descriptor.as_mut_ptr() as *mut c_void,
            1, // SECURITY_DESCRIPTOR_REVISION
        )
    } {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    let admin_sid = [
        0x01_u8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02,
        0x00, 0x00,
    ]
    .to_vec();

    if !unsafe {
        (get_instance().unwrap().advapi.set_security_descriptor_owner)(
            security_descriptor.as_mut_ptr() as *mut c_void,
            admin_sid.as_ptr() as *mut c_void,
            false, // bOwnerDefaulted
        )
    } {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    let permissions = 983551; // sddl string = CCDCLCSWRPWPDTLOCRSDRCWDWO basically every permission
    let mut ace = ACCESS_ALLOWED_ACE {
        Header: ACE_HEADER {
            AceType: 0, //ACCESS_ALLOWED_ACE_TYPE
            AceFlags: 0,
            AceSize: size_of::<ACCESS_ALLOWED_ACE>() as u16,
        },
        Mask: permissions,
        SidStart: sid.as_ptr() as u32, // Assign the SID here
    };

    let acl_size = size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() + sid.len();
    let mut acl_buf = Vec::<u8>::with_capacity(acl_size);
    let pacl = acl_buf.as_mut_ptr();

    if !unsafe { (get_instance().unwrap().advapi.initialize_acl)(pacl as _, acl_size as u32, 2) } {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    if !unsafe {
        (get_instance().unwrap().advapi.add_access_allowed_ace_ex)(
            pacl as _,
            2,
            0,
            permissions,
            sid.as_ptr() as _,
        )
    } {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    if !unsafe {
        (get_instance().unwrap().advapi.set_security_descriptor_dacl)(
            security_descriptor.as_mut_ptr() as *mut c_void,
            true, // bDaclPresent
            pacl as _,
            false, // bDaclDefaulted
        )
    } {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    let mut sd_size: u32 = 0;
    if !unsafe {
        (get_instance().unwrap().advapi.make_self_relative_sd)(
            security_descriptor.as_mut_ptr() as *mut c_void,
            null_mut(),
            &mut sd_size,
        )
    } {
        let err = unsafe { (get_instance().unwrap().k32.get_last_error)() };
        if err != 0x7a {
            return Err(err);
        }
    }

    let mut binary_sd: Vec<u8> = Vec::with_capacity(sd_size as usize);

    if !unsafe {
        (get_instance().unwrap().advapi.make_self_relative_sd)(
            security_descriptor.as_mut_ptr() as *mut c_void,
            binary_sd.as_mut_ptr() as *mut c_void,
            &mut sd_size,
        )
    } {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    unsafe { binary_sd.set_len(sd_size as usize) };

    Ok(binary_sd)
}



#[derive(Debug, Clone)]
pub struct TicketEntry {
    username: String,
    client_name: String,
    service: String,
    service_realm: String,
    base64: String,
}

pub struct KerberosTickets {
    tickets: Vec<TicketEntry>,
    index: BTreeMap<(String, String), usize>, // (ClientName, ServiceRealm) -> Index in `tickets`
}

impl KerberosTickets {
    /// Creates a new empty KerberosTickets struct
    pub fn new() -> Self {
        Self {
            tickets: Vec::new(),
            index: BTreeMap::new(),
        }
    }

    /// Parses the text and populates the tickets
    pub fn parse(&mut self, text: &str) {
        let mut current_client_name = String::new();
        let mut current_client_username = String::new();
        let mut current_service_realm = String::new();
        let mut current_service = String::new();
        let mut current_base64 = String::new();
        let mut in_ticket_block = false;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("ClientName") {
                current_client_name = trimmed.split(':').nth(1).unwrap_or("").trim().to_string();
                current_client_username = current_client_name.split('@').nth(0).unwrap_or("").trim().to_string();
                in_ticket_block = true;
            } else if trimmed.starts_with("ServiceRealm") {
                current_service_realm = trimmed.split(':').nth(1).unwrap_or("").trim().to_string();
                current_service = current_service_realm.split('/').nth(0).unwrap_or("").trim().to_string();
            } else if in_ticket_block && !trimmed.is_empty() && !trimmed.contains(':') {
                current_base64.push_str(trimmed);
            } else if in_ticket_block && trimmed.is_empty() && !current_base64.is_empty() {
                // End of ticket block
                if !current_client_name.is_empty() && !current_service_realm.is_empty() && !current_base64.is_empty() {
                    let entry = TicketEntry {
                        username: current_client_username.clone(),
                        client_name: current_client_name.clone(),
                        service: current_service.clone(),
                        service_realm: current_service_realm.clone(),
                        base64: current_base64.clone(),
                    };
                    self.index.insert((current_client_username.clone(), current_service.clone()), self.tickets.len());
                    self.tickets.push(entry);
                }
                current_client_name.clear();
                current_service_realm.clear();
                current_service.clear();
                current_base64.clear();
                current_client_username.clear();
                in_ticket_block = false;
            }
        }
    }

    /// Checks if a specific (client_name, service_realm) pair exists
    pub fn exists(&self, username: &str, service: &str) -> bool {
        self.index.contains_key(&(username.to_string(), service.to_string()))
    }

    /// Gets the base64 string for a specific (client_name, service_realm) pair
    pub fn get(&self, username: &str, service: &str) -> Option<&str> {
        self.index
            .get(&(username.to_string(), service.to_string()))
            .and_then(|&idx| self.tickets.get(idx))
            .map(|entry| entry.base64.as_str())
    }
}