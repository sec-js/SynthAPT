use core::{
    ffi::{c_void, CStr},
    mem::zeroed,
    ptr::{null, null_mut},
};

use alloc::{
    slice,
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    get_instance,
    libs::{
        ldap32::{BerElement, LDAPMessage, LDAPModW, LDAPModW_0, LDAP, LDAP_BERVAL},
        utils::int_to_str,
    },
};

fn bind_ldap(
    ldap_server: &str,
    username: Option<&str>,
    password: Option<&str>,
    domain: Option<&str>,
) -> Result<*mut LDAP, u32> {
    // For serverless binding (auto-discover DC), pass NULL instead of empty string
    let server_w: Vec<u16> = ldap_server.encode_utf16().chain(Some(0)).collect();
    let server_ptr = if ldap_server.is_empty() { null() } else { server_w.as_ptr() };
    let ldap_handle = unsafe { (get_instance().unwrap().ldap.ldap_init_w)(server_ptr, 389) }; // Port 389 for LDAP

    if ldap_handle.is_null() {
        return Err(unsafe { (get_instance().unwrap().ldap.ldap_get_last_error)() } as u32);
    }

    let connect_result =
        unsafe { (get_instance().unwrap().ldap.ldap_connect)(ldap_handle, null_mut()) };

    if connect_result != 0 {
        unsafe { (get_instance().unwrap().ldap.ldap_unbind)(ldap_handle) };
        return Err(connect_result as u32);
    }

    let version: u32 = 3;

    let setopt_response = unsafe {
        (get_instance().unwrap().ldap.ldap_set_option_w)(
            ldap_handle,
            0x11,
            &version as *const u32 as *const c_void,
        )
    };

    if setopt_response != 0 {
        unsafe { (get_instance().unwrap().ldap.ldap_unbind)(ldap_handle) };
        return Err(setopt_response as u32);
    }

    let mut dn = null();
    let mut cred = null();
    let mut auth_id: SEC_WINNT_AUTH_IDENTITY_W = unsafe { zeroed() };

    let mut username_buffer: Vec<u16> = Vec::new();
    let mut password_buffer: Vec<u16> = Vec::new();
    let mut domain_buffer: Vec<u16> = Vec::new();
    if let (Some(user), Some(pass)) = (username.as_deref(), password.as_deref()) {
        username_buffer = user.encode_utf16().chain(Some(0)).collect();
        password_buffer = pass.encode_utf16().chain(Some(0)).collect();

        auth_id.User = username_buffer.as_ptr() as *mut u16;
        auth_id.UserLength = username_buffer.len() as u32; // Exclude the null terminator from the length

        auth_id.Password = password_buffer.as_ptr() as *mut u16;
        auth_id.PasswordLength = password_buffer.len() as u32; // Exclude the null terminator from the length

        auth_id.Domain = null_mut(); // Optional, depending on your AD setup
        auth_id.DomainLength = 0; // Set to 0 if not used
        if let Some(dom) = domain {
            domain_buffer = dom.encode_utf16().chain(Some(0)).collect();
            auth_id.Domain = domain_buffer.as_ptr() as *mut u16; // Optional, depending on your AD setup
            auth_id.DomainLength = domain_buffer.len() as u32; // Set to 0 if not used
        }

        auth_id.Flags = 0x02; // SEC_WINNT_AUTH_IDENTITY_ANSI (using ANSI strings)

        cred = &mut auth_id as *const _ as *const u8;
    }

    let bind_result = unsafe {
        (get_instance().unwrap().ldap.ldap_bind_s)(
            ldap_handle,
            dn,
            cred,
            0x400 | 0x86, //LDAP_AUTH_NEGOTIATE
        )
    };

    if bind_result != 0 {
        unsafe { (get_instance().unwrap().ldap.ldap_unbind)(ldap_handle) };
        return Err(unsafe { (get_instance().unwrap().ldap.ldap_get_last_error)() } as u32);
    }
    Ok(ldap_handle)
}

pub fn set_ad_attr_str(
    ldap_server: &str,
    dn: &str,
    attribute: &str,
    new_value: &str,
    username: Option<&str>,
    password: Option<&str>,
    domain: Option<&str>,
) -> Result<(), u32> {
    // Convert inputs to UTF-16
    let dn_w: Vec<u16> = dn.encode_utf16().chain(Some(0)).collect();
    let mut attribute_w: Vec<u16> = attribute.encode_utf16().chain(Some(0)).collect();
    let new_value_w: Vec<u16> = new_value.encode_utf16().chain(Some(0)).collect();

    let ldap_handle = bind_ldap(ldap_server, username, password, domain)?;

    // Prepare the LDAP modification
    let mut values: [*mut u16; 2] = [new_value_w.as_ptr() as *mut u16, null_mut()];
    let mut ldap_mod = LDAPModW {
        mod_op: 2, //LDAP_MOD_REPLACE, // Replace the attribute's value
        mod_type: attribute_w.as_mut_ptr(),
        mod_vals: LDAPModW_0 {
            modv_strvals: values.as_ptr() as *mut *mut u16,
        },
    };

    let mut mods: [*mut LDAPModW; 2] = [&mut ldap_mod as *mut LDAPModW, null_mut()];

    // Perform the update
    let modify_result = unsafe {
        (get_instance().unwrap().ldap.ldap_modify_s_w)(
            ldap_handle,
            dn_w.as_ptr(),
            mods.as_mut_ptr(),
        )
    };
    if modify_result != 0 {
        unsafe { (get_instance().unwrap().ldap.ldap_unbind)(ldap_handle) };
        return Err(modify_result as u32);
    }

    // Unbind and clean up
    unsafe { (get_instance().unwrap().ldap.ldap_unbind)(ldap_handle) };

    Ok(())
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub struct SEC_WINNT_AUTH_IDENTITY_W {
    pub User: *mut u16,
    pub UserLength: u32,
    pub Domain: *mut u16,
    pub DomainLength: u32,
    pub Password: *mut u16,
    pub PasswordLength: u32,
    pub Flags: SEC_WINNT_AUTH_IDENTITY,
}
#[allow(non_camel_case_types)]
pub type SEC_WINNT_AUTH_IDENTITY = u32;

pub struct LdapAttribute {
    pub attr_name: String,
    pub is_binary: bool,
    pub str_val: Vec<String>,
    pub bin_val: Vec<Vec<u8>>,
}

impl LdapAttribute {
    fn new() -> Self {
        LdapAttribute {
            attr_name: String::new(),
            is_binary: false,
            str_val: Vec::new(),
            bin_val: Vec::new(),
        }
    }
}

///Scope:
/// LDAP_SCOPE_BASE = 0
/// LDAP_SCOPE_ONELEVEL = 1
/// LDAP_SCOPE_SUBTREE = 2
pub fn query_ldap(
    ldap_server: &str,
    dn: &str,
    base: &str,
    filter: &str,
    scope: u32,
    attributes: Option<Vec<&str>>,
    username: Option<&str>,
    password: Option<&str>,
    domain: Option<&str>,
) -> Result<Vec<Vec<LdapAttribute>>, u32> {
    let mut ldap_entries: Vec<Vec<LdapAttribute>> = Vec::new();

    let ldap_handle = bind_ldap(ldap_server, username, password, domain)?;
    let base_w = base.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let filter_w = filter.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let mut res: *mut LDAPMessage = null_mut();

    let mut attrs_w_vec: Vec<Vec<u16>> = Vec::new();
    let mut attrs: Vec<*const u16> = Vec::new();
    let mut attrs_ptr = null();
    if let Some(attrs_vec) = attributes {
        attrs_w_vec = attrs_vec
            .iter()
            .map(|&attr| attr.encode_utf16().chain(Some(0)).collect())
            .collect();
        attrs = attrs_w_vec.iter().map(|v| v.as_ptr()).collect();
        attrs_ptr = attrs.as_ptr();
    }

    let search_handle = unsafe {
        (get_instance().unwrap().ldap.ldap_search_init_page_w)(
            ldap_handle,
            base_w.as_ptr(),
            scope,
            filter_w.as_ptr(),
            attrs_ptr,
            0,
            null_mut(),
            null_mut(),
            0,
            1000,
            null_mut(),
        )
    };

    if search_handle == 0 {
        return Err(0x80004005);
    }

    loop {
        let search_result = unsafe {
            (get_instance().unwrap().ldap.ldap_get_next_page_s)(
                ldap_handle,
                search_handle,
                null_mut(),
                1000,
                null_mut(),
                &mut res,
            )
        };
        if search_result != 0 {
            break;
        }

        let mut entry = unsafe { (get_instance().unwrap().ldap.ldap_first_entry)(ldap_handle, res) };
        while !entry.is_null() {
            let mut entry_attributes: Vec<LdapAttribute> = Vec::new();
            let mut ber: *mut BerElement = null_mut();

            let mut attr = unsafe {
                (get_instance().unwrap().ldap.ldap_first_attribute)(ldap_handle, entry, &mut ber)
            };
            while !attr.is_null() {
                let mut ldap_attr = LdapAttribute::new();
                ldap_attr.attr_name = unsafe {
                    CStr::from_ptr(attr as *const i8)
                        .to_string_lossy()
                        .to_string()
                };

                ldap_attr.is_binary = is_binary_attribute(ldap_attr.attr_name.clone());

                if ldap_attr.is_binary {
                    let mut values = unsafe {
                        (get_instance().unwrap().ldap.ldap_get_values_len)(ldap_handle, entry, attr)
                    };
                    let values_ptr = values;

                    while !values.is_null() {
                        let value_ptr = unsafe { *values };
                        if !value_ptr.is_null() {
                            let value_slice = unsafe {
                                slice::from_raw_parts(
                                    (*value_ptr).bv_val as *const u8,
                                    (*value_ptr).bv_len as usize,
                                )
                            };
                            ldap_attr.bin_val.push(value_slice.to_vec());
                        } else {
                            break;
                        }
                        values = unsafe { values.add(1) };
                    }
                    if !values_ptr.is_null() {
                        unsafe { (get_instance().unwrap().ldap.ldap_value_free_len)(values_ptr) };
                    }
                } else {
                    let mut values = unsafe {
                        (get_instance().unwrap().ldap.ldap_get_values)(ldap_handle, entry, attr)
                    };
                    let values_ptr = values;

                    while !values.is_null() {
                        let value_ptr = unsafe { *values };
                        if !value_ptr.is_null() {
                            let value_slice = unsafe { CStr::from_ptr(value_ptr as *const i8) };
                            ldap_attr
                                .str_val
                                .push(value_slice.to_string_lossy().to_string());
                        } else {
                            break;
                        }
                        values = unsafe { values.add(1) };
                    }
                    if !values_ptr.is_null() {
                        unsafe { (get_instance().unwrap().ldap.ldap_value_free)(values_ptr) };
                    }
                }
                entry_attributes.push(ldap_attr);

                attr = unsafe {
                    (get_instance().unwrap().ldap.ldap_next_attribute)(ldap_handle, entry, ber)
                };
            }

            ldap_entries.push(entry_attributes);

            entry = unsafe { (get_instance().unwrap().ldap.ldap_next_entry)(ldap_handle, entry) };
        }
        unsafe { (get_instance().unwrap().ldap.ldap_msgfree)(res) };
    }

    unsafe { (get_instance().unwrap().ldap.ldap_search_abandon_page)(ldap_handle, search_handle) };
    unsafe { (get_instance().unwrap().ldap.ldap_unbind)(ldap_handle) };

    Ok(ldap_entries)
}

fn is_binary_attribute(attr_name: String) -> bool {
    let binary_attributes = [
        "objectSid",
        "objectGUID",
        "userCertificate",
        "cACertificate",
        "nTSecurityDescriptor",
        "schemaIDGUID",
        "pwdHistory",
        "msDS-GenerationId",
        "mSMQDigests",
        "mSMQSignCertificates",
    ];

    binary_attributes.iter().any(|&attr| attr_name.eq(attr))
}

pub fn set_ad_attr_bin(
    ldap_server: &str,
    dn: &str,
    attribute: &str,
    new_value: Option<&[u8]>,
    username: Option<&str>,
    password: Option<&str>,
    domain: Option<&str>,
) -> Result<(), u32> {
    // Convert inputs to UTF-16
    let dn_w: Vec<u16> = dn.encode_utf16().chain(Some(0)).collect();
    let mut attribute_w: Vec<u16> = attribute.encode_utf16().chain(Some(0)).collect();

    let ldap_handle = bind_ldap(ldap_server, username, password, domain)?;

    let mut value: LDAP_BERVAL = unsafe { zeroed() };
    let mut values: [*mut LDAP_BERVAL; 2] = [&value as *const _ as *mut _, null_mut()];
    let mut values_ptr = null_mut();
    let mut mod_op = 1 | 128u32; //LDAP_MOD_DELETE
    if let Some(new_value) = new_value {
        value.bv_len = new_value.len() as u32;
        value.bv_val = new_value.as_ptr() as *mut u8;
        mod_op = 2 | 128u32; //set LDAP_MOD_REPLACE
        values_ptr = values.as_mut_ptr() as *mut _
    }

    let mut ldap_mod = LDAPModW {
        mod_op: mod_op, //LDAP_MOD_REPLACE, // Replace the attribute's value
        mod_type: attribute_w.as_mut_ptr(),
        mod_vals: LDAPModW_0 {
            //modv_bvals: values.as_ptr() as *mut *mut LDAP_BERVAL, // Use the mutable reference to the value
            modv_bvals: values_ptr, // Use the mutable reference to the value
        },
    };

    let mut mods: [*mut LDAPModW; 2] = [&mut ldap_mod, null_mut()];

    let modify_result = unsafe {
        (get_instance().unwrap().ldap.ldap_modify_s_w)(
            ldap_handle,
            dn_w.as_ptr(),
            mods.as_mut_ptr(),
        )
    };
    if modify_result != 0 {
        unsafe { (get_instance().unwrap().ldap.ldap_unbind)(ldap_handle) };
        return Err(modify_result as u32);
    }

    // Unbind and clean up
    unsafe { (get_instance().unwrap().ldap.ldap_unbind)(ldap_handle) };

    Ok(())
}

///returns true if the property was enabled (added), false if it was disabled.
pub fn toggle_user_account_control(
    ldap_server: &str,
    dn: &str,
    user_dn: &str,
    uac_prop: u32,
    username: Option<&str>,
    password: Option<&str>,
    domain: Option<&str>,
) -> Result<bool, u32> {
    let mut enabled = true;
    let entries = query_ldap(
        ldap_server,
        dn,
        user_dn,
        "(distinguishedName=*)",
        0,
        Some(Vec::from(["userAccountControl"])),
        username,
        password,
        domain,
    )?;
    // Get userAccountControl from first entry's first attribute
    let uac_int: u32 = entries[0][0].str_val[0].parse().unwrap();
    let mut uac_str = String::new();
    //if the property is present we remove the flag with an xor
    if uac_int & uac_prop == uac_prop {
        uac_str = int_to_str(uac_int ^ uac_prop);
        enabled = false;
        //else include it with or
    } else {
        uac_str = int_to_str(uac_int | uac_prop);
    }
    set_ad_attr_str(
        ldap_server,
        user_dn,
        "userAccountControl",
        uac_str.clone().as_str(),
        username,
        password,
        domain,
    )?;

    Ok(enabled)
}
