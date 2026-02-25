use core::{
    mem::zeroed,
    ptr::{null, null_mut},
};

use alloc::vec::Vec;

use crate::{
    get_instance,
    libs::ole::{
        COAUTHIDENTITY, COAUTHINFO, COSERVERINFO, GUID,
        MULTI_QI
    },
};

pub struct Creds {
    domain: Vec<u16>,
    username: Vec<u16>,
    password: Vec<u16>,
}

impl Creds {
    pub fn new(domain: &str, username: &str, password: &str) -> Self {
        Creds {
            domain: domain.encode_utf16().chain(Some(0)).collect(),
            username: username.encode_utf16().chain(Some(0)).collect(),
            password: password.encode_utf16().chain(Some(0)).collect(),
        }
    }
}

/// Instantiate a COM object, optionally on a remote target with credentials.
/// When creds is None, uses current user's default credentials.
pub fn instantiate_com_object(
    clsid: &str,
    target: Option<&str>,
    creds: Option<&mut Creds>,
) -> Result<MULTI_QI, u32> {
    let clsid_w: Vec<u16> = clsid.encode_utf16().chain(Some(0)).collect();
    let mut ifid: GUID = unsafe { zeroed() };
    let mut target_w: Vec<u16> = target.unwrap_or("").encode_utf16().chain(Some(0)).collect();

    let hr = unsafe {
        (get_instance().unwrap().ole.clsid_from_string)(clsid_w.as_ptr(), &mut ifid as *mut GUID)
    };
    if hr != 0 {
        return Err(hr as u32);
    }

    let hr = unsafe { (get_instance().unwrap().ole.co_initialize)(null()) };
    if hr != 0 {
        return Err(hr as u32);
    }

    let clsid_w: Vec<u16> = clsid.encode_utf16().chain(Some(0)).collect();

    let mut auth_identity: COAUTHIDENTITY = unsafe { zeroed() };
    let has_creds = creds.is_some();
    if let Some(creds) = creds {
        auth_identity.domain = creds.domain.as_mut_ptr();
        auth_identity.domain_length = creds.domain.len() as u32;
        auth_identity.user = creds.username.as_mut_ptr();
        auth_identity.user_length = creds.username.len() as u32;
        auth_identity.password = creds.password.as_mut_ptr();
        auth_identity.password_length = creds.password.len() as u32;
        auth_identity.flags = 2;
    }

    let mut auth_info = COAUTHINFO {
        dw_authn_svc: 10, // RPC_C_AUTHN_NEGOTIATE;
        dw_authz_svc: 0,  //RPC_C_AUTHZ_NONE;
        pwsz_server_princ_name: null_mut(),
        dw_authn_level: 0,         //RPC_C_AUTHN_LEVEL_DEFAULT;
        dw_impersonation_level: 3, //RPC_C_IMP_LEVEL_IMPERSONATE;
        p_auth_identity_data: if has_creds { &mut auth_identity } else { null_mut() },
        dw_capabilities: 0, //EOAC_NONE;
    };

    let mut server_info: COSERVERINFO = unsafe { zeroed() };

    let mut clsctx = 4;
    if let Some(target) = target {
        server_info.pwsz_name = target_w.as_mut_ptr();
        clsctx = 16; //CLSCTX_REMOTE_SERVER
        server_info.p_auth_info = &auth_info as *const _ as *mut _;
    }

    let iunknown = GUID {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
    };

    let mut mqi: MULTI_QI = unsafe { zeroed() };
    mqi.p_iid = &iunknown as *const _ as *mut _;

    let hr = unsafe {
        (get_instance().unwrap().ole.co_create_instance_ex)(
            &ifid,
            null_mut(),
            clsctx,
            &server_info,
            1,
            &mut mqi as *mut _,
        )
    };
    if hr != 0 {
        unsafe { (get_instance().unwrap().ole.co_uninitialize)() };
        return Err(hr as u32);
    }

    Ok(mqi)
}
