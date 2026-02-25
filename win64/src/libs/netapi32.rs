use core::{ffi::c_void, ptr::null_mut};

use alloc::vec::Vec;

use super::ntdef::UnicodeString;
use crate::get_instance;

#[repr(C)]
pub struct USER_INFO_1003 {
    pub usri1003_password: *mut u16,
}
#[repr(C)]
pub struct LOCALGROUP_MEMBERS_INFO_3 {
    pub lgrmi3_domainandname: *mut u16,
}

pub type NetUserSetInfo = unsafe extern "system" fn(
    servername: *const u16,
    username: *const u16,
    level: u32,
    buf: *const u8,
    parm_err: *mut u32,
) -> u32;

pub type NetLocalGroupAddMembers = unsafe extern "system" fn(
    servername: *const u16,
    groupname: *const u16,
    level: u32,
    buf: *const u8,
    totalentries: u32,
) -> u32;

pub type NetLocalGroupDelMembers = unsafe extern "system" fn(
    servername: *const u16,
    groupname: *const u16,
    level: u32,
    buf: *const u8,
    totalentries: u32,
) -> u32;

pub type NetGroupAddUser = unsafe extern "system" fn(
    servername: *mut u16,
    groupname: *mut u16,
    username: *mut u16,
) -> u32;

pub type NetGroupDelUser = unsafe extern "system" fn(
    servername: *mut u16,
    groupname: *mut u16,
    username: *mut u16,
) -> u32;

pub struct Netapi32 {
    pub module_base: *mut u8,
    pub net_user_set_info: NetUserSetInfo,
    pub net_localgroup_add_members: NetLocalGroupAddMembers,
    pub net_localgroup_del_members: NetLocalGroupDelMembers,
    pub net_group_add_user: NetGroupAddUser,
    pub net_group_del_user: NetGroupDelUser,
}

impl Netapi32 {
    pub fn new() -> Self {
        Netapi32 {
            module_base: null_mut(),
            net_user_set_info: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            net_localgroup_add_members: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            net_localgroup_del_members: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            net_group_add_user: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            net_group_del_user: unsafe { core::mem::transmute(null_mut::<c_void>()) },
        }
    }
}

unsafe impl Sync for Netapi32 {}
unsafe impl Send for Netapi32 {}

pub fn init_netapi32_funcs() {
    unsafe {
        let mut netapi_dll_unicode = UnicodeString::new();
        let utf16_string: Vec<u16> = "Netapi32.dll".encode_utf16().chain(Some(0)).collect();
        netapi_dll_unicode.init(utf16_string.as_ptr());

        let mut h_netapi: *mut c_void = null_mut();

        let instance = get_instance().unwrap();
        unsafe {
            (instance.ntdll.ldr_load_dll)(
                null_mut(),
                null_mut(),
                netapi_dll_unicode,
                &mut h_netapi as *mut _ as *mut c_void,
            )
        };

        if h_netapi.is_null() {
            return;
        }

        instance.netapi.module_base = h_netapi as *mut u8;

        let nt_net_user_set_info_addr = (get_instance().unwrap().k32.get_proc_address)(
            instance.netapi.module_base as *mut c_void,
            "NetUserSetInfo\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.netapi.net_user_set_info = core::mem::transmute(nt_net_user_set_info_addr);

        let nt_net_localgroup_add_members_addr = (get_instance().unwrap().k32.get_proc_address)(
            instance.netapi.module_base as *mut c_void,
            "NetLocalGroupAddMembers\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.netapi.net_localgroup_add_members =
            core::mem::transmute(nt_net_localgroup_add_members_addr);

        let nt_net_localgroup_del_members_addr = (get_instance().unwrap().k32.get_proc_address)(
            instance.netapi.module_base as *mut c_void,
            "NetLocalGroupDelMembers\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.netapi.net_localgroup_del_members =
            core::mem::transmute(nt_net_localgroup_del_members_addr);

        let nt_net_group_add_user_addr = (get_instance().unwrap().k32.get_proc_address)(
            instance.netapi.module_base as *mut c_void,
            "NetGroupAddUser\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.netapi.net_group_add_user =
            core::mem::transmute(nt_net_group_add_user_addr);


        let nt_net_group_del_user_addr = (get_instance().unwrap().k32.get_proc_address)(
            instance.netapi.module_base as *mut c_void,
            "NetGroupDelUser\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.netapi.net_group_del_user =
            core::mem::transmute(nt_net_group_del_user_addr);
    }
}
