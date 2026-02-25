use core::{ffi::c_void, ptr::null_mut};

use alloc::vec::Vec;

use crate::{get_instance, libs::ldrapi::ldr_function};

use super::ntdef::UnicodeString;

#[repr(C)]
#[allow(non_snake_case)]
pub struct LDAPMessage {
    pub lm_msgid: u32,
    pub lm_msgtype: u32,
    pub lm_ber: *mut c_void,
    pub lm_chain: *mut LDAPMessage,
    pub lm_next: *mut LDAPMessage,
    pub lm_time: u32,
    pub Connection: *mut LDAP,
    pub Request: *mut c_void,
    pub lm_returncode: u32,
    pub lm_referral: u16,
    pub lm_chased: u8,
    pub lm_eom: u8,
    pub ConnectionReferenced: u8,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct LDAP {
    pub ld_sb: LDAP_0,
    pub ld_host: *mut u8,
    pub ld_version: u32,
    pub ld_lberoptions: u8,
    pub ld_deref: u32,
    pub ld_timelimit: u32,
    pub ld_sizelimit: u32,
    pub ld_errno: u32,
    pub ld_matched: *mut u8,
    pub ld_error: *mut u8,
    pub ld_msgid: u32,
    pub Reserved3: [u8; 25],
    pub ld_cldaptries: u32,
    pub ld_cldaptimeout: u32,
    pub ld_refhoplimit: u32,
    pub ld_options: u32,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub struct LDAP_0 {
    pub sb_sd: usize,
    pub Reserved1: [u8; 41],
    pub sb_naddr: usize,
    pub Reserved2: [u8; 24],
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct LDAP_TIMEVAL {
    pub tv_sec: i32,
    pub tv_usec: i32,
}

#[repr(C)]
pub struct LDAPModW {
    pub mod_op: u32,
    pub mod_type: *mut u16,
    pub mod_vals: LDAPModW_0,
}

#[repr(C)]
pub union LDAPModW_0 {
    pub modv_strvals: *mut *mut u16,
    pub modv_bvals: *mut *mut LDAP_BERVAL,
}
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct LDAP_BERVAL {
    pub bv_len: u32,
    pub bv_val: *mut u8,
}
#[repr(C)]
pub struct BerElement {
    pub opaque: *mut u8,
}

#[repr(C)]
pub struct LDAPSortKeyW {
    pub sk_attrtype: *mut u16,
    pub sk_matchruleoid: *mut u16,
    pub sk_reverseorder: u8,
}

#[repr(C)]
pub struct LDAPControlW {
    pub ldctl_oid: *mut u16,
    pub ldctl_value: LDAP_BERVAL,
    pub ldctl_iscritical: u8,
}

#[allow(non_camel_case_types)]
pub type ldap_initW = unsafe extern "cdecl" fn(hostname: *const u16, portnumber: u32) -> *mut LDAP;

#[allow(non_camel_case_types)]
pub type ldap_sslinitW =
    unsafe extern "cdecl" fn(hostname: *const u16, portnumber: u32, secure: i32) -> *mut LDAP;

#[allow(non_camel_case_types)]
pub type ldap_bind_s =
    unsafe extern "cdecl" fn(ld: *mut LDAP, dn: *const u8, cred: *const u8, method: u32) -> u32;

#[allow(non_camel_case_types)]
pub type ldap_unbind = unsafe extern "cdecl" fn(ld: *mut LDAP) -> u32;

#[allow(non_camel_case_types)]
pub type ldap_modify_sW =
    unsafe extern "cdecl" fn(ld: *mut LDAP, dn: *const u16, mods: *mut *mut LDAPModW) -> u32;

#[allow(non_camel_case_types)]
pub type LdapGetLastError = unsafe extern "cdecl" fn() -> u32;

#[allow(non_camel_case_types)]
pub type ldap_connect = unsafe extern "cdecl" fn(ld: *mut LDAP, timeout: *mut LDAP_TIMEVAL) -> u32;

#[allow(non_camel_case_types)]
pub type ldap_search_sW = unsafe extern "cdecl" fn(
    ld: *mut LDAP,
    base: *const u16,
    scope: u32,
    filter: *const u16,
    attrs: *const *const u16,
    attrsonly: u32,
    res: *mut *mut LDAPMessage,
) -> u32;

#[allow(non_camel_case_types)]
pub type ldap_first_entry =
    unsafe extern "cdecl" fn(ld: *mut LDAP, res: *mut LDAPMessage) -> *mut LDAPMessage;

#[allow(non_camel_case_types)]
pub type ldap_next_entry =
    unsafe extern "cdecl" fn(ld: *mut LDAP, entry: *mut LDAPMessage) -> *mut LDAPMessage;

#[allow(non_camel_case_types)]
pub type ldap_first_attribute = unsafe extern "cdecl" fn(
    ld: *mut LDAP,
    entry: *mut LDAPMessage,
    ber: *mut *mut BerElement,
) -> *mut u8;

#[allow(non_camel_case_types)]
pub type ldap_next_attribute = unsafe extern "cdecl" fn(
    ld: *mut LDAP,
    entry: *mut LDAPMessage,
    ptr: *mut BerElement,
) -> *mut u8;

#[allow(non_camel_case_types)]
pub type ldap_get_values = unsafe extern "cdecl" fn(
    ld: *mut LDAP,
    entry: *mut LDAPMessage,
    attr: *const u8,
) -> *mut *mut u8;

#[allow(non_camel_case_types)]
pub type ldap_value_free = unsafe extern "cdecl" fn(vals: *mut *mut u8) -> u32;

#[allow(non_camel_case_types)]
pub type ldap_memfree = unsafe extern "cdecl" fn(block: *const u8);

#[allow(non_camel_case_types)]
pub type ldap_msgfree = unsafe extern "cdecl" fn(res: *mut LDAPMessage) -> u32;

#[allow(non_camel_case_types)]
pub type ldap_set_optionW =
    unsafe extern "cdecl" fn(ld: *mut LDAP, option: i32, invalue: *const c_void) -> u32;

#[allow(non_camel_case_types)]
pub type ldap_simple_bindW =
    unsafe extern "cdecl" fn(ld: *mut LDAP, dn: *const u16, passwd: *const u16) -> u32;

#[allow(non_camel_case_types)]
pub type ldap_search_init_pageW = unsafe extern "cdecl" fn(
    externalhandle: *mut LDAP,
    distinguishedname: *const u16,
    scopeofsearch: u32,
    searchfilter: *const u16,
    attributelist: *const *const u16,
    attributesonly: u32,
    servercontrols: *mut *mut LDAPControlW,
    clientcontrols: *mut *mut LDAPControlW,
    pagetimelimit: u32,
    totalsizelimit: u32,
    sortkeys: *mut *mut LDAPSortKeyW,
) -> isize;

#[allow(non_camel_case_types)]
pub type ldap_get_next_page_s = unsafe extern "cdecl" fn(
    externalhandle: *mut LDAP,
    searchhandle: isize,
    timeout: *mut LDAP_TIMEVAL,
    pagesize: u32,
    totalcount: *mut u32,
    results: *mut *mut LDAPMessage,
) -> u32;

#[allow(non_camel_case_types)]
pub type ldap_count_entries = unsafe extern "cdecl" fn(ld: *mut LDAP, res: *mut LDAPMessage) -> u32;

#[allow(non_camel_case_types)]
pub type ldap_get_values_len = unsafe extern "cdecl" fn(
    externalhandle: *mut LDAP,
    message: *mut LDAPMessage,
    attr: *const u8,
) -> *mut *mut LDAP_BERVAL;

#[allow(non_camel_case_types)]
pub type ldap_value_free_len = unsafe extern "cdecl" fn(vals: *mut *mut LDAP_BERVAL) -> u32;

#[allow(non_camel_case_types)]
pub type ldap_search_abandon_page =
    unsafe extern "cdecl" fn(externalhandle: *mut LDAP, searchblock: isize) -> u32;

pub struct Ldap32 {
    pub module_base: *mut u8,
    pub ldap_init_w: ldap_initW,
    pub ldap_sslinit_w: ldap_sslinitW,
    pub ldap_bind_s: ldap_bind_s,
    pub ldap_unbind: ldap_unbind,
    pub ldap_modify_s_w: ldap_modify_sW,
    pub ldap_get_last_error: LdapGetLastError,
    pub ldap_connect: ldap_connect,
    pub ldap_search_s_w: ldap_search_sW,
    pub ldap_first_entry: ldap_first_entry,
    pub ldap_next_entry: ldap_next_entry,
    pub ldap_first_attribute: ldap_first_attribute,
    pub ldap_get_values: ldap_get_values,
    pub ldap_value_free: ldap_value_free,
    pub ldap_memfree: ldap_memfree,
    pub ldap_msgfree: ldap_msgfree,
    pub ldap_set_option_w: ldap_set_optionW,
    pub ldap_simple_bind_w: ldap_simple_bindW,
    pub ldap_search_init_page_w: ldap_search_init_pageW,
    pub ldap_get_next_page_s: ldap_get_next_page_s,
    pub ldap_count_entries: ldap_count_entries,
    pub ldap_get_values_len: ldap_get_values_len,
    pub ldap_value_free_len: ldap_value_free_len,
    pub ldap_search_abandon_page: ldap_search_abandon_page,
    pub ldap_next_attribute: ldap_next_attribute,
}

impl Ldap32 {
    pub fn new() -> Self {
        Ldap32 {
            module_base: null_mut(),
            ldap_init_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_sslinit_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_bind_s: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_unbind: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_modify_s_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_get_last_error: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_connect: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_search_s_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_first_entry: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_next_entry: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_first_attribute: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_get_values: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_value_free: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_memfree: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_msgfree: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_set_option_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_simple_bind_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_search_init_page_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_get_next_page_s: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_count_entries: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_get_values_len: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_value_free_len: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_search_abandon_page: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            ldap_next_attribute: unsafe { core::mem::transmute(null_mut::<c_void>()) },
        }
    }
}

unsafe impl Sync for Ldap32 {}
unsafe impl Send for Ldap32 {}

pub fn init_ldap32_funcs() {
    unsafe {
        let mut ldap_dll_unicode = UnicodeString::new();
        let utf16_string: Vec<u16> = "Wldap32.dll".encode_utf16().chain(Some(0)).collect();
        ldap_dll_unicode.init(utf16_string.as_ptr());

        let mut h_ldap: *mut c_void = null_mut();

        let instance = get_instance().unwrap();
        unsafe {
            (instance.ntdll.ldr_load_dll)(
                null_mut(),
                null_mut(),
                ldap_dll_unicode,
                &mut h_ldap as *mut _ as *mut c_void,
            )
        };

        if h_ldap.is_null() {
            return;
        }

        instance.ldap.module_base = h_ldap as *mut u8;

        let nt_ldap_init_w_addr = ldr_function(instance.ldap.module_base, 0x47b81a90);
        instance.ldap.ldap_init_w = core::mem::transmute(nt_ldap_init_w_addr);

        let nt_ldap_sslinit_w_addr = ldr_function(instance.ldap.module_base, 0x9cf30fc2);
        instance.ldap.ldap_sslinit_w = core::mem::transmute(nt_ldap_sslinit_w_addr);

        let nt_ldap_bind_s_addr = ldr_function(instance.ldap.module_base, 0x2e0f50d4);
        instance.ldap.ldap_bind_s = core::mem::transmute(nt_ldap_bind_s_addr);

        let nt_ldap_unbind_addr = ldr_function(instance.ldap.module_base, 0xeff96bab);
        instance.ldap.ldap_unbind = core::mem::transmute(nt_ldap_unbind_addr);

        let nt_ldap_modify_s_w_addr = ldr_function(instance.ldap.module_base, 0x67095916);
        instance.ldap.ldap_modify_s_w = core::mem::transmute(nt_ldap_modify_s_w_addr);

        let nt_ldap_get_last_error_addr = ldr_function(instance.ldap.module_base, 0xbe4b7884);
        instance.ldap.ldap_get_last_error = core::mem::transmute(nt_ldap_get_last_error_addr);

        let nt_ldap_connect_addr = ldr_function(instance.ldap.module_base, 0x4af7a74f);
        instance.ldap.ldap_connect = core::mem::transmute(nt_ldap_connect_addr);

        let nt_ldap_search_s_w_addr = ldr_function(instance.ldap.module_base, 0x25ec832);
        instance.ldap.ldap_search_s_w = core::mem::transmute(nt_ldap_search_s_w_addr);

        let nt_ldap_first_entry_addr = ldr_function(instance.ldap.module_base, 0x6c31235e);
        instance.ldap.ldap_first_entry = core::mem::transmute(nt_ldap_first_entry_addr);

        let nt_ldap_next_entry_addr = ldr_function(instance.ldap.module_base, 0xbc259ff5);
        instance.ldap.ldap_next_entry = core::mem::transmute(nt_ldap_next_entry_addr);

        let nt_ldap_first_attribute_addr = ldr_function(instance.ldap.module_base, 0x534cf940);
        instance.ldap.ldap_first_attribute = core::mem::transmute(nt_ldap_first_attribute_addr);

        let nt_ldap_get_values_addr = ldr_function(instance.ldap.module_base, 0x284d0af4);
        instance.ldap.ldap_get_values = core::mem::transmute(nt_ldap_get_values_addr);

        let nt_ldap_value_free_addr = ldr_function(instance.ldap.module_base, 0x99896a3);
        instance.ldap.ldap_value_free = core::mem::transmute(nt_ldap_value_free_addr);

        let nt_ldap_memfree_addr = ldr_function(instance.ldap.module_base, 0x35542c86);
        instance.ldap.ldap_memfree = core::mem::transmute(nt_ldap_memfree_addr);

        let nt_ldap_msgfree_addr = ldr_function(instance.ldap.module_base, 0x558fd24e);
        instance.ldap.ldap_msgfree = core::mem::transmute(nt_ldap_msgfree_addr);

        let nt_ldap_set_option_w_addr = ldr_function(instance.ldap.module_base, 0x7af6fa60);
        instance.ldap.ldap_set_option_w = core::mem::transmute(nt_ldap_set_option_w_addr);

        let nt_ldap_simple_bind_w_addr = ldr_function(instance.ldap.module_base, 0x5553082);
        instance.ldap.ldap_simple_bind_w = core::mem::transmute(nt_ldap_simple_bind_w_addr);

        let nt_ldap_search_init_page_w_addr = ldr_function(instance.ldap.module_base, 0xddafe4e1);
        instance.ldap.ldap_search_init_page_w =
            core::mem::transmute(nt_ldap_search_init_page_w_addr);

        let nt_ldap_get_next_page_s_addr = ldr_function(instance.ldap.module_base, 0x2b312091);
        instance.ldap.ldap_get_next_page_s = core::mem::transmute(nt_ldap_get_next_page_s_addr);

        let nt_ldap_count_entries_addr = ldr_function(instance.ldap.module_base, 0xf07f95e7);
        instance.ldap.ldap_count_entries = core::mem::transmute(nt_ldap_count_entries_addr);

        let nt_ldap_get_values_len_addr = ldr_function(instance.ldap.module_base, 0x4d36c972);
        instance.ldap.ldap_get_values_len = core::mem::transmute(nt_ldap_get_values_len_addr);

        let nt_ldap_value_free_len_addr = ldr_function(instance.ldap.module_base, 0xbbae94a1);
        instance.ldap.ldap_value_free_len = core::mem::transmute(nt_ldap_value_free_len_addr);

        let nt_ldap_search_abandon_page_addr = ldr_function(instance.ldap.module_base, 0x4e2967c9);
        instance.ldap.ldap_search_abandon_page =
            core::mem::transmute(nt_ldap_search_abandon_page_addr);

        let nt_ldap_next_attribute_addr = ldr_function(instance.ldap.module_base, 0x4bcbe957);
        instance.ldap.ldap_next_attribute = core::mem::transmute(nt_ldap_next_attribute_addr);
    }
}