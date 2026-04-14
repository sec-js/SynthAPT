use core::{ffi::c_void, mem::{transmute, zeroed}, ptr::null_mut};

use alloc::vec::Vec;

use crate::get_instance;

pub const IID_NULL: GUID = GUID {
    data1: 0,
    data2: 0,
    data3: 0,
    data4: [0, 0, 0, 0, 0, 0, 0, 0],
};

pub const IID_IDispatch: GUID = GUID {
    data1: 0x00020400,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

#[repr(C)]
pub struct IUnknownVtbl {
    pub QueryInterface: unsafe extern "system" fn(
        This: *mut c_void,
        riid: *const GUID,
        ppvObject: *mut *mut c_void,
    ) -> i32,
    pub AddRef: unsafe extern "system" fn(This: *mut c_void) -> u32,
    pub Release: unsafe extern "system" fn(This: *mut c_void) -> u32,
}

#[repr(C)]
pub struct IUnknown {
    pub lpVtbl: *const IUnknownVtbl,
}

#[repr(C)]
pub struct VARIANT {
    pub vt: u16,        // The variant type (VARTYPE)
    pub reserved1: u16, // Reserved
    pub reserved2: u16, // Reserved
    pub reserved3: u16, // Reserved
    pub data: VARIANT_Data,
}

#[repr(C)]
pub union VARIANT_Data {
    pub iVal: i32,             // VT_I4
    pub uiVal: u32,            // VT_UI4
    pub fltVal: f32,           // VT_R4
    pub dblVal: f64,           // VT_R8
    pub bstrVal: *mut u16,     // VT_BSTR (wide string)
    pub boolVal: i16,          // VT_BOOL
    pub date: f64,             // VT_DATE
    pub punkVal: *mut c_void,  // VT_UNKNOWN (IUnknown pointer)
    pub pdispVal: *mut c_void, // VT_DISPATCH (IDispatch pointer)
    pub cyVal: CY,             // VT_CY (currency)
    pub bVal: i8,              // VT_UI1
    pub scode: i32,            // VT_ERROR (SCODE/HRESULT)
    pub _pad: [u8; 16],        // Ensure union is 16 bytes (for BRECORD with 2 ptrs)
}

#[repr(C)]
pub struct CY {
    low: i32,
    high: i32,
}
impl Copy for CY {}
impl Clone for CY {
    fn clone(&self) -> Self {
        *self
    }
}

impl VARIANT {
    pub fn new() -> Self {
        VARIANT {
            vt: 0, // VT_EMPTY (by default)
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            data: unsafe { zeroed() },
        }
    }

    pub fn from_i32(value: i32) -> Self {
        let mut variant = VARIANT::new();
        variant.vt = 3; // VT_I4
        unsafe {
            variant.data.iVal = value;
        }
        variant
    }

    pub fn from_u32(value: u32) -> Self {
        let mut variant = VARIANT::new();
        variant.vt = 19; // VT_UI4
        unsafe {
            variant.data.uiVal = value;
        }
        variant
    }

    pub fn from_f32(value: f32) -> Self {
        let mut variant = VARIANT::new();
        variant.vt = 4; // VT_R4
        unsafe {
            variant.data.fltVal = value;
        }
        variant
    }

    pub fn from_f64(value: f64) -> Self {
        let mut variant = VARIANT::new();
        variant.vt = 5; // VT_R8
        unsafe {
            variant.data.dblVal = value;
        }
        variant
    }

    pub fn from_bstr(value: &str) -> Self {
        let oleaut =
            unsafe { (get_instance().unwrap().k32.load_library_a)("OLEAUT32.DLL\0".as_ptr()) };

        type SysAllocStringFn = unsafe extern "system" fn(*const u16) -> *mut u16;
        let sys_alloc_string = unsafe {
            let address =
                (get_instance().unwrap().k32.get_proc_address)(oleaut, "SysAllocString\0".as_ptr()).unwrap();
            transmute::<_, SysAllocStringFn>(address)
        };
        let mut variant = VARIANT::new();
        variant.vt = 8; // VT_BSTR
        let wide_str: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();
        let bstr = unsafe{sys_alloc_string(wide_str.as_ptr())};
        unsafe {
            variant.data.bstrVal = bstr;
        }
        variant
    }

    pub fn from_bool(value: bool) -> Self {
        let mut variant = VARIANT::new();
        variant.vt = 11; // VT_BOOL
        unsafe {
            variant.data.boolVal = if value { 1 } else { 0 };
        }
        variant
    }

    pub fn from_error(scode: i32) -> Self {
        let mut variant = VARIANT::new();
        variant.vt = 10; // VT_ERROR
        unsafe {
            variant.data.scode = scode;
        }
        variant
    }
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct IDispatchVtbl {
    pub QueryInterface: unsafe extern "system" fn(
        This: *mut c_void,
        riid: *const GUID,
        ppvObject: *mut *mut c_void,
    ) -> i32,
    pub AddRef: unsafe extern "system" fn(This: *mut c_void) -> u32,
    pub Release: unsafe extern "system" fn(This: *mut c_void) -> u32,
    pub GetTypeInfoCount: unsafe extern "system" fn(This: *mut c_void, pctinfo: *mut u32) -> i32,
    pub GetTypeInfo: unsafe extern "system" fn(
        This: *mut c_void,
        itinfo: u32,
        lcid: u32,
        pptinfo: *mut *mut c_void,
    ) -> i32,
    pub GetIDsOfNames: unsafe extern "system" fn(
        This: *mut c_void,
        riid: *const GUID,
        rgszNames: *const *const u16,
        cNames: u32,
        lcid: u32,
        rgdispid: *mut i32,
    ) -> i32,
    pub Invoke: unsafe extern "system" fn(
        This: *mut c_void,
        dispidMember: i32,
        riid: *const GUID,
        lcid: u32,
        wFlags: u16,
        pDispParams: *mut c_void,
        pVarResult: *mut c_void,
        pExcepInfo: *mut c_void,
        puArgErr: *mut u32,
    ) -> i32,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct IDispatch {
    pub lpVtbl: *const IDispatchVtbl,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct DISPPARAMS {
    pub rgvarg: *mut VARIANT,
    pub rgdispidNamedArgs: *mut i32,
    pub cArgs: u32,
    pub cNamedArgs: u32,
}

#[repr(C)]
pub struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[repr(C)]
pub struct COAUTHIDENTITY {
    pub user: *mut u16,
    pub user_length: u32,
    pub domain: *mut u16,
    pub domain_length: u32,
    pub password: *mut u16,
    pub password_length: u32,
    pub flags: u32,
}

#[repr(C)]
pub struct COAUTHINFO {
    pub dw_authn_svc: u32,
    pub dw_authz_svc: u32,
    pub pwsz_server_princ_name: *mut u16,
    pub dw_authn_level: u32,
    pub dw_impersonation_level: u32,
    pub p_auth_identity_data: *mut COAUTHIDENTITY,
    pub dw_capabilities: u32,
}

#[repr(C)]
pub struct COSERVERINFO {
    pub dw_reserved1: u32,
    pub pwsz_name: *mut u16,
    pub p_auth_info: *mut COAUTHINFO,
    pub dw_reserved2: u32,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct MULTI_QI {
    pub p_iid: *const GUID,
    pub p_itf: *mut c_void,
    pub hr: i32,
}

pub type CoInitialize = unsafe extern "system" fn(pvreserved: *const c_void) -> i32;
pub type CoInitializeEx =
    unsafe extern "system" fn(pvreserved: *const c_void, dwcoinit: u32) -> i32;

pub type CLSIDFromString = unsafe extern "system" fn(lpsz: *const u16, pclsid: *mut GUID) -> i32;

pub type CoCreateInstance = unsafe extern "system" fn(
    rclsid: *const GUID,
    punkouter: *mut c_void,
    dwclscontext: u32,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> i32;

pub type CoCreateInstanceEx = unsafe extern "system" fn(
    clsid: *const GUID,
    punkouter: *mut c_void,
    dwclsctx: u32,
    pserverinfo: *const COSERVERINFO,
    dwcount: u32,
    presults: *mut MULTI_QI,
) -> i32;

pub type CoUninitialize = unsafe extern "system" fn();

pub type CoSetProxyBlanket = unsafe extern "system" fn(
    pproxy: *mut c_void,
    dwauthnsvc: u32,
    dwauthzsvc: u32,
    pserverprincname: *const u16,
    dwauthnlevel: u32,
    dwimplevel: u32,
    pauthinfo: *const c_void,
    dwcapabilities: u32,
) -> i32;

pub type CoInitializeSecurity = unsafe extern "system" fn(
    psec_desc: *const c_void,
    cauthn_svc: i32,
    asauthn_svc: *const c_void,
    preserved1: *const c_void,
    dw_authn_level: u32,
    dw_imp_level: u32,
    preserved2: *const c_void,
    dw_capabilities: u32,
    preserved3: *const c_void,
) -> i32;

pub type SysAllocStringLen = unsafe extern "system" fn(
    strin: *const u16,
    ui: u32,
) -> *mut u16;

pub type SysAllocString = unsafe extern "system" fn(psz: *const u16) -> *mut u16;

pub type SysFreeString = unsafe extern "system" fn(bstrstring: *mut u16);

pub struct Ole32 {
    pub module_base: *mut u8,
    pub co_initialize_ex: CoInitializeEx,
    pub co_initialize: CoInitialize,
    pub clsid_from_string: CLSIDFromString,
    pub co_create_instance: CoCreateInstance,
    pub co_create_instance_ex: CoCreateInstanceEx,
    pub co_uninitialize: CoUninitialize,
    pub co_set_proxy_blanket: CoSetProxyBlanket,
    pub co_initialize_security: CoInitializeSecurity,
    pub sys_alloc_string_len: SysAllocStringLen,
    pub sys_alloc_string: SysAllocString,
    pub sys_free_string: SysFreeString,
}

impl Ole32 {
    pub fn new() -> Self {
        Ole32 {
            module_base: null_mut(),
            co_initialize_ex: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            co_initialize: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            clsid_from_string: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            co_create_instance: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            co_create_instance_ex: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            co_uninitialize: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            co_set_proxy_blanket: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            co_initialize_security: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            sys_alloc_string_len: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            sys_alloc_string: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            sys_free_string: unsafe { core::mem::transmute(null_mut::<c_void>()) },
        }
    }
}

unsafe impl Sync for Ole32 {}
unsafe impl Send for Ole32 {}

pub fn init_ole32_funcs() {
    unsafe {
        let instance = get_instance().unwrap();
        let h_ole = (instance.k32.load_library_a)(b"ole32.dll\0".as_ptr());
        instance.ole.module_base = h_ole as *mut u8;

        let h_oleaut = (instance.k32.load_library_a)(b"OLEAUT32.dll\0".as_ptr());

        let nt_co_initialize_ex_addr = (get_instance().unwrap().k32.get_proc_address)(
            instance.ole.module_base as *mut c_void,
            "CoInitializeEx\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.ole.co_initialize_ex = core::mem::transmute(nt_co_initialize_ex_addr);

        let nt_clsid_from_string_addr = (get_instance().unwrap().k32.get_proc_address)(
            instance.ole.module_base as *mut c_void,
            "CLSIDFromString\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.ole.clsid_from_string = core::mem::transmute(nt_clsid_from_string_addr);

        let nt_co_create_instance_addr = (get_instance().unwrap().k32.get_proc_address)(
            instance.ole.module_base as *mut c_void,
            "CoCreateInstance\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.ole.co_create_instance = core::mem::transmute(nt_co_create_instance_addr);

        let nt_co_create_instance_ex_addr = (get_instance().unwrap().k32.get_proc_address)(
            instance.ole.module_base as *mut c_void,
            "CoCreateInstanceEx\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.ole.co_create_instance_ex = core::mem::transmute(nt_co_create_instance_ex_addr);

        let nt_co_uninitialize_addr = (get_instance().unwrap().k32.get_proc_address)(
            instance.ole.module_base as *mut c_void,
            "CoUninitialize\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.ole.co_uninitialize = core::mem::transmute(nt_co_uninitialize_addr);

        let nt_co_set_proxy_blanket_addr = (get_instance().unwrap().k32.get_proc_address)(
            instance.ole.module_base as *mut c_void,
            "CoSetProxyBlanket\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.ole.co_set_proxy_blanket = core::mem::transmute(nt_co_set_proxy_blanket_addr);

        let nt_co_initialize_security_addr = (get_instance().unwrap().k32.get_proc_address)(
            instance.ole.module_base as *mut c_void,
            "CoInitializeSecurity\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.ole.co_initialize_security = core::mem::transmute(nt_co_initialize_security_addr);

        let nt_co_initialize_addr = (get_instance().unwrap().k32.get_proc_address)(
            instance.ole.module_base as *mut c_void,
            "CoInitialize\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.ole.co_initialize = core::mem::transmute(nt_co_initialize_addr);

        let sys_alloc_string_len_addr= (get_instance().unwrap().k32.get_proc_address)(
            h_oleaut as *mut c_void,
            "SysAllocStringLen\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.ole.sys_alloc_string_len = core::mem::transmute(sys_alloc_string_len_addr);

        let sys_alloc_string_addr= (get_instance().unwrap().k32.get_proc_address)(
            h_oleaut as *mut c_void,
            "SysAllocString\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.ole.sys_alloc_string = core::mem::transmute(sys_alloc_string_addr);

        let sys_free_string_addr= (get_instance().unwrap().k32.get_proc_address)(
            h_oleaut as *mut c_void,
            "SysFreeString\0".as_bytes().as_ptr(),
        )
        .unwrap();
        instance.ole.sys_free_string = core::mem::transmute(sys_free_string_addr);

    }
}
