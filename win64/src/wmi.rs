use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr::null_mut;
extern crate alloc;

use crate::get_instance;
use crate::libs::ole::{VARIANT_Data, GUID, VARIANT, COAUTHIDENTITY, COAUTHINFO, COSERVERINFO, MULTI_QI};

// Additional GUIDs we need
pub const IID_IWBEMCLASSOBJECT: GUID = GUID {
    data1: 0xdc12a681,
    data2: 0x737f,
    data3: 0x11cf,
    data4: [0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24],
};

#[repr(C)]
pub struct IWbemClassObject {
    pub vtable: *const IWbemClassObjectVtbl,
}

// VT_BSTR constant
const VT_BSTR: u16 = 8;

#[repr(C)]
pub struct IWbemClassObjectVtbl {
    // IUnknown methods
    pub query_interface:
        unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32,
    pub add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    pub release: unsafe extern "system" fn(*mut c_void) -> u32,
    // IWbemClassObject methods (simplified - only what we need)
    pub get_qualifier_set: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32,
    pub get: unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        i32,
        *mut VARIANT,
        *mut i32,
        *mut i32,
    ) -> i32,
    pub put: unsafe extern "system" fn(*mut c_void, *const u16, i32, *const VARIANT, i32) -> i32,
    pub delete: unsafe extern "system" fn(*mut c_void, *const u16) -> i32,
    pub get_names: unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        i32,
        *const VARIANT,
        *mut *mut c_void,
    ) -> i32,
    pub begin_enumeration: unsafe extern "system" fn(*mut c_void, i32) -> i32,
    pub next: unsafe extern "system" fn(
        *mut c_void,
        i32,
        *mut *mut u16,
        *mut VARIANT,
        *mut i32,
        *mut i32,
    ) -> i32,
    pub end_enumeration: unsafe extern "system" fn(*mut c_void) -> i32,
    pub get_property_qualifier_set:
        unsafe extern "system" fn(*mut c_void, *const u16, *mut *mut c_void) -> i32,
    pub clone: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32,
    pub get_object_text: unsafe extern "system" fn(*mut c_void, i32, *mut *mut u16) -> i32,
    pub spawn_derived_class: unsafe extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> i32,
    pub spawn_instance: unsafe extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> i32,
    pub compare_to: unsafe extern "system" fn(*mut c_void, i32, *mut c_void) -> i32,
    pub get_property_origin:
        unsafe extern "system" fn(*mut c_void, *const u16, *mut *mut u16) -> i32,
    pub inherits_from: unsafe extern "system" fn(*mut c_void, *const u16) -> i32,
    pub get_method: unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        i32,
        *mut *mut c_void,
        *mut *mut c_void,
    ) -> i32,
    pub put_method:
        unsafe extern "system" fn(*mut c_void, *const u16, i32, *mut c_void, *mut c_void) -> i32,
    pub delete_method: unsafe extern "system" fn(*mut c_void, *const u16) -> i32,
    pub begin_method_enumeration: unsafe extern "system" fn(*mut c_void, i32) -> i32,
    pub next_method: unsafe extern "system" fn(
        *mut c_void,
        i32,
        *mut *mut u16,
        *mut *mut c_void,
        *mut *mut c_void,
    ) -> i32,
    pub end_method_enumeration: unsafe extern "system" fn(*mut c_void) -> i32,
    pub get_method_qualifier_set:
        unsafe extern "system" fn(*mut c_void, *const u16, *mut *mut c_void) -> i32,
    pub get_method_origin: unsafe extern "system" fn(*mut c_void, *const u16, *mut *mut u16) -> i32,
}

// GUID definitions from previous code...
pub const IID_IWBEMSERVICES: GUID = GUID {
    data1: 0x9556dc99,
    data2: 0x828c,
    data3: 0x11cf,
    data4: [0xa3, 0x7e, 0x08, 0x00, 0x2b, 0x3a, 0x64, 0x02],
};

pub const CLSID_WBEMLOCATOR: GUID = GUID {
    data1: 0x4590f811,
    data2: 0x1d3a,
    data3: 0x11d0,
    data4: [0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24],
};

pub const IID_IWBEMLOCATOR: GUID = GUID {
    data1: 0xdc12a687,
    data2: 0x737f,
    data3: 0x11cf,
    data4: [0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24],
};

// Previous struct definitions...
#[repr(C)]
pub struct IWbemLocator {
    pub vtable: *const IWbemLocatorVtbl,
}

#[repr(C)]
pub struct IWbemLocatorVtbl {
    pub query_interface:
        unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32,
    pub add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    pub release: unsafe extern "system" fn(*mut c_void) -> u32,
    pub connect_server: unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        *const u16,
        *const u16,
        *const u16,
        i32,
        *const u16,
        *mut c_void,
        *mut *mut c_void,
    ) -> i32,
}

#[repr(C)]
pub struct IWbemServices {
    pub vtable: *const IWbemServicesVtbl,
}

#[repr(C)]
pub struct IWbemServicesVtbl {
    pub query_interface:
        unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32,
    pub add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    pub release: unsafe extern "system" fn(*mut c_void) -> u32,
    // Skip intermediate methods for brevity...
    pub open_namespace: unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        i32,
        *mut c_void,
        *mut *mut c_void,
        *mut *mut c_void,
    ) -> i32,
    pub cancel_async_call: unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32,
    pub query_object_sink: unsafe extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> i32,
    pub get_object: unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        i32,
        *mut c_void,
        *mut *mut c_void,
        *mut *mut c_void,
    ) -> i32,
    pub get_object_async:
        unsafe extern "system" fn(*mut c_void, *const u16, i32, *mut c_void, *mut c_void) -> i32,
    pub put_class: unsafe extern "system" fn(
        *mut c_void,
        *mut c_void,
        i32,
        *mut c_void,
        *mut *mut c_void,
    ) -> i32,
    pub put_class_async:
        unsafe extern "system" fn(*mut c_void, *mut c_void, i32, *mut c_void, *mut c_void) -> i32,
    pub delete_class: unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        i32,
        *mut c_void,
        *mut *mut c_void,
    ) -> i32,
    pub delete_class_async:
        unsafe extern "system" fn(*mut c_void, *const u16, i32, *mut c_void, *mut c_void) -> i32,
    pub create_class_enum: unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        i32,
        *mut c_void,
        *mut *mut c_void,
    ) -> i32,
    pub create_class_enum_async:
        unsafe extern "system" fn(*mut c_void, *const u16, i32, *mut c_void, *mut c_void) -> i32,
    pub put_instance: unsafe extern "system" fn(
        *mut c_void,
        *mut c_void,
        i32,
        *mut c_void,
        *mut *mut c_void,
    ) -> i32,
    pub put_instance_async:
        unsafe extern "system" fn(*mut c_void, *mut c_void, i32, *mut c_void, *mut c_void) -> i32,
    pub delete_instance: unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        i32,
        *mut c_void,
        *mut *mut c_void,
    ) -> i32,
    pub delete_instance_async:
        unsafe extern "system" fn(*mut c_void, *const u16, i32, *mut c_void, *mut c_void) -> i32,
    pub create_instance_enum: unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        i32,
        *mut c_void,
        *mut *mut c_void,
    ) -> i32,
    pub create_instance_enum_async:
        unsafe extern "system" fn(*mut c_void, *const u16, i32, *mut c_void, *mut c_void) -> i32,
    pub exec_query: unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        *const u16,
        i32,
        *mut c_void,
        *mut *mut c_void,
    ) -> i32,
    pub exec_query_async: unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        *const u16,
        i32,
        *mut c_void,
        *mut c_void,
    ) -> i32,
    pub exec_notification_query: unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        *const u16,
        i32,
        *mut c_void,
        *mut *mut c_void,
    ) -> i32,
    pub exec_notification_query_async: unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        *const u16,
        i32,
        *mut c_void,
        *mut c_void,
    ) -> i32,
    pub exec_method: unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        *const u16,
        i32,
        *mut c_void,
        *mut c_void,
        *mut *mut c_void,
        *mut *mut c_void,
    ) -> i32,
}

fn to_wide_string(s: &str) -> Vec<u16> {
    let mut wide: Vec<u16> = s.encode_utf16().collect();
    wide.push(0);
    wide
}

// Create a BSTR from a Rust string
unsafe fn create_bstr(s: &str) -> *mut u16 {
    let wide = to_wide_string(s);
    // Allocate BSTR (length prefix + string + null terminator)
    let len = (wide.len() - 1) * 2; // Length in bytes, excluding null terminator
    let bstr = (get_instance().unwrap().ole.sys_alloc_string_len)(wide.as_ptr(), len as u32 / 2);
    bstr
}

pub unsafe fn wmi_create_process(command_line: &str) -> Result<u32, u32> {
    // Initialize COM
    let hr = (get_instance().unwrap().ole.co_initialize)(null_mut());
    if hr < 0 {
        return Err(hr as u32);
    }

    // Create WbemLocator
    let mut locator: *mut c_void = null_mut();
    let hr = (get_instance().unwrap().ole.co_create_instance)(
        &CLSID_WBEMLOCATOR,
        null_mut(),
        1, // CLSCTX_INPROC_SERVER
        &IID_IWBEMLOCATOR,
        &mut locator,
    );

    if hr < 0 {
        (get_instance().unwrap().ole.co_uninitialize)();
        return Err(hr as u32);
    }

    let locator = locator as *mut IWbemLocator;

    // Connect to WMI namespace
    let namespace = to_wide_string("ROOT\\CIMV2");
    let mut services: *mut c_void = null_mut();

    let hr = ((*locator).vtable.as_ref().unwrap().connect_server)(
        locator as *mut c_void,
        namespace.as_ptr(),
        null_mut(),
        null_mut(),
        null_mut(),
        0,
        null_mut(),
        null_mut(),
        &mut services,
    );

    if hr < 0 {
        ((*locator).vtable.as_ref().unwrap().release)(locator as *mut c_void);
        (get_instance().unwrap().ole.co_uninitialize)();
        return Err(hr as u32);
    }

    let services = services as *mut IWbemServices;

    // Set proxy blanket for security
    let hr = (get_instance().unwrap().ole.co_set_proxy_blanket)(
        services as *mut c_void,
        10, // RPC_C_AUTHN_WINNT
        0,  // RPC_C_AUTHZ_NONE
        null_mut(),
        3,  // RPC_C_AUTHN_LEVEL_CALL
        3,  // RPC_C_IMP_LEVEL_IMPERSONATE
        null_mut(),
        0,  // EOAC_NONE
    );

    if hr < 0 {
        ((*services).vtable.as_ref().unwrap().release)(services as *mut c_void);
        ((*locator).vtable.as_ref().unwrap().release)(locator as *mut c_void);
        (get_instance().unwrap().ole.co_uninitialize)();
        return Err(hr as u32);
    }

    // Get the Win32_Process class to create input parameters
    let class_name = to_wide_string("Win32_Process");
    let mut class_object: *mut c_void = null_mut();
    let mut call_result: *mut c_void = null_mut();

    let hr = ((*services).vtable.as_ref().unwrap().get_object)(
        services as *mut c_void,
        class_name.as_ptr(),
        0,          // flags
        null_mut(), // context
        &mut class_object,
        &mut call_result,
    );

    if hr < 0 {
        ((*services).vtable.as_ref().unwrap().release)(services as *mut c_void);
        ((*locator).vtable.as_ref().unwrap().release)(locator as *mut c_void);
        (get_instance().unwrap().ole.co_uninitialize)();
        return Err(hr as u32);
    }

    let class_obj = class_object as *mut IWbemClassObject;

    // Get the Create method input parameters
    let method_name = to_wide_string("Create");
    let mut in_signature: *mut c_void = null_mut();
    let mut out_signature: *mut c_void = null_mut();

    let hr = ((*class_obj).vtable.as_ref().unwrap().get_method)(
        class_obj as *mut c_void,
        method_name.as_ptr(),
        0, // flags
        &mut in_signature,
        &mut out_signature,
    );

    if hr < 0 {
        ((*class_obj).vtable.as_ref().unwrap().release)(class_obj as *mut c_void);
        ((*services).vtable.as_ref().unwrap().release)(services as *mut c_void);
        ((*locator).vtable.as_ref().unwrap().release)(locator as *mut c_void);
        (get_instance().unwrap().ole.co_uninitialize)();
        return Err(hr as u32);
    }

    let in_sig = in_signature as *mut IWbemClassObject;

    // Spawn an instance of the input parameters
    let mut in_params: *mut c_void = null_mut();
    let hr = ((*in_sig).vtable.as_ref().unwrap().spawn_instance)(
        in_sig as *mut c_void,
        0, // flags
        &mut in_params,
    );

    if hr < 0 {
        ((*in_sig).vtable.as_ref().unwrap().release)(in_sig as *mut c_void);
        if !out_signature.is_null() {
            ((out_signature as *mut IWbemClassObject)
                .as_ref()
                .unwrap()
                .vtable
                .as_ref()
                .unwrap()
                .release)(out_signature);
        }
        ((*class_obj).vtable.as_ref().unwrap().release)(class_obj as *mut c_void);
        ((*services).vtable.as_ref().unwrap().release)(services as *mut c_void);
        ((*locator).vtable.as_ref().unwrap().release)(locator as *mut c_void);
        (get_instance().unwrap().ole.co_uninitialize)();
        return Err(hr as u32);
    }

    let in_params_obj = in_params as *mut IWbemClassObject;

    // Set the CommandLine parameter
    let command_line_prop = to_wide_string("CommandLine");
    let command_line_bstr = create_bstr(command_line);

    let mut variant = VARIANT {
        vt: VT_BSTR,
        reserved1: 0,
        reserved2: 0,
        reserved3: 0,
        data: VARIANT_Data {
            bstrVal: command_line_bstr,
        },
    };

    let hr = ((*in_params_obj).vtable.as_ref().unwrap().put)(
        in_params_obj as *mut c_void,
        command_line_prop.as_ptr(),
        0, // flags
        &variant,
        0, // type
    );

    if hr < 0 {
        (get_instance().unwrap().ole.sys_free_string)(command_line_bstr);
        ((*in_params_obj).vtable.as_ref().unwrap().release)(in_params_obj as *mut c_void);
        ((*in_sig).vtable.as_ref().unwrap().release)(in_sig as *mut c_void);
        if !out_signature.is_null() {
            ((out_signature as *mut IWbemClassObject)
                .as_ref()
                .unwrap()
                .vtable
                .as_ref()
                .unwrap()
                .release)(out_signature);
        }
        ((*class_obj).vtable.as_ref().unwrap().release)(class_obj as *mut c_void);
        ((*services).vtable.as_ref().unwrap().release)(services as *mut c_void);
        ((*locator).vtable.as_ref().unwrap().release)(locator as *mut c_void);
        (get_instance().unwrap().ole.co_uninitialize)();
        return Err(hr as u32);
    }

    // Execute the Create method
    let object_path = to_wide_string("Win32_Process");
    let mut out_params: *mut c_void = null_mut();
    let mut method_result: *mut c_void = null_mut();

    let hr = ((*services).vtable.as_ref().unwrap().exec_method)(
        services as *mut c_void,
        object_path.as_ptr(),
        method_name.as_ptr(),
        0,          // flags
        null_mut(), // context
        in_params,
        &mut out_params,
        &mut method_result,
    );

    // Clean up
    (get_instance().unwrap().ole.sys_free_string)(command_line_bstr);
    ((*in_params_obj).vtable.as_ref().unwrap().release)(in_params_obj as *mut c_void);
    ((*in_sig).vtable.as_ref().unwrap().release)(in_sig as *mut c_void);
    if !out_signature.is_null() {
        ((out_signature as *mut IWbemClassObject)
            .as_ref()
            .unwrap()
            .vtable
            .as_ref()
            .unwrap()
            .release)(out_signature);
    }
    ((*class_obj).vtable.as_ref().unwrap().release)(class_obj as *mut c_void);
    ((*services).vtable.as_ref().unwrap().release)(services as *mut c_void);
    ((*locator).vtable.as_ref().unwrap().release)(locator as *mut c_void);

    if !out_params.is_null() {
        // TODO: Extract process ID from out_params
        ((out_params as *mut IWbemClassObject)
            .as_ref()
            .unwrap()
            .vtable
            .as_ref()
            .unwrap()
            .release)(out_params);
    }

    (get_instance().unwrap().ole.co_uninitialize)();

    if hr < 0 {
        return Err(hr as u32);
    }

    Ok(0)
}

pub unsafe fn wmi_execute_command(
    command_line: &str,
    host: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<u32, u32> {
    // Initialize COM
    let hr = (get_instance().unwrap().ole.co_initialize)(null_mut());
    if hr < 0 {
        return Err(hr as u32);
    }

    let mut locator: *mut c_void = null_mut();

    // Create WbemLocator - use CoCreateInstanceEx for remote connections if host is provided
    if let Some(hostname) = host {
        let host_wide = to_wide_string(hostname);

        let mut auth_identity: *mut COAUTHIDENTITY = null_mut();
        let mut auth_info: *mut COAUTHINFO = null_mut();

        let user_wide_opt = username.map(|u| to_wide_string(u));
        let pass_wide_opt = password.map(|p| to_wide_string(p));

        if let (Some(ref user_wide), Some(ref pass_wide)) = (&user_wide_opt, &pass_wide_opt) {
            let identity = alloc::boxed::Box::new(COAUTHIDENTITY {
                user: user_wide.as_ptr() as *mut u16,
                user_length: (user_wide.len() - 1) as u32,
                domain: null_mut(),
                domain_length: 0,
                password: pass_wide.as_ptr() as *mut u16,
                password_length: (pass_wide.len() - 1) as u32,
                flags: 2, // SEC_WINNT_AUTH_IDENTITY_UNICODE
            });
            auth_identity = alloc::boxed::Box::into_raw(identity);

            let info = alloc::boxed::Box::new(COAUTHINFO {
                dw_authn_svc: 10, // RPC_C_AUTHN_WINNT
                dw_authz_svc: 0,  // RPC_C_AUTHZ_NONE
                pwsz_server_princ_name: null_mut(),
                dw_authn_level: 3, // RPC_C_AUTHN_LEVEL_CALL
                dw_impersonation_level: 3, // RPC_C_IMP_LEVEL_IMPERSONATE
                p_auth_identity_data: auth_identity,
                dw_capabilities: 0,
            });
            auth_info = alloc::boxed::Box::into_raw(info);
        }

        let server = alloc::boxed::Box::new(COSERVERINFO {
            dw_reserved1: 0,
            pwsz_name: host_wide.as_ptr() as *mut u16,
            p_auth_info: auth_info,
            dw_reserved2: 0,
        });
        let server_info = alloc::boxed::Box::into_raw(server);

        let mut qi = MULTI_QI {
            p_iid: &IID_IWBEMLOCATOR,
            p_itf: null_mut(),
            hr: 0,
        };

        let hr = (get_instance().unwrap().ole.co_create_instance_ex)(
            &CLSID_WBEMLOCATOR,
            null_mut(),
            1, // CLSCTX_INPROC_SERVER
            server_info,
            1,
            &mut qi,
        );

        // Cleanup server info structures
        let _ = alloc::boxed::Box::from_raw(server_info);
        if !auth_info.is_null() {
            let _ = alloc::boxed::Box::from_raw(auth_info);
        }
        if !auth_identity.is_null() {
            let _ = alloc::boxed::Box::from_raw(auth_identity);
        }

        if hr < 0 || qi.hr < 0 {
            let error = if hr < 0 { hr } else { qi.hr };
            (get_instance().unwrap().ole.co_uninitialize)();
            return Err(error as u32);
        }

        locator = qi.p_itf;
    } else {
        // Local connection
        let hr = (get_instance().unwrap().ole.co_create_instance)(
            &CLSID_WBEMLOCATOR,
            null_mut(),
            1, // CLSCTX_INPROC_SERVER
            &IID_IWBEMLOCATOR,
            &mut locator,
        );

        if hr < 0 {
            (get_instance().unwrap().ole.co_uninitialize)();
            return Err(hr as u32);
        }
    }

    let locator = locator as *mut IWbemLocator;

    // Build namespace string
    let namespace = if let Some(hostname) = host {
        let mut ns = String::from("\\\\");
        ns.push_str(hostname);
        ns.push_str("\\ROOT\\CIMV2");
        ns
    } else {
        "ROOT\\CIMV2".to_string()
    };
    let namespace_wide = to_wide_string(&namespace);

    let mut services: *mut c_void = null_mut();
    let user_wide = username.map(|u| to_wide_string(u));
    let pass_wide = password.map(|p| to_wide_string(p));
    let user_wide_ptr = user_wide.as_ref().map_or(null_mut(), |w| w.as_ptr() as *mut u16);
    let pass_wide_ptr = pass_wide.as_ref().map_or(null_mut(), |w| w.as_ptr() as *mut u16);

    let hr = ((*locator).vtable.as_ref().unwrap().connect_server)(
        locator as *mut c_void,
        namespace_wide.as_ptr(),
        user_wide_ptr,
        pass_wide_ptr,
        null_mut(),
        0,
        null_mut(),
        null_mut(),
        &mut services,
    );

    if hr < 0 {
        ((*locator).vtable.as_ref().unwrap().release)(locator as *mut c_void);
        (get_instance().unwrap().ole.co_uninitialize)();
        return Err(hr as u32);
    }

    let services = services as *mut IWbemServices;

    // Set proxy blanket for security
    let hr = (get_instance().unwrap().ole.co_set_proxy_blanket)(
        services as *mut c_void,
        10, // RPC_C_AUTHN_WINNT
        0,  // RPC_C_AUTHZ_NONE
        null_mut(),
        3,  // RPC_C_AUTHN_LEVEL_CALL
        3,  // RPC_C_IMP_LEVEL_IMPERSONATE
        null_mut(),
        0,  // EOAC_NONE
    );

    if hr < 0 {
        ((*services).vtable.as_ref().unwrap().release)(services as *mut c_void);
        ((*locator).vtable.as_ref().unwrap().release)(locator as *mut c_void);
        (get_instance().unwrap().ole.co_uninitialize)();
        return Err(hr as u32);
    }

    // Execute the WMI command using the same logic as wmi_create_process
    let result = execute_wmi_create_process_internal(services, command_line);

    // Cleanup
    ((*services).vtable.as_ref().unwrap().release)(services as *mut c_void);
    ((*locator).vtable.as_ref().unwrap().release)(locator as *mut c_void);
    (get_instance().unwrap().ole.co_uninitialize)();

    result
}

unsafe fn execute_wmi_create_process_internal(
    services: *mut IWbemServices,
    command_line: &str,
) -> Result<u32, u32> {
    // Get the Win32_Process class to create input parameters
    let class_name = to_wide_string("Win32_Process");
    let mut class_object: *mut c_void = null_mut();
    let mut call_result: *mut c_void = null_mut();

    let hr = ((*services).vtable.as_ref().unwrap().get_object)(
        services as *mut c_void,
        class_name.as_ptr(),
        0,          // flags
        null_mut(), // context
        &mut class_object,
        &mut call_result,
    );

    if hr < 0 {
        return Err(hr as u32);
    }

    let class_obj = class_object as *mut IWbemClassObject;

    // Get the Create method input parameters
    let method_name = to_wide_string("Create");
    let mut in_signature: *mut c_void = null_mut();
    let mut out_signature: *mut c_void = null_mut();

    let hr = ((*class_obj).vtable.as_ref().unwrap().get_method)(
        class_obj as *mut c_void,
        method_name.as_ptr(),
        0, // flags
        &mut in_signature,
        &mut out_signature,
    );

    if hr < 0 {
        ((*class_obj).vtable.as_ref().unwrap().release)(class_obj as *mut c_void);
        return Err(hr as u32);
    }

    let in_sig = in_signature as *mut IWbemClassObject;

    // Spawn an instance of the input parameters
    let mut in_params: *mut c_void = null_mut();
    let hr = ((*in_sig).vtable.as_ref().unwrap().spawn_instance)(
        in_sig as *mut c_void,
        0, // flags
        &mut in_params,
    );

    if hr < 0 {
        ((*in_sig).vtable.as_ref().unwrap().release)(in_sig as *mut c_void);
        if !out_signature.is_null() {
            ((out_signature as *mut IWbemClassObject)
                .as_ref()
                .unwrap()
                .vtable
                .as_ref()
                .unwrap()
                .release)(out_signature);
        }
        ((*class_obj).vtable.as_ref().unwrap().release)(class_obj as *mut c_void);
        return Err(hr as u32);
    }

    let in_params_obj = in_params as *mut IWbemClassObject;

    // Set the CommandLine parameter
    let command_line_prop = to_wide_string("CommandLine");
    let command_line_bstr = create_bstr(command_line);

    let mut variant = VARIANT {
        vt: VT_BSTR,
        reserved1: 0,
        reserved2: 0,
        reserved3: 0,
        data: VARIANT_Data {
            bstrVal: command_line_bstr,
        },
    };

    let hr = ((*in_params_obj).vtable.as_ref().unwrap().put)(
        in_params_obj as *mut c_void,
        command_line_prop.as_ptr(),
        0, // flags
        &variant,
        0, // type
    );

    if hr < 0 {
        (get_instance().unwrap().ole.sys_free_string)(command_line_bstr);
        ((*in_params_obj).vtable.as_ref().unwrap().release)(in_params_obj as *mut c_void);
        ((*in_sig).vtable.as_ref().unwrap().release)(in_sig as *mut c_void);
        if !out_signature.is_null() {
            ((out_signature as *mut IWbemClassObject)
                .as_ref()
                .unwrap()
                .vtable
                .as_ref()
                .unwrap()
                .release)(out_signature);
        }
        ((*class_obj).vtable.as_ref().unwrap().release)(class_obj as *mut c_void);
        return Err(hr as u32);
    }

    // Execute the Create method
    let object_path = to_wide_string("Win32_Process");
    let mut out_params: *mut c_void = null_mut();
    let mut method_result: *mut c_void = null_mut();

    let hr = ((*services).vtable.as_ref().unwrap().exec_method)(
        services as *mut c_void,
        object_path.as_ptr(),
        method_name.as_ptr(),
        0,          // flags
        null_mut(), // context
        in_params,
        &mut out_params,
        &mut method_result,
    );

    // Clean up
    (get_instance().unwrap().ole.sys_free_string)(command_line_bstr);
    ((*in_params_obj).vtable.as_ref().unwrap().release)(in_params_obj as *mut c_void);
    ((*in_sig).vtable.as_ref().unwrap().release)(in_sig as *mut c_void);
    if !out_signature.is_null() {
        ((out_signature as *mut IWbemClassObject)
            .as_ref()
            .unwrap()
            .vtable
            .as_ref()
            .unwrap()
            .release)(out_signature);
    }
    ((*class_obj).vtable.as_ref().unwrap().release)(class_obj as *mut c_void);

    if !out_params.is_null() {
        // TODO: Extract process ID from out_params
        ((out_params as *mut IWbemClassObject)
            .as_ref()
            .unwrap()
            .vtable
            .as_ref()
            .unwrap()
            .release)(out_params);
    }

    if hr < 0 {
        return Err(hr as u32);
    }

    Ok(0)
}