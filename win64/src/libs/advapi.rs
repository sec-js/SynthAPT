use core::{ffi::c_void, ptr::null_mut};

use alloc::vec::Vec;

use crate::{get_instance, libs::ldrapi::ldr_function};

use super::{
    k32::SecurityAttributes,
    ntdef::UnicodeString,
};

#[repr(C)]
pub struct ACL {
    pub AclRevision: u8,
    pub Sbz1: u8,
    pub AclSize: u16,
    pub AceCount: u16,
    pub Sbz2: u16,
}

#[repr(C)]
pub struct TRUSTEE_W {
    pub pMultipleTrustee: *mut TRUSTEE_W,
    pub MultipleTrusteeOperation: i32,
    pub TrusteeForm: i32,
    pub TrusteeType: i32,
    pub ptstrName: *mut u16,
}

#[repr(C)]
pub struct EXPLICIT_ACCESS_W {
    pub grfAccessPermissions: u32,
    pub grfAccessMode: i32,
    pub grfInheritance: u32,
    pub Trustee: TRUSTEE_W,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub struct SID {
    pub Revision: u8,
    pub SubAuthorityCount: u8,
    pub IdentifierAuthority: SID_IDENTIFIER_AUTHORITY,
    pub SubAuthority: [u32; 1],
}
#[repr(C)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub struct SID_IDENTIFIER_AUTHORITY {
    pub Value: [u8; 6],
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub struct LUID_AND_ATTRIBUTES {
    pub Luid: LUID,
    pub Attributes: u32,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub struct TOKEN_PRIVILEGES {
    pub PrivilegeCount: u32,
    pub Privileges: [LUID_AND_ATTRIBUTES; 1],
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct LUID {
    pub LowPart: u32,
    pub HighPart: i32,
}

#[repr(C)]
pub struct TokenElevation {
    pub token_is_elevated: u32,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub struct SECURITY_ATTRIBUTES {
    pub nLength: u32,
    pub lpSecurityDescriptor: *mut c_void,
    pub bInheritHandle: u32,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub struct SERVICE_STATUS {
    pub dwServiceType: u32,
    pub dwCurrentState: u32,
    pub dwControlsAccepted: u32,
    pub dwWin32ExitCode: u32,
    pub dwServiceSpecificExitCode: u32,
    pub dwCheckPoint: u32,
    pub dwWaitHint: u32,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub struct SERVICE_STATUS_PROCESS {
    pub dwServiceType: u32,
    pub dwCurrentState: u32,
    pub dwControlsAccepted: u32,
    pub dwWin32ExitCode: u32,
    pub dwServiceSpecificExitCode: u32,
    pub dwCheckPoint: u32,
    pub dwWaitHint: u32,
    pub dwProcessId: u32,
    pub dwServiceFlags: u32,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct FILETIME {
    pub dwLowDateTime: u32,
    pub dwHighDateTime: u32,
}

pub type GetTokenInformation = unsafe extern "system" fn(
    token_handle: *mut c_void,
    token_information_class: i32,
    token_information: *mut c_void,
    token_information_length: u32,
    return_length: *mut u32,
) -> bool;

pub type RevertToSelf = unsafe extern "system" fn() -> i32;

pub type OpenProcessToken = unsafe extern "system" fn(
    process_handle: *mut c_void,
    desired_access: u32,
    token_handle: *mut *mut c_void,
) -> bool;

pub type SetThreadToken =
    unsafe extern "system" fn(thread: *mut c_void, token: *mut c_void) -> bool;

pub type OpenSCManagerW = unsafe extern "system" fn(
    lpmachinename: *const u16,
    lpdatabasename: *const u16,
    dwdesiredaccess: u32,
) -> *mut c_void;

pub type OpenServiceW = unsafe extern "system" fn(
    hscmanager: *mut c_void,
    lpservicename: *const u16,
    dwdesiredaccess: u32,
) -> *mut c_void;

pub type StartServiceW = unsafe extern "system" fn(
    hservice: *mut c_void,
    dwnumserviceargs: u32,
    lpserviceargvectors: *const *const u16,
) -> bool;

pub type CreateServiceW = unsafe extern "system" fn(
    hscmanager: *mut c_void,
    lpservicename: *const u16,
    lpdisplayname: *const u16,
    dwdesiredaccess: u32,
    dwservicetype: u32,
    dwstarttype: u32,
    dwerrorcontrol: u32,
    lpbinarypathname: *const u16,
    lploadordergroup: *const u16,
    lpdwtagid: *mut u32,
    lpdependencies: *const u16,
    lpservicestartname: *const u16,
    lppassword: *const u16,
) -> *mut c_void;

pub type LogonUserW = unsafe extern "system" fn(
    lpszusername: *const u16,
    lpszdomain: *const u16,
    lpszpassword: *const u16,
    dwlogontype: u32,
    dwlogonprovider: u32,
    phtoken: *mut *mut c_void,
) -> bool;

pub type ImpersonateLoggedOnUser = unsafe extern "system" fn(htoken: *mut c_void) -> bool;

pub type CloseServiceHandle = unsafe extern "system" fn(hscobject: *mut c_void) -> bool;

pub type QueryServiceStatus =
    unsafe extern "system" fn(hservice: *mut c_void, lpservicestatus: *mut SERVICE_STATUS) -> bool;

pub type QueryServiceStatusEx = unsafe extern "system" fn(
    hservice: *mut c_void,
    infotype: u32,
    lpbuffer: *mut c_void,
    cbbufsize: u32,
    pcbbytesneeded: *mut u32,
) -> bool;

pub type DeleteService = unsafe extern "system" fn(hservice: *mut c_void) -> bool;

pub type ControlService = unsafe extern "system" fn(
    hservice: *mut c_void,
    dwcontrol: u32,
    lpservicestatus: *mut SERVICE_STATUS,
) -> bool;

pub type ChangeServiceConfigW = unsafe extern "system" fn(
    hservice: *mut c_void,
    dwservicetype: u32,
    dwstarttype: u32,
    dwerrorcontrol: u32,
    lpbinarypathname: *const u16,
    lploadordergroup: *const u16,
    lpdwtagid: *mut u32,
    lpdependencies: *const u16,
    lpservicestartname: *const u16,
    lppassword: *const u16,
    lpdisplayname: *const u16,
) -> bool;

pub type RegConnectRegistryW = unsafe extern "system" fn(
    lpmachinename: *const u16,
    hkey: *mut c_void,
    phkresult: *mut *mut c_void,
) -> u32;

pub type RegOpenKeyExW = unsafe extern "system" fn(
    hkey: *mut c_void,
    lpsubkey: *const u16,
    uloptions: u32,
    samdesired: u32,
    phkresult: *mut *mut c_void,
) -> u32;

pub type RegQueryValueExW = unsafe extern "system" fn(
    hkey: *mut c_void,
    lpvaluename: *const u16,
    lpreserved: *const u32,
    lptype: *mut u32,
    lpdata: *mut u8,
    lpcbdata: *mut u32,
) -> u32;

pub type RegEnumKeyExW = unsafe extern "system" fn(
    hkey: *mut c_void,
    dwindex: u32,
    lpname: *mut u16,
    lpcchname: *mut u32,
    lpreserved: *const u32,
    lpclass: *mut u16,
    lpcchclass: *mut u32,
    lpftlastwritetime: *mut FILETIME,
) -> u32;

pub type RegSaveKeyW = unsafe extern "system" fn(
    hkey: *mut c_void,
    lpfile: *const u16,
    lpsecurityattributes: *const SECURITY_ATTRIBUTES,
) -> u32;

pub type RegCloseKey = unsafe extern "system" fn(*mut c_void) -> u32;

pub type DuplicateTokenEx = unsafe extern "system" fn(
    hexistingtoken: *mut c_void,
    dwdesiredaccess: u32,
    lptokenattributes: *const SecurityAttributes,
    impersonationlevel: i32,
    tokentype: i32,
    phnewtoken: *mut *mut c_void,
) -> bool;

pub type LookupPrivilegeValueW = unsafe extern "system" fn(
    lpsystemname: *const u16,
    lpname: *const u16,
    lpluid: *mut LUID,
) -> bool;

pub type AdjustTokenPrivileges = unsafe extern "system" fn(
    tokenhandle: *mut c_void,
    disableallprivileges: bool,
    newstate: *const TOKEN_PRIVILEGES,
    bufferlength: u32,
    previousstate: *mut TOKEN_PRIVILEGES,
    returnlength: *mut u32,
) -> bool;

pub type RegCreateKeyExW = unsafe extern "system" fn(
    hkey: *mut c_void,
    lpsubkey: *const u16,
    reserved: u32,
    lpclass: *const u16,
    dwoptions: u32,
    samdesired: u32,
    lpsecurityattributes: *const SecurityAttributes,
    phkresult: *mut *mut c_void,
    lpdwdisposition: *mut u32,
) -> u32;

pub type RegSetValueExW = unsafe extern "system" fn(
    hkey: *mut c_void,
    lpvaluename: *const u16,
    reserved: u32,
    dwtype: u32,
    lpdata: *const u8,
    cbdata: u32,
) -> u32;

pub type OpenThreadToken = unsafe extern "system" fn(
    threadhandle: *mut c_void,
    desiredaccess: u32,
    openasself: bool,
    tokenhandle: *mut *mut c_void,
) -> bool;

pub type LookupPrivilegeNameW = unsafe extern "system" fn(
    lpsystemname: *const u16,
    lpluid: *const LUID,
    lpname: *mut u16,
    cchname: *mut u32,
) -> bool;

pub type RegDeleteKeyW = unsafe extern "system" fn(hkey: *mut c_void, lpsubkey: *const u16) -> u32;

pub type LookupAccountNameW = unsafe extern "system" fn(
    lpsystemname: *const u16,
    lpaccountname: *const u16,
    sid: *mut c_void,
    cbsid: *mut u32,
    referenceddomainname: *mut u16,
    cchreferenceddomainname: *mut u32,
    peuse: *mut *mut i32,
) -> bool;

pub type ConvertSidToStringSidW =
    unsafe extern "system" fn(sid: *mut c_void, stringsid: *mut *mut u16) -> bool;

pub type SetEntriesInAclW = unsafe extern "system" fn(
    ccountofexplicitentries: u32,
    plistofexplicitentries: *const EXPLICIT_ACCESS_W,
    oldacl: *const ACL,
    newacl: *mut *mut ACL,
) -> u32;

pub type InitializeSecurityDescriptor =
    unsafe extern "system" fn(psecuritydescriptor: *mut c_void, dwrevision: u32) -> bool;

pub type SetSecurityDescriptorDacl = unsafe extern "system" fn(
    psecuritydescriptor: *mut c_void,
    bdaclpresent: bool,
    pdacl: *const ACL,
    bdacldefaulted: bool,
) -> bool;

pub type MakeSelfRelativeSD = unsafe extern "system" fn(
    pabsolutesecuritydescriptor: *mut c_void,
    pselfrelativesecuritydescriptor: *mut c_void,
    lpdwbufferlength: *mut u32,
) -> bool;

pub type SetSecurityDescriptorOwner = unsafe extern "system" fn(
    psecuritydescriptor: *mut c_void,
    powner: *mut c_void,
    bownerdefaulted: bool,
) -> bool;

pub type InitializeAcl =
    unsafe extern "system" fn(pacl: *mut ACL, nacllength: u32, dwaclrevision: u32) -> bool;

pub type AddAce = unsafe extern "system" fn(
    pacl: *mut ACL,
    dwacerevision: u32,
    dwstartingaceindex: u32,
    pacelist: *const c_void,
    nacelistlength: u32,
) -> bool;

pub type AddAccessAllowedAceEx = unsafe extern "system" fn(
    pacl: *mut ACL,
    dwacerevision: u32,
    aceflags: u32,
    accessmask: u32,
    psid: *mut c_void,
) -> bool;

pub type CryptAcquireContextW = unsafe extern "system" fn(
    phprov: *mut usize,
    szcontainer: *const u16,
    szprovider: *const u16,
    dwprovtype: u32,
    dwflags: u32,
) -> bool;

pub type CryptGenRandom =
    unsafe extern "system" fn(hprov: usize, dwlen: u32, pbbuffer: *mut u8) -> bool;

pub type CryptReleaseContext = unsafe extern "system" fn(hprov: usize, dwflags: u32) -> bool;

// Service control handler callback type
pub type ServiceCtrlHandler = unsafe extern "system" fn(dwcontrol: u32);

// SERVICE_TABLE_ENTRYW structure
#[repr(C)]
pub struct ServiceTableEntryW {
    pub lp_service_name: *mut u16,
    pub lp_service_proc: Option<unsafe extern "system" fn(*mut u16)>,
}

pub type StartServiceCtrlDispatcherW =
    unsafe extern "system" fn(lpservicetable: *const ServiceTableEntryW) -> bool;

pub type RegisterServiceCtrlHandlerW = unsafe extern "system" fn(
    lpservicename: *const u16,
    lphandlerproc: ServiceCtrlHandler,
) -> *mut c_void;

pub type SetServiceStatus = unsafe extern "system" fn(
    hservicestatus: *mut c_void,
    lpservicestatus: *mut SERVICE_STATUS,
) -> bool;


pub struct Advapi32 {
    pub module_base: *mut u8,
    pub get_token_information: GetTokenInformation,
    pub revert_to_self: RevertToSelf,
    pub open_process_token: OpenProcessToken,
    pub set_thread_token: SetThreadToken,
    pub open_sc_manager_w: OpenSCManagerW,
    pub open_service_w: OpenServiceW,
    pub start_service_w: StartServiceW,
    pub create_service_w: CreateServiceW,
    pub logon_user_w: LogonUserW,
    pub impersonate_logged_on_user: ImpersonateLoggedOnUser,
    pub close_service_handle: CloseServiceHandle,
    pub query_service_status: QueryServiceStatus,
    pub query_service_status_ex: QueryServiceStatusEx,
    pub delete_service: DeleteService,
    pub control_service: ControlService,
    pub change_service_config_w: ChangeServiceConfigW,
    pub reg_connect_registry_w: RegConnectRegistryW,
    pub reg_open_key_ex_w: RegOpenKeyExW,
    pub reg_query_value_ex_w: RegQueryValueExW,
    pub reg_close_key: RegCloseKey,
    pub reg_enum_key_ex_w: RegEnumKeyExW,
    pub reg_save_key_w: RegSaveKeyW,
    pub duplicate_token_ex: DuplicateTokenEx,
    pub lookup_privilege_value_w: LookupPrivilegeValueW,
    pub adjust_token_privileges: AdjustTokenPrivileges,
    pub reg_create_key_ex_w: RegCreateKeyExW,
    pub reg_set_value_ex_w: RegSetValueExW,
    pub lookup_privilege_name_w: LookupPrivilegeNameW,
    pub open_thread_token: OpenThreadToken,
    pub reg_delete_key_w: RegDeleteKeyW,
    pub lookup_account_name_w: LookupAccountNameW,
    pub convert_sid_to_string_sid_w: ConvertSidToStringSidW,
    pub set_entries_in_acl_w: SetEntriesInAclW,
    pub initialize_security_descriptor: InitializeSecurityDescriptor,
    pub set_security_descriptor_dacl: SetSecurityDescriptorDacl,
    pub make_self_relative_sd: MakeSelfRelativeSD,
    pub set_security_descriptor_owner: SetSecurityDescriptorOwner,
    pub initialize_acl: InitializeAcl,
    pub add_ace: AddAce,
    pub add_access_allowed_ace_ex: AddAccessAllowedAceEx,
    pub crypt_acquire_context_w: CryptAcquireContextW,
    pub crypt_gen_random: CryptGenRandom,
    pub crypt_release_context: CryptReleaseContext,
    pub start_service_ctrl_dispatcher_w: StartServiceCtrlDispatcherW,
    pub register_service_ctrl_handler_w: RegisterServiceCtrlHandlerW,
    pub set_service_status: SetServiceStatus,
}

impl Advapi32 {
    pub fn new() -> Self {
        Advapi32 {
            module_base: null_mut(),
            get_token_information: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            revert_to_self: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            open_process_token: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            set_thread_token: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            open_sc_manager_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            open_service_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            start_service_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            create_service_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            logon_user_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            impersonate_logged_on_user: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            close_service_handle: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            query_service_status: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            query_service_status_ex: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            delete_service: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            control_service: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            change_service_config_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            reg_connect_registry_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            reg_open_key_ex_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            reg_query_value_ex_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            reg_close_key: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            reg_enum_key_ex_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            reg_save_key_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            duplicate_token_ex: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            lookup_privilege_value_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            adjust_token_privileges: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            reg_create_key_ex_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            reg_set_value_ex_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            lookup_privilege_name_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            open_thread_token: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            reg_delete_key_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            lookup_account_name_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            convert_sid_to_string_sid_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            set_entries_in_acl_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            initialize_security_descriptor: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            set_security_descriptor_dacl: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            make_self_relative_sd: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            set_security_descriptor_owner: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            initialize_acl: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            add_ace: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            add_access_allowed_ace_ex: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            crypt_acquire_context_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            crypt_gen_random: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            crypt_release_context: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            start_service_ctrl_dispatcher_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            register_service_ctrl_handler_w: unsafe { core::mem::transmute(null_mut::<c_void>()) },
            set_service_status: unsafe { core::mem::transmute(null_mut::<c_void>()) },
        }
    }
}

unsafe impl Sync for Advapi32 {}
unsafe impl Send for Advapi32 {}

pub fn init_advapi32_funcs() {
    unsafe {
        let mut advapi_dll_unicode = UnicodeString::new();
        let utf16_string: Vec<u16> = "advapi32.dll".encode_utf16().chain(Some(0)).collect();
        advapi_dll_unicode.init(utf16_string.as_ptr());

        let mut h_advapi: *mut c_void = null_mut();

        let instance = get_instance().unwrap();
        unsafe {
            (instance.ntdll.ldr_load_dll)(
                null_mut(),
                null_mut(),
                advapi_dll_unicode,
                &mut h_advapi as *mut _ as *mut c_void,
            )
        };

        if h_advapi.is_null() {
            return;
        }

        instance.advapi.module_base = h_advapi as *mut u8;

        //could also use getprocaddress i guess
        let nt_get_token_information_addr = ldr_function(instance.advapi.module_base, 0x10357d2c);
        instance.advapi.get_token_information = core::mem::transmute(nt_get_token_information_addr);

        let nt_revert_to_self_addr = ldr_function(instance.advapi.module_base, 0x7292758a);
        instance.advapi.revert_to_self = core::mem::transmute(nt_revert_to_self_addr);

        let nt_open_process_token_addr = ldr_function(instance.advapi.module_base, 0xd9f566f7);
        instance.advapi.open_process_token = core::mem::transmute(nt_open_process_token_addr);

        let nt_set_thread_token_addr = ldr_function(instance.advapi.module_base, 0xc9f4966a);
        instance.advapi.set_thread_token = core::mem::transmute(nt_set_thread_token_addr);

        let nt_open_sc_manager_w_addr = ldr_function(instance.advapi.module_base, 0x18c9ee7f);
        instance.advapi.open_sc_manager_w = core::mem::transmute(nt_open_sc_manager_w_addr);

        let nt_open_service_w_addr = ldr_function(instance.advapi.module_base, 0xd3c797bf);
        instance.advapi.open_service_w = core::mem::transmute(nt_open_service_w_addr);

        let nt_start_service_w_addr = ldr_function(instance.advapi.module_base, 0xb7b675fb);
        instance.advapi.start_service_w = core::mem::transmute(nt_start_service_w_addr);

        let nt_create_service_w_addr = ldr_function(instance.advapi.module_base, 0xe01930c1);
        instance.advapi.create_service_w = core::mem::transmute(nt_create_service_w_addr);

        let k_logon_user_w_addr = ldr_function(instance.advapi.module_base, 0x5ed5d61a);
        instance.advapi.logon_user_w = core::mem::transmute(k_logon_user_w_addr);

        let k_impersonate_logged_on_user_addr =
            ldr_function(instance.advapi.module_base, 0x47ec82fa);
        instance.advapi.impersonate_logged_on_user =
            core::mem::transmute(k_impersonate_logged_on_user_addr);

        let k_close_service_handle_addr = ldr_function(instance.advapi.module_base, 0x6d882098);
        instance.advapi.close_service_handle = core::mem::transmute(k_close_service_handle_addr);

        let k_query_service_status_addr = ldr_function(instance.advapi.module_base, 0x3b0a3d50);
        instance.advapi.query_service_status = core::mem::transmute(k_query_service_status_addr);

        let k_query_service_status_ex_addr = ldr_function(instance.advapi.module_base, 0x268eda8d);
        instance.advapi.query_service_status_ex = core::mem::transmute(k_query_service_status_ex_addr);

        let k_delete_service_addr = ldr_function(instance.advapi.module_base, 0xe4d65009);
        instance.advapi.delete_service = core::mem::transmute(k_delete_service_addr);

        let k_control_service_addr = ldr_function(instance.advapi.module_base, 0xb6816097);
        instance.advapi.control_service = core::mem::transmute(k_control_service_addr);

        let k_change_service_config_w_addr = ldr_function(instance.advapi.module_base, 0x2472a9f2);
        instance.advapi.change_service_config_w =
            core::mem::transmute(k_change_service_config_w_addr);

        let k_reg_connect_registry_w_addr = ldr_function(instance.advapi.module_base, 0x510625d);
        instance.advapi.reg_connect_registry_w =
            core::mem::transmute(k_reg_connect_registry_w_addr);

        let k_reg_open_key_ex_w_addr = ldr_function(instance.advapi.module_base, 0x83e34e72);
        instance.advapi.reg_open_key_ex_w = core::mem::transmute(k_reg_open_key_ex_w_addr);

        let k_reg_query_value_ex_w_addr = ldr_function(instance.advapi.module_base, 0xd37cffca);
        instance.advapi.reg_query_value_ex_w = core::mem::transmute(k_reg_query_value_ex_w_addr);

        let k_reg_close_key_addr = ldr_function(instance.advapi.module_base, 0x7649a602);
        instance.advapi.reg_close_key = core::mem::transmute(k_reg_close_key_addr);

        let k_reg_enum_key_ex_w_addr = ldr_function(instance.advapi.module_base, 0xe9a3d275);
        instance.advapi.reg_enum_key_ex_w = core::mem::transmute(k_reg_enum_key_ex_w_addr);

        let k_reg_save_key_w_addr = ldr_function(instance.advapi.module_base, 0xfb005072);
        instance.advapi.reg_save_key_w = core::mem::transmute(k_reg_save_key_w_addr);

        let k_duplicate_token_ex_addr = ldr_function(instance.advapi.module_base, 0x10ad057e);
        instance.advapi.duplicate_token_ex = core::mem::transmute(k_duplicate_token_ex_addr);

        let k_lookup_privilege_value_w_addr = ldr_function(instance.advapi.module_base, 0x1e34407a);
        instance.advapi.lookup_privilege_value_w =
            core::mem::transmute(k_lookup_privilege_value_w_addr);

        let k_adjust_token_privileges_addr = ldr_function(instance.advapi.module_base, 0x677fbb8b);
        instance.advapi.adjust_token_privileges =
            core::mem::transmute(k_adjust_token_privileges_addr);

        let k_reg_create_key_ex_w_addr = ldr_function(instance.advapi.module_base, 0xc988e74);
        instance.advapi.reg_create_key_ex_w = core::mem::transmute(k_reg_create_key_ex_w_addr);

        let k_reg_set_value_ex_w_addr = ldr_function(instance.advapi.module_base, 0x2cea05e0);
        instance.advapi.reg_set_value_ex_w = core::mem::transmute(k_reg_set_value_ex_w_addr);

        let k_lookup_privilege_name_w_addr = ldr_function(instance.advapi.module_base, 0x843a85fe);
        instance.advapi.lookup_privilege_name_w =
            core::mem::transmute(k_lookup_privilege_name_w_addr);

        let k_open_thread_token_addr = ldr_function(instance.advapi.module_base, 0xe249d070);
        instance.advapi.open_thread_token = core::mem::transmute(k_open_thread_token_addr);

        let k_reg_delete_key_w_addr = ldr_function(instance.advapi.module_base, 0x2c0da6d6);
        instance.advapi.reg_delete_key_w = core::mem::transmute(k_reg_delete_key_w_addr);

        let k_lookup_account_name_w_addr = ldr_function(instance.advapi.module_base, 0x78bd1ac4);
        instance.advapi.lookup_account_name_w = core::mem::transmute(k_lookup_account_name_w_addr);

        let k_convert_sid_to_string_sid_w_addr =
            ldr_function(instance.advapi.module_base, 0x2fb2f7d7);
        instance.advapi.convert_sid_to_string_sid_w =
            core::mem::transmute(k_convert_sid_to_string_sid_w_addr);

        let k_set_entries_in_acl_w_addr = ldr_function(instance.advapi.module_base, 0xd396389);
        instance.advapi.set_entries_in_acl_w = core::mem::transmute(k_set_entries_in_acl_w_addr);

        let k_initialize_security_descriptor_addr =
            ldr_function(instance.advapi.module_base, 0x31e175ce);
        instance.advapi.initialize_security_descriptor =
            core::mem::transmute(k_initialize_security_descriptor_addr);

        let k_set_security_descriptor_dacl_addr =
            ldr_function(instance.advapi.module_base, 0x5c048f5c);
        instance.advapi.set_security_descriptor_dacl =
            core::mem::transmute(k_set_security_descriptor_dacl_addr);

        let k_make_self_relative_sd_addr = ldr_function(instance.advapi.module_base, 0x9dca6c40);
        instance.advapi.make_self_relative_sd = core::mem::transmute(k_make_self_relative_sd_addr);

        let k_set_security_descriptor_owner_addr =
            ldr_function(instance.advapi.module_base, 0xdd69c6f3);
        instance.advapi.set_security_descriptor_owner =
            core::mem::transmute(k_set_security_descriptor_owner_addr);

        let k_initialize_acl_addr = ldr_function(instance.advapi.module_base, 0x136c4367);
        instance.advapi.initialize_acl = core::mem::transmute(k_initialize_acl_addr);

        let k_add_ace_addr = ldr_function(instance.advapi.module_base, 0xa4733f17);
        instance.advapi.add_ace = core::mem::transmute(k_add_ace_addr);

        let k_add_access_allowed_ace_ex_addr = ldr_function(instance.advapi.module_base, 0x8adf5ae);
        instance.advapi.add_access_allowed_ace_ex =
            core::mem::transmute(k_add_access_allowed_ace_ex_addr);

        let k_crypt_acquire_context_w_addr = ldr_function(instance.advapi.module_base, 0xc4e81a5d);
        instance.advapi.crypt_acquire_context_w =
            core::mem::transmute(k_crypt_acquire_context_w_addr);

        let k_crypt_gen_random_addr = ldr_function(instance.advapi.module_base, 0x343d3c72);
        instance.advapi.crypt_gen_random = core::mem::transmute(k_crypt_gen_random_addr);

        let k_crypt_release_context_addr = ldr_function(instance.advapi.module_base, 0x674798fd);
        instance.advapi.crypt_release_context = core::mem::transmute(k_crypt_release_context_addr);

        let k_start_service_ctrl_dispatcher_w_addr = ldr_function(instance.advapi.module_base, 0xdf8573b7);
        instance.advapi.start_service_ctrl_dispatcher_w = core::mem::transmute(k_start_service_ctrl_dispatcher_w_addr);

        let k_register_service_ctrl_handler_w_addr = ldr_function(instance.advapi.module_base, 0x140c5585);
        instance.advapi.register_service_ctrl_handler_w = core::mem::transmute(k_register_service_ctrl_handler_w_addr);

        let k_set_service_status_addr = ldr_function(instance.advapi.module_base, 0xbadbf0a6);
        instance.advapi.set_service_status = core::mem::transmute(k_set_service_status_addr);

    }
}

pub fn random_in_range(lower: u32, upper: u32) -> Result<u32, u32> {
    let random_number = get_random()?;
    Ok(lower + (random_number % (upper - lower + 1)))
}

pub fn get_random() -> Result<u32, u32> {
    let mut h_prov = 0;

    if !unsafe {
        (get_instance().unwrap().advapi.crypt_acquire_context_w)(
            &mut h_prov,
            null_mut(),
            null_mut(),
            1,
            4026531840u32,
        )
    } {
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    let mut buffer: [u8; 4] = [0; 4];
    if !unsafe {
        (get_instance().unwrap().advapi.crypt_gen_random)(
            h_prov,
            buffer.len() as u32,
            buffer.as_mut_ptr(),
        )
    } {
        unsafe { (get_instance().unwrap().advapi.crypt_release_context)(h_prov, 0) };
        return Err(unsafe { (get_instance().unwrap().k32.get_last_error)() });
    }

    if h_prov != 0 {
        unsafe { (get_instance().unwrap().advapi.crypt_release_context)(h_prov, 0) };
    }
    Ok(u32::from_le_bytes(buffer))
}


/// Generate a random number with a decay function to simulate long-tail data like DNS requests
/// n sets the y intersection and lambda determins how step the decay is - higher = steeper
pub fn random_decay(lower: u32, upper: u32, lambda: f32) -> Result<u32, u32> {
    let r = get_random()?;

    let uniform_random = r as f32 / u32::MAX as f32;

    let uniform_random = uniform_random.min(1.0 - f32::EPSILON);

    let exp_random = -ln_approx(1.0 - uniform_random) / lambda;

    let range = (upper - lower) as f32;
    let weighted_value = lower as f32 + exp_random * range;

    Ok(weighted_value.min(upper as f32).max(lower as f32) as u32)
}


fn ln_approx(x: f32) -> f32 {
    // Approximation for natural logarithm using a series expansion
    if x <= 0.0 {
        return f32::NAN; // ln(x) is undefined for x <= 0
    }
    let mut y = (x - 1.0) / (x + 1.0); // Transform for better convergence
    let mut y2 = y * y;
    let mut result = 0.0;
    let mut term = y;
    let mut n = 1.0;

    // Perform a few iterations of the series
    for _ in 0..10 {
        result += term / n;
        term *= y2;
        n += 2.0;
    }

    2.0 * result
}


fn exp_approx(x: f32) -> f32 {
    let mut term = 1.0; // Start with the first term (1.0)
    let mut result = 1.0; // Accumulate the sum
    let mut numerator = x; // x^1
    let mut denominator = 1.0; // 1!

    // Add terms up to a certain precision (4 terms in this example)
    for i in 1..10 { // More iterations = more accuracy
        result += numerator / denominator;
        numerator *= x; // Update x^i
        denominator *= i as f32; // Update i!
    }

    result
}