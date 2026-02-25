//! Shell automation for user-like file operations
//! Uses Shell.Application COM object to simulate user actions

use core::{
    ffi::c_void,
    mem::zeroed,
    ptr::{null, null_mut},
};

use alloc::vec::Vec;

use crate::{
    get_instance,
    libs::ole::{DISPPARAMS, GUID, IDispatch, IID_NULL, VARIANT},
};

const E_FAIL: u32 = 0x80004005;

// Shell.Application CLSID: {13709620-C279-11CE-A49E-444553540000}
const CLSID_SHELL: GUID = GUID {
    data1: 0x13709620,
    data2: 0xC279,
    data3: 0x11CE,
    data4: [0xA4, 0x9E, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00],
};

// ShellWindows CLSID: {9BA05972-F6A8-11CF-A442-00A0C90A8F39}
const CLSID_SHELL_WINDOWS: GUID = GUID {
    data1: 0x9BA05972,
    data2: 0xF6A8,
    data3: 0x11CF,
    data4: [0xA4, 0x42, 0x00, 0xA0, 0xC9, 0x0A, 0x8F, 0x39],
};

// Scripting.FileSystemObject CLSID: {0D43FE01-F093-11CF-8940-00A0C9054228}
const CLSID_FSO: GUID = GUID {
    data1: 0x0D43FE01,
    data2: 0xF093,
    data3: 0x11CF,
    data4: [0x89, 0x40, 0x00, 0xA0, 0xC9, 0x05, 0x42, 0x28],
};

// IID_IDispatch for QueryInterface
const IID_IDISPATCH: GUID = GUID {
    data1: 0x00020400,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

// Copy flags for CopyHere
const COPY_FLAGS: i32 = 0x14;  // No progress + Yes to all

/// EXCEPINFO structure for COM exception info
#[repr(C)]
struct EXCEPINFO {
    wCode: u16,
    wReserved: u16,
    bstrSource: *mut u16,
    bstrDescription: *mut u16,
    bstrHelpFile: *mut u16,
    dwHelpContext: u32,
    pvReserved: *mut c_void,
    pfnDeferredFillIn: *mut c_void,
    scode: i32,
}

/// Create a COM object by CLSID
fn create_com_object(clsid: &GUID) -> Result<*mut IDispatch, u32> {
    unsafe {
        let instance = get_instance().unwrap();

        let hr = (instance.ole.co_initialize)(null());
        if hr != 0 && hr != 1 {
            return Err(hr as u32);
        }

        let mut obj_ptr: *mut c_void = null_mut();

        let hr = (instance.ole.co_create_instance)(
            clsid,
            null_mut(),
            1 | 2 | 4,  // CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER | CLSCTX_LOCAL_SERVER
            &IID_IDISPATCH,
            &mut obj_ptr,
        );

        if hr != 0 {
            return Err(hr as u32);
        }

        Ok(obj_ptr as *mut IDispatch)
    }
}

/// Create Shell.Application COM object (in-process, for FSO operations)
fn create_shell_application() -> Result<*mut IDispatch, u32> {
    create_com_object(&CLSID_SHELL)
}

/// Get the running shell instance via ShellWindows (out-of-process, for ShellExecute)
/// This connects to the actual running explorer.exe shell
fn get_running_shell() -> Result<*mut IDispatch, u32> {
    unsafe {
        let instance = get_instance().unwrap();

        let hr = (instance.ole.co_initialize)(null());
        if hr != 0 && hr != 1 {
            return Err(hr as u32);
        }

        // Create ShellWindows object
        let mut shell_windows: *mut c_void = null_mut();
        let hr = (instance.ole.co_create_instance)(
            &CLSID_SHELL_WINDOWS,
            null_mut(),
            1 | 4,  // CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER
            &IID_IDISPATCH,
            &mut shell_windows,
        );

        if hr != 0 || shell_windows.is_null() {
            return Err(if hr != 0 { hr as u32 } else { E_FAIL });
        }

        let shell_windows = shell_windows as *mut IDispatch;

        // Get Count property to iterate windows
        let count_dispid = match get_dispid(shell_windows, "Count") {
            Ok(d) => d,
            Err(e) => {
                release(shell_windows);
                return Err(e);
            }
        };

        let mut args: [VARIANT; 0] = [];
        let count_result = match invoke_method(shell_windows, count_dispid, &mut args, 2) {
            Ok(v) => v,
            Err(e) => {
                release(shell_windows);
                return Err(e);
            }
        };

        let count = count_result.data.iVal;

        // Iterate through windows to find desktop shell
        let item_dispid = match get_dispid(shell_windows, "Item") {
            Ok(d) => d,
            Err(e) => {
                release(shell_windows);
                return Err(e);
            }
        };

        for i in 0..count {
            let mut item_args = [VARIANT::from_i32(i)];
            let item_result = match invoke_method(shell_windows, item_dispid, &mut item_args, 1) {
                Ok(v) => v,
                Err(_) => continue,
            };

            if item_result.vt != 9 || item_result.data.pdispVal.is_null() {
                continue;
            }

            let window = item_result.data.pdispVal as *mut IDispatch;

            // Get Document property (this is the folder)
            let doc_dispid = match get_dispid(window, "Document") {
                Ok(d) => d,
                Err(_) => {
                    release(window);
                    continue;
                }
            };

            let mut doc_args: [VARIANT; 0] = [];
            let doc_result = match invoke_method(window, doc_dispid, &mut doc_args, 2) {
                Ok(v) => v,
                Err(_) => {
                    release(window);
                    continue;
                }
            };

            release(window);

            if doc_result.vt != 9 || doc_result.data.pdispVal.is_null() {
                continue;
            }

            let document = doc_result.data.pdispVal as *mut IDispatch;

            // Get Application from the Document (folder) - this is Shell.Application
            let app_dispid = match get_dispid(document, "Application") {
                Ok(d) => d,
                Err(_) => {
                    release(document);
                    continue;
                }
            };

            let mut app_args: [VARIANT; 0] = [];
            let app_result = match invoke_method(document, app_dispid, &mut app_args, 2) {
                Ok(v) => v,
                Err(_) => {
                    release(document);
                    continue;
                }
            };

            release(document);

            if app_result.vt == 9 && !app_result.data.pdispVal.is_null() {
                release(shell_windows);
                return Ok(app_result.data.pdispVal as *mut IDispatch);
            }
        }

        release(shell_windows);
        Err(E_FAIL)
    }
}

/// Create Scripting.FileSystemObject COM object
fn create_fso() -> Result<*mut IDispatch, u32> {
    create_com_object(&CLSID_FSO)
}

/// Get DISPID for a method name
unsafe fn get_dispid(dispatch: *mut IDispatch, name: &str) -> Result<i32, u32> {
    let name_w: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let name_ptr = name_w.as_ptr();
    let mut dispid: i32 = 0;

    let vtbl = (*dispatch).lpVtbl;
    let hr = ((*vtbl).GetIDsOfNames)(
        dispatch as *mut c_void,
        &IID_NULL,
        &name_ptr,
        1,
        0x0400,
        &mut dispid,
    );

    if hr != 0 {
        return Err(hr as u32);
    }

    Ok(dispid)
}

/// Invoke a method that returns a VARIANT
unsafe fn invoke_method(
    dispatch: *mut IDispatch,
    dispid: i32,
    args: &mut [VARIANT],
    flags: u16,
) -> Result<VARIANT, u32> {
    let vtbl = (*dispatch).lpVtbl;

    let mut params = DISPPARAMS {
        rgvarg: if args.is_empty() { null_mut() } else { args.as_mut_ptr() },
        rgdispidNamedArgs: null_mut(),
        cArgs: args.len() as u32,
        cNamedArgs: 0,
    };

    let mut result: VARIANT = zeroed();
    let mut excep: EXCEPINFO = zeroed();
    let mut arg_err: u32 = 0;

    let hr = ((*vtbl).Invoke)(
        dispatch as *mut c_void,
        dispid,
        &IID_NULL,
        0x0400,
        flags,
        &mut params as *mut _ as *mut c_void,
        &mut result as *mut _ as *mut c_void,
        &mut excep as *mut _ as *mut c_void,
        &mut arg_err,
    );

    if hr != 0 {
        return Err(hr as u32);
    }

    Ok(result)
}

/// Call Shell.NameSpace(path) - returns a Folder object
unsafe fn shell_namespace(shell: *mut IDispatch, path: &str) -> Result<*mut IDispatch, u32> {
    let dispid = get_dispid(shell, "NameSpace")?;
    let mut args = [VARIANT::from_bstr(path)];
    let result = invoke_method(shell, dispid, &mut args, 1)?;

    if result.vt != 9 {
        return Err(E_FAIL);
    }

    let folder = result.data.pdispVal as *mut IDispatch;
    if folder.is_null() {
        return Err(E_FAIL);
    }

    Ok(folder)
}

/// Call Folder.Items() - returns a FolderItems collection
unsafe fn folder_items(folder: *mut IDispatch) -> Result<*mut IDispatch, u32> {
    let dispid = get_dispid(folder, "Items")?;
    let mut args: [VARIANT; 0] = [];
    let result = invoke_method(folder, dispid, &mut args, 1)?;

    if result.vt != 9 {
        return Err(E_FAIL);
    }

    let items = result.data.pdispVal as *mut IDispatch;
    if items.is_null() {
        return Err(E_FAIL);
    }

    Ok(items)
}

/// Call Folder.CopyHere(items, flags)
unsafe fn folder_copy_here(
    dest_folder: *mut IDispatch,
    items: *mut IDispatch,
    flags: i32,
) -> Result<(), u32> {
    let dispid = get_dispid(dest_folder, "CopyHere")?;

    let mut items_var = VARIANT::new();
    items_var.vt = 9;  // VT_DISPATCH
    items_var.data.pdispVal = items as *mut c_void;

    let mut args = [
        VARIANT::from_i32(flags),
        items_var,
    ];

    invoke_method(dest_folder, dispid, &mut args, 1)?;
    Ok(())
}

/// Release a COM object
unsafe fn release(obj: *mut IDispatch) {
    if !obj.is_null() {
        let vtbl = (*obj).lpVtbl;
        ((*vtbl).Release)(obj as *mut c_void);
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Extract a ZIP file using Shell
/// Automatically creates a folder with the zip name (without .zip) and extracts into it
/// Returns the path to the created folder
pub fn shell_extract_zip(zip_path: &str) -> Result<Vec<u8>, u32> {
    // Derive destination folder from zip path (remove .zip extension)
    let dest_path = if zip_path.to_lowercase().ends_with(".zip") {
        &zip_path[..zip_path.len() - 4]
    } else {
        zip_path
    };

    // Create destination folder if it doesn't exist
    if !shell_folder_exists(dest_path).unwrap_or(false) {
        shell_create_folder(dest_path)?;
    }

    unsafe {
        let shell = create_shell_application()?;

        let zip_folder = match shell_namespace(shell, zip_path) {
            Ok(f) => f,
            Err(e) => {
                release(shell);
                return Err(e);
            }
        };

        let dest_folder = match shell_namespace(shell, dest_path) {
            Ok(f) => f,
            Err(e) => {
                release(zip_folder);
                release(shell);
                return Err(e);
            }
        };

        let items = match folder_items(zip_folder) {
            Ok(i) => i,
            Err(e) => {
                release(dest_folder);
                release(zip_folder);
                release(shell);
                return Err(e);
            }
        };

        let result = folder_copy_here(dest_folder, items, COPY_FLAGS);

        release(items);
        release(dest_folder);
        release(zip_folder);
        release(shell);

        result?;
        Ok(Vec::from(dest_path.as_bytes()))
    }
}

/// Execute a file using Shell.Application.ShellExecute (in-process)
/// Parent process will be the calling process
/// - path: file to execute (required)
/// - verb: action verb - "open", "runas", "edit", "print", "explore", etc. (optional, empty = default)
/// - args: command line arguments (optional)
pub fn shell_execute(path: &str, verb: &str, args: &str) -> Result<(), u32> {
    unsafe {
        let shell = create_shell_application()?;

        let dispid = match get_dispid(shell, "ShellExecute") {
            Ok(d) => d,
            Err(e) => {
                release(shell);
                return Err(e);
            }
        };

        // ShellExecute(sFile, vArgs, vDir, vOperation, vShow)
        // Args in reverse order for DISPPARAMS

        // Derive working directory from path (parent folder)
        let dir = if let Some(pos) = path.rfind('\\') {
            &path[..pos]
        } else {
            ""
        };

        let show_var = VARIANT::from_i32(1);  // SW_SHOWNORMAL
        let verb_var = if verb.is_empty() { VARIANT::from_bstr("") } else { VARIANT::from_bstr(verb) };
        let dir_var = VARIANT::from_bstr(dir);
        let args_var = if args.is_empty() { VARIANT::from_bstr("") } else { VARIANT::from_bstr(args) };
        let path_var = VARIANT::from_bstr(path);

        let mut args_arr = [
            show_var,   // vShow (param 5)
            verb_var,   // vOperation (param 4)
            dir_var,    // vDir (param 3)
            args_var,   // vArgs (param 2)
            path_var,   // sFile (param 1)
        ];

        let result = invoke_method(shell, dispid, &mut args_arr, 1);
        release(shell);

        result.map(|_| ())
    }
}

/// Execute a file using the running explorer.exe shell via ShellWindows
/// Parent process will be explorer.exe (simulates user double-click)
/// - path: file to execute (required)
/// - verb: action verb - "open", "runas", "edit", "print", "explore", etc. (optional, empty = default)
/// - args: command line arguments (optional)
pub fn shell_execute_explorer(path: &str, verb: &str, args: &str) -> Result<(), u32> {
    unsafe {
        // Use running shell so processes are spawned from explorer.exe
        let shell = get_running_shell()?;

        let dispid = match get_dispid(shell, "ShellExecute") {
            Ok(d) => d,
            Err(e) => {
                release(shell);
                return Err(e);
            }
        };

        // ShellExecute(sFile, vArgs, vDir, vOperation, vShow)
        // Args in reverse order for DISPPARAMS

        // Derive working directory from path (parent folder)
        let dir = if let Some(pos) = path.rfind('\\') {
            &path[..pos]
        } else {
            ""
        };

        let show_var = VARIANT::from_i32(1);  // SW_SHOWNORMAL
        let verb_var = if verb.is_empty() { VARIANT::from_bstr("") } else { VARIANT::from_bstr(verb) };
        let dir_var = VARIANT::from_bstr(dir);
        let args_var = if args.is_empty() { VARIANT::from_bstr("") } else { VARIANT::from_bstr(args) };
        let path_var = VARIANT::from_bstr(path);

        let mut args_arr = [
            show_var,   // vShow (param 5)
            verb_var,   // vOperation (param 4)
            dir_var,    // vDir (param 3)
            args_var,   // vArgs (param 2)
            path_var,   // sFile (param 1)
        ];

        let result = invoke_method(shell, dispid, &mut args_arr, 1);
        release(shell);

        result.map(|_| ())
    }
}

/// Create a folder using Scripting.FileSystemObject
fn shell_create_folder(path: &str) -> Result<(), u32> {
    unsafe {
        let fso = create_fso()?;

        let dispid = match get_dispid(fso, "CreateFolder") {
            Ok(d) => d,
            Err(e) => {
                release(fso);
                return Err(e);
            }
        };

        let mut args = [VARIANT::from_bstr(path)];
        let result = invoke_method(fso, dispid, &mut args, 1);
        release(fso);

        result.map(|_| ())
    }
}

/// Check if a folder exists using Scripting.FileSystemObject
fn shell_folder_exists(path: &str) -> Result<bool, u32> {
    unsafe {
        let fso = create_fso()?;

        let dispid = match get_dispid(fso, "FolderExists") {
            Ok(d) => d,
            Err(e) => {
                release(fso);
                return Err(e);
            }
        };

        let mut args = [VARIANT::from_bstr(path)];
        let result = invoke_method(fso, dispid, &mut args, 1)?;
        release(fso);

        // Result is VT_BOOL (11), boolVal is -1 for true, 0 for false
        Ok(result.vt == 11 && result.data.boolVal != 0)
    }
}
