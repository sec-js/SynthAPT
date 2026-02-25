use alloc::{string::String, vec::Vec};
use core::{
    ffi::{c_ulong, c_void},
    ptr::null_mut,
};

use crate::get_instance;

use super::{
    k32::SecurityAttributes,
    ntdef::{
        nt_current_teb, IoStatusBlock, LargeInteger, ObjectAttributes, UnicodeString, FILE_CREATE,
        FILE_GENERIC_WRITE, FILE_NON_DIRECTORY_FILE, FILE_PIPE_BYTE_STREAM_MODE,
        FILE_PIPE_BYTE_STREAM_TYPE, FILE_PIPE_QUEUE_OPERATION, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_SYNCHRONOUS_IO_NONALERT, FILE_WRITE_ATTRIBUTES, GENERIC_READ, OBJ_CASE_INSENSITIVE,
        OBJ_INHERIT, SYNCHRONIZE,
    },
    utils::format_named_pipe_string,
};

/// Creates a named pipe and returns handles for reading and writing.
///
/// This function sets up a named pipe with specified security attributes, buffer size,
/// and other options. It creates the pipe with both read and write handles, making it
/// ready for inter-process communication using the `NtCreateNamedPipeFile` NT API function.
pub unsafe fn nt_create_named_pipe_file(
    h_read_pipe: &mut *mut c_void,
    h_write_pipe: &mut *mut c_void,
    lp_pipe_attributes: *mut SecurityAttributes,
    n_size: u32,
    pipe_id: u32,
) -> i32 {
    let mut pipe_name: UnicodeString = UnicodeString::new();
    let mut object_attributes: ObjectAttributes = ObjectAttributes::new();
    let mut status_block: IoStatusBlock = IoStatusBlock::new();
    let mut default_timeout: LargeInteger = LargeInteger::new();
    let mut read_pipe_handle: *mut c_void = null_mut();
    let mut write_pipe_handle: *mut c_void = null_mut();
    let mut security_descriptor: *mut c_void = null_mut();

    // Set the default timeout to 120 seconds
    default_timeout.high_part = -1200000000;

    // Use the default buffer size if not provided
    let n_size = if n_size == 0 { 0x1000 } else { n_size };

    // Format the pipe name using the process ID and pipe ID
    let pipe_name_utf16 = format_named_pipe_string(
        nt_current_teb().as_ref().unwrap().client_id.unique_process as usize,
        pipe_id,
    );

    // Initialize the `UnicodeString` with the formatted pipe name
    pipe_name.init(pipe_name_utf16.as_ptr());

    // Use case-insensitive object attributes by default
    let mut attributes: c_ulong = OBJ_CASE_INSENSITIVE;

    // Check if custom security attributes were provided
    if !lp_pipe_attributes.is_null() {
        // Use the provided security descriptor
        security_descriptor = (*lp_pipe_attributes).lp_security_descriptor;

        // Set the OBJ_INHERIT flag if handle inheritance is requested
        if (*lp_pipe_attributes).b_inherit_handle {
            attributes |= OBJ_INHERIT;
        }
    }

    // Initialize the object attributes for the named pipe
    ObjectAttributes::initialize(
        &mut object_attributes,
        &mut pipe_name,
        attributes, // Case-insensitive and possibly inheritable
        null_mut(),
        security_descriptor,
    );

    // Create the named pipe for reading
    let status = get_instance().unwrap().ntdll.nt_create_named_pipe.run(
        &mut read_pipe_handle,
        (GENERIC_READ | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE).into(), // Desired access: read, write attributes, sync
        &mut object_attributes,
        &mut status_block,
        FILE_SHARE_READ | FILE_SHARE_WRITE, // Share mode: allows read/write by other processes
        FILE_CREATE.into(),                        // Creation disposition: create new, fail if exists
        FILE_SYNCHRONOUS_IO_NONALERT.into(),       // Create options: synchronous I/O, no alerts
        FILE_PIPE_BYTE_STREAM_TYPE.into(),         // Pipe type: byte stream (no message boundaries)
        FILE_PIPE_BYTE_STREAM_MODE.into(),         // Read mode: byte stream mode for reading
        FILE_PIPE_QUEUE_OPERATION.into(),          // Completion mode: operations are queued
        1,                                  // Max instances: only one instance of the pipe
        n_size.into(),                             // Inbound quota: input buffer size
        n_size.into(),                             // Outbound quota: output buffer size
        &default_timeout,                   // Default timeout for pipe operations
    );

    // Check if the pipe creation failed
    if status != 0 {
        get_instance().unwrap().ntdll.nt_close.run(read_pipe_handle);
        return status;
    }

    let mut status_block_2 = IoStatusBlock::new();

    // Open the pipe for writing
    let status = get_instance().unwrap().ntdll.nt_open_file.run(
        &mut write_pipe_handle,
        FILE_GENERIC_WRITE.into(),
        &mut object_attributes,
        &mut status_block_2,
        FILE_SHARE_READ,
        (FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE).into(),
    );

    // Check if the pipe opening failed
    if status != 0 {
        get_instance().unwrap().ntdll.nt_close.run(read_pipe_handle);
        return status;
    }

    // Assign the read and write handles to the output parameters
    *h_read_pipe = read_pipe_handle;
    *h_write_pipe = write_pipe_handle;
    0
}

/// Creates a named pipe server (read-only) for client connection.
///
/// This only creates the server/read end of the pipe, leaving it in "listening" state.
/// The client (child process) must connect via CreateFile/redirect_stdout.
pub unsafe fn nt_create_named_pipe_server(
    h_read_pipe: &mut *mut c_void,
    name: &str,
) -> i32 {
    let mut pipe_name: UnicodeString = UnicodeString::new();
    let mut object_attributes: ObjectAttributes = ObjectAttributes::new();
    let mut status_block: IoStatusBlock = IoStatusBlock::new();
    let mut default_timeout: LargeInteger = LargeInteger::new();
    let mut read_pipe_handle: *mut c_void = null_mut();

    // Set the default timeout to 120 seconds
    default_timeout.high_part = -1200000000;

    let n_size: u32 = 0x1000;

    // Format the pipe name: \Device\NamedPipe\{name}
    let mut pipe_path = String::from("\\Device\\NamedPipe\\");
    pipe_path.push_str(name);
    let pipe_name_utf16: Vec<u16> = pipe_path.encode_utf16().chain(Some(0)).collect();

    pipe_name.init(pipe_name_utf16.as_ptr());

    ObjectAttributes::initialize(
        &mut object_attributes,
        &mut pipe_name,
        OBJ_CASE_INSENSITIVE,
        null_mut(),
        null_mut(),
    );

    // Create the named pipe server (read-only)
    let status = get_instance().unwrap().ntdll.nt_create_named_pipe.run(
        &mut read_pipe_handle,
        (GENERIC_READ | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE).into(),
        &mut object_attributes,
        &mut status_block,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_CREATE.into(),
        FILE_SYNCHRONOUS_IO_NONALERT.into(),
        FILE_PIPE_BYTE_STREAM_TYPE.into(),
        FILE_PIPE_BYTE_STREAM_MODE.into(),
        FILE_PIPE_QUEUE_OPERATION.into(),
        1,
        n_size.into(),
        n_size.into(),
        &default_timeout,
    );

    if status == 0 {
        *h_read_pipe = read_pipe_handle;
    }
    status
}

/// Creates an anonymous pipe using kernel32 CreatePipe.
///
/// This creates a true anonymous pipe (not a named pipe with an auto-generated name).
/// Use this when PPID spoofing is not needed.
pub unsafe fn create_anonymous_pipe(
    h_read_pipe: *mut *mut c_void,
    h_write_pipe: *mut *mut c_void,
    lp_pipe_attributes: *const SecurityAttributes,
    n_size: u32,
) -> bool {
    (get_instance().unwrap().k32.create_pipe)(
        h_read_pipe,
        h_write_pipe,
        lp_pipe_attributes,
        n_size,
    )
}
