use alloc::string::String;
use alloc::vec::Vec;

use crate::libs::coffee::beacon_pack::BeaconPack;
use crate::libs::coffee::loader::CoffeeLdrError;
use crate::libs::coffee::parser::CoffSource;
use crate::libs::utils::decode_base64;
use crate::libs::{coffee::loader::CoffeeLdr, utils::write_output};

pub fn run_bof<'a, T>(bof_source: T, entry: &str, inputs: &str) -> String
where
    T: Into<CoffSource<'a>>,
{
    let coffee = CoffeeLdr::new(bof_source.into()).unwrap();

    let mut pack = BeaconPack::default();
    for input in split_args(inputs) {
        process_input(&input, &mut pack);
    }

    let mut buffer = pack.get_buffer().unwrap();

    match coffee.run(entry, Some(buffer.as_mut_ptr()), Some(buffer.len())) {
        Ok(result) => {
            //write_output(result.as_bytes());
            return result;
        }
        Err(err_code) => output_error_type(&err_code),
    }
    //todo: fix the error handling
    return String::new();
}

fn output_error_type(error: &CoffeeLdrError) {
    match error {
        CoffeeLdrError::FileReadError(s) => {
            write_output(b"File Read Error: ");
            write_output(s.as_bytes());
        }
        CoffeeLdrError::ParseError(s) => {
            write_output(b"Parse Error: ");
            write_output(s.as_bytes());
        }
        CoffeeLdrError::MemoryAllocationError(code) => {
            write_output(b"Memory Allocation Error: ");
            let buf = num_to_str(*code);
            write_output(&buf[..]);
        }
        CoffeeLdrError::MemoryProtectionError(code) => {
            write_output(b"Memory Protection Error: ");
            let buf = num_to_str(*code);
            write_output(&buf[..]);
        }
        CoffeeLdrError::ModuleNotFound(s) => {
            write_output(b"Module Not Found: ");
            write_output(s.as_bytes());
        }
        CoffeeLdrError::FunctionNotFound(s) => {
            write_output(b"Function Not Found: ");
            write_output(s.as_bytes());
        }
        CoffeeLdrError::FunctionInternalNotFound(s) => {
            write_output(b"Internal Function Not Found: ");
            write_output(s.as_bytes());
        }
        CoffeeLdrError::SymbolIgnored => {
            write_output(b"Symbol Ignored");
        }
        CoffeeLdrError::TooManySymbols(count) => {
            write_output(b"Too Many Symbols");
        }
        CoffeeLdrError::OutputError => {
            write_output(b"Output Error");
        }
        CoffeeLdrError::InvalidRelocationType(typ) => {
            write_output(b"Invalid Relocation Type: ");
        }
        CoffeeLdrError::ArchitectureMismatch { expected, actual } => {
            write_output(b"Architecture Mismatch - Expected: ");
            write_output(expected.as_bytes());
            write_output(b", Found: ");
            write_output(actual.as_bytes());
        }
    }
}

fn num_to_str(mut n: u32) -> [u8; 20] {
    let mut buf = [0u8; 20];
    let mut i = 19;
    if n == 0 {
        buf[i] = b'0';
        return buf;
    }
    while n > 0 {
        i -= 1;
        buf[i] = (n % 10) as u8 + b'0';
        n /= 10;
    }
    buf
}

fn process_input(input: &str, pack: &mut BeaconPack) -> Result<(), &'static str> {
    if input.starts_with("/short:") {
        let short_data = &input[7..];
        match short_data.parse::<i16>() {
            Ok(value) => {
                pack.add_short(value).unwrap();
            }
            Err(e) => return Err("Error converting to short"),
        }
    } else if input.starts_with("/int:") {
        let int_data = &input[5..];
        match int_data.parse::<i32>() {
            Ok(value) => {
                pack.add_int(value).unwrap();
            }
            Err(e) => return Err("Error converting to int"),
        }
    } else if input.starts_with("/str:") {
        let str_data = &input[5..];
        pack.add_str(str_data).unwrap();
    } else if input.starts_with("/wstr:") {
        let wstr_data = &input[6..];
        pack.add_wstr(wstr_data).unwrap();
    } else if input.starts_with("/bin:") {
        let base64_data = &input[5..];
        match decode_base64(base64_data) {
            Ok(decoded) => {
                pack.add_bin(&decoded).unwrap();
            }
            Err(e) => return Err(e),
        }
    } else {
        write_output(b"Invalid input");
        return Err("Invalid input format");
    }

    Ok(())
}

pub fn split_args(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current_arg = String::new();
    let mut in_quotes = false;

    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                // Check for an escaped character
                if let Some(&next) = chars.peek() {
                    if next == '"' {
                        // Consume the escaped quote and add it to the current argument
                        chars.next();
                        current_arg.push('"');
                    } else {
                        // Treat as a normal backslash
                        current_arg.push(c);
                    }
                } else {
                    current_arg.push(c);
                }
            }
            '"' => {
                in_quotes = !in_quotes;
            }
            ' ' if !in_quotes => {
                if !current_arg.is_empty() {
                    //write_output(&current_arg.as_bytes());
                    args.push(current_arg);
                    current_arg = String::new();
                }
            }
            _ => {
                // Add the character to the current argument
                current_arg.push(c);
            }
        }
    }

    // Add the last argument if it's non-empty
    if !current_arg.is_empty() {
        args.push(current_arg);
    }

    args
}
