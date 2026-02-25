#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;
use {
    alloc::{string::String, vec::Vec}, core::{mem::size_of, ptr}
};

#[derive(Debug)]
pub enum CoffError {
    InvalidCoffFile,
    InvalidSectionsOrSymbols,
    SectionLimitExceeded,
    UnsupportedArchitecture,
    InvalidCoffSymbolsFile,
    InvalidCoffSectionFile,
}

const COFF_MACHINE_X64: u16 = 0x8664;
const COFF_MACHINE_X32: u16 = 0x14c;
const MAX_SECTIONS: u16 = 96;

pub struct Coff<'a> {
    pub file_header: IMAGE_FILE_HEADER,
    pub symbols: Vec<IMAGE_SYMBOL>,
    pub sections: Vec<IMAGE_SECTION_HEADER>,
    pub buffer: &'a [u8],
    pub arch: CoffMachine,
}

impl<'a> Default for Coff<'a> {
    fn default() -> Self {
        Self {
            file_header: IMAGE_FILE_HEADER::default(),
            symbols: Vec::new(),
            sections: Vec::new(),
            buffer: &[],
            arch: CoffMachine::X64
        }
    }
}

impl<'a> Coff<'a> {
    pub fn from_buffer(buffer: &'a [u8]) -> Result<Self, CoffError> {
        Self::parse(buffer)
    }

    fn parse(buffer: &'a [u8]) -> Result<Self, CoffError> {
        if buffer.len() < size_of::<IMAGE_FILE_HEADER>() {
            return Err(CoffError::InvalidCoffFile);
        }

        let file_header = IMAGE_FILE_HEADER::from_bytes(&buffer[..size_of::<IMAGE_FILE_HEADER>()])
            .ok_or(CoffError::InvalidCoffFile)?;

        let arch = Self::validate_architecture(file_header)?;

        let num_sections = file_header.NumberOfSections;
        let num_symbols = file_header.NumberOfSymbols;
        if num_sections == 0 || num_symbols == 0 {
            return Err(CoffError::InvalidSectionsOrSymbols);
        }

        if num_sections > MAX_SECTIONS {
            return Err(CoffError::SectionLimitExceeded);
        }

        let mut symbols = Vec::with_capacity(num_symbols as usize);
        let mut symbol_offset = file_header.PointerToSymbolTable as usize;
        
        for _ in 0..num_symbols as usize {
            if let Some(symbol) = IMAGE_SYMBOL::from_bytes(&buffer[symbol_offset..]) {
                symbols.push(symbol);
                symbol_offset += size_of::<IMAGE_SYMBOL>();
            } else {
                return Err(CoffError::InvalidCoffSymbolsFile);
            }
        }

        let mut sections = Vec::with_capacity(num_sections as usize);
        let mut offset = size_of::<IMAGE_FILE_HEADER>();
        
        for _ in 0..num_sections as usize {
            if let Some(section) = IMAGE_SECTION_HEADER::from_bytes(&buffer[offset..]) {
                sections.push(section);
                offset += size_of::<IMAGE_SECTION_HEADER>();
            } else {
                return Err(CoffError::InvalidCoffSectionFile);
            }
        }

        Ok(Self {
            file_header,
            symbols,
            sections,
            buffer,
            arch,
        })
    }

    fn validate_architecture(file_header: IMAGE_FILE_HEADER) -> Result<CoffMachine, CoffError> {
        match file_header.Machine {
            COFF_MACHINE_X64 => Ok(CoffMachine::X64),
            COFF_MACHINE_X32 => Ok(CoffMachine::X32),
            _ => Err(CoffError::UnsupportedArchitecture),
        }
    }

    pub fn size(&self) -> usize {
        let length: usize = self.sections
            .iter()
            .filter(|section| section.SizeOfRawData > 0)
            .map(|section| Self::page_align(section.SizeOfRawData as usize))
            .sum();

        let total_length = self.sections.iter().fold(length, |mut total_length, section| {
            let relocations = self.get_relocations(section);
            relocations.iter().for_each(|relocation| {
                let sym = &self.symbols[relocation.SymbolTableIndex as usize];
                let name = self.get_symbol_name(sym);
                if name.starts_with("_imp") {
                    total_length += size_of::<usize>();
                }
            });
            total_length
        });

        Self::page_align(total_length)
    }

    pub fn get_relocations(&self, section: &IMAGE_SECTION_HEADER) -> Vec<IMAGE_RELOCATION> {
        let mut relocations = Vec::with_capacity(section.NumberOfRelocations as usize);
        let mut offset = section.PointerToRelocations as usize;
        
        for _ in 0..section.NumberOfRelocations {
            if let Some(relocation) = IMAGE_RELOCATION::from_bytes(&self.buffer[offset..]) {
                relocations.push(relocation);
                offset += size_of::<IMAGE_RELOCATION>();
            }
        }
        
        relocations
    }

    pub fn get_symbol_name(&self, symtbl: &IMAGE_SYMBOL) -> String {
        let name = if unsafe { symtbl.N.ShortName[0] } != 0 {
            let short_name = unsafe { &symtbl.N.ShortName };
            String::from_utf8_lossy(short_name).into_owned()
        } else {
            let long_name_offset = unsafe { symtbl.N.Name.Long } as usize;
            let string_table_offset = self.file_header.PointerToSymbolTable as usize
                + self.file_header.NumberOfSymbols as usize * size_of::<IMAGE_SYMBOL>();
            let full_offset = string_table_offset + long_name_offset;

            let mut end = full_offset;
            while end < self.buffer.len() && self.buffer[end] != 0 {
                end += 1;
            }
            
            String::from_utf8_lossy(&self.buffer[full_offset..end]).into_owned()
        };

        String::from(name.trim_end_matches('\0'))
    }

    pub fn page_align(page: usize) -> usize {
        page + ((0x1000 - (page & (0x1000 - 1))) % 0x1000)
    }

    pub fn get_section_name(section: &IMAGE_SECTION_HEADER) -> String {
        String::from(String::from_utf8_lossy(&section.Name)
            .trim_end_matches('\0'))
    }

    pub fn is_fcn(x: u16) -> bool {
        (x & 0x30) == (2 << 4)
    }
}

#[derive(Debug, PartialEq)]
pub enum CoffMachine {
    X64,
    X32
}

pub enum CoffSource<'a> {
    File(&'a str),
    Buffer(&'a [u8]),
}

impl<'a> From<&'a str> for CoffSource<'a> {
    fn from(file: &'a str) -> Self {
        CoffSource::File(file)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for CoffSource<'a> {
    fn from(buffer: &'a [u8; N]) -> Self {
        CoffSource::Buffer(buffer)
    }
}

impl<'a> From<&'a [u8]> for CoffSource<'a> {
    fn from(buffer: &'a [u8]) -> Self {
        CoffSource::Buffer(buffer)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

impl IMAGE_FILE_HEADER {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < size_of::<Self>() {
            return None;
        }
        
        let ptr = bytes.as_ptr() as *const Self;
        Some(unsafe { ptr::read_unaligned(ptr) })
    }
}

impl Default for IMAGE_FILE_HEADER {
    fn default() -> Self {
        Self {
            Machine: 0,
            NumberOfSections: 0,
            TimeDateStamp: 0,
            PointerToSymbolTable: 0,
            NumberOfSymbols: 0,
            SizeOfOptionalHeader: 0,
            Characteristics: 0,
        }
    }
}

#[repr(C, packed(2))]
#[derive(Clone, Copy)]
pub struct IMAGE_SYMBOL {
    pub N: IMAGE_SYMBOL_0,
    pub Value: u32,
    pub SectionNumber: i16,
    pub Type: u16,
    pub StorageClass: u8,
    pub NumberOfAuxSymbols: u8,
}

impl IMAGE_SYMBOL {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < size_of::<Self>() {
            return None;
        }
        
        let ptr = bytes.as_ptr() as *const Self;
        Some(unsafe { ptr::read_unaligned(ptr) })
    }
}

#[repr(C, packed(2))]
#[derive(Clone, Copy)]
pub union IMAGE_SYMBOL_0 {
    pub ShortName: [u8; 8],
    pub Name: IMAGE_SYMBOL_0_0,
    pub LongName: [u32; 2],
}

#[repr(C, packed(2))]
#[derive(Clone, Copy)]
pub struct IMAGE_SYMBOL_0_0 {
    pub Short: u32,
    pub Long: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub Misc: IMAGE_SECTION_HEADER_0,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}

impl IMAGE_SECTION_HEADER {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < size_of::<Self>() {
            return None;
        }
        
        let ptr = bytes.as_ptr() as *const Self;
        Some(unsafe { ptr::read_unaligned(ptr) })
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union IMAGE_SECTION_HEADER_0 {
    pub PhysicalAddress: u32,
    pub VirtualSize: u32,
}

#[repr(C, packed(2))]
pub struct IMAGE_RELOCATION {
    pub Anonymous: IMAGE_RELOCATION_0,
    pub SymbolTableIndex: u32,
    pub Type: u16,
}

impl IMAGE_RELOCATION {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < size_of::<Self>() {
            return None;
        }
        
        let ptr = bytes.as_ptr() as *const Self;
        Some(unsafe { ptr::read_unaligned(ptr) })
    }
}

#[repr(C, packed(2))]
pub union IMAGE_RELOCATION_0 {
    pub VirtualAddress: u32,
    pub RelocCount: u32,
}