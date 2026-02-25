use alloc::boxed::Box;
use core::error::Error;

use alloc::vec::Vec;

pub struct BeaconPack {
    pub buffer: Vec<u8>,
    pub size: u32,
}

impl BeaconPack {
    /// `new` returns a new `BeaconPack`
    pub fn new() -> BeaconPack {
        BeaconPack {
            buffer: Vec::new(),
            size: 0,
        }
    }

    /// `get_buffer` returns the buffer with the size prepended
    pub fn get_buffer(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut result = Vec::new();
        result.extend_from_slice(&(self.size).to_le_bytes());
        result.extend(&self.buffer);
        Ok(result)
    }

    /// `add_short` adds a short to the buffer
    pub fn add_short(&mut self, short: i16) -> Result<(), Box<dyn Error>> {
        self.buffer.extend_from_slice(&short.to_le_bytes());
        self.size += 2;
        Ok(())
    }

    /// `add_int` adds an int to the buffer
    pub fn add_int(&mut self, int: i32) -> Result<(), Box<dyn Error>> {
        self.buffer.extend_from_slice(&int.to_le_bytes());
        self.size += 4;
        Ok(())
    }

    /// `add_str` adds a string to the buffer
    pub fn add_str(&mut self, str: &str) -> Result<(), Box<dyn Error>> {
        let s_bytes = str.as_bytes();
        let len = (s_bytes.len() + 1) as u32;
        self.buffer.extend_from_slice(&len.to_le_bytes());
        self.buffer.extend_from_slice(s_bytes);
        self.buffer.push(0);
        self.size += len + 4;

        Ok(())
    }

    /// `add_wstr` adds a wide string to the buffer
    pub fn add_wstr(&mut self, wstr: &str) -> Result<(), Box<dyn Error>> {
        let s_bytes = wstr.encode_utf16().collect::<Vec<u16>>();
        let len = (s_bytes.len() as u32 * 2) + 2;

        self.buffer.extend_from_slice(&len.to_le_bytes());

        for c in &s_bytes {
            self.buffer.extend_from_slice(&c.to_le_bytes());
        }
        self.buffer.extend_from_slice(&0u16.to_le_bytes()); // Ensure proper UTF-16 null-termination
        self.size += len + 4;
        Ok(())
    }

    /// `add_bin` adds binary data to the buffer
    pub fn add_bin(&mut self, bin: &[u8]) -> Result<(), Box<dyn Error>> {
        self.buffer.extend_from_slice(&bin.len().to_le_bytes());
        self.buffer.extend_from_slice(bin);
        self.size += (bin.len() as u32) + 4;
        Ok(())
    }
}

impl Default for BeaconPack {
    fn default() -> Self {
        Self::new()
    }
}
