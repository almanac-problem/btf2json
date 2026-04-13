use anyhow::Result;
use regex::bytes::{Match, Regex};

use crate::btf::Endian;

pub trait MemoryImage: AsRef<[u8]> {
    fn name(&self) -> String;
    fn carve_banner(&self) -> Result<String>;
    fn carve_btf(&self) -> Result<(Endian, Vec<u8>)>;
    fn scan_bytes(&self, needle: &[u8]) -> Vec<usize>;
    fn scan_regex(&self, regex: &Regex) -> Vec<Match>;
}

pub trait ImageRead {
    fn read_until(&self, offset: usize, until: Vec<u8>, max_length: Option<usize>)
        -> Option<&[u8]>;

    fn read_bytes(&self, offset: usize, length: usize) -> Option<&[u8]>;
}

// Backing source should implement Iter and Read?
