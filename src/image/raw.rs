use std::{
    fs::File,
    path::{Path, PathBuf},
    rc::Rc,
};

use crate::image::traits::{ImageRead, MemoryImage};
use anyhow::{bail, Context, Result};
use memchr::memmem::Finder;
use memmap2::Mmap;
use regex::bytes::{Match, Regex};

pub struct RawImage {
    mmap: Rc<Mmap>,
    path: PathBuf,
}

impl RawImage {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).with_context(|| "Failed to open memory image")?;
        let mmap = unsafe { Mmap::map(&file)? };

        Ok(RawImage {
            mmap: Rc::new(mmap),
            path: path.to_owned(),
        })
    }
}

impl MemoryImage for RawImage {
    fn name(&self) -> String {
        match self.path.file_name() {
            Some(f) => f.to_string_lossy().to_string(),
            None => String::from(""),
        }
    }

    fn carve_banner(&self) -> Result<String> {
        bail!("carve_banner unimplemented")
    }

    fn carve_btf(&self) -> Result<(crate::btf::Endian, Vec<u8>)> {
        bail!("carve_btf unimplemented")
    }

    fn scan_bytes(&self, needle: &[u8]) -> Vec<usize> {
        let finder = Finder::new(needle);
        let mut results: Vec<usize> = vec![];

        for offset in finder.find_iter(&self.mmap[..]) {
            results.push(offset);
        }

        results
    }

    fn scan_regex(&self, regex: &Regex) -> Vec<Match> {
        regex.find_iter(&self.mmap).collect()
    }
}

impl AsRef<[u8]> for RawImage {
    fn as_ref(&self) -> &[u8] {
        return &self.mmap;
    }
}

impl ImageRead for RawImage {
    fn read_until(
        &self,
        offset: usize,
        until: Vec<u8>,
        max_length: Option<usize>,
    ) -> Option<&[u8]> {
        let read_max = max_length.unwrap_or(1024);

        let mmap_len = self.mmap.len();
        let start = offset as usize;
        let mut end = offset as usize;
        let max_end = start.saturating_add(read_max);

        while end != mmap_len && end < max_end {
            if until.contains(&self.mmap[end]) {
                break;
            }

            end += 1;
        }

        Some(&self.mmap[start..end])
    }

    fn read_bytes(&self, offset: usize, length: usize) -> Option<&[u8]> {
        let mmap_len = self.mmap.len();
        let start = offset as usize;
        let mut end = start + length;
        if end > mmap_len {
            end = mmap_len
        }

        Some(&self.mmap[start..end])
    }
}
