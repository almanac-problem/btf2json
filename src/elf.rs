//! Utilities for working with ELF files.

use crate::btf::Endian;

use anyhow::{bail, Context, Result};
use goblin::elf::Elf;

const ELF_MAGIC_LE: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];
const ELF_MAGIC_BE: [u8; 4] = [0x46, 0x4c, 0x45, 0x7f];

const BTF_SEC_NAME: &str = ".BTF";

/// Determines whether buffer is an ELF file, and, if yes, its endianness.
// TODO: Wrong use of Result type?
pub fn is_elf(raw: &[u8]) -> Result<Endian> {
    if raw[..4] == ELF_MAGIC_LE {
        Ok(Endian::Little)
    } else if raw[..4] == ELF_MAGIC_BE {
        Ok(Endian::Big)
    } else {
        bail!("Not an ELF file.")
    }
}

pub fn get_size(elf: &Elf) -> Result<u64> {
    let ehdr = elf.header;
    let mut size: u64 = 0;

    if ehdr.e_shoff > 0 {
        size = ehdr.e_shoff + (ehdr.e_shentsize as u64 * ehdr.e_shnum as u64);
    }

    if ehdr.e_phoff > 0 {
        let max_ph: u64 = elf
            .program_headers
            .iter()
            .map(|ph| ph.p_offset + ph.p_filesz)
            .max()
            .context("Error while iterating ELF program headers")?;

        if max_ph > size {
            size = max_ph;
        }
    }

    Ok(size)
}

/// Returns the `.BTF` section of the ELF file.
pub fn extract_btfsec(raw: &[u8]) -> Result<&[u8]> {
    let elf = Elf::parse(raw)?;
    for shdr in elf.section_headers.iter() {
        let Some(sec_name) = elf.shdr_strtab.get_at(shdr.sh_name) else {
            log::debug!("Unable to get name for section: {}", shdr.sh_name);
            continue;
        };
        log::trace!("Checking section: {}", sec_name);
        if sec_name != BTF_SEC_NAME {
            continue;
        }
        return Ok(&raw[shdr.sh_offset as usize..(shdr.sh_offset + shdr.sh_size) as usize]);
    }
    bail!("No {} section in ELF file", BTF_SEC_NAME)
}

/// Returns the Linux banner of the ELF file.
pub fn get_banner(raw: &[u8]) -> Result<String> {
    let elf = Elf::parse(raw)?;
    for sym in elf.syms.iter() {
        let Some(sym_name) = elf.strtab.get_at(sym.st_name) else {
            log::debug!("Unable to get name for symbol: {}", sym.st_name);
            continue;
        };

        if sym_name != "linux_banner" {
            continue;
        }

        let sh_hdr = elf
            .section_headers
            .get(sym.st_shndx)
            .context("Banner is in non-existent section.")?;
        let offset = sym.st_value - sh_hdr.sh_addr;
        let name_start = (sh_hdr.sh_offset + offset) as usize;
        let name_end = name_start + sym.st_size as usize;

        log::debug!(
            "Found Linux banner: sec {}, off {}, size {}",
            sym.st_shndx,
            offset,
            sym.st_size
        );

        return Ok(String::from_utf8(raw[name_start..name_end].to_vec())?);
    }

    bail!("Unable to find Linux banner.")
}
