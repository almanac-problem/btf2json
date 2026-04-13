use std::sync::LazyLock;

use anyhow::{bail, Context, Result};
use log::warn;
use regex::bytes::Regex;

use crate::{banner::Architectures, image::traits::MemoryImage};

static KERNELOFFSET_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"KERNELOFFSET=([a-fA-F0-9]+)\x0A").unwrap());

// TODO: Implement alternative strategies for other architectures
pub fn find_kaslr_slide<I: MemoryImage>(image: &I, architecture: Architectures) -> Result<u64> {
    match architecture {
        Architectures::aarch64 | Architectures::x86_64 => find_kaslr_via_vmcoreinfo(image),
        Architectures::armbe
        | Architectures::armle
        | Architectures::superhbe
        | Architectures::superhle
        | Architectures::sparc => Ok(0),
        _ => bail!("Error finding KASLR - Unsupported architecture"),
    }
}

// Currently, this strategy will only work for x86_64 and ARM64
// https://www.kernel.org/doc/html/latest/admin-guide/kdump/vmcoreinfo.html#kerneloffset
fn find_kaslr_via_vmcoreinfo<I: MemoryImage>(image: &I) -> Result<u64> {
    let matches = image.scan_regex(&KERNELOFFSET_REGEX);

    if matches.is_empty() {
        bail!("Unable to identify KASLR via VMCOREINFO/KERNELOFFSET");
    }

    // For each match, read it to see if all values are the same
    let mut kaslr_slides = vec![];
    for m in matches {
        let match_string = String::from_utf8_lossy(m.as_bytes());
        let (_, kernel_offset_hex_str) = match_string
            .split_once("=")
            .context("Format of VMCOREINFO/KERNELOFFSET incorrect, no equals sign")?;

        let kaslr_slide: u64 = u64::from_str_radix(kernel_offset_hex_str.trim(), 16)?;
        kaslr_slides.push(kaslr_slide);
    }

    // Return appropriate values
    if kaslr_slides.is_empty() {
        warn!("No identified VMCOREINFO/KERNELOFFSETs. KASLR slide was set to zero. If not functional, consider running in verbose mode (-v) to investigate");
        return Ok(0);
    } else if kaslr_slides.windows(2).all(|w| w[0] == w[1]) {
        return Ok(kaslr_slides.first().unwrap().to_owned());
    } else {
        warn!("Found multiple potential VMCOREINFO/KERNELOFFSETs, using first - Run with verbose mode (-v) to get offsets");
        return Ok(kaslr_slides.first().unwrap().to_owned());
    }
}
