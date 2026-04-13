use std::fs::File;
use std::path::Path;
use std::sync::LazyLock;

use anyhow::{bail, Context, Error, Result};
use memmap2::Mmap;

use crate::elf;
use crate::image::raw::RawImage;
use crate::utils::most_common;
use crate::{
    btf::Endian,
    cli::Cli,
    image::traits::{ImageRead, MemoryImage},
};

pub static BANNER_REGEX: LazyLock<regex::bytes::Regex> = LazyLock::new(|| {
    regex::bytes::Regex::new(r"Linux version [0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}").unwrap()
});

pub static BITNESS_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"itanium|(?:amd|aarch|ia|arm|x86_|\D-)64").unwrap());

pub fn banner_scan<I: MemoryImage + ImageRead>(image: &I) -> Option<String> {
    let matches = image.scan_regex(&BANNER_REGEX);
    let banner_offsets = matches.iter().map(|m| m.start()).collect::<Vec<usize>>();

    let mut banners = vec![];

    for offset in banner_offsets {
        if let Some(banner) = image.read_until(offset, vec![0x00 as u8, 0x0a as u8], None) {
            let banner_string = match String::from_utf8(banner.to_vec()) {
                Ok(b) => b,
                Err(_) => continue,
            };

            banners.push(banner_string);
        }
    }

    if banners.len() == 0 {
        return None;
    }

    most_common(banners)
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum Architectures {
    aarch64,
    arcompact,
    armle,
    armbe,
    mipsle,
    mipsbe,
    mips64be,
    mips64le,
    powerpcbe,
    powerpcle,
    sparc,
    superhbe,
    superhle,
    riscv,
    x86,
    x86_64,
}

#[derive(Debug)]
pub struct Architecture {
    pub architecture: Architectures,
    pub is_64_bit: bool,
    pub endian: Endian,
}

impl TryFrom<&str> for Architecture {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let architecture = Architectures::x86_64; // TODO
        let is_64_bit = BITNESS_REGEX.is_match(value);
        let endian = Endian::Little; // TODO

        Ok(Architecture {
            architecture,
            is_64_bit,
            endian,
        })
    }
}

#[derive(Debug)]
pub struct KernelVersion {
    pub major: u8,
    pub minor: u8,
    pub banner_string: String,
}

impl TryFrom<&str> for KernelVersion {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let numerical_version = value
            .split(" ")
            .nth(2)
            .context("Unable to derive kernel version from banner")?;

        let major = numerical_version
            .split(".")
            .nth(0)
            .context("Unable to derive kernel version from banner")?
            .parse::<u8>()?;

        let minor = numerical_version
            .split(".")
            .nth(1)
            .context("Unable to derive kernel version from banner")?
            .parse::<u8>()?;

        Ok(KernelVersion {
            major,
            minor,
            banner_string: value.to_string(),
        })
    }
}

/// Linux banner.
pub struct Banner(String);

impl std::fmt::Display for Banner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<[u8]> for Banner {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Banner {
    fn from_btfsec(raw: &[u8]) -> Result<Self> {
        elf::is_elf(raw)?;
        let banner = elf::get_banner(raw)?;

        Ok(Banner(banner))
    }
}

impl TryFrom<&Cli> for Banner {
    type Error = Error;

    fn try_from(cli: &Cli) -> Result<Banner> {
        if cli.banner.is_some() {
            return Ok(Banner(cli.banner.as_ref().unwrap().to_owned()));
        };

        if cli.btf.is_some() {
            let file_path: &Path = Path::new(cli.btf.as_ref().unwrap());
            let file = File::open(file_path)?;
            let mmap = unsafe { Mmap::map(&file)? };

            let banner = Banner::from_btfsec(&mmap);

            if banner.is_ok() {
                return banner;
            }
        };

        if cli.image.is_some() {
            let image = RawImage::open(cli.image.as_ref().unwrap())?;
            if let Some(banner) = banner_scan(&image) {
                return Ok(Banner(banner));
            }
        }

        bail!("Unable to find Linux banner.")
    }
}
