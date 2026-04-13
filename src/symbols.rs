//! Generation of symbol information.

use crate::banner::{Architectures, Banner};
use crate::btf::{Btf, SourceRaw};
use crate::cli::Cli;
use crate::image::raw::RawImage;
use crate::kallsyms::{carve_kallsyms, Kallsyms};
use crate::kaslr::find_kaslr_slide;

use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::iter::{IntoIterator, Iterator};
use std::path::PathBuf;
use std::rc::Rc;
use std::{iter::zip, str};

use anyhow::{bail, Context, Error, Result};
use base64::prelude::*;
use memmap2::Mmap;
use rust_embed::RustEmbed;

/// The embedded symdb.
#[derive(RustEmbed)]
#[folder = "symdb/"]
struct SymDbAssets;

impl SymDbAssets {
    const SYMDB_NAME: &'static str = "dummy.symdb";
}

/// Mapping from symbol names to types.
struct SymDb {
    lines: Vec<(&'static str, &'static str)>,
}

impl SymDb {
    /// Get a reference to the embedded object.
    fn get_raw() -> &'static [u8] {
        let Some(symdb) = SymDbAssets::get(SymDbAssets::SYMDB_NAME) else {
            panic!("BUG: symdb not found.");
        };
        let std::borrow::Cow::Borrowed(data) = symdb.data else {
            panic!("BUG: symdb was not embedded into executable.");
        };

        data
    }

    fn new() -> Self {
        let Ok(symdb) = str::from_utf8(Self::get_raw()) else {
            panic!("BUG: invalid data in symdb.");
        };
        Self {
            lines: symdb
                .lines()
                .map(|l| match l.split_once(' ') {
                    Some((name, t)) => (name, t),
                    _ => panic!("BUG: invalid entry in symdb: {}", l),
                })
                .collect(),
        }
    }
}

impl IntoIterator for SymDb {
    type Item = (&'static str, &'static str);
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.lines.into_iter()
    }
}

/// Symbol information that we have about the kernel.
#[derive(Default)]
pub struct Symbols {
    raw_map: Option<Rc<SourceRaw>>,
    name_map: Option<String>,
    raw_symdb: Option<&'static [u8]>,
    name_symdb: Option<&'static str>,
    symbols: HashMap<String, Symbol>,
}

impl IntoIterator for Symbols {
    type Item = (String, Symbol);
    type IntoIter = std::collections::hash_map::IntoIter<String, Symbol>;

    fn into_iter(self) -> Self::IntoIter {
        self.symbols.into_iter()
    }
}

impl Symbols {
    /// Returns number of symbols that have associated type information.
    fn with_types(&self) -> u64 {
        self.symbols.iter().filter(|(_, s)| s.t.is_some()).count() as u64
    }

    /// Get memory mapping of the System.map that was used to construct these
    /// `Symbols`.
    pub fn raw_map(&self) -> Option<Rc<SourceRaw>> {
        self.raw_map.as_ref().map(|p| p.clone())
    }

    /// Get name of the System.map that was used to construct these `Symbols`.
    pub fn map_name(&self) -> Option<String> {
        self.name_map.clone()
    }

    /// Returns pointer to the embedded symdb.
    pub fn raw_symdb(&self) -> Option<&'static [u8]> {
        self.raw_symdb
    }

    /// Returns pointer to the name of the embedded symdb.
    pub fn symdb_name(&self) -> Option<&'static str> {
        self.name_symdb
    }
}

enum SymbolScope {
    Global,
    Local,
}

impl From<&char> for SymbolScope {
    fn from(chr: &char) -> SymbolScope {
        if chr.is_lowercase() {
            SymbolScope::Local
        } else {
            SymbolScope::Global
        }
    }
}

#[allow(non_camel_case_types, dead_code)]
enum SymbolKind {
    V, // weak object
    v,
    A, // absolute
    R, // .rodata
    r,
    W, // weak
    w,
    B, // .bss
    b,
    D, // .data
    d,
    T, // .text
    t,
}

impl TryFrom<&char> for SymbolKind {
    type Error = Error;

    fn try_from(chr: &char) -> Result<Self> {
        Ok(match chr {
            'V' | 'v' => SymbolKind::V,
            'A' | 'a' => SymbolKind::A,
            'R' | 'r' => SymbolKind::R,
            'W' | 'w' => SymbolKind::W,
            'B' | 'b' => SymbolKind::B,
            'D' | 'd' => SymbolKind::D,
            'T' | 't' => SymbolKind::T,
            _ => {
                log::warn!("{} is not a valid symbol kind.", chr);
                bail!("{} is not a valid symbol kind.", chr)
            }
        })
    }
}

/// Information about a single symbol.
#[allow(dead_code)]
pub struct Symbol {
    addr: u64,
    t: Option<String>,
    kind: SymbolKind,
    scope: SymbolScope,
    constant_data: Option<String>,
}

impl Symbol {
    pub fn r#type(&self) -> Option<&String> {
        self.t.as_ref()
    }

    pub fn address(&self) -> u64 {
        self.addr
    }

    pub fn constant_data(&mut self) -> Option<String> {
        self.constant_data.take()
    }
}

/// Used to build up symbol information by combining different sources.
pub struct SymbolsBuilder(Symbols);

impl SymbolsBuilder {
    fn new() -> Self {
        Self(Symbols::default())
    }

    pub fn build(self) -> Symbols {
        self.0
    }

    /// Add symbol information from a System.map file.
    fn add_from_system_map(mut self, map: &PathBuf) -> Result<Self> {
        let mut system_map_symbols: HashMap<String, Symbol> = HashMap::new();
        // Names are not suitable to disambiguate symbols. ISF nevertheless does
        // just that. If a symbol name appears more than once we ignore it all
        // together.
        let mut ambiguous_names: HashSet<String> = HashSet::new();

        for line in BufReader::new(File::open(map)?).lines() {
            let Ok(line) = line else {
                bail!("Error while reading system map: {}", line.unwrap_err())
            };
            match line.split(' ').collect::<Vec<&str>>()[..] {
                [addr, scope, name] => {
                    if ambiguous_names.contains(name) {
                        continue;
                    }
                    if system_map_symbols.contains_key(name) {
                        system_map_symbols.remove(name);
                        ambiguous_names.insert(String::from(name));
                        log::trace!("Symbol name {} is ambiguous, dropping.", name);
                        continue;
                    }
                    let Some(scope) = scope.chars().next() else {
                        bail!("Invalid scope in system map: {}", scope)
                    };
                    let Ok(addr) = u64::from_str_radix(addr, 16) else {
                        bail!("Invalid address in system map: {}", addr)
                    };
                    system_map_symbols.insert(
                        String::from(name),
                        Symbol {
                            addr,
                            t: None,
                            kind: SymbolKind::try_from(&scope)?,
                            scope: SymbolScope::from(&scope),
                            constant_data: None,
                        },
                    )
                }
                _ => bail!("Invalid format of system map: {}", line),
            };
        }
        self.0.symbols.extend(system_map_symbols);

        // record metadata
        let name_map = String::from(
            map.file_name()
                .context("Path to System.map is invalid")?
                .to_str()
                .context("Unicode error")?,
        );
        let file = File::open(map)?;
        let mmap = unsafe { Mmap::map(&file) }?;
        self.0.raw_map = Some(Rc::new(SourceRaw::Mapped(mmap)));
        self.0.name_map = Some(name_map);

        Ok(self)
    }

    /// Add symbol information from a carved Kallsyms
    fn add_from_kallsyms(mut self, kallsyms: &Kallsyms, kaslr_slide: u64) -> Result<Self> {
        let mut kallsyms_symbols: HashMap<String, Symbol> = HashMap::new();
        // Names are not suitable to disambiguate symbols. ISF nevertheless does
        // just that. If a symbol name appears more than once we ignore it all
        // together.
        let mut ambiguous_names: HashSet<String> = HashSet::new();

        for (runtime_addr, sym_name_with_scope) in
            zip(&kallsyms.symbol_offsets, &kallsyms.symbol_names)
        {
            // Adjust address for kaslr and extract scope from symbol name
            let addr = runtime_addr - kaslr_slide;
            let mut sym_chars = sym_name_with_scope.chars();
            let Some(scope) = sym_chars.next() else {
                bail!("Invalid symbol name: {}", sym_name_with_scope);
            };
            let name = sym_chars.as_str(); // Iterator is advanced with next(), so this is just the symbol name

            if ambiguous_names.contains(name) {
                continue;
            }
            if kallsyms_symbols.contains_key(name) {
                kallsyms_symbols.remove(name);
                ambiguous_names.insert(String::from(name));
                log::trace!("Symbol name {} is ambiguous, dropping.", name);
                continue;
            }

            kallsyms_symbols.insert(
                String::from(name),
                Symbol {
                    addr,
                    t: None,
                    kind: SymbolKind::try_from(&scope)?,
                    scope: SymbolScope::from(&scope),
                    constant_data: None,
                },
            );
        }

        self.0.symbols.extend(kallsyms_symbols);

        // record metadata
        let name_map = String::from("Carved kallsyms");
        self.0.raw_map = None;
        self.0.name_map = Some(name_map);

        Ok(self)
    }

    /// Add type information from embedded database.
    fn add_types_from_symdb(mut self) -> Self {
        for (name, t) in SymDb::new().into_iter() {
            if let Some(s) = self.0.symbols.get_mut(name) {
                log::trace!("[symdb] name {}, type {}", name, t);
                s.t = Some(String::from(t));
            }
        }

        // Record metadata
        self.0.name_symdb = Some(SymDbAssets::SYMDB_NAME);
        self.0.raw_symdb = Some(SymDb::get_raw());

        self
    }

    /// Add type information from BTF section.
    pub fn add_types_from_btf(self, _btf: &Btf) -> Self {
        log::info!("Types from BTF not implemented.");
        self
    }

    /// Add the base64 encoded banner as payload to the corresponding symbol.
    ///
    /// This is how Volatility expects it.
    fn add_banner_from_cli(mut self, cli: &Cli) -> Result<Self> {
        let banner = Banner::try_from(cli)?;

        log::info!("Found banner: {}", banner);

        let Some(sym) = self.0.symbols.get_mut("linux_banner") else {
            bail!("No symbol entry for Linux banner.")
        };

        sym.constant_data = Some(BASE64_STANDARD.encode(banner));

        Ok(self)
    }
}

impl TryFrom<&Cli> for SymbolsBuilder {
    type Error = Error;

    fn try_from(cli: &Cli) -> Result<SymbolsBuilder> {
        let sym_builder = if cli.map.is_some() {
            log::debug!("Got System.map file for symbol addresses.");
            SymbolsBuilder::new().add_from_system_map(cli.map.as_ref().unwrap())
        } else if cli.image.is_some() {
            log::debug!("Got memory image, extracting symbol information.");

            // TODO: Abstract after other source types are implemented
            let image = RawImage::open(cli.image.as_ref().unwrap())?;
            let kallsyms = carve_kallsyms(&image)?;
            let kaslr_slide = find_kaslr_slide(&image, Architectures::x86_64)?; // TODO: Obviously change this, need to implement an architecture identification process
            SymbolsBuilder::new().add_from_kallsyms(&kallsyms, kaslr_slide)
        } else {
            bail!("No source for symbol information provided.")
        }?;
        let sym_builder = sym_builder
            .add_types_from_symdb()
            .add_banner_from_cli(cli)?;
        log::debug!(
            "Got {} symbols ({} with types)",
            sym_builder.0.symbols.len(),
            sym_builder.0.with_types()
        );

        Ok(sym_builder)
    }
}
