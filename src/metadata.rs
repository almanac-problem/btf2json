//! ISF Metadata.

use crate::btf::{Btf, SourceRaw};
use crate::symbols::Symbols;

use std::convert::From;
use std::rc::Rc;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use serde::Serialize;

/// Representation of the ISF metadata object.
#[derive(Serialize)]
pub struct Metadata {
    producer: &'static Producer,
    format: &'static Format,
    linux: Linux,
}

impl From<MetadataBuilder> for Metadata {
    fn from(builder: MetadataBuilder) -> Self {
        Self {
            producer: &PRODUCER,
            format: &FORMAT,
            linux: Linux::from(builder),
        }
    }
}

/// Metadata for a component of the ISF file.
///
/// We provide metadata for the BTF file, System.map, and symdb used to generate
/// the profile.
#[derive(Debug)]
struct CompMeta<T, U, const K: u32> {
    raw: T,
    name: U,
}

impl<T, U, const K: u32> CompMeta<T, U, K> {
    fn new(raw: T, name: U) -> Self {
        Self { raw, name }
    }

    fn try_new(raw: Option<T>, name: Option<U>) -> Option<Self> {
        if let (Some(raw), Some(name)) = (raw, name) {
            Some(Self { raw, name })
        } else {
            None
        }
    }
}

type BtfMeta = CompMeta<Rc<SourceRaw>, String, { SourceKind::Btf as u32 }>;
type MapMeta = CompMeta<Rc<SourceRaw>, String, { SourceKind::SystemMap as u32 }>;
type SymDbMeta = CompMeta<&'static [u8], &'static str, { SourceKind::Symdb as u32 }>;

/// Builder for [`Metadata`].
#[derive(Debug)]
pub struct MetadataBuilder {
    btf: BtfMeta,
    map: Option<MapMeta>,
    symdb: Option<SymDbMeta>,
}

impl MetadataBuilder {
    pub fn build(self) -> Metadata {
        self.into()
    }

    pub fn new(btf: &Btf, syms: &Symbols) -> Self {
        Self {
            btf: BtfMeta::new(btf.raw().clone(), btf.name().clone()),
            map: MapMeta::try_new(syms.raw_map(), syms.map_name()),
            symdb: SymDbMeta::try_new(syms.raw_symdb(), syms.symdb_name()),
        }
    }
}

/// Metadata about the tool that produced the ISF file.
#[derive(Serialize)]
struct Producer {
    name: &'static str,
    version: &'static str,
}

const PRODUCER_NAME: &str = env!("CARGO_CRATE_NAME");
const PRODUCER_VERSION: &str = env!("CARGO_PKG_VERSION");
const PRODUCER: Producer = Producer {
    name: PRODUCER_NAME,
    version: PRODUCER_VERSION,
};

/// ISF file format version.
#[derive(Serialize)]
struct Format(&'static str);

const FORMAT_VERSION: &str = "6.2.0";
const FORMAT: Format = Format(FORMAT_VERSION);

/// Metadata for Linux profiles.
///
/// Sources used to generate the contained type and symbol information.
#[derive(Serialize)]
struct Linux {
    symbols: Vec<Symbol>,
    types: Vec<Type>,
}

impl From<MetadataBuilder> for Linux {
    fn from(ctx: MetadataBuilder) -> Self {
        let types = vec![ctx.btf.into()];
        let mut symbols = Vec::new();

        if let Some(map) = ctx.map {
            symbols.push(map.into());
        }

        if let Some(symdb) = ctx.symdb {
            symbols.push(symdb.into());
        }

        Self { types, symbols }
    }
}

type Symbol = Source;
type Type = Source;

/// Sources that can be used to generate (parts of) components of an ISF file.
#[derive(Serialize)]
enum SourceKind {
    #[serde(rename = "symdb")]
    Symdb,
    #[serde(rename = "btf")]
    Btf,
    #[serde(rename = "system-map")]
    SystemMap,
}

impl SourceKind {
    // Hack to use const generics to encode enum variants.
    const fn from_u32(desc: u32) -> Self {
        if desc == Self::Symdb as u32 {
            Self::Symdb
        } else if desc == Self::Btf as u32 {
            Self::Btf
        } else if desc == Self::SystemMap as u32 {
            Self::SystemMap
        } else {
            panic!("BUG")
        }
    }
}

/// Metadata for a concrete source used to generate (part of) a component of an
/// ISF file.
#[derive(Serialize)]
struct Source {
    kind: SourceKind,
    name: String,
    hash_type: &'static str,
    hash_value: String,
}

// TODO: Remove duplication.
impl<T: AsRef<[u8]>, U: ToString, const K: u32> From<CompMeta<Rc<T>, U, K>> for Source {
    fn from(meta: CompMeta<Rc<T>, U, K>) -> Self {
        let mut hash = Sha256::new();
        hash.input(meta.raw.as_ref().as_ref());
        Self {
            kind: SourceKind::from_u32(K),
            name: meta.name.to_string(),
            hash_type: "sha256",
            hash_value: hash.result_str(),
        }
    }
}

impl<U: ToString, const K: u32> From<CompMeta<&[u8], U, K>> for Source {
    fn from(meta: CompMeta<&[u8], U, K>) -> Self {
        let mut hash = Sha256::new();
        hash.input(meta.raw);
        Self {
            kind: SourceKind::from_u32(K),
            name: meta.name.to_string(),
            hash_type: "sha256",
            hash_value: hash.result_str(),
        }
    }
}
