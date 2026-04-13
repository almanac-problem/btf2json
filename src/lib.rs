//! Generating ISF files using BTF information.

use crate::btf::{Btf, Typedefs};
use crate::cli::Cli;
use crate::metadata::MetadataBuilder;
use crate::symbols::SymbolsBuilder;

use std::collections::BTreeSet;
use std::convert::TryFrom;

use anyhow::{Error, Result};

pub mod banner;
pub mod btf;
pub mod cli;
pub mod elf;
pub mod image;
pub mod isf;
pub mod kallsyms;
pub mod kaslr;
pub mod metadata;
pub mod symbols;
pub mod utils;
pub mod v_symbols;
pub mod v_types;

/// Information required to generate an ISF file.
pub struct GenerationContext {
    // TODO: Gross...
    mbuilder: Option<MetadataBuilder>,
    btf: Btf,
    // In the end, the underlying types are going to be disambiguated by name.
    // There can be types of the same kind and name, but with different ids.
    // If we use hash sets here the iteration order will not be deterministic,
    // which will lead to randomness in the types that are included in the final
    // ISF file.
    user_ids: BTreeSet<btf::Id>,
    enum_ids: BTreeSet<btf::Id>,
    basic_ids: BTreeSet<btf::Id>,
    symbols: symbols::Symbols,
    typedefs: Typedefs,
}

impl TryFrom<&Cli> for GenerationContext {
    type Error = Error;

    /// Try to gather the required information from the sources given on the
    /// CLI.
    fn try_from(cli: &Cli) -> Result<GenerationContext> {
        let btf = Btf::try_from(cli)?;
        let (user_ids, enum_ids, basic_ids, typedefs) = btf.gen_vol_id_sets()?;
        let symbols = SymbolsBuilder::try_from(cli)?
            .add_types_from_btf(&btf)
            .build();
        Ok(GenerationContext {
            mbuilder: Some(MetadataBuilder::new(&btf, &symbols)),
            btf,
            user_ids,
            enum_ids,
            basic_ids,
            symbols,
            typedefs,
        })
    }
}
