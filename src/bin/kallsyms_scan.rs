use std::path::PathBuf;

use anyhow::Result;
use btf2json::{
    banner::Architectures, image::raw::RawImage, kallsyms::carve_kallsyms, kaslr::find_kaslr_slide,
};

use clap::Parser;
use log::info;

#[derive(Parser)]
struct Args {
    #[clap(short, long = "image")]
    pub image: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let image = RawImage::open(&args.image)?;

    let kallsyms = carve_kallsyms(&image)?;

    let kaslr_slide = find_kaslr_slide(&image, Architectures::x86_64)?;

    // If this executes, a full structure was found!
    info!(
        "[+] Found kallsyms_token_table at file offset 0x{:x}",
        kallsyms.kallsyms_token_table
    );
    info!(
        "[+] Found kallsyms_token_index at file offset 0x{:x}",
        kallsyms.kallsyms_token_index
    );
    info!(
        "[+] Found kallsyms_markers at file offset 0x{:x}",
        kallsyms.kallsyms_markers
    );
    info!(
        "[+] Found kallsyms_num_syms at file offset 0x{:x}",
        kallsyms.kallsyms_num_syms
    );
    info!(
        "[+] Found kallsyms_names at file offset 0x{:x} ({} symbols)",
        kallsyms.kallsyms_names, kallsyms.num_syms
    );
    info!(
        "[+] Found kallsyms_relative_base at file offset 0x{:x}",
        kallsyms.kallsyms_relative_base
    );
    info!(
        "[+] Found kallsyms_offsets at file offset 0x{:x}",
        kallsyms.kallsyms_offsets
    );

    info!("[+] Found kaslr_slide of 0x{:x}", kaslr_slide);

    Ok(())
}
