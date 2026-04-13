use std::{error::Error, fs::File, io::Write, path::PathBuf};

use btf2json::{btf::carve_btf, image::raw::RawImage};

use clap::Parser;

#[derive(Parser)]
struct Args {
    #[clap(short, long = "image")]
    pub image: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let image = RawImage::open(&args.image)?;
    let (_endian, btf_bytes) = carve_btf(&image)?;
    let mut fout = File::create("./extracted_BTF.bin")?;
    fout.write_all(btf_bytes)?;

    Ok(())
}
