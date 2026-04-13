use std::{error::Error, path::PathBuf};

use btf2json::{
    banner::{banner_scan, Architecture, KernelVersion},
    image::raw::RawImage,
};
use clap::Parser;

#[derive(Parser)]
struct Args {
    #[clap(short, long = "image")]
    pub image: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let raw_image = RawImage::open(&args.image).unwrap();
    let banner = banner_scan(&raw_image).unwrap();
    let _architecture = Architecture::try_from(banner.as_str())?;
    let _kernel_version = KernelVersion::try_from(banner.as_str())?;

    println!("{banner}");
    Ok(())
}
