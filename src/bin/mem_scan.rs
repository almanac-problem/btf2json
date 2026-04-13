use std::{error::Error, path::PathBuf};

use btf2json::image::{raw::RawImage, traits::MemoryImage};

use clap::Parser;
use log::info;
use regex::bytes::Regex;

#[derive(Parser)]
struct Args {
    #[clap(short, long = "image")]
    pub image: PathBuf,

    #[clap(short, long = "pattern")]
    pub pattern: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let pattern_string = format!(r#"{}"#, args.pattern);
    let search_regex = Regex::new(&pattern_string)?;
    let raw_image = RawImage::open(&args.image)?;

    let matches = raw_image.scan_regex(&search_regex);

    for m in matches {
        info!("{} - {}", m.start(), m.len());
    }

    Ok(())
}
