use clap::Parser;
use std::process::exit;

use btf2json::cli::Cli;
use btf2json::isf::Isf;
use btf2json::GenerationContext;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let cli = Cli::parse();

    env_logger::Builder::new()
        .filter_level(if cli.debug {
            log::LevelFilter::Trace
        } else if cli.verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Error
        })
        .init();

    if cli.version {
        println!("v{}", VERSION);
        return;
    }

    let ctx = match GenerationContext::try_from(&cli) {
        Ok(ctx) => ctx,
        Err(err) => {
            println!("Unable to gather information for ISF generation: {}", err);
            exit(1);
        }
    };
    match Isf::try_from(ctx) {
        Ok(mut isf) => {
            // We do not fail if types are broken.
            let _ = isf.fix_symbol_types();
            if cfg!(debug_assertions) {
                let _ = isf.check_user_types();
            }
            isf.dump_stdout()
        }
        Err(err) => {
            println!("Unable to generate ISF file: {}", err);
            exit(1);
        }
    }
}
