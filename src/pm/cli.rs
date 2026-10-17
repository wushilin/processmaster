use clap::Parser;
use std::path::PathBuf;

/// Command line of the `processmaster` daemon. Everything else is done through `pmctl`.
#[derive(Debug, Parser)]
#[command(name = "processmaster", version, about = "processmaster supervisor")]
pub struct Args {
    /// Path to master config YAML
    #[arg(short = 'c', long = "config", default_value = "config.yaml")]
    pub config: PathBuf,
}
