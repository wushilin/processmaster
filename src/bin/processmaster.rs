use clap::Parser;
use nix::unistd::geteuid;

fn main() -> anyhow::Result<()> {
    let args = processmaster::pm::cli::Args::parse();
    // Fail fast: processmaster daemon must run as root.
    if !geteuid().is_root() {
        anyhow::bail!("processmaster daemon is not running as root; please start it as root");
    }
    let cfg = processmaster::pm::config::load_master_config(&args.config)?;
    processmaster::pm::daemon::run_daemon(&cfg)
}


