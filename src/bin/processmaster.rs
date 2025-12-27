use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = processmaster::pm::cli::Args::parse();
    let cfg = processmaster::pm::config::load_master_config(&args.config)?;
    // processmaster is daemon-only: ignore subcommands (pmctl is for that).
    processmaster::pm::daemon::run_daemon_async(cfg).await
}


