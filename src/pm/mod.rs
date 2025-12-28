pub mod app;
pub mod asyncutil;
pub mod build_info;
pub mod cli;
pub mod config;
pub mod cgroup;
pub mod daemon;
pub mod pmctl_cli;
pub mod web_console;
pub mod rpc;

pub fn main() -> anyhow::Result<()> {
    cli::run()
}


