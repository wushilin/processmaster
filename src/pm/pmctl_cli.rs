use crate::pm::{cli, rpc};
use clap::Parser;
use std::path::PathBuf;
use std::{env, fmt};

#[derive(Debug, Parser)]
#[command(name = "pmctl", version, about = "processmaster control client")]
pub struct PmctlArgs {
    /// Unix socket path to the processmaster daemon
    #[arg(short = 's', long = "sock")]
    pub sock: Option<PathBuf>,

    #[command(subcommand)]
    pub cmd: Option<cli::Cmd>,
}

fn resolve_sock(args: &PmctlArgs) -> anyhow::Result<PathBuf> {
    if let Some(sock) = args.sock.clone() {
        return Ok(sock);
    }
    if let Ok(v) = env::var("PMCTL_SOCK") {
        let t = v.trim();
        if !t.is_empty() {
            return Ok(PathBuf::from(t));
        }
    }

    anyhow::bail!("{}", MissingSockHelp);
}

struct MissingSockHelp;

impl fmt::Display for MissingSockHelp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "no processmaster socket specified")?;
        writeln!(f)?;
        writeln!(f, "pmctl does not read the processmaster config file.")?;
        writeln!(f, "You must provide the daemon unix socket path via one of:")?;
        writeln!(f, "  - pmctl --sock /path/to/processmaster.sock <command>")?;
        writeln!(f, "  - pmctl -s /path/to/processmaster.sock <command>")?;
        writeln!(f, "  - export PMCTL_SOCK=/path/to/processmaster.sock")?;
        writeln!(f)?;
        writeln!(f, "Examples:")?;
        writeln!(f, "  pmctl --sock /tmp/processmaster.sock status")?;
        writeln!(f, "  PMCTL_SOCK=/tmp/processmaster.sock pmctl events -n 200")?;
        writeln!(f)?;
        writeln!(
            f,
            "If you start the daemon with a custom socket, pass the same path here."
        )?;
        Ok(())
    }
}

pub fn run() -> anyhow::Result<()> {
    let args = PmctlArgs::parse();
    let sock = resolve_sock(&args)?;

    let cmd = args.cmd.unwrap_or(cli::Cmd::Status {
        name: None,
        format: cli::OutputFormat::Text,
    });

    match cmd {
        cli::Cmd::Update => {
            let resp = rpc::client_call(&sock, rpc::Request::Update)?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            if !resp.restarted.is_empty() {
                println!("restarted: {}", resp.restarted.join(","));
            }
            Ok(())
        }
        cli::Cmd::Start { name, force } => {
            let resp = rpc::client_call(&sock, rpc::Request::Start { name, force })?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        cli::Cmd::Stop { name } => {
            let resp = rpc::client_call(&sock, rpc::Request::Stop { name })?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        cli::Cmd::Restart { name, force } => {
            let resp = rpc::client_call(&sock, rpc::Request::Restart { name, force })?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        cli::Cmd::Flag { name, flags, ttl } => {
            let flags: Vec<String> = flags
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            anyhow::ensure!(!flags.is_empty(), "no flags provided");
            let resp = rpc::client_call(&sock, rpc::Request::Flag { name, flags, ttl })?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        cli::Cmd::Unflag { name, flags } => {
            let flags: Vec<String> = flags
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            anyhow::ensure!(!flags.is_empty(), "no flags provided");
            let resp = rpc::client_call(&sock, rpc::Request::Unflag { name, flags })?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        cli::Cmd::Enable { name } => {
            let resp = rpc::client_call(&sock, rpc::Request::Enable { name })?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        cli::Cmd::Disable { name } => {
            let resp = rpc::client_call(&sock, rpc::Request::Disable { name })?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        cli::Cmd::Logs { name, n, f } => {
            if f.is_some() {
                let filename = f.and_then(|s| {
                    let t = s.trim().to_string();
                    if t.is_empty() { None } else { Some(t) }
                });
                return rpc::client_follow(
                    &sock,
                    rpc::Request::LogsFollow { name, filename, n },
                    |line| {
                        println!("{line}");
                    },
                );
            }

            let Some(name) = name else {
                anyhow::bail!("pmctl logs requires an app name, or use `pmctl logs -f [filename]`");
            };
            let resp = rpc::client_call(&sock, rpc::Request::Logs { name, n })?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        cli::Cmd::Status { name, format } => {
            let resp = rpc::client_call(&sock, rpc::Request::Status { name })?;
            match format {
                cli::OutputFormat::Text => println!("{}", resp.render_text()),
                cli::OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
            }
            Ok(())
        }
        cli::Cmd::Events { name, n, format } => {
            let resp = rpc::client_call(&sock, rpc::Request::Events { name, n })?;
            match format {
                cli::OutputFormat::Text => {
                    for e in resp.events {
                        if let Some(app) = e.app {
                            println!("{} [{}] app={} {}", e.ts, e.component, app, e.message);
                        } else {
                            println!("{} [{}] {}", e.ts, e.component, e.message);
                        }
                    }
                    Ok(())
                }
                cli::OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                    Ok(())
                }
            }
        }
    }
}


