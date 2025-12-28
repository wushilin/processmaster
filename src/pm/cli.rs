use crate::pm::{config, daemon, rpc};
use clap::{Parser, Subcommand};
use clap::ValueEnum;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "pm", version, about = "processmaster supervisor")]
pub struct Args {
    /// Path to master config YAML
    #[arg(short = 'c', long = "config", default_value = "config.yaml")]
    pub config: PathBuf,

    #[command(subcommand)]
    pub cmd: Option<Cmd>,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Reload app definitions and reconcile state (stop removed/disabled services)
    Update,
    /// Start a service, or all
    Start {
        name: String,
        /// Start even if the service is disabled (does not edit YAML)
        #[arg(long = "force")]
        force: bool,
    },
    /// Stop a service, or all
    Stop { name: String },
    /// Restart a service, or all
    Restart {
        name: String,
        /// Start even if the service is disabled (does not edit YAML)
        #[arg(long = "force")]
        force: bool,
    },
    /// Set user flags on an app (comma-separated list)
    Flag {
        name: String,
        flags: String,
        /// Optional TTL for these flags, e.g. 5d4h3s or 10m or 1500ms. Units: ms/s/m/h/d.
        /// Must be specified from larger to smaller units; no repeats (3h1m ok, 1m3h invalid).
        #[arg(short = 't', long = "ttl")]
        ttl: Option<String>,
    },
    /// Remove user flags from an app (comma-separated list)
    Unflag { name: String, flags: String },
    /// Enable a service (writes enabled: true into its YAML)
    Enable { name: String },
    /// Disable a service (writes enabled: false into its YAML)
    Disable { name: String },
    /// Show recent logs for an app (stdout/stderr + hinted log files)
    Logs {
        /// App name (required unless using -f to follow across all apps)
        name: Option<String>,
        /// Number of lines to show per file
        #[arg(short = 'n', default_value_t = 50)]
        n: usize,
        /// Follow logs continuously. Optional value filters by filename only (basename, not path).
        /// Examples: `-f` (all logs), `-f stdout.log`, `-f syslog`
        #[arg(short = 'f', num_args = 0..=1, default_missing_value = "")]
        f: Option<String>,
    },
    /// Show status for a service, or all (default)
    Status {
        name: Option<String>,
        /// Output format: text (default) or json
        #[arg(long = "format", default_value = "text")]
        format: OutputFormat,
    },
    /// Show recent daemon events ("what happened")
    Events {
        /// Optional app name filter
        name: Option<String>,
        /// Number of events to show
        #[arg(short = 'n', default_value_t = 200)]
        n: usize,
        /// Output format: text (default) or json
        #[arg(long = "format", default_value = "text")]
        format: OutputFormat,
    },
    /// Print local build info
    Version,
    /// Print server build info (requires daemon socket)
    ServerVersion,
    /// Show per-app performance/resource metrics from cgroup (memory/swap/cpu + pressure/throttling)
    PerfMetrics {
        name: String,
        /// Sampling interval used to compute CPU utilization from cumulative cpu.stat counters.
        /// If you pass `--once`, no utilization is computed and this is ignored.
        #[arg(long = "interval-ms", default_value_t = 1000)]
        interval_ms: u64,
        /// Only print a single snapshot (no sleep; no utilization %).
        #[arg(long = "once")]
        once: bool,
    },

    /// List configured admin actions (name + label)
    AdminList,
    /// Kill all running admin actions via cgroup.kill (no mercy)
    AdminKill,
    /// Run an admin action by its id (the admin_actions map key)
    AdminRun { id: String },
    /// Show PIDs currently running in the admin_actions cgroup
    AdminPs,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

pub fn run() -> anyhow::Result<()> {
    let args = Args::parse();
    if matches!(&args.cmd, Some(Cmd::Version)) {
        println!("{}", crate::pm::build_info::banner());
        return Ok(());
    }
    let cfg = config::load_master_config(&args.config)?;

    match args.cmd {
        None => daemon::run_daemon(&cfg),
        Some(Cmd::ServerVersion) => {
            let resp = rpc::client_call(&cfg.sock, rpc::Request::ServerVersion)?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        Some(Cmd::PerfMetrics { name, .. }) => {
            let resp = rpc::client_call(&cfg.sock, rpc::Request::PerfMetrics { name })?;
            if let Some(m) = resp.perf_metrics {
                println!("app: {}", m.app);
                println!("cgroup: {}", m.cgroup_dir);
                println!("memory.current: {:?}", m.memory_current);
                println!("memory.max: {:?}", m.memory_max);
                println!("swap.current: {:?}", m.swap_current);
                println!("swap.max: {:?}", m.swap_max);
                println!("cpu.max: {:?}", m.cpu_max);
                if let Some(st) = m.cpu_stat {
                    println!("cpu.stat: {:?}", st);
                }
            } else if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            } else {
                println!("(no metrics)");
            }
            Ok(())
        }
        Some(Cmd::Update) => {
            let resp = rpc::client_call(&cfg.sock, rpc::Request::Update)?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        Some(Cmd::Start { name, force }) => {
            let resp = rpc::client_call(&cfg.sock, rpc::Request::Start { name, force })?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        Some(Cmd::Stop { name }) => {
            let resp = rpc::client_call(&cfg.sock, rpc::Request::Stop { name })?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        Some(Cmd::Restart { name, force }) => {
            let resp = rpc::client_call(&cfg.sock, rpc::Request::Restart { name, force })?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        Some(Cmd::Flag { name, flags, ttl }) => {
            let flags: Vec<String> = flags
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            anyhow::ensure!(!flags.is_empty(), "no flags provided");
            let resp = rpc::client_call(&cfg.sock, rpc::Request::Flag { name, flags, ttl })?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        Some(Cmd::Unflag { name, flags }) => {
            let flags: Vec<String> = flags
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            anyhow::ensure!(!flags.is_empty(), "no flags provided");
            let resp = rpc::client_call(&cfg.sock, rpc::Request::Unflag { name, flags })?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        Some(Cmd::Enable { name }) => {
            let resp = rpc::client_call(&cfg.sock, rpc::Request::Enable { name })?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        Some(Cmd::Disable { name }) => {
            let resp = rpc::client_call(&cfg.sock, rpc::Request::Disable { name })?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        Some(Cmd::Logs { name, n, f }) => {
            if f.is_some() {
                let filename = f.and_then(|s| {
                    let t = s.trim().to_string();
                    if t.is_empty() { None } else { Some(t) }
                });
                return rpc::client_follow(
                    &cfg.sock,
                    rpc::Request::LogsFollow { name, filename, n },
                    |line| {
                    println!("{line}");
                    },
                );
            }

            let Some(name) = name else {
                anyhow::bail!("pmctl logs requires an app name, or use `pmctl logs -f [filename]`");
            };
            let resp = rpc::client_call(&cfg.sock, rpc::Request::Logs { name, n })?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        Some(Cmd::Status { name, format }) => {
            let resp = rpc::client_call(&cfg.sock, rpc::Request::Status { name })?;
            match format {
                OutputFormat::Text => println!("{}", resp.render_text()),
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
            }
            Ok(())
        }
        Some(Cmd::Events { name, n, format }) => {
            let resp = rpc::client_call(&cfg.sock, rpc::Request::Events { name, n })?;
            match format {
                OutputFormat::Text => {
                    for e in resp.events {
                        if let Some(app) = e.app {
                            println!("{} [{}] app={} {}", e.ts, e.component, app, e.message);
                        } else {
                            println!("{} [{}] {}", e.ts, e.component, e.message);
                        }
                    }
                    Ok(())
                }
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                    Ok(())
                }
            }
        }
        Some(Cmd::AdminList) => {
            let resp = rpc::client_call(&cfg.sock, rpc::Request::AdminList)?;
            for a in resp.admin_actions {
                println!("{} ({})", a.label, a.name);
            }
            Ok(())
        }
        Some(Cmd::AdminKill) => {
            let resp = rpc::client_call(&cfg.sock, rpc::Request::AdminKill)?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        Some(Cmd::AdminRun { id }) => {
            let resp = rpc::client_call(&cfg.sock, rpc::Request::AdminAction { name: id })?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        Some(Cmd::AdminPs) => {
            let resp = rpc::client_call(&cfg.sock, rpc::Request::AdminPs)?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        Some(Cmd::Version) => unreachable!("handled before config load"),
    }
}


