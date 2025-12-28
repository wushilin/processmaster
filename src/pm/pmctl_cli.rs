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
    if matches!(&args.cmd, Some(cli::Cmd::Version)) {
        println!("{}", crate::pm::build_info::banner());
        return Ok(());
    }

    let sock = resolve_sock(&args)?;

    let cmd = args.cmd.unwrap_or(cli::Cmd::Status {
        name: None,
        format: cli::OutputFormat::Text,
    });

    match cmd {
        cli::Cmd::ServerVersion => {
            let resp = rpc::client_call(&sock, rpc::Request::ServerVersion)?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        cli::Cmd::PerfMetrics {
            name,
            interval_ms,
            once,
        } => {
            fn fmt_bytes(n: Option<u64>) -> String {
                let Some(n) = n else { return "-".to_string() };
                const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
                let mut v = n as f64;
                let mut i = 0usize;
                while v >= 1024.0 && i + 1 < UNITS.len() {
                    v /= 1024.0;
                    i += 1;
                }
                let digits = if i == 0 { 0 } else if v >= 10.0 { 1 } else { 2 };
                format!("{:.*} {}", digits, v, UNITS[i])
            }

            fn parse_limit_bytes(raw: &Option<String>) -> Option<u64> {
                let s = raw.as_deref()?.trim();
                if s.is_empty() || s == "max" { return None; }
                s.parse::<u64>().ok()
            }

            fn fmt_limit(raw: &Option<String>) -> String {
                let Some(s) = raw.as_deref() else { return "-".to_string() };
                let t = s.trim();
                if t.is_empty() { return "-".to_string() }
                if t == "max" { return "unlimited".to_string() }
                match t.parse::<u64>() {
                    Ok(n) => fmt_bytes(Some(n)),
                    Err(_) => t.to_string(),
                }
            }

            fn fmt_pct(cur: Option<u64>, max_raw: &Option<String>) -> String {
                let Some(cur) = cur else { return "-".to_string() };
                let Some(max) = parse_limit_bytes(max_raw) else { return "-".to_string() };
                if max == 0 { return "-".to_string() }
                let pct = (cur as f64) / (max as f64) * 100.0;
                if !pct.is_finite() { return "-".to_string() }
                format!("{pct:.1}%")
            }

            fn psi_avg10(p: &Option<rpc::PerfPressure>) -> String {
                let Some(p) = p else { return "-".to_string() };
                let Some(s) = &p.some else { return "-".to_string() };
                let Some(v) = s.avg10 else { return "-".to_string() };
                if !v.is_finite() { return "-".to_string() }
                format!("{v:.2}")
            }

            fn parse_cpu_max(raw: &Option<String>) -> (Option<u64>, Option<u64>) {
                // returns (quota_usec, period_usec). quota_usec=None means unlimited.
                let Some(s) = raw.as_deref() else { return (None, None) };
                let t = s.trim();
                if t.is_empty() { return (None, None) }
                let mut it = t.split_whitespace();
                let a = it.next().unwrap_or("");
                let b = it.next().unwrap_or("");
                if a == "max" {
                    let period = b.parse::<u64>().ok();
                    return (None, period);
                }
                let quota = a.parse::<u64>().ok();
                let period = b.parse::<u64>().ok();
                (quota, period)
            }

            fn fmt_cpu_quota(raw: &Option<String>) -> String {
                let (quota, period) = parse_cpu_max(raw);
                match (quota, period) {
                    (None, Some(p)) => format!("unlimited (period={}ms)", (p as f64) / 1000.0),
                    (None, None) => "unlimited".to_string(),
                    (Some(q), Some(p)) => {
                        let qms = (q as f64) / 1000.0;
                        let pms = (p as f64) / 1000.0;
                        let millicores = ((q as f64) / (p as f64) * 1000.0).round();
                        format!("{qms:.3}ms/{pms:.3}ms (~{}m)", millicores as i64)
                    }
                    (Some(_), None) => raw.as_deref().unwrap_or("-").to_string(),
                }
            }

            fn get_stat(st: &std::collections::BTreeMap<String, u64>, k: &str) -> Option<u64> {
                st.get(k).copied()
            }

            fn delta_u64(a: Option<u64>, b: Option<u64>) -> Option<u64> {
                match (a, b) {
                    (Some(a), Some(b)) if b >= a => Some(b - a),
                    _ => None,
                }
            }

            fn fetch(sock: &std::path::PathBuf, name: &str) -> anyhow::Result<rpc::PerfMetricsSnapshot> {
                let resp = rpc::client_call(sock, rpc::Request::PerfMetrics { name: name.to_string() })?;
                if !resp.ok {
                    if !resp.message.trim().is_empty() {
                        anyhow::bail!("{}", resp.message.trim_end());
                    }
                    anyhow::bail!("perf-metrics failed");
                }
                resp.perf_metrics.ok_or_else(|| anyhow::anyhow!("(no metrics)"))
            }

            let m1 = fetch(&sock, &name)?;
            let st1 = m1.cpu_stat.clone().unwrap_or_default();
            let usage1 = get_stat(&st1, "usage_usec");
            let thr1 = get_stat(&st1, "throttled_usec");
            let nrp1 = get_stat(&st1, "nr_periods");
            let nrt1 = get_stat(&st1, "nr_throttled");

            let mut sample = None; // (m2, dt_us)
            if !once {
                let t0 = std::time::Instant::now();
                std::thread::sleep(std::time::Duration::from_millis(interval_ms.max(1)));
                let dt_us = t0.elapsed().as_micros().max(1) as u64;
                let m2 = fetch(&sock, &name)?;
                sample = Some((m2, dt_us));
            }

            // For printing, prefer the newest snapshot (m2 if available).
            let m = sample.as_ref().map(|(m2, _)| m2).unwrap_or(&m1);

            println!("app: {}", m.app);
            println!("cgroup: {}", m.cgroup_dir);
            println!();
            println!(
                "memory: current={} max={} util={} psi.avg10={}",
                fmt_bytes(m.memory_current),
                fmt_limit(&m.memory_max),
                fmt_pct(m.memory_current, &m.memory_max),
                psi_avg10(&m.memory_pressure),
            );
            println!(
                "swap:   current={} max={} util={}",
                fmt_bytes(m.swap_current),
                fmt_limit(&m.swap_max),
                fmt_pct(m.swap_current, &m.swap_max),
            );
            println!(
                "cpu:    cpu.max={}  psi.avg10={}",
                fmt_cpu_quota(&m.cpu_max),
                psi_avg10(&m.cpu_pressure),
            );
            let st = m.cpu_stat.clone().unwrap_or_default();
            let usage = get_stat(&st, "usage_usec");
            let thr = get_stat(&st, "throttled_usec");
            let nr_thr = get_stat(&st, "nr_throttled");
            let nr_p = get_stat(&st, "nr_periods");
            println!(
                "cpu.stat: usage_usec={} throttled_usec={} nr_throttled={} nr_periods={}",
                usage.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
                thr.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
                nr_thr.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
                nr_p.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
            );

            // IO (snapshot): show caps + PSI + a compact view of io.stat.
            println!();
            println!(
                "io:     io.max={}  psi.avg10={}",
                m.io_max
                    .as_deref()
                    .map(|s| if s.trim().is_empty() { "-" } else { s.trim() })
                    .unwrap_or("-"),
                psi_avg10(&m.io_pressure),
            );
            if let Some(stat) = m.io_stat.as_deref() {
                let lines: Vec<&str> = stat.lines().filter(|l| !l.trim().is_empty()).collect();
                if !lines.is_empty() {
                    let cap = 12usize;
                    println!("io.stat (first {} lines):", lines.len().min(cap));
                    for l in lines.iter().take(cap) {
                        println!("  {l}");
                    }
                    if lines.len() > cap {
                        println!("  … (+{} more lines)", lines.len() - cap);
                    }
                }
            }

            if let Some((m2, dt_us)) = sample {
                let st2 = m2.cpu_stat.clone().unwrap_or_default();
                let usage2 = get_stat(&st2, "usage_usec");
                let thr2 = get_stat(&st2, "throttled_usec");
                let nrp2 = get_stat(&st2, "nr_periods");
                let nrt2 = get_stat(&st2, "nr_throttled");

                let d_usage = delta_u64(usage1, usage2);
                let d_thr = delta_u64(thr1, thr2);
                let d_nrp = delta_u64(nrp1, nrp2);
                let d_nrt = delta_u64(nrt1, nrt2);

                let (quota, period) = parse_cpu_max(&m2.cpu_max);
                let effective_cores = match (quota, period) {
                    (Some(q), Some(p)) if p > 0 => Some((q as f64) / (p as f64)), // cores
                    _ => None,
                };

                println!();
                println!("cpu.util (sampled over ~{:.3}ms):", (dt_us as f64) / 1000.0);
                if let Some(du) = d_usage {
                    let one_core_pct = (du as f64) / (dt_us as f64) * 100.0;
                    print!("  - usage: {:.1}% of 1 core", one_core_pct);
                    if let Some(ec) = effective_cores {
                        if ec > 0.0 {
                            let quota_pct = (du as f64) / ((dt_us as f64) * ec) * 100.0;
                            print!("  ({:.1}% of quota ~{}m)", quota_pct, (ec * 1000.0).round() as i64);
                        }
                    }
                    println!();
                } else {
                    println!("  - usage: - (missing/non-monotonic cpu.stat usage_usec)");
                }
                if let Some(dt) = d_thr {
                    let thr_pct = (dt as f64) / (dt_us as f64) * 100.0;
                    println!("  - throttled: {:.1}% of wall time", thr_pct);
                } else {
                    println!("  - throttled: - (missing/non-monotonic cpu.stat throttled_usec)");
                }
                println!(
                    "  - periods: nr_periods Δ={} nr_throttled Δ={}",
                    d_nrp.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
                    d_nrt.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
                );
                if let (Some(p), Some(d)) = (period, d_nrp) {
                    // Helpful intuition: expected enforcement windows in dt ~= dt_us / period.
                    let expected = (dt_us as f64) / (p as f64);
                    println!("  - cpu.max period={}us (expected ~{expected:.1} periods in sample)", p);
                    if d == 0 {
                        // Not necessarily an error; just means cpu controller stats may not be updating as expected.
                    }
                }

                // IO sampled deltas (per-device), derived from io.stat.
                fn parse_io_stat(raw: Option<&str>) -> std::collections::BTreeMap<String, std::collections::BTreeMap<String, u64>> {
                    let mut out: std::collections::BTreeMap<String, std::collections::BTreeMap<String, u64>> = std::collections::BTreeMap::new();
                    let Some(raw) = raw else { return out };
                    for line in raw.lines() {
                        let t = line.trim();
                        if t.is_empty() {
                            continue;
                        }
                        let mut it = t.split_whitespace();
                        let Some(dev) = it.next() else { continue };
                        if !dev.contains(':') {
                            continue;
                        }
                        let ent = out.entry(dev.to_string()).or_default();
                        for kv in it {
                            let Some((k, v)) = kv.split_once('=') else { continue };
                            if let Ok(n) = v.parse::<u64>() {
                                ent.insert(k.to_string(), n);
                            }
                        }
                    }
                    out
                }

                fn delta(a: Option<u64>, b: Option<u64>) -> Option<u64> {
                    match (a, b) {
                        (Some(a), Some(b)) if b >= a => Some(b - a),
                        _ => None,
                    }
                }

                fn fmt_bytes_per_s(bytes: Option<u64>, dt_us: u64) -> String {
                    let Some(bytes) = bytes else { return "-".to_string() };
                    let dt = dt_us.max(1) as f64;
                    let bps = (bytes as f64) * 1_000_000.0 / dt;
                    if !bps.is_finite() { return "-".to_string() }
                    const UNITS: [&str; 5] = ["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"];
                    let mut v = bps;
                    let mut i = 0usize;
                    while v >= 1024.0 && i + 1 < UNITS.len() {
                        v /= 1024.0;
                        i += 1;
                    }
                    let digits = if i == 0 { 0 } else if v >= 10.0 { 1 } else { 2 };
                    format!("{:.*} {}", digits, v, UNITS[i])
                }

                fn fmt_iops(ops: Option<u64>, dt_us: u64) -> String {
                    let Some(ops) = ops else { return "-".to_string() };
                    let dt = dt_us.max(1) as f64;
                    let iops = (ops as f64) * 1_000_000.0 / dt;
                    if !iops.is_finite() { return "-".to_string() }
                    if iops >= 100.0 { format!("{iops:.0} iops") } else { format!("{iops:.1} iops") }
                }

                let a = parse_io_stat(m1.io_stat.as_deref());
                let b = parse_io_stat(m2.io_stat.as_deref());
                if !a.is_empty() || !b.is_empty() {
                    println!();
                    println!("io.util (sampled over ~{:.3}ms):", (dt_us as f64) / 1000.0);
                    let mut devs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
                    for k in a.keys() { devs.insert(k.clone()); }
                    for k in b.keys() { devs.insert(k.clone()); }
                    let cap = 20usize;
                    let mut shown = 0usize;
                    for dev in devs.iter() {
                        if shown >= cap { break; }
                        let va = a.get(dev).cloned().unwrap_or_default();
                        let vb = b.get(dev).cloned().unwrap_or_default();
                        let drb = delta(va.get("rbytes").copied(), vb.get("rbytes").copied());
                        let dwb = delta(va.get("wbytes").copied(), vb.get("wbytes").copied());
                        let dri = delta(va.get("rios").copied(), vb.get("rios").copied());
                        let dwi = delta(va.get("wios").copied(), vb.get("wios").copied());
                        println!(
                            "  - {dev} read={} ({}) write={} ({})",
                            fmt_bytes_per_s(drb, dt_us),
                            fmt_iops(dri, dt_us),
                            fmt_bytes_per_s(dwb, dt_us),
                            fmt_iops(dwi, dt_us),
                        );
                        shown += 1;
                    }
                    if devs.len() > cap {
                        println!("  … (+{} more devices)", devs.len() - cap);
                    }
                }
            } else {
                println!();
                println!("cpu.util: (pass --interval-ms N to compute; default is 1000ms, or use --once to disable)");
            }
            Ok(())
        }
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
        cli::Cmd::AdminList => {
            let resp = rpc::client_call(&sock, rpc::Request::AdminList)?;
            if resp.admin_actions.is_empty() {
                println!("(no admin actions configured)");
            } else {
                for a in resp.admin_actions {
                    println!("{} ({})", a.label, a.name);
                }
            }
            Ok(())
        }
        cli::Cmd::AdminKill => {
            let resp = rpc::client_call(&sock, rpc::Request::AdminKill)?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        cli::Cmd::AdminRun { id } => {
            let resp = rpc::client_call(&sock, rpc::Request::AdminAction { name: id })?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        cli::Cmd::AdminPs => {
            let resp = rpc::client_call(&sock, rpc::Request::AdminPs)?;
            if !resp.message.trim().is_empty() {
                println!("{}", resp.message.trim_end());
            }
            Ok(())
        }
        cli::Cmd::Version => unreachable!("handled before sock resolution"),
    }
}


