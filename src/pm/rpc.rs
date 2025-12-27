use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use chrono::{Local, TimeZone};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum Request {
    Update,
    Start { name: String, #[serde(default)] force: bool },
    Stop { name: String },
    Restart { name: String, #[serde(default)] force: bool },
    Flag { name: String, flags: Vec<String>, #[serde(default)] ttl: Option<String> },
    Unflag { name: String, flags: Vec<String> },
    Enable { name: String },
    Disable { name: String },
    Logs { name: String, #[serde(default = "default_log_lines")] n: usize },
    LogsFollow {
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        filename: Option<String>,
        #[serde(default = "default_log_lines")]
        n: usize,
    },
    Events {
        #[serde(default)]
        name: Option<String>,
        #[serde(default = "default_event_lines")]
        n: usize,
    },
    Status { name: Option<String> },
}

fn default_log_lines() -> usize {
    50
}

fn default_event_lines() -> usize {
    200
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEntry {
    pub ts: String,
    pub component: String,
    #[serde(default)]
    pub app: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusEntry {
    pub application: String,
    pub enabled: bool,
    pub running: bool,
    /// Desired state (daemon-side intent): RUNNING / STOPPED / SCHEDULED
    #[serde(default)]
    pub desired: String,
    /// Actual state (cgroup truth): RUNNING / STOPPED
    #[serde(default)]
    pub actual: String,
    #[serde(default)]
    pub phase: String,
    /// System-observed crashes that resulted in a restart attempt in the last 10 minutes.
    /// NOTE: rendered as column header "crashes_10m" in pmctl.
    #[serde(default)]
    pub restarts_10m: u32,
    /// System flags derived from daemon logic (e.g. FAILED/BACKOFF).
    #[serde(default)]
    pub system_flags: Vec<String>,
    /// User-defined flags (for fine-grained controls).
    #[serde(default)]
    pub user_flags: Vec<String>,
    #[serde(default)]
    pub pids: Vec<i32>,
    /// Per-pid uptime in milliseconds, aligned with `pids` by index.
    /// Computed on the daemon host (so pmctl can run remotely in the future).
    #[serde(default)]
    pub pid_uptimes_ms: Vec<i64>,
    pub source_file: Option<String>,
    #[serde(default)]
    pub last_run_at_ms: Option<i64>,
    #[serde(default)]
    pub last_exit_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default)]
    pub message: String,
    /// Services that were restarted as part of an operation (e.g. update defs).
    #[serde(default)]
    pub restarted: Vec<String>,
    #[serde(default)]
    pub statuses: Vec<StatusEntry>,
    #[serde(default)]
    pub events: Vec<EventEntry>,
}

impl Response {
    pub fn render_text(&self) -> String {
        if !self.message.is_empty() && self.statuses.is_empty() {
            return self.message.clone();
        }
        if self.statuses.is_empty() {
            return "(no services)".to_string();
        }

        #[derive(Clone)]
        struct Row {
            cols: Vec<String>,
        }

        fn pad(s: &str, width: usize) -> String {
            if s.len() >= width {
                return s.to_string();
            }
            let mut out = String::with_capacity(width);
            out.push_str(s);
            out.push_str(&" ".repeat(width - s.len()));
            out
        }

        fn border(widths: &[usize]) -> String {
            let mut out = String::new();
            out.push('+');
            for (i, w) in widths.iter().enumerate() {
                // 1 leading + 1 trailing padding space per cell.
                out.push_str(&"-".repeat(*w + 2));
                out.push('+');
                if i + 1 == widths.len() {
                    // no-op
                }
            }
            out
        }

        fn row_line(cols: &[String], widths: &[usize]) -> String {
            let mut out = String::new();
            out.push('|');
            for (i, w) in widths.iter().enumerate() {
                let v = cols.get(i).map(|s| s.as_str()).unwrap_or("");
                out.push(' ');
                out.push_str(&pad(v, *w));
                out.push(' ');
                out.push('|');
            }
            out
        }

        let headers = vec![
            "application",
            "desired",
            "actual",
            "status",
            "crashes_10m",
            "pid",
            "uptime",
            "sys_flags",
            "user_flags",
            "enabled",
            "last_run",
            "src",
        ];

        // Each service can occupy multiple physical table rows (one per PID).
        // We keep them grouped so we can draw a border only once per service.
        let mut groups: Vec<Vec<Row>> = vec![];
        for s in &self.statuses {
            let desired = if s.desired.is_empty() { "-" } else { s.desired.as_str() };
            let actual = if s.actual.is_empty() {
                if s.running { "RUNNING" } else { "STOPPED" }
            } else {
                s.actual.as_str()
            };
            let status = if s.phase.is_empty() {
                if s.running { "RUNNING" } else { "STOPPED" }
            } else {
                s.phase.as_str()
            };
            let enabled = if s.enabled { "enabled" } else { "disabled" };
            let src = s
                .source_file
                .as_deref()
                .and_then(|p| Path::new(p).file_name())
                .map(|os| os.to_string_lossy().to_string())
                .unwrap_or_else(|| "-".to_string());
            let last_run = s
                .last_run_at_ms
                .and_then(|ms| Local.timestamp_millis_opt(ms).single())
                .map(|dt| dt.format("%Y-%m-%d_%H:%M:%S%.3f").to_string())
                .unwrap_or_else(|| "-".to_string());
            let sys_flags = if s.system_flags.is_empty() { "-".to_string() } else { s.system_flags.join(",") };
            let user_flags = if s.user_flags.is_empty() { "-".to_string() } else { s.user_flags.join(",") };
            let crashes_10m = s.restarts_10m.to_string();

            if s.pids.is_empty() {
                groups.push(vec![Row {
                    cols: vec![
                        s.application.clone(),
                        desired.to_string(),
                        actual.to_string(),
                        status.to_string(),
                        crashes_10m,
                        "-".to_string(),
                        "-".to_string(),
                        sys_flags,
                        user_flags,
                        enabled.to_string(),
                        last_run,
                        src,
                    ],
                }]);
                continue;
            }

            // One physical table line per PID. First PID line carries metadata.
            let mut g: Vec<Row> = vec![];
            let height = s.pids.len().max(1);
            let _ = height; // (for readability: height is the number of ASCII rows this service occupies)

            let up0 = s
                .pid_uptimes_ms
                .get(0)
                .copied()
                .map(fmt_uptime_ms)
                .unwrap_or_else(|| "-".to_string());
            g.push(Row {
                cols: vec![
                    s.application.clone(),
                    desired.to_string(),
                    actual.to_string(),
                    status.to_string(),
                    crashes_10m,
                    s.pids[0].to_string(),
                    up0,
                    sys_flags,
                    user_flags,
                    enabled.to_string(),
                    last_run,
                    src,
                ],
            });

            // Remaining PIDs: keep all other columns blank so pid/uptime align under headers.
            for (idx, pid) in s.pids.iter().enumerate().skip(1) {
                let up = s
                    .pid_uptimes_ms
                    .get(idx)
                    .copied()
                    .map(fmt_uptime_ms)
                    .unwrap_or_else(|| "-".to_string());
                g.push(Row {
                    cols: vec![
                        "".to_string(),
                        "".to_string(),
                        "".to_string(),
                        "".to_string(),
                        "".to_string(),
                        pid.to_string(),
                        up,
                        "".to_string(),
                        "".to_string(),
                        "".to_string(),
                        "".to_string(),
                        "".to_string(),
                    ],
                });
            }
            groups.push(g);
        }

        // Compute widths from headers + all rows (no fixed spacing).
        let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
        for g in &groups {
            for r in g {
                for (i, c) in r.cols.iter().enumerate() {
                    widths[i] = widths[i].max(c.len());
                }
            }
        }

        let mut out = String::new();
        let top = border(&widths);
        out.push_str(&top);
        out.push('\n');
        out.push_str(&row_line(
            &headers.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &widths,
        ));
        out.push('\n');
        out.push_str(&top);
        out.push('\n');

        for g in &groups {
            for r in g {
                out.push_str(&row_line(&r.cols, &widths));
                out.push('\n');
            }
            // Draw a row separator only once per service (even if it spans multiple PID lines).
            out.push_str(&top);
            out.push('\n');
        }

        out
    }
}

fn fmt_uptime_ms(ms: i64) -> String {
    if ms < 0 {
        return "-".to_string();
    }
    let mut s = (ms as u64 + 500) / 1000;
    let days = s / 86_400;
    s %= 86_400;
    let hours = s / 3_600;
    s %= 3_600;
    let mins = s / 60;
    let secs = s % 60;
    if days > 0 {
        format!("{days}d{hours:02}h")
    } else if hours > 0 {
        format!("{hours}h{mins:02}m")
    } else if mins > 0 {
        format!("{mins}m{secs:02}s")
    } else {
        format!("{secs}s")
    }
}

pub fn client_call(sock: &Path, req: Request) -> anyhow::Result<Response> {
    let mut stream = UnixStream::connect(sock).map_err(|e| {
        anyhow::anyhow!(
            "failed to connect to pm daemon socket {}: {e}",
            sock.display()
        )
    })?;

    let line = serde_json::to_string(&req)? + "\n";
    stream.write_all(line.as_bytes())?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut resp_line = String::new();
    reader.read_line(&mut resp_line)?;
    if resp_line.trim().is_empty() {
        anyhow::bail!("empty response from daemon");
    }
    let resp: Response = serde_json::from_str(resp_line.trim_end())?;
    if !resp.ok {
        anyhow::bail!("{}", resp.message);
    }
    Ok(resp)
}

pub fn client_follow<F>(sock: &Path, req: Request, mut on_line: F) -> anyhow::Result<()>
where
    F: FnMut(&str),
{
    let mut stream = UnixStream::connect(sock).map_err(|e| {
        anyhow::anyhow!(
            "failed to connect to processmaster socket {}: {e}",
            sock.display()
        )
    })?;

    let line = serde_json::to_string(&req)? + "\n";
    stream.write_all(line.as_bytes())?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut first = String::new();
    reader.read_line(&mut first)?;
    if first.trim().is_empty() {
        anyhow::bail!("empty response from daemon");
    }
    let resp: Response = serde_json::from_str(first.trim_end())?;
    if !resp.ok {
        anyhow::bail!("{}", resp.message);
    }

    // Stream subsequent lines until EOF.
    let mut buf = String::new();
    loop {
        buf.clear();
        let n = reader.read_line(&mut buf)?;
        if n == 0 {
            break;
        }
        on_line(buf.trim_end_matches('\n'));
    }
    Ok(())
}


