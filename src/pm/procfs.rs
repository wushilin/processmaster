//! Small readers for `/proc` shared by the daemon and the web console.

/// One reading of the clock that `/proc/<pid>/stat` start times are measured against:
/// system uptime plus the tick rate. Taken once per report so every pid in it is
/// measured against the same instant.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ProcClock {
    sys_uptime_s: Option<f64>,
    hz: Option<f64>,
}

impl ProcClock {
    pub(crate) fn now() -> Self {
        ProcClock { sys_uptime_s: read_system_uptime_seconds(), hz: clock_ticks_per_second() }
    }

    /// Per-pid uptime in milliseconds, aligned with `pids` by index; -1 where unknown.
    pub(crate) fn uptimes_ms<P: Copy + Into<i64>>(&self, pids: &[P]) -> Vec<i64> {
        pids.iter().map(|&pid| self.uptime_ms(pid.into()).unwrap_or(-1)).collect()
    }

    fn uptime_ms(&self, pid: i64) -> Option<i64> {
        let sys_uptime_s = self.sys_uptime_s?;
        let hz = self.hz?;
        let start_ticks = read_pid_starttime_ticks(pid)?;
        let started_s = (start_ticks as f64) / hz;
        let up_s = (sys_uptime_s - started_s).max(0.0);
        Some((up_s * 1000.0).round() as i64)
    }
}

fn clock_ticks_per_second() -> Option<f64> {
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v <= 0 { None } else { Some(v as f64) }
}

fn read_system_uptime_seconds() -> Option<f64> {
    let s = std::fs::read_to_string("/proc/uptime").ok()?;
    let first = s.split_whitespace().next()?;
    first.parse::<f64>().ok()
}

fn read_pid_starttime_ticks(pid: i64) -> Option<u64> {
    let path = format!("/proc/{pid}/stat");
    let stat = std::fs::read_to_string(path).ok()?;
    let rparen = stat.rfind(')')?;
    let after = stat.get(rparen + 2..)?; // skip ") "
    let fields: Vec<&str> = after.split_whitespace().collect();
    // fields[0] is original field 3 (state). starttime is original field 22 => index 22-3 = 19
    let start = *fields.get(19)?;
    start.parse::<u64>().ok()
}
