#![allow(dead_code)]

use anyhow::Context as _;
use nix::errno::Errno;
use nix::sys::signal::{kill as kill_pid, Signal};
use nix::unistd::Pid;
use nix::unistd::setsid;
use serde::Serialize;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::io::Write;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::os::unix::process::CommandExt;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::fs as tokio_fs;
use tokio::task;

/// Minimal cgroup-v2 helpers intended to replace external "launcher" features over time.
///
/// NOTE: This module is currently not wired into the daemon. It's meant for evaluation and
/// incremental rollout.

fn write_file(path: &Path, content: &str) -> anyhow::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| {
            anyhow::anyhow!(
                "open for write {} failed: kind={:?} os_error={:?} err={}",
                path.display(),
                e.kind(),
                e.raw_os_error(),
                e
            )
        })?;
    f.write_all(content.as_bytes()).map_err(|e| {
        anyhow::anyhow!(
            "write {} failed: kind={:?} os_error={:?} err={}",
            path.display(),
            e.kind(),
            e.raw_os_error(),
            e
        )
    })?;
    Ok(())
}

fn ensure_dir(path: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create_dir_all {}", path.display()))?;
    Ok(())
}

/// List pids in a cgroup by reading `cgroup.procs` (this cgroup only; not recursive).
pub(crate) fn list_pids_self_only(cgroup_dir: &Path) -> anyhow::Result<Vec<u32>> {
    let procs = cgroup_dir.join("cgroup.procs");
    let s = match fs::read_to_string(&procs) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Fail-safe: if the cgroup doesn't exist yet, treat it as empty.
            return Ok(vec![]);
        }
        Err(e) => return Err(e).with_context(|| format!("read {}", procs.display())),
    };
    let mut out = Vec::new();
    for (idx, line) in s.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let pid: u32 = line
            .parse()
            .with_context(|| format!("parse pid from {} line {}: {line}", procs.display(), idx + 1))?;
        out.push(pid);
    }
    Ok(out)
}

/// List pids in a cgroup **recursively**, including all descendant cgroups.
///
/// This walks the cgroup directory tree and unions all `cgroup.procs` contents.
pub(crate) fn list_pids(cgroup_dir: &Path) -> anyhow::Result<Vec<u32>> {
    // A missing cgroup is treated as empty.
    if !cgroup_dir.exists() {
        return Ok(vec![]);
    }

    // Iterative DFS to avoid deep recursion.
    let mut stack: Vec<PathBuf> = vec![cgroup_dir.to_path_buf()];
    let mut pids: Vec<u32> = Vec::new();

    // Safety guard: avoid pathological trees.
    const MAX_DIRS: usize = 50_000;
    let mut dirs_seen = 0usize;

    while let Some(dir) = stack.pop() {
        dirs_seen += 1;
        if dirs_seen > MAX_DIRS {
            anyhow::bail!(
                "cgroup tree too large under {} (>{MAX_DIRS} dirs)",
                cgroup_dir.display()
            );
        }

        pids.extend(list_pids_self_only(&dir)?);

        let rd = match fs::read_dir(&dir) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("read_dir {}", dir.display())),
        };
        for ent in rd {
            let ent = ent.with_context(|| format!("read_dir entry under {}", dir.display()))?;
            let ft = ent
                .file_type()
                .with_context(|| format!("file_type {}", ent.path().display()))?;
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                stack.push(ent.path());
            }
        }
    }

    // Keep stable output.
    pids.sort_unstable();
    pids.dedup();
    Ok(pids)
}

/// Async list pids in a cgroup (recursive).
pub(crate) async fn list_pids_async(cgroup_dir: &Path) -> anyhow::Result<Vec<u32>> {
    let dir = cgroup_dir.to_path_buf();
    task::spawn_blocking(move || list_pids(&dir))
        .await
        .map_err(|e| anyhow::anyhow!("list_pids_async join error: {e}"))?
}

/// Async list pids in a cgroup by reading `cgroup.procs` (this cgroup only; not recursive).
pub(crate) async fn list_pids_self_only_async(cgroup_dir: &Path) -> anyhow::Result<Vec<u32>> {
    let procs = cgroup_dir.join("cgroup.procs");
    let s = match tokio_fs::read_to_string(&procs).await {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Fail-safe: if the cgroup doesn't exist yet, treat it as empty.
            return Ok(vec![]);
        }
        Err(e) => return Err(e).with_context(|| format!("read {}", procs.display())),
    };
    let mut out = Vec::new();
    for (idx, line) in s.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let pid: u32 = line
            .parse()
            .with_context(|| format!("parse pid from {} line {}: {line}", procs.display(), idx + 1))?;
        out.push(pid);
    }
    Ok(out)
}

/// Kill all pids in the cgroup using the kernel's `cgroup.kill` interface.
///
/// This is the fastest/least-racy option when available.
pub(crate) fn kill_all_pids(cgroup_dir: &Path) -> anyhow::Result<()> {
    let killf = cgroup_dir.join("cgroup.kill");
    // Kernel expects "1". Newline is commonly tolerated; keep it explicit.
    match write_file(&killf, "1\n") {
        Ok(()) => {}
        Err(e) => {
            // Fail-safe: if cgroup doesn't exist, nothing to kill.
            if let Some(ioe) = e.downcast_ref::<io::Error>()
                && ioe.kind() == io::ErrorKind::NotFound
            {
                return Ok(());
            }
            return Err(e).with_context(|| format!("kill all via {}", killf.display()));
        }
    }
    Ok(())
}

/// Kill all pids in the cgroup by enumerating `cgroup.procs` and sending a signal.
///
/// Returns the number of pids we attempted to signal.
pub(crate) fn kill_with_signal(cgroup_dir: &Path, signal: Option<Signal>) -> anyhow::Result<usize> {
    let sig = signal.unwrap_or(Signal::SIGTERM);
    let pids = list_pids(cgroup_dir)?;
    for pid in &pids {
        // Best-effort: ignore ESRCH races (process already exited).
        let _ = kill_pid(Pid::from_raw(*pid as i32), sig);
    }
    Ok(pids.len())
}

#[cfg(target_os = "linux")]
fn pidfd_open(pid: u32) -> io::Result<RawFd> {
    // SAFETY: syscall invocation; returns -1 and sets errno on failure.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        let errno = Errno::last();
        // Racy case: PID already exited between reading cgroup.procs and opening pidfd.
        // Kernel typically reports ESRCH here; normalize to NotFound so callers can just retry.
        if errno == Errno::ESRCH {
            let inner = io::Error::from_raw_os_error(errno as i32);
            return Err(io::Error::new(io::ErrorKind::NotFound, inner));
        }
        return Err(io::Error::from_raw_os_error(errno as i32));
    }
    Ok(fd as RawFd)
}

#[cfg(target_os = "linux")]
fn wait_pidfd(fd: RawFd, timeout_ms: i32) -> io::Result<bool> {
    // A pidfd becomes pollable/readable when the process exits.
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: pfd points to a valid pollfd; nfds=1; timeout=-1 blocks.
        let rc = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, timeout_ms) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if rc == 0 {
            return Ok(false);
        }
        // Any readiness is sufficient for our use: process is gone or fd is errored/hung up.
        return Ok(true);
    }
}

/// Synchronously wait until the cgroup becomes empty.
///
/// Algorithm:
/// - loop:
///   - read pids from `cgroup.procs`
///   - if empty -> done
///   - pick one pid and block on its pidfd (poll) until it dies
///   - repeat
///
/// This is intentionally simple and robust against PID churn.
#[cfg(target_os = "linux")]
pub(crate) fn wait_all(cgroup_dir: &Path) -> anyhow::Result<()> {
    loop {
        let pids = list_pids(cgroup_dir)?;
        if pids.is_empty() {
            return Ok(());
        }

        // "Random" isn't required for correctness; picking the first is fine.
        let pid = pids[0];
        let fd = match pidfd_open(pid) {
            Ok(fd) => fd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // PID raced away between reading cgroup.procs and pidfd_open; retry.
                continue;
            }
            Err(e) => {
                return Err(anyhow::anyhow!("pidfd_open pid={pid} failed: {e}"));
            }
        };

        let r = wait_pidfd(fd, -1);
        // SAFETY: fd came from pidfd_open.
        unsafe {
            let _ = libc::close(fd);
        }
        let _exited = r.with_context(|| format!("wait on pidfd for pid={pid}"))?;
    }
}

/// Like `wait_all`, but can be cancelled (to avoid leaking waiter threads across generations).
///
/// Returns:
/// - `Ok(true)` when the cgroup became empty
/// - `Ok(false)` when cancelled
#[cfg(target_os = "linux")]
pub(crate) fn wait_all_cancellable(cgroup_dir: &Path, cancel: &AtomicBool) -> anyhow::Result<bool> {
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Ok(false);
        }
        let pids = list_pids(cgroup_dir)?;
        if pids.is_empty() {
            return Ok(true);
        }

        let pid = pids[0];
        let fd = match pidfd_open(pid) {
            Ok(fd) => fd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(anyhow::anyhow!("pidfd_open pid={pid} failed: {e}")),
        };

        // Poll in intervals so we can observe cancellation without burning CPU.
        // Note: we don't have an eventfd to interrupt poll; cancellation is cooperative on timeout.
        // Keep this reasonably small, but not 1s (which adds up with many services).
        const CANCEL_POLL_MS: i32 = 5_000;
        loop {
            if cancel.load(Ordering::Relaxed) {
                unsafe { let _ = libc::close(fd); }
                return Ok(false);
            }
            let ready = wait_pidfd(fd, CANCEL_POLL_MS)
                .with_context(|| format!("wait on pidfd for pid={pid}"))?;
            if ready {
                break;
            }
        }

        unsafe {
            let _ = libc::close(fd);
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Resources {
    /// cgroup v2 `cpu.max` payload, e.g. `"max 100000"` or `"20000 100000"`.
    pub(crate) cpu_max: Option<String>,
    /// cgroup v2 `memory.max` payload, e.g. `"max"` or `"268435456"`.
    pub(crate) memory_max: Option<String>,
    /// cgroup v2 `memory.swap.max` payload, e.g. `"max"` or `"0"`.
    pub(crate) swap_max: Option<String>,
    /// cgroup v2 `cpu.weight` (1..=10000).
    pub(crate) cpu_weight: Option<u16>,
    /// cgroup v2 `io.weight` default weight (1..=10000). Written as `default <n>`.
    pub(crate) io_weight: Option<u16>,
    /// cgroup v2 `io.max` lines (one per block device), e.g. `"8:0 rbps=1048576 wbps=1048576"`.
    pub(crate) io_max: Vec<String>,
}

impl Default for Resources {
    fn default() -> Self {
        Self {
            cpu_max: None,
            memory_max: None,
            swap_max: None,
            cpu_weight: None,
            io_weight: None,
            io_max: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LaunchParams {
    /// argv vector. Must be non-empty (argv[0] is the program).
    pub(crate) argv: Vec<OsString>,
    pub(crate) working_directory: PathBuf,
    /// Absolute path to the *app* cgroup directory (not the master processmaster cgroup).
    pub(crate) cgroup_dir: PathBuf,
    /// If set, decorate argv[0] as `<basename>[<group>]` (e.g. `sleep[logger]`).
    pub(crate) argv0_decoration_group: Option<String>,
    /// Linux user to run as (name).
    pub(crate) user: Option<String>,
    /// Linux group to run as (name).
    pub(crate) group: Option<String>,
    pub(crate) environment: Vec<(OsString, OsString)>,
    pub(crate) resources: Resources,
}

impl LaunchParams {
    pub(crate) fn new(argv: Vec<impl Into<OsString>>, working_directory: PathBuf, cgroup_dir: PathBuf) -> Self {
        Self {
            argv: argv.into_iter().map(Into::into).collect(),
            working_directory,
            cgroup_dir,
            argv0_decoration_group: None,
            user: None,
            group: None,
            environment: Vec::new(),
            resources: Resources::default(),
        }
    }
}

fn apply_resources(cgroup_dir: &Path, res: &Resources) -> anyhow::Result<()> {
    ensure_dir(cgroup_dir)?;

    if let Some(v) = &res.cpu_max {
        write_file(&cgroup_dir.join("cpu.max"), &format!("{v}\n"))
            .with_context(|| format!("set cpu.max for {}", cgroup_dir.display()))?;
    }
    if let Some(v) = &res.memory_max {
        write_file(&cgroup_dir.join("memory.max"), &format!("{v}\n"))
            .with_context(|| format!("set memory.max for {}", cgroup_dir.display()))?;
    }
    if let Some(v) = &res.swap_max {
        write_file(&cgroup_dir.join("memory.swap.max"), &format!("{v}\n"))
            .with_context(|| format!("set memory.swap.max for {}", cgroup_dir.display()))?;
    }
    if let Some(v) = res.cpu_weight {
        write_file(&cgroup_dir.join("cpu.weight"), &format!("{v}\n"))
            .with_context(|| format!("set cpu.weight for {}", cgroup_dir.display()))?;
    }
    if let Some(v) = res.io_weight {
        // cgroup v2 expects "default <weight>" for the default weight.
        write_file(&cgroup_dir.join("io.weight"), &format!("default {v}\n"))
            .with_context(|| format!("set io.weight for {}", cgroup_dir.display()))?;
    }
    if !res.io_max.is_empty() {
        let mut body = res.io_max.join("\n");
        body.push('\n');
        // NOTE: io.max is device-specific and kernel validation can fail with EINVAL/ENODEV.
        // Include the exact payload in the error chain so operators can reproduce with `echo ... > io.max`.
        let payload = body.trim_end().to_string();
        write_file(&cgroup_dir.join("io.max"), &body).with_context(|| {
            format!(
                "set io.max for {} (payload={payload:?}). Hint: ensure the device MAJ:MIN exists in io.stat; some kernels/devices may reject riops/wiops with EINVAL.",
                cgroup_dir.display()
            )
        })?;
    }
    Ok(())
}

/// Resolve a block-device identifier (major:minor) from a path.
///
/// - If `path` is a block device node (e.g. `/dev/sda`), uses `st_rdev`.
/// - Otherwise (directory/file/mountpoint), uses the filesystem device `st_dev`.
pub(crate) fn resolve_device_major_minor(path: &Path) -> anyhow::Result<(u32, u32)> {
    let md = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    let dev: u64 = if md.file_type().is_block_device() {
        md.rdev()
    } else {
        md.dev()
    };
    let maj = libc::major(dev) as u32;
    let min = libc::minor(dev) as u32;
    Ok((maj, min))
}

fn decorate_argv0(program: &OsString, group: &str) -> OsString {
    let base = program.to_string_lossy();
    let basename = base.rsplit('/').next().unwrap_or(&base);
    OsString::from(format!("{basename}[{group}]"))
}

/// Launch a process, attaching it to the provided cgroup in `pre_exec` (child side) by writing
/// `"0\n"` into `cgroup.procs`.
///
/// Resource knobs are applied in the parent (best-effort; requires permissions).
pub(crate) fn build_command(p: &LaunchParams) -> anyhow::Result<Command> {
    anyhow::ensure!(!p.argv.is_empty(), "LaunchParams.argv must not be empty");

    // `p.cgroup_dir` is treated as the app's *parent* cgroup. Services may create sub-cgroups under it.
    // In cgroup v2, a cgroup with child cgroups must not host processes ("no internal processes"),
    // otherwise attaching a process can fail with EBUSY. To avoid that, we always attach the process
    // into a dedicated leaf child cgroup `${p.cgroup_dir}/run`.
    apply_resources(&p.cgroup_dir, &p.resources)?;
    let attach_cgroup_dir = p.cgroup_dir.join("run");
    ensure_dir(&attach_cgroup_dir)?;

    let program = p.argv[0].clone();
    let mut cmd = Command::new(&program);
    if p.argv.len() > 1 {
        cmd.args(&p.argv[1..]);
    }
    cmd.current_dir(&p.working_directory);
    for (k, v) in &p.environment {
        cmd.env(k, v);
    }

    if let Some(group) = &p.argv0_decoration_group {
        cmd.arg0(decorate_argv0(&program, group));
    }

    let cgroup_procs = attach_cgroup_dir.join("cgroup.procs");
    let user = p.user.clone();
    let group = p.group.clone();

    // Preflight in parent: ensure we can at least open cgroup.procs for write.
    // This does NOT move the parent into the cgroup (only writing a pid would).
    if let Err(e) = std::fs::OpenOptions::new().write(true).open(&cgroup_procs) {
        return Err(anyhow::anyhow!(
            "cannot open cgroup.procs for write: {}: {e}",
            cgroup_procs.display()
        ));
    }

    // Child-side setup order:
    // - detach from processmaster's controlling terminal (setsid)
    // - attach to cgroup (requires only write access to cgroup.procs)
    // - optionally drop gid/uid
    // - then exec
    unsafe {
        cmd.pre_exec(move || {
            let _ = setsid();

            // Attach child to cgroup.
            // "0" means "self" when written to cgroup.procs.
            // NOTE: do not wrap these io::Errors with `io::Error::new(...)` because that loses
            // the raw OS error code. The parent only reliably receives errno from pre_exec failures.
            let mut f = std::fs::OpenOptions::new().write(true).open(&cgroup_procs)?;
            f.write_all(b"0\n")?;

            // Drop privileges if requested.
            if let Some(gname) = group.as_deref() {
                let g = users::get_group_by_name(gname)
                    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, format!("group not found: {gname}")))?;
                let gid = nix::unistd::Gid::from_raw(g.gid());
                nix::unistd::setgid(gid)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("setgid({gname}) failed: {e}")))?;
            }
            if let Some(uname) = user.as_deref() {
                let u = users::get_user_by_name(uname)
                    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, format!("user not found: {uname}")))?;
                let uid = nix::unistd::Uid::from_raw(u.uid());
                nix::unistd::setuid(uid)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("setuid({uname}) failed: {e}")))?;
            }
            Ok(())
        });
    }

    Ok(cmd)
}

/// Convenience wrapper over [`build_command`] + `spawn()`.
pub(crate) fn launch_process(p: &LaunchParams) -> anyhow::Result<Child> {
    let mut cmd = build_command(p)?;
    let program = p.argv[0].clone();
    cmd.spawn()
        .with_context(|| format!("spawn program={}", program.to_string_lossy()))
}

fn read_to_string_opt(path: &Path) -> anyhow::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

fn read_trimmed_opt(path: &Path) -> anyhow::Result<Option<String>> {
    Ok(read_to_string_opt(path)?
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty()))
}

fn read_u64_opt(path: &Path) -> anyhow::Result<Option<u64>> {
    let Some(s) = read_trimmed_opt(path)? else {
        return Ok(None);
    };
    let v: u64 = s
        .trim()
        .parse()
        .with_context(|| format!("parse u64 from {}: {s}", path.display()))?;
    Ok(Some(v))
}

fn parse_kv_u64_lines(s: &str) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for line in s.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let mut it = t.split_whitespace();
        let Some(k) = it.next() else { continue };
        let Some(vs) = it.next() else { continue };
        if let Ok(v) = vs.parse::<u64>() {
            out.insert(k.to_string(), v);
        }
    }
    out
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CgroupPressureLine {
    pub avg10: Option<f64>,
    pub avg60: Option<f64>,
    pub avg300: Option<f64>,
    pub total: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CgroupPressure {
    /// `some ...` line, if present (PSI).
    pub some: Option<CgroupPressureLine>,
    /// `full ...` line, if present (PSI).
    pub full: Option<CgroupPressureLine>,
    /// Raw file contents (trimmed), for debugging.
    pub raw: Option<String>,
}

fn parse_pressure_opt(s: Option<String>) -> Option<CgroupPressure> {
    let raw = s.map(|x| x.trim().to_string()).filter(|x| !x.is_empty())?;
    let mut some: Option<CgroupPressureLine> = None;
    let mut full: Option<CgroupPressureLine> = None;

    for line in raw.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let mut parts = t.split_whitespace();
        let Some(kind) = parts.next() else { continue };
        let mut pl = CgroupPressureLine {
            avg10: None,
            avg60: None,
            avg300: None,
            total: None,
        };
        for p in parts {
            let Some((k, v)) = p.split_once('=') else { continue };
            match k {
                "avg10" => pl.avg10 = v.parse::<f64>().ok(),
                "avg60" => pl.avg60 = v.parse::<f64>().ok(),
                "avg300" => pl.avg300 = v.parse::<f64>().ok(),
                "total" => pl.total = v.parse::<u64>().ok(),
                _ => {}
            }
        }
        match kind {
            "some" => some = Some(pl),
            "full" => full = Some(pl),
            _ => {}
        }
    }

    Some(CgroupPressure {
        some,
        full,
        raw: Some(raw),
    })
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CgroupResourceSnapshot {
    pub cgroup_dir: String,

    /// `memory.max` raw (e.g. "max" or bytes).
    pub memory_max: Option<String>,
    /// `memory.current` bytes.
    pub memory_current: Option<u64>,

    /// `memory.swap.max` raw (e.g. "max" or bytes). May be missing if swap controller isn't enabled.
    pub swap_max: Option<String>,
    /// `memory.swap.current` bytes. May be missing if swap controller isn't enabled.
    pub swap_current: Option<u64>,

    /// `cpu.max` raw (e.g. "max 100000" or "20000 100000").
    pub cpu_max: Option<String>,
    /// `cpu.stat` parsed key/value map.
    pub cpu_stat: Option<BTreeMap<String, u64>>,
    /// `cpu.pressure` PSI (if available).
    pub cpu_pressure: Option<CgroupPressure>,
    /// `memory.pressure` PSI (if available).
    pub memory_pressure: Option<CgroupPressure>,

    /// `io.max` raw (if available). This reflects the current I/O caps for this cgroup.
    pub io_max: Option<String>,
    /// `io.stat` raw (if available). Per-device cumulative I/O counters.
    pub io_stat: Option<String>,
    /// `io.pressure` PSI (if available).
    pub io_pressure: Option<CgroupPressure>,
}

/// Read a lightweight snapshot of resource-related cgroup v2 files for display/debugging.
///
/// The values are taken from the provided cgroup directory. For processmaster apps, this should
/// typically be the *parent* app cgroup (e.g. `.../pm-<app>`), so the stats cover the whole subtree.
pub(crate) fn read_resource_snapshot(cgroup_dir: &Path) -> anyhow::Result<CgroupResourceSnapshot> {
    let memory_max = read_trimmed_opt(&cgroup_dir.join("memory.max"))?;
    let memory_current = read_u64_opt(&cgroup_dir.join("memory.current"))?;

    let swap_max = read_trimmed_opt(&cgroup_dir.join("memory.swap.max"))?;
    let swap_current = read_u64_opt(&cgroup_dir.join("memory.swap.current"))?;

    let cpu_max = read_trimmed_opt(&cgroup_dir.join("cpu.max"))?;
    let cpu_stat = read_to_string_opt(&cgroup_dir.join("cpu.stat"))?
        .map(|s| parse_kv_u64_lines(&s))
        .or_else(|| None);

    let cpu_pressure = parse_pressure_opt(read_to_string_opt(&cgroup_dir.join("cpu.pressure"))?);
    let memory_pressure =
        parse_pressure_opt(read_to_string_opt(&cgroup_dir.join("memory.pressure"))?);

    let io_max = read_to_string_opt(&cgroup_dir.join("io.max"))?
        .map(|s| s.trim_end().to_string())
        .filter(|s| !s.trim().is_empty());
    let io_stat = read_to_string_opt(&cgroup_dir.join("io.stat"))?
        .map(|s| s.trim_end().to_string())
        .filter(|s| !s.trim().is_empty());
    let io_pressure = parse_pressure_opt(read_to_string_opt(&cgroup_dir.join("io.pressure"))?);

    Ok(CgroupResourceSnapshot {
        cgroup_dir: cgroup_dir.display().to_string(),
        memory_max,
        memory_current,
        swap_max,
        swap_current,
        cpu_max,
        cpu_stat: Some(cpu_stat.unwrap_or_default()),
        cpu_pressure,
        memory_pressure,
        io_max,
        io_stat,
        io_pressure,
    })
}


