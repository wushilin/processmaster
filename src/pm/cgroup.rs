#![allow(dead_code)]

use anyhow::Context as _;
use nix::errno::Errno;
use nix::sys::signal::{kill as kill_pid, Signal};
use nix::unistd::Pid;
use nix::unistd::setsid;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::fs as tokio_fs;

/// Minimal cgroup-v2 helpers intended to replace external "launcher" features over time.
///
/// NOTE: This module is currently not wired into the daemon. It's meant for evaluation and
/// incremental rollout.

fn write_file(path: &Path, content: &str) -> anyhow::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("open for write: {}", path.display()))?;
    f.write_all(content.as_bytes())
        .with_context(|| format!("write: {}", path.display()))?;
    Ok(())
}

fn ensure_dir(path: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create_dir_all {}", path.display()))?;
    Ok(())
}

/// List pids in a cgroup by reading `cgroup.procs`.
pub(crate) fn list_pids(cgroup_dir: &Path) -> anyhow::Result<Vec<u32>> {
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

/// Async list pids in a cgroup by reading `cgroup.procs`.
pub(crate) async fn list_pids_async(cgroup_dir: &Path) -> anyhow::Result<Vec<u32>> {
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

        // Poll in short intervals so we can observe cancellation.
        loop {
            if cancel.load(Ordering::Relaxed) {
                unsafe { let _ = libc::close(fd); }
                return Ok(false);
            }
            let ready = wait_pidfd(fd, 1000).with_context(|| format!("wait on pidfd for pid={pid}"))?;
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
}

impl Default for Resources {
    fn default() -> Self {
        Self {
            cpu_max: None,
            memory_max: None,
            swap_max: None,
            cpu_weight: None,
            io_weight: None,
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
    Ok(())
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

    apply_resources(&p.cgroup_dir, &p.resources)?;

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

    let cgroup_procs = p.cgroup_dir.join("cgroup.procs");
    let user = p.user.clone();
    let group = p.group.clone();

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
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&cgroup_procs)
                .map_err(|e| std::io::Error::new(e.kind(), format!("open {}: {e}", cgroup_procs.display())))?;
            f.write_all(b"0\n")
                .map_err(|e| std::io::Error::new(e.kind(), format!("write {}: {e}", cgroup_procs.display())))?;

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


