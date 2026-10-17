use crate::pm::app::{
    normalize_memory_string, normalize_swap_string, parse_app_definition_yaml,
    parse_cpu_millicores, AppDefinition,
    LogRotation, LogRotationMode, RestartConfig, RestartPolicy, RestartTolerance, RestartPolicyParsed,
};
use crate::pm::cgroup;
use crate::pm::config::MasterConfig;
use crate::pm::procfs::ProcClock;
use crate::pm::asyncutil::TaskTracker;
use crate::pm::rpc::{EventEntry, Request, Response, StatusEntry};
use base64::Engine as _;
use anyhow::Context as _;
use chrono::{Local, Timelike};
use cron::Schedule;
use nix::sys::signal::Signal;
use nix::sys::signal::kill;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use nix::unistd::{chown, geteuid, getegid, Gid, Uid};
use libc;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::ffi::OsString;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Stdio, ChildStdout, ChildStderr};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use users::{get_group_by_gid, get_group_by_name, get_user_by_name, get_user_by_uid};
use std::str::FromStr;
use std::collections::VecDeque;
// signal-hook kept as dependency for now, but daemon uses tokio signals.
use tokio::net::UnixListener as TokioUnixListener;
use tokio::io::unix::AsyncFd;
use tokio::io::AsyncWriteExt;
use tokio::signal::unix::{signal as unix_signal, SignalKind};
use tokio::time as tokio_time;
use tokio::task::JoinSet;
use tokio::sync::{mpsc as tokio_mpsc, oneshot};
use tokio::io::{AsyncBufReadExt, BufReader as TokioBufReader};
use serde::{Deserialize, Serialize};

mod admin;
mod appstate;
mod defs;
mod events;
mod flags;
mod handlers;
mod host_setup;
mod logs;
mod process;
mod provision;
mod reaper;
mod schedule;
mod server;
mod supervisor;
use admin::*;
use appstate::*;
use defs::*;
use events::*;
use flags::*;
use handlers::*;
use host_setup::*;
use logs::*;
use process::*;
use provision::*;
use reaper::*;
use schedule::*;
use server::*;
use supervisor::*;

// The daemon's surface for the rest of the crate (web console, app definitions).
pub(crate) use admin::admin_action_pids_by_id;
pub(crate) use events::pm_event;
pub(crate) use process::parse_size_spec_bytes;
pub(crate) use server::dispatch_async;

static TASKS: OnceLock<TaskTracker> = OnceLock::new();

pub(crate) fn tasks() -> &'static TaskTracker {
    TASKS.get().expect("TASKS not initialized")
}

#[derive(Debug)]
pub(crate) struct DaemonState {
    pub(crate) cfg: MasterConfig,
    defs: HashMap<String, AppDefinition>,
    supervisors: HashMap<String, SupervisorHandle>,
    run_info: Arc<Mutex<HashMap<String, RunInfo>>>,
    events: Arc<Mutex<VecDeque<EventEntry>>>,
    pub(crate) shutting_down: Arc<AtomicBool>,
    appstate_path: std::path::PathBuf,
    appstate_dirty: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Default)]
struct RunInfo {
    // last time we attempted to start (manual/autostart/schedule/restart)
    last_start_attempt_ms: Option<i64>,
    // last time we actually started (spawned) a new process
    last_started_ms: Option<i64>,
    // "start" or "restart" for the last actual start
    last_start_kind: Option<String>,
    last_exit_code: Option<i32>,
    /// System flags controlled by the daemon logic.
    /// value: expiry timestamp (ms since epoch) or None (never expires)
    system_flags: BTreeMap<SystemFlag, Option<i64>>,
    /// User-defined flags for future fine-grained controls (in-memory only for now).
    /// value: expiry timestamp (ms since epoch) or None (never expires)
    user_flags: BTreeMap<String, Option<i64>>,
    /// System-observed crashes (exits) that resulted in a restart attempt in the last window (timestamps ms since epoch).
    /// Not persisted; resets on daemon restart and manual intervention.
    recent_system_crashes_ms: VecDeque<i64>,
    // last emitted derived phase (for state transition events only)
    last_emitted_phase: Option<Phase>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Starting,
    Restarting,
    Running,
    Stopping,
    Stopped,
    Backoff,
    Failed,
}

impl Phase {
    fn as_str(&self) -> &'static str {
        match self {
            Phase::Starting => "STARTING",
            Phase::Restarting => "RESTARTING",
            Phase::Running => "RUNNING",
            Phase::Stopping => "STOPPING",
            Phase::Stopped => "STOPPED",
            Phase::Backoff => "BACKOFF",
            Phase::Failed => "FAILED",
        }
    }
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy)]
enum StartKind {
    Start,
    Restart,
}

impl StartKind {
    fn as_str(&self) -> &'static str {
        match self {
            StartKind::Start => "start",
            StartKind::Restart => "restart",
        }
    }
}

pub fn run_daemon(cfg: &MasterConfig) -> anyhow::Result<()> {
    // The daemon's entry point: builds the runtime itself (rather than `#[tokio::main]`)
    // so the blocking-pool budget below is explicit.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        // Size the blocking pool explicitly rather than inheriting tokio's default of
        // 512. Every `pmctl logs -f` session parks one of these threads for as long as
        // the client stays connected, and once the pool is exhausted every other
        // spawn_blocking call queues forever -- including stops and status. The
        // semaphore below is the real bound; this just makes the budget visible.
        .max_blocking_threads(MAX_BLOCKING_THREADS)
        .build()
        .context("build tokio runtime")?;
    rt.block_on(run_daemon_async(cfg.clone()))
}

pub async fn run_daemon_async(cfg: MasterConfig) -> anyhow::Result<()> {
    let _ = TASKS.set(TaskTracker::new());
    if !geteuid().is_root() {
        anyhow::bail!("processmaster daemon is not running as root; please start it as root");
    }
    validate_web_console_config(&cfg)?;
    // Preflight: validate config and app definitions before doing side effects (socket bind, cgroups).
    let defs = preflight_validate_and_load_defs(&cfg)?;

    let sock = cfg.sock.clone();
    prepare_socket(&sock)?;
    // bind() creates the socket with 0777 & ~umask, and the daemon inherits whatever
    // umask it was started with -- a unit with UMask=0000 would publish a
    // world-connectable root control socket for the window before the chmod below.
    // Force a restrictive umask across the bind, then restore it.
    let listener = {
        // SAFETY: umask is process-global but this runs during single-threaded startup,
        // before any worker or supervisor task exists.
        let prev_umask = unsafe { libc::umask(0o177) };
        let l = TokioUnixListener::bind(&sock)
            .map_err(|e| anyhow::anyhow!("failed to bind socket {}: {e}", sock.display()));
        unsafe {
            libc::umask(prev_umask);
        }
        l?
    };

    // The socket's permissions are the only access control on the RPC protocol, so a
    // directory anyone can write is a problem regardless of the socket's own mode: a
    // local user could unlink and replace it. Warn rather than refuse, since operators
    // may deliberately use /tmp.
    if let Some(parent) = sock.parent()
        && let Ok(md) = std::fs::metadata(parent) {
            let mode = std::os::unix::fs::MetadataExt::mode(&md);
            let world_writable = mode & 0o002 != 0;
            let sticky = mode & 0o1000 != 0;
            if world_writable && !sticky {
                pm_event(
                    "rpc",
                    None,
                    format!(
                        "WARNING socket directory {} is world-writable without the sticky bit;                          consider unix_socket.path under /run/processmaster",
                        parent.display()
                    ),
                );
            }
        }

    let shutting_down = Arc::new(AtomicBool::new(false));

    // Apply socket ownership/mode while we still have the original privileges.
    apply_socket_settings(&cfg)?;

    // Apply master cgroup limits and move this process into the master cgroup.
    // This must happen before dropping privileges if root is required.
    setup_master_cgroup_or_instructions(&cfg)?;
    // Print the effective master cgroup root (important for unprivileged mode).
    pm_event(
        "cgroup",
        None,
        format!(
            "master_cgroup_effective configured_root={} configured_name={} effective_path={}",
            cfg.cgroup_root,
            cfg.cgroup_name,
            cgroup::master_dir(&cfg).display()
        ),
    );

    // Default daemon logging to file (in addition to journald via stderr):
    // <config_directory>/logs/processmaster.log (rotate 10 MiB, 10 backups, gzip).
    start_daemon_log_file(&cfg);

    // Build metadata (from build.rs) for easy debugging in deployed environments.
    let build_time = option_env!("PROCESSMASTER_BUILD_TIME").unwrap_or("unknown");
    let build_host = option_env!("PROCESSMASTER_BUILD_HOST").unwrap_or("unknown");
    pm_event(
        "boot",
        None,
        format!("build_time={build_time} build_host={build_host}"),
    );

    // Load sysflag rules once (runtime-configured). Used for chained clears/also_sets.
    let _ = FLAG_RULES.set(load_flag_rules(&cfg));

    let appstate_path = cfg.config_directory.join("appstate.json");
    let appstate_dirty = Arc::new(AtomicBool::new(false));

    let state = Arc::new(Mutex::new(DaemonState {
        cfg: cfg.clone(),
        defs,
        supervisors: HashMap::new(),
        run_info: Arc::new(Mutex::new(HashMap::new())),
        events: Arc::new(Mutex::new(VecDeque::new())),
        shutting_down: Arc::clone(&shutting_down),
        appstate_path,
        appstate_dirty: Arc::clone(&appstate_dirty),
    }));

    // Best-effort: restore persisted app state (user flags) from appstate.json.
    restore_app_state_best_effort(Arc::clone(&state));

    // Start/update restart supervisors for apps that have restart configured.
    refresh_supervisors(&state)?;

    // On daemon boot (including after a restart), emit a reconcile snapshot so operators can
    // see what was already running and what we plan to manage.
    emit_reconcile_snapshot(&state, "boot");

    // If processmaster crashed previously while using capture-only stdout/stderr, services may
    // still be running but their stdout/stderr pipes are no longer drained. Best-effort:
    // - if enabled: force-restart to reattach logging + supervision
    // - if disabled: stop (enforce desired state)
    restart_or_stop_running_services_on_boot(Arc::clone(&state)).await;

    // Reap any child processes we might spawn (launcher exec-mode services, etc.).
    start_child_reaper_thread();

    // Log rotation + cleanup (runs every minute).
    start_log_maintenance_thread(Arc::clone(&state));

    // Cron-like scheduler (runs at minute boundaries).
    start_scheduler_thread(Arc::clone(&state));
    // Periodically stop scheduled jobs that exceed their configured max_time_per_run.
    start_overtime_scheduler_thread(Arc::clone(&state));

    // Periodically prune expired user flags (in-memory) and emit expiry events.
    start_flag_maintenance_thread(Arc::clone(&state));
    // Periodically flush appstate.json if dirty (atomic write).
    start_appstate_flush_thread(Arc::clone(&state));

    // Periodically emit task stats so we can detect leaks (active tasks not returning).
    start_task_stats_reporter(Arc::clone(&state));

    // Optional embedded web console (axum).
    crate::pm::web_console::start_web_console(Arc::clone(&state));

    // Supervisor-like behavior: start all enabled services on daemon boot.
    if let Err(e) = start_enabled_services_async(&state).await {
        eprintln!("autostart error: {e}");
    }

    start_signal_listener_async(Arc::clone(&shutting_down));

    pm_event("rpc", None, format!("listening sock={}", sock.display()));
    // Admin actions whose code a non-root user could modify are refused at run time;
    // say so loudly at startup rather than when someone clicks.
    for (id, a) in &cfg.admin_actions {
        if let Err(e) = crate::pm::config::ensure_admin_action_trusted(id, &a.command, &[0])
            .and_then(|()| crate::pm::config::ensure_admin_cwd_trusted(&[0]))
        {
            pm_event("admin_action", None, format!("WARNING action={id} will_be_refused=true err={e:#}"));
        }
    }

    // Async accept loop. Each connection holds a permit: without a cap, a client that
    // opens thousands of idle connections exhausts the root daemon's descriptors, and
    // then log reopen, spawns and cgroup reads start failing for every service.
    const MAX_RPC_CONNECTIONS: usize = 256;
    let conn_permits = Arc::new(tokio::sync::Semaphore::new(MAX_RPC_CONNECTIONS));
    while !shutting_down.load(Ordering::Relaxed) {
        tokio::select! {
            r = listener.accept() => {
                match r {
                    Ok((stream, _addr)) => {
                        let Ok(permit) = Arc::clone(&conn_permits).try_acquire_owned() else {
                            // Saturated: drop the connection rather than queue it.
                            drop(stream);
                            continue;
                        };
                        let st = Arc::clone(&state);
                        tasks().spawn(async move {
                            let _permit = permit;
                            if let Err(e) = handle_connection_async(st, stream).await {
                                eprintln!("rpc error: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("accept error: {e}");
                        tokio_time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
            _ = tokio_time::sleep(Duration::from_millis(200)) => {
                // periodic wake so we can observe shutting_down without relying on accept.
            }
        }
    }

    pm_event("shutdown", None, "signal received; shutting down (best-effort stop all services)");
    graceful_shutdown_async(&state).await?;
    // Best-effort: remove socket file so clients fail fast until restarted.
    let _ = fs::remove_file(&sock);
    Ok(())
}

fn validate_web_console_config(cfg: &MasterConfig) -> anyhow::Result<()> {
    let wc = &cfg.web_console;
    if !wc.enabled {
        return Ok(());
    }

    // bind/port sanity
    let _addr = crate::pm::config::parse_bind_addr(&wc.bind, wc.port)
        .map_err(|e| anyhow::anyhow!("web_console bind/port invalid: {e}"))?;

    // basic auth required
    anyhow::ensure!(
        !wc.auth.basic.users.is_empty(),
        "web_console.enabled=true but web_console.auth.basic.users is empty"
    );
    for u in &wc.auth.basic.users {
        let t = u.trim();
        anyhow::ensure!(
            t.contains(':'),
            "invalid web_console.auth.basic.users entry (expected 'user:hash'): {t:?}"
        );
    }

    // The bootstrap credential is published in the README and in examples/, so leaving
    // it in place is equivalent to no authentication at all — and this console can run
    // arbitrary root commands via admin_actions. Warn on every startup, and refuse
    // outright if the console is also reachable off-host.
    if wc.auth.basic.users.iter().any(|u| {
        u.trim() == crate::pm::config::DEFAULT_BOOTSTRAP_BASIC_AUTH_ENTRY
    }) {
        let loopback_only = wc.bind.trim() == "127.0.0.1" || wc.bind.trim() == "::1";
        anyhow::ensure!(
            loopback_only,
            "web_console is bound to {} with the default bootstrap credentials still in \
             place. That password is published in the README, and the console can run \
             admin_actions as root. Generate a real entry with `pmctl password generate` \
             and set web_console.auth.basic.users, or bind to 127.0.0.1 for local-only use.",
            wc.bind
        );
        pm_event(
            "web",
            None,
            "WARNING default bootstrap web console credentials are in use \
             (loopback-only); replace them via `pmctl password generate`",
        );
    }

    if wc.tls.enabled {
        anyhow::ensure!(
            wc.tls.server_cert_pem.as_ref().is_some_and(|s| !s.trim().is_empty()),
            "web_console.tls.enabled=true but web_console.tls.server_cert_pem is not set"
        );
        anyhow::ensure!(
            wc.tls.server_key_pem.as_ref().is_some_and(|s| !s.trim().is_empty()),
            "web_console.tls.enabled=true but web_console.tls.server_key_pem is not set"
        );
        if wc.tls.mtls {
            anyhow::ensure!(
                wc.tls.ca_pem.as_ref().is_some_and(|s| !s.trim().is_empty()),
                "web_console.tls.mtls=true but web_console.tls.ca_pem is not set"
            );
        }
    }

    Ok(())
}

fn start_signal_listener_async(flag: Arc<AtomicBool>) {
    tasks().spawn(async move {
        // Prefer tokio's signal handling (required for future web console anyway).
        let mut term = unix_signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut int = unix_signal(SignalKind::interrupt()).expect("SIGINT handler");
        tokio::select! {
            _ = term.recv() => { flag.store(true, Ordering::Relaxed); }
            _ = int.recv() => { flag.store(true, Ordering::Relaxed); }
        }
    });
}

async fn graceful_shutdown_async(state: &Arc<Mutex<DaemonState>>) -> anyhow::Result<()> {
    // Best-effort stop all services so we don't leave processes with broken stdout/stderr pipes.
    let (sock, cfg, shutting_down) = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        (st.cfg.sock.clone(), st.cfg.clone(), Arc::clone(&st.shutting_down))
    };
    shutting_down.store(true, Ordering::Relaxed);
    // Stop services in parallel (best-effort).
    stop_all_services_best_effort(Arc::clone(state)).await;
    // Final sweep: ensure app cgroups are empty before declaring shutdown complete.
    drain_all_cgroups_best_effort(Arc::clone(state)).await;
    let _ = cfg;
    pm_event_state(state, "shutdown", None, format!("done; closing sock={}", sock.display()));
    Ok(())
}

async fn stop_all_services_best_effort(state: Arc<Mutex<DaemonState>>) {
    let names: Vec<String> = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        let mut v: Vec<String> = st.defs.keys().cloned().collect();
        v.sort();
        v
    };
    if names.is_empty() {
        return;
    }
    let mut js: JoinSet<()> = JoinSet::new();
    for name in names {
        let st = Arc::clone(&state);
        js.spawn(async move {
            // Best-effort: use the per-app supervisor stop path so it is consistent with normal shutdown.
            let _ = shutdown_stop_via_supervisor_async(&st, &name).await;
        });
    }
    while js.join_next().await.is_some() {}
}

async fn drain_all_cgroups_best_effort(state: Arc<Mutex<DaemonState>>) {
    let (cfg, names, events) = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        let mut v: Vec<String> = st.defs.keys().cloned().collect();
        v.sort();
        (st.cfg.clone(), v, Arc::clone(&st.events))
    };
    if names.is_empty() {
        return;
    }
    push_event(&events, "shutdown", None, format!("drain_cgroups_begin count={}", names.len()));

    let mut js: JoinSet<()> = JoinSet::new();
    for name in names {
        let cfg2 = cfg.clone();
        let ev = Arc::clone(&events);
        js.spawn(async move {
            let _ = tasks().spawn_blocking(move || {
                match cgroup_running(&cfg2, &name) {
                    Ok(true) => {
                        push_event(&ev, "shutdown", Some(&name), "drain decision=kill-all");
                        let _ = launcher_kill_all(&cfg2, &name);
                        let _ = wait_until_empty(&cfg2, &name, Duration::from_millis(5000));
                    }
                    Ok(false) => {}
                    Err(_) => {}
                }
            }).await;
        });
    }
    while js.join_next().await.is_some() {}
    push_event(&events, "shutdown", None, "drain_cgroups_done");
}

async fn restart_or_stop_running_services_on_boot(state: Arc<Mutex<DaemonState>>) {
    let (cfg, defs, events) = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        (st.cfg.clone(), st.defs.clone(), Arc::clone(&st.events))
    };

    let mut actions: Vec<(String, bool)> = vec![]; // (app, enabled)
    for (name, def) in defs {
        match cgroup_running(&cfg, &name) {
            Ok(true) => actions.push((name, def.enabled)),
            Ok(false) => {}
            Err(_) => {}
        }
    }
    if actions.is_empty() {
        return;
    }

    push_event(&events, "reconcile", None, format!("boot_found_running count={}", actions.len()));

    let mut js: JoinSet<()> = JoinSet::new();
    for (name, enabled) in actions {
        let st = Arc::clone(&state);
        let cfg2 = cfg.clone();
        let ev = Arc::clone(&events);
        js.spawn(async move {
            if enabled {
                push_event(&ev, "reconcile", Some(&name), "decision=restart reason=found_running");
                // Force-kill then restart to ensure fresh stdout/stderr attachment.
                let cfg3 = cfg2.clone();
                let name3 = name.clone();
                let _ = tasks().spawn_blocking(move || {
                    let _ = launcher_kill_all(&cfg3, &name3);
                    let _ = wait_until_empty(&cfg3, &name3, Duration::from_millis(5000));
                })
                .await;
                let _ = boot_start_via_supervisor_async(&st, &name).await;
            } else {
                push_event(&ev, "reconcile", Some(&name), "decision=stop reason=disabled_but_running");
                let _ = shutdown_stop_via_supervisor_async(&st, &name).await;
            }
        });
    }
    while js.join_next().await.is_some() {}
}

fn start_task_stats_reporter(state: Arc<Mutex<DaemonState>>) {
    tasks().spawn(async move {
        let events = {
            let st = state.lock().unwrap_or_else(|p| p.into_inner());
            Arc::clone(&st.events)
        };
        let mut ticker = tokio_time::interval(Duration::from_secs(30));
        loop {
            ticker.tick().await;
            // If shutting down, stop reporting.
            if state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .shutting_down
                .load(Ordering::Relaxed)
            {
                break;
            }
            let t = tasks();
            push_event(
                &events,
                "taskstats",
                None,
                format!(
                    "code=TASK_STATS active_async={} total_async={} active_blocking={} total_blocking={}",
                    t.active_count(),
                    t.total_spawned(),
                    t.active_blocking_count(),
                    t.total_blocking_spawned(),
                ),
            );
        }
    });
}

/// Size of tokio's blocking pool. Follow sessions park threads here, so this and
/// [`MAX_CONCURRENT_LOG_FOLLOWS`] together guarantee headroom for supervision work.
const MAX_BLOCKING_THREADS: usize = 512;

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    // ---- child reaping ---------------------------------------------------------
    // Regression: every non-scheduled service start dropped its `Child` and relied on
    // the cgroup waiter, which never calls waitpid. Once the reaper stopped doing
    // waitpid(-1), each service exit left a <defunct> under the daemon.

    fn proc_state(pid: u32) -> Option<char> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // "<pid> (<comm>) <state> ..." — comm may contain spaces/parens, so anchor
        // on the last ')'.
        let rest = stat.rsplit_once(')')?.1;
        rest.split_whitespace().next()?.chars().next()
    }

    fn wait_reaped(pid: u32, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            match proc_state(pid) {
                // Reaped: the /proc entry is gone.
                None => return true,
                Some(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
        false
    }

    #[test]
    fn disowned_service_child_is_reaped_not_left_defunct() {
        // Control: a dropped, unregistered child really does become a zombie, so the
        // assertion below is checking something.
        let ctl = Command::new("sleep").arg("30").stdin(Stdio::null()).spawn().unwrap();
        let ctl_pid = ctl.id();
        drop(ctl);
        let _ = kill(Pid::from_raw(ctl_pid as i32), Signal::SIGKILL);
        let deadline = Instant::now() + Duration::from_secs(3);
        while proc_state(ctl_pid) != Some('Z') && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(proc_state(ctl_pid), Some('Z'), "control child should be a zombie");
        // Clean the control up so the test process does not leak it.
        let _ = waitpid(Pid::from_raw(ctl_pid as i32), None);

        // The fix: same flow, but through disown_service_child + the reaper.
        start_child_reaper_thread();
        let child = Command::new("sleep").arg("30").stdin(Stdio::null()).spawn().unwrap();
        let pid = child.id();
        disown_service_child(child);
        assert!(disowned_pids().lock().unwrap().contains(&(pid as i32)));
        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
        assert!(
            wait_reaped(pid, Duration::from_secs(5)),
            "pid {pid} still present (state={:?}) after kill — reaper did not collect it",
            proc_state(pid)
        );
        assert!(
            !disowned_pids().lock().unwrap().contains(&(pid as i32)),
            "reaped pid must be dropped from the registry so a reused pid is never waited on"
        );
    }

    // ---- stop-behavior matrix --------------------------------------------------
    // Whatever a service child does — exit instantly, ignore the stop signal,
    // outlive its stop deadline, daemonize — once the daemon lets go of the Child
    // handle the reaper must collect it, and it must never touch a child whose
    // handle is still owned (scheduled jobs). One test per behavior.

    fn spawn_sh(script: &str) -> std::process::Child {
        Command::new("sh")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    fn wait_zombie(pid: u32, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if proc_state(pid) == Some('Z') {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[test]
    fn quick_exit_child_already_dead_at_disown_is_still_reaped() {
        // A service can exit before the daemon even finishes its bookkeeping, so the
        // pid enters the registry as a zombie. WNOHANG must still collect it.
        start_child_reaper_thread();
        let child = spawn_sh("exit 0");
        let pid = child.id();
        assert!(wait_zombie(pid, Duration::from_secs(3)), "quick-exit child should be a zombie");
        disown_service_child(child);
        assert!(
            wait_reaped(pid, Duration::from_secs(5)),
            "already-dead child was not reaped (state={:?})",
            proc_state(pid)
        );
        assert!(!disowned_pids().lock().unwrap().contains(&(pid as i32)));
    }

    #[test]
    fn sigterm_immune_child_survives_term_then_is_reaped_after_kill() {
        // The "refuses to die" service: ignores the stop signal, dies only to the
        // cgroup force-kill. The reaper must neither drop it from the registry while
        // it is alive nor leave a zombie once SIGKILL lands.
        start_child_reaper_thread();
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("trap '' TERM; echo ready; exec >/dev/null; sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // Wait for "ready" so SIGTERM cannot race the trap installation.
        let mut out = child.stdout.take().unwrap();
        let mut buf = [0u8; 6];
        std::io::Read::read_exact(&mut out, &mut buf).unwrap();
        assert_eq!(&buf, b"ready\n");

        let pid = child.id();
        disown_service_child(child);
        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
        // Give the reaper a few cycles: the child must still be alive and tracked.
        std::thread::sleep(Duration::from_millis(1200));
        assert!(
            matches!(proc_state(pid), Some(s) if s != 'Z'),
            "TERM-immune child should still be running, got {:?}",
            proc_state(pid)
        );
        assert!(
            disowned_pids().lock().unwrap().contains(&(pid as i32)),
            "a live disowned child must stay registered"
        );
        // Escalation (stand-in for cgroup.kill).
        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
        assert!(
            wait_reaped(pid, Duration::from_secs(5)),
            "TERM-immune child not reaped after SIGKILL (state={:?})",
            proc_state(pid)
        );
        assert!(!disowned_pids().lock().unwrap().contains(&(pid as i32)));
    }

    #[test]
    fn timed_out_stop_helper_is_reaped_after_the_force_kill() {
        // Mirror of run_stop_command_in_context's timeout contract: on
        // "stop_command_timeout" the Child is dropped, the pid handed to the reaper,
        // and the caller cgroup-kills the helper. Nothing may stay <defunct>.
        start_child_reaper_thread();
        let child = spawn_sh("sleep 30");
        let pid = child.id();
        drop(child);
        disown_child_pid(pid);
        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
        assert!(
            wait_reaped(pid, Duration::from_secs(5)),
            "timed-out stop helper not reaped (state={:?})",
            proc_state(pid)
        );
    }

    #[test]
    fn daemonizing_child_is_reaped_when_it_exits_immediately() {
        // A service that double-forks: the direct child exits at once, the grandchild
        // is reparented to init and is not ours to reap. The direct child must not
        // linger as a zombie.
        start_child_reaper_thread();
        let child = spawn_sh("sleep 2 & exit 0");
        let pid = child.id();
        disown_service_child(child);
        assert!(
            wait_reaped(pid, Duration::from_secs(5)),
            "daemonizing child not reaped (state={:?})",
            proc_state(pid)
        );
    }

    #[test]
    fn restart_storm_of_mixed_behaviors_leaves_no_zombies() {
        // A reload cycling many services at once, with every temperament in the mix:
        // instant exits (clean and failing), long sleepers, TERM-ignorers. After
        // TERM-then-KILL, every single one must be reaped and deregistered.
        start_child_reaper_thread();
        let behaviors = [
            "exit 0",
            "exit 3",
            "sleep 30",
            "trap '' TERM; sleep 30",
            "sleep 2 & exit 0",
        ];
        let pids: Vec<u32> = (0..15)
            .map(|i| {
                let child = spawn_sh(behaviors[i % behaviors.len()]);
                let pid = child.id();
                disown_service_child(child);
                pid
            })
            .collect();
        for &pid in &pids {
            let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
        }
        // The TERM-immune ones need the escalation; ESRCH on already-reaped pids is fine.
        std::thread::sleep(Duration::from_millis(300));
        for &pid in &pids {
            let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
        }
        for &pid in &pids {
            assert!(
                wait_reaped(pid, Duration::from_secs(10)),
                "pid {pid} left behind (state={:?}) after the restart storm",
                proc_state(pid)
            );
        }
        let set = disowned_pids().lock().unwrap();
        for &pid in &pids {
            assert!(!set.contains(&(pid as i32)), "pid {pid} still registered after reap");
        }
    }

    #[test]
    fn reaper_never_steals_an_owned_childs_exit_status() {
        // The design constraint that forbids waitpid(-1): a scheduled job's Child is
        // owned by spawn_process_waiter, which needs the real exit status. Even while
        // that child sits as an un-waited zombie, the reaper must leave it alone.
        start_child_reaper_thread();
        let mut child = spawn_sh("exit 7");
        let pid = child.id();
        // Let it die and give the reaper several cycles over the zombie.
        assert!(wait_zombie(pid, Duration::from_secs(3)));
        std::thread::sleep(Duration::from_millis(1500));
        let st = child.wait().expect("owner must still be able to wait on its child");
        assert_eq!(st.code(), Some(7), "exit status must reach the owner, not the reaper");
    }

    // ---- parse_size_spec_bytes -------------------------------------------------
    // Feeds both cgroup memory limits and log rotation thresholds, so a wrong answer
    // here silently writes a wrong memory.max.

    #[test]
    fn size_plain_integer_is_bytes() {
        assert_eq!(parse_size_spec_bytes("1234").unwrap(), 1234);
        assert_eq!(parse_size_spec_bytes("0").unwrap(), 0);
        assert_eq!(parse_size_spec_bytes("  42  ").unwrap(), 42);
    }

    #[test]
    fn size_decimal_units_are_powers_of_1000() {
        assert_eq!(parse_size_spec_bytes("10k").unwrap(), 10_000);
        assert_eq!(parse_size_spec_bytes("10m").unwrap(), 10_000_000);
        assert_eq!(parse_size_spec_bytes("2g").unwrap(), 2_000_000_000);
        // The trailing `b` is optional and case is irrelevant.
        assert_eq!(parse_size_spec_bytes("10MB").unwrap(), 10_000_000);
        assert_eq!(parse_size_spec_bytes("10mb").unwrap(), 10_000_000);
    }

    #[test]
    fn size_binary_units_are_powers_of_1024() {
        assert_eq!(parse_size_spec_bytes("1ki").unwrap(), 1024);
        assert_eq!(parse_size_spec_bytes("64MiB").unwrap(), 64 * 1024 * 1024);
        assert_eq!(parse_size_spec_bytes("1GiB").unwrap(), 1024 * 1024 * 1024);
    }

    #[test]
    fn size_accepts_fractions_only_with_a_unit() {
        assert_eq!(parse_size_spec_bytes("1.5GiB").unwrap(), 1_610_612_736);
        // Documented quirk: a bare decimal has no unit boundary to split on and is
        // rejected. Pinned so a future refactor makes the change deliberately.
        assert!(parse_size_spec_bytes("1.5").is_err());
    }

    #[test]
    fn size_rejects_garbage() {
        assert!(parse_size_spec_bytes("").is_err());
        assert!(parse_size_spec_bytes("   ").is_err());
        assert!(parse_size_spec_bytes("abc").is_err());
        assert!(parse_size_spec_bytes("10x").is_err());
        assert!(parse_size_spec_bytes("m10").is_err());
    }

    // ---- parse_flag_ttl_ms -----------------------------------------------------

    #[test]
    fn ttl_single_and_compound_units() {
        assert_eq!(parse_flag_ttl_ms("1500ms").unwrap(), 1500);
        assert_eq!(parse_flag_ttl_ms("10s").unwrap(), 10_000);
        assert_eq!(parse_flag_ttl_ms("10m").unwrap(), 600_000);
        assert_eq!(parse_flag_ttl_ms("2h").unwrap(), 7_200_000);
        assert_eq!(parse_flag_ttl_ms("1d").unwrap(), 86_400_000);
        assert_eq!(parse_flag_ttl_ms("3h1m").unwrap(), 3 * 3_600_000 + 60_000);
        assert_eq!(
            parse_flag_ttl_ms("5d4h3m2s1ms").unwrap(),
            5 * 86_400_000 + 4 * 3_600_000 + 3 * 60_000 + 2 * 1_000 + 1
        );
    }

    #[test]
    fn ttl_requires_descending_units_without_repeats() {
        assert!(parse_flag_ttl_ms("1m3h").is_err(), "ascending units must be rejected");
        assert!(parse_flag_ttl_ms("1h1h").is_err(), "repeated units must be rejected");
        assert!(parse_flag_ttl_ms("1m1m").is_err());
    }

    #[test]
    fn ttl_is_case_insensitive_and_rejects_malformed_input() {
        assert_eq!(parse_flag_ttl_ms("2H").unwrap(), 7_200_000);
        assert!(parse_flag_ttl_ms("").is_err());
        assert!(parse_flag_ttl_ms("10").is_err(), "missing unit");
        assert!(parse_flag_ttl_ms("h").is_err(), "missing number");
        assert!(parse_flag_ttl_ms("10y").is_err(), "unknown unit");
        assert!(parse_flag_ttl_ms("1h 1m").is_err(), "whitespace is not allowed");
        assert!(parse_flag_ttl_ms("18446744073709551615d").is_err(), "overflow");
    }

    // ---- normalize_cron_expr ---------------------------------------------------

    #[test]
    fn cron_five_fields_gets_a_seconds_column() {
        assert_eq!(normalize_cron_expr("0 * * * *").unwrap(), "0 0 * * * *");
        assert_eq!(normalize_cron_expr("*/15 2 * * MON").unwrap(), "0 */15 2 * * MON");
        // Surrounding whitespace is trimmed before the seconds column is prepended.
        assert_eq!(normalize_cron_expr("  15 2 * * *  ").unwrap(), "0 15 2 * * *");
    }

    #[test]
    fn cron_rejects_field_counts_we_cannot_honour() {
        // 6 fields would imply seconds resolution, which the scheduler cannot provide.
        assert!(normalize_cron_expr("0 0 * * * *").is_err());
        assert!(normalize_cron_expr("* * * *").is_err());
        assert!(normalize_cron_expr("").is_err());
        assert!(normalize_cron_expr("   ").is_err());
    }

    #[test]
    fn cron_shorthands_pass_through() {
        assert_eq!(normalize_cron_expr("@hourly").unwrap(), "@hourly");
        assert_eq!(normalize_cron_expr("@daily").unwrap(), "@daily");
    }

    #[test]
    fn cron_normalized_output_is_accepted_by_the_cron_crate() {
        use std::str::FromStr as _;
        // The whole point of normalization is that the result parses downstream.
        for expr in ["0 * * * *", "*/15 2 * * MON", "15 2 * * *", "0 0 1 JAN *"] {
            let norm = normalize_cron_expr(expr).unwrap();
            assert!(
                cron::Schedule::from_str(&norm).is_ok(),
                "normalized {expr:?} -> {norm:?} was rejected by the cron crate"
            );
        }
    }

    // ---- parse_signal ----------------------------------------------------------

    #[test]
    fn signal_accepts_both_prefixed_and_bare_names_any_case() {
        assert_eq!(parse_signal("SIGTERM").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("TERM").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("sigterm").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("  SIGKILL ").unwrap(), Signal::SIGKILL);
        assert_eq!(parse_signal("USR1").unwrap(), Signal::SIGUSR1);
    }

    #[test]
    fn signal_rejects_unknown_names() {
        assert!(parse_signal("SIGDANCE").is_err());
        assert!(parse_signal("").is_err());
        assert!(parse_signal("9").is_err(), "numeric signals are not supported");
    }

    // ---- cgroup control-file payloads -----------------------------------------

    #[test]
    fn cpu_max_payload_matches_cgroup_v2_format() {
        assert_eq!(to_cpu_max_string("MAX").unwrap(), "max 100000\n");
        assert_eq!(to_cpu_max_string("max").unwrap(), "max 100000\n");
        // 100 millicores of a 100ms period is a 10ms quota.
        assert_eq!(to_cpu_max_string("100m").unwrap(), "10000 100000\n");
        assert_eq!(to_cpu_max_string("1").unwrap(), "100000 100000\n");
        assert_eq!(to_cpu_max_string("1.5").unwrap(), "150000 100000\n");
        // An explicit "quota period" pair is passed through untouched.
        assert_eq!(to_cpu_max_string("20000 100000").unwrap(), "20000 100000\n");
    }

    // ---- symlink-safe root file operations --------------------------------------
    //
    // Security regressions. Provisioning runs as root against a tree the *service*
    // user owns, so every one of these must refuse to traverse a planted symlink.

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let mut nonce = [0u8; 6];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let p = std::env::temp_dir().join(format!(
            "pm-test-{tag}-{}",
            nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        std::fs::create_dir_all(&p).expect("mkdir");
        p
    }

    fn provision_test_def(workdir: &Path, entries_yaml: &str) -> AppDefinition {
        let yaml = format!(
            "application: provtest\nprocess:\n  working_directory: {}\n  start_command: [\"/bin/true\"]\nprovisioning:\n{entries_yaml}",
            workdir.display()
        );
        crate::pm::app::parse_app_definition_yaml(&yaml, &workdir.join("provtest.yaml"), None, None)
            .expect("parse test def")
    }

    // Regression: a panicked task in a bulk operation used to vanish from the reply and
    // leave its slot unfilled, so every target queued behind it was silently skipped.
    #[tokio::test]
    async fn fan_out_reports_a_panic_and_still_runs_every_target() {
        let targets: Vec<String> = (0..40).map(|i| format!("t{i:02}")).collect();
        let results = fan_out(targets.clone(), 4, |t| async move {
            if t == "t03" {
                panic!("boom");
            }
            Ok(t)
        })
        .await;
        assert_eq!(results.iter().map(|(t, _)| t.clone()).collect::<Vec<_>>(), targets);
        for (t, r) in &results {
            match r {
                Ok(v) => assert_eq!(v, t),
                Err(e) => {
                    assert_eq!(t, "t03");
                    assert!(format!("{e}").contains("panic"), "{e}");
                }
            }
        }
        assert_eq!(results.iter().filter(|(_, r)| r.is_err()).count(), 1);
    }

    // Regression: a log that cannot be written used to end the pump, dropping the pipe's
    // read end so the service died of SIGPIPE on its next write. A shared full disk
    // would take every service down at once. The pump must keep draining and resume
    // writing once the log is usable again.
    #[tokio::test]
    async fn log_pump_drains_while_the_log_is_unwritable_and_then_resumes() {
        let dir = tmpdir("logpump");
        let def = provision_test_def(&dir, "  []");
        let log = dir.join("out.log");
        std::fs::create_dir(&log).unwrap(); // a directory where the log should be
        let (rd, wr) = nix::unistd::pipe().unwrap();
        let pump = tokio::spawn(log_pump_async(def, log.clone(), rd));
        let mut wr = std::fs::File::from(wr);

        // Unwritable: output is discarded, but the pipe stays open (a write would
        // otherwise fail with EPIPE).
        wr.write_all(b"lost\n").unwrap();
        tokio_time::sleep(Duration::from_millis(50)).await;
        std::fs::remove_dir(&log).unwrap();
        tokio_time::sleep(LOG_REOPEN_RETRY + Duration::from_millis(50)).await;
        wr.write_all(b"kept\n").unwrap();
        drop(wr);

        pump.await.unwrap().unwrap();
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "kept\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Regression: the marker used to be a bare "provisioned once" flag, so replacing a
    // setcap'd binary (a redeploy) silently lost the capability until the marker was
    // deleted by hand. Mode is used here as the observable stand-in for setcap, since
    // tests do not run as root; both are dropped the same way by a file replacement.
    #[test]
    fn replacing_a_provisioned_file_triggers_reprovision() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tmpdir("reprov");
        let bin = d.join("server");
        std::fs::write(&bin, b"v1").unwrap();
        let def = provision_test_def(&d, "  - path: ./server\n    mode: \"0750\"\n  - path: ./data\n");
        let marker = d.join(".pm_provisioned");

        assert_eq!(provisioning_staleness(&def, &marker).as_deref(), Some("marker_missing"));
        maybe_provision_workdir(&def).unwrap();
        assert_eq!(std::fs::metadata(&bin).unwrap().permissions().mode() & 0o7777, 0o750);
        assert_eq!(provisioning_staleness(&def, &marker), None, "fresh marker must be current");

        // A file created inside a directory target must not count as a change.
        std::fs::write(d.join("data").join("x"), b"x").unwrap();
        assert_eq!(provisioning_staleness(&def, &marker), None);

        // Redeploy: new build written to a temp name and renamed over the old one.
        let staged = d.join("server.new");
        std::fs::write(&staged, b"v2").unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::rename(&staged, &bin).unwrap();
        let why = provisioning_staleness(&def, &marker).expect("replacement must be detected");
        assert!(why.starts_with("target_changed idx=0"), "{why}");

        maybe_provision_workdir(&def).unwrap();
        assert_eq!(std::fs::metadata(&bin).unwrap().permissions().mode() & 0o7777, 0o750);
        assert_eq!(provisioning_staleness(&def, &marker), None);

        // Byte-identical redeploy still gets a fresh inode, so it is still detected:
        // this is why the fingerprint is stat identity rather than a content hash.
        let staged = d.join("server.new");
        std::fs::write(&staged, b"v2").unwrap();
        std::fs::rename(&staged, &bin).unwrap();
        assert!(provisioning_staleness(&def, &marker).is_some());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn spec_change_and_legacy_marker_trigger_reprovision() {
        let d = tmpdir("reprov-spec");
        std::fs::write(d.join("server"), b"v1").unwrap();
        let marker = d.join(".pm_provisioned");

        let def = provision_test_def(&d, "  - path: ./server\n    mode: \"0750\"\n");
        // Markers from older releases (empty, or "provisioned_at_ms=...") are accepted
        // and simply trigger one more, idempotent, provisioning pass.
        std::fs::write(&marker, "").unwrap();
        assert_eq!(
            provisioning_staleness(&def, &marker).as_deref(),
            Some("marker_legacy_or_malformed")
        );
        maybe_provision_workdir(&def).unwrap();
        assert_eq!(provisioning_staleness(&def, &marker), None);
        std::fs::write(&marker, "provisioned_at_ms=1\n").unwrap();
        assert_eq!(
            provisioning_staleness(&def, &marker).as_deref(),
            Some("marker_legacy_or_malformed")
        );
        maybe_provision_workdir(&def).unwrap();
        assert_eq!(provisioning_staleness(&def, &marker), None);

        let def2 = provision_test_def(&d, "  - path: ./server\n    mode: \"0700\"\n");
        assert_eq!(provisioning_staleness(&def2, &marker).as_deref(), Some("spec_changed idx=0"));
        let _ = std::fs::remove_dir_all(&d);
    }

    // ---- symlink-safe provisioning ------------------------------------------------
    //
    // Regression: provisioning checked only the *final* path component, so a service
    // that replaced `app` with a symlink to /usr got root to chown/chmod `/usr/bin`
    // for an entry like `./app/bin`.

    #[test]
    fn provisioning_refuses_a_symlinked_intermediate_directory() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tmpdir("prov-midlink");
        let outside = tmpdir("prov-outside");
        std::fs::create_dir(outside.join("bin")).unwrap();
        std::fs::set_permissions(outside.join("bin"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(&outside, d.join("app")).unwrap();
        let def = provision_test_def(&d, "  - path: ./app/bin\n    mode: \"0700\"\n");

        let e = maybe_provision_workdir(&def).unwrap_err();
        assert!(format!("{e:#}").contains("symlink"), "{e:#}");
        let mode = std::fs::metadata(outside.join("bin")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "chmod must not have gone through the symlink");
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn provisioning_refuses_a_final_symlink_and_parent_escapes() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tmpdir("prov-link");
        let victim = d.join("victim");
        std::fs::write(&victim, b"secret").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&victim, d.join("link")).unwrap();

        let def = provision_test_def(&d, "  - path: ./link\n    mode: \"0777\"\n");
        assert!(maybe_provision_workdir(&def).is_err());
        assert_eq!(std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777, 0o600);

        let def = provision_test_def(&d, "  - path: ../x\n");
        assert!(format!("{:#}", maybe_provision_workdir(&def).unwrap_err()).contains(".."));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn chown_tree_does_not_follow_links_or_hardlinks_and_keeps_definitions() {
        let d = tmpdir("chown-tree");
        std::fs::create_dir_all(d.join("sub/deeper")).unwrap();
        std::fs::write(d.join("sub/f"), b"x").unwrap();
        std::os::unix::fs::symlink("/etc", d.join("etc-link")).unwrap();
        std::fs::write(d.join("a"), b"x").unwrap();
        std::fs::hard_link(d.join("a"), d.join("b")).unwrap();
        // service.yml hard-linked to a backup: if it were visited it would count as a
        // skipped hard link, so the count below proves it was skipped *by name*.
        std::fs::write(d.join("service.yml"), b"x").unwrap();
        std::fs::hard_link(d.join("service.yml"), d.join("service.yml.bak")).unwrap();
        let dir = crate::pm::safefs::open_dir_safely(&d, false).unwrap();
        // chown to our own ids: permitted unprivileged, and exercises the full walk.
        let (uid, gid) = (nix::unistd::getuid().as_raw(), nix::unistd::getgid().as_raw());
        let skipped = chown_tree(&dir, Some(uid), Some(gid), DEFINITION_FILE_NAMES, 0).unwrap();
        assert_eq!(skipped, 3, "a, b and service.yml.bak (service.yml itself is skipped by name)");
        let _ = std::fs::remove_dir_all(&d);
    }

    // Regression: an auto service's definition lives in its working directory. If the
    // service user can write that directory, no file in it can be trusted -- the user
    // can rename a root-owned log (holding its own output) into service.yml, or any
    // root-owned file into .regen_pm_config. Such directories are not loaded at all.
    #[test]
    fn auto_service_dirs_a_user_can_write_are_never_loaded() {
        use std::os::unix::fs::PermissionsExt as _;
        let auto = tmpdir("auto-trust");
        let app_dir = auto.join("svc");
        std::fs::create_dir(&app_dir).unwrap();
        let yml = app_dir.join("service.yml");
        std::fs::write(&yml, "application: svc\nprocess:\n  start_command: [\"/bin/true\"]\n").unwrap();
        std::fs::set_permissions(&yml, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(app_dir.join(".regen_pm_config"), b"").unwrap();
        let load = |defs: &mut HashMap<String, AppDefinition>| {
            let (mut warnings, mut outdated) = (vec![], vec![]);
            merge_auto_services_best_effort(
                defs, &HashMap::new(), Some(&auto), "root", "root", &mut warnings, &mut outdated,
            )
            .unwrap();
            warnings
        };

        // /tmp is world-writable, so nothing below it is root-controlled: even a
        // well-formed 0644 definition (and a regen marker) is ignored, nothing is
        // generated, and the file is left alone.
        let mut defs = HashMap::new();
        let warnings = load(&mut defs);
        assert!(defs.is_empty(), "{warnings:?}");
        assert!(warnings.iter().any(|w| w.contains("auto_service_dir_not_root_controlled")), "{warnings:?}");
        assert!(app_dir.join(".regen_pm_config").exists(), "regen must not have run");
        assert!(!app_dir.join("service.yml.bak").exists());

        // Migration path: a config_directory definition for the same app takes over
        // quietly instead of the auto directory being a hard conflict.
        let mut defs = HashMap::new();
        defs.insert("svc".to_string(), provision_test_def(&app_dir, "  - path: ./x\n"));
        let warnings = load(&mut defs);
        assert!(!warnings.iter().any(|w| w.contains("svc") && w.contains("not_root_controlled")), "{warnings:?}");
        let _ = std::fs::remove_dir_all(&auto);
    }

    // Regression: the marker read used a blocking open with no size cap, so a service
    // could hang the daemon (at boot, too) with a FIFO, or OOM it with a sparse file.
    #[test]
    fn hostile_marker_cannot_hang_or_exhaust_the_daemon() {
        let d = tmpdir("reprov-fifo");
        let marker = d.join(".pm_provisioned");
        let def = provision_test_def(&d, "  - path: ./sub\n");
        nix::unistd::mkfifo(&marker, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        // Would block forever before the fix.
        assert_eq!(provisioning_staleness(&def, &marker).as_deref(), Some("marker_not_regular_file"));
        std::fs::remove_file(&marker).unwrap();
        let f = std::fs::File::create(&marker).unwrap();
        f.set_len(8 << 30).unwrap(); // 8 GiB sparse
        assert_eq!(provisioning_staleness(&def, &marker).as_deref(), Some("marker_unreadable"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn symlinked_marker_is_replaced_not_written_through() {
        let d = tmpdir("reprov-link");
        let victim = d.join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        std::fs::create_dir(d.join("w")).unwrap();
        let marker = d.join("w").join(".pm_provisioned");
        std::os::unix::fs::symlink(&victim, &marker).unwrap();
        let def = provision_test_def(&d.join("w"), "  - path: ./sub\n");

        assert_eq!(provisioning_staleness(&def, &marker).as_deref(), Some("marker_unreadable"));
        maybe_provision_workdir(&def).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert!(!std::fs::symlink_metadata(&marker).unwrap().file_type().is_symlink());
        assert_eq!(provisioning_staleness(&def, &marker), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn read_pids_from_cgroup_procs_parses_and_filters() {
        let d = tmpdir("procs");
        let f = d.join("cgroup.procs");
        std::fs::write(&f, "123\n456\n\n1\n0\nnot-a-pid\n").unwrap();
        let pids = read_pids_from_cgroup_procs(&f);
        assert_eq!(pids, vec![123, 456], "pid 0/1 and junk must be dropped");
        // A missing file yields an empty set, so callers narrow rather than widen.
        assert!(read_pids_from_cgroup_procs(&d.join("absent")).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    // ---- @file:// environment indirection ---------------------------------------

    #[test]
    fn env_file_rejects_non_regular_files() {
        // Regression: the size cap was guarded by `if m.is_file()`, so /dev/zero
        // skipped it entirely and read until the daemon was OOM-killed.
        let err = decode_env_value("@file:///dev/zero").expect_err("must refuse");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not a regular file"),
            "expected a regular-file complaint, got: {msg}"
        );
    }

    #[test]
    fn env_file_reads_a_regular_file_and_enforces_the_cap() {
        let d = tmpdir("envfile");
        let ok = d.join("ok");
        std::fs::write(&ok, b"hello").unwrap();
        let got = decode_env_value(&format!("@file://{}", ok.display())).unwrap();
        assert_eq!(got.to_string_lossy(), "hello");

        let big = d.join("big");
        std::fs::write(&big, vec![b'a'; (MAX_ENV_FILE_BYTES + 1) as usize]).unwrap();
        assert!(decode_env_value(&format!("@file://{}", big.display())).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn env_indirections_still_decode() {
        assert_eq!(decode_env_value("plain").unwrap().to_string_lossy(), "plain");
        assert_eq!(
            decode_env_value("@base64://aGVsbG8=").unwrap().to_string_lossy(),
            "hello"
        );
        assert_eq!(
            decode_env_value("@hex://68656c6c6f").unwrap().to_string_lossy(),
            "hello"
        );
    }

    // ---- log hint containment ----------------------------------------------------

    #[test]
    fn log_hints_may_not_escape_the_working_directory() {
        // Security regression: hints are read by the ROOT daemon and streamed to any
        // console user, so `hints: ["/etc/shadow"]` was a remote root-file read.
        let d = tmpdir("hints");
        let workdir = d.join("svc");
        std::fs::create_dir_all(workdir.join("logs")).unwrap();
        std::fs::write(workdir.join("logs/app.log"), b"ok").unwrap();

        // Inside: accepted.
        assert!(resolve_hint_under_workdir(&workdir, Path::new("./logs/app.log")).is_some());
        assert!(resolve_hint_under_workdir(&workdir, Path::new("logs/app.log")).is_some());

        // Absolute path outside the workdir: rejected.
        assert!(resolve_hint_under_workdir(&workdir, Path::new("/etc/shadow")).is_none());
        // Traversal: rejected.
        assert!(resolve_hint_under_workdir(&workdir, Path::new("../../../etc/passwd")).is_none());
        // A symlink pointing outside is refused when it is *read* (checking at resolve
        // time and opening later was a race): tail_lines opens without following it.
        let escape = workdir.join("logs/escape.log");
        std::os::unix::fs::symlink("/etc/hostname", &escape).unwrap();
        let p = resolve_hint_under_workdir(&workdir, Path::new("./logs/escape.log")).unwrap();
        assert!(tail_lines(&p, 10).is_err(), "must not read through the symlink");
        // Nor through a symlinked directory component.
        std::os::unix::fs::symlink("/etc", workdir.join("etc")).unwrap();
        let p = resolve_hint_under_workdir(&workdir, Path::new("./etc/hostname")).unwrap();
        assert!(tail_lines(&p, 10).is_err(), "must not read through a symlinked directory");
        assert!(tail_lines(&workdir.join("logs/app.log"), 10).is_ok());

        let _ = std::fs::remove_dir_all(&d);
    }

    // ---- atomic YAML writes -------------------------------------------------------

    #[test]
    fn write_yaml_atomically_replaces_content_and_leaves_no_temp() {
        let d = tmpdir("atomic");
        let f = d.join("service.yml");
        std::fs::write(&f, "old: true\n").unwrap();

        write_yaml_atomically(&f, "new: true\n").unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "new: true\n");

        // No .tmp leftovers.
        let leftovers: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "temp files left behind: {leftovers:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn write_yaml_atomically_replaces_a_symlink_rather_than_writing_through_it() {
        // rename() replaces the directory entry itself, so a service that planted a
        // symlink gets it replaced by a regular file -- the link target is untouched.
        let d = tmpdir("atomic-link");
        let victim = d.join("victim");
        std::fs::write(&victim, b"DO NOT TOUCH").unwrap();
        let link = d.join("service.yml");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        write_yaml_atomically(&link, "new: true\n").unwrap();

        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "DO NOT TOUCH");
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "new: true\n");
        assert!(!std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        let _ = std::fs::remove_dir_all(&d);
    }

    // ---- web console config validation -----------------------------------------

    fn cfg_with_console(bind: &str, users: Vec<String>) -> MasterConfig {
        let mut cfg = MasterConfig::default();
        cfg.web_console.enabled = true;
        cfg.web_console.bind = bind.to_string();
        cfg.web_console.port = 9001;
        cfg.web_console.auth.basic.users = users;
        cfg
    }

    #[test]
    fn default_bootstrap_credentials_may_not_be_exposed_off_host() {
        // Security regression: the bootstrap hash is published in the README, and the
        // console can run admin_actions as root.
        let default_entry = crate::pm::config::DEFAULT_BOOTSTRAP_BASIC_AUTH_ENTRY.to_string();
        for bind in ["0.0.0.0", "::", "192.168.1.10"] {
            let cfg = cfg_with_console(bind, vec![default_entry.clone()]);
            assert!(
                validate_web_console_config(&cfg).is_err(),
                "binding to {bind} with default credentials must be refused"
            );
        }
    }

    #[test]
    fn default_bootstrap_credentials_are_allowed_on_loopback() {
        let default_entry = crate::pm::config::DEFAULT_BOOTSTRAP_BASIC_AUTH_ENTRY.to_string();
        for bind in ["127.0.0.1", "::1"] {
            let cfg = cfg_with_console(bind, vec![default_entry.clone()]);
            assert!(
                validate_web_console_config(&cfg).is_ok(),
                "loopback bind should remain usable for bootstrapping (bind={bind})"
            );
        }
    }

    #[test]
    fn real_credentials_may_be_exposed_anywhere() {
        let cfg = cfg_with_console(
            "0.0.0.0",
            vec!["alice:$2b$12$BZCGuMAbOe5rXqoieAs5aOxvCRLsq5VaFUSiKk/7xlEM305d63GN6".to_string()],
        );
        assert!(validate_web_console_config(&cfg).is_ok());
    }

    #[test]
    fn console_requires_at_least_one_well_formed_user() {
        assert!(validate_web_console_config(&cfg_with_console("127.0.0.1", vec![])).is_err());
        assert!(
            validate_web_console_config(&cfg_with_console(
                "127.0.0.1",
                vec!["missing-colon".to_string()]
            ))
            .is_err()
        );
    }

    #[test]
    fn disabled_console_is_not_validated() {
        let mut cfg = cfg_with_console("0.0.0.0", vec![]);
        cfg.web_console.enabled = false;
        assert!(validate_web_console_config(&cfg).is_ok());
    }

    #[test]
    fn mem_max_payload_matches_cgroup_v2_format() {
        assert_eq!(to_mem_max_string("MAX").unwrap(), "max\n");
        assert_eq!(to_mem_max_string("64MiB").unwrap(), "67108864\n");
        assert_eq!(to_mem_max_string("0").unwrap(), "0\n");
        assert!(to_mem_max_string("not-a-size").is_err());
    }
}
