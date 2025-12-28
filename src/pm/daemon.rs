use crate::pm::app::{
    normalize_memory_string, normalize_swap_string, parse_app_definition_yaml,
    parse_cpu_millicores, AppDefinition,
    LogRotation, LogRotationMode, RestartConfig, RestartPolicy, RestartTolerance, RestartPolicyParsed,
};
use crate::pm::cgroup;
use crate::pm::config::MasterConfig;
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
use std::process::{Command, Stdio, ChildStdout, ChildStderr};
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

const EMBEDDED_FLAG_RULES_JSON: &str = include_str!("flag_rules.default.json");

#[derive(Debug, Clone, Default, Deserialize)]
struct FlagRuleFileEntry {
    #[serde(default)]
    clears: Vec<String>,
    #[serde(default)]
    also_sets: Vec<String>,
}

type FlagRulesFile = HashMap<String, FlagRuleFileEntry>;

#[derive(Debug, Clone, Default)]
struct FlagRuleCompiled {
    clear_all_except_fresh: bool,
    clears: Vec<SystemFlag>,
    also_sets: Vec<SystemFlag>,
}

type FlagRulesCompiled = HashMap<SystemFlag, FlagRuleCompiled>;

// (removed TOKIO_HANDLE: daemon is now async end-to-end; callers should `await` directly)
static TASKS: OnceLock<TaskTracker> = OnceLock::new();

pub(crate) fn tasks() -> &'static TaskTracker {
    TASKS.get().expect("TASKS not initialized")
}

const MAX_USER_FLAG_LEN: usize = 50;
const MAX_USER_FLAGS_PER_APP: usize = 100;
const MAX_APPS: usize = 10_000;
const MAX_APP_CONFIG_BYTES: u64 = 1024 * 1024; // 1 MiB
const LOGSFOLLOW_LINE_MAX_BYTES: usize = 4096;
const LOGSFOLLOW_READ_CHUNK_BYTES: usize = 64 * 1024;
const MAX_APPSTATE_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB (guard against corrupted/malicious file)
const MAX_ENV_FILE_BYTES: u64 = 64 * 1024; // 64 KiB per env indirection file
const RESTARTS_WINDOW_MS: i64 = 10 * 60 * 1000; // 10 minutes

static GZIP_MISSING_WARNED: AtomicBool = AtomicBool::new(false);

// Daemon log file defaults (independent of per-app stdout/stderr logs).
const DAEMON_LOG_NAME: &str = "processmaster";
const DAEMON_LOG_MAX_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB
const DAEMON_LOG_BACKUPS: usize = 10;

static DAEMON_LOG_TX: OnceLock<tokio_mpsc::UnboundedSender<String>> = OnceLock::new();
static EARLY_DAEMON_LOG: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();
const EARLY_DAEMON_LOG_MAX_LINES: usize = 5000;

static FLAG_RULES: OnceLock<FlagRulesCompiled> = OnceLock::new();

// Operator intent is expressed via transient system flags (not persisted).
const SYSFLAG_USER_STOP: SystemFlag = SystemFlag::UserStop;
const SYSFLAG_USER_START: SystemFlag = SystemFlag::UserStart;
const SYSFLAG_OT_KILLED: SystemFlag = SystemFlag::OtKilled;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedAppState {
    #[serde(default)]
    user_flags: BTreeMap<String, Option<i64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedStateFile {
    version: u32,
    #[serde(default)]
    apps: HashMap<String, PersistedAppState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum SystemFlag {
    Failed,
    Backoff,
    Outdated,
    UserStop,
    UserStart,
    OtKilled,
    ExitOk,
    ExitErr,
    Dummy1,
    Dummy2,
    Dummy3,
    Dummy4,
    Dummy5,
    Dummy6,
    Dummy7,
    Dummy8,
    Dummy9,
    Dummy10,
    SystemStart,
    NoFlag,
    #[allow(dead_code)] // constructed by the flag rules engine (runtime-configured)
    FlagBug,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // may be extended with RUNNING-only flags; kept for the design
enum FlagScope {
    Running,
    Stopped,
    Both,
}

impl SystemFlag {
    fn as_str(&self) -> &'static str {
        match self {
            SystemFlag::Failed => "failed",
            SystemFlag::Backoff => "backoff",
            SystemFlag::Outdated => "outdated",
            SystemFlag::UserStop => "user_stop",
            SystemFlag::UserStart => "user_start",
            SystemFlag::OtKilled => "ot_killed",
            SystemFlag::ExitOk => "exit_ok",
            SystemFlag::ExitErr => "exit_err",
            SystemFlag::Dummy1 => "dummy1",
            SystemFlag::Dummy2 => "dummy2",
            SystemFlag::Dummy3 => "dummy3",
            SystemFlag::Dummy4 => "dummy4",
            SystemFlag::Dummy5 => "dummy5",
            SystemFlag::Dummy6 => "dummy6",
            SystemFlag::Dummy7 => "dummy7",
            SystemFlag::Dummy8 => "dummy8",
            SystemFlag::Dummy9 => "dummy9",
            SystemFlag::Dummy10 => "dummy10",
            SystemFlag::SystemStart => "system_start",
            SystemFlag::NoFlag => "no_flag",
            SystemFlag::FlagBug => "flag_bug",
        }
    }

    fn scope(&self) -> FlagScope {
        match self {
            // These describe stopped-state conditions only.
            SystemFlag::Failed => FlagScope::Stopped,
            SystemFlag::Backoff => FlagScope::Stopped,
            SystemFlag::OtKilled => FlagScope::Stopped,
            SystemFlag::ExitOk => FlagScope::Stopped,
            SystemFlag::ExitErr => FlagScope::Stopped,
            SystemFlag::Dummy1 => FlagScope::Both,
            SystemFlag::Dummy2 => FlagScope::Both,
            SystemFlag::Dummy3 => FlagScope::Both,
            SystemFlag::Dummy4 => FlagScope::Both,
            SystemFlag::Dummy5 => FlagScope::Both,
            SystemFlag::Dummy6 => FlagScope::Both,
            SystemFlag::Dummy7 => FlagScope::Both,
            SystemFlag::Dummy8 => FlagScope::Both,
            SystemFlag::Dummy9 => FlagScope::Both,
            SystemFlag::Dummy10 => FlagScope::Both,

            // These can be useful in either state (or might be set transiently during transitions).
            SystemFlag::Outdated => FlagScope::Both,
            SystemFlag::UserStop => FlagScope::Stopped,
            SystemFlag::UserStart => FlagScope::Running,
            // Internal/controller-only flags; generally should not be displayed, but scoping doesn't matter much
            // because rules clear them immediately.
            SystemFlag::SystemStart => FlagScope::Running,
            SystemFlag::NoFlag => FlagScope::Both,
            SystemFlag::FlagBug => FlagScope::Both,
        }
    }

    fn parse(s: &str) -> Option<SystemFlag> {
        match s.trim() {
            "failed" => Some(SystemFlag::Failed),
            "backoff" => Some(SystemFlag::Backoff),
            "outdated" => Some(SystemFlag::Outdated),
            "user_stop" => Some(SystemFlag::UserStop),
            "user_start" => Some(SystemFlag::UserStart),
            "ot_killed" => Some(SystemFlag::OtKilled),
            "exit_ok" => Some(SystemFlag::ExitOk),
            "exit_err" => Some(SystemFlag::ExitErr),
            "dummy1" => Some(SystemFlag::Dummy1),
            "dummy2" => Some(SystemFlag::Dummy2),
            "dummy3" => Some(SystemFlag::Dummy3),
            "dummy4" => Some(SystemFlag::Dummy4),
            "dummy5" => Some(SystemFlag::Dummy5),
            "dummy6" => Some(SystemFlag::Dummy6),
            "dummy7" => Some(SystemFlag::Dummy7),
            "dummy8" => Some(SystemFlag::Dummy8),
            "dummy9" => Some(SystemFlag::Dummy9),
            "dummy10" => Some(SystemFlag::Dummy10),
            "system_start" => Some(SystemFlag::SystemStart),
            "no_flag" => Some(SystemFlag::NoFlag),
            "flag_bug" => Some(SystemFlag::FlagBug),
            _ => None,
        }
    }
}

impl std::fmt::Display for SystemFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

fn sysflag_set(map: &mut BTreeMap<SystemFlag, Option<i64>>, flag: SystemFlag, expires_at_ms: Option<i64>) {
    map.insert(flag, expires_at_ms);
}

fn sysflag_clear(map: &mut BTreeMap<SystemFlag, Option<i64>>, flag: SystemFlag) {
    map.remove(&flag);
}

fn sysflag_has(map: &BTreeMap<SystemFlag, Option<i64>>, flag: SystemFlag) -> bool {
    map.contains_key(&flag)
}

fn sysflag_set_with_rules(
    app: &str,
    map: &mut BTreeMap<SystemFlag, Option<i64>>,
    flag: SystemFlag,
    expires_at_ms: Option<i64>,
) {
    // Two-phase rule application:
    // - Evaluate rules on a snapshot (BFS) to compute (1) flags to remove, (2) flags to add/update.
    // - Apply removals first, then apply adds/updates.
    //
    // Conflict resolution: if a flag is both set and cleared by rules, "set wins".
    use std::collections::{HashSet, VecDeque};

    // Rules source (avoid allocating/cloning in the common case).
    let rules_owned;
    let rules: &FlagRulesCompiled = match FLAG_RULES.get() {
        Some(r) => r,
        None => {
            rules_owned = default_flag_rules_compiled();
            &rules_owned
        }
    };

    // Snapshot of existing flags.
    let existing: Vec<SystemFlag> = map.keys().copied().collect();

    // BFS evaluation.
    let mut queue: VecDeque<SystemFlag> = VecDeque::new();
    let mut expanded: HashSet<SystemFlag> = HashSet::new();
    let mut to_clear: std::collections::BTreeSet<SystemFlag> = std::collections::BTreeSet::new();
    // These are flags being applied in this round (the "fresh set" to keep under clears=["*"] semantics).
    let mut applied_set: std::collections::BTreeSet<SystemFlag> = std::collections::BTreeSet::new();
    // Track which flags are requested via also_sets (used to decide whether to insert them if absent).
    let mut also_set_requested: std::collections::BTreeSet<SystemFlag> = std::collections::BTreeSet::new();

    let mut clear_all = false;
    let mut actions: usize = 0;
    applied_set.insert(flag);
    queue.push_back(flag);

    while let Some(f) = queue.pop_front() {
        if actions > 10_000 {
            break;
        }
        if !expanded.insert(f) {
            continue;
        }
        let Some(rule) = rules.get(&f) else { continue };

        if rule.clear_all_except_fresh {
            clear_all = true;
            actions += 1;
        }

        for c in &rule.clears {
            if to_clear.insert(*c) {
                actions += 1;
            }
        }

        for a in &rule.also_sets {
            if also_set_requested.insert(*a) {
                actions += 1;
            }
            // "Apply" the flag in this round (even if it already existed) so its clears/also_sets are evaluated.
            applied_set.insert(*a);
            queue.push_back(*a);
        }
    }

    if actions > 10_000 {
        applied_set.insert(SystemFlag::FlagBug);
        pm_event("flags", Some(app), "decision=stop reason=side_effect_limit_exceeded limit=10000");
    }

    // Expand clears=["*"] as: clear all existing flags except those applied in this round.
    if clear_all {
        let mut n = 0usize;
        for k in &existing {
            if applied_set.contains(k) {
                continue;
            }
            if to_clear.insert(*k) {
                n += 1;
            }
        }
        pm_event(
            "flags",
            Some(app),
            format!("effect=clear_all kept_applied={} clear_candidates={}", applied_set.len(), n),
        );
    }

    // Resolve conflicts: set wins.
    for k in &applied_set {
        to_clear.remove(k);
    }

    // Apply removals.
    for r in to_clear {
        if map.remove(&r).is_some() {
            pm_event("flags", Some(app), format!("effect=clear cleared={}", r.as_str()));
        }
    }

    // Apply adds/updates:
    // - The primary flag is always set/updated with the requested expiry.
    map.insert(flag, expires_at_ms);
    pm_event("flags", Some(app), format!("effect=set flag={}", flag.as_str()));

    // - also_sets are inserted if missing; existing ones are kept as-is.
    for a in also_set_requested {
        if a == flag {
            continue;
        }
        if map.contains_key(&a) {
            continue;
        }
        map.insert(a, None);
        pm_event("flags", Some(app), format!("effect=also_set flag={}", a.as_str()));
    }
}

fn default_flag_rules_compiled() -> FlagRulesCompiled {
    // Safe defaults matching current semantics:
    // - user_start implies not user_stop, and clears the "ot_killed" marker (manual intervention acknowledges it).
    // - user_stop implies not user_start.
    let mut m: FlagRulesCompiled = HashMap::new();
    m.insert(
        SystemFlag::UserStart,
        FlagRuleCompiled {
            clear_all_except_fresh: false,
            clears: vec![SystemFlag::UserStop, SystemFlag::OtKilled],
            also_sets: vec![],
        },
    );
    m.insert(
        SystemFlag::UserStop,
        FlagRuleCompiled {
            clear_all_except_fresh: false,
            clears: vec![SystemFlag::UserStart],
            also_sets: vec![],
        },
    );
    m.insert(
        SystemFlag::Failed,
        FlagRuleCompiled {
            clear_all_except_fresh: false,
            clears: vec![SystemFlag::Backoff],
            also_sets: vec![],
        },
    );
    m
}

fn load_flag_rules(cfg: &MasterConfig) -> FlagRulesCompiled {
    fn compile_from_parsed(parsed: FlagRulesFile) -> FlagRulesCompiled {
        let mut compiled: FlagRulesCompiled = HashMap::new();
        for (k, v) in parsed {
            let Some(flag) = SystemFlag::parse(&k) else {
                pm_event("flags", None, &format!("ignore_rule reason=unknown_flag flag={k}"));
                continue;
            };
            let mut clears: Vec<SystemFlag> = vec![];
            let mut clear_all_except_fresh = false;
            for c in v.clears {
                if c.trim() == "*" {
                    clear_all_except_fresh = true;
                    continue;
                }
                if let Some(f) = SystemFlag::parse(&c) {
                    clears.push(f);
                } else {
                    pm_event(
                        "flags",
                        None,
                        &format!(
                            "ignore_rule_field reason=unknown_flag parent={} field=clears value={c}",
                            flag.as_str()
                        ),
                    );
                }
            }
            let mut also_sets: Vec<SystemFlag> = vec![];
            for a in v.also_sets {
                if let Some(f) = SystemFlag::parse(&a) {
                    also_sets.push(f);
                } else {
                    pm_event(
                        "flags",
                        None,
                        &format!(
                            "ignore_rule_field reason=unknown_flag parent={} field=also_sets value={a}",
                            flag.as_str()
                        ),
                    );
                }
            }
            compiled.insert(
                flag,
                FlagRuleCompiled {
                    clear_all_except_fresh,
                    clears,
                    also_sets,
                },
            );
        }
        compiled
    }

    // 1) Start from embedded JSON (compiled into the binary).
    let embedded_parsed: Option<FlagRulesFile> = match serde_json::from_str(EMBEDDED_FLAG_RULES_JSON) {
        Ok(v) => Some(v),
        Err(e) => {
            pm_event("flags", None, &format!("decision=use_builtin_defaults reason=embedded_json_parse_error err={e}"));
            None
        }
    };
    let mut base = embedded_parsed
        .map(compile_from_parsed)
        .unwrap_or_else(default_flag_rules_compiled);

    // 2) Optional on-disk override at <config_directory>/flag_rules.json.
    let path = cfg.config_directory.join("flag_rules.json");
    match std::fs::read_to_string(&path) {
        Ok(text) => match serde_json::from_str::<FlagRulesFile>(&text) {
            Ok(parsed) => {
                base = compile_from_parsed(parsed);
                pm_event("flags", None, &format!("loaded source=disk file={} rules={}", path.display(), base.len()));
            }
            Err(e) => {
                pm_event(
                    "flags",
                    None,
                    &format!(
                        "decision=keep_embedded reason=json_parse_error file={} err={e}",
                        path.display()
                    ),
                );
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            pm_event("flags", None, &format!("loaded source=embedded rules={}", base.len()));
        }
        Err(e) => {
            pm_event(
                "flags",
                None,
                &format!("decision=keep_embedded reason=read_error file={} err={e}", path.display()),
            );
        }
    }

    base
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

pub(crate) fn pm_event(component: &str, app: Option<&str>, msg: impl AsRef<str>) {
    let ts = Local::now().format("%Y-%m-%d_%H:%M:%S%.3f");
    fn normalize_app_for_log(a: &str) -> &str {
        // Defensive: avoid printing debug-formatted Option values like `Some("dnsmasq")`.
        // This can happen if an upstream caller accidentally formats an Option and passes it as a string.
        a.strip_prefix("Some(\"")
            .and_then(|s| s.strip_suffix("\")"))
            .unwrap_or(a)
    }
    match app {
        Some(a) => {
            let a2 = normalize_app_for_log(a);
            let line = format!("{ts} [{component}] app={a2} {}", msg.as_ref());
            eprintln!("{line}");
            if let Some(tx) = DAEMON_LOG_TX.get() {
                let _ = tx.send(line);
            } else {
                let q = EARLY_DAEMON_LOG.get_or_init(|| Mutex::new(VecDeque::new()));
                let mut g = q.lock().unwrap_or_else(|p| p.into_inner());
                g.push_back(line);
                while g.len() > EARLY_DAEMON_LOG_MAX_LINES {
                    g.pop_front();
                }
            }
        }
        None => {
            let line = format!("{ts} [{component}] {}", msg.as_ref());
            eprintln!("{line}");
            if let Some(tx) = DAEMON_LOG_TX.get() {
                let _ = tx.send(line);
            } else {
                let q = EARLY_DAEMON_LOG.get_or_init(|| Mutex::new(VecDeque::new()));
                let mut g = q.lock().unwrap_or_else(|p| p.into_inner());
                g.push_back(line);
                while g.len() > EARLY_DAEMON_LOG_MAX_LINES {
                    g.pop_front();
                }
            }
        }
    }
}

fn pm_event_state(state: &Arc<Mutex<DaemonState>>, component: &str, app: Option<&str>, msg: impl AsRef<str>) {
    pm_event(component, app, msg.as_ref());
    let entry = EventEntry {
        ts: Local::now().format("%Y-%m-%d_%H:%M:%S%.3f").to_string(),
        component: component.to_string(),
        app: app.map(|s| s.to_string()),
        message: msg.as_ref().to_string(),
    };
    let events = {
        let st = match state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        Arc::clone(&st.events)
    };
    let mut q = events.lock().unwrap_or_else(|p| p.into_inner());
    q.push_back(entry);
    while q.len() > 2000 {
        q.pop_front();
    }
}

fn push_event(events: &Arc<Mutex<VecDeque<EventEntry>>>, component: &str, app: Option<&str>, msg: impl AsRef<str>) {
    // Also print to stderr so operators can see it live.
    pm_event(component, app, msg.as_ref());
    let entry = EventEntry {
        ts: Local::now().format("%Y-%m-%d_%H:%M:%S%.3f").to_string(),
        component: component.to_string(),
        app: app.map(|s| s.to_string()),
        message: msg.as_ref().to_string(),
    };
    let mut q = events.lock().unwrap_or_else(|p| p.into_inner());
    q.push_back(entry);
    while q.len() > 2000 {
        q.pop_front();
    }
}

fn start_daemon_log_file(cfg: &MasterConfig) {
    // Default daemon log file:
    // - Prefer $CWD/logs/processmaster.log (systemd WorkingDirectory)
    // - Fallback: <config_directory>/logs/processmaster.log
    let base_path = std::env::current_dir()
        .ok()
        .map(|d| d.join("logs").join(format!("{DAEMON_LOG_NAME}.log")))
        .unwrap_or_else(|| cfg.config_directory.join("logs").join(format!("{DAEMON_LOG_NAME}.log")));
    let (tx, mut rx) = tokio_mpsc::unbounded_channel::<String>();
    let _ = DAEMON_LOG_TX.set(tx);

    // Log where we're writing (also goes to the log file, since tx is set above).
    pm_event(
        "log",
        None,
        format!(
            "daemon_log_file path={} rotate=size max_bytes={} backups={} gzip=true",
            base_path.display(),
            DAEMON_LOG_MAX_BYTES,
            DAEMON_LOG_BACKUPS
        ),
    );

    tasks().spawn(async move {
        let mut f = match open_append_log_async(&base_path).await {
            Ok(f) => f,
            Err(e) => {
                eprintln!(
                    "{} [log] failed to open daemon log file {} err={e}",
                    Local::now().format("%Y-%m-%d_%H:%M:%S%.3f"),
                    base_path.display()
                );
                return;
            }
        };

        // Flush early boot logs (including config parse/misconfig warnings) into the daemon log file.
        if let Some(q) = EARLY_DAEMON_LOG.get() {
            // IMPORTANT: do not hold the mutex guard across `.await` (TaskTracker requires Send futures).
            let drained: Vec<String> = {
                let mut g = q.lock().unwrap_or_else(|p| p.into_inner());
                g.drain(..).collect()
            };
            for line in drained {
                let mut s = line;
                if !s.ends_with('\n') {
                    s.push('\n');
                }
                let _ = f.write_all(s.as_bytes()).await;
            }
            let _ = f.flush().await;
        }

        let mut bytes_written: u64 = tokio::fs::metadata(&base_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);

        while let Some(line) = rx.recv().await {
            // Rotate before write (size based).
            if DAEMON_LOG_MAX_BYTES > 0 && bytes_written >= DAEMON_LOG_MAX_BYTES {
                let _ = f.flush().await;
                if let Ok(rr) = rotate_numbered_reopen_async(&base_path, DAEMON_LOG_BACKUPS).await {
                    if let Some(rotated) = rr.rotated.as_deref() {
                        maybe_compress_rotated_best_effort(DAEMON_LOG_NAME, true, rotated);
                    }
                    f = rr.f;
                    bytes_written = 0;
                }
            }

            let mut s = line;
            if !s.ends_with('\n') {
                s.push('\n');
            }
            if f.write_all(s.as_bytes()).await.is_ok() {
                bytes_written = bytes_written.saturating_add(s.as_bytes().len() as u64);
            }

            // Rotate after write too (covers single large writes).
            if DAEMON_LOG_MAX_BYTES > 0 && bytes_written >= DAEMON_LOG_MAX_BYTES {
                let _ = f.flush().await;
                if let Ok(rr) = rotate_numbered_reopen_async(&base_path, DAEMON_LOG_BACKUPS).await {
                    if let Some(rotated) = rr.rotated.as_deref() {
                        maybe_compress_rotated_best_effort(DAEMON_LOG_NAME, true, rotated);
                    }
                    f = rr.f;
                    bytes_written = 0;
                }
            }
        }
    });
}

pub fn run_daemon(cfg: &MasterConfig) -> anyhow::Result<()> {
    // Keep a sync wrapper for CLI/binary compatibility while we migrate internals to async.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
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
    let listener = TokioUnixListener::bind(&sock)
        .map_err(|e| anyhow::anyhow!("failed to bind socket {}: {e}", sock.display()))?;

    let shutting_down = Arc::new(AtomicBool::new(false));

    // Apply socket ownership/mode while we still have the original privileges.
    apply_socket_settings(&cfg)?;

    // Apply master cgroup limits and move this process into the master cgroup.
    // This must happen before dropping privileges if root is required.
    setup_master_cgroup_or_instructions(&cfg)?;
    // Print the effective master cgroup root (important for unprivileged mode).
    if let Ok(eff) = effective_master_cgroup_path(&cfg) {
        pm_event(
            "cgroup",
            None,
            format!(
                "master_cgroup_effective configured_root={} configured_name={} effective_path={}",
                cfg.cgroup_root,
                cfg.cgroup_name,
                eff.display()
            ),
        );
    } else {
        pm_event(
            "cgroup",
            None,
            format!(
                "master_cgroup_effective configured_root={} configured_name={} effective_path=<error>",
                cfg.cgroup_root,
                cfg.cgroup_name
            ),
        );
    }

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

    // Async accept loop.
    while !shutting_down.load(Ordering::Relaxed) {
        tokio::select! {
            r = listener.accept() => {
                match r {
                    Ok((stream, _addr)) => {
                        let st = Arc::clone(&state);
                        tasks().spawn(async move {
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
    let _addr: std::net::SocketAddr = format!("{}:{}", wc.bind, wc.port)
        .parse()
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
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
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

fn start_scheduler_thread(state: Arc<Mutex<DaemonState>>) {
    // Kept name for compatibility; now implemented as a tokio task.
    tasks().spawn(async move {
        // Map app -> last minute key we triggered (avoid duplicate triggers within same minute)
        let mut last_fired: HashMap<String, i64> = HashMap::new();
        loop {
            // Do not start cron jobs while shutting down.
            if state
                .lock()
                .map(|st| st.shutting_down.load(Ordering::Relaxed))
                .unwrap_or(true)
            {
                pm_event("schedule", None, "exit reason=shutting_down");
                break;
            }
            // Wait until the wall-clock minute identity changes (same strategy as log maintenance).
            let start_minute = Local::now().timestamp() / 60;
            loop {
                if state
                    .lock()
                    .map(|st| st.shutting_down.load(Ordering::Relaxed))
                    .unwrap_or(true)
                {
                    pm_event("schedule", None, "exit reason=shutting_down");
                    return;
                }
                let cur_minute = Local::now().timestamp() / 60;
                if cur_minute != start_minute {
                    break;
                }
                // sleep until next minute boundary
                let now_ms = Local::now().timestamp_millis();
                let next_minute_ms = ((now_ms / 60_000) + 1) * 60_000;
                let mut sleep_ms = (next_minute_ms - now_ms).max(1);
                if sleep_ms > 60_000 {
                    sleep_ms = 60_000;
                }
                tokio_time::sleep(Duration::from_millis(sleep_ms as u64)).await;
            }

            let now = Local::now();
            let minute_key = now.timestamp() / 60;

            let defs = {
                let st = match state.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                st.defs.clone()
            };

            for (name, def) in defs {
                if state
                    .lock()
                    .map(|st| st.shutting_down.load(Ordering::Relaxed))
                    .unwrap_or(true)
                {
                    pm_event("schedule", None, "exit reason=shutting_down");
                    return;
                }
                let Some(expr) = def.schedule.as_deref() else { continue };
                if !def.enabled {
                pm_event_state(&state, "schedule", Some(&name), format!("skip disabled schedule={expr:?}"));
                    continue;
                }

                // Optional schedule window checks.
                let now_ms = now.timestamp_millis();
                if let Some(nb) = def.schedule_not_before_ms {
                    if now_ms < nb {
                        pm_event_state(&state, "schedule", Some(&name), format!("skip not_before now_ms={} not_before_ms={} schedule={expr:?}", now_ms, nb));
                        continue;
                    }
                }
                if let Some(na) = def.schedule_not_after_ms {
                    if now_ms > na {
                        pm_event_state(&state, "schedule", Some(&name), format!("skip not_after now_ms={} not_after_ms={} schedule={expr:?}", now_ms, na));
                        continue;
                    }
                }

                // Avoid double-firing if we ever loop twice within the same minute.
                if last_fired.get(&name).copied() == Some(minute_key) {
                    continue;
                }

                let normalized = normalize_cron_expr(expr);
                let schedule = match Schedule::from_str(&normalized) {
                    Ok(s) => s,
                    Err(e) => {
                        pm_event_state(&state, "schedule", Some(&name), format!("parse_error schedule={expr:?} err={e}"));
                        continue;
                    }
                };

                // Check if an occurrence is exactly at this minute boundary.
                // We look for the first occurrence after (now - 1s) and see if it equals now (to the second).
                let target = now
                    .with_second(0)
                    .and_then(|t| t.with_nanosecond(0))
                    .unwrap_or(now);
                let prev = target - chrono::Duration::seconds(1);
                let due = schedule
                    .after(&prev)
                    .next()
                    .map(|dt| dt == target)
                    .unwrap_or(false);
                if !due {
                    continue;
                }

                last_fired.insert(name.clone(), minute_key);

                pm_event_state(&state, "schedule", Some(&name), format!("due schedule={expr:?} attempt=run_once"));
                match scheduled_start_via_supervisor_async(&state, &name).await {
                    Ok(()) => pm_event_state(&state, "schedule", Some(&name), "outcome=accepted"),
                    Err(e) => pm_event_state(&state, "schedule", Some(&name), format!("outcome=error err={e}")),
                }
            }
        }
    });
}

fn start_overtime_scheduler_thread(state: Arc<Mutex<DaemonState>>) {
    tasks().spawn(async move {
        loop {
            if state
                .lock()
                .map(|st| st.shutting_down.load(Ordering::Relaxed))
                .unwrap_or(true)
            {
                pm_event("schedule", None, "overtime_monitor exit reason=shutting_down");
                break;
            }

            let (cfg, defs) = {
                let st = match state.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                (st.cfg.clone(), st.defs.clone())
            };

            let sys_uptime_s = read_system_uptime_seconds();
            let hz = clock_ticks_per_second();

            // Check any scheduled jobs that have max_time_per_run configured.
            let mut js: JoinSet<()> = JoinSet::new();
            for (name, def) in defs {
                let Some(max_ms) = def.schedule_max_time_per_run_ms else { continue };
                if def.schedule.is_none() {
                    continue;
                }
                // Disabled scheduled jobs shouldn't be running; but if they are, stop them anyway.
                let st2 = Arc::clone(&state);
                let cfg2 = cfg.clone();
                js.spawn(async move {
                    let pids = match launcher_pids(&cfg2, &name) {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    if pids.is_empty() {
                        return;
                    }
                    let uptimes = compute_pid_uptimes_ms(&pids, sys_uptime_s, hz);
                    let oldest_ms: i64 = uptimes.iter().copied().filter(|v| *v >= 0).max().unwrap_or(0);
                    if oldest_ms <= 0 {
                        return;
                    }
                    if (oldest_ms as u64) <= max_ms {
                        return;
                    }
                    pm_event_state(
                        &st2,
                        "schedule",
                        Some(&name),
                        format!(
                            "overtime detected=true oldest_uptime_ms={} max_time_per_run_ms={} attempt=overtime_stop",
                            oldest_ms, max_ms
                        ),
                    );
                    match overtime_stop_via_supervisor_async(&st2, &name).await {
                        Ok(()) => pm_event_state(&st2, "schedule", Some(&name), "overtime_stop outcome=stopped"),
                        Err(e) => pm_event_state(&st2, "schedule", Some(&name), format!("overtime_stop outcome=error err={e}")),
                    }
                });
            }
            while js.join_next().await.is_some() {}

            tokio_time::sleep(Duration::from_secs(5)).await;
        }
    });
}

fn normalize_cron_expr(expr: &str) -> String {
    // Accept standard 5-field cron ("m h dom mon dow") by prepending seconds=0.
    // If user already provided 6+ fields, pass through unchanged.
    let parts: Vec<&str> = expr.split_whitespace().collect();
    if parts.len() == 5 {
        format!("0 {expr}")
    } else {
        expr.to_string()
    }
}

fn start_log_maintenance_thread(state: Arc<Mutex<DaemonState>>) {
    tasks().spawn(async move {
        loop {
            if let Err(e) = run_log_maintenance_tick_async(&state).await {
                eprintln!("log maintenance error: {e}");
            }
            // Sleep until the wall-clock minute identity actually changes.
            // (Some platforms can wake early; this avoids running a "next minute" tick too soon.)
            let start_minute = Local::now().timestamp_millis() / 60_000;
            loop {
                let now_ms = Local::now().timestamp_millis();
                let cur_minute = now_ms / 60_000;
                if cur_minute != start_minute {
                    break;
                }
                let next_minute_ms = (start_minute + 1) * 60_000;
                let mut sleep_ms = (next_minute_ms - now_ms).max(1);
                // Clamp to avoid pathological sleeps if the clock jumps.
                if sleep_ms > 60_000 {
                    sleep_ms = 60_000;
                }
                tokio_time::sleep(Duration::from_millis(sleep_ms as u64)).await;
            }
        }
    });
}

fn start_flag_maintenance_thread(state: Arc<Mutex<DaemonState>>) {
    tasks().spawn(async move {
        loop {
            if state
                .lock()
                .map(|st| st.shutting_down.load(Ordering::Relaxed))
                .unwrap_or(true)
            {
                break;
            }

            let now_ms = Local::now().timestamp_millis();
            let (run_info, events) = {
                let st = state.lock().unwrap_or_else(|p| p.into_inner());
                (Arc::clone(&st.run_info), Arc::clone(&st.events))
            };

            let mut expired_pairs: Vec<(String, String)> = vec![];
            let mut expired_user_any = false;
            {
                let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                for (app, info) in ri.iter_mut() {
                    // system flags
                    let mut to_remove_sys: Vec<SystemFlag> = vec![];
                    for (k, v) in info.system_flags.iter() {
                        if let Some(deadline) = v {
                            if now_ms >= *deadline {
                                to_remove_sys.push(*k);
                            }
                        }
                    }
                    for k in to_remove_sys {
                        info.system_flags.remove(&k);
                        expired_pairs.push((app.clone(), k.to_string()));
                    }

                    let mut to_remove: Vec<String> = vec![];
                    for (k, v) in info.user_flags.iter() {
                        if let Some(deadline) = v {
                            if now_ms >= *deadline {
                                to_remove.push(k.clone());
                            }
                        }
                    }
                    for k in to_remove {
                        info.user_flags.remove(&k);
                        expired_pairs.push((app.clone(), k));
                        expired_user_any = true;
                    }
                }
            }

            let had_expired = !expired_pairs.is_empty();
            for (app, flag) in expired_pairs {
                push_event(&events, "flag", Some(&app), format!("expired flag={flag}"));
            }
            // Persisted state is user flags only; system flags must not trigger writes.
            if had_expired && expired_user_any {
                let dirty = {
                    let st = state.lock().unwrap_or_else(|p| p.into_inner());
                    Arc::clone(&st.appstate_dirty)
                };
                dirty.store(true, Ordering::Relaxed);
            }

            tokio_time::sleep(Duration::from_millis(250)).await;
        }
    });
}

fn restore_app_state_best_effort(state: Arc<Mutex<DaemonState>>) {
    let (path, run_info, events) = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        (st.appstate_path.clone(), Arc::clone(&st.run_info), Arc::clone(&st.events))
    };
    if let Ok(m) = fs::metadata(&path) {
        if m.is_file() && m.len() > MAX_APPSTATE_BYTES {
            push_event(
                &events,
                "appstate",
                None,
                format!(
                    "discard_too_large path={} bytes={} limit_bytes={}",
                    path.display(),
                    m.len(),
                    MAX_APPSTATE_BYTES
                ),
            );
            return;
        }
    }
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                push_event(&events, "appstate", None, format!("load_failed path={} err={e}", path.display()));
            }
            return;
        }
    };
    let parsed: PersistedStateFile = match serde_json::from_str(&text) {
        Ok(p) => p,
        Err(e) => {
            push_event(&events, "appstate", None, format!("discard_unreadable path={} err={e}", path.display()));
            return;
        }
    };
    // version 2 used to include a stopped_by_user field; we now express intent via user_flags instead.
    if parsed.version != 1 && parsed.version != 2 {
        push_event(&events, "appstate", None, format!("discard_version_mismatch path={} version={}", path.display(), parsed.version));
        return;
    }
    let now_ms = Local::now().timestamp_millis();
    let mut applied = 0usize;
    {
        let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
        for (app, st) in parsed.apps {
            let e = ri.entry(app).or_default();
            // Restore persisted app state (only user flags; system flags are derived).
            e.user_flags = st.user_flags;
            // prune expired immediately
            e.user_flags.retain(|_, v| v.map(|d| now_ms < d).unwrap_or(true));
            // enforce caps
            e.user_flags.retain(|k, _| !k.is_empty() && k.len() <= MAX_USER_FLAG_LEN);
            if e.user_flags.len() > MAX_USER_FLAGS_PER_APP {
                // Keep first N keys in sorted order (BTreeMap order) and drop the rest.
                let keep: Vec<String> = e
                    .user_flags
                    .keys()
                    .take(MAX_USER_FLAGS_PER_APP)
                    .cloned()
                    .collect();
                e.user_flags.retain(|k, _| keep.binary_search(k).is_ok());
            }
            applied += 1;
        }
    }
    if applied > 0 {
        push_event(&events, "appstate", None, format!("restored apps={applied} path={}", path.display()));
    }
}

fn start_appstate_flush_thread(state: Arc<Mutex<DaemonState>>) {
    tasks().spawn(async move {
        loop {
            let (dirty, path, run_info, events, shutting_down) = {
                let st = state.lock().unwrap_or_else(|p| p.into_inner());
                (
                    Arc::clone(&st.appstate_dirty),
                    st.appstate_path.clone(),
                    Arc::clone(&st.run_info),
                    Arc::clone(&st.events),
                    Arc::clone(&st.shutting_down),
                )
            };

            if shutting_down.load(Ordering::Relaxed) {
                // One last best-effort flush.
                if dirty.swap(false, Ordering::Relaxed) {
                    let _ = write_appstate_atomic(&path, &run_info, &events);
                }
                break;
            }

            if dirty.swap(false, Ordering::Relaxed) {
                let _ = write_appstate_atomic(&path, &run_info, &events);
            }
            tokio_time::sleep(Duration::from_millis(500)).await;
        }
    });
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
                .map(|st| st.shutting_down.load(Ordering::Relaxed))
                .unwrap_or(true)
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

fn write_appstate_atomic(path: &Path, run_info: &Arc<Mutex<HashMap<String, RunInfo>>>, events: &Arc<Mutex<VecDeque<EventEntry>>>) -> anyhow::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if let Err(e) = fs::create_dir_all(parent) {
        push_event(events, "appstate", None, format!("flush_failed mkdir {} err={e}", parent.display()));
        return Ok(());
    }

    let snapshot: PersistedStateFile = {
        let ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
        let mut apps: HashMap<String, PersistedAppState> = HashMap::new();
        for (app, info) in ri.iter() {
            if info.user_flags.is_empty() {
                continue;
            }
            apps.insert(
                app.clone(),
                PersistedAppState {
                    user_flags: info.user_flags.clone(),
                },
            );
        }
        PersistedStateFile { version: 1, apps }
    };

    let json = serde_json::to_vec_pretty(&snapshot)?;
    let tmp = parent.join(format!(".appstate.json.tmp.{}", std::process::id()));
    fs::write(&tmp, &json)?;
    // Atomic replace on POSIX.
    fs::rename(&tmp, path)?;
    Ok(())
}

async fn run_log_maintenance_tick_async(state: &Arc<Mutex<DaemonState>>) -> anyhow::Result<()> {
    let defs: Vec<AppDefinition> = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        st.defs.values().cloned().collect()
    };

    let now_sys = std::time::SystemTime::now();

    for def in defs {
        let (stdout_path, stderr_path) = resolve_log_paths(&def);
        // capture-only: rotation is done by log pumps; maintenance only does cleanup/pruning.
        let _ = cleanup_or_prune_rotated_logs_async(&def, &stdout_path, now_sys).await;
        let _ = cleanup_or_prune_rotated_logs_async(&def, &stderr_path, now_sys).await;

        // Optional: rotate/cleanup stop_command stdout/stderr logs too.
        if let Some(p) = resolve_stop_command_log(def.stop_command_stdout.as_ref(), &def.working_directory) {
            let _ = cleanup_or_prune_rotated_logs_async(&def, &p, now_sys).await;
        }
        if let Some(p) = resolve_stop_command_log(def.stop_command_stderr.as_ref(), &def.working_directory) {
            let _ = cleanup_or_prune_rotated_logs_async(&def, &p, now_sys).await;
        }
    }
    Ok(())
}

async fn cleanup_or_prune_rotated_logs_async(def: &AppDefinition, base_path: &Path, now: std::time::SystemTime) -> anyhow::Result<()> {
    match def.rotation_mode {
        LogRotationMode::Time => cleanup_rotated_logs_async(base_path, def.rotation_max_age_ms, now).await,
        LogRotationMode::Size => {
            let keep = def.rotation_backups.unwrap_or(10);
            prune_numbered_backups_async(base_path, keep).await
        }
    }
}

async fn prune_numbered_backups_async(base_path: &Path, keep: usize) -> anyhow::Result<()> {
    let Some(dir) = base_path.parent() else { return Ok(()) };
    let Some(base_name) = base_path.file_name().and_then(|s| s.to_str()) else { return Ok(()) };
    let prefix = format!("{base_name}.");

    let mut rd = match tokio::fs::read_dir(dir).await {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };
    let mut nums: Vec<(u64, PathBuf)> = vec![];
    while let Ok(Some(e)) = rd.next_entry().await {
        let p = e.path();
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else { continue };
        if !name.starts_with(&prefix) {
            continue;
        }
        // Only prune numeric suffix backups: base.<N> or base.<N>.gz
        let mut suffix = &name[prefix.len()..];
        if let Some(s) = suffix.strip_suffix(".gz") {
            suffix = s;
        }
        if suffix.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(n) = suffix.parse::<u64>() {
                nums.push((n, p));
            }
        }
    }
    // delete any backups with N > keep
    for (n, p) in nums {
        if n as usize > keep {
            let _ = tokio::fs::remove_file(&p).await;
        }
    }
    Ok(())
}

async fn cleanup_rotated_logs_async(base_path: &Path, max_age_ms: u64, now: std::time::SystemTime) -> anyhow::Result<()> {
    let Some(dir) = base_path.parent() else { return Ok(()) };
    let Some(base_name) = base_path.file_name().and_then(|s| s.to_str()) else { return Ok(()) };
    let prefix = format!("{base_name}.");
    let cutoff = if max_age_ms == 0 {
        std::time::SystemTime::UNIX_EPOCH
    } else {
        now.checked_sub(Duration::from_millis(max_age_ms))
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
    };

    let mut rd = match tokio::fs::read_dir(dir).await {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };
    while let Ok(Some(e)) = rd.next_entry().await {
        let p = e.path();
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else { continue };
        if !name.starts_with(&prefix) {
            continue;
        }
        let m = match e.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        let mt = match m.modified() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if mt < cutoff {
            let _ = tokio::fs::remove_file(&p).await;
        }
    }
    Ok(())
}

fn setup_master_cgroup_or_instructions(cfg: &MasterConfig) -> anyhow::Result<()> {
    // If running unprivileged, proactively validate that the cgroup subtree has been delegated
    // (writable, controllers enabled, and child creation allowed).
    if !geteuid().is_root() {
        ensure_cgroup_access_or_instructions(cfg)?;
    }
    if let Err(e) = setup_master_cgroup(cfg) {
        if !geteuid().is_root() {
            // Non-root: print actionable instructions and then return the original error.
            let _ = ensure_cgroup_access_or_instructions(cfg);
        }
        return Err(e);
    }
    Ok(())
}

/// Resolve the effective master cgroup path.
///
/// For root, this is simply `${cgroup_root}/${cgroup_name}`.
///
/// For non-root, this is still `${cgroup_root}/${cgroup_name}`. We do not auto-detect or
/// auto-rewrite the path based on `/proc/self/cgroup`. If the configured cgroup path isn't
/// delegated to the current user, later preflight / attach steps will fail with a clear error.
fn effective_master_cgroup_path(cfg: &MasterConfig) -> anyhow::Result<PathBuf> {
    let root = PathBuf::from(&cfg.cgroup_root);
    let name = cfg.cgroup_name.trim();
    if name.is_empty() {
        anyhow::bail!("cgroup.name is empty");
    }
    // Basic sanity to avoid weird paths.
    if name.split('/').any(|seg| seg == "..") {
        anyhow::bail!("cgroup.name must not contain '..'");
    }

    // Respect configured cgroup root/name. Allow a leading '/' for convenience on name.
    Ok(root.join(name.trim_start_matches('/')))
}

fn setup_master_cgroup(cfg: &MasterConfig) -> anyhow::Result<()> {
    let cg_path = effective_master_cgroup_path(cfg)?;
    // Log how we resolved the effective path (helps a lot for unprivileged mode debugging).
    let cgroup_text = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let self_cg = cgroup_text
        .lines()
        .find_map(|line| {
            // cgroup v2 format: "0::/some/path"
            let mut parts = line.splitn(3, ':');
            let hier = parts.next()?;
            let _controllers = parts.next()?;
            let path = parts.next()?;
            if hier == "0" {
                Some(path.trim())
            } else {
                None
            }
        })
        .unwrap_or("/");
    pm_event(
        "cgroup",
        None,
        format!(
            "master_cgroup_resolve configured_root={} configured_name={} effective_path={} self_cgroup={} euid={}",
            cfg.cgroup_root,
            cfg.cgroup_name,
            cg_path.display(),
            self_cg,
            geteuid().as_raw(),
        ),
    );
    fs::create_dir_all(&cg_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to create master cgroup {}: {e}",
            cg_path.display()
        )
    })?;

    // Enable controllers for children (cgroup v2).
    // If these are not enabled, child cgroups won't be able to use those controller knobs.
    if cfg.cgroup_subtree_control_allow {
        enable_all_subtree_controllers(&cg_path)?;
    } else {
        // Conservative default list (legacy behavior).
        enable_subtree_controllers(&cg_path, &["cpu", "memory", "io", "pids", "misc"])?;
    }

    // Apply limits.
    let cpu_max = to_cpu_max_string(&cfg.cgroup_cpu_max)?;
    let mem_max = to_mem_max_string(&cfg.cgroup_memory_max)?;
    let swap_max = to_mem_max_string(&cfg.cgroup_memory_swap_max)?;

    fs::write(cg_path.join("cpu.max"), cpu_max.as_bytes()).map_err(|e| {
        anyhow::anyhow!("failed to write cpu.max for {}: {e}", cg_path.display())
    })?;
    fs::write(cg_path.join("memory.max"), mem_max.as_bytes()).map_err(|e| {
        anyhow::anyhow!("failed to write memory.max for {}: {e}", cg_path.display())
    })?;
    fs::write(cg_path.join("memory.swap.max"), swap_max.as_bytes()).map_err(|e| {
        anyhow::anyhow!(
            "failed to write memory.swap.max for {}: {e}",
            cg_path.display()
        )
    })?;

    // IMPORTANT (cgroup v2): the "no internal processes" rule means the cgroup that contains
    // child cgroups for apps (domain controllers like cpu/memory) should not itself contain
    // processes. So we keep `${cgroup_name}` as a pure parent and move processmaster into a
    // dedicated leaf child cgroup.
    //
    // Naming convention: `${cgroup_name}/run` is always the daemon's own leaf cgroup.
    let pm_cg = cg_path.join("run");
    fs::create_dir_all(&pm_cg).map_err(|e| {
        anyhow::anyhow!(
            "failed to create processmaster cgroup {}: {e}",
            pm_cg.display()
        )
    })?;

    // Unprivileged mode check: try a harmless write to cgroup.procs to validate delegation.
    //
    // Writing an invalid PID like "0" should not move any processes; kernels typically return
    // EINVAL when delegation is OK, and EPERM/EACCES when the subtree isn't actually delegated.
    if !geteuid().is_root() {
        let procs = pm_cg.join("cgroup.procs");
        match fs::write(&procs, "0\n") {
            Ok(()) => {}
            Err(e) => {
                // If we get EINVAL, that generally means we were allowed to write, but the value
                // is rejected (expected). Treat it as success.
                if e.raw_os_error() == Some(libc::EINVAL) {
                    // ok
                } else {
                    anyhow::bail!(
                        "cgroup appears not delegated for unprivileged attach: cannot write to {}: {e}\n\
hint: on systemd systems, you typically must run processmaster in a delegated unit/scope (Delegate=yes),\n\
      and keep the cgroup subtree under that unit.\n\
try:  systemd-run --user --scope -p Delegate=yes processmaster -c <config>\n\
or:   run processmaster as root",
                        procs.display()
                    );
                }
            }
        }
    }

    // Before moving ourselves into the daemon leaf cgroup, kill any leftover processes in that cgroup.
    // This cleans up orphaned launcher --wait helpers from previous crashes/restarts.
    kill_orphan_pids_in_cgroup_procs_file(None, "cgroup", &pm_cg.join("cgroup.procs"), None);

    let pid = std::process::id();
    fs::write(pm_cg.join("cgroup.procs"), format!("{pid}\n")).map_err(|e| {
        anyhow::anyhow!(
            "failed to move processmaster pid {pid} into cgroup {}: {e}\n\
hint: this can happen if the target cgroup isn't delegated to the current user/session (common on systemd),\n\
      or if the master cgroup already has internal processes.\n\
recommended: run processmaster under a delegated systemd scope (Delegate=yes), or run as root.\n\
diagnostic: current cgroup is from /proc/self/cgroup; if you're in /user.slice/... you generally cannot attach to /processmaster.",
            pm_cg.display()
        )
    })?;

    Ok(())
}

fn enable_subtree_controllers(parent: &Path, wanted: &[&str]) -> anyhow::Result<()> {
    let controllers_path = parent.join("cgroup.controllers");
    let subtree_path = parent.join("cgroup.subtree_control");
    let controllers = fs::read_to_string(&controllers_path)
        .with_context(|| format!("read {}", controllers_path.display()))?;
    let available: std::collections::HashSet<&str> = controllers.split_whitespace().collect();
    let mut ops: Vec<String> = vec![];
    for &c in wanted {
        if available.contains(c) {
            ops.push(format!("+{c}"));
        }
    }
    if ops.is_empty() {
        return Ok(());
    }
    fs::write(&subtree_path, format!("{}\n", ops.join(" ")))
        .with_context(|| format!("write {}", subtree_path.display()))?;
    Ok(())
}

fn enable_all_subtree_controllers(parent: &Path) -> anyhow::Result<()> {
    let controllers_path = parent.join("cgroup.controllers");
    let controllers = fs::read_to_string(&controllers_path)
        .with_context(|| format!("read {}", controllers_path.display()))?;
    let all: Vec<&str> = controllers
        .split_whitespace()
        .filter(|s| !s.trim().is_empty())
        .collect();
    if all.is_empty() {
        // Not an error: some kernels may expose no controllers here depending on mount and delegation.
        return Ok(());
    }
    enable_subtree_controllers(parent, &all)
}

fn kill_orphan_pids_in_cgroup_procs_file(
    state: Option<&Arc<Mutex<DaemonState>>>,
    component: &str,
    cgroup_procs: &Path,
    exclude_pid: Option<u32>,
) {
    let text = match fs::read_to_string(cgroup_procs) {
        Ok(t) => t,
        Err(_) => return,
    };
    let mut pids: Vec<i32> = vec![];
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Ok(pid) = t.parse::<i32>() {
            if let Some(ex) = exclude_pid {
                if pid == ex as i32 {
                    continue;
                }
            }
            // Skip obviously invalid entries.
            if pid > 1 {
                pids.push(pid);
            }
        }
    }
    if pids.is_empty() {
        return;
    }

    let filtered = pids;

    let msg = format!(
        "found_orphans cgroup_procs={} count={} exclude_pid={}",
        cgroup_procs.display(),
        filtered.len(),
        exclude_pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string())
    );
    match state {
        Some(st) => pm_event_state(st, component, None, msg),
        None => pm_event(component, None, msg),
    }

    // Try TERM first, then KILL.
    for pid in &filtered {
        let _ = kill(Pid::from_raw(*pid), Signal::SIGTERM);
    }
    std::thread::sleep(Duration::from_millis(300));
    for pid in &filtered {
        let _ = kill(Pid::from_raw(*pid), Signal::SIGKILL);
    }

    let msg2 = format!(
        "cleanup_orphans_done cgroup_procs={} killed_count={}",
        cgroup_procs.display(),
        filtered.len()
    );
    match state {
        Some(st) => pm_event_state(st, component, None, msg2),
        None => pm_event(component, None, msg2),
    }
}

fn wait_until_empty(cfg: &MasterConfig, app: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if !cgroup_running(cfg, app).unwrap_or(true) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn to_cpu_max_string(s: &str) -> anyhow::Result<String> {
    let t = s.trim();
    if t.eq_ignore_ascii_case("max") || t == "MAX" {
        return Ok("max 100000\n".to_string());
    }
    // If the user already provided "quota period", pass through.
    if t.split_whitespace().count() >= 2 {
        return Ok(format!("{t}\n"));
    }
    // Otherwise interpret as "millicores" / "cores" like app cpu (e.g. 100m, 1.0).
    let mc = crate::pm::app::parse_cpu_millicores(t)?;
    let period: u64 = 100_000;
    let quota = (period * mc) / 1000;
    Ok(format!("{quota} {period}\n"))
}

fn to_mem_max_string(s: &str) -> anyhow::Result<String> {
    let t = s.trim();
    if t.eq_ignore_ascii_case("max") || t == "MAX" {
        return Ok("max\n".to_string());
    }
    let bytes = parse_size_spec_bytes(t)?;
    Ok(format!("{bytes}\n"))
}

/// Parse a human-friendly size into bytes.
///
/// Supports:
/// - raw bytes: `"1234"`
/// - base10: `k/m/g/t` with optional `b` suffix: `"10m"`, `"10MB"`
/// - base2: `ki/mi/gi/ti` with optional `b` suffix: `"64MiB"`
/// - decimal numbers: `"1.5GiB"`
///
/// Note: this is used for both memory settings and log size rotation.
pub(crate) fn parse_size_spec_bytes(s: &str) -> anyhow::Result<u64> {
    let t = s.trim();
    if t.is_empty() {
        anyhow::bail!("empty size");
    }
    // plain integer
    if t.chars().all(|c| c.is_ascii_digit()) {
        return Ok(t.parse()?);
    }
    // split numeric + unit
    let mut idx = 0usize;
    for (i, ch) in t.char_indices() {
        if !(ch.is_ascii_digit() || ch == '.') {
            idx = i;
            break;
        }
    }
    if idx == 0 {
        anyhow::bail!("invalid size: {s}");
    }
    let (num_s, unit_s) = t.split_at(idx);
    let num: f64 = num_s.parse()?;
    if num < 0.0 {
        anyhow::bail!("size must be >= 0");
    }
    // Units:
    // - raw bytes: plain number
    // - k/m/g/t (base10) with optional trailing b/B
    // - ki/mi/gi/ti (base2) with optional trailing b/B
    // - case-insensitive; "k" == "kb", "ki" == "kib", etc.
    let mut unit = unit_s.trim().to_ascii_lowercase();
    if unit.ends_with('b') {
        unit.pop();
    }
    let mult: f64 = match unit.as_str() {
        "" => 1.0,
        "b" => 1.0,
        "k" | "kb" => 1000.0,
        "m" | "mb" => 1000.0_f64.powi(2),
        "g" | "gb" => 1000.0_f64.powi(3),
        "t" | "tb" => 1000.0_f64.powi(4),
        "ki" | "kib" => 1024.0,
        "mi" | "mib" => 1024.0_f64.powi(2),
        "gi" | "gib" => 1024.0_f64.powi(3),
        "ti" | "tib" => 1024.0_f64.powi(4),
        _ => anyhow::bail!("unknown size unit: {unit_s} (try k/m/g/t or ki/mi/gi/ti, optional b)"),
    };
    Ok((num * mult).round() as u64)
}

fn apply_socket_settings(cfg: &MasterConfig) -> anyhow::Result<()> {
    // chmod (best-effort, but error if requested and we can't apply)
    let mode = cfg.sock_mode;
    let perms = PermissionsExt::from_mode(mode);
    std::fs::set_permissions(&cfg.sock, perms).map_err(|e| {
        anyhow::anyhow!(
            "failed to chmod socket {} to {:o}: {e}",
            cfg.sock.display(),
            mode
        )
    })?;

    // chown if requested
    if cfg.sock_owner.is_none() && cfg.sock_group.is_none() {
        return Ok(());
    }

    if !geteuid().is_root() {
        anyhow::bail!(
            "sock_owner/sock_group configured but process is not root; cannot chown {}",
            cfg.sock.display()
        );
    }

    let uid = match cfg.sock_owner.as_deref() {
        None => None,
        Some(u) => {
            let user = get_user_by_name(u).ok_or_else(|| anyhow::anyhow!("unknown sock_owner user: {u}"))?;
            Some(Uid::from_raw(user.uid()))
        }
    };
    let gid = match cfg.sock_group.as_deref() {
        None => None,
        Some(g) => {
            let group = get_group_by_name(g).ok_or_else(|| anyhow::anyhow!("unknown sock_group group: {g}"))?;
            Some(Gid::from_raw(group.gid()))
        }
    };
    chown(&cfg.sock, uid, gid).map_err(|e| {
        anyhow::anyhow!(
            "failed to chown socket {} to {:?}:{:?}: {e}",
            cfg.sock.display(),
            cfg.sock_owner,
            cfg.sock_group
        )
    })?;
    Ok(())
}

fn ensure_cgroup_access_or_instructions(cfg: &MasterConfig) -> anyhow::Result<()> {
    let cg_path = effective_master_cgroup_path(cfg)?;

    let euid = geteuid();
    let egid = getegid();
    let cur_user = get_user_by_uid(euid.as_raw())
        .map(|u| u.name().to_string_lossy().to_string())
        .unwrap_or_else(|| euid.as_raw().to_string());
    let cur_group = get_group_by_gid(egid.as_raw())
        .map(|g| g.name().to_string_lossy().to_string())
        .unwrap_or_else(|| egid.as_raw().to_string());

    // Does it exist and is it a directory?
    match fs::metadata(&cg_path) {
        Ok(m) if m.is_dir() => {}
        Ok(_) | Err(_) => {
            eprintln!(
                "cgroup path {} is missing (or not a directory). To use cgroups as a non-root user, run the following as root:\n\
\n\
  mkdir -p {p}\n\
  chown {u}:{g} {p}\n\
  chmod 0775 {p}\n",
                cg_path.display(),
                p = cg_path.display(),
                u = cur_user,
                g = cur_group
            );
            anyhow::bail!("cgroup not set up for non-root usage: {}", cg_path.display());
        }
    }

    // Ensure controllers are enabled for children at this delegated subtree.
    // (cgroup v2: available controllers are in cgroup.controllers; enabled for children are in cgroup.subtree_control)
    let controllers_path = cg_path.join("cgroup.controllers");
    let subtree_path = cg_path.join("cgroup.subtree_control");
    let controllers = fs::read_to_string(&controllers_path).unwrap_or_default();
    let subtree = fs::read_to_string(&subtree_path).unwrap_or_default();
    if cfg.cgroup_subtree_control_allow {
        for c in controllers.split_whitespace().filter(|s| !s.trim().is_empty()) {
            if !subtree.split_whitespace().any(|x| x == c) {
                eprintln!(
                    "cgroup subtree {} exists but controllers are not enabled for children (missing {c:?} in {}).\n\
To enable all available controllers as root, run:\n\
\n\
  cat {} | sed 's/^/+/' | tr '\\n' ' ' | xargs echo > {}\n\
  # or: echo +<controller> +<controller> ... > {}\n",
                    cg_path.display(),
                    subtree_path.display(),
                    controllers_path.display(),
                    subtree_path.display(),
                    subtree_path.display()
                );
                anyhow::bail!(
                    "cgroup controllers not enabled for unprivileged usage: {}",
                    cg_path.display()
                );
            }
        }
    } else {
        let want = ["cpu", "memory", "io", "pids", "misc"];
        for c in want {
            if !controllers.split_whitespace().any(|x| x == c) {
                anyhow::bail!(
                    "cgroup subtree {} does not have controller {c:?} available (missing in {}); cannot run unprivileged",
                    cg_path.display(),
                    controllers_path.display()
                );
            }
            if !subtree.split_whitespace().any(|x| x == c) {
                eprintln!(
                    "cgroup subtree {} exists but controllers are not enabled for children (missing {c:?} in {}).\n\
To enable controllers as root, run:\n\
\n\
  echo +cpu +memory +io +pids +misc > {}\n",
                    cg_path.display(),
                    subtree_path.display(),
                    subtree_path.display()
                );
                anyhow::bail!(
                    "cgroup controllers not enabled for unprivileged usage: {}",
                    cg_path.display()
                );
            }
        }
    }

    // Check whether we can create a subgroup (needed for appgroups).
    let probe = cg_path.join(format!(".pm_probe_{}", std::process::id()));
    match fs::create_dir(&probe) {
        Ok(_) => {
            let _ = fs::remove_dir(&probe);
            // Also verify we can at least attempt to write cgroup.procs in a child.
            // This catches missing delegation early (EPERM) and is more actionable than failing
            // later when moving the daemon itself.
            let pm_cg = cg_path.join("run");
            let _ = fs::create_dir_all(&pm_cg);
            let procs = pm_cg.join("cgroup.procs");
            match fs::write(&procs, "0\n") {
                Ok(()) => Ok(()),
                Err(e) if e.raw_os_error() == Some(libc::EINVAL) => Ok(()),
                Err(e) => {
                    eprintln!(
                        "cgroup subtree {} exists, but attaching processes is not permitted ({}: {e}).\n\
This usually means the subtree is not delegated by systemd, even if files are chowned.\n\
Recommended (systemd):\n\
\n\
  systemd-run --user --scope -p Delegate=yes processmaster -c <config>\n\
\n\
Then keep cgroups under the unit's current cgroup (processmaster will do this automatically\n\
for non-root when cgroup.name is a simple name).",
                        cg_path.display(),
                        procs.display(),
                    );
                    Err(anyhow::anyhow!(
                        "cgroup not usable for unprivileged operation (cannot write {}): {e}",
                        procs.display()
                    ))
                }
            }
        }
        Err(e) => {
            eprintln!(
                "cgroup path {} exists but is not writable by {u}:{g}.\n\
To use cgroups as a non-root user, run the following as root:\n\
\n\
  chown {u}:{g} {p}\n\
  chmod 0775 {p}\n",
                cg_path.display(),
                p = cg_path.display(),
                u = cur_user,
                g = cur_group
            );
            Err(anyhow::anyhow!(
                "cannot create sub-cgroups under {}: {e}",
                cg_path.display()
            ))
        }
    }
}

fn start_child_reaper_thread() {
    std::thread::spawn(move || loop {
        // Reap all exited children without blocking.
        loop {
            match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    });
}

fn prepare_socket(sock: &Path) -> anyhow::Result<()> {
    if let Some(parent) = sock.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            anyhow::anyhow!(
                "failed to create socket directory {}: {e}",
                parent.display()
            )
        })?;
    }

    if sock.exists() {
        // If something is already listening, fail. Otherwise remove stale socket.
        match UnixStream::connect(sock) {
            Ok(_) => anyhow::bail!(
                "pm daemon already running (socket {} is accepting connections)",
                sock.display()
            ),
            Err(_) => {
                fs::remove_file(sock).map_err(|e| {
                    anyhow::anyhow!("failed to remove stale socket {}: {e}", sock.display())
                })?;
            }
        }
    }
    Ok(())
}

async fn handle_connection_async(
    state: Arc<Mutex<DaemonState>>,
    stream: tokio::net::UnixStream,
) -> anyhow::Result<()> {
    let mut reader = TokioBufReader::new(stream);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 || line.trim().is_empty() {
        return Ok(());
    }
    let wire: crate::pm::rpc::WireRequest = serde_json::from_str(line.trim_end())?;

    // Grab the underlying stream back so we can write response (or hand to follow).
    let mut stream = reader.into_inner();

    let daemon_build_time = option_env!("PROCESSMASTER_BUILD_TIME").unwrap_or("unknown");
    let daemon_build_host = option_env!("PROCESSMASTER_BUILD_HOST").unwrap_or("unknown");
    if wire.client.build_time != daemon_build_time || wire.client.build_host != daemon_build_host {
        let resp = Response {
            ok: false,
            message: format!(
                "pmctl is not co-built with this daemon.\n\
daemon: build_time={daemon_build_time} build_host={daemon_build_host}\n\
client: build_time={} build_host={}\n\
\n\
Fix: use the `pmctl` binary built from the same build/release as the running daemon.",
                wire.client.build_time, wire.client.build_host
            ),
            restarted: vec![],
            statuses: vec![],
            events: vec![],
            admin_actions: vec![],
        };
        let resp_line = serde_json::to_string(&resp)? + "\n";
        stream.write_all(resp_line.as_bytes()).await?;
        stream.flush().await?;
        return Ok(());
    }

    match wire.request {
        Request::LogsFollow { name, filename, n, .. } => {
            // Long-running follow loop; keep it off the core runtime threads for now.
            let std_stream = stream.into_std()?;
            let _ = std_stream.set_nonblocking(false);
            let st = Arc::clone(&state);
            tasks().spawn_blocking(move || handle_logs_follow(st, std_stream, name, filename, n))
                .await
                .map_err(|e| anyhow::anyhow!("join error: {e}"))??;
            Ok(())
        }
        other => {
            let resp = match dispatch_async(state, other).await {
                Ok(r) => r,
                Err(e) => Response {
                    ok: false,
                    // Use the full anyhow chain so clients can actually debug failures (e.g. spawn/pre_exec/cgroup issues).
                    message: format!("{e:#}"),
                    restarted: vec![],
                    statuses: vec![],
                    events: vec![],
                    admin_actions: vec![],
                },
            };
            let resp_line = serde_json::to_string(&resp)? + "\n";
            stream.write_all(resp_line.as_bytes()).await?;
            stream.flush().await?;
            Ok(())
        }
    }
}

pub(crate) async fn dispatch_async(state: Arc<Mutex<DaemonState>>, req: Request) -> anyhow::Result<Response> {
    match req {
        Request::Update => do_update_async(&state).await,
        Request::AdminAction { name } => do_admin_action_async(&state, &name).await,
        Request::AdminList => do_admin_list(&state),
        Request::AdminKill => do_admin_kill(&state),
        Request::AdminPs => do_admin_ps(&state),
        Request::ServerVersion => do_server_version(),
        Request::Start { name, force } => do_start_async(&state, &name, force).await,
        Request::Stop { name } => do_stop_async(&state, &name).await,
        Request::Restart { name, force } => do_restart_async(&state, &name, force).await,
        Request::StartAll { force } => do_start_all_async(&state, force).await,
        Request::StopAll => do_stop_all_async(&state).await,
        Request::RestartAll { force } => do_restart_all_async(&state, force).await,
        Request::Flag { name, flags, ttl } => {
            tasks().spawn_blocking({
                let st = Arc::clone(&state);
                move || do_flag(&st, &name, &flags, ttl.as_deref())
            })
            .await
            .map_err(|e| anyhow::anyhow!("join error: {e}"))?
        }
        Request::Unflag { name, flags } => {
            tasks().spawn_blocking({
                let st = Arc::clone(&state);
                move || do_unflag(&st, &name, &flags)
            })
            .await
            .map_err(|e| anyhow::anyhow!("join error: {e}"))?
        }
        Request::Enable { name } => do_set_enabled_async(&state, &name, true).await,
        Request::Disable { name } => do_set_enabled_async(&state, &name, false).await,
        Request::Logs { name, n } => {
            tasks().spawn_blocking({
                let st = Arc::clone(&state);
                move || do_logs(&st, &name, n)
            })
            .await
            .map_err(|e| anyhow::anyhow!("join error: {e}"))?
        }
        Request::Status { name } => {
            tasks().spawn_blocking({
                let st = Arc::clone(&state);
                move || do_status(&st, name.as_deref())
            })
            .await
            .map_err(|e| anyhow::anyhow!("join error: {e}"))?
        }
        Request::Events { name, n } => {
            tasks().spawn_blocking({
                let st = Arc::clone(&state);
                move || do_events(&st, name.as_deref(), n)
            })
            .await
            .map_err(|e| anyhow::anyhow!("join error: {e}"))?
        }
        _ => Err(anyhow::anyhow!("unsupported request")),
    }
}

// Compatibility helper (some call sites may format build-time strings for display).
#[allow(dead_code)]
pub(crate) fn format_build_time_pretty(raw: &str) -> String {
    crate::pm::build_info::format_build_time_pretty(raw)
}

fn do_server_version() -> anyhow::Result<Response> {
    Ok(Response {
        ok: true,
        message: crate::pm::build_info::banner(),
        restarted: vec![],
        statuses: vec![],
        events: vec![],
        admin_actions: vec![],
    })
}

fn admin_actions_cgroup_dir(cfg: &MasterConfig) -> anyhow::Result<PathBuf> {
    Ok(effective_master_cgroup_path(cfg)?.join("admin_actions"))
}

fn do_admin_ps(state: &Arc<Mutex<DaemonState>>) -> anyhow::Result<Response> {
    let cfg = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        st.cfg.clone()
    };
    let cg = admin_actions_cgroup_dir(&cfg)?;
    let mut pids = crate::pm::cgroup::list_pids(&cg).unwrap_or_default();
    pids.sort();
    let msg = if pids.is_empty() {
        "(none)".to_string()
    } else {
        pids.iter().map(|p| p.to_string()).collect::<Vec<_>>().join("\n")
    };
    Ok(Response {
        ok: true,
        message: msg,
        restarted: vec![],
        statuses: vec![],
        events: vec![],
        admin_actions: vec![],
    })
}

fn do_admin_list(state: &Arc<Mutex<DaemonState>>) -> anyhow::Result<Response> {
    let actions = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        st.cfg
            .admin_actions
            .iter()
            .map(|(name, a)| crate::pm::rpc::AdminActionInfo {
                name: name.clone(),
                label: a.label.clone().unwrap_or_else(|| name.clone()),
            })
            .collect::<Vec<_>>()
    };
    Ok(Response {
        ok: true,
        message: String::new(),
        restarted: vec![],
        statuses: vec![],
        events: vec![],
        admin_actions: actions,
    })
}

fn do_admin_kill(state: &Arc<Mutex<DaemonState>>) -> anyhow::Result<Response> {
    let cfg = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        st.cfg.clone()
    };
    let cg = admin_actions_cgroup_dir(&cfg)?;
    let before = crate::pm::cgroup::list_pids(&cg).unwrap_or_default();
    crate::pm::cgroup::kill_all_pids(&cg)?;
    pm_event_state(
        state,
        "admin_action",
        None,
        format!("decision=kill_all cgroup={} pids_before={}", cg.display(), before.len()),
    );
    Ok(Response {
        ok: true,
        message: format!("killed admin actions via cgroup.kill (pids_before={})", before.len()),
        restarted: vec![],
        statuses: vec![],
        events: vec![],
        admin_actions: vec![],
    })
}

async fn do_admin_action_async(state: &Arc<Mutex<DaemonState>>, name: &str) -> anyhow::Result<Response> {
    if !geteuid().is_root() {
        return Ok(Response {
            ok: false,
            message: "admin_action requires the daemon to run as root".to_string(),
            restarted: vec![],
            statuses: vec![],
            events: vec![],
            admin_actions: vec![],
        });
    }

    let (label, argv, cfg) = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        match st.cfg.admin_actions.get(name) {
            Some(a) => (
                a.label.clone().unwrap_or_else(|| name.to_string()),
                a.command.clone(),
                st.cfg.clone(),
            ),
            None => {
                return Ok(Response {
                    ok: false,
                    message: format!("admin_action {name:?} is not configured in the main config (admin_actions)"),
                    restarted: vec![],
                    statuses: vec![],
                    events: vec![],
                    admin_actions: vec![],
                });
            }
        }
    };

    if argv.is_empty() {
        return Ok(Response {
            ok: false,
            message: format!("admin_action {name:?} has empty command"),
            restarted: vec![],
            statuses: vec![],
            events: vec![],
            admin_actions: vec![],
        });
    }

    pm_event_state(
        state,
        "admin_action",
        None,
        format!("decision=spawn name={name} label={label:?} argv={}", argv.join(" ")),
    );

    // Capture output for debugging (best-effort, but fail fast if we can't open the files).
    let logs_dir = PathBuf::from("./logs");
    fs::create_dir_all(&logs_dir).map_err(|e| {
        anyhow::anyhow!(
            "failed to create admin_action logs dir {}: {e}",
            logs_dir.display()
        )
    })?;
    let stdout_path = logs_dir.join("admin_action_stdout.log");
    let stderr_path = logs_dir.join("admin_action_stderr.log");
    let stdout_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&stdout_path)
        .map_err(|e| anyhow::anyhow!("failed to open {}: {e}", stdout_path.display()))?;
    let stderr_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&stderr_path)
        .map_err(|e| anyhow::anyhow!("failed to open {}: {e}", stderr_path.display()))?;

    // Place all admin actions under a dedicated cgroup so operators can inspect/kill them.
    // Example (default config): /sys/fs/cgroup/processmaster/admin_actions
    let admin_cg = effective_master_cgroup_path(&cfg)?.join("admin_actions");

    let argv_os: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let mut p = cgroup::LaunchParams::new(argv_os, PathBuf::from("."), admin_cg);
    p.environment.push((
        OsString::from("PROCESSMASTER_ADMIN_ACTION"),
        OsString::from(name),
    ));
    let mut cmd = cgroup::build_command(&p)?;
    // Fire-and-forget: don't tie up the daemon waiting on output pipes.
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(stdout_file))
        .stderr(std::process::Stdio::from(stderr_file));

    let child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn admin_action {name:?}: {e}"))?;
    let pid = child.id();
    // Drop the child handle to "disown" it. The daemon's child reaper thread will reap it.
    drop(child);

    pm_event_state(
        state,
        "admin_action",
        None,
        format!("outcome=spawned name={name} pid={pid}"),
    );

    Ok(Response {
        ok: true,
        message: format!("admin_action {name} spawned pid={pid}"),
        restarted: vec![],
        statuses: vec![],
        events: vec![],
        admin_actions: vec![],
    })
}

fn do_events(state: &Arc<Mutex<DaemonState>>, name: Option<&str>, n: usize) -> anyhow::Result<Response> {
    let events = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        Arc::clone(&st.events)
    };
    let q = events.lock().unwrap_or_else(|p| p.into_inner());
    let mut v: Vec<EventEntry> = q
        .iter()
        .filter(|e| match name {
            None => true,
            Some(app) => e.app.as_deref() == Some(app),
        })
        .cloned()
        .collect();
    if v.len() > n {
        v = v[v.len() - n..].to_vec();
    }
    Ok(Response {
        ok: true,
        message: String::new(),
        restarted: vec![],
        statuses: vec![],
        events: v,
        admin_actions: vec![],
    })
}

async fn do_set_enabled_async(state: &Arc<Mutex<DaemonState>>, name: &str, enabled: bool) -> anyhow::Result<Response> {
    let source_file = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        let def = st
            .defs
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("unknown service: {name}"))?;
        def.source_file
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("service {name} has no source_file; cannot edit"))?
    };

    let source_file2 = source_file.clone();
    tasks().spawn_blocking(move || set_enabled_in_yaml(&source_file2, enabled))
        .await
        .map_err(|e| anyhow::anyhow!("join error: {e}"))??;

    // Reload definitions so status/start/stop reflect the new enabled flag immediately.
    let _ = do_update_async(state).await?;

    Ok(Response {
        ok: true,
        message: format!("{} {}", if enabled { "enabled" } else { "disabled" }, name),
        restarted: vec![],
        statuses: vec![],
        events: vec![],
        admin_actions: vec![],
    })
}

fn set_enabled_in_yaml(path: &Path, enabled: bool) -> anyhow::Result<()> {
    let raw = fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;
    let mut v: serde_yaml::Value = serde_yaml::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("failed to parse {}: {e}", path.display()))?;

    let mapping = v
        .as_mapping_mut()
        .ok_or_else(|| anyhow::anyhow!("{} is not a YAML mapping/object", path.display()))?;

    // App configs are grouped; enabled is stored at global.enabled.
    let global_key = serde_yaml::Value::String("global".to_string());
    let enabled_key = serde_yaml::Value::String("enabled".to_string());

    let global_val = mapping
        .entry(global_key)
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));

    let global_map = global_val
        .as_mapping_mut()
        .ok_or_else(|| anyhow::anyhow!("{}.global is not a YAML mapping/object", path.display()))?;

    global_map.insert(enabled_key, serde_yaml::Value::Bool(enabled));

    let out = serde_yaml::to_string(&v)?;
    fs::write(path, out)
        .map_err(|e| anyhow::anyhow!("failed to write {}: {e}", path.display()))?;
    Ok(())
}

fn do_logs(state: &Arc<Mutex<DaemonState>>, name: &str, n: usize) -> anyhow::Result<Response> {
    let def = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        st.defs
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown service: {name}"))?
    };

    let (stdout_path, stderr_path) = resolve_log_paths(&def);
    let mut files: Vec<PathBuf> = vec![stdout_path, stderr_path];
    for p in &def.alt_log_file_hint {
        files.push(resolve_under_workdir(&def.working_directory, p));
    }

    let mut out = String::new();
    for p in files {
        if !p.exists() {
            continue;
        }
        let display_path = canonicalize_for_display(&p);
        out.push_str(&format!("==> {} <==\n", display_path.display()));
        match tail_lines(&p, n) {
            Ok(s) => {
                out.push_str(&s);
                if !s.ends_with('\n') {
                    out.push('\n');
                }
            }
            Err(e) => {
                out.push_str(&format!("(failed to read: {e})\n"));
            }
        }
        out.push('\n');
    }
    if out.trim().is_empty() {
        out = format!("{name}: no log files found");
    }

    Ok(Response {
        ok: true,
        message: out.trim_end().to_string(),
        restarted: vec![],
        statuses: vec![],
        events: vec![],
        admin_actions: vec![],
    })
}

fn handle_logs_follow(
    state: Arc<Mutex<DaemonState>>,
    mut stream: UnixStream,
    name: Option<String>,
    filename: Option<String>,
    n: usize,
) -> anyhow::Result<()> {
    fn write_wrapped(stream: &mut UnixStream, display: &str, bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            let out_line = format!("{display}: \n");
            return stream.write_all(out_line.as_bytes()).is_ok();
        }
        let mut i = 0usize;
        while i < bytes.len() {
            let end = (i + LOGSFOLLOW_LINE_MAX_BYTES).min(bytes.len());
            let s = String::from_utf8_lossy(&bytes[i..end]);
            let out_line = format!("{display}: {s}\n");
            if stream.write_all(out_line.as_bytes()).is_err() {
                return false;
            }
            i = end;
        }
        true
    }

    // Send initial OK response as JSON line.
    let resp = Response {
        ok: true,
        message: String::new(),
        restarted: vec![],
        statuses: vec![],
        events: vec![],
        admin_actions: vec![],
    };
    let resp_line = serde_json::to_string(&resp)? + "\n";
    stream.write_all(resp_line.as_bytes())?;
    stream.flush()?;

    // Collect candidate files across apps (or one app if specified).
    let defs: Vec<AppDefinition> = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        if let Some(ref n) = name {
            vec![st
                .defs
                .get(n)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("unknown service: {n}"))?]
        } else {
            st.defs.values().cloned().collect()
        }
    };

    let mut paths: Vec<PathBuf> = vec![];
    for def in defs {
        let (stdout_path, stderr_path) = resolve_log_paths(&def);
        paths.push(stdout_path);
        paths.push(stderr_path);
        for p in &def.alt_log_file_hint {
            paths.push(resolve_under_workdir(&def.working_directory, p));
        }
    }

    // Filter + canonicalize existing files, dedup.
    let mut selected: Vec<PathBuf> = vec![];
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for p in paths {
        if !p.exists() {
            continue;
        }
        let canon = std::fs::canonicalize(&p).unwrap_or(p);
        if let Some(ref want) = filename {
            let base = canon.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if base != want {
                continue;
            }
        }
        if seen.insert(canon.clone()) {
            selected.push(canon);
        }
    }
    selected.sort();

    if selected.is_empty() {
        let msg = if let Some(want) = filename {
            format!("no log files found matching filename {want}")
        } else {
            "no log files found".to_string()
        };
        stream.write_all(msg.as_bytes())?;
        stream.write_all(b"\n")?;
        stream.flush()?;
        return Ok(());
    }

    // Initial tail per file.
    for p in &selected {
        let header = format!("==> {} <==\n", p.display());
        stream.write_all(header.as_bytes())?;
        if n > 0 {
            if let Ok(s) = tail_lines(p, n) {
                if !s.is_empty() {
                    // Keep the "tail" output plain (no per-line prefix), but still wrap long lines.
                    for line in s.split_terminator('\n') {
                        let b = line.as_bytes();
                        let mut i = 0usize;
                        while i < b.len() {
                            let end = (i + LOGSFOLLOW_LINE_MAX_BYTES).min(b.len());
                            if stream.write_all(&b[i..end]).is_err() {
                                return Ok(());
                            }
                            if stream.write_all(b"\n").is_err() {
                                return Ok(());
                            }
                            i = end;
                        }
                        if b.is_empty() {
                            let _ = stream.write_all(b"\n");
                        }
                    }
                }
            }
        }
        stream.write_all(b"\n")?;
    }
    stream.flush()?;

    // Follow: keep offsets and partial line buffers.
    struct FollowState {
        path: PathBuf,
        display: String,
        offset: u64,
        partial: Vec<u8>,
    }

    let mut fs = vec![];
    for p in selected {
        let len = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
        fs.push(FollowState {
            display: p.display().to_string(),
            path: p,
            offset: len,
            partial: vec![],
        });
    }

    loop {
        for st in fs.iter_mut() {
            let len = match fs::metadata(&st.path) {
                Ok(m) => m.len(),
                Err(_) => continue,
            };
            if len < st.offset {
                // truncated (copytruncate rotation) -> start over
                st.offset = 0;
                st.partial.clear();
            }
            if len == st.offset {
                continue;
            }
            let mut f = match std::fs::OpenOptions::new().read(true).open(&st.path) {
                Ok(f) => f,
                Err(_) => continue,
            };
            f.seek(SeekFrom::Start(st.offset))?;
            // Read the appended delta in bounded chunks to avoid allocating (len - offset) all at once.
            // This also keeps memory bounded if a file grows very quickly.
            let mut remaining = (len - st.offset) as usize;
            let mut carry = std::mem::take(&mut st.partial);
            while remaining > 0 {
                let take = remaining.min(LOGSFOLLOW_READ_CHUNK_BYTES);
                let mut buf = vec![0u8; take];
                if let Err(_) = std::io::Read::read_exact(&mut f, &mut buf) {
                    break;
                }
                st.offset += take as u64;
                remaining -= take;

                carry.extend_from_slice(&buf);

                // Emit complete lines from carry.
                let mut start = 0usize;
                for i in 0..carry.len() {
                    if carry[i] == b'\n' {
                        let line_bytes = &carry[start..i];
                        start = i + 1;
                        if !write_wrapped(&mut stream, &st.display, line_bytes) {
                            return Ok(());
                        }
                    }
                }

                // Keep remainder, but cap it (wrap-around) so we never buffer an unbounded "no newline" line.
                if start < carry.len() {
                    let mut rem = &carry[start..];
                    while rem.len() > LOGSFOLLOW_LINE_MAX_BYTES {
                        if !write_wrapped(&mut stream, &st.display, &rem[..LOGSFOLLOW_LINE_MAX_BYTES]) {
                            return Ok(());
                        }
                        rem = &rem[LOGSFOLLOW_LINE_MAX_BYTES..];
                    }
                    carry = rem.to_vec();
                } else {
                    carry.clear();
                }
            }
            st.partial = carry;
        }
        if stream.flush().is_err() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn canonicalize_for_display(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

fn tail_lines(path: &Path, n: usize) -> anyhow::Result<String> {
    if n == 0 {
        return Ok(String::new());
    }
    let mut f = std::fs::OpenOptions::new().read(true).open(path)?;
    let len = f.metadata()?.len();
    if len == 0 {
        return Ok(String::new());
    }

    // Read from the end in chunks until we have enough newlines.
    let mut pos = len;
    let mut newline_count: usize = 0;
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    while pos > 0 && newline_count <= n {
        let read_size = std::cmp::min(8192u64, pos) as usize;
        pos -= read_size as u64;
        f.seek(SeekFrom::Start(pos))?;
        let mut buf = vec![0u8; read_size];
        std::io::Read::read_exact(&mut f, &mut buf)?;
        newline_count += buf.iter().filter(|&&b| b == b'\n').count();
        chunks.push(buf);
        if chunks.len() > 512 {
            // Safety cap (~4MB) to avoid unbounded memory on huge line counts.
            break;
        }
    }
    chunks.reverse();
    let data = chunks.concat();
    let s = String::from_utf8_lossy(&data);
    let mut lines: Vec<&str> = s.split_terminator('\n').collect();
    if lines.len() > n {
        lines = lines[lines.len() - n..].to_vec();
    }
    Ok(lines.join("\n"))
}

async fn do_update_async(state: &Arc<Mutex<DaemonState>>) -> anyhow::Result<Response> {
    let (cfg, old_defs) = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        (st.cfg.clone(), st.defs.clone())
    };

    let cfg_dir = cfg.config_directory.clone();
    let auto_dir = cfg.auto_service_directory.clone();
    let old_defs_for_load = old_defs.clone();
    let (new_defs, warnings, outdated) = match tasks().spawn_blocking(move || {
        load_app_definitions_best_effort(
            &cfg_dir,
            &old_defs_for_load,
            auto_dir.as_deref(),
        )
    })
        .await
        .map_err(|e| anyhow::anyhow!("join error: {e}"))?
    {
        Ok(v) => v,
        Err(e) => {
            // Fail-safe: keep last-known-good config; do not disrupt a running system.
            pm_event_state(state, "reconcile", None, format!("update_skipped reason=config_load_failed err={e}"));
            return Ok(Response {
                ok: true,
                message: format!("update skipped: config load failed: {e} (kept last-known-good)"),
                restarted: vec![],
                statuses: vec![],
                events: vec![],
                admin_actions: vec![],
            });
        }
    };

    // Best-effort: any un-loadable/misconfigured services should have been skipped or kept from old_defs.

    // Determine which definitions were modified (mtime-based) so we can restart affected services after updating.
    // NOTE: this intentionally only considers services with a known YAML `source_file` and mtime.
    let mut modified_apps: Vec<String> = vec![];
    for (name, new_def) in &new_defs {
        if let Some(old_def) = old_defs.get(name) {
            if new_def.source_file.is_some() && old_def.source_file.is_some() {
                if let (Some(nm), Some(om)) = (new_def.source_mtime_ms, old_def.source_mtime_ms) {
                    if nm > om {
                        modified_apps.push(name.clone());
                    }
                }
            }
        }
    }
    modified_apps.sort();
    modified_apps.dedup();

    // Mark "outdated" system flag for any services that fell back to last-known-good on this update.
    // Clear it for other services that are currently defined.
    {
        let run_info = {
            let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
            Arc::clone(&st.run_info)
        };
        let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
        for app in new_defs.keys() {
            let e = ri.entry(app.clone()).or_default();
            if outdated.iter().any(|x| x == app) {
                sysflag_set(&mut e.system_flags, SystemFlag::Outdated, None);
            } else {
                sysflag_clear(&mut e.system_flags, SystemFlag::Outdated);
            }
        }
    }

    // Stop removed/disabled services (based on launcher PID query).
    let mut to_stop = vec![];
    for name in old_defs.keys() {
        match new_defs.get(name) {
            None => {
                if cgroup_running_async(&cfg, name).await.unwrap_or(false) {
                    to_stop.push(name.clone());
                }
            }
            Some(def) if !def.enabled => {
                if cgroup_running_async(&cfg, name).await.unwrap_or(false) {
                    to_stop.push(name.clone());
                }
            }
            _ => {}
        }
    }
    for name in to_stop {
        pm_event_state(state, "reconcile", Some(&name), "decision=stop reason=removed_or_disabled");
        // If the app was removed, there is no controller (and no stop_command) anymore.
        // Best-effort: kill the cgroup.
        let removed = !new_defs.contains_key(&name);
        if removed {
            let cfg2 = cfg.clone();
            let name2 = name.clone();
            let st2 = Arc::clone(state);
            let r = tasks().spawn_blocking(move || {
                match launcher_kill_all(&cfg2, &name2) {
                    Ok(()) => {
                        let _ = wait_until_empty(&cfg2, &name2, Duration::from_millis(5000));
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            })
            .await
            .map_err(|e| anyhow::anyhow!("join error: {e}"))?;
            match r {
                Ok(()) => pm_event_state(&st2, "reconcile", Some(&name), "outcome=killed (removed)"),
                Err(e) => pm_event_state(&st2, "reconcile", Some(&name), format!("outcome=error err={e}")),
            }
        } else {
            match shutdown_stop_via_supervisor_async(state, &name).await {
                Ok(()) => pm_event_state(state, "reconcile", Some(&name), "outcome=accepted desired=STOPPED"),
                Err(e) => pm_event_state(state, "reconcile", Some(&name), format!("outcome=error err={e}")),
            }
        }
    }

    {
        let mut st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        st.cfg = cfg.clone();
        st.defs = new_defs;
    }

    // Update/create/shutdown supervisors based on updated definitions.
    refresh_supervisors(state)?;

    // Services whose definition file was modified (mtime-based) should be treated like an operator action:
    // clear FAILED/BACKOFF suppression and ensure they are (re)started.
    //
    // - If running: stop-now (one-off) so the supervisor immediately restarts under the new def.
    // - If not running (even if FAILED/BACKOFF): manual SetDesired(RUNNING) clears flags and allows start.
    //
    // NOTE: we do not do this for scheduled jobs.
    let mut restarted: Vec<String> = vec![];
    for name in &modified_apps {
        let def = {
            let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
            st.defs.get(name).cloned()
        };
        let Some(def) = def else { continue };
        if !def.enabled {
            continue;
        }
        if def.schedule.is_some() {
            continue;
        }
        // Respect operator intent to keep the service stopped ("user_stop" flag).
        let stopped_by_user = {
            let ri = {
                let st = state.lock().unwrap_or_else(|p| p.into_inner());
                Arc::clone(&st.run_info)
            };
            let g = ri.lock().unwrap_or_else(|p| p.into_inner());
            g.get(name)
                .map(|i| sysflag_has(&i.system_flags, SYSFLAG_USER_STOP))
                .unwrap_or(false)
        };
        if stopped_by_user {
            pm_event_state(state, "reconcile", Some(name), "skip reason=stopped_by_user");
            continue;
        }

        pm_event_state(state, "reconcile", Some(name), "decision=apply_modified_def intent=manual_start");
        if let Err(e) = manual_start_via_supervisor_async(state, name, false).await {
            // Keep this log line single-line, but preserve the full anyhow chain.
            let chain = format!("{e:#}").replace('\n', "\\n");
            pm_event_state(
                state,
                "reconcile",
                Some(name),
                format!("outcome=error action=set_desired err={chain}"),
            );
            continue;
        }

        // If it's running, force a restart by stopping it now; desired remains RUNNING so it will come back.
        if cgroup_running_async(&cfg, name).await.unwrap_or(false) {
            pm_event_state(state, "reconcile", Some(name), "decision=restart reason=definition_modified");
            match manual_restart_via_supervisor_async(state, name, false).await {
                Ok(()) => {
                    restarted.push(name.clone());
                    pm_event_state(state, "reconcile", Some(name), "outcome=accepted restart=true");
                }
                Err(e) => {
                    pm_event_state(state, "reconcile", Some(name), format!("outcome=error action=restart err={e}"));
                }
            }
        } else {
            // Not running: SetDesired(manual=true) already cleared FAILED/BACKOFF and queued a reconcile tick.
            restarted.push(name.clone());
            pm_event_state(state, "reconcile", Some(name), "outcome=accepted start=true");
        }
    }

    // Also start any enabled services that are not running (full reconcile).
    // This matches supervisor-style "ensure enabled programs are up".
    if let Err(e) = start_enabled_services_async(state).await {
        pm_event_state(state, "reconcile", None, format!("start_enabled_services_error err={e}"));
    }

    // Emit a reconcile snapshot after update so operators can see observed state.
    emit_reconcile_snapshot(state, "update");

    if !warnings.is_empty() {
        pm_event_state(
            state,
            "reconcile",
            None,
            format!("update_warnings count={}", warnings.len()),
        );
        for w in &warnings {
            pm_event_state(state, "reconcile", None, format!("update_warning {w}"));
        }
    }

    Ok(Response {
        ok: true,
        message: if warnings.is_empty() {
            "updated".to_string()
        } else {
            format!("updated (warnings: {})", warnings.len())
        },
        restarted,
        statuses: vec![],
        events: vec![],
        admin_actions: vec![],
    })
}

fn emit_reconcile_snapshot(state: &Arc<Mutex<DaemonState>>, pass: &str) {
    let (cfg, defs) = {
        let st = match state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        (st.cfg.clone(), st.defs.clone())
    };

    let mut names: Vec<String> = defs.keys().cloned().collect();
    names.sort();

    for name in names {
        let def = match defs.get(&name) {
            Some(d) => d,
            None => continue,
        };
        let has_restart = def.restart.is_some();
        let has_schedule = def.schedule.is_some();
        match launcher_pids(&cfg, &name) {
            Ok(pids) => {
                let running = !pids.is_empty();
                pm_event_state(
                    state,
                    "reconcile",
                    Some(&name),
                    format!(
                        "pass={pass} observed running={running} pids={} enabled={} restart={} schedule={}",
                        pids.len(),
                        def.enabled,
                        has_restart,
                        has_schedule
                    ),
                );
                if has_restart && running {
                    pm_event_state(state, "reconcile", Some(&name), format!("pass={pass} decision=watch action=attach_waiter"));
                }
            }
            Err(e) => {
                pm_event_state(
                    state,
                    "reconcile",
                    Some(&name),
                    format!(
                        "pass={pass} observed status=error enabled={} restart={} schedule={} err={e}",
                        def.enabled, has_restart, has_schedule
                    ),
                );
            }
        }
    }
}

async fn start_enabled_services_async(state: &Arc<Mutex<DaemonState>>) -> anyhow::Result<()> {
    // Collect candidates without holding the lock during starts.
    // NOTE: scheduled jobs are not services; do not autostart them.
    let (cfg, names) = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        let mut names = vec![];
        for (name, def) in &st.defs {
            if def.enabled && def.schedule.is_none() {
                names.push(name.clone());
            }
        }
        names.sort();
        (st.cfg.clone(), names)
    };
    if names.is_empty() {
        return Ok(());
    }

    let mut js: JoinSet<()> = JoinSet::new();
    for name in names {
        let st = Arc::clone(state);
        let cfg2 = cfg.clone();
        js.spawn(async move {
            // Respect operator intent to keep the service stopped ("user_stop" flag).
            let run_info = {
                let g = st.lock().unwrap_or_else(|p| p.into_inner());
                Arc::clone(&g.run_info)
            };
            let stopped_by_user = {
                let ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                ri.get(&name)
                    .map(|i| sysflag_has(&i.system_flags, SYSFLAG_USER_STOP))
                    .unwrap_or(false)
            };
            if stopped_by_user {
                pm_event_state(&st, "autostart", Some(&name), "skip stopped_by_user");
                return;
            }
            // If already running, skip.
            match cgroup_running_async(&cfg2, &name).await {
                Ok(true) => {
                    pm_event_state(&st, "autostart", Some(&name), "skip already_running");
                    return;
                }
                Ok(false) => {}
                Err(e) => {
                    pm_event_state(&st, "autostart", Some(&name), format!("status_check_failed err={e}"));
                    return;
                }
            }
            pm_event_state(&st, "autostart", Some(&name), "attempt=set_desired enabled");
            match boot_start_via_supervisor_async(&st, &name).await {
                Ok(()) => pm_event_state(&st, "autostart", Some(&name), "outcome=accepted desired=RUNNING"),
                Err(e) => pm_event_state(&st, "autostart", Some(&name), format!("outcome=error err={e}")),
            }
        });
    }
    while js.join_next().await.is_some() {}
    Ok(())
}

// record_start_attempt removed: desired state changes are handled via controller commands.

fn record_started_in_store(
    run_info: &Arc<Mutex<HashMap<String, RunInfo>>>,
    name: &str,
    kind: StartKind,
    reason_flag: SystemFlag,
) {
    let now = Local::now().timestamp_millis();
    let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
    let e = ri.entry(name.to_string()).or_default();
    e.last_started_ms = Some(now);
    e.last_start_kind = Some(kind.as_str().to_string());
    // On successful start, apply the "reason the running app is started" marker. Its rule side-effects
    // are the single source of truth for clearing stale flags (failed/backoff/user_stop/ot_killed/...).
    sysflag_set_with_rules(name, &mut e.system_flags, reason_flag, None);
    // NOTE: user_flags are persisted operator labels and must survive starts/restarts.
}

fn record_start_attempt_in_store(run_info: &Arc<Mutex<HashMap<String, RunInfo>>>, name: &str) {
    let now = Local::now().timestamp_millis();
    let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
    let e = ri.entry(name.to_string()).or_default();
    e.last_start_attempt_ms = Some(now);
}

fn record_system_crash_in_store(run_info: &Arc<Mutex<HashMap<String, RunInfo>>>, name: &str) {
    let now = Local::now().timestamp_millis();
    let cutoff = now - RESTARTS_WINDOW_MS;
    let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
    let e = ri.entry(name.to_string()).or_default();
    e.recent_system_crashes_ms.push_back(now);
    while let Some(front) = e.recent_system_crashes_ms.front().copied() {
        if front < cutoff {
            e.recent_system_crashes_ms.pop_front();
        } else {
            break;
        }
    }
    // Hard cap (should be redundant with tolerance cap, but keeps memory bounded even if logic changes).
    while e.recent_system_crashes_ms.len() > 500 {
        e.recent_system_crashes_ms.pop_front();
    }
}

// record_started removed: controller uses `record_started_in_store` directly after spawning.

fn set_phase_and_emit(
    run_info: &Arc<Mutex<HashMap<String, RunInfo>>>,
    events: &Arc<Mutex<VecDeque<EventEntry>>>,
    app: &str,
    new_phase: Phase,
    reason: &str,
) {
    let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
    let e = ri.entry(app.to_string()).or_default();
    let old = e
        .last_emitted_phase
        .map(|p| p.to_string())
        .unwrap_or_else(|| "UNKNOWN".to_string());
    if e.last_emitted_phase == Some(new_phase) {
        return;
    }
    e.last_emitted_phase = Some(new_phase);
    drop(ri);
    push_event(
        events,
        "state",
        Some(app),
        format!("transition {} -> {} reason={}", old, new_phase, reason),
    );
}

// Probation is derived at status time from PID uptime; no background timers needed.

async fn do_start_async(state: &Arc<Mutex<DaemonState>>, name: &str, force: bool) -> anyhow::Result<Response> {
    let targets = resolve_targets(state, name, !force)?;

    async fn start_one(st: &Arc<Mutex<DaemonState>>, t: &str, force2: bool) -> anyhow::Result<String> {
        let def = {
            let g = st.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
            g.defs.get(t).cloned().ok_or_else(|| anyhow::anyhow!("unknown service: {t}"))?
        };
        // Cron jobs: "start" means run once, not set desired=RUNNING forever.
        if def.schedule.is_some() {
            pm_event_state(st, "cmd", Some(t), format!("attempt=run_once force={force2}"));
            manual_start_via_supervisor_async(st, t, force2).await?;
            pm_event_state(st, "cmd", Some(t), "outcome=accepted run_once=true");
            Ok(format!("{t}: accepted (run once)"))
        } else {
            pm_event_state(st, "cmd", Some(t), format!("attempt=set_desired desired=RUNNING force={force2}"));
            manual_start_via_supervisor_async(st, t, force2).await?;
            pm_event_state(st, "cmd", Some(t), "outcome=accepted desired=RUNNING");
            Ok(format!("{t}: accepted (desired=RUNNING)"))
        }
    }

    // Bounded parallelism.
    let mut js: JoinSet<(String, anyhow::Result<String>)> = JoinSet::new();
    let mut pending = targets.into_iter();
    let limit = 16usize;

    for _ in 0..limit {
        if let Some(t) = pending.next() {
            let st = Arc::clone(state);
            js.spawn(async move {
                let r = start_one(&st, &t, force).await;
                (t, r)
            });
        }
    }

    let mut out: Vec<(String, anyhow::Result<String>)> = vec![];
    while let Some(res) = js.join_next().await {
        if let Ok((t, r)) = res {
            out.push((t.clone(), r));
            if let Some(next) = pending.next() {
                let st = Arc::clone(state);
                js.spawn(async move {
                    let r = start_one(&st, &next, force).await;
                    (next, r)
                });
            }
        }
    }

    out.sort_by(|a, b| a.0.cmp(&b.0));
    let mut lines: Vec<String> = vec![];
    for (_t, r) in out {
        match r {
            Ok(line) => lines.push(line),
            Err(e) => lines.push(format!("error: {e}")),
        }
    }

    Ok(Response { ok: true, message: lines.join("\n"), restarted: vec![], statuses: vec![], events: vec![], admin_actions: vec![] })
}

async fn do_stop_async(state: &Arc<Mutex<DaemonState>>, name: &str) -> anyhow::Result<Response> {
    let targets = resolve_targets(state, name, false)?;

    async fn stop_one_cmd(st: &Arc<Mutex<DaemonState>>, t: &str) -> anyhow::Result<String> {
        let def = {
            let g = st.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
            g.defs.get(t).cloned().ok_or_else(|| anyhow::anyhow!("unknown service: {t}"))?
        };
        if def.schedule.is_some() {
            pm_event_state(st, "cmd", Some(t), "attempt=stop_now (scheduled)");
            manual_stop_via_supervisor_async(st, t).await?;
            pm_event_state(st, "cmd", Some(t), "outcome=accepted stop_now=true");
            Ok(format!("{t}: accepted (stop now)"))
        } else {
            pm_event_state(st, "cmd", Some(t), "attempt=set_desired desired=STOPPED");
            manual_stop_via_supervisor_async(st, t).await?;
            pm_event_state(st, "cmd", Some(t), "outcome=accepted desired=STOPPED");
            Ok(format!("{t}: accepted (desired=STOPPED)"))
        }
    }

    let mut js: JoinSet<(String, anyhow::Result<String>)> = JoinSet::new();
    let mut pending = targets.into_iter();
    let limit = 16usize;

    for _ in 0..limit {
        if let Some(t) = pending.next() {
            let st = Arc::clone(state);
            js.spawn(async move {
                let r = stop_one_cmd(&st, &t).await;
                (t, r)
            });
        }
    }

    let mut out: Vec<(String, anyhow::Result<String>)> = vec![];
    while let Some(res) = js.join_next().await {
        if let Ok((t, r)) = res {
            out.push((t.clone(), r));
            if let Some(next) = pending.next() {
                let st = Arc::clone(state);
                js.spawn(async move {
                    let r = stop_one_cmd(&st, &next).await;
                    (next, r)
                });
            }
        }
    }

    out.sort_by(|a, b| a.0.cmp(&b.0));
    let mut lines: Vec<String> = vec![];
    for (_t, r) in out {
        match r {
            Ok(line) => lines.push(line),
            Err(e) => lines.push(format!("error: {e}")),
        }
    }

    Ok(Response { ok: true, message: lines.join("\n"), restarted: vec![], statuses: vec![], events: vec![], admin_actions: vec![] })
}

async fn do_restart_async(state: &Arc<Mutex<DaemonState>>, name: &str, force: bool) -> anyhow::Result<Response> {
    let targets = resolve_targets(state, name, !force)?;

    async fn restart_one_cmd(st: &Arc<Mutex<DaemonState>>, t: &str, force2: bool) -> anyhow::Result<String> {
        pm_event_state(st, "cmd", Some(t), format!("attempt=restart force={force2}"));
        // NOTE: this will be routed to the per-app supervisor command queue after the supervisor refactor.
        // For now, implement it as stop + start for services, and stop-now + run-once for scheduled jobs.
        let def = {
            let g = st.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
            g.defs.get(t).cloned().ok_or_else(|| anyhow::anyhow!("unknown service: {t}"))?
        };
        if def.schedule.is_some() {
            manual_stop_via_supervisor_async(st, t).await?;
            manual_start_via_supervisor_async(st, t, force2).await?;
            pm_event_state(st, "cmd", Some(t), "outcome=accepted restart=true (scheduled)");
            Ok(format!("{t}: accepted (restart run once)"))
        } else {
            manual_restart_via_supervisor_async(st, t, force2).await?;
            pm_event_state(st, "cmd", Some(t), "outcome=accepted restart=true");
            Ok(format!("{t}: accepted (restart)"))
        }
    }

    // Bounded parallelism.
    let mut js: JoinSet<(String, anyhow::Result<String>)> = JoinSet::new();
    let mut pending = targets.into_iter();
    let limit = 16usize;

    for _ in 0..limit {
        if let Some(t) = pending.next() {
            let st = Arc::clone(state);
            js.spawn(async move {
                let r = restart_one_cmd(&st, &t, force).await;
                (t, r)
            });
        }
    }

    let mut out: Vec<(String, anyhow::Result<String>)> = vec![];
    while let Some(res) = js.join_next().await {
        if let Ok((t, r)) = res {
            out.push((t.clone(), r));
            if let Some(next) = pending.next() {
                let st = Arc::clone(state);
                js.spawn(async move {
                    let r = restart_one_cmd(&st, &next, force).await;
                    (next, r)
                });
            }
        }
    }

    out.sort_by(|a, b| a.0.cmp(&b.0));
    let mut lines: Vec<String> = vec![];
    for (_t, r) in out {
        match r {
            Ok(line) => lines.push(line),
            Err(e) => lines.push(format!("error: {e}")),
        }
    }

    Ok(Response { ok: true, message: lines.join("\n"), restarted: vec![], statuses: vec![], events: vec![], admin_actions: vec![] })
}

async fn do_start_all_async(state: &Arc<Mutex<DaemonState>>, force: bool) -> anyhow::Result<Response> {
    // Server-side bulk op for the web UI: start all enabled non-scheduled services.
    let names: Vec<String> = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        let mut v: Vec<String> = st
            .defs
            .iter()
            .filter(|(_n, d)| d.enabled && d.schedule.is_none())
            .map(|(n, _)| n.clone())
            .collect();
        v.sort();
        v
    };
    if names.is_empty() {
        return Ok(Response { ok: true, message: "no enabled services to start".to_string(), restarted: vec![], statuses: vec![], events: vec![], admin_actions: vec![] });
    }

    let mut js: JoinSet<(String, bool, String)> = JoinSet::new();
    let mut pending = names.into_iter();
    let limit = 16usize;

    for _ in 0..limit {
        if let Some(name) = pending.next() {
            let st2 = Arc::clone(state);
            js.spawn(async move {
                let r = do_start_async(&st2, &name, force).await;
                match r {
                    Ok(resp) => (name, resp.ok, resp.message),
                    Err(e) => (name, false, e.to_string()),
                }
            });
        }
    }

    let mut ok = 0usize;
    let mut fail = 0usize;
    let mut failures: Vec<String> = vec![];
    while let Some(res) = js.join_next().await {
        if let Ok((name, is_ok, msg)) = res {
            if is_ok { ok += 1; } else { fail += 1; failures.push(format!("{name}: {msg}")); }
            if let Some(next) = pending.next() {
                let st2 = Arc::clone(state);
                js.spawn(async move {
                    let r = do_start_async(&st2, &next, force).await;
                    match r {
                        Ok(resp) => (next, resp.ok, resp.message),
                        Err(e) => (next, false, e.to_string()),
                    }
                });
            }
        }
    }

    failures.sort();
    let mut message = format!("start_all done: {ok} ok, {fail} failed.");
    if !failures.is_empty() {
        let cap = 20usize;
        let shown = failures.iter().take(cap).cloned().collect::<Vec<_>>().join("\n");
        let more = if failures.len() > cap { format!("\n…(+{})", failures.len() - cap) } else { "".to_string() };
        message.push_str("\n");
        message.push_str(&shown);
        message.push_str(&more);
    }
    Ok(Response { ok: fail == 0, message, restarted: vec![], statuses: vec![], events: vec![], admin_actions: vec![] })
}

async fn do_stop_all_async(state: &Arc<Mutex<DaemonState>>) -> anyhow::Result<Response> {
    // Server-side bulk op for the web UI: stop all *running* apps.
    // Because this is an operator action ("Stop all"), we DO apply operator-intent flags where applicable:
    // - services (non-scheduled) should get SYSFLAG_USER_STOP (and clear SYSFLAG_USER_START)
    // - scheduled jobs do not use user_stop/user_start markers
    //
    // IMPORTANT: we set the intent marker BEFORE issuing the stop so the subsequent exit event
    // is reliably treated as "stopped by user" and will not auto-restart.
    let (cfg, names): (MasterConfig, Vec<String>) = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        let mut v: Vec<String> = st.defs.keys().cloned().collect();
        v.sort();
        (st.cfg.clone(), v)
    };
    if names.is_empty() {
        return Ok(Response { ok: true, message: "no services".to_string(), restarted: vec![], statuses: vec![], events: vec![], admin_actions: vec![] });
    }

    // First: only target apps that are actually running right now.
    // This avoids "stop_all" affecting disabled/stopped apps (and keeps the counts meaningful).
    let total = names.len();
    let mut running: Vec<String> = vec![];
    {
        let mut js: JoinSet<(String, bool)> = JoinSet::new();
        let mut pending = names.clone().into_iter();
        let limit = 32usize;
        for _ in 0..limit {
            if let Some(name) = pending.next() {
                let cfg2 = cfg.clone();
                js.spawn(async move {
                    let is_running = cgroup_running_async(&cfg2, &name).await.unwrap_or(false);
                    (name, is_running)
                });
            }
        }
        while let Some(res) = js.join_next().await {
            if let Ok((name, is_running)) = res {
                if is_running {
                    running.push(name);
                }
                if let Some(next) = pending.next() {
                    let cfg2 = cfg.clone();
                    js.spawn(async move {
                        let is_running = cgroup_running_async(&cfg2, &next).await.unwrap_or(false);
                        (next, is_running)
                    });
                }
            }
        }
    }
    running.sort();
    let skipped = total.saturating_sub(running.len());
    if running.is_empty() {
        return Ok(Response {
            ok: true,
            message: format!("stop_all: no running apps (skipped_not_running={skipped})"),
            restarted: vec![],
            statuses: vec![],
            events: vec![],
            admin_actions: vec![],
        });
    }

    // Apply operator intent markers for running apps up-front (including cron jobs).
    // Also clear FAILED/BACKOFF suppression so the UI state is clean after an operator intervention.
    {
        let (run_info, _defs) = {
            let st = state.lock().unwrap_or_else(|p| p.into_inner());
            (Arc::clone(&st.run_info), st.defs.clone())
        };
        let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
        for name in &running {
            let e = ri.entry(name.clone()).or_default();
            sysflag_set_with_rules(name, &mut e.system_flags, SYSFLAG_USER_STOP, None);
            e.recent_system_crashes_ms.clear();
        }
    }

    let mut js: JoinSet<(String, bool, String)> = JoinSet::new();
    let mut pending = running.into_iter();
    let limit = 16usize;

    for _ in 0..limit {
        if let Some(name) = pending.next() {
            let st2 = Arc::clone(state);
            js.spawn(async move {
                match shutdown_stop_via_supervisor_async(&st2, &name).await {
                    Ok(()) => (name, true, String::new()),
                    Err(e) => (name, false, e.to_string()),
                }
            });
        }
    }

    let mut ok = 0usize;
    let mut fail = 0usize;
    let mut failures: Vec<String> = vec![];
    while let Some(res) = js.join_next().await {
        if let Ok((name, is_ok, msg)) = res {
            if is_ok {
                ok += 1;
            } else {
                // Stop failed: revert the pre-set operator stop marker for services, so we don't leave a stale
                // "stopped by user" intent on a still-running service.
                {
                    let (run_info, _defs) = {
                        let st = state.lock().unwrap_or_else(|p| p.into_inner());
                        (Arc::clone(&st.run_info), st.defs.clone())
                    };
                    let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some(entry) = ri.get_mut(&name) {
                        sysflag_clear(&mut entry.system_flags, SYSFLAG_USER_STOP);
                    }
                }
                fail += 1;
                failures.push(format!("{name}: {msg}"));
            }
            if let Some(next) = pending.next() {
                let st2 = Arc::clone(state);
                js.spawn(async move {
                    match shutdown_stop_via_supervisor_async(&st2, &next).await {
                        Ok(()) => (next, true, String::new()),
                        Err(e) => (next, false, e.to_string()),
                    }
                });
            }
        }
    }

    failures.sort();
    let mut message = format!("stop_all done: {ok} ok, {fail} failed. skipped_not_running={skipped}");
    if !failures.is_empty() {
        let cap = 20usize;
        let shown = failures.iter().take(cap).cloned().collect::<Vec<_>>().join("\n");
        let more = if failures.len() > cap { format!("\n…(+{})", failures.len() - cap) } else { "".to_string() };
        message.push_str("\n");
        message.push_str(&shown);
        message.push_str(&more);
    }
    Ok(Response { ok: fail == 0, message, restarted: vec![], statuses: vec![], events: vec![], admin_actions: vec![] })
}

async fn do_restart_all_async(state: &Arc<Mutex<DaemonState>>, force: bool) -> anyhow::Result<Response> {
    // Server-side bulk op for the web UI: restart all enabled non-scheduled services.
    let names: Vec<String> = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        let mut v: Vec<String> = st
            .defs
            .iter()
            .filter(|(_n, d)| d.enabled && d.schedule.is_none())
            .map(|(n, _)| n.clone())
            .collect();
        v.sort();
        v
    };
    if names.is_empty() {
        return Ok(Response { ok: true, message: "no enabled services to restart".to_string(), restarted: vec![], statuses: vec![], events: vec![], admin_actions: vec![] });
    }

    let mut js: JoinSet<(String, bool, String)> = JoinSet::new();
    let mut pending = names.into_iter();
    let limit = 16usize;

    for _ in 0..limit {
        if let Some(name) = pending.next() {
            let st2 = Arc::clone(state);
            js.spawn(async move {
                let r = do_restart_async(&st2, &name, force).await;
                match r {
                    Ok(resp) => (name, resp.ok, resp.message),
                    Err(e) => (name, false, e.to_string()),
                }
            });
        }
    }

    let mut ok = 0usize;
    let mut fail = 0usize;
    let mut failures: Vec<String> = vec![];
    while let Some(res) = js.join_next().await {
        if let Ok((name, is_ok, msg)) = res {
            if is_ok { ok += 1; } else { fail += 1; failures.push(format!("{name}: {msg}")); }
            if let Some(next) = pending.next() {
                let st2 = Arc::clone(state);
                js.spawn(async move {
                    let r = do_restart_async(&st2, &next, force).await;
                    match r {
                        Ok(resp) => (next, resp.ok, resp.message),
                        Err(e) => (next, false, e.to_string()),
                    }
                });
            }
        }
    }

    failures.sort();
    let mut message = format!("restart_all done: {ok} ok, {fail} failed.");
    if !failures.is_empty() {
        let cap = 20usize;
        let shown = failures.iter().take(cap).cloned().collect::<Vec<_>>().join("\n");
        let more = if failures.len() > cap { format!("\n…(+{})", failures.len() - cap) } else { "".to_string() };
        message.push_str("\n");
        message.push_str(&shown);
        message.push_str(&more);
    }
    Ok(Response { ok: fail == 0, message, restarted: vec![], statuses: vec![], events: vec![], admin_actions: vec![] })
}

fn parse_flag_ttl_ms(spec: &str) -> anyhow::Result<u64> {
    let t = spec.trim();
    anyhow::ensure!(!t.is_empty(), "empty ttl");
    anyhow::ensure!(!t.chars().any(|c| c.is_whitespace()), "ttl must not contain whitespace");
    let s = t.to_ascii_lowercase();

    // Units must be specified from larger to smaller; no repeats.
    // Supported: d, h, m, s, ms
    // Rank: d(5) > h(4) > m(3) > s(2) > ms(1)
    fn rank(unit: &str) -> Option<u8> {
        match unit {
            "d" => Some(5),
            "h" => Some(4),
            "m" => Some(3),
            "s" => Some(2),
            "ms" => Some(1),
            _ => None,
        }
    }
    fn mult(unit: &str) -> u64 {
        match unit {
            "d" => 86_400_000,
            "h" => 3_600_000,
            "m" => 60_000,
            "s" => 1_000,
            "ms" => 1,
            _ => 1,
        }
    }

    let mut i = 0usize;
    let b = s.as_bytes();
    let mut prev_rank: u8 = 255;
    let mut seen_mask: u8 = 0;
    let mut total: u64 = 0;

    while i < b.len() {
        // number
        let start = i;
        while i < b.len() && (b[i] as char).is_ascii_digit() {
            i += 1;
        }
        anyhow::ensure!(i > start, "ttl: expected number at offset {}", start);
        let num: u64 = s[start..i].parse()?;

        // unit
        anyhow::ensure!(i < b.len(), "ttl: missing unit after {}", num);
        let unit = if s[i..].starts_with("ms") {
            i += 2;
            "ms"
        } else {
            let ch = b[i] as char;
            anyhow::ensure!(matches!(ch, 'd' | 'h' | 'm' | 's'), "ttl: invalid unit at offset {}", i);
            i += 1;
            match ch {
                'd' => "d",
                'h' => "h",
                'm' => "m",
                's' => "s",
                _ => unreachable!(),
            }
        };

        let r = rank(unit).unwrap();
        anyhow::ensure!(r < prev_rank, "ttl: units must go from larger to smaller (e.g. 3h1m); got ...{unit} after smaller/equal unit");
        let bit = 1u8 << (r - 1);
        anyhow::ensure!((seen_mask & bit) == 0, "ttl: unit {unit} repeated");
        seen_mask |= bit;
        prev_rank = r;

        let add = num.checked_mul(mult(unit)).ok_or_else(|| anyhow::anyhow!("ttl overflow"))?;
        total = total.checked_add(add).ok_or_else(|| anyhow::anyhow!("ttl overflow"))?;
    }
    Ok(total)
}

fn do_flag(state: &Arc<Mutex<DaemonState>>, name: &str, flags: &[String], ttl: Option<&str>) -> anyhow::Result<Response> {
    let (run_info, events) = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        if name != "all" && !st.defs.contains_key(name) {
            anyhow::bail!("unknown service: {name}");
        }
        (Arc::clone(&st.run_info), Arc::clone(&st.events))
    };
    // Mark appstate dirty (persist user flags).
    {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        st.appstate_dirty.store(true, Ordering::Relaxed);
    }

    let now_ms = Local::now().timestamp_millis();
    let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
    let e = ri.entry(name.to_string()).or_default();

    // Prune expired flags before returning (fail-safe even if maintenance thread hasn't run yet).
    let mut expired: Vec<String> = vec![];
    for (k, v) in e.user_flags.iter() {
        if let Some(deadline) = v {
            if now_ms >= *deadline {
                expired.push(k.clone());
            }
        }
    }
    for k in &expired {
        e.user_flags.remove(k);
    }
    let expires_at_ms: Option<i64> = match ttl {
        None => None,
        Some(spec) => {
            let dur = parse_flag_ttl_ms(spec)? as i64;
            Some(Local::now().timestamp_millis() + dur)
        }
    };
    // Enforce user flag limits (avoid unbounded memory from operator input).
    // - max length per flag: 50 chars
    // - max flags per app: 100 total (after applying this request)
    let mut to_set: Vec<String> = vec![];
    for f in flags {
        let t = f.trim().to_ascii_lowercase();
        if t.is_empty() {
            continue;
        }
        if t.len() > MAX_USER_FLAG_LEN {
            anyhow::bail!("service {name}: flag {t:?} exceeds max length {MAX_USER_FLAG_LEN}");
        }
        to_set.push(t);
    }
    to_set.sort();
    to_set.dedup();

    // Compute prospective size (distinct keys).
    let mut prospective = e.user_flags.len();
    for k in &to_set {
        if !e.user_flags.contains_key(k) {
            prospective += 1;
        }
    }
    if prospective > MAX_USER_FLAGS_PER_APP {
        anyhow::bail!(
            "service {name}: too many user flags (would become {prospective}, max {MAX_USER_FLAGS_PER_APP})"
        );
    }
    for t in to_set {
        e.user_flags.insert(t, expires_at_ms);
    }
    let now_flags: Vec<String> = e.user_flags.keys().cloned().collect();
    drop(ri);

    for f in expired {
        push_event(&events, "flag", Some(name), format!("expired flag={f}"));
    }
    push_event(
        &events,
        "flag",
        Some(name),
        format!("set flags={} ttl={}", flags.join(","), ttl.unwrap_or("never")),
    );
    Ok(Response {
        ok: true,
        message: format!("{name}: flags={}", now_flags.join(",")),
        restarted: vec![],
        statuses: vec![],
        events: vec![],
        admin_actions: vec![],
    })
}

fn do_unflag(state: &Arc<Mutex<DaemonState>>, name: &str, flags: &[String]) -> anyhow::Result<Response> {
    let (run_info, events) = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        if name != "all" && !st.defs.contains_key(name) {
            anyhow::bail!("unknown service: {name}");
        }
        (Arc::clone(&st.run_info), Arc::clone(&st.events))
    };
    {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        st.appstate_dirty.store(true, Ordering::Relaxed);
    }

    let now_ms = Local::now().timestamp_millis();
    let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
    let e = ri.entry(name.to_string()).or_default();

    // Prune expired flags before returning (fail-safe even if maintenance thread hasn't run yet).
    let mut expired: Vec<String> = vec![];
    for (k, v) in e.user_flags.iter() {
        if let Some(deadline) = v {
            if now_ms >= *deadline {
                expired.push(k.clone());
            }
        }
    }
    for k in &expired {
        e.user_flags.remove(k);
    }
    for f in flags {
        let t = f.trim().to_ascii_lowercase();
        if !t.is_empty() {
            e.user_flags.remove(&t);
        }
    }
    let now_flags: Vec<String> = e.user_flags.keys().cloned().collect();
    drop(ri);

    for f in expired {
        push_event(&events, "flag", Some(name), format!("expired flag={f}"));
    }
    push_event(&events, "flag", Some(name), format!("unset flags={}", flags.join(",")));
    Ok(Response {
        ok: true,
        message: format!("{name}: flags={}", now_flags.join(",")),
        restarted: vec![],
        statuses: vec![],
        events: vec![],
        admin_actions: vec![],
    })
}

// All task/service/cron state manipulation happens through the per-app supervisor MPSC.
// For externally-visible commands, the oneshot response is only sent after the action completes.

async fn manual_start_via_supervisor_async(state: &Arc<Mutex<DaemonState>>, name: &str, force: bool) -> anyhow::Result<()> {
    let tx = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        st.supervisors.get(name).map(|h| h.tx.clone())
    }
    .ok_or_else(|| anyhow::anyhow!("no controller for service: {name}"))?;
    let (resp_tx, resp_rx) = oneshot::channel();
    tx.send(SupervisorCmd::ManualStart { force, resp: resp_tx })
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    resp_rx.await.map_err(|e| anyhow::anyhow!("{e}"))?
}

async fn manual_stop_via_supervisor_async(state: &Arc<Mutex<DaemonState>>, name: &str) -> anyhow::Result<()> {
    let tx = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        st.supervisors.get(name).map(|h| h.tx.clone())
    }
    .ok_or_else(|| anyhow::anyhow!("no controller for service: {name}"))?;
    let (resp_tx, resp_rx) = oneshot::channel();
    tx.send(SupervisorCmd::ManualStop { resp: resp_tx })
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    resp_rx.await.map_err(|e| anyhow::anyhow!("{e}"))?
}

async fn manual_restart_via_supervisor_async(state: &Arc<Mutex<DaemonState>>, name: &str, force: bool) -> anyhow::Result<()> {
    let tx = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        st.supervisors.get(name).map(|h| h.tx.clone())
    }
    .ok_or_else(|| anyhow::anyhow!("no controller for service: {name}"))?;
    let (resp_tx, resp_rx) = oneshot::channel();
    tx.send(SupervisorCmd::ManualRestart { force, resp: resp_tx })
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    resp_rx.await.map_err(|e| anyhow::anyhow!("{e}"))?
}

async fn boot_start_via_supervisor_async(state: &Arc<Mutex<DaemonState>>, name: &str) -> anyhow::Result<()> {
    let tx = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        st.supervisors.get(name).map(|h| h.tx.clone())
    }
    .ok_or_else(|| anyhow::anyhow!("no controller for service: {name}"))?;
    let (resp_tx, resp_rx) = oneshot::channel();
    tx.send(SupervisorCmd::BootStart { resp: resp_tx })
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    resp_rx.await.map_err(|e| anyhow::anyhow!("{e}"))?
}

async fn scheduled_start_via_supervisor_async(state: &Arc<Mutex<DaemonState>>, name: &str) -> anyhow::Result<()> {
    let tx = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        st.supervisors.get(name).map(|h| h.tx.clone())
    }
    .ok_or_else(|| anyhow::anyhow!("no controller for service: {name}"))?;
    let (resp_tx, resp_rx) = oneshot::channel();
    tx.send(SupervisorCmd::ScheduledStart { resp: resp_tx })
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    resp_rx.await.map_err(|e| anyhow::anyhow!("{e}"))?
}

async fn shutdown_stop_via_supervisor_async(state: &Arc<Mutex<DaemonState>>, name: &str) -> anyhow::Result<()> {
    let tx = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        st.supervisors.get(name).map(|h| h.tx.clone())
    }
    .ok_or_else(|| anyhow::anyhow!("no controller for service: {name}"))?;
    let (resp_tx, resp_rx) = oneshot::channel();
    tx.send(SupervisorCmd::ShutdownStop { resp: resp_tx })
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    resp_rx.await.map_err(|e| anyhow::anyhow!("{e}"))?
}

async fn overtime_stop_via_supervisor_async(state: &Arc<Mutex<DaemonState>>, name: &str) -> anyhow::Result<()> {
    let tx = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        st.supervisors.get(name).map(|h| h.tx.clone())
    }
    .ok_or_else(|| anyhow::anyhow!("no controller for service: {name}"))?;
    let (resp_tx, resp_rx) = oneshot::channel();
    tx.send(SupervisorCmd::OverTimeStop { resp: resp_tx })
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    resp_rx.await.map_err(|e| anyhow::anyhow!("{e}"))?
}

fn refresh_supervisors(state: &Arc<Mutex<DaemonState>>) -> anyhow::Result<()> {
    let (cfg, defs, existing, shutting_down) = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        (
            st.cfg.clone(),
            st.defs.clone(),
            st.supervisors.keys().cloned().collect::<Vec<_>>(),
            Arc::clone(&st.shutting_down),
        )
    };

    // Cron jobs are "run on schedule if not running"; restart policy is invalid for them.
    for (name, def) in &defs {
        if def.schedule.is_some() && def.restart.is_some() {
            anyhow::bail!(
                "service {name}: restart policy is invalid for scheduled jobs (remove `restart:` or `schedule:`)"
            );
        }
    }

    // Remove controllers for deleted apps only.
    for name in existing {
        if !defs.contains_key(&name) {
            let tx = {
                let mut st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
                st.supervisors.remove(&name).map(|h| h.tx)
            };
            if let Some(tx) = tx {
                let _ = tx.send(SupervisorCmd::Shutdown);
            }
        }
    }

    // Add/update controllers for all apps.
    for (name, def) in defs {
        // Best-effort: ensure app cgroup directory exists so status/stop operations are fail-safe.
        // (Creation failures should not crash a running daemon; we'll surface them in events.)
        let cg_dir = app_cgroup_dir(&cfg, &name);
        if let Err(e) = fs::create_dir_all(&cg_dir) {
            // If we can't create the cgroup dir, we can still keep the daemon running;
            // starts/stops for this app will fail later and should be visible to operators.
            let (events, ) = {
                let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
                (Arc::clone(&st.events),)
            };
            push_event(&events, "cgroup", Some(&name), format!("ensure_dir_failed dir={} err={e}", cg_dir.display()));
        }

        // Validate restart policy is parseable (supported: never|always) if present.
        if let Some(restart) = def.restart.as_ref() {
            let _policy = restart.policy.parsed()?;
        }

        let tx_opt = {
            let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
            st.supervisors.get(&name).map(|h| h.tx.clone())
        };
        if let Some(tx) = tx_opt {
            let _ = tx.send(SupervisorCmd::Update { def: def.clone() });
            continue;
        }
        // Enable controllers for children of this app cgroup so nested cgroup trees work
        // (e.g. nested processmaster, or apps that create their own sub-cgroups).
        if cfg.cgroup_subtree_control_allow {
            if let Err(e) = enable_all_subtree_controllers(&cg_dir) {
                pm_event_state(
                    state,
                    "cgroup",
                    Some(name.as_str()),
                    format!(
                        "warn=enable_subtree_controllers_failed cgroup_dir={} err={e:#}",
                        cg_dir.display()
                    ),
                );
            }
        }

        let (run_info, events) = {
            let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
            (Arc::clone(&st.run_info), Arc::clone(&st.events))
        };
        pm_event("supervisor", Some(&name), "spawn");
        let handle = spawn_supervisor_thread(cfg.clone(), def.clone(), run_info, events, Arc::clone(&shutting_down));
        let mut st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        st.supervisors.insert(name.clone(), handle);
    }
    Ok(())
}

fn do_status(state: &Arc<Mutex<DaemonState>>, name: Option<&str>) -> anyhow::Result<Response> {
    let mut entries: Vec<StatusEntry> = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        let mut v = vec![];
        let run_info = Arc::clone(&st.run_info);
        let _events = Arc::clone(&st.events);
        let now_ms = Local::now().timestamp_millis();
        let sys_uptime_s = read_system_uptime_seconds();
        let hz = clock_ticks_per_second();

        let want_one = name
            .filter(|n| *n != "all")
            .map(|s| s.to_string());
        if let Some(ref one) = want_one {
            if !st.defs.contains_key(one) {
                anyhow::bail!("unknown service: {one}");
            }
        }

        for (app, def) in &st.defs {
            if let Some(ref one) = want_one {
                if app != one {
                    continue;
                }
            }
            let pids = launcher_pids(&st.cfg, app)?;
            let pid_uptimes_ms = compute_pid_uptimes_ms(&pids, sys_uptime_s, hz);
            let info = {
                let ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                ri.get(app).cloned().unwrap_or_default()
            };
            let last_run_at_ms = info.last_start_attempt_ms;
            let last_exit_code = info.last_exit_code;
            let restarts_10m: u32 = {
                let cutoff = now_ms - RESTARTS_WINDOW_MS;
                info.recent_system_crashes_ms
                    .iter()
                    .filter(|t| **t >= cutoff)
                    .count()
                    .min(u32::MAX as usize) as u32
            };
            let user_flags: Vec<String> = info.user_flags.keys().cloned().collect();
            let is_running_now = !pids.is_empty();
            let system_flags: Vec<String> = info
                .system_flags
                .keys()
                .copied()
                .filter(|k| match (is_running_now, k.scope()) {
                    (true, FlagScope::Running | FlagScope::Both) => true,
                    (false, FlagScope::Stopped | FlagScope::Both) => true,
                    _ => false,
                })
                .map(|k| k.to_string())
                .collect();
            let actual = if pids.is_empty() { "STOPPED" } else { "RUNNING" }.to_string();

            let phase = {
                let actual_running = !pids.is_empty();
                let oldest_uptime_ms: i64 = pid_uptimes_ms
                    .iter()
                    .copied()
                    .filter(|v| *v >= 0)
                    .max()
                    .unwrap_or(0);

                // Derive phase from actual/flags + probation window.
                if actual_running {
                    // STARTING/RESTARTING until the oldest PID is >= 10s.
                    if oldest_uptime_ms < 10_000 {
                        if info.last_start_kind.as_deref() == Some("restart") {
                            Phase::Restarting.to_string()
                        } else {
                            Phase::Starting.to_string()
                        }
                    } else {
                        Phase::Running.to_string()
                    }
                } else {
                    if !def.enabled || sysflag_has(&info.system_flags, SYSFLAG_USER_STOP) {
                        Phase::Stopped.to_string()
                    } else if sysflag_has(&info.system_flags, SystemFlag::Backoff) {
                        Phase::Backoff.to_string()
                    } else if sysflag_has(&info.system_flags, SystemFlag::Failed) {
                        Phase::Failed.to_string()
                    } else {
                        Phase::Stopped.to_string()
                    }
                }
            };
            v.push(StatusEntry {
                application: app.clone(),
                enabled: def.enabled,
                running: !pids.is_empty(),
                actual,
                phase,
                restarts_10m,
                system_flags,
                user_flags,
                pids,
                pid_uptimes_ms,
                working_directory: Some(def.working_directory.display().to_string()),
                provisioning_marker: if def.provisioning.is_empty() {
                    None
                } else {
                    Some(def.working_directory.join(".pm_provisioned").display().to_string())
                },
                provisioning_defined: !def.provisioning.is_empty(),
                provisioning_marker_exists: !def.provisioning.is_empty()
                    && def.working_directory.join(".pm_provisioned").exists(),
                source_file: def
                    .source_file
                    .as_ref()
                    .map(|p| p.display().to_string()),
                last_run_at_ms,
                last_exit_code,
                schedule: def.schedule.clone(),
                schedule_not_before_ms: def.schedule_not_before_ms,
                schedule_not_after_ms: def.schedule_not_after_ms,
                schedule_max_time_per_run_ms: def.schedule_max_time_per_run_ms,
            });
        }
        v
    };

    entries.sort_by(|a, b| a.application.cmp(&b.application));

    Ok(Response {
        ok: true,
        message: String::new(),
        restarted: vec![],
        statuses: entries,
        events: vec![],
        admin_actions: vec![],
    })
}

fn clock_ticks_per_second() -> Option<f64> {
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v <= 0 { None } else { Some(v as f64) }
}

fn read_system_uptime_seconds() -> Option<f64> {
    let s = fs::read_to_string("/proc/uptime").ok()?;
    let first = s.split_whitespace().next()?;
    first.parse::<f64>().ok()
}

fn compute_pid_uptimes_ms(pids: &[i32], sys_uptime_s: Option<f64>, hz: Option<f64>) -> Vec<i64> {
    let mut out = Vec::with_capacity(pids.len());
    for &pid in pids {
        let ms = pid_uptime_ms(pid, sys_uptime_s, hz);
        out.push(ms.unwrap_or(-1));
    }
    out
}

fn pid_uptime_ms(pid: i32, sys_uptime_s: Option<f64>, hz: Option<f64>) -> Option<i64> {
    let sys_uptime_s = sys_uptime_s?;
    let hz = hz?;
    let start_ticks = read_pid_starttime_ticks(pid)?;
    let started_s = (start_ticks as f64) / hz;
    let up_s = (sys_uptime_s - started_s).max(0.0);
    Some((up_s * 1000.0).round() as i64)
}

fn read_pid_starttime_ticks(pid: i32) -> Option<u64> {
    let path = format!("/proc/{pid}/stat");
    let stat = fs::read_to_string(path).ok()?;
    let rparen = stat.rfind(')')?;
    let after = stat.get(rparen + 2..)?; // skip ") "
    let fields: Vec<&str> = after.split_whitespace().collect();
    // fields[0] is original field 3 (state). starttime is original field 22 => index 22-3 = 19
    let start = *fields.get(19)?;
    start.parse::<u64>().ok()
}

fn resolve_targets(
    state: &Arc<Mutex<DaemonState>>,
    name: &str,
    require_enabled: bool,
) -> anyhow::Result<Vec<String>> {
    let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
    if name == "all" {
        let mut out = vec![];
        for (n, def) in &st.defs {
            if require_enabled && !def.enabled {
                continue;
            }
            out.push(n.clone());
        }
        out.sort();
        return Ok(out);
    }
    let def = st
        .defs
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("unknown service: {name}"))?;
    if require_enabled && !def.enabled {
        anyhow::bail!("service {name} is disabled");
    }
    Ok(vec![name.to_string()])
}

fn master_cgroup_dir(cfg: &MasterConfig) -> PathBuf {
    PathBuf::from(&cfg.cgroup_root).join(&cfg.cgroup_name)
}

fn app_cgroup_dir(cfg: &MasterConfig, app: &str) -> PathBuf {
    // Prefix app cgroups to avoid reserved/system cgroup names (e.g. "failure").
    // App names remain the user-facing identifiers; only the cgroup directory is prefixed.
    master_cgroup_dir(cfg).join(format!("pm-{app}"))
}

fn decode_hex(s: &str) -> anyhow::Result<Vec<u8>> {
    let t = s
        .trim()
        .strip_prefix("0x")
        .or_else(|| s.trim().strip_prefix("0X"))
        .unwrap_or(s.trim());
    let mut bytes = Vec::with_capacity(t.len() / 2);
    let mut buf = Vec::with_capacity(t.len());
    for ch in t.chars() {
        if ch.is_ascii_hexdigit() {
            buf.push(ch as u8);
        }
    }
    if buf.len() % 2 != 0 {
        anyhow::bail!("hex string has odd length");
    }
    for pair in buf.chunks(2) {
        let hi = (pair[0] as char).to_digit(16).unwrap();
        let lo = (pair[1] as char).to_digit(16).unwrap();
        bytes.push(((hi << 4) | lo) as u8);
    }
    Ok(bytes)
}

fn decode_env_value(value: &str) -> anyhow::Result<std::ffi::OsString> {
    let v = value.trim();
    if let Some(path) = v.strip_prefix("@file://") {
        if let Ok(m) = fs::metadata(path) {
            if m.is_file() && m.len() > MAX_ENV_FILE_BYTES {
                anyhow::bail!(
                    "env file {path:?} too large ({} bytes > {} bytes limit)",
                    m.len(),
                    MAX_ENV_FILE_BYTES
                );
            }
        }
        let bytes = fs::read(path).with_context(|| format!("read env file {path:?}"))?;
        return Ok(std::ffi::OsString::from_vec(bytes));
    }
    if let Some(b64) = v.strip_prefix("@base64://").or_else(|| v.strip_prefix("@b64://")) {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .with_context(|| "base64 decode")?;
        return Ok(std::ffi::OsString::from_vec(bytes));
    }
    if let Some(hex) = v.strip_prefix("@hex://") {
        let bytes = decode_hex(hex)?;
        return Ok(std::ffi::OsString::from_vec(bytes));
    }
    Ok(std::ffi::OsString::from(value))
}

fn spawn_launcher_child(cfg: &MasterConfig, def: &AppDefinition) -> anyhow::Result<std::process::Child> {
    enforce_app_user_group_rules(def)?;

    let argv = def.start_command.clone();
    if argv.is_empty() {
        anyhow::bail!("start_command for {} is empty", def.application);
    }

    // Enforce: working directory must exist (do not create it implicitly).
    if !def.working_directory.exists() || !def.working_directory.is_dir() {
        anyhow::bail!(
            "working_directory {} does not exist (refuse to start {})",
            def.working_directory.display(),
            def.application
        );
    }

    // processmaster is now self-contained: we launch directly and self-attach into the app cgroup.
    // Keep the start/stop launch path consistent by using the shared LaunchParams builder.
    let lp = build_launch_params_for_app(cfg, def, &argv, Some(def.application.clone()))?;

    let mut cmd = cgroup::build_command(&lp)
        .with_context(|| format!("build command app={} cgroup_dir={}", def.application, lp.cgroup_dir.display()))?;

    let (stdout_path, stderr_path) = resolve_log_paths(def);
    // Capture-only mode: stdout/stderr always go through processmaster log pumps.
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            // `Command::spawn` may fail due to exec errors OR due to `pre_exec` errors.
            // For `pre_exec`, the OS error code is the most actionable signal, so always include it.
            anyhow::bail!(
                "spawn app={} cwd={} cgroup_dir={} argv={} failed: kind={:?} os_error={:?} err={}",
                def.application,
                def.working_directory.display(),
                lp.cgroup_dir.display(),
                argv.join(" "),
                e.kind(),
                e.raw_os_error(),
                e
            );
        }
    };
    let out = child.stdout.take();
    let err = child.stderr.take();
    if let Some(s) = out {
        spawn_log_pump_stdout_async(def.clone(), stdout_path.clone(), s);
    }
    if let Some(s) = err {
        spawn_log_pump_stderr_async(def.clone(), stderr_path.clone(), s);
    }
    Ok(child)
}

fn maybe_provision_workdir(def: &AppDefinition) -> anyhow::Result<()> {
    if def.provisioning.is_empty() {
        return Ok(());
    }
    let marker = def.working_directory.join(".pm_provisioned");
    if marker.exists() {
        pm_event(
            "provision",
            Some(&def.application),
            format!("decision=skip reason=marker_exists marker={}", marker.display()),
        );
        return Ok(());
    }
    pm_event(
        "provision",
        Some(&def.application),
        format!(
            "decision=attempt marker_missing marker={} workdir={} entries={}",
            marker.display(),
            def.working_directory.display(),
            def.provisioning.len()
        ),
    );

    pm_event(
        "provision",
        Some(&def.application),
        format!("decision=run reason=marker_missing marker={}", marker.display()),
    );

    // If we need root-only actions, fail fast with a clear error.
    if !geteuid().is_root() {
        for p in &def.provisioning {
            let wants_chown = p
                .ownership
                .as_ref()
                .map(|o| o.owner.as_ref().is_some() || o.group.as_ref().is_some())
                .unwrap_or(false);
            if wants_chown || p.add_net_bind_capability {
                anyhow::bail!(
                    "service {} provisioning requires root for ownership/capabilities (pm is not root)",
                    def.application
                );
            }
        }
    }

    for (idx, p) in def.provisioning.iter().enumerate() {
        let target = resolve_under_workdir(&def.working_directory, &p.path);

        // If the target doesn't exist, create it only when it looks like a directory provisioning action.
        if !target.exists() {
            if p.add_net_bind_capability {
                anyhow::bail!(
                    "service {} provisioning[{}]: target {} does not exist (needed for setcap)",
                    def.application,
                    idx,
                    target.display()
                );
            }
            fs::create_dir_all(&target).map_err(|e| {
                anyhow::anyhow!(
                    "service {} provisioning[{}]: failed to create directory {}: {e}",
                    def.application,
                    idx,
                    target.display()
                )
            })?;
        }

        // Ownership (optional)
        if let Some(own) = p.ownership.as_ref() {
            let uid_opt: Option<Uid> = match own.owner.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(s) => {
                    if let Ok(n) = s.parse::<u32>() {
                        Some(Uid::from_raw(n))
                    } else {
                        let usr = get_user_by_name(s).ok_or_else(|| anyhow::anyhow!("unknown user: {s}"))?;
                        Some(Uid::from_raw(usr.uid()))
                    }
                }
            };
            let gid_opt: Option<Gid> = match own.group.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(s) => {
                    if let Ok(n) = s.parse::<u32>() {
                        Some(Gid::from_raw(n))
                    } else {
                        let grp = get_group_by_name(s).ok_or_else(|| anyhow::anyhow!("unknown group: {s}"))?;
                        Some(Gid::from_raw(grp.gid()))
                    }
                }
            };
            if uid_opt.is_some() || gid_opt.is_some() {
                if own.recursive {
                    chown_recursive(&target, uid_opt, gid_opt)
                        .with_context(|| format!("service {} provisioning[{}]: chown_recursive {}", def.application, idx, target.display()))?;
                } else {
                    chown(&target, uid_opt, gid_opt).map_err(|e| {
                        anyhow::anyhow!(
                            "service {} provisioning[{}]: chown failed for {}: {e}",
                            def.application,
                            idx,
                            target.display()
                        )
                    })?;
                }
            }
        }

        // Mode (optional; non-recursive)
        if let Some(mode) = p.mode {
            let perm = std::fs::Permissions::from_mode(mode);
            fs::set_permissions(&target, perm).map_err(|e| {
                anyhow::anyhow!(
                    "service {} provisioning[{}]: chmod {:o} failed for {}: {e}",
                    def.application,
                    idx,
                    mode,
                    target.display()
                )
            })?;
        }

        // Capabilities (optional)
        if p.add_net_bind_capability {
            let status = Command::new("setcap")
                .arg("cap_net_bind_service=+ep")
                .arg(&target)
                .status()
                .map_err(|e| anyhow::anyhow!("service {} provisioning[{}]: setcap exec failed: {e}", def.application, idx))?;
            if !status.success() {
                anyhow::bail!(
                    "service {} provisioning[{}]: setcap failed for {} (status={status})",
                    def.application,
                    idx,
                    target.display()
                );
            }
        }

        pm_event(
            "provision",
            Some(&def.application),
            format!("effect=applied idx={idx} target={}", target.display()),
        );
    }

    fs::write(
        &marker,
        format!("provisioned_at_ms={}\n", Local::now().timestamp_millis()),
    )
    .map_err(|e| anyhow::anyhow!("service {}: failed to write marker {}: {e}", def.application, marker.display()))?;

    pm_event(
        "provision",
        Some(&def.application),
        format!("decision=done marker={}", marker.display()),
    );
    Ok(())
}

fn chown_recursive(root: &Path, uid: Option<Uid>, gid: Option<Gid>) -> anyhow::Result<()> {
    // Apply to root itself
    chown(root, uid, gid).map_err(|e| anyhow::anyhow!("chown failed for {}: {e}", root.display()))?;
    let md = fs::symlink_metadata(root)?;
    if !md.is_dir() {
        return Ok(());
    }
    fn walk(path: &Path, uid: Option<Uid>, gid: Option<Gid>) -> anyhow::Result<()> {
        for ent in fs::read_dir(path)? {
            let ent = ent?;
            let p = ent.path();
            let md = fs::symlink_metadata(&p)?;
            if md.file_type().is_symlink() {
                // Do not follow symlinks (avoid loops / unexpected ownership changes).
                continue;
            }
            chown(&p, uid, gid).map_err(|e| anyhow::anyhow!("chown failed for {}: {e}", p.display()))?;
            if md.is_dir() {
                walk(&p, uid, gid)?;
            }
        }
        Ok(())
    }
    walk(root, uid, gid)
}

async fn open_append_log_async(path: &Path) -> anyhow::Result<tokio::fs::File> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create_dir_all {}", parent.display()))?;
    }
    let f = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .write(true)
        .open(path)
        .await
        .with_context(|| format!("open log {}", path.display()))?;
    Ok(f)
}

struct RotatedReopen {
    f: tokio::fs::File,
    rotated: Option<PathBuf>,
}

fn maybe_compress_rotated_best_effort(app: &str, enabled: bool, rotated: &Path) {
    if !enabled {
        return;
    }
    if rotated.extension().and_then(|s| s.to_str()) == Some("gz") {
        return;
    }
    let app = app.to_string();
    let rotated = rotated.to_path_buf();
    tasks().spawn_blocking(move || {
        if !rotated.exists() {
            return;
        }
        let res = Command::new("gzip").arg("-f").arg(&rotated).status();
        match res {
            Ok(st) => {
                if !st.success() {
                    pm_event(
                        "logrotate",
                        Some(&app),
                        format!("gzip_failed file={} status={st}", rotated.display()),
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !GZIP_MISSING_WARNED.swap(true, Ordering::Relaxed) {
                    pm_event(
                        "logrotate",
                        None,
                        "gzip not found; rotated logs will not be compressed (install gzip to enable)",
                    );
                }
            }
            Err(e) => {
                pm_event(
                    "logrotate",
                    Some(&app),
                    format!("gzip_error file={} err={e}", rotated.display()),
                );
            }
        }
    });
}

async fn rotate_rename_reopen_async(base_path: &Path) -> anyhow::Result<RotatedReopen> {
    let now = Local::now();
    let ts = now.format("%Y-%m-%d_%H:%M:%S%.3f").to_string();
    let rotated = PathBuf::from(format!("{}.{}", base_path.display(), ts));
    // Best-effort: rename base -> rotated if it exists.
    let rotated_path = if tokio::fs::metadata(base_path).await.is_ok() {
        let _ = tokio::fs::rename(base_path, &rotated).await;
        Some(rotated)
    } else {
        None
    };
    let f = open_append_log_async(base_path).await?;
    Ok(RotatedReopen { f, rotated: rotated_path })
}

async fn rotate_numbered_reopen_async(base_path: &Path, backups: usize) -> anyhow::Result<RotatedReopen> {
    // Size-based rotation:
    // base -> base.1 -> base.2 ...
    if backups == 0 {
        // keep no backups; just recreate base
        if tokio::fs::metadata(base_path).await.is_ok() {
            let _ = tokio::fs::remove_file(base_path).await;
        }
        let f = open_append_log_async(base_path).await?;
        return Ok(RotatedReopen { f, rotated: None });
    }

    // Delete oldest first.
    let oldest = PathBuf::from(format!("{}.{}", base_path.display(), backups));
    if tokio::fs::metadata(&oldest).await.is_ok() {
        let _ = tokio::fs::remove_file(&oldest).await;
    }
    let oldest_gz = PathBuf::from(format!("{}.{}.gz", base_path.display(), backups));
    if tokio::fs::metadata(&oldest_gz).await.is_ok() {
        let _ = tokio::fs::remove_file(&oldest_gz).await;
    }

    // Shift: (backups-1 ..= 1)
    for i in (1..backups).rev() {
        let from = PathBuf::from(format!("{}.{}", base_path.display(), i));
        let to = PathBuf::from(format!("{}.{}", base_path.display(), i + 1));
        if tokio::fs::metadata(&from).await.is_ok() {
            let _ = tokio::fs::rename(&from, &to).await;
        }
        let from_gz = PathBuf::from(format!("{}.{}.gz", base_path.display(), i));
        let to_gz = PathBuf::from(format!("{}.{}.gz", base_path.display(), i + 1));
        if tokio::fs::metadata(&from_gz).await.is_ok() {
            let _ = tokio::fs::rename(&from_gz, &to_gz).await;
        }
    }

    // Move base -> base.1
    let to1 = PathBuf::from(format!("{}.1", base_path.display()));
    let rotated_path = if tokio::fs::metadata(base_path).await.is_ok() {
        let _ = tokio::fs::rename(base_path, &to1).await;
        Some(to1)
    } else {
        None
    };

    let f = open_append_log_async(base_path).await?;
    Ok(RotatedReopen { f, rotated: rotated_path })
}

fn log_rotation_key(rot: LogRotation, now: chrono::DateTime<Local>) -> String {
    match rot {
        LogRotation::Minutely => now.format("%Y-%m-%d_%H:%M").to_string(),
        LogRotation::Hourly => now.format("%Y-%m-%d_%H").to_string(),
        LogRotation::Daily => now.format("%Y-%m-%d").to_string(),
        LogRotation::Weekly => now.format("%G-W%V").to_string(),
        LogRotation::Monthly => now.format("%Y-%m").to_string(),
        LogRotation::None => "none".to_string(),
    }
}

fn spawn_log_pump_stdout_async(def: AppDefinition, base_path: PathBuf, pipe: ChildStdout) {
    tasks().spawn(async move {
        if let Err(e) = log_pump_async(def.clone(), base_path, pipe).await {
            pm_event("logpump", Some(&def.application), format!("stream=stdout outcome=error err={e}"));
        }
    });
}

fn spawn_log_pump_stderr_async(def: AppDefinition, base_path: PathBuf, pipe: ChildStderr) {
    tasks().spawn(async move {
        if let Err(e) = log_pump_async(def.clone(), base_path, pipe).await {
            pm_event("logpump", Some(&def.application), format!("stream=stderr outcome=error err={e}"));
        }
    });
}

fn set_nonblocking_fd(fd: i32) -> anyhow::Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    let flags = OFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFL)?);
    let new_flags = flags | OFlag::O_NONBLOCK;
    fcntl(fd, FcntlArg::F_SETFL(new_flags))?;
    Ok(())
}

async fn read_from_asyncfd(fd: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> anyhow::Result<usize> {
    loop {
        let mut guard = fd.readable().await?;
        let r = guard.try_io(|inner| {
            // SAFETY: fd is a valid pipe fd; buf is valid.
            let n = unsafe {
                libc::read(
                    inner.get_ref().as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n < 0 {
                let errno = nix::errno::Errno::last();
                if errno == nix::errno::Errno::EAGAIN || errno == nix::errno::Errno::EWOULDBLOCK {
                    return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                }
                return Err(std::io::Error::from_raw_os_error(errno as i32));
            }
            Ok(n as usize)
        });
        match r {
            Ok(Ok(n)) => return Ok(n),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Ok(Err(e)) => return Err(anyhow::anyhow!("read failed: {e}")),
            Err(_would_block) => continue,
        }
    }
}

async fn log_pump_async<P: IntoRawFd>(
    def: AppDefinition,
    base_path: PathBuf,
    pipe: P,
) -> anyhow::Result<()> {
    // Convert pipe into an owned fd and make it non-blocking for AsyncFd.
    let raw = pipe.into_raw_fd();
    set_nonblocking_fd(raw)?;
    // SAFETY: we just took ownership via into_raw_fd.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    let afd = AsyncFd::new(owned)?;

    let mut f = open_append_log_async(&base_path).await?;
    let mut buf = vec![0u8; 16 * 1024];
    let mut bytes_written: u64 = 0;
    let mut last_key = log_rotation_key(def.rotation_frequency, Local::now());

    loop {
        let n = read_from_asyncfd(&afd, &mut buf).await?;
        if n == 0 {
            break;
        }

        match def.rotation_mode {
            LogRotationMode::Time => {
                let now = Local::now();
                let key = log_rotation_key(def.rotation_frequency, now);
                if key != last_key && !matches!(def.rotation_frequency, LogRotation::None) {
                    last_key = key;
                    let _ = f.flush().await;
                    let rr = rotate_rename_reopen_async(&base_path).await?;
                    if let Some(rotated) = rr.rotated.as_deref() {
                        maybe_compress_rotated_best_effort(
                            &def.application,
                            def.log_compression_enabled,
                            rotated,
                        );
                    }
                    f = rr.f;
                    bytes_written = 0;
                }
            }
            LogRotationMode::Size => {
                if let Some(max) = def.rotation_size_bytes {
                    if bytes_written >= max && max > 0 {
                        let _ = f.flush().await;
                        let backups = def.rotation_backups.unwrap_or(10);
                        let rr = rotate_numbered_reopen_async(&base_path, backups).await?;
                        if let Some(rotated) = rr.rotated.as_deref() {
                            maybe_compress_rotated_best_effort(
                                &def.application,
                                def.log_compression_enabled,
                                rotated,
                            );
                        }
                        f = rr.f;
                        bytes_written = 0;
                    }
                }
            }
        }

        f.write_all(&buf[..n]).await?;
        bytes_written = bytes_written.saturating_add(n as u64);

        // For size-based rotation, also rotate *after* writing if we crossed the threshold.
        // This fixes the case where the process writes once (one chunk), exceeds the limit,
        // and then goes quiet/EOF—without this, we'd never rotate.
        if matches!(def.rotation_mode, LogRotationMode::Size) {
            if let Some(max) = def.rotation_size_bytes
                && max > 0
                && bytes_written >= max
            {
                let _ = f.flush().await;
                let backups = def.rotation_backups.unwrap_or(10);
                let rr = rotate_numbered_reopen_async(&base_path, backups).await?;
                if let Some(rotated) = rr.rotated.as_deref() {
                    maybe_compress_rotated_best_effort(
                        &def.application,
                        def.log_compression_enabled,
                        rotated,
                    );
                }
                f = rr.f;
                bytes_written = 0;
            }
        }
    }
    let _ = f.flush().await;
    Ok(())
}

// We intentionally do not keep per-child process handles; liveness is derived from cgroup PIDs.

// start_one removed: starts are driven by the per-app controller reconcile loop.

fn resolve_log_paths(def: &AppDefinition) -> (PathBuf, PathBuf) {
    let stdout = def
        .log_stdout
        .as_ref()
        .map(|p| resolve_under_workdir(&def.working_directory, p))
        .unwrap_or_else(|| def.working_directory.join("logs").join("stdout.log"));
    let stderr = def
        .log_stderr
        .as_ref()
        .map(|p| resolve_under_workdir(&def.working_directory, p))
        .unwrap_or_else(|| def.working_directory.join("logs").join("stderr.log"));
    (stdout, stderr)
}

fn resolve_stop_command_log(p: Option<&PathBuf>, workdir: &Path) -> Option<PathBuf> {
    let p = p?;
    Some(resolve_under_workdir(workdir, p))
}

fn resolve_under_workdir(workdir: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        workdir.join(p)
    }
}

fn validate_env_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        anyhow::bail!("environment.name must not be empty");
    }
    if name.contains('=') {
        anyhow::bail!("environment.name must not contain '=': {name}");
    }
    Ok(())
}


fn stop_common(
    events: Option<&Arc<Mutex<VecDeque<EventEntry>>>>,
    cfg: &MasterConfig,
    def: &AppDefinition,
    name: &str,
) -> anyhow::Result<StopResult> {
    let log = |msg: String| {
        if let Some(ev) = events {
            push_event(ev, "stop", Some(name), msg);
        } else {
            pm_event("stop", Some(name), msg);
        }
    };

    // Ensure user/group requirements are consistent when processmaster runs unprivileged.
    enforce_app_user_group_rules(def)?;

    if !cgroup_running(cfg, name)? {
        log("attempt=stop outcome=not_running".to_string());
        return Ok(StopResult::AlreadyStopped);
    }

    // Single fixed deadline: T + stop_grace_period_ms.
    let stop_deadline = Instant::now() + Duration::from_millis(def.stop_grace_period_ms);

    if let Some(argv) = def.stop_command.as_ref() {
        let t0 = Instant::now();
        log(format!("attempt=stop_command argv={:?}", argv));
        if argv.is_empty() {
            anyhow::bail!("stop_command for {name} is empty");
        }
        let status = match run_stop_command_in_context(cfg, def, name, argv, stop_deadline) {
            Ok(s) => Some(s),
            Err(e) => {
                // IMPORTANT: do not treat all errors as "timeout". Only a real timeout should go straight to kill-all.
                let es = e.to_string();
                if es.contains("stop_command_timeout") {
                    log(format!(
                        "outcome=stop_command_timeout stop_deadline_ms={} decision=kill-all",
                        def.stop_grace_period_ms
                    ));
                    // Force-kill everything left in the cgroup, including the stop command itself.
                    launcher_kill_all(cfg, name)?;
                    if !wait_until_empty(cfg, name, Duration::from_millis(3000)) && cgroup_running(cfg, name)? {
                        let pids = launcher_pids(cfg, name).unwrap_or_default();
                        log(format!("outcome=kill-all_failed remaining_pids={}", pids.len()));
                        anyhow::bail!("{name}: still running after kill-all");
                    }
                    log("outcome=stopped".to_string());
                    return Ok(StopResult::Stopped);
                }

                // Spawn/chdir/permission/etc failure: fall back to signal+grace instead of kill-all immediately.
                log(format!("outcome=stop_command_error elapsed_ms={} fallback=signal err={e}", t0.elapsed().as_millis()));
                let sig_s = def.stop_signal.as_deref().unwrap_or("SIGTERM");
                let sig = parse_signal(sig_s)?;
                log(format!("attempt=signal sig={} sig_num={}", sig_s, sig as i32));
                launcher_kill_signal(cfg, name, sig_s)?;
                log("outcome=signal_sent".to_string());
                None
            }
        };
        let elapsed_ms = t0.elapsed().as_millis();
        if let Some(status) = status {
            if !status.success() {
                let code = status.code().map(|c| c.to_string()).unwrap_or_else(|| "-".to_string());
                log(format!(
                    "outcome=stop_command_failed exit_code={} elapsed_ms={} fallback=signal",
                    code, elapsed_ms
                ));
                let sig_s = def.stop_signal.as_deref().unwrap_or("SIGTERM");
                let sig = parse_signal(sig_s)?;
                log(format!("attempt=signal sig={} sig_num={}", sig_s, sig as i32));
                launcher_kill_signal(cfg, name, def.stop_signal.as_deref().unwrap_or("SIGTERM"))?;
                log("outcome=signal_sent".to_string());
            } else {
                let code = status.code().map(|c| c.to_string()).unwrap_or_else(|| "0".to_string());
                log(format!("outcome=stop_command_ok exit_code={} elapsed_ms={}", code, elapsed_ms));
            }
        } else {
            // stop_command_error path already logged fallback to signal
        }
    } else {
        let sig_s = def.stop_signal.as_deref().unwrap_or("SIGTERM");
        let sig = parse_signal(sig_s)?;
        log(format!("attempt=signal sig={} sig_num={}", sig_s, sig as i32));
        launcher_kill_signal(cfg, name, def.stop_signal.as_deref().unwrap_or("SIGTERM"))?;
        log("outcome=signal_sent".to_string());
    }

    // After stop attempt (stop_command or signal), wait for graceful exit.
    log(format!("attempt=grace_wait stop_grace_period_ms={}", def.stop_grace_period_ms));
    let grace_t0 = Instant::now();
    loop {
        if !cgroup_running(cfg, name)? {
            log(format!("outcome=grace_exit elapsed_ms={}", grace_t0.elapsed().as_millis()));
            return Ok(StopResult::Stopped);
        }
        if Instant::now() >= stop_deadline {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    // Still running after grace window => force kill-all.
    let pids = launcher_pids(cfg, name).unwrap_or_default();
    log(format!(
        "outcome=grace_expired elapsed_ms={} decision=kill-all remaining_pids={}",
        grace_t0.elapsed().as_millis(),
        pids.len()
    ));
    let kill_t0 = Instant::now();
    launcher_kill_all(cfg, name)?;
    log(format!("attempt=kill-all outcome=sent elapsed_ms={}", kill_t0.elapsed().as_millis()));

    // cgroup.kill is asynchronous; give it a short window to settle.
    if !wait_until_empty(cfg, name, Duration::from_millis(3000)) && cgroup_running(cfg, name)? {
        let pids = launcher_pids(cfg, name).unwrap_or_default();
        log(format!("outcome=kill-all_failed remaining_pids={}", pids.len()));
        anyhow::bail!("{name}: still running after kill-all");
    }

    log("outcome=stopped".to_string());
    Ok(StopResult::Stopped)
}

fn resources_for_app(def: &AppDefinition) -> anyhow::Result<cgroup::Resources> {
    let mut r = cgroup::Resources::default();

    if let Some(cpu) = def.max_cpu.as_deref() {
        // Keep semantics consistent with start path: "MAX" means no cpu limit.
        let t = cpu.trim();
        if !t.is_empty() && !t.eq_ignore_ascii_case("max") {
            let mc = parse_cpu_millicores(t)?;
            let period: u64 = 100_000;
            let quota = (period * mc) / 1000;
            r.cpu_max = Some(format!("{quota} {period}"));
        }
    }
    if let Some(mem) = def.max_memory.as_deref() {
        // Reuse existing parsing rules (MAX and size suffixes).
        let v = to_mem_max_string(&normalize_memory_string(mem)?)?;
        r.memory_max = Some(v.trim().to_string());
    }
    let v = to_mem_max_string(&normalize_swap_string(def.max_swap.as_deref())?)?;
    r.swap_max = Some(v.trim().to_string());
    Ok(r)
}

fn build_launch_params_for_app(
    cfg: &MasterConfig,
    def: &AppDefinition,
    argv: &[String],
    argv0_group: Option<String>,
) -> anyhow::Result<cgroup::LaunchParams> {
    anyhow::ensure!(!argv.is_empty(), "argv is empty");
    let cgroup_dir = app_cgroup_dir(cfg, &def.application);
    let mut lp = cgroup::LaunchParams::new(argv.to_vec(), def.working_directory.clone(), cgroup_dir);

    // Same user/group as the app, when possible.
    if geteuid().is_root() {
        lp.user = def.user.clone();
        lp.group = def.group.clone();
    }

    // Optional argv0 decoration.
    lp.argv0_decoration_group = argv0_group;

    // Environment: support user-specified indirections (@file/@base64/@hex).
    for ev in &def.environment {
        validate_env_name(&ev.name)?;
        let v = decode_env_value(&ev.value)
            .with_context(|| format!("decode environment value app={} name={}", def.application, ev.name))?;
        lp.environment.push((ev.name.clone().into(), v));
    }

    // Resources (best-effort).
    lp.resources = resources_for_app(def)?;

    Ok(lp)
}

fn run_stop_command_in_context(
    cfg: &MasterConfig,
    def: &AppDefinition,
    name: &str,
    argv: &[String],
    stop_deadline: Instant,
) -> anyhow::Result<std::process::ExitStatus> {
    // Run stop_command in the *same* app cgroup: on timeout/escalation we want `cgroup.kill`
    // to kill everything, including a stuck stop helper.
    let lp = build_launch_params_for_app(cfg, def, argv, Some(format!("{name}.stop")))?;

    let mut cmd = cgroup::build_command(&lp)?;
    // Stop command output:
    // - If configured, capture via pipes and pump to stop_command log files (with rotation)
    // - Otherwise, discard to avoid interleaving with daemon logs
    cmd.stdin(Stdio::null());

    let stdout_path = resolve_stop_command_log(def.stop_command_stdout.as_ref(), &def.working_directory);
    let stderr_path = resolve_stop_command_log(def.stop_command_stderr.as_ref(), &def.working_directory);
    if stdout_path.is_some() {
        cmd.stdout(Stdio::piped());
    } else {
        cmd.stdout(Stdio::null());
    }
    if stderr_path.is_some() {
        cmd.stderr(Stdio::piped());
    } else {
        cmd.stderr(Stdio::null());
    }

    let mut child = cmd.spawn().with_context(|| format!("spawn stop_command app={}", def.application))?;
    if let (Some(p), Some(s)) = (stdout_path, child.stdout.take()) {
        spawn_log_pump_stdout_async(def.clone(), p, s);
    }
    if let (Some(p), Some(s)) = (stderr_path, child.stderr.take()) {
        spawn_log_pump_stderr_async(def.clone(), p, s);
    }

    // Use the shared stop deadline (T + grace). If stop_command doesn't finish by then,
    // the caller will force-kill the cgroup (which will kill this helper too).
    loop {
        if let Some(st) = child.try_wait().with_context(|| "try_wait stop_command")? {
            return Ok(st);
        }
        if Instant::now() >= stop_deadline {
            anyhow::bail!("stop_command_timeout");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

enum StopResult {
    Stopped,
    AlreadyStopped,
}

#[derive(Debug, Clone)]
struct SupervisorHandle {
    tx: tokio_mpsc::UnboundedSender<SupervisorCmd>,
}

enum SupervisorCmd {
    ManualStart {
        force: bool,
        resp: oneshot::Sender<anyhow::Result<()>>,
    },
    ManualStop {
        resp: oneshot::Sender<anyhow::Result<()>>,
    },
    ManualRestart {
        force: bool,
        resp: oneshot::Sender<anyhow::Result<()>>,
    },
    BootStart {
        resp: oneshot::Sender<anyhow::Result<()>>,
    },
    ScheduledStart {
        resp: oneshot::Sender<anyhow::Result<()>>,
    },
    FailureAutoRestart,
    OverTimeStop {
        resp: oneshot::Sender<anyhow::Result<()>>,
    },
    ShutdownStop {
        resp: oneshot::Sender<anyhow::Result<()>>,
    },
    Update {
        def: AppDefinition,
    },
    WaiterExited {
        epoch: u64,
        code: Option<i32>,
    },
    Shutdown,
}

fn spawn_supervisor_thread(
    cfg: MasterConfig,
    def0: AppDefinition,
    run_info: Arc<Mutex<HashMap<String, RunInfo>>>,
    events: Arc<Mutex<VecDeque<EventEntry>>>,
    shutting_down: Arc<AtomicBool>,
) -> SupervisorHandle {
    let (tx, mut rx) = tokio_mpsc::unbounded_channel::<SupervisorCmd>();
    let tx_self = tx.clone();
    tasks().spawn(async move {
        let mut def = def0;
        let app = def.application.clone();

        // No separate "desired" state; operator intent is represented via user flags.

        let mut restart_times: VecDeque<Instant> = VecDeque::new();
        let mut waiter_running = false;
        let mut waiter_epoch: u64 = 0;
        let mut waiter_cancel: Option<Arc<AtomicBool>> = None;
        let mut pending_failure_restart_at: Option<Instant> = None;

        fn cancel_waiter(waiter_running: &mut bool, waiter_cancel: &mut Option<Arc<AtomicBool>>) {
            *waiter_running = false;
            if let Some(c) = waiter_cancel.take() {
                c.store(true, Ordering::Relaxed);
            }
        }

        async fn wait_for_cgroup_nonempty(cfg: &MasterConfig, app: &str, timeout: Duration) -> bool {
            let deadline = Instant::now() + timeout;
            loop {
                if cgroup_running_async(cfg, app).await.unwrap_or(false) {
                    return true;
                }
                if Instant::now() >= deadline {
                    return false;
                }
                tokio_time::sleep(Duration::from_millis(50)).await;
            }
        }

        async fn ensure_waiter_attached(
            cfg: &MasterConfig,
            app: &str,
            tx: &tokio_mpsc::UnboundedSender<SupervisorCmd>,
            waiter_running: &mut bool,
            waiter_epoch: &mut u64,
            waiter_cancel: &mut Option<Arc<AtomicBool>>,
            events: &Arc<Mutex<VecDeque<EventEntry>>>,
        ) {
            if *waiter_running {
                return;
            }
            if !cgroup_running_async(cfg, app).await.unwrap_or(false) {
                return;
            }
            *waiter_epoch = waiter_epoch.wrapping_add(1);
            if let Some(c) = waiter_cancel.take() {
                c.store(true, Ordering::Relaxed);
            }
            let cancel = Arc::new(AtomicBool::new(false));
            if spawn_cgroup_waiter(cfg, app, tx, *waiter_epoch, Arc::clone(&cancel)).is_ok() {
                *waiter_running = true;
                *waiter_cancel = Some(cancel);
                push_event(events, "watch", Some(app), "waiter=attached");
            }
        }

        async fn exec_stop_blocking(
            cfg: MasterConfig,
            def: AppDefinition,
            app: String,
            events: Arc<Mutex<VecDeque<EventEntry>>>,
        ) -> anyhow::Result<StopResult> {
            tasks()
                .spawn_blocking(move || stop_common(Some(&events), &cfg, &def, &app))
                .await
                .map_err(|e| anyhow::anyhow!("join error: {e}"))?
        }

        // If the app is already running before processmaster starts, attach a waiter so we can detect exits.
        ensure_waiter_attached(
            &cfg,
            &app,
            &tx_self,
            &mut waiter_running,
            &mut waiter_epoch,
            &mut waiter_cancel,
            &events,
        )
        .await;

        loop {
            if shutting_down.load(Ordering::Relaxed) {
                push_event(&events, "shutdown", Some(&app), "supervisor=exit reason=shutting_down");
                break;
            }
            // Wait for next command, or fire pending FailureAutoRestart when due.
            let mut timer_fired = false;
            let cmd_opt = if let Some(at) = pending_failure_restart_at {
                let timeout = at.saturating_duration_since(Instant::now());
                tokio::select! {
                    cmd = rx.recv() => cmd,
                    _ = tokio_time::sleep(timeout) => {
                        timer_fired = true;
                        None
                    },
                }
            } else {
                rx.recv().await
            };

            let cmd = match cmd_opt {
                Some(c) => c,
                None => {
                    if timer_fired {
                        pending_failure_restart_at = None;
                        SupervisorCmd::FailureAutoRestart
                    } else {
                        // Channel closed: supervisor should exit.
                        break;
                    }
                }
            };

            match cmd {
                SupervisorCmd::Update { def: new_def } => {
                    def = new_def;
                }
                SupervisorCmd::ManualStart { force, resp } => {
                    // Track "last start attempt" for any accepted start command (even if already running).
                    record_start_attempt_in_store(&run_info, &app);
                    // Manual start clears FAILED/BACKOFF suppression.
                    restart_times.clear();
                    pending_failure_restart_at = None;

                    if !force && !def.enabled {
                        let _ = resp.send(Err(anyhow::anyhow!("service {app} is disabled")));
                        continue;
                    }

                    // If already running, just ensure waiter and return OK.
                    if cgroup_running_async(&cfg, &app).await.unwrap_or(false) {
                        // No-op: starting an already running service should not change intent markers or other flags.
                        ensure_waiter_attached(
                            &cfg,
                            &app,
                            &tx_self,
                            &mut waiter_running,
                            &mut waiter_epoch,
                            &mut waiter_cancel,
                            &events,
                        )
                        .await;
                        let _ = resp.send(Ok(()));
                        continue;
                    }

                    // Not running: this manual start will actually start it, so mark operator intent.
                    // Clear crash history on accepted manual start attempts.
                    {
                        let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                        let e = ri.entry(app.clone()).or_default();
                        e.recent_system_crashes_ms.clear();
                    }

                    set_phase_and_emit(&run_info, &events, &app, Phase::Starting, "manual_start");
                    let cfg2 = cfg.clone();
                    let def2 = def.clone();
                    let spawn_r = tasks()
                        .spawn_blocking(move || spawn_launcher_child(&cfg2, &def2))
                        .await
                        .map_err(|e| anyhow::anyhow!("join error: {e}"));
                    let child_r = match spawn_r {
                        Ok(r) => r,
                        Err(e) => {
                            let _ = resp.send(Err(e));
                            continue;
                        }
                    };
                    if def.schedule.is_some() {
                        // For scheduled jobs, we want a real exit code. Attach a process waiter to the spawned child.
                        // This replaces the cgroup-only waiter (which cannot provide an exit status).
                        let child = match child_r {
                            Ok(c) => c,
                            Err(e) => {
                                let _ = resp.send(Err(e));
                                continue;
                            }
                        };
                        waiter_epoch = waiter_epoch.wrapping_add(1);
                        if let Some(c) = waiter_cancel.take() {
                            c.store(true, Ordering::Relaxed);
                        }
                        waiter_running = true;
                        waiter_cancel = None;
                        let _ = spawn_process_waiter(child, &tx_self, waiter_epoch);
                    } else if let Err(e) = child_r {
                        let _ = resp.send(Err(e));
                        continue;
                    }

                    if !wait_for_cgroup_nonempty(&cfg, &app, Duration::from_secs(3)).await {
                        {
                            let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                            let e = ri.entry(app.clone()).or_default();
                            sysflag_set_with_rules(&app, &mut e.system_flags, SystemFlag::Failed, None);
                        }
                        set_phase_and_emit(&run_info, &events, &app, Phase::Failed, "manual_start_timeout");
                        let _ = resp.send(Err(anyhow::anyhow!("{app}: start timeout (cgroup stayed empty)")));
                        continue;
                    }
                    record_started_in_store(&run_info, &app, StartKind::Start, SYSFLAG_USER_START);
                    if def.schedule.is_none() {
                        ensure_waiter_attached(
                            &cfg,
                            &app,
                            &tx_self,
                            &mut waiter_running,
                            &mut waiter_epoch,
                            &mut waiter_cancel,
                            &events,
                        )
                        .await;
                    }
                    set_phase_and_emit(&run_info, &events, &app, Phase::Running, "manual_start_completed");
                    let _ = resp.send(Ok(()));
                }
                SupervisorCmd::ManualStop { resp }
                => {
                    // If already stopped, do NOT update markers OR clear FAILED/BACKOFF/history.
                    // "Stop" should be a no-op if nothing is running; keeping FAILED makes sense for failed/stopped services.
                    if !cgroup_running_async(&cfg, &app).await.unwrap_or(false) {
                        set_phase_and_emit(&run_info, &events, &app, Phase::Stopped, "stop_noop_already_stopped");
                        let _ = resp.send(Ok(()));
                        continue;
                    }

                    // Now we know it's actually running: manual stop is a real intervention.
                    // Clear pending auto-restart state and failure suppression/history.
                    restart_times.clear();
                    pending_failure_restart_at = None;
                    {
                        let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                        let e = ri.entry(app.clone()).or_default();
                        e.recent_system_crashes_ms.clear();
                    }

                    // The app is actually running: now apply operator intent markers.
                    // Manual stop: persist operator intent marker, including for cron jobs (it will clear on next start).
                    {
                        let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                        let e = ri.entry(app.clone()).or_default();
                        sysflag_set_with_rules(&app, &mut e.system_flags, SYSFLAG_USER_STOP, None);
                    }

                    set_phase_and_emit(&run_info, &events, &app, Phase::Stopping, "stop_requested");
                    let r = exec_stop_blocking(cfg.clone(), def.clone(), app.clone(), Arc::clone(&events)).await;
                    match r {
                        Ok(_) => {
                            set_phase_and_emit(&run_info, &events, &app, Phase::Stopped, "stop_completed");
                            let _ = resp.send(Ok(()));
                        }
                        Err(e) => {
                            // If the stop failed, revert the operator "stopped-by-user" marker.
                            // We set it pre-stop to avoid auto-restart races when the exit is observed,
                            // but if we didn't actually stop the service we must not leave a stale marker behind.
                            let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                            if let Some(entry) = ri.get_mut(&app) {
                                sysflag_clear(&mut entry.system_flags, SYSFLAG_USER_STOP);
                            }
                            let _ = resp.send(Err(e));
                        }
                    }
                }
                SupervisorCmd::ShutdownStop { resp } => {
                    // System stop should not persist operator intent.
                    if !cgroup_running_async(&cfg, &app).await.unwrap_or(false) {
                        set_phase_and_emit(&run_info, &events, &app, Phase::Stopped, "stop_noop_already_stopped");
                        let _ = resp.send(Ok(()));
                        continue;
                    }
                    set_phase_and_emit(&run_info, &events, &app, Phase::Stopping, "stop_requested");
                    let r = exec_stop_blocking(cfg.clone(), def.clone(), app.clone(), Arc::clone(&events)).await;
                    match r {
                        Ok(_) => {
                            set_phase_and_emit(&run_info, &events, &app, Phase::Stopped, "stop_completed");
                            let _ = resp.send(Ok(()));
                        }
                        Err(e) => {
                            let _ = resp.send(Err(e));
                        }
                    }
                }
                SupervisorCmd::OverTimeStop { resp } => {
                    // Overtime stop should not persist operator intent, but does set an informational sysflag for cron jobs.
                    if !cgroup_running_async(&cfg, &app).await.unwrap_or(false) {
                        set_phase_and_emit(&run_info, &events, &app, Phase::Stopped, "stop_noop_already_stopped");
                        let _ = resp.send(Ok(()));
                        continue;
                    }
                    set_phase_and_emit(&run_info, &events, &app, Phase::Stopping, "stop_requested");
                    let r = exec_stop_blocking(cfg.clone(), def.clone(), app.clone(), Arc::clone(&events)).await;
                    match r {
                        Ok(_) => {
                            if def.schedule.is_some() {
                                let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                                let e = ri.entry(app.clone()).or_default();
                                sysflag_set(&mut e.system_flags, SYSFLAG_OT_KILLED, None);
                            }
                            set_phase_and_emit(&run_info, &events, &app, Phase::Stopped, "stop_completed");
                            let _ = resp.send(Ok(()));
                        }
                        Err(e) => {
                            let _ = resp.send(Err(e));
                        }
                    }
                }
                SupervisorCmd::ManualRestart { force, resp } => {
                    // Track "last start attempt" for restart requests (even if already running later).
                    record_start_attempt_in_store(&run_info, &app);
                    // Manual restart clears FAILED/BACKOFF suppression.
                    restart_times.clear();
                    pending_failure_restart_at = None;
                    if !force && !def.enabled {
                        let _ = resp.send(Err(anyhow::anyhow!("service {app} is disabled")));
                        continue;
                    }
                    {
                        let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                        let e = ri.entry(app.clone()).or_default();
                        e.recent_system_crashes_ms.clear();
                    }
                    // Stop step
                    if cgroup_running_async(&cfg, &app).await.unwrap_or(false) {
                        // IMPORTANT: during manual restart we intentionally stop the cgroup.
                        // The existing waiter is "wait until cgroup empty" and would report this as an exit event,
                        // which can race and be interpreted as a crash after restart. Invalidate it before stopping.
                        waiter_epoch = waiter_epoch.wrapping_add(1);
                        cancel_waiter(&mut waiter_running, &mut waiter_cancel);
                        set_phase_and_emit(&run_info, &events, &app, Phase::Stopping, "manual_restart_stop");
                        if let Err(e) = exec_stop_blocking(cfg.clone(), def.clone(), app.clone(), Arc::clone(&events)).await {
                            set_phase_and_emit(&run_info, &events, &app, Phase::Failed, "manual_restart_stop_error");
                            let _ = resp.send(Err(e));
                            continue;
                        }
                    }
                    // Start step
                    if cgroup_running_async(&cfg, &app).await.unwrap_or(false) {
                        ensure_waiter_attached(
                            &cfg,
                            &app,
                            &tx_self,
                            &mut waiter_running,
                            &mut waiter_epoch,
                            &mut waiter_cancel,
                            &events,
                        )
                        .await;
                        let _ = resp.send(Ok(()));
                        continue;
                    }
                    set_phase_and_emit(&run_info, &events, &app, Phase::Restarting, "manual_restart_start");
                    let cfg2 = cfg.clone();
                    let def2 = def.clone();
                    let spawn_r = tasks()
                        .spawn_blocking(move || spawn_launcher_child(&cfg2, &def2))
                        .await
                        .map_err(|e| anyhow::anyhow!("join error: {e}"));
                    let child_r = match spawn_r {
                        Ok(r) => r,
                        Err(e) => {
                            let _ = resp.send(Err(e));
                            continue;
                        }
                    };
                    if def.schedule.is_some() {
                        let child = match child_r {
                            Ok(c) => c,
                            Err(e) => {
                                let _ = resp.send(Err(e));
                                continue;
                            }
                        };
                        waiter_epoch = waiter_epoch.wrapping_add(1);
                        if let Some(c) = waiter_cancel.take() {
                            c.store(true, Ordering::Relaxed);
                        }
                        waiter_running = true;
                        waiter_cancel = None;
                        let _ = spawn_process_waiter(child, &tx_self, waiter_epoch);
                    } else if let Err(e) = child_r {
                        let _ = resp.send(Err(e));
                        continue;
                    }
                    if !wait_for_cgroup_nonempty(&cfg, &app, Duration::from_secs(3)).await {
                        {
                            let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                            let e = ri.entry(app.clone()).or_default();
                            sysflag_set_with_rules(&app, &mut e.system_flags, SystemFlag::Failed, None);
                        }
                        set_phase_and_emit(&run_info, &events, &app, Phase::Failed, "manual_restart_start_timeout");
                        let _ = resp.send(Err(anyhow::anyhow!("{app}: restart timeout (cgroup stayed empty)")));
                        continue;
                    }
                    record_started_in_store(&run_info, &app, StartKind::Restart, SYSFLAG_USER_START);
                    if def.schedule.is_none() {
                        ensure_waiter_attached(
                            &cfg,
                            &app,
                            &tx_self,
                            &mut waiter_running,
                            &mut waiter_epoch,
                            &mut waiter_cancel,
                            &events,
                        )
                        .await;
                    }
                    // After a successful manual restart:
                    // - clear FAILED (operator intervened)
                    // - clear restart history used for tolerance/backoff decisions
                    restart_times.clear();
                    pending_failure_restart_at = None;
                    {
                        let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                        let e = ri.entry(app.clone()).or_default();
                        e.recent_system_crashes_ms.clear();
                    }
                    set_phase_and_emit(&run_info, &events, &app, Phase::Running, "manual_restart_completed");
                    let _ = resp.send(Ok(()));
                }
                SupervisorCmd::BootStart { resp } => {
                    // Track start attempt for boot starts too.
                    record_start_attempt_in_store(&run_info, &app);
                    // Boot start is a system action: do not clear FAILED; if FAILED is set, skip.
                    if !def.enabled || def.schedule.is_some() {
                        let _ = resp.send(Ok(()));
                        continue;
                    }
                    {
                        let ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                        let info = ri.get(&app).cloned().unwrap_or_default();
                        if sysflag_has(&info.system_flags, SystemFlag::Failed) {
                            let _ = resp.send(Err(anyhow::anyhow!("{app}: failed (manual intervention required)")));
                            continue;
                        }
                        if sysflag_has(&info.system_flags, SYSFLAG_USER_STOP) {
                            let _ = resp.send(Err(anyhow::anyhow!("{app}: stopped by user")));
                            continue;
                        }
                    }
                    if cgroup_running_async(&cfg, &app).await.unwrap_or(false) {
                        ensure_waiter_attached(
                            &cfg,
                            &app,
                            &tx_self,
                            &mut waiter_running,
                            &mut waiter_epoch,
                            &mut waiter_cancel,
                            &events,
                        )
                        .await;
                        let _ = resp.send(Ok(()));
                        continue;
                    }
                    set_phase_and_emit(&run_info, &events, &app, Phase::Starting, "boot_start");
                    let cfg2 = cfg.clone();
                    let def2 = def.clone();
                    let spawn_r = tasks()
                        .spawn_blocking(move || spawn_launcher_child(&cfg2, &def2))
                        .await
                        .map_err(|e| anyhow::anyhow!("join error: {e}"));
                    if let Err(e) = spawn_r {
                        let _ = resp.send(Err(e));
                        continue;
                    }
                    if !wait_for_cgroup_nonempty(&cfg, &app, Duration::from_secs(3)).await {
                        {
                            let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                            let e = ri.entry(app.clone()).or_default();
                            sysflag_set_with_rules(&app, &mut e.system_flags, SystemFlag::Failed, None);
                        }
                        set_phase_and_emit(&run_info, &events, &app, Phase::Failed, "boot_start_timeout");
                        let _ = resp.send(Err(anyhow::anyhow!("{app}: start timeout (cgroup stayed empty)")));
                        continue;
                    }
                    record_started_in_store(&run_info, &app, StartKind::Start, SystemFlag::SystemStart);
                    ensure_waiter_attached(
                        &cfg,
                        &app,
                        &tx_self,
                        &mut waiter_running,
                        &mut waiter_epoch,
                        &mut waiter_cancel,
                        &events,
                    )
                    .await;
                    set_phase_and_emit(&run_info, &events, &app, Phase::Running, "boot_start_completed");
                    let _ = resp.send(Ok(()));
                }
                SupervisorCmd::ScheduledStart { resp } => {
                    // Track last start attempt for scheduled triggers too.
                    record_start_attempt_in_store(&run_info, &app);
                    // Scheduled start is only meaningful for scheduled jobs.
                    if def.schedule.is_none() {
                        let _ = resp.send(Err(anyhow::anyhow!("{app}: not a scheduled job")));
                        continue;
                    }
                    if !def.enabled {
                        let _ = resp.send(Err(anyhow::anyhow!("{app}: disabled")));
                        continue;
                    }
                    if cgroup_running_async(&cfg, &app).await.unwrap_or(false) {
                        ensure_waiter_attached(
                            &cfg,
                            &app,
                            &tx_self,
                            &mut waiter_running,
                            &mut waiter_epoch,
                            &mut waiter_cancel,
                            &events,
                        )
                        .await;
                        let _ = resp.send(Ok(()));
                        continue;
                    }
                    set_phase_and_emit(&run_info, &events, &app, Phase::Starting, "scheduled_start");
                    let cfg2 = cfg.clone();
                    let def2 = def.clone();
                    let spawn_r = tasks()
                        .spawn_blocking(move || spawn_launcher_child(&cfg2, &def2))
                        .await
                        .map_err(|e| anyhow::anyhow!("join error: {e}"));
                    let child = match spawn_r {
                        Ok(Ok(c)) => c,
                        Ok(Err(e)) => {
                            let _ = resp.send(Err(e));
                            continue;
                        }
                        Err(e) => {
                            let _ = resp.send(Err(e));
                            continue;
                        }
                    };
                    // For scheduled jobs, attach a process waiter to capture the real exit code (0 vs non-0).
                    // The cgroup-only waiter cannot provide an exit status and would report code=None.
                    waiter_epoch = waiter_epoch.wrapping_add(1);
                    if let Some(c) = waiter_cancel.take() {
                        c.store(true, Ordering::Relaxed);
                    }
                    waiter_running = true;
                    waiter_cancel = None;
                    let _ = spawn_process_waiter(child, &tx_self, waiter_epoch);
                    if !wait_for_cgroup_nonempty(&cfg, &app, Duration::from_secs(3)).await {
                        let _ = resp.send(Err(anyhow::anyhow!("{app}: start timeout (cgroup stayed empty)")));
                        continue;
                    }
                    record_started_in_store(&run_info, &app, StartKind::Start, SystemFlag::SystemStart);
                    set_phase_and_emit(&run_info, &events, &app, Phase::Running, "scheduled_start_completed");
                    let _ = resp.send(Ok(()));
                }
                SupervisorCmd::FailureAutoRestart => {
                    // Track last start attempt for auto-restart attempts too.
                    record_start_attempt_in_store(&run_info, &app);
                    // Auto restart attempt after a failure/backoff window.
                    // Respect FAILED: it permanently disables auto restart until manual intervention.
                    if !def.enabled || def.schedule.is_some() {
                        continue;
                    }
                    // Restart config defaults to "always" with tolerance 3 restarts / 3 minutes.
                    // Treat missing restart config as the default (so we don't immediately become FAILED).
                    let restart = def.restart.clone().unwrap_or_default();
                    let info = {
                        let ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                        ri.get(&app).cloned().unwrap_or_default()
                    };
                    if sysflag_has(&info.system_flags, SYSFLAG_USER_STOP) {
                        set_phase_and_emit(&run_info, &events, &app, Phase::Stopped, "failure_auto_restart_stopped_by_user");
                        continue;
                    }
                    if sysflag_has(&info.system_flags, SystemFlag::Failed) {
                        set_phase_and_emit(&run_info, &events, &app, Phase::Failed, "failure_auto_restart_failed_flag_set");
                        continue;
                    }
                    if cgroup_running_async(&cfg, &app).await.unwrap_or(false) {
                        // Already running again; just ensure waiter.
                        ensure_waiter_attached(
                            &cfg,
                            &app,
                            &tx_self,
                            &mut waiter_running,
                            &mut waiter_epoch,
                            &mut waiter_cancel,
                            &events,
                        )
                        .await;
                        continue;
                    }

                    set_phase_and_emit(&run_info, &events, &app, Phase::Restarting, "failure_auto_restart");
                    let cfg2 = cfg.clone();
                    let def2 = def.clone();
                    let spawn_r = tasks()
                        .spawn_blocking(move || spawn_launcher_child(&cfg2, &def2))
                        .await
                        .map_err(|e| anyhow::anyhow!("join error: {e}"));
                    if let Err(e) = spawn_r {
                        // Treat restart attempt failures as restart attempts within tolerance.
                        // Do NOT immediately mark FAILED; only do so once tolerance is exceeded.
                        let now = Instant::now();
                        while let Some(front) = restart_times.front() {
                            if now.duration_since(*front).as_millis() as u64 > restart.tolerance.duration {
                                restart_times.pop_front();
                            } else {
                                break;
                            }
                        }
                        restart_times.push_back(now);
                        if restart_times.len() > restart.tolerance.max_restarts {
                            push_event(
                                &events,
                                "restart",
                                Some(&app),
                                format!(
                                    "decision=suppress reason=tolerance_exceeded outcome=spawn_error max_restarts={} window_ms={} err={e}",
                                    restart.tolerance.max_restarts, restart.tolerance.duration
                                ),
                            );
                            {
                                let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                                let e2 = ri.entry(app.clone()).or_default();
                                sysflag_set_with_rules(&app, &mut e2.system_flags, SystemFlag::Failed, None);
                            }
                            set_phase_and_emit(&run_info, &events, &app, Phase::Failed, "failure_auto_restart_tolerance_exceeded_spawn_error");
                        } else {
                            let backoff_ms = restart.restart_backoff_ms;
                            push_event(
                                &events,
                                "restart",
                                Some(&app),
                                format!(
                                    "decision=backoff outcome=spawn_error backoff_ms={} recent_restarts_in_window={} err={e}",
                                    backoff_ms,
                                    restart_times.len()
                                ),
                            );
                            {
                                let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                                let e2 = ri.entry(app.clone()).or_default();
                                let until_ms = Local::now().timestamp_millis() + backoff_ms as i64;
                                sysflag_set(&mut e2.system_flags, SystemFlag::Backoff, Some(until_ms));
                            }
                            set_phase_and_emit(&run_info, &events, &app, Phase::Backoff, "failure_auto_restart_spawn_error_backoff");
                            pending_failure_restart_at = Some(Instant::now() + Duration::from_millis(backoff_ms));
                        }
                        continue;
                    }

                    if !wait_for_cgroup_nonempty(&cfg, &app, Duration::from_secs(3)).await {
                        // Treat restart attempt failures as restart attempts within tolerance.
                        // Do NOT immediately mark FAILED; only do so once tolerance is exceeded.
                        let now = Instant::now();
                        while let Some(front) = restart_times.front() {
                            if now.duration_since(*front).as_millis() as u64 > restart.tolerance.duration {
                                restart_times.pop_front();
                            } else {
                                break;
                            }
                        }
                        restart_times.push_back(now);
                        if restart_times.len() > restart.tolerance.max_restarts {
                            push_event(
                                &events,
                                "restart",
                                Some(&app),
                                format!(
                                    "decision=suppress reason=tolerance_exceeded outcome=start_timeout max_restarts={} window_ms={} cgroup_empty_after_ms=3000",
                                    restart.tolerance.max_restarts, restart.tolerance.duration
                                ),
                            );
                            {
                                let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                                let e2 = ri.entry(app.clone()).or_default();
                                sysflag_set_with_rules(&app, &mut e2.system_flags, SystemFlag::Failed, None);
                            }
                            set_phase_and_emit(&run_info, &events, &app, Phase::Failed, "failure_auto_restart_tolerance_exceeded_timeout");
                        } else {
                            let backoff_ms = restart.restart_backoff_ms;
                            push_event(
                                &events,
                                "restart",
                                Some(&app),
                                format!(
                                    "decision=backoff outcome=start_timeout backoff_ms={} recent_restarts_in_window={} cgroup_empty_after_ms=3000",
                                    backoff_ms,
                                    restart_times.len()
                                ),
                            );
                            {
                                let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                                let e2 = ri.entry(app.clone()).or_default();
                                let until_ms = Local::now().timestamp_millis() + backoff_ms as i64;
                                sysflag_set(&mut e2.system_flags, SystemFlag::Backoff, Some(until_ms));
                            }
                            set_phase_and_emit(&run_info, &events, &app, Phase::Backoff, "failure_auto_restart_timeout_backoff");
                            pending_failure_restart_at = Some(Instant::now() + Duration::from_millis(backoff_ms));
                        }
                        continue;
                    }

                    record_started_in_store(&run_info, &app, StartKind::Restart, SystemFlag::SystemStart);
                    ensure_waiter_attached(
                        &cfg,
                        &app,
                        &tx_self,
                        &mut waiter_running,
                        &mut waiter_epoch,
                        &mut waiter_cancel,
                        &events,
                    )
                    .await;
                    set_phase_and_emit(&run_info, &events, &app, Phase::Running, "failure_auto_restart_completed");
                }
                SupervisorCmd::WaiterExited { epoch, code } => {
                    if epoch != waiter_epoch {
                        push_event(&events, "watch", Some(&app), format!("ignore_exit reason=stale_epoch got={epoch} want={waiter_epoch}"));
                        continue;
                    }
                    waiter_running = false;
                    waiter_cancel = None;
                    {
                        let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                        let e = ri.entry(app.clone()).or_default();
                        e.last_exit_code = code;
                    }
                    push_event(&events, "watch", Some(&app), format!("event=exit_observed code={}", code.unwrap_or(-1)));

                    // Scheduled jobs: return to SCHEDULED after exit; no auto-restart.
                    if def.schedule.is_some() {
                        let c = code.unwrap_or(1);
                        if c != 0 {
                            record_system_crash_in_store(&run_info, &app);
                        }
                        // Cron exit outcome flags (mutually exclusive via flag rules).
                        {
                            let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                            let e = ri.entry(app.clone()).or_default();
                            if c == 0 {
                                sysflag_set_with_rules(&app, &mut e.system_flags, SystemFlag::ExitOk, None);
                            } else {
                                sysflag_set_with_rules(&app, &mut e.system_flags, SystemFlag::ExitErr, None);
                            }
                        }
                        // Do not clear sysflags for cron jobs on exit. Cron has no auto-restart/backoff semantics,
                        // and flags like `ot_killed` should remain visible until the next run clears them.
                        set_phase_and_emit(&run_info, &events, &app, Phase::Stopped, "scheduled_completed");
                        continue;
                    }

                    // Services: decide whether to auto-restart.
                    // If disabled, or stopped by user, just mark stopped.
                    let info = {
                        let ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                        ri.get(&app).cloned().unwrap_or_default()
                    };
                    if !def.enabled {
                        set_phase_and_emit(&run_info, &events, &app, Phase::Stopped, "exit_observed_disabled");
                        continue;
                    }
                    if sysflag_has(&info.system_flags, SYSFLAG_USER_STOP) {
                        set_phase_and_emit(&run_info, &events, &app, Phase::Stopped, "exit_observed_stopped_by_user");
                        continue;
                    }

                    // FAILED permanently disables auto restart until manual intervention.
                    if sysflag_has(&info.system_flags, SystemFlag::Failed) {
                        set_phase_and_emit(&run_info, &events, &app, Phase::Failed, "failed_flag_set");
                        continue;
                    }

                    record_system_crash_in_store(&run_info, &app);

                    // Restart config defaults to "always" with tolerance 3 restarts / 3 minutes.
                    // Treat missing restart config as the default (so the first crash doesn't immediately become FAILED).
                    let restart = def.restart.clone().unwrap_or_default();

                    let policy = match restart.policy.parsed() {
                        Ok(p) => p,
                        Err(e) => {
                            push_event(&events, "restart", Some(&app), format!("decision=skip reason=policy_parse_error err={e}"));
                            {
                                let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                                let e = ri.entry(app.clone()).or_default();
                                sysflag_set_with_rules(&app, &mut e.system_flags, SystemFlag::Failed, None);
                            }
                            set_phase_and_emit(&run_info, &events, &app, Phase::Failed, "restart_policy_parse_error");
                            continue;
                        }
                    };

                    match policy {
                        RestartPolicyParsed::Never => {
                            {
                                let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                                let e = ri.entry(app.clone()).or_default();
                                sysflag_set_with_rules(&app, &mut e.system_flags, SystemFlag::Failed, None);
                            }
                            set_phase_and_emit(&run_info, &events, &app, Phase::Failed, "exit_policy_never");
                        }
                        RestartPolicyParsed::Always => {
                            // Restart tolerance window (count this restart attempt).
                            let now = Instant::now();
                            while let Some(front) = restart_times.front() {
                                if now.duration_since(*front).as_millis() as u64 > restart.tolerance.duration {
                                    restart_times.pop_front();
                                } else {
                                    break;
                                }
                            }
                            restart_times.push_back(now);
                            if restart_times.len() > restart.tolerance.max_restarts {
                                push_event(
                                    &events,
                                    "restart",
                                    Some(&app),
                                    format!(
                                        "decision=suppress reason=tolerance_exceeded max_restarts={} window_ms={}",
                                        restart.tolerance.max_restarts, restart.tolerance.duration
                                    ),
                                );
                                {
                                    let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                                    let e = ri.entry(app.clone()).or_default();
                                    sysflag_set_with_rules(&app, &mut e.system_flags, SystemFlag::Failed, None);
                                }
                                set_phase_and_emit(&run_info, &events, &app, Phase::Failed, "tolerance_exceeded");
                            } else {
                                // Enter BACKOFF until the next restart attempt.
                                {
                                    let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
                                    let e = ri.entry(app.clone()).or_default();
                                    let until_ms = Local::now().timestamp_millis() + restart.restart_backoff_ms as i64;
                                    sysflag_set(&mut e.system_flags, SystemFlag::Backoff, Some(until_ms));
                                }
                                set_phase_and_emit(&run_info, &events, &app, Phase::Backoff, "restart_backoff");
                                pending_failure_restart_at = Some(Instant::now() + Duration::from_millis(restart.restart_backoff_ms));
                                push_event(
                                    &events,
                                    "restart",
                                    Some(&app),
                                    format!(
                                        "decision=backoff backoff_ms={} recent_restarts_in_window={}",
                                        restart.restart_backoff_ms,
                                        restart_times.len()
                                    ),
                                );
                            }
                        }
                    }
                }
                SupervisorCmd::Shutdown => break,
            }
        }
    });
    SupervisorHandle { tx }
}

fn spawn_cgroup_waiter(
    cfg: &MasterConfig,
    app: &str,
    tx: &tokio_mpsc::UnboundedSender<SupervisorCmd>,
    epoch: u64,
    cancel: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let app_s = app.to_string();
    let tx2 = tx.clone();
    let cg_dir = app_cgroup_dir(cfg, &app_s);
    std::thread::spawn(move || {
        match cgroup::wait_all_cancellable(&cg_dir, &cancel) {
            Ok(true) => {
                let _ = tx2.send(SupervisorCmd::WaiterExited { epoch, code: None });
            }
            Ok(false) => {
                // cancelled
            }
            Err(_) => {
                let _ = tx2.send(SupervisorCmd::WaiterExited { epoch, code: Some(1) });
            }
        }
    });
    Ok(())
}

fn spawn_process_waiter(
    mut child: std::process::Child,
    tx: &tokio_mpsc::UnboundedSender<SupervisorCmd>,
    epoch: u64,
) -> anyhow::Result<()> {
    let tx2 = tx.clone();
    std::thread::spawn(move || {
        let code = match child.wait() {
            Ok(st) => st.code().unwrap_or(1),
            Err(_) => 1,
        };
        let _ = tx2.send(SupervisorCmd::WaiterExited { epoch, code: Some(code) });
    });
    Ok(())
}

fn parse_signal(s: &str) -> anyhow::Result<Signal> {
    let raw = s.trim().to_uppercase();
    let name = raw.strip_prefix("SIG").unwrap_or(&raw);
    let sig = match name {
        "TERM" => Signal::SIGTERM,
        "KILL" => Signal::SIGKILL,
        "INT" => Signal::SIGINT,
        "HUP" => Signal::SIGHUP,
        "QUIT" => Signal::SIGQUIT,
        "ABRT" => Signal::SIGABRT,
        "ALRM" => Signal::SIGALRM,
        "USR1" => Signal::SIGUSR1,
        "USR2" => Signal::SIGUSR2,
        "CHLD" => Signal::SIGCHLD,
        _ => anyhow::bail!("unsupported stop_signal: {s}"),
    };
    Ok(sig)
}

fn preflight_validate_and_load_defs(cfg: &MasterConfig) -> anyhow::Result<HashMap<String, AppDefinition>> {
    // Best-effort load: keep daemon up even if some services cannot be loaded.
    // Rules:
    // - parse/misconfig failures: skip that service
    // - duplicates: do not load ambiguous new defs (best-effort keeps old elsewhere; at boot there is no old)
    let empty: HashMap<String, AppDefinition> = HashMap::new();
    let (defs, warnings, _outdated) = load_app_definitions_best_effort(
        &cfg.config_directory,
        &empty,
        cfg.auto_service_directory.as_deref(),
    )?;
    for w in warnings {
        pm_event("config", None, format!("load_warning {w}"));
    }
    Ok(defs)
}

fn load_app_definitions_best_effort(
    dir: &Path,
    old_defs: &HashMap<String, AppDefinition>,
    auto_service_directory: Option<&Path>,
) -> anyhow::Result<(HashMap<String, AppDefinition>, Vec<String>, Vec<String>)> {
    if !dir.exists() {
        return Ok((
            old_defs.clone(),
            vec![format!("config_directory_missing dir={} kept_last_known_good=true", dir.display())],
            vec![],
        ));
    }
    if !dir.is_dir() {
        return Ok((
            old_defs.clone(),
            vec![format!("config_directory_not_dir dir={} kept_last_known_good=true", dir.display())],
            vec![],
        ));
    }

    // Non-recursive: only load direct children of the directory.
    let mut files: Vec<PathBuf> = vec![];
    let rd = fs::read_dir(dir).map_err(|e| anyhow::anyhow!("failed to read config_directory {}: {e}", dir.display()))?;
    for e in rd.flatten() {
        if files.len() >= MAX_APPS {
            anyhow::bail!("too many app definitions (max {MAX_APPS})");
        }
        let p = e.path();
        let meta = match e.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_file() {
            continue;
        }
        let Some(ext) = p.extension().and_then(|s| s.to_str()) else { continue };
        let ext = ext.to_ascii_lowercase();
        if ext != "yaml" && ext != "yml" {
            continue;
        }
        files.push(p);
    }

    let mut defs: HashMap<String, AppDefinition> = HashMap::new();
    let mut warnings: Vec<String> = vec![];
    let mut outdated: Vec<String> = vec![];
    let mut seen_sources: HashMap<String, Vec<PathBuf>> = HashMap::new();
    let mut dup_apps: HashMap<String, Vec<PathBuf>> = HashMap::new();

    for path in &files {
        // Enforce per-file size limit (best-effort: keep previous if possible).
        if let Ok(m) = fs::metadata(path) {
            if m.is_file() && m.len() > MAX_APP_CONFIG_BYTES {
                if let Some((app, old)) = old_defs
                    .iter()
                    .find(|(_, d)| d.source_file.as_deref() == Some(path.as_path()))
                {
                    defs.insert(app.clone(), old.clone());
                    warnings.push(format!(
                        "file_too_large file={} kept_previous_app={} bytes={} limit_bytes={}",
                        path.display(),
                        app,
                        m.len(),
                        MAX_APP_CONFIG_BYTES
                    ));
                    outdated.push(app.clone());
                } else {
                    warnings.push(format!(
                        "file_too_large file={} bytes={} limit_bytes={}",
                        path.display(),
                        m.len(),
                        MAX_APP_CONFIG_BYTES
                    ));
                }
                continue;
            }
        }
        let raw = match fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                // Keep old definition for this file if possible.
                if let Some((app, old)) = old_defs
                    .iter()
                    .find(|(_, d)| d.source_file.as_deref() == Some(path.as_path()))
                {
                    defs.insert(app.clone(), old.clone());
                    warnings.push(format!(
                        "read_failed file={} kept_previous_app={} err={e}",
                        path.display(),
                        app
                    ));
                    outdated.push(app.clone());
                } else {
                    warnings.push(format!("read_failed file={} err={e}", path.display()));
                }
                continue;
            }
        };

        match parse_app_definition_yaml(&raw, path, auto_service_directory) {
            Ok(def) => {
                // Misconfig check: working directory must exist (otherwise skip/keep old).
                if !def.working_directory.exists() || !def.working_directory.is_dir() {
                    if let Some((app, old)) = old_defs
                        .iter()
                        .find(|(_, d)| d.source_file.as_deref() == Some(path.as_path()))
                    {
                        defs.insert(app.clone(), old.clone());
                        warnings.push(format!(
                            "misconfigured_workdir file={} kept_previous_app={} workdir={}",
                            path.display(),
                            app,
                            def.working_directory.display()
                        ));
                        outdated.push(app.clone());
                    } else {
                        warnings.push(format!(
                            "misconfigured_workdir file={} dropped_app={} workdir={}",
                            path.display(),
                            def.application,
                            def.working_directory.display()
                        ));
                    }
                    continue;
                }

                // Provisioning is an optional, one-time setup step. If defined and not yet provisioned
                // (marker missing), provisioning must succeed for the app to be loadable.
                // If provisioning fails, we drop the app from this load (do NOT keep last-known-good),
                // so a subsequent reload will retry provisioning.
                if !def.provisioning.is_empty() {
                    if let Err(e) = maybe_provision_workdir(&def) {
                        pm_event(
                            "provision",
                            Some(&def.application),
                            format!(
                                "decision=drop_load reason=provision_failed file={} err={e}",
                                path.display()
                            ),
                        );
                        warnings.push(format!(
                            "provision_failed file={} dropped_app={} err={e}",
                            path.display(),
                            def.application
                        ));
                        continue;
                    }
                }

                let app = def.application.clone();
                seen_sources.entry(app.clone()).or_default().push(path.to_path_buf());
                if defs.contains_key(&app) {
                    dup_apps.entry(app.clone()).or_default().push(path.to_path_buf());
                }
                defs.insert(app, def);
            }
            Err(e) => {
                if let Some((app, old)) = old_defs
                    .iter()
                    .find(|(_, d)| d.source_file.as_deref() == Some(path.as_path()))
                {
                    defs.insert(app.clone(), old.clone());
                    warnings.push(format!(
                        "parse_failed file={} kept_previous_app={} err={e}",
                        path.display(),
                        app
                    ));
                    outdated.push(app.clone());
                } else {
                    warnings.push(format!("parse_failed file={} err={e}", path.display()));
                }
            }
        }
    }

    // Preserve any in-memory definitions that have no source_file (should be rare).
    for (app, def) in old_defs {
        if def.source_file.is_none() && !defs.contains_key(app) {
            defs.insert(app.clone(), def.clone());
            warnings.push(format!("kept_in_memory_definition app={app} reason=no_source_file"));
        }
    }

    // Merge implicit services from auto_service_directory (best-effort: report read errors as warnings,
    // but treat name collisions as hard errors).
    merge_auto_services_best_effort(
        &mut defs,
        old_defs,
        auto_service_directory,
        warnings.as_mut(),
        &mut outdated,
    )?;

    // Handle duplicates: if multiple sources define the same app name, do not pick one arbitrarily.
    // Best-effort rule: keep last-known-good if available; otherwise drop the app from this load.
    for (app, dups) in &dup_apps {
        let mut sources = seen_sources.get(app).cloned().unwrap_or_default();
        sources.extend_from_slice(dups);
        sources.sort();
        sources.dedup();

        if let Some(old) = old_defs.get(app) {
            defs.insert(app.clone(), old.clone());
            warnings.push(format!(
                "duplicate_application app={} action=kept_previous sources={}",
                app,
                sources
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ));
            outdated.push(app.clone());
        } else {
            defs.remove(app);
            warnings.push(format!(
                "duplicate_application app={} action=dropped sources={}",
                app,
                sources
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
    }

    outdated.sort();
    outdated.dedup();
    Ok((defs, warnings, outdated))
}

fn build_auto_service_def(app: &str, workdir: &Path, source_file: PathBuf) -> anyhow::Result<AppDefinition> {
    let rotation_size_bytes = parse_size_spec_bytes("10m").ok();
    let source_mtime_ms = source_file
        .metadata()
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|mt| mt.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_millis()).ok());
    Ok(AppDefinition {
        application: app.to_string(),
        working_directory: workdir.to_path_buf(),
        log_stdout: None,
        log_stderr: None,
        stop_command_stdout: Some("./logs/stop_command_stdout.log".into()),
        stop_command_stderr: Some("./logs/stop_command_stderr.log".into()),
        alt_log_file_hint: vec![],
        start_command: vec!["./run.sh".to_string()],
        environment: vec![],
        restart: Some(RestartConfig {
            policy: RestartPolicy::default(),
            restart_backoff_ms: 1000,
            tolerance: RestartTolerance::default(),
        }),
        stop_signal: Some("SIGTERM".to_string()),
        stop_command: None,
        stop_grace_period_ms: 5_000,
        max_cpu: Some("MAX".to_string()),
        max_memory: Some("MAX".to_string()),
        max_swap: Some("MAX".to_string()),
        user: None,
        group: None,
        rotation_mode: LogRotationMode::Size,
        rotation_frequency: LogRotation::Daily,
        rotation_max_age_ms: 30 * 24 * 60 * 60 * 1000,
        rotation_size_bytes,
        rotation_backups: Some(10),
        log_compression_enabled: true,
        enabled: true,
        schedule: None,
        schedule_not_before_ms: None,
        schedule_not_after_ms: None,
        schedule_max_time_per_run_ms: None,
        provisioning: vec![],
        source_file: Some(source_file),
        source_mtime_ms,
    })
}

fn merge_auto_services_best_effort(
    defs: &mut HashMap<String, AppDefinition>,
    old_defs: &HashMap<String, AppDefinition>,
    auto_service_directory: Option<&Path>,
    warnings: &mut Vec<String>,
    outdated: &mut Vec<String>,
) -> anyhow::Result<()> {
    let Some(dir) = auto_service_directory else { return Ok(()) };
    if !dir.exists() {
        warnings.push(format!("auto_service_directory_missing dir={}", dir.display()));
        return Ok(());
    }
    if !dir.is_dir() {
        warnings.push(format!("auto_service_directory_not_dir dir={}", dir.display()));
        return Ok(());
    }
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            warnings.push(format!("auto_service_directory_read_failed dir={} err={e}", dir.display()));
            return Ok(());
        }
    };
    for e in rd.flatten() {
        if defs.len() >= MAX_APPS {
            anyhow::bail!("too many app definitions (max {MAX_APPS})");
        }
        let path = e.path();
        let meta = match e.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else { continue };
        let app = name.trim();
        if app.is_empty() {
            continue;
        }
        // Quick disable: any auto-service directory ending with ".disabled" is ignored.
        if app.ends_with(".disabled") {
            continue;
        }
        if defs.contains_key(app) {
            anyhow::bail!(
                "auto_service_directory conflict: application {} is already defined in config_directory",
                app
            );
        }
        let svc_yml = path.join("service.yml");
        let svc_yaml = path.join("service.yaml");

        // Optional regeneration marker for lazy upgrades:
        // If `.regen_pm_config` exists, we rotate any existing service.{yml,yaml} to `service.yml.bak*`,
        // generate a fresh `service.yml` from defaults, and load it. Finally remove the marker.
        let regen_marker = path.join(".regen_pm_config");
        let mut svc_file = if svc_yml.is_file() {
            Some(svc_yml.clone())
        } else if svc_yaml.is_file() {
            Some(svc_yaml.clone())
        } else {
            None
        };
        if regen_marker.is_file() {
            fn next_bak_path(dir: &Path) -> PathBuf {
                let base = dir.join("service.yml.bak");
                if !base.exists() {
                    return base;
                }
                for i in 1..10_000usize {
                    let c = dir.join(format!("service.yml.bak.{i}"));
                    if !c.exists() {
                        return c;
                    }
                }
                // Extremely unlikely; fall back.
                dir.join(format!("service.yml.bak.{}", std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis())
                    .unwrap_or(0)))
            }

            let mut regen_ok = true;

            // Rotate existing service.yml/service.yaml (if any) into service.yml.bak(.N).
            for old in [&svc_yml, &svc_yaml] {
                if old.is_file() {
                    let bak = next_bak_path(&path);
                    if let Err(e) = std::fs::rename(old, &bak) {
                        warnings.push(format!(
                            "auto_service_regen_backup_failed app={} from={} to={} err={e}",
                            app,
                            old.display(),
                            bak.display()
                        ));
                        regen_ok = false;
                    } else {
                        warnings.push(format!(
                            "auto_service_regen_backed_up app={} from={} to={}",
                            app,
                            old.display(),
                            bak.display()
                        ));
                    }
                }
            }

            // Generate a fresh service.yml.
            let yaml_text = match crate::pm::app::render_auto_service_yaml(app, &path) {
                Ok(s) => s,
                Err(e) => {
                    warnings.push(format!(
                        "auto_service_regen_generate_failed app={} file={} err={e}",
                        app,
                        svc_yml.display()
                    ));
                    regen_ok = false;
                    String::new()
                }
            };
            if regen_ok {
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&svc_yml)
                {
                    Ok(mut f) => {
                        if let Err(e) = f.write_all(yaml_text.as_bytes()) {
                            warnings.push(format!(
                                "auto_service_regen_write_failed app={} file={} err={e}",
                                app,
                                svc_yml.display()
                            ));
                            regen_ok = false;
                        } else {
                            warnings.push(format!(
                                "auto_service_regen_written app={} file={}",
                                app,
                                svc_yml.display()
                            ));
                        }
                    }
                    Err(e) => {
                        warnings.push(format!(
                            "auto_service_regen_write_failed app={} file={} err={e}",
                            app,
                            svc_yml.display()
                        ));
                        regen_ok = false;
                    }
                }
            }

            // Set to load the regenerated `service.yml` (even if the backup step failed; user asked for regen).
            svc_file = Some(svc_yml.clone());

            // Remove marker only if generation + write succeeded.
            if regen_ok {
                if let Err(e) = std::fs::remove_file(&regen_marker) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        warnings.push(format!(
                            "auto_service_regen_marker_remove_failed app={} file={} err={e}",
                            app,
                            regen_marker.display()
                        ));
                    }
                }
            }
        }

        let def = if let Some(sf) = svc_file.as_ref() {
            match fs::metadata(sf) {
                Ok(m) if m.len() > MAX_APP_CONFIG_BYTES => {
                    if let Some(old) = old_defs.get(app) {
                        defs.insert(app.to_string(), old.clone());
                        warnings.push(format!(
                            "auto_service_yml_too_large app={} file={} bytes={} limit_bytes={} kept_previous=true",
                            app,
                            sf.display(),
                            m.len(),
                            MAX_APP_CONFIG_BYTES
                        ));
                        outdated.push(app.to_string());
                    } else {
                        warnings.push(format!(
                            "auto_service_yml_too_large app={} file={} bytes={} limit_bytes={} kept_previous=false",
                            app,
                            sf.display(),
                            m.len(),
                            MAX_APP_CONFIG_BYTES
                        ));
                    }
                    continue;
                }
                _ => {
                    match fs::read_to_string(sf) {
                        Ok(raw) => match parse_app_definition_yaml(&raw, sf, Some(dir)) {
                            Ok(def) => {
                                if def.application != app {
                                    // Best-effort: treat as malconfigured; keep previous if any.
                                    if let Some(old) = old_defs.get(app) {
                                        defs.insert(app.to_string(), old.clone());
                                        warnings.push(format!(
                                            "auto_service_yml_app_mismatch app={} parsed_application={} file={} kept_previous=true",
                                            app,
                                            def.application,
                                            sf.display()
                                        ));
                                        outdated.push(app.to_string());
                                    } else {
                                        warnings.push(format!(
                                            "auto_service_yml_app_mismatch app={} parsed_application={} file={} kept_previous=false",
                                            app,
                                            def.application,
                                            sf.display()
                                        ));
                                    }
                                    continue;
                                }
                                def
                            }
                            Err(e) => {
                                if let Some(old) = old_defs.get(app) {
                                    defs.insert(app.to_string(), old.clone());
                                    warnings.push(format!(
                                        "auto_service_yml_parse_failed app={} file={} err={e} kept_previous=true",
                                        app,
                                        sf.display()
                                    ));
                                    outdated.push(app.to_string());
                                } else {
                                    warnings.push(format!(
                                        "auto_service_yml_parse_failed app={} file={} err={e} kept_previous=false",
                                        app,
                                        sf.display()
                                    ));
                                }
                                continue;
                            }
                        },
                        Err(e) => {
                            if let Some(old) = old_defs.get(app) {
                                defs.insert(app.to_string(), old.clone());
                                warnings.push(format!(
                                    "auto_service_yml_read_failed app={} file={} err={e} kept_previous=true",
                                    app,
                                    sf.display()
                                ));
                                outdated.push(app.to_string());
                            } else {
                                warnings.push(format!(
                                    "auto_service_yml_read_failed app={} file={} err={e} kept_previous=false",
                                    app,
                                    sf.display()
                                ));
                            }
                            continue;
                        }
                    }
                }
            }
        } else {
            // No service.yml: synthesize a default service AND (best-effort) auto-generate
            // a full `service.yml` for convenience.
            //
            // We only create the file if missing; we never overwrite.
            let target = path.join("service.yml");

            let yaml_text = match crate::pm::app::render_auto_service_yaml(app, &path) {
                Ok(s) => Some(s),
                Err(e) => {
                    warnings.push(format!(
                        "auto_service_generate_failed app={} file={} err={e}",
                        app,
                        target.display()
                    ));
                    None
                }
            };

            if let Some(yaml_text) = yaml_text {
                // Best-effort write: only if missing (no overwrite).
                if !target.exists() {
                    match std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&target)
                    {
                        Ok(mut f) => {
                            if let Err(e) = f.write_all(yaml_text.as_bytes()) {
                                warnings.push(format!(
                                    "auto_service_write_failed app={} file={} err={e}",
                                    app,
                                    target.display()
                                ));
                            } else {
                                warnings.push(format!(
                                    "auto_service_generated app={} file={}",
                                    app,
                                    target.display()
                                ));
                            }
                        }
                        Err(e) => {
                            // If another actor created it concurrently, that's fine.
                            if e.kind() != std::io::ErrorKind::AlreadyExists {
                                warnings.push(format!(
                                    "auto_service_write_failed app={} file={} err={e}",
                                    app,
                                    target.display()
                                ));
                            }
                        }
                    }
                }

                // Parse the generated YAML so runtime behavior matches the file.
                match parse_app_definition_yaml(&yaml_text, &target, Some(dir)) {
                    Ok(def) => def,
                    Err(e) => {
                        warnings.push(format!(
                            "auto_service_generated_parse_failed app={} file={} err={e}",
                            app,
                            target.display()
                        ));
                        build_auto_service_def(app, &path, target)?
                    }
                }
            } else {
                // Still load defaults in-memory if we couldn't generate YAML.
                build_auto_service_def(app, &path, target)?
            }
        };

        // Provisioning gate (auto services too): if provisioning is defined and marker is missing,
        // provisioning must succeed for the app to be loadable. If it fails, do NOT keep any old def;
        // the next reload will retry.
        if !def.provisioning.is_empty() {
            if let Err(e) = maybe_provision_workdir(&def) {
                let file_s = def
                    .source_file
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(none)".to_string());
                pm_event(
                    "provision",
                    Some(&def.application),
                    format!("decision=drop_load reason=provision_failed auto_service=true file={} err={e}", file_s),
                );
                warnings.push(format!(
                    "auto_service_provision_failed app={} file={} err={e}",
                    def.application, file_s
                ));
                continue;
            }
        }

        defs.insert(app.to_string(), def);
    }
    Ok(())
}

fn launcher_pids(cfg: &MasterConfig, app: &str) -> anyhow::Result<Vec<i32>> {
    let dir = app_cgroup_dir(cfg, app);
    let mut pids: Vec<i32> = cgroup::list_pids(&dir)?
        .into_iter()
        .filter_map(|p| i32::try_from(p).ok())
        .collect();
    pids.sort();
    pids.dedup();
    Ok(pids)
}

fn cgroup_running(cfg: &MasterConfig, app: &str) -> anyhow::Result<bool> {
    Ok(!launcher_pids(cfg, app)?.is_empty())
}

async fn cgroup_running_async(cfg: &MasterConfig, app: &str) -> anyhow::Result<bool> {
    let dir = app_cgroup_dir(cfg, app);
    Ok(!cgroup::list_pids_async(&dir).await?.is_empty())
}

fn launcher_kill_signal(cfg: &MasterConfig, app: &str, sig: &str) -> anyhow::Result<()> {
    let s = parse_signal(sig)?;
    let dir = app_cgroup_dir(cfg, app);
    let _count = cgroup::kill_with_signal(&dir, Some(s))?;
    Ok(())
}

fn launcher_kill_all(cfg: &MasterConfig, app: &str) -> anyhow::Result<()> {
    let dir = app_cgroup_dir(cfg, app);
    cgroup::kill_all_pids(&dir)?;
    Ok(())
}

fn enforce_app_user_group_rules(def: &AppDefinition) -> anyhow::Result<()> {
    if geteuid().is_root() {
        return Ok(());
    }
    let euid = geteuid();
    let egid = getegid();
    let cur_user = get_user_by_uid(euid.as_raw())
        .map(|u| u.name().to_string_lossy().to_string())
        .unwrap_or_else(|| euid.as_raw().to_string());
    let cur_group = get_group_by_gid(egid.as_raw())
        .map(|g| g.name().to_string_lossy().to_string())
        .unwrap_or_else(|| egid.as_raw().to_string());

    if let Some(u) = def.user.as_deref() {
        if u != cur_user {
            anyhow::bail!(
                "service {} requests user={u}, but pm is running as non-root {cur_user}:{cur_group}",
                def.application
            );
        }
    }
    if let Some(g) = def.group.as_deref() {
        if g != cur_group {
            anyhow::bail!(
                "service {} requests group={g}, but pm is running as non-root {cur_user}:{cur_group}",
                def.application
            );
        }
    }
    Ok(())
}



