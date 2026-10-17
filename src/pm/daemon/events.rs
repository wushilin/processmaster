//! The daemon's event stream: the in-memory ring shown by `pmctl events`, and the
//! daemon's own rotated log file.

use super::*;

// Daemon log file defaults (independent of per-app stdout/stderr logs).
pub(super) const DAEMON_LOG_NAME: &str = "processmaster";
pub(super) const DAEMON_LOG_MAX_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB
pub(super) const DAEMON_LOG_BACKUPS: usize = 10;

pub(super) static DAEMON_LOG_TX: OnceLock<tokio_mpsc::UnboundedSender<String>> = OnceLock::new();
pub(super) static EARLY_DAEMON_LOG: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();
pub(super) const EARLY_DAEMON_LOG_MAX_LINES: usize = 5000;

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

pub(super) fn pm_event_state(state: &Arc<Mutex<DaemonState>>, component: &str, app: Option<&str>, msg: impl AsRef<str>) {
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

pub(super) fn push_event(events: &Arc<Mutex<VecDeque<EventEntry>>>, component: &str, app: Option<&str>, msg: impl AsRef<str>) {
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

pub(super) fn start_daemon_log_file(cfg: &MasterConfig) {
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
        let log = match pin_log(&base_path, true) {
            Ok(l) => l,
            Err(e) => {
                eprintln!(
                    "{} [log] failed to open daemon log directory for {} err={e:#}",
                    Local::now().format("%Y-%m-%d_%H:%M:%S%.3f"),
                    base_path.display()
                );
                return;
            }
        };
        let base_path = log.base.clone();
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
                        maybe_compress_rotated_best_effort(DAEMON_LOG_NAME, true, &log.dir, rotated);
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
                        maybe_compress_rotated_best_effort(DAEMON_LOG_NAME, true, &log.dir, rotated);
                    }
                    f = rr.f;
                    bytes_written = 0;
                }
            }
        }
    });
}
