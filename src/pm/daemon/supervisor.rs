//! The per-service supervisor: one task per service that owns its lifecycle, fed by a
//! command queue, plus the waiters that report when its processes exit.

use super::*;

pub(super) const RESTARTS_WINDOW_MS: i64 = 10 * 60 * 1000; // 10 minutes

pub(super) fn record_started_in_store(
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

pub(super) fn record_start_attempt_in_store(run_info: &Arc<Mutex<HashMap<String, RunInfo>>>, name: &str) {
    let now = Local::now().timestamp_millis();
    let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
    let e = ri.entry(name.to_string()).or_default();
    e.last_start_attempt_ms = Some(now);
}

pub(super) fn record_system_crash_in_store(run_info: &Arc<Mutex<HashMap<String, RunInfo>>>, name: &str) {
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

pub(super) fn record_cron_failed_start_in_store(
    run_info: &Arc<Mutex<HashMap<String, RunInfo>>>,
    events: &Arc<Mutex<VecDeque<EventEntry>>>,
    name: &str,
    reason: &str,
    err: &str,
    code: i32,
) {
    // Cron jobs have no restart/backoff semantics, but we still want clear visibility in UI:
    // - `last_exit_code` populated
    // - `exit_err` flag set (mutually exclusive with `exit_ok` via flag rules)
    // - crash recorded (for recent crash counters/telemetry)
    {
        let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
        let e = ri.entry(name.to_string()).or_default();
        e.last_exit_code = Some(code);
        sysflag_set_with_rules(name, &mut e.system_flags, SystemFlag::ExitErr, None);
    }
    record_system_crash_in_store(run_info, name);
    push_event(
        events,
        "schedule",
        Some(name),
        format!("event=start_failed reason={reason} code={code} err={err}"),
    );
    // Cron jobs return to stopped between runs.
    set_phase_and_emit(run_info, events, name, Phase::Stopped, reason);
}

pub(super) fn set_phase_and_emit(
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

/// Sends one command to a service's supervisor and waits for its verdict.
pub(super) async fn ask_supervisor(
    state: &Arc<Mutex<DaemonState>>,
    name: &str,
    cmd: impl FnOnce(oneshot::Sender<anyhow::Result<()>>) -> SupervisorCmd,
) -> anyhow::Result<()> {
    let tx = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        st.supervisors.get(name).map(|h| h.tx.clone())
    }
    .ok_or_else(|| anyhow::anyhow!("no controller for service: {name}"))?;
    let (resp_tx, resp_rx) = oneshot::channel();
    let gone = || anyhow::anyhow!("supervisor for {name} is not running (see events; `pmctl update` replaces it)");
    tx.send(cmd(resp_tx)).map_err(|_| gone())?;
    resp_rx.await.map_err(|_| gone())?
}

pub(super) async fn manual_start_via_supervisor_async(state: &Arc<Mutex<DaemonState>>, name: &str, force: bool) -> anyhow::Result<()> {
    ask_supervisor(state, name, |resp| SupervisorCmd::ManualStart { force, resp }).await
}

pub(super) async fn manual_stop_via_supervisor_async(state: &Arc<Mutex<DaemonState>>, name: &str) -> anyhow::Result<()> {
    ask_supervisor(state, name, |resp| SupervisorCmd::ManualStop { resp }).await
}

pub(super) async fn manual_restart_via_supervisor_async(state: &Arc<Mutex<DaemonState>>, name: &str, force: bool) -> anyhow::Result<()> {
    ask_supervisor(state, name, |resp| SupervisorCmd::ManualRestart { force, resp }).await
}

pub(super) async fn reload_start_via_supervisor_async(state: &Arc<Mutex<DaemonState>>, name: &str, force: bool) -> anyhow::Result<()> {
    ask_supervisor(state, name, |resp| SupervisorCmd::ReloadStart { force, resp }).await
}

pub(super) async fn reload_restart_via_supervisor_async(state: &Arc<Mutex<DaemonState>>, name: &str, force: bool) -> anyhow::Result<()> {
    ask_supervisor(state, name, |resp| SupervisorCmd::ReloadRestart { force, resp }).await
}

pub(super) async fn boot_start_via_supervisor_async(state: &Arc<Mutex<DaemonState>>, name: &str) -> anyhow::Result<()> {
    ask_supervisor(state, name, |resp| SupervisorCmd::BootStart { resp }).await
}

pub(super) async fn scheduled_start_via_supervisor_async(state: &Arc<Mutex<DaemonState>>, name: &str) -> anyhow::Result<()> {
    ask_supervisor(state, name, |resp| SupervisorCmd::ScheduledStart { resp }).await
}

pub(super) async fn shutdown_stop_via_supervisor_async(state: &Arc<Mutex<DaemonState>>, name: &str) -> anyhow::Result<()> {
    ask_supervisor(state, name, |resp| SupervisorCmd::ShutdownStop { resp }).await
}

pub(super) async fn overtime_stop_via_supervisor_async(state: &Arc<Mutex<DaemonState>>, name: &str) -> anyhow::Result<()> {
    ask_supervisor(state, name, |resp| SupervisorCmd::OverTimeStop { resp }).await
}

pub(super) fn refresh_supervisors(state: &Arc<Mutex<DaemonState>>) -> anyhow::Result<()> {
    let (cfg, defs, existing, shutting_down) = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
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
                let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
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
        let cg_dir = cgroup::app_dir(&cfg, &name);
        if let Err(e) = fs::create_dir_all(&cg_dir) {
            // If we can't create the cgroup dir, we can still keep the daemon running;
            // starts/stops for this app will fail later and should be visible to operators.
            let (events, ) = {
                let st = state.lock().unwrap_or_else(|p| p.into_inner());
                (Arc::clone(&st.events),)
            };
            push_event(&events, "cgroup", Some(&name), format!("ensure_dir_failed dir={} err={e}", cg_dir.display()));
        }

        // Validate restart policy is parseable (supported: never|always) if present.
        if let Some(restart) = def.restart.as_ref() {
            let _policy = restart.policy.parsed()?;
        }

        let tx_opt = {
            let st = state.lock().unwrap_or_else(|p| p.into_inner());
            st.supervisors.get(&name).map(|h| h.tx.clone())
        };
        if let Some(tx) = tx_opt {
            if tx.send(SupervisorCmd::Update { def: Box::new(def.clone()) }).is_ok() {
                continue;
            }
            // Its task is gone (see spawn_supervisor_thread): replace it, or the
            // service stays unmanaged.
            pm_event("supervisor", Some(&name), "respawn reason=task_gone");
        }
        // Enable controllers for children of this app cgroup so nested cgroup trees work
        // (e.g. nested processmaster, or apps that create their own sub-cgroups).
        if cfg.cgroup_subtree_control_allow
            && let Err(e) = enable_all_subtree_controllers(&cg_dir) {
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

        let (run_info, events) = {
            let st = state.lock().unwrap_or_else(|p| p.into_inner());
            (Arc::clone(&st.run_info), Arc::clone(&st.events))
        };
        pm_event("supervisor", Some(&name), "spawn");
        let handle = spawn_supervisor_thread(cfg.clone(), def.clone(), run_info, events, Arc::clone(&shutting_down));
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        st.supervisors.insert(name.clone(), handle);
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub(super) struct SupervisorHandle {
    tx: tokio_mpsc::UnboundedSender<SupervisorCmd>,
}

pub(super) enum SupervisorCmd {
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
    /// Start due to a service definition reload (system-triggered). Behaves like manual start
    /// (clears suppression/history) but records `system_start` as the reason flag.
    ReloadStart {
        force: bool,
        resp: oneshot::Sender<anyhow::Result<()>>,
    },
    /// Restart due to a service definition reload (system-triggered). Behaves like manual restart
    /// but records `system_start` as the reason flag.
    ReloadRestart {
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
        def: Box<AppDefinition>,
    },
    WaiterExited {
        epoch: u64,
        code: Option<i32>,
    },
    /// The cgroup waiter could not determine liveness (I/O error, fd exhaustion).
    /// Distinct from `WaiterExited` on purpose: "I could not look" is not "it exited".
    WaiterFailed {
        epoch: u64,
    },
    Shutdown,
}

/// Spawns the supervisor task for one service and returns the handle that feeds it.
pub(super) fn spawn_supervisor_thread(
    cfg: MasterConfig,
    def: AppDefinition,
    run_info: Arc<Mutex<HashMap<String, RunInfo>>>,
    events: Arc<Mutex<VecDeque<EventEntry>>>,
    shutting_down: Arc<AtomicBool>,
) -> SupervisorHandle {
    let (tx, rx) = tokio_mpsc::unbounded_channel::<SupervisorCmd>();
    let sup = Supervisor {
        app: def.application.clone(),
        cfg,
        def,
        run_info,
        events,
        tx_self: tx.clone(),
        restart_times: VecDeque::new(),
        waiter_running: false,
        waiter_epoch: 0,
        waiter_cancel: None,
        pending_failure_restart_at: None,
    };
    let app = sup.app.clone();
    let task = tasks().spawn(sup.run(rx, shutting_down));
    // A supervisor only ends on shutdown or removal. If it panics instead, the service
    // keeps running with nobody watching it and commands fail with a closed channel;
    // say so loudly. `pmctl update` replaces it (see refresh_supervisors).
    tasks().spawn(async move {
        if task.await.is_err_and(|e| e.is_panic()) {
            pm_event(
                "supervisor",
                Some(&app),
                "outcome=panicked service=unsupervised action=run `pmctl update` to replace the supervisor",
            );
        }
    });
    SupervisorHandle { tx }
}

/// Owns one service's lifecycle. Commands are handled one at a time, so nothing else
/// ever starts, stops or restarts the service concurrently with it.
///
/// No separate "desired" state: operator intent is represented via system flags.
struct Supervisor {
    cfg: MasterConfig,
    def: AppDefinition,
    app: String,
    run_info: Arc<Mutex<HashMap<String, RunInfo>>>,
    events: Arc<Mutex<VecDeque<EventEntry>>>,
    /// For handing to waiters, which report back through the same queue.
    tx_self: tokio_mpsc::UnboundedSender<SupervisorCmd>,
    /// Automatic restarts inside the current tolerance window.
    restart_times: VecDeque<Instant>,
    waiter_running: bool,
    /// Bumped whenever the current waiter is replaced or abandoned; a waiter's report
    /// carrying an older epoch is stale and ignored.
    waiter_epoch: u64,
    waiter_cancel: Option<WaiterCancel>,
    /// When set, a `FailureAutoRestart` fires at this instant (BACKOFF).
    pending_failure_restart_at: Option<Instant>,
}

/// Bounded wait for a fresh start to show up in the service's cgroup.
const START_WINDOW: Duration = Duration::from_secs(3);

impl Supervisor {
    async fn run(mut self, mut rx: tokio_mpsc::UnboundedReceiver<SupervisorCmd>, shutting_down: Arc<AtomicBool>) {
        // If the app is already running before processmaster starts, attach a waiter so we can detect exits.
        self.ensure_waiter_attached(false).await;

        loop {
            if shutting_down.load(Ordering::Relaxed) {
                push_event(&self.events, "shutdown", Some(&self.app), "supervisor=exit reason=shutting_down");
                break;
            }
            // Wait for next command, or fire pending FailureAutoRestart when due.
            let cmd = if let Some(at) = self.pending_failure_restart_at {
                let timeout = at.saturating_duration_since(Instant::now());
                tokio::select! {
                    cmd = rx.recv() => cmd,
                    _ = tokio_time::sleep(timeout) => {
                        self.pending_failure_restart_at = None;
                        Some(SupervisorCmd::FailureAutoRestart)
                    },
                }
            } else {
                rx.recv().await
            };
            // Channel closed: supervisor should exit.
            let Some(cmd) = cmd else { break };

            match cmd {
                SupervisorCmd::Update { def } => self.def = *def,
                SupervisorCmd::ReloadStart { force, resp } => {
                    let _ = resp.send(self.reload_start(force).await);
                }
                SupervisorCmd::ManualStart { force, resp } => {
                    let _ = resp.send(self.manual_start(force).await);
                }
                SupervisorCmd::ManualStop { resp } => {
                    let _ = resp.send(self.manual_stop().await);
                }
                SupervisorCmd::ShutdownStop { resp } => {
                    let _ = resp.send(self.shutdown_stop().await);
                }
                SupervisorCmd::OverTimeStop { resp } => {
                    let _ = resp.send(self.overtime_stop().await);
                }
                SupervisorCmd::ManualRestart { force, resp } => {
                    let _ = resp.send(self.manual_restart(force).await);
                }
                SupervisorCmd::ReloadRestart { force, resp } => {
                    let _ = resp.send(self.reload_restart(force).await);
                }
                SupervisorCmd::BootStart { resp } => {
                    let _ = resp.send(self.boot_start().await);
                }
                SupervisorCmd::ScheduledStart { resp } => {
                    let _ = resp.send(self.scheduled_start().await);
                }
                SupervisorCmd::FailureAutoRestart => self.failure_auto_restart().await,
                SupervisorCmd::WaiterFailed { epoch } => self.waiter_failed(epoch),
                SupervisorCmd::WaiterExited { epoch, code } => self.waiter_exited(epoch, code),
                SupervisorCmd::Shutdown => break,
            }
        }
    }

    // ---- commands ------------------------------------------------------------------

    async fn reload_start(&mut self, force: bool) -> anyhow::Result<()> {
        let app = self.app.clone();
        // Track "last start attempt" for reload starts too.
        record_start_attempt_in_store(&self.run_info, &app);
        // Reload start should behave like a manual intervention: clear suppression/history.
        self.restart_times.clear();
        self.pending_failure_restart_at = None;

        if !force && !self.def.enabled {
            anyhow::bail!("service {app} is disabled");
        }
        if self.def.schedule.is_some() {
            anyhow::bail!("{app}: scheduled jobs do not support reload start");
        }

        // If already running, do not change markers (same as manual start).
        if cgroup_running_or_assume_running(&self.cfg, &app).await {
            self.ensure_waiter_attached(false).await;
            return Ok(());
        }

        // Not running: clear crash history, and start now.
        self.update_info(|e| e.recent_system_crashes_ms.clear());

        self.set_phase(Phase::Starting, "reload_start");
        disown_service_child(self.spawn_child().await??);

        if !self.wait_for_cgroup_nonempty().await {
            anyhow::bail!(self.handle_exit_during_start("reload_start"));
        }
        record_started_in_store(&self.run_info, &app, StartKind::Start, SystemFlag::SystemStart);
        self.ensure_waiter_attached(true).await;
        self.set_phase(Phase::Running, "reload_start_completed");
        Ok(())
    }

    async fn manual_start(&mut self, force: bool) -> anyhow::Result<()> {
        let app = self.app.clone();
        // Track "last start attempt" for any accepted start command (even if already running).
        record_start_attempt_in_store(&self.run_info, &app);
        // Manual start clears FAILED/BACKOFF suppression.
        self.restart_times.clear();
        self.pending_failure_restart_at = None;

        if !force && !self.def.enabled {
            anyhow::bail!("service {app} is disabled");
        }

        // If already running, just ensure waiter and return OK.
        if cgroup_running_or_assume_running(&self.cfg, &app).await {
            // No-op: starting an already running service should not change intent markers or other flags.
            self.ensure_waiter_attached(false).await;
            return Ok(());
        }

        // Not running: this manual start will actually start it, so mark operator intent.
        // Clear crash history on accepted manual start attempts.
        self.update_info(|e| e.recent_system_crashes_ms.clear());

        self.set_phase(Phase::Starting, "manual_start");
        let child_r = self.spawn_child().await?;
        if self.def.schedule.is_some() {
            // For scheduled jobs, we want a real exit code. Attach a process waiter to the spawned child.
            // This replaces the cgroup-only waiter (which cannot provide an exit status).
            let child = match child_r {
                Ok(c) => c,
                Err(e) => {
                    record_cron_failed_start_in_store(
                        &self.run_info,
                        &self.events,
                        &app,
                        "manual_start_spawn_error",
                        &e.to_string(),
                        1,
                    );
                    return Err(e);
                }
            };
            self.attach_process_waiter(child).await;
        } else {
            disown_service_child(child_r?);
        }

        if !self.wait_for_cgroup_nonempty().await {
            if self.def.schedule.is_some() {
                // NOTE: cron jobs may start+exit too quickly for the cgroup poll loop to observe
                // a non-empty cgroup (50ms polling). We already attached a process waiter above,
                // so do NOT mark exit_err here; let the actual exit code decide.
                push_event(&self.events, "schedule", Some(&app), "event=start_timeout scope=cron detail=cgroup_stayed_empty");
                self.set_phase(Phase::Stopped, "manual_start_timeout");
                anyhow::bail!("{app}: start timeout (cgroup stayed empty)");
            }
            anyhow::bail!(self.handle_exit_during_start("manual_start"));
        }
        record_started_in_store(&self.run_info, &app, StartKind::Start, SYSFLAG_USER_START);
        if self.def.schedule.is_none() {
            self.ensure_waiter_attached(true).await;
        }
        self.set_phase(Phase::Running, "manual_start_completed");
        Ok(())
    }

    async fn manual_stop(&mut self) -> anyhow::Result<()> {
        let app = self.app.clone();
        // If already stopped, do NOT update markers OR clear FAILED/BACKOFF/history.
        // "Stop" should be a no-op if nothing is running; keeping FAILED makes sense for failed/stopped services.
        if !cgroup_running_or_assume_running(&self.cfg, &app).await {
            // Nothing running -- but a restart may be scheduled (BACKOFF). A stop
            // must cancel it, or the service comes back after the operator
            // stopped it.
            if self.pending_failure_restart_at.take().is_some() {
                self.restart_times.clear();
                self.update_info(|e| {
                    sysflag_clear(&mut e.system_flags, SystemFlag::Backoff);
                    sysflag_set_with_rules(&app, &mut e.system_flags, SYSFLAG_USER_STOP, None);
                });
            }
            self.set_phase(Phase::Stopped, "stop_noop_already_stopped");
            return Ok(());
        }

        // Now we know it's actually running: manual stop is a real intervention.
        // Clear pending auto-restart state and failure suppression/history.
        self.restart_times.clear();
        self.pending_failure_restart_at = None;
        self.update_info(|e| e.recent_system_crashes_ms.clear());

        // The app is actually running: now apply operator intent markers.
        // Manual stop: persist operator intent marker, including for cron jobs (it will clear on next start).
        self.update_info(|e| sysflag_set_with_rules(&app, &mut e.system_flags, SYSFLAG_USER_STOP, None));

        self.set_phase(Phase::Stopping, "stop_requested");
        match self.exec_stop().await {
            Ok(_) => {
                self.set_phase(Phase::Stopped, "stop_completed");
                Ok(())
            }
            Err(e) => {
                // If the stop failed, revert the operator "stopped-by-user" marker.
                // We set it pre-stop to avoid auto-restart races when the exit is observed,
                // but if we didn't actually stop the service we must not leave a stale marker behind.
                let mut ri = self.run_info.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(entry) = ri.get_mut(&app) {
                    sysflag_clear(&mut entry.system_flags, SYSFLAG_USER_STOP);
                }
                Err(e)
            }
        }
    }

    async fn shutdown_stop(&mut self) -> anyhow::Result<()> {
        // System stop should not persist operator intent.
        // A restart scheduled during backoff must not fire mid-shutdown.
        self.pending_failure_restart_at = None;
        if !cgroup_running_or_assume_running(&self.cfg, &self.app).await {
            self.set_phase(Phase::Stopped, "stop_noop_already_stopped");
            return Ok(());
        }
        self.set_phase(Phase::Stopping, "stop_requested");
        self.exec_stop().await?;
        self.set_phase(Phase::Stopped, "stop_completed");
        Ok(())
    }

    async fn overtime_stop(&mut self) -> anyhow::Result<()> {
        // Overtime stop should not persist operator intent, but does set an informational sysflag for cron jobs.
        if !cgroup_running_or_assume_running(&self.cfg, &self.app).await {
            self.set_phase(Phase::Stopped, "stop_noop_already_stopped");
            return Ok(());
        }
        self.set_phase(Phase::Stopping, "stop_requested");
        self.exec_stop().await?;
        if self.def.schedule.is_some() {
            self.update_info(|e| sysflag_set(&mut e.system_flags, SYSFLAG_OT_KILLED, None));
        }
        self.set_phase(Phase::Stopped, "stop_completed");
        Ok(())
    }

    async fn manual_restart(&mut self, force: bool) -> anyhow::Result<()> {
        let app = self.app.clone();
        // Track "last start attempt" for restart requests (even if already running later).
        record_start_attempt_in_store(&self.run_info, &app);
        // Manual restart clears FAILED/BACKOFF suppression.
        self.restart_times.clear();
        self.pending_failure_restart_at = None;
        if !force && !self.def.enabled {
            anyhow::bail!("service {app} is disabled");
        }
        self.update_info(|e| e.recent_system_crashes_ms.clear());
        // Stop step
        if cgroup_running_or_assume_running(&self.cfg, &app).await {
            // IMPORTANT: during manual restart we intentionally stop the cgroup.
            // The existing waiter is "wait until cgroup empty" and would report this as an exit event,
            // which can race and be interpreted as a crash after restart. Invalidate it before stopping.
            self.detach_waiter();
            self.set_phase(Phase::Stopping, "manual_restart_stop");
            if let Err(e) = self.exec_stop().await {
                self.set_phase(Phase::Failed, "manual_restart_stop_error");
                return Err(e);
            }
        }
        // Start step
        if cgroup_running_or_assume_running(&self.cfg, &app).await {
            self.ensure_waiter_attached(false).await;
            return Ok(());
        }
        self.set_phase(Phase::Restarting, "manual_restart_start");
        let child = self.spawn_child().await??;
        if self.def.schedule.is_some() {
            self.attach_process_waiter(child).await;
        } else {
            disown_service_child(child);
        }
        if !self.wait_for_cgroup_nonempty().await {
            anyhow::bail!(self.handle_exit_during_start("manual_restart"));
        }
        record_started_in_store(&self.run_info, &app, StartKind::Restart, SYSFLAG_USER_START);
        if self.def.schedule.is_none() {
            self.ensure_waiter_attached(true).await;
        }
        // After a successful manual restart:
        // - clear FAILED (operator intervened)
        // - clear restart history used for tolerance/backoff decisions
        self.restart_times.clear();
        self.pending_failure_restart_at = None;
        self.update_info(|e| e.recent_system_crashes_ms.clear());
        self.set_phase(Phase::Running, "manual_restart_completed");
        Ok(())
    }

    async fn reload_restart(&mut self, force: bool) -> anyhow::Result<()> {
        let app = self.app.clone();
        // Similar to manual restart, but records `system_start` as the reason flag.
        record_start_attempt_in_store(&self.run_info, &app);
        self.restart_times.clear();
        self.pending_failure_restart_at = None;
        if !force && !self.def.enabled {
            anyhow::bail!("service {app} is disabled");
        }
        if self.def.schedule.is_some() {
            anyhow::bail!("{app}: scheduled jobs do not support reload restart");
        }
        self.update_info(|e| e.recent_system_crashes_ms.clear());
        // Stop step (same invalidation as manual restart).
        if cgroup_running_or_assume_running(&self.cfg, &app).await {
            self.detach_waiter();
            self.set_phase(Phase::Stopping, "reload_restart_stop");
            if let Err(e) = self.exec_stop().await {
                self.set_phase(Phase::Failed, "reload_restart_stop_error");
                return Err(e);
            }
        }
        // Start step
        if cgroup_running_or_assume_running(&self.cfg, &app).await {
            self.ensure_waiter_attached(false).await;
            record_started_in_store(&self.run_info, &app, StartKind::Restart, SystemFlag::SystemStart);
            self.set_phase(Phase::Running, "reload_restart_completed");
            return Ok(());
        }
        self.set_phase(Phase::Starting, "reload_restart_start");
        disown_service_child(self.spawn_child().await??);
        if !self.wait_for_cgroup_nonempty().await {
            anyhow::bail!(self.handle_exit_during_start("reload_restart"));
        }
        record_started_in_store(&self.run_info, &app, StartKind::Restart, SystemFlag::SystemStart);
        self.ensure_waiter_attached(true).await;
        self.set_phase(Phase::Running, "reload_restart_completed");
        Ok(())
    }

    async fn boot_start(&mut self) -> anyhow::Result<()> {
        let app = self.app.clone();
        // Track start attempt for boot starts too.
        record_start_attempt_in_store(&self.run_info, &app);
        // Boot start is a system action: do not clear FAILED; if FAILED is set, skip.
        if !self.def.enabled || self.def.schedule.is_some() {
            return Ok(());
        }
        let info = self.info();
        if sysflag_has(&info.system_flags, SystemFlag::Failed) {
            anyhow::bail!("{app}: failed (manual intervention required)");
        }
        if sysflag_has(&info.system_flags, SYSFLAG_USER_STOP) {
            anyhow::bail!("{app}: stopped by user");
        }
        // A restart is already scheduled (e.g. a reload start just exited and
        // backed off): starting again now would skip the backoff and burn a
        // second tolerance slot.
        if self.pending_failure_restart_at.is_some() {
            return Ok(());
        }
        if cgroup_running_or_assume_running(&self.cfg, &app).await {
            self.ensure_waiter_attached(false).await;
            return Ok(());
        }
        self.set_phase(Phase::Starting, "boot_start");
        disown_service_child(self.spawn_child().await??);
        if !self.wait_for_cgroup_nonempty().await {
            anyhow::bail!(self.handle_exit_during_start("boot_start"));
        }
        record_started_in_store(&self.run_info, &app, StartKind::Start, SystemFlag::SystemStart);
        self.ensure_waiter_attached(true).await;
        self.set_phase(Phase::Running, "boot_start_completed");
        Ok(())
    }

    async fn scheduled_start(&mut self) -> anyhow::Result<()> {
        let app = self.app.clone();
        // Track last start attempt for scheduled triggers too.
        record_start_attempt_in_store(&self.run_info, &app);
        // Scheduled start is only meaningful for scheduled jobs.
        if self.def.schedule.is_none() {
            anyhow::bail!("{app}: not a scheduled job");
        }
        if !self.def.enabled {
            anyhow::bail!("{app}: disabled");
        }
        if cgroup_running_or_assume_running(&self.cfg, &app).await {
            self.ensure_waiter_attached(false).await;
            return Ok(());
        }
        self.set_phase(Phase::Starting, "scheduled_start");
        let child = match self.spawn_child().await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) | Err(e) => {
                let reason = if e.is::<tokio::task::JoinError>() { "scheduled_start_join_error" } else { "scheduled_start_spawn_error" };
                record_cron_failed_start_in_store(&self.run_info, &self.events, &app, reason, &e.to_string(), 1);
                return Err(e);
            }
        };
        // For scheduled jobs, attach a process waiter to capture the real exit code (0 vs non-0).
        // The cgroup-only waiter cannot provide an exit status and would report code=None.
        self.attach_process_waiter(child).await;
        if !self.wait_for_cgroup_nonempty().await {
            // Same reasoning as manual_start_timeout: don't guess failure for cron jobs here.
            push_event(&self.events, "schedule", Some(&app), "event=start_timeout scope=cron detail=cgroup_stayed_empty");
            self.set_phase(Phase::Stopped, "scheduled_start_timeout");
            anyhow::bail!("{app}: start timeout (cgroup stayed empty)");
        }
        record_started_in_store(&self.run_info, &app, StartKind::Start, SystemFlag::SystemStart);
        self.set_phase(Phase::Running, "scheduled_start_completed");
        Ok(())
    }

    /// Auto restart attempt after a failure/backoff window.
    async fn failure_auto_restart(&mut self) {
        let app = self.app.clone();
        // Track last start attempt for auto-restart attempts too.
        record_start_attempt_in_store(&self.run_info, &app);
        if !self.def.enabled || self.def.schedule.is_some() {
            return;
        }
        // Restart config defaults to "always" with tolerance 3 restarts / 3 minutes.
        // Treat missing restart config as the default (so we don't immediately become FAILED).
        let restart = self.def.restart.clone().unwrap_or_default();
        let info = self.info();
        if sysflag_has(&info.system_flags, SYSFLAG_USER_STOP) {
            self.set_phase(Phase::Stopped, "failure_auto_restart_stopped_by_user");
            return;
        }
        // Respect FAILED: it permanently disables auto restart until manual intervention.
        if sysflag_has(&info.system_flags, SystemFlag::Failed) {
            self.set_phase(Phase::Failed, "failure_auto_restart_failed_flag_set");
            return;
        }
        if cgroup_running_or_assume_running(&self.cfg, &app).await {
            // Already running again; just ensure waiter.
            self.ensure_waiter_attached(false).await;
            return;
        }

        self.set_phase(Phase::Restarting, "failure_auto_restart");
        let spawn_err = match self.spawn_child().await {
            Ok(Ok(child)) => {
                disown_service_child(child);
                None
            }
            Ok(Err(e)) | Err(e) => Some(e),
        };
        // A failed attempt counts against the tolerance like any other restart: do NOT
        // immediately mark FAILED; only do so once the tolerance is exceeded.
        if let Some(e) = spawn_err {
            if self.count_restart(&restart) {
                push_event(
                    &self.events,
                    "restart",
                    Some(&app),
                    format!(
                        "decision=suppress reason=tolerance_exceeded outcome=spawn_error max_restarts={} window_ms={} err={e}",
                        restart.tolerance.max_restarts, restart.tolerance.duration
                    ),
                );
                self.mark_failed("failure_auto_restart_tolerance_exceeded_spawn_error");
            } else {
                push_event(
                    &self.events,
                    "restart",
                    Some(&app),
                    format!(
                        "decision=backoff outcome=spawn_error backoff_ms={} recent_restarts_in_window={} err={e}",
                        restart.restart_backoff_ms,
                        self.restart_times.len()
                    ),
                );
                self.enter_backoff(restart.restart_backoff_ms, "failure_auto_restart_spawn_error_backoff");
            }
            return;
        }

        if !self.wait_for_cgroup_nonempty().await {
            if self.count_restart(&restart) {
                push_event(
                    &self.events,
                    "restart",
                    Some(&app),
                    format!(
                        "decision=suppress reason=tolerance_exceeded outcome=start_timeout max_restarts={} window_ms={} cgroup_empty_after_ms=3000",
                        restart.tolerance.max_restarts, restart.tolerance.duration
                    ),
                );
                self.mark_failed("failure_auto_restart_tolerance_exceeded_timeout");
            } else {
                push_event(
                    &self.events,
                    "restart",
                    Some(&app),
                    format!(
                        "decision=backoff outcome=start_timeout backoff_ms={} recent_restarts_in_window={} cgroup_empty_after_ms=3000",
                        restart.restart_backoff_ms,
                        self.restart_times.len()
                    ),
                );
                self.enter_backoff(restart.restart_backoff_ms, "failure_auto_restart_timeout_backoff");
            }
            return;
        }

        record_started_in_store(&self.run_info, &app, StartKind::Restart, SystemFlag::SystemStart);
        self.ensure_waiter_attached(true).await;
        self.set_phase(Phase::Running, "failure_auto_restart_completed");
    }

    fn waiter_failed(&mut self, epoch: u64) {
        if epoch != self.waiter_epoch {
            return;
        }
        // Drop the waiter but record nothing: no exit code, no crash, no
        // restart. The periodic reconcile will re-observe real state from
        // the cgroup and re-attach a waiter if the service is still up.
        self.waiter_running = false;
        self.waiter_cancel = None;
        push_event(&self.events, "watch", Some(&self.app), "event=waiter_failed action=detached (state unchanged)");
    }

    fn waiter_exited(&mut self, epoch: u64, code: Option<i32>) {
        let app = self.app.clone();
        if epoch != self.waiter_epoch {
            push_event(
                &self.events,
                "watch",
                Some(&app),
                format!("ignore_exit reason=stale_epoch got={epoch} want={}", self.waiter_epoch),
            );
            return;
        }
        self.waiter_running = false;
        self.waiter_cancel = None;
        self.update_info(|e| e.last_exit_code = code);
        push_event(&self.events, "watch", Some(&app), format!("event=exit_observed code={}", code.unwrap_or(-1)));

        // Scheduled jobs: return to SCHEDULED after exit; no auto-restart.
        if self.def.schedule.is_some() {
            let c = code.unwrap_or(1);
            if c != 0 {
                record_system_crash_in_store(&self.run_info, &app);
            }
            // Cron exit outcome flags (mutually exclusive via flag rules).
            let flag = if c == 0 { SystemFlag::ExitOk } else { SystemFlag::ExitErr };
            self.update_info(|e| sysflag_set_with_rules(&app, &mut e.system_flags, flag, None));
            // Do not clear sysflags for cron jobs on exit. Cron has no auto-restart/backoff semantics,
            // and flags like `ot_killed` should remain visible until the next run clears them.
            self.set_phase(Phase::Stopped, "scheduled_completed");
            return;
        }

        // Services: decide whether to auto-restart.
        // If disabled, or stopped by user, just mark stopped.
        let info = self.info();
        if !self.def.enabled {
            self.set_phase(Phase::Stopped, "exit_observed_disabled");
            return;
        }
        if sysflag_has(&info.system_flags, SYSFLAG_USER_STOP) {
            self.set_phase(Phase::Stopped, "exit_observed_stopped_by_user");
            return;
        }

        // FAILED permanently disables auto restart until manual intervention.
        if sysflag_has(&info.system_flags, SystemFlag::Failed) {
            self.set_phase(Phase::Failed, "failed_flag_set");
            return;
        }

        record_system_crash_in_store(&self.run_info, &app);

        // Restart config defaults to "always" with tolerance 3 restarts / 3 minutes.
        // Treat missing restart config as the default (so the first crash doesn't immediately become FAILED).
        let restart = self.def.restart.clone().unwrap_or_default();

        let policy = match restart.policy.parsed() {
            Ok(p) => p,
            Err(e) => {
                push_event(&self.events, "restart", Some(&app), format!("decision=skip reason=policy_parse_error err={e}"));
                self.mark_failed("restart_policy_parse_error");
                return;
            }
        };

        match policy {
            RestartPolicyParsed::Never => self.mark_failed("exit_policy_never"),
            RestartPolicyParsed::Always => {
                // Restart tolerance window (count this restart attempt).
                if self.count_restart(&restart) {
                    push_event(
                        &self.events,
                        "restart",
                        Some(&app),
                        format!(
                            "decision=suppress reason=tolerance_exceeded max_restarts={} window_ms={}",
                            restart.tolerance.max_restarts, restart.tolerance.duration
                        ),
                    );
                    self.mark_failed("tolerance_exceeded");
                } else {
                    // Enter BACKOFF until the next restart attempt.
                    self.enter_backoff(restart.restart_backoff_ms, "restart_backoff");
                    push_event(
                        &self.events,
                        "restart",
                        Some(&app),
                        format!(
                            "decision=backoff backoff_ms={} recent_restarts_in_window={}",
                            restart.restart_backoff_ms,
                            self.restart_times.len()
                        ),
                    );
                }
            }
        }
    }

    // ---- restart policy ------------------------------------------------------------

    /// A service's processes are gone right after a start: its cgroup never became
    /// non-empty within the start window, because the process exited (or crashed) almost
    /// immediately. That is a crash like any other, so apply the restart policy instead
    /// of declaring the service FAILED on the first attempt: `never` fails it; `always`
    /// counts it against the tolerance window and schedules a restart after the backoff,
    /// failing it only once the tolerance is used up. Returns the operator-facing message.
    fn handle_exit_during_start(&mut self, origin: &str) -> String {
        let app = self.app.clone();
        // Cron jobs have no restart policy, and a short job legitimately finishes before
        // the cgroup poll sees it; its process waiter reports the real exit code.
        if self.def.schedule.is_some() {
            push_event(&self.events, "schedule", Some(&app), format!("event=start_timeout scope=cron origin={origin} detail=cgroup_stayed_empty"));
            self.set_phase(Phase::Stopped, &format!("{origin}_timeout"));
            return format!("{app}: finished (or exited) right after start");
        }
        // An operator start or a definition reload is a fresh attempt: drop any FAILED /
        // BACKOFF left from before, so the policy below starts from a clean budget (a
        // successful start clears them through the flag rules; an instant exit must too).
        if origin.starts_with("manual") || origin.starts_with("reload") {
            self.update_info(|e| {
                sysflag_clear(&mut e.system_flags, SystemFlag::Failed);
                sysflag_clear(&mut e.system_flags, SystemFlag::Backoff);
            });
        }
        record_system_crash_in_store(&self.run_info, &app);
        let restart = self.def.restart.clone().unwrap_or_default();
        match restart.policy.parsed() {
            Ok(RestartPolicyParsed::Always) => {
                if self.count_restart(&restart) {
                    push_event(
                        &self.events,
                        "restart",
                        Some(&app),
                        format!(
                            "decision=suppress reason=tolerance_exceeded outcome=exited_during_start origin={origin} max_restarts={} window_ms={}",
                            restart.tolerance.max_restarts, restart.tolerance.duration
                        ),
                    );
                    self.mark_failed(&format!("{origin}_exited_tolerance_exceeded"));
                    return format!("{app}: exited right after start; restart tolerance exceeded, marked FAILED");
                }
                let backoff_ms = restart.restart_backoff_ms;
                push_event(
                    &self.events,
                    "restart",
                    Some(&app),
                    format!(
                        "decision=backoff outcome=exited_during_start origin={origin} backoff_ms={backoff_ms} recent_restarts_in_window={}",
                        self.restart_times.len()
                    ),
                );
                self.enter_backoff(backoff_ms, &format!("{origin}_exited_backoff"));
                format!("{app}: exited right after start; retrying in {backoff_ms}ms per restart policy")
            }
            Ok(RestartPolicyParsed::Never) => {
                self.mark_failed(&format!("{origin}_exited_policy_never"));
                format!("{app}: exited right after start (restart policy never), marked FAILED")
            }
            Err(e) => {
                self.mark_failed("restart_policy_parse_error");
                format!("{app}: exited right after start; restart policy invalid ({e}), marked FAILED")
            }
        }
    }

    /// Records an automatic restart in the tolerance window and reports whether the
    /// window is now over its budget.
    fn count_restart(&mut self, restart: &RestartConfig) -> bool {
        let now = Instant::now();
        while let Some(front) = self.restart_times.front() {
            if now.duration_since(*front).as_millis() as u64 > restart.tolerance.duration {
                self.restart_times.pop_front();
            } else {
                break;
            }
        }
        self.restart_times.push_back(now);
        self.restart_times.len() > restart.tolerance.max_restarts
    }

    fn mark_failed(&self, reason: &str) {
        let app = &self.app;
        self.update_info(|e| sysflag_set_with_rules(app, &mut e.system_flags, SystemFlag::Failed, None));
        self.set_phase(Phase::Failed, reason);
    }

    fn enter_backoff(&mut self, backoff_ms: u64, reason: &str) {
        let until_ms = Local::now().timestamp_millis() + backoff_ms as i64;
        self.update_info(|e| sysflag_set(&mut e.system_flags, SystemFlag::Backoff, Some(until_ms)));
        self.set_phase(Phase::Backoff, reason);
        self.pending_failure_restart_at = Some(Instant::now() + Duration::from_millis(backoff_ms));
    }

    // ---- processes and waiters -----------------------------------------------------

    /// Launches the service off the async runtime. The outer error is a failed join of
    /// the blocking task, the inner one a failed launch.
    async fn spawn_child(&self) -> anyhow::Result<anyhow::Result<std::process::Child>> {
        let cfg = self.cfg.clone();
        let def = self.def.clone();
        Ok(tasks().spawn_blocking(move || spawn_launcher_child(&cfg, &def)).await?)
    }

    async fn exec_stop(&self) -> anyhow::Result<StopResult> {
        let (cfg, def, app, events) = (self.cfg.clone(), self.def.clone(), self.app.clone(), Arc::clone(&self.events));
        tasks()
            .spawn_blocking(move || stop_common(Some(&events), &cfg, &def, &app))
            .await
            .map_err(|e| anyhow::anyhow!("join error: {e}"))?
    }

    async fn wait_for_cgroup_nonempty(&self) -> bool {
        let deadline = Instant::now() + START_WINDOW;
        loop {
            if cgroup_running_async(&self.cfg, &self.app).await.unwrap_or(false) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio_time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn ensure_waiter_attached(&mut self, after_start: bool) {
        if self.waiter_running {
            return;
        }
        // Right after a start the process was just seen in its cgroup, but it may
        // already have exited again. Attach anyway: the waiter reports an empty
        // cgroup as an exit at once. Skipping it here left the exit unobserved and
        // the service RUNNING forever with nothing running.
        if !after_start && !cgroup_running_or_assume_running(&self.cfg, &self.app).await {
            return;
        }
        self.detach_waiter();
        if let Ok(cancel) = spawn_cgroup_waiter(&self.cfg, &self.app, &self.tx_self, self.waiter_epoch) {
            self.waiter_running = true;
            self.waiter_cancel = Some(cancel);
            push_event(&self.events, "watch", Some(&self.app), "waiter=attached");
        }
    }

    /// Replaces the cgroup waiter with one that waits on `child` itself, so a scheduled
    /// job's real exit status is reported (the cgroup waiter can only say "empty").
    async fn attach_process_waiter(&mut self, child: std::process::Child) {
        self.detach_waiter();
        match spawn_process_waiter(child, &self.tx_self, &self.app, self.waiter_epoch) {
            Ok(()) => self.waiter_running = true,
            Err(e) => {
                // No thread to wait on the child (it went to the reaper). Watch the
                // cgroup instead: the exit is still seen, only without its status.
                push_event(
                    &self.events,
                    "watch",
                    Some(&self.app),
                    format!("process_waiter=failed fallback=cgroup_waiter err={e:#}"),
                );
                self.ensure_waiter_attached(true).await;
            }
        }
    }

    /// Abandons the current waiter: a later report from it carries a stale epoch.
    fn detach_waiter(&mut self) {
        self.waiter_epoch = self.waiter_epoch.wrapping_add(1);
        self.waiter_running = false;
        if let Some(c) = self.waiter_cancel.take() {
            c.cancel();
        }
    }

    // ---- run info --------------------------------------------------------------------

    fn info(&self) -> RunInfo {
        let ri = self.run_info.lock().unwrap_or_else(|p| p.into_inner());
        ri.get(&self.app).cloned().unwrap_or_default()
    }

    fn update_info(&self, f: impl FnOnce(&mut RunInfo)) {
        let mut ri = self.run_info.lock().unwrap_or_else(|p| p.into_inner());
        f(ri.entry(self.app.clone()).or_default());
    }

    fn set_phase(&self, phase: Phase, reason: &str) {
        set_phase_and_emit(&self.run_info, &self.events, &self.app, phase, reason);
    }
}

/// Stops a cgroup waiter that is no longer wanted.
pub(super) enum WaiterCancel {
    Task(tokio::task::AbortHandle),
    /// The thread fallback notices on its next poll (within a few seconds).
    Thread(Arc<AtomicBool>),
    /// The waiter has already reported.
    Done,
}

impl WaiterCancel {
    fn cancel(self) {
        match self {
            WaiterCancel::Task(h) => h.abort(),
            WaiterCancel::Thread(flag) => flag.store(true, Ordering::Relaxed),
            WaiterCancel::Done => {}
        }
    }
}

/// Watches the service's cgroup and reports `WaiterExited` once it is empty. Must be
/// called inside the runtime.
pub(super) fn spawn_cgroup_waiter(
    cfg: &MasterConfig,
    app: &str,
    tx: &tokio_mpsc::UnboundedSender<SupervisorCmd>,
    epoch: u64,
) -> anyhow::Result<WaiterCancel> {
    let app_s = app.to_string();
    let tx2 = tx.clone();
    let cg_dir = cgroup::app_dir(cfg, &app_s);
    // NOT an exit. Synthesising `code: Some(1)` for an error made an unreadable cgroup
    // indistinguishable from a crashed service: the supervisor recorded a crash,
    // restarted, and ended up with two live instances sharing one cgroup. Report the
    // failure and let the reconcile loop re-observe actual state instead.
    let report_error = move |tx: &tokio_mpsc::UnboundedSender<SupervisorCmd>, app: &str, e: anyhow::Error| {
        pm_event("watch", Some(app), format!("waiter=error (not treated as an exit) err={e:#}"));
        let _ = tx.send(SupervisorCmd::WaiterFailed { epoch });
    };

    match cgroup::PopulatedWatch::open(&cg_dir) {
        Ok(watch) => {
            let task = tasks().spawn(async move {
                match watch.wait_empty().await {
                    Ok(()) => {
                        let _ = tx2.send(SupervisorCmd::WaiterExited { epoch, code: None });
                    }
                    Err(e) => report_error(&tx2, &app_s, e),
                }
            });
            Ok(WaiterCancel::Task(task.abort_handle()))
        }
        // No cgroup: nothing is running in it. Report that as an exit at once, as the
        // poll-based waiter always has.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let _ = tx2.send(SupervisorCmd::WaiterExited { epoch, code: None });
            Ok(WaiterCancel::Done)
        }
        // The events file cannot be watched (unusual kernel or fs): fall back to a
        // thread that follows the cgroup's processes with pidfds.
        Err(e) => {
            pm_event("watch", Some(&app_s), format!("waiter=thread_fallback reason={e}"));
            let cancel = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&cancel);
            std::thread::Builder::new().name(format!("pm-waiter-{app_s}")).spawn(move || {
                match cgroup::wait_all_cancellable(&cg_dir, &flag) {
                    Ok(true) => {
                        let _ = tx2.send(SupervisorCmd::WaiterExited { epoch, code: None });
                    }
                    Ok(false) => {} // cancelled
                    Err(e) => report_error(&tx2, &app_s, e),
                }
            })?;
            Ok(WaiterCancel::Thread(cancel))
        }
    }
}

pub(super) fn spawn_process_waiter(
    mut child: std::process::Child,
    tx: &tokio_mpsc::UnboundedSender<SupervisorCmd>,
    app: &str,
    epoch: u64,
) -> anyhow::Result<()> {
    let tx2 = tx.clone();
    let tname = format!("pm-procwait-{}", app);
    let pid = child.id();
    let spawned = std::thread::Builder::new().name(tname).spawn(move || {
        let code = match child.wait() {
            Ok(st) => st.code().unwrap_or(1),
            Err(_) => 1,
        };
        let _ = tx2.send(SupervisorCmd::WaiterExited { epoch, code: Some(code) });
    });
    if let Err(e) = spawned {
        // The closure (and the Child inside it) is dropped on failure: the process
        // is still running with nobody to wait on it. The reaper is the fallback.
        disown_child_pid(pid);
        return Err(e.into());
    }
    Ok(())
}
