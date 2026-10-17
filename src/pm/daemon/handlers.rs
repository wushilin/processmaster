//! RPC handlers for service control, status, flags and definition reloads.

use super::*;

// Compatibility helper (some call sites may format build-time strings for display).
#[allow(dead_code)]
pub(crate) fn format_build_time_pretty(raw: &str) -> String {
    crate::pm::build_info::format_build_time_pretty(raw)
}

pub(super) fn do_server_version() -> anyhow::Result<Response> {
    Ok(Response::message(true, crate::pm::build_info::banner()))
}

pub(super) fn do_perf_metrics(state: &Arc<Mutex<DaemonState>>, name: &str) -> anyhow::Result<Response> {
    let (cfg, app) = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        let app = name.trim().to_string();
        // Resolve against the loaded definitions like every other handler does. Without
        // this the name went straight into a cgroup path, so a client could read
        // memory/cpu/io/PSI files of any cgroup on the host.
        anyhow::ensure!(!app.is_empty(), "missing/empty app name");
        anyhow::ensure!(st.defs.contains_key(&app), "unknown service: {app}");
        (st.cfg.clone(), app)
    };

    let cg_dir = cgroup::app_dir(&cfg, &app);
    let snap = crate::pm::cgroup::read_resource_snapshot(&cg_dir)?;

    let cpu_pressure = snap.cpu_pressure.map(|p| crate::pm::rpc::PerfPressure {
        some: p.some.map(|l| crate::pm::rpc::PerfPressureLine {
            avg10: l.avg10,
            avg60: l.avg60,
            avg300: l.avg300,
            total: l.total,
        }),
        full: p.full.map(|l| crate::pm::rpc::PerfPressureLine {
            avg10: l.avg10,
            avg60: l.avg60,
            avg300: l.avg300,
            total: l.total,
        }),
    });
    let memory_pressure = snap.memory_pressure.map(|p| crate::pm::rpc::PerfPressure {
        some: p.some.map(|l| crate::pm::rpc::PerfPressureLine {
            avg10: l.avg10,
            avg60: l.avg60,
            avg300: l.avg300,
            total: l.total,
        }),
        full: p.full.map(|l| crate::pm::rpc::PerfPressureLine {
            avg10: l.avg10,
            avg60: l.avg60,
            avg300: l.avg300,
            total: l.total,
        }),
    });
    let io_pressure = snap.io_pressure.map(|p| crate::pm::rpc::PerfPressure {
        some: p.some.map(|l| crate::pm::rpc::PerfPressureLine {
            avg10: l.avg10,
            avg60: l.avg60,
            avg300: l.avg300,
            total: l.total,
        }),
        full: p.full.map(|l| crate::pm::rpc::PerfPressureLine {
            avg10: l.avg10,
            avg60: l.avg60,
            avg300: l.avg300,
            total: l.total,
        }),
    });

    Ok(Response {
        ok: true,
        message: "".to_string(),
        perf_metrics: Some(crate::pm::rpc::PerfMetricsSnapshot {
            app,
            cgroup_dir: snap.cgroup_dir,
            memory_max: snap.memory_max,
            memory_current: snap.memory_current,
            swap_max: snap.swap_max,
            swap_current: snap.swap_current,
            cpu_max: snap.cpu_max,
            cpu_stat: snap.cpu_stat,
            cpu_pressure,
            memory_pressure,
            io_max: snap.io_max,
            io_stat: snap.io_stat,
            io_pressure,
        }),
        ..Default::default()
    })
}

pub(super) fn do_events(state: &Arc<Mutex<DaemonState>>, name: Option<&str>, n: usize) -> anyhow::Result<Response> {
    let events = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
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
        events: v,
        ..Default::default()
    })
}

pub(super) async fn do_set_enabled_async(state: &Arc<Mutex<DaemonState>>, name: &str, enabled: bool) -> anyhow::Result<Response> {
    let source_file = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
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

    Ok(Response::message(true, format!("{} {}", if enabled { "enabled" } else { "disabled" }, name)))
}

pub(super) fn set_enabled_in_yaml(path: &Path, enabled: bool) -> anyhow::Result<()> {
    // `pmctl enable/disable` makes root rewrite a file inside a service-owned tree.
    // Read it under the same rules as loading it: no symlinks anywhere below the
    // root-controlled prefix, root-owned, single link.
    let raw = crate::pm::safefs::read_trusted_file(path, MAX_APP_CONFIG_BYTES)?;
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
    write_yaml_atomically(path, &out)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

pub(super) async fn do_update_async(state: &Arc<Mutex<DaemonState>>) -> anyhow::Result<Response> {
    let (cfg, old_defs) = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        (st.cfg.clone(), st.defs.clone())
    };

    let cfg_dir = cfg.config_directory.clone();
    let auto_dir = cfg.auto_service_directory.clone();
    let default_service_user = cfg.default_service_user.clone();
    let default_service_group = cfg.default_service_group.clone();
    let old_defs_for_load = old_defs.clone();
    let (new_defs, warnings, outdated) = match tasks().spawn_blocking(move || {
        load_app_definitions_best_effort(
            &cfg_dir,
            &old_defs_for_load,
            auto_dir.as_deref(),
            &default_service_user,
            &default_service_group,
        )
    })
        .await
        .map_err(|e| anyhow::anyhow!("join error: {e}"))?
    {
        Ok(v) => v,
        Err(e) => {
            // Fail-safe: keep last-known-good config; do not disrupt a running system.
            pm_event_state(state, "reconcile", None, format!("update_skipped reason=config_load_failed err={e}"));
            return Ok(Response::message(true, format!("update skipped: config load failed: {e} (kept last-known-good)")));
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
            let st = state.lock().unwrap_or_else(|p| p.into_inner());
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
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
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
            let st = state.lock().unwrap_or_else(|p| p.into_inner());
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

        pm_event_state(state, "reconcile", Some(name), "decision=apply_modified_def intent=reload_start");
        if let Err(e) = reload_start_via_supervisor_async(state, name, false).await {
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
            match reload_restart_via_supervisor_async(state, name, false).await {
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
        ..Default::default()
    })
}

pub(super) fn emit_reconcile_snapshot(state: &Arc<Mutex<DaemonState>>, pass: &str) {
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

pub(super) async fn start_enabled_services_async(state: &Arc<Mutex<DaemonState>>) -> anyhow::Result<()> {
    // Collect candidates without holding the lock during starts.
    // NOTE: scheduled jobs are not services; do not autostart them.
    let (cfg, names) = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
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

    // Bounded like every other bulk operation: each start occupies a blocking thread
    // to launch and then polls the cgroup, so a large config would otherwise queue
    // thousands of launches at once.
    let results = fan_out(names, 32, |name| {
        let st = Arc::clone(state);
        let cfg = cfg.clone();
        async move {
            autostart_one(&st, &cfg, &name).await;
            Ok(())
        }
    })
    .await;
    for (name, r) in results {
        if let Err(e) = r {
            pm_event_state(state, "autostart", Some(&name), format!("outcome=error err={e:#}"));
        }
    }
    Ok(())
}

async fn autostart_one(st: &Arc<Mutex<DaemonState>>, cfg: &MasterConfig, name: &str) {
    // Respect operator intent to keep the service stopped ("user_stop" flag).
    let run_info = {
        let g = st.lock().unwrap_or_else(|p| p.into_inner());
        Arc::clone(&g.run_info)
    };
    let stopped_by_user = {
        let ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
        ri.get(name)
            .map(|i| sysflag_has(&i.system_flags, SYSFLAG_USER_STOP))
            .unwrap_or(false)
    };
    if stopped_by_user {
        pm_event_state(st, "autostart", Some(name), "skip stopped_by_user");
        return;
    }
    // If already running, skip.
    match cgroup_running_async(cfg, name).await {
        Ok(true) => {
            pm_event_state(st, "autostart", Some(name), "skip already_running");
            return;
        }
        Ok(false) => {}
        Err(e) => {
            pm_event_state(st, "autostart", Some(name), format!("status_check_failed err={e}"));
            return;
        }
    }
    pm_event_state(st, "autostart", Some(name), "attempt=set_desired enabled");
    match boot_start_via_supervisor_async(st, name).await {
        Ok(()) => pm_event_state(st, "autostart", Some(name), "outcome=accepted desired=RUNNING"),
        Err(e) => pm_event_state(st, "autostart", Some(name), format!("outcome=error err={e}")),
    }
}

/// Runs `f` over every target with at most `limit` in flight and returns one result per
/// target, sorted by name. A task that panics yields an error for its target instead of
/// vanishing: dropping it would also leave its slot unfilled, so the rest of the queue
/// would be skipped without a word in the reply.
pub(super) async fn fan_out<T, F, Fut>(targets: Vec<String>, limit: usize, f: F) -> Vec<(String, anyhow::Result<T>)>
where
    T: Send + 'static,
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>> + Send + 'static,
{
    let mut js: JoinSet<anyhow::Result<T>> = JoinSet::new();
    let mut in_flight: HashMap<tokio::task::Id, String> = HashMap::new();
    let mut pending = targets.into_iter();
    let mut out: Vec<(String, anyhow::Result<T>)> = vec![];
    let mut spawn_next = |js: &mut JoinSet<anyhow::Result<T>>, in_flight: &mut HashMap<tokio::task::Id, String>| {
        if let Some(t) = pending.next() {
            let h = js.spawn(f(t.clone()));
            in_flight.insert(h.id(), t);
        }
    };
    for _ in 0..limit.max(1) {
        spawn_next(&mut js, &mut in_flight);
    }
    while let Some(res) = js.join_next_with_id().await {
        let (id, r) = match res {
            Ok((id, r)) => (id, r),
            Err(e) => (e.id(), Err(anyhow::anyhow!("internal error: {e}"))),
        };
        let t = in_flight.remove(&id).unwrap_or_default();
        out.push((t, r));
        spawn_next(&mut js, &mut in_flight);
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// One line per target. `ok` must reflect whether every target succeeded: pmctl derives
/// its exit status from it, and scripts chain destructive work off `pmctl stop <app> && ...`.
pub(super) fn per_target_response(results: Vec<(String, anyhow::Result<String>)>) -> Response {
    let mut lines: Vec<String> = vec![];
    let mut any_err = false;
    for (_t, r) in results {
        match r {
            Ok(line) => lines.push(line),
            Err(e) => {
                any_err = true;
                lines.push(format!("error: {e:#}"));
            }
        }
    }
    Response::message(!any_err, lines.join("\n"))
}

/// Summary for the bulk (`*_all`) operations: counts plus the first few failures.
pub(super) fn bulk_summary_response(op: &str, suffix: &str, results: Vec<(String, anyhow::Result<()>)>) -> Response {
    let ok = results.iter().filter(|(_, r)| r.is_ok()).count();
    let failures: Vec<String> = results
        .iter()
        .filter_map(|(name, r)| r.as_ref().err().map(|e| format!("{name}: {e}")))
        .collect();
    let mut message = format!("{op} done: {ok} ok, {} failed.{suffix}", failures.len());
    if !failures.is_empty() {
        let cap = 20usize;
        message.push('\n');
        message.push_str(&failures.iter().take(cap).cloned().collect::<Vec<_>>().join("\n"));
        if failures.len() > cap {
            message.push_str(&format!("\n…(+{})", failures.len() - cap));
        }
    }
    Response::message(failures.is_empty(), message)
}

/// A nested per-target `Response` folded into the bulk result: `ok: false` is a failure.
pub(super) fn response_as_result(r: anyhow::Result<Response>) -> anyhow::Result<()> {
    let resp = r?;
    if resp.ok { Ok(()) } else { Err(anyhow::anyhow!("{}", resp.message)) }
}

pub(super) fn enabled_service_names(state: &Arc<Mutex<DaemonState>>) -> anyhow::Result<Vec<String>> {
    let st = state.lock().unwrap_or_else(|p| p.into_inner());
    let mut v: Vec<String> = st
        .defs
        .iter()
        .filter(|(_n, d)| d.enabled && d.schedule.is_none())
        .map(|(n, _)| n.clone())
        .collect();
    v.sort();
    Ok(v)
}

pub(super) async fn do_start_async(state: &Arc<Mutex<DaemonState>>, name: &str, force: bool) -> anyhow::Result<Response> {
    let targets = resolve_targets(state, name, !force)?;

    async fn start_one(st: Arc<Mutex<DaemonState>>, t: String, force2: bool) -> anyhow::Result<String> {
        let (st, t) = (&st, t.as_str());
        let def = {
            let g = st.lock().unwrap_or_else(|p| p.into_inner());
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

    let results = fan_out(targets, 16, |t| start_one(Arc::clone(state), t, force)).await;
    Ok(per_target_response(results))
}

pub(super) async fn do_stop_async(state: &Arc<Mutex<DaemonState>>, name: &str) -> anyhow::Result<Response> {
    let targets = resolve_targets(state, name, false)?;

    async fn stop_one_cmd(st: Arc<Mutex<DaemonState>>, t: String) -> anyhow::Result<String> {
        let (st, t) = (&st, t.as_str());
        let def = {
            let g = st.lock().unwrap_or_else(|p| p.into_inner());
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

    let results = fan_out(targets, 16, |t| stop_one_cmd(Arc::clone(state), t)).await;
    Ok(per_target_response(results))
}

pub(super) async fn do_restart_async(state: &Arc<Mutex<DaemonState>>, name: &str, force: bool) -> anyhow::Result<Response> {
    let targets = resolve_targets(state, name, !force)?;

    async fn restart_one_cmd(st: Arc<Mutex<DaemonState>>, t: String, force2: bool) -> anyhow::Result<String> {
        let (st, t) = (&st, t.as_str());
        pm_event_state(st, "cmd", Some(t), format!("attempt=restart force={force2}"));
        let def = {
            let g = st.lock().unwrap_or_else(|p| p.into_inner());
            g.defs.get(t).cloned().ok_or_else(|| anyhow::anyhow!("unknown service: {t}"))?
        };
        // Scheduled jobs restart as stop-now + run-once; services go through the supervisor's restart.
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

    let results = fan_out(targets, 16, |t| restart_one_cmd(Arc::clone(state), t, force)).await;
    Ok(per_target_response(results))
}

pub(super) async fn do_start_all_async(state: &Arc<Mutex<DaemonState>>, force: bool) -> anyhow::Result<Response> {
    // Server-side bulk op for the web UI: start all enabled non-scheduled services.
    let names = enabled_service_names(state)?;
    if names.is_empty() {
        return Ok(Response::message(true, "no enabled services to start"));
    }
    let results = fan_out(names, 16, |name| {
        let st = Arc::clone(state);
        async move { response_as_result(do_start_async(&st, &name, force).await) }
    })
    .await;
    Ok(bulk_summary_response("start_all", "", results))
}

pub(super) async fn do_stop_all_async(state: &Arc<Mutex<DaemonState>>) -> anyhow::Result<Response> {
    // Server-side bulk op for the web UI: stop all *running* apps.
    // Because this is an operator action ("Stop all"), we DO apply operator-intent flags where applicable:
    // - services (non-scheduled) should get SYSFLAG_USER_STOP (and clear SYSFLAG_USER_START)
    // - scheduled jobs do not use user_stop/user_start markers
    //
    // IMPORTANT: we set the intent marker BEFORE issuing the stop so the subsequent exit event
    // is reliably treated as "stopped by user" and will not auto-restart.
    let (cfg, run_info, names): (MasterConfig, _, Vec<String>) = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        let mut v: Vec<String> = st.defs.keys().cloned().collect();
        v.sort();
        (st.cfg.clone(), Arc::clone(&st.run_info), v)
    };
    if names.is_empty() {
        return Ok(Response::message(true, "no services"));
    }

    // First: only target apps that are actually running right now.
    // This avoids "stop_all" affecting disabled/stopped apps (and keeps the counts meaningful).
    // A probe that fails outright counts as running: stopping too much is safer than too little.
    let total = names.len();
    let probes = fan_out(names, 32, |name| {
        let cfg2 = cfg.clone();
        async move { Ok(cgroup_running_or_assume_running(&cfg2, &name).await) }
    })
    .await;
    let running: Vec<String> = probes
        .into_iter()
        .filter(|(_, r)| !matches!(r, Ok(false)))
        .map(|(name, _)| name)
        .collect();
    let skipped = total.saturating_sub(running.len());
    if running.is_empty() {
        return Ok(Response::message(true, format!("stop_all: no running apps (skipped_not_running={skipped})")));
    }

    // Apply operator intent markers for running apps up-front (including cron jobs).
    // Also clear FAILED/BACKOFF suppression so the UI state is clean after an operator intervention.
    {
        let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
        for name in &running {
            let e = ri.entry(name.clone()).or_default();
            sysflag_set_with_rules(name, &mut e.system_flags, SYSFLAG_USER_STOP, None);
            e.recent_system_crashes_ms.clear();
        }
    }

    let results = fan_out(running, 16, |name| {
        let st = Arc::clone(state);
        async move { shutdown_stop_via_supervisor_async(&st, &name).await }
    })
    .await;

    // Stop failed: revert the pre-set operator stop marker, so we don't leave a stale
    // "stopped by user" intent on a still-running service.
    {
        let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
        for (name, r) in &results {
            if r.is_err() {
                if let Some(entry) = ri.get_mut(name) {
                    sysflag_clear(&mut entry.system_flags, SYSFLAG_USER_STOP);
                }
            }
        }
    }
    Ok(bulk_summary_response("stop_all", &format!(" skipped_not_running={skipped}"), results))
}

pub(super) async fn do_restart_all_async(state: &Arc<Mutex<DaemonState>>, force: bool) -> anyhow::Result<Response> {
    // Server-side bulk op for the web UI: restart all enabled non-scheduled services.
    let names = enabled_service_names(state)?;
    if names.is_empty() {
        return Ok(Response::message(true, "no enabled services to restart"));
    }
    let results = fan_out(names, 16, |name| {
        let st = Arc::clone(state);
        async move { response_as_result(do_restart_async(&st, &name, force).await) }
    })
    .await;
    Ok(bulk_summary_response("restart_all", "", results))
}

pub(super) fn do_flag(state: &Arc<Mutex<DaemonState>>, name: &str, flags: &[String], ttl: Option<&str>) -> anyhow::Result<Response> {
    let (run_info, events) = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        if name != "all" && !st.defs.contains_key(name) {
            anyhow::bail!("unknown service: {name}");
        }
        (Arc::clone(&st.run_info), Arc::clone(&st.events))
    };
    // Mark appstate dirty (persist user flags).
    {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
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
            // Bounded so the deadline arithmetic cannot overflow.
            const MAX_FLAG_TTL_MS: u64 = 3650 * 86_400_000;
            let dur = parse_flag_ttl_ms(spec)?;
            anyhow::ensure!(dur <= MAX_FLAG_TTL_MS, "ttl {spec:?} exceeds 3650 days");
            Some(Local::now().timestamp_millis() + dur as i64)
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
        validate_flag_chars(&t)?;
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
    Ok(Response::message(true, format!("{name}: flags={}", now_flags.join(","))))
}

pub(super) fn do_unflag(state: &Arc<Mutex<DaemonState>>, name: &str, flags: &[String]) -> anyhow::Result<Response> {
    // No charset check here: removing is harmless, and flags saved before the charset
    // rule existed must stay removable.
    let (run_info, events) = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        if name != "all" && !st.defs.contains_key(name) {
            anyhow::bail!("unknown service: {name}");
        }
        (Arc::clone(&st.run_info), Arc::clone(&st.events))
    };
    {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
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
    Ok(Response::message(true, format!("{name}: flags={}", now_flags.join(","))))
}

// All task/service/cron state manipulation happens through the per-app supervisor MPSC.
// For externally-visible commands, the oneshot response is only sent after the action completes.

pub(super) fn do_status(state: &Arc<Mutex<DaemonState>>, name: Option<&str>) -> anyhow::Result<Response> {
    // Snapshot under the lock, then read cgroups and /proc without it: those reads grow
    // with the number of processes the services run, and every other handler and the
    // scheduler wait on this lock.
    let (cfg, defs, run_info) = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        let want_one = name.filter(|n| *n != "all");
        if let Some(one) = want_one {
            if !st.defs.contains_key(one) {
                anyhow::bail!("unknown service: {one}");
            }
        }
        let defs: Vec<(String, AppDefinition)> = st
            .defs
            .iter()
            .filter(|(app, _)| want_one.is_none_or(|one| app.as_str() == one))
            .map(|(app, def)| (app.clone(), def.clone()))
            .collect();
        (st.cfg.clone(), defs, Arc::clone(&st.run_info))
    };
    let now_ms = Local::now().timestamp_millis();
    let clock = ProcClock::now();

    let mut entries: Vec<StatusEntry> = Vec::with_capacity(defs.len());
    for (app, def) in &defs {
        let pids = launcher_pids(&cfg, app)?;
        let pid_uptimes_ms = clock.uptimes_ms(&pids);
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
        entries.push(StatusEntry {
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

    entries.sort_by(|a, b| a.application.cmp(&b.application));

    Ok(Response {
        ok: true,
        message: String::new(),
        statuses: entries,
        ..Default::default()
    })
}

pub(super) fn resolve_targets(
    state: &Arc<Mutex<DaemonState>>,
    name: &str,
    require_enabled: bool,
) -> anyhow::Result<Vec<String>> {
    let st = state.lock().unwrap_or_else(|p| p.into_inner());
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
