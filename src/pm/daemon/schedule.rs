//! Cron scheduling: firing scheduled jobs and stopping runs that exceed their time limit.

use super::*;

pub(super) fn start_scheduler_thread(state: Arc<Mutex<DaemonState>>) {
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

                let normalized = match normalize_cron_expr(expr) {
                    Ok(s) => s,
                    Err(e) => {
                        pm_event_state(
                            &state,
                            "schedule",
                            Some(&name),
                            format!("parse_error schedule={expr:?} err={e}"),
                        );
                        continue;
                    }
                };
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

pub(super) fn start_overtime_scheduler_thread(state: Arc<Mutex<DaemonState>>) {
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

            let clock = ProcClock::now();

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
                    let uptimes = clock.uptimes_ms(&pids);
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

pub(super) fn normalize_cron_expr(expr: &str) -> Result<String, String> {
    // processmaster evaluates cron schedules on minute boundaries.
    // We therefore only support 5-field cron ("min hour dom mon dow") and we normalize it to the
    // `cron` crate's longhand by prepending seconds=0.
    //
    // Note: the upstream `cron` crate supports 6/7-field expressions (sec ... [year]) and @daily-like
    // shorthands, but seconds-level precision is not supported by our scheduler loop.
    let expr = expr.trim();
    if expr.is_empty() {
        return Err("schedule is empty".to_string());
    }

    // Keep compatibility with upstream cron shorthands like "@hourly" (they are minute-resolution here).
    if expr.starts_with('@') {
        return Ok(expr.to_string());
    }

    let parts: Vec<&str> = expr.split_whitespace().collect();
    if parts.len() == 5 {
        Ok(format!("0 {expr}"))
    } else {
        Err(format!(
            "unsupported schedule format (expected 5 fields: min hour day-of-month month day-of-week; got {} fields)",
            parts.len()
        ))
    }
}
