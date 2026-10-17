//! A service's processes: building the launch, applying cgroup limits, signalling, and
//! the stop sequence (stop command, grace period, kill).

use super::*;

pub(super) const MAX_ENV_FILE_BYTES: u64 = 64 * 1024; // 64 KiB per env indirection file
/// Read the pids currently listed in a `cgroup.procs` file.
///
/// Returns an empty set if the file is gone or unreadable — callers use this to
/// *narrow* an existing kill list, so failing closed is the safe direction.
pub(super) fn read_pids_from_cgroup_procs(cgroup_procs: &Path) -> Vec<i32> {
    let Ok(text) = fs::read_to_string(cgroup_procs) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| l.trim().parse::<i32>().ok())
        .filter(|p| *p > 1)
        .collect()
}

pub(super) fn kill_orphan_pids_in_cgroup_procs_file(
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
    // Re-read the cgroup and only KILL pids that are *still* members. A pid that
    // exited during the grace window can have been recycled by the kernel, and this
    // runs as root: the stale entry would send SIGKILL to an unrelated process.
    let still_present: std::collections::HashSet<i32> =
        read_pids_from_cgroup_procs(&cgroup_procs).into_iter().collect();
    for pid in &filtered {
        if still_present.contains(pid) {
            let _ = kill(Pid::from_raw(*pid), Signal::SIGKILL);
        }
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

pub(super) fn wait_until_empty(cfg: &MasterConfig, app: &str, timeout: Duration) -> bool {
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

pub(super) fn to_cpu_max_string(s: &str) -> anyhow::Result<String> {
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

pub(super) fn to_mem_max_string(s: &str) -> anyhow::Result<String> {
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

pub(super) fn decode_hex(s: &str) -> anyhow::Result<Vec<u8>> {
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

pub(super) fn decode_env_value(value: &str) -> anyhow::Result<std::ffi::OsString> {
    let v = value.trim();
    if let Some(path) = v.strip_prefix("@file://") {
        // Read as root, often from a service-writable directory: no symlink anywhere
        // below the root-controlled prefix (it could point at a root-only key), only a
        // regular file (a FIFO would hang the launch path, /dev/zero would exhaust
        // memory), and no hard link to someone else's file.
        use std::io::Read as _;
        let abs = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")).join(path);
        let f = crate::pm::safefs::open_regular_for_read(&abs)
            .with_context(|| format!("read env file {path:?}"))?;
        // (open_regular_for_read also refuses a file with more than one hard link.)
        let md = f.metadata()?;
        anyhow::ensure!(
            md.len() <= MAX_ENV_FILE_BYTES,
            "env file {path:?} too large ({} bytes > {} bytes limit)",
            md.len(),
            MAX_ENV_FILE_BYTES
        );
        let mut bytes = Vec::new();
        f.take(MAX_ENV_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("read env file {path:?}"))?;
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_ENV_FILE_BYTES,
            "env file {path:?} exceeded the {MAX_ENV_FILE_BYTES} byte limit while reading"
        );
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

pub(super) fn spawn_launcher_child(cfg: &MasterConfig, def: &AppDefinition) -> anyhow::Result<std::process::Child> {
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

    // Re-check provisioning on every start, not only at definition load: replacing a
    // provisioned binary (a redeploy) silently drops its file capability, and without
    // this the service would fail to bind until someone deleted the marker by hand.
    maybe_provision_workdir(def)
        .with_context(|| format!("provisioning for {} (refuse to start)", def.application))?;

    // processmaster is now self-contained: we launch directly and self-attach into the app cgroup.
    // Keep the start/stop launch path consistent by using the shared LaunchParams builder.
    let lp = build_launch_params_for_app(cfg, def, &argv, Some(def.application.clone()))?;

    let mut cmd = cgroup::build_command(&lp)
        .with_context(|| format!("build command app={} cgroup_dir={}", def.application, lp.cgroup_dir.display()))?;

    let (stdout_path, stderr_path) = resolve_log_paths(def);
    // Capture-only mode: stdout/stderr always go through processmaster log pumps.
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    // Never hand a service the daemon's stdin. setsid() detaches the session but does
    // not close fd 0, so without this a daemon started from a terminal leaks that
    // terminal to every supervised service.
    cmd.stdin(Stdio::null());
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

pub(super) fn resolve_stop_command_log(p: Option<&PathBuf>, workdir: &Path) -> Option<PathBuf> {
    let p = p?;
    Some(resolve_under_workdir(workdir, p))
}

pub(super) fn resolve_under_workdir(workdir: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        workdir.join(p)
    }
}

pub(super) fn validate_env_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        anyhow::bail!("environment.name must not be empty");
    }
    if name.contains('=') {
        anyhow::bail!("environment.name must not contain '=': {name}");
    }
    Ok(())
}

/// How often the stop sequence checks whether the service has exited.
pub(super) const GRACE_POLL: Duration = Duration::from_millis(50);

pub(super) fn stop_common(
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
        let now = Instant::now();
        if now >= stop_deadline {
            break;
        }
        // Most services exit within milliseconds of the signal; a coarse poll would add
        // up to its whole interval to every stop and restart.
        std::thread::sleep(GRACE_POLL.min(stop_deadline - now));
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

pub(super) fn resources_for_app(def: &AppDefinition) -> anyhow::Result<cgroup::Resources> {
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
    r.pids_max = def.max_pids;

    if let Some(w) = def.io_weight {
        anyhow::ensure!((1..=10_000).contains(&w), "io_weight must be in 1..=10000");
        r.io_weight = Some(w);
    }

    if let Some(cfg) = &def.io_bandwidth {
        let mk_line = |dev_mm: &str, rbps: Option<u64>, wbps: Option<u64>, riops: Option<u64>, wiops: Option<u64>| -> anyhow::Result<String> {
            let t = dev_mm.trim();
            anyhow::ensure!(!t.is_empty(), "io_bandwidth.device is empty");
            let (maj_s, min_s) = t
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("io_bandwidth.device must be MAJ:MIN (got {t:?})"))?;
            let maj: u32 = maj_s.trim().parse().map_err(|_| anyhow::anyhow!("invalid device major in {t:?}"))?;
            let min: u32 = min_s.trim().parse().map_err(|_| anyhow::anyhow!("invalid device minor in {t:?}"))?;
            let mut parts = vec![format!("{maj}:{min}")];
            if let Some(v) = rbps { parts.push(format!("rbps={v}")); }
            if let Some(v) = wbps { parts.push(format!("wbps={v}")); }
            if let Some(v) = riops { parts.push(format!("riops={v}")); }
            if let Some(v) = wiops { parts.push(format!("wiops={v}")); }
            anyhow::ensure!(
                parts.len() > 1,
                "io_bandwidth rule for {t:?} must set at least one of rbps/wbps/riops/wiops"
            );
            Ok(parts.join(" "))
        };

        for rule in &cfg.0 {
            let rbps = match rule.max_read_bytes_per_second.as_deref() {
                None => None,
                Some(s) => {
                    let v = parse_size_spec_bytes(s)?;
                    anyhow::ensure!(
                        v >= 1024,
                        "io_bandwidth device={} max_read_bytes_per_second too small: {s:?} (bytes={v}). Minimum is 1024 bytes/s.",
                        rule.device
                    );
                    Some(v)
                }
            };
            let wbps = match rule.max_write_bytes_per_second.as_deref() {
                None => None,
                Some(s) => {
                    let v = parse_size_spec_bytes(s)?;
                    anyhow::ensure!(
                        v >= 1024,
                        "io_bandwidth device={} max_write_bytes_per_second too small: {s:?} (bytes={v}). Minimum is 1024 bytes/s.",
                        rule.device
                    );
                    Some(v)
                }
            };
            let riops = rule.max_read_iops;
            let wiops = rule.max_write_iops;
            if let Some(v) = riops {
                anyhow::ensure!(
                    v >= 5,
                    "io_bandwidth device={} max_read_iops too small: {}. Minimum is 5.",
                    rule.device,
                    v
                );
            }
            if let Some(v) = wiops {
                anyhow::ensure!(
                    v >= 5,
                    "io_bandwidth device={} max_write_iops too small: {}. Minimum is 5.",
                    rule.device,
                    v
                );
            }
            anyhow::ensure!(
                rbps.is_some() || wbps.is_some() || riops.is_some() || wiops.is_some(),
                "io_bandwidth rule for {:?} must set at least one cap",
                rule.device
            );
            let line = mk_line(&rule.device, rbps, wbps, riops, wiops)?;
            r.io_max.push(line);
        }
    }
    Ok(r)
}

pub(super) fn build_launch_params_for_app(
    cfg: &MasterConfig,
    def: &AppDefinition,
    argv: &[String],
    argv0_group: Option<String>,
) -> anyhow::Result<cgroup::LaunchParams> {
    anyhow::ensure!(!argv.is_empty(), "argv is empty");
    let cgroup_dir = cgroup::app_dir(cfg, &def.application);
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

    lp.inherit_environment = def.inherit_environment;

    // Resources (best-effort).
    lp.resources = resources_for_app(def)?;

    Ok(lp)
}

pub(super) fn run_stop_command_in_context(
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
        match child.try_wait() {
            Ok(Some(st)) => return Ok(st),
            Ok(None) => {}
            Err(e) => {
                disown_child_pid(child.id());
                return Err(e).context("try_wait stop_command");
            }
        }
        if Instant::now() >= stop_deadline {
            // The caller cgroup-kills the helper. Nobody waits on it after this point,
            // so hand it to the reaper or it stays <defunct> for the daemon's lifetime.
            disown_child_pid(child.id());
            anyhow::bail!("stop_command_timeout");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub(super) enum StopResult {
    Stopped,
    AlreadyStopped,
}

pub(super) fn parse_signal(s: &str) -> anyhow::Result<Signal> {
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

pub(super) fn launcher_pids(cfg: &MasterConfig, app: &str) -> anyhow::Result<Vec<i32>> {
    let dir = cgroup::app_dir(cfg, app);
    let mut pids: Vec<i32> = cgroup::list_pids(&dir)?
        .into_iter()
        .filter_map(|p| i32::try_from(p).ok())
        .collect();
    pids.sort();
    pids.dedup();
    Ok(pids)
}

pub(super) fn cgroup_running(cfg: &MasterConfig, app: &str) -> anyhow::Result<bool> {
    Ok(!launcher_pids(cfg, app)?.is_empty())
}

pub(super) async fn cgroup_running_async(cfg: &MasterConfig, app: &str) -> anyhow::Result<bool> {
    let dir = cgroup::app_dir(cfg, app);
    Ok(!cgroup::list_pids_async(&dir).await?.is_empty())
}

/// Liveness check that fails **safe**: if the cgroup cannot be read, assume the
/// service may still be running.
///
/// Use this anywhere a `false` would cause the caller to skip stopping something.
/// Treating "I could not look" as "it is stopped" is how a stop silently becomes a
/// no-op — and how a restart ends up with two live instances sharing one cgroup.
pub(super) async fn cgroup_running_or_assume_running(cfg: &MasterConfig, app: &str) -> bool {
    match cgroup_running_async(cfg, app).await {
        Ok(v) => v,
        Err(e) => {
            pm_event(
                "cgroup",
                Some(app),
                format!("liveness_check_failed assuming_running err={e:#}"),
            );
            true
        }
    }
}

pub(super) fn launcher_kill_signal(cfg: &MasterConfig, app: &str, sig: &str) -> anyhow::Result<()> {
    let s = parse_signal(sig)?;
    let dir = cgroup::app_dir(cfg, app);
    let _count = cgroup::kill_with_signal(&dir, Some(s))?;
    Ok(())
}

pub(super) fn launcher_kill_all(cfg: &MasterConfig, app: &str) -> anyhow::Result<()> {
    let dir = cgroup::app_dir(cfg, app);
    cgroup::kill_all_pids(&dir)?;
    Ok(())
}

pub(super) fn enforce_app_user_group_rules(def: &AppDefinition) -> anyhow::Result<()> {
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
