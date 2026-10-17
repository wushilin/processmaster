//! Admin actions: operator-defined root commands run from the console, each in its own cgroup.

use super::*;

/// Running admin-action pids grouped by action id (the child cgroup name). Processes
/// left in the pre-per-id `run` leaf by an older release are reported under "run".
pub(crate) fn admin_action_pids_by_id(cfg: &MasterConfig) -> anyhow::Result<Vec<(String, Vec<u32>)>> {
    let root = cgroup::admin_actions_dir(cfg);
    let mut out = Vec::new();
    let rd = match fs::read_dir(&root) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e).with_context(|| format!("read_dir {}", root.display())),
    };
    for ent in rd.flatten() {
        if !ent.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let pids = crate::pm::cgroup::list_pids(&ent.path()).unwrap_or_default();
        if !pids.is_empty() {
            out.push((ent.file_name().to_string_lossy().into_owned(), pids));
        }
    }
    out.sort();
    Ok(out)
}

pub(super) fn do_admin_ps(state: &Arc<Mutex<DaemonState>>) -> anyhow::Result<Response> {
    let cfg = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        st.cfg.clone()
    };
    let running = admin_action_pids_by_id(&cfg)?;
    let msg = if running.is_empty() {
        "(none)".to_string()
    } else {
        running
            .iter()
            .flat_map(|(id, pids)| pids.iter().map(move |p| format!("{id}\t{p}")))
            .collect::<Vec<_>>()
            .join("\n")
    };
    Ok(Response::message(true, msg))
}

pub(super) fn do_admin_list(state: &Arc<Mutex<DaemonState>>) -> anyhow::Result<Response> {
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
        admin_actions: actions,
        ..Default::default()
    })
}

pub(super) fn do_admin_kill(state: &Arc<Mutex<DaemonState>>) -> anyhow::Result<Response> {
    let cfg = {
        let st = state.lock().map_err(|p| anyhow::anyhow!("{p}"))?;
        st.cfg.clone()
    };
    let cg = cgroup::admin_actions_dir(&cfg);
    let before = crate::pm::cgroup::list_pids(&cg).unwrap_or_default();
    crate::pm::cgroup::kill_all_pids(&cg)?;
    pm_event_state(
        state,
        "admin_action",
        None,
        format!("decision=kill_all cgroup={} pids_before={}", cg.display(), before.len()),
    );
    Ok(Response::message(true, format!("killed admin actions via cgroup.kill (pids_before={})", before.len())))
}

/// A plain `ok: false` response carrying `message`.
pub(super) fn admin_refusal(message: String) -> Response {
    Response::message(false, message)
}

pub(super) async fn do_admin_action_async(state: &Arc<Mutex<DaemonState>>, name: &str) -> anyhow::Result<Response> {
    if !geteuid().is_root() {
        return Ok(Response::message(false, "admin_action requires the daemon to run as root".to_string()));
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
                return Ok(Response::message(false, format!("admin_action {name:?} is not configured in the main config (admin_actions)")));
            }
        }
    };

    if argv.is_empty() {
        return Ok(Response::message(false, format!("admin_action {name:?} has empty command")));
    }

    // Re-check at run time too: the config is read once at startup, and ownership or
    // permissions may have been changed since.
    if let Err(e) = crate::pm::config::ensure_admin_action_trusted(name, &argv, &[0])
        .and_then(|()| crate::pm::config::ensure_admin_cwd_trusted(&[0]))
    {
        pm_event_state(state, "admin_action", None, format!("decision=refuse name={name} err={e:#}"));
        return Ok(admin_refusal(format!("admin_action {name} refused: {e:#}")));
    }

    // One cgroup per action id, and at most one run of an id at a time. The lock covers
    // the emptiness check *and* the spawn (the child joins its cgroup before spawn()
    // returns), so two concurrent clicks cannot both see an empty cgroup.
    let action_cg = cgroup::admin_actions_dir(&cfg).join(name);
    static SPAWN_LOCK: Mutex<()> = Mutex::new(());
    let _guard = SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    // Fail closed: if the cgroup cannot be read we cannot prove the action is idle.
    let running = match crate::pm::cgroup::list_pids(&action_cg) {
        Ok(p) => p,
        Err(e) => {
            return Ok(admin_refusal(format!(
                "admin_action {name}: cannot tell whether it is already running ({e:#}); refusing"
            )));
        }
    };
    if !running.is_empty() {
        pm_event_state(
            state,
            "admin_action",
            None,
            format!("decision=refuse name={name} reason=already_running pids={running:?}"),
        );
        return Ok(admin_refusal(format!(
            "admin_action {name} is already running (pids {running:?}); wait for it or use admin-kill"
        )));
    }

    pm_event_state(
        state,
        "admin_action",
        None,
        format!("decision=spawn name={name} label={label:?} argv={}", argv.join(" ")),
    );

    // Capture output for debugging (best-effort, but fail fast if we can't open the files).
    // Root-written output: symlink-safe directory, O_NOFOLLOW file, 0640 (an action's
    // output can carry secrets), same as service logs.
    let cwd = std::env::current_dir().context("determine daemon working directory")?;
    let logs_dir = crate::pm::safefs::open_dir_safely(&cwd.join("logs"), true)
        .context("open admin_action logs dir")?;
    let open_log = |file: &str| -> anyhow::Result<fs::File> {
        let fd = crate::pm::safefs::openat(
            &logs_dir,
            std::ffi::OsStr::new(file),
            libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT | libc::O_NOFOLLOW,
            0o640,
        )
        .with_context(|| format!("open logs/{file} (refusing to follow a symlink is intentional)"))?;
        Ok(fs::File::from(fd))
    };
    let stdout_file = open_log("admin_action_stdout.log")?;
    let stderr_file = open_log("admin_action_stderr.log")?;

    // Example (default config): /sys/fs/cgroup/processmaster/admin_actions/<id>
    let argv_os: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let mut p = cgroup::LaunchParams::new(argv_os, PathBuf::from("."), action_cg);
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
    // Disown: no handle is kept, so register the pid with the reaper. It reaps only
    // pids on that list, never waitpid(-1), so it cannot steal exit statuses from
    // supervisor code that still owns its children.
    drop(child);
    disown_child_pid(pid);

    pm_event_state(
        state,
        "admin_action",
        None,
        format!("outcome=spawned name={name} pid={pid}"),
    );

    Ok(Response::message(true, format!("admin_action {name} spawned pid={pid}")))
}
