//! One-time host preparation at boot: the master cgroup, controller delegation, and the
//! control socket's path and permissions.

use super::*;

pub(super) fn setup_master_cgroup_or_instructions(cfg: &MasterConfig) -> anyhow::Result<()> {
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

pub(super) fn setup_master_cgroup(cfg: &MasterConfig) -> anyhow::Result<()> {
    let cg_path = cgroup::master_dir(cfg);
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

pub(super) fn enable_subtree_controllers(parent: &Path, wanted: &[&str]) -> anyhow::Result<()> {
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

pub(super) fn enable_all_subtree_controllers(parent: &Path) -> anyhow::Result<()> {
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

pub(super) fn apply_socket_settings(cfg: &MasterConfig) -> anyhow::Result<()> {
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

pub(super) fn ensure_cgroup_access_or_instructions(cfg: &MasterConfig) -> anyhow::Result<()> {
    let cg_path = cgroup::master_dir(cfg);

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

pub(super) fn prepare_socket(sock: &Path) -> anyhow::Result<()> {
    if let Some(parent) = sock.parent() {
        let existed = parent.exists();
        fs::create_dir_all(parent).map_err(|e| {
            anyhow::anyhow!(
                "failed to create socket directory {}: {e}",
                parent.display()
            )
        })?;
        // Only tighten a directory we just created. Narrowing one the operator already
        // set up (say a shared /run/pm owned by an ops group) would be presumptuous.
        if !existed {
            let _ = fs::set_permissions(parent, PermissionsExt::from_mode(0o700));
        }
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
