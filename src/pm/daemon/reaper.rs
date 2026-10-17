//! Reaping children the daemon has handed off, so none are left defunct.

use super::*;

/// Pids of children the daemon has deliberately disowned (currently only
/// fire-and-forget admin actions) and which therefore have no `Child` handle left to
/// reap them.
///
/// This registry exists because the reaper must NOT call `waitpid(-1)`. A blanket
/// reaper races every live `Child::wait`/`try_wait` in the process: it consumes the
/// exit status first, the owner then gets `ECHILD`, and the daemon misreads that as
/// "the stop command failed" (escalating to a cgroup kill of a service that was
/// shutting down cleanly) or as "the service crashed" (spurious restart). Reaping only
/// pids we explicitly disowned removes the race by construction.
pub(super) static DISOWNED_PIDS: std::sync::OnceLock<Mutex<std::collections::HashSet<i32>>> =
    std::sync::OnceLock::new();

pub(super) fn disowned_pids() -> &'static Mutex<std::collections::HashSet<i32>> {
    DISOWNED_PIDS.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

/// Hand a pid to the reaper. Call this immediately after dropping a `Child` handle.
pub(super) fn disown_child_pid(pid: u32) {
    if let Ok(mut set) = disowned_pids().lock() {
        set.insert(pid as i32);
    }
}

/// Give up the `Child` handle of a freshly spawned (non-scheduled) service and hand
/// its pid to the reaper.
///
/// Non-scheduled services are supervised by the cgroup waiter, which observes the
/// cgroup via pidfd and never calls `waitpid`. Dropping the `Child` without
/// registering it therefore left one `<defunct>` entry under the daemon for every
/// service exit once the reaper stopped doing `waitpid(-1)`. Scheduled jobs must NOT
/// go through here: they keep their `Child` in `spawn_process_waiter`, which needs the
/// exit status, and the reaper would steal it.
pub(super) fn disown_service_child(child: std::process::Child) {
    let pid = child.id();
    drop(child);
    disown_child_pid(pid);
}

pub(super) fn start_child_reaper_thread() {
    // Idempotent: two reapers doing targeted waitpid would be harmless but pointless.
    static STARTED: std::sync::Once = std::sync::Once::new();
    let mut first = false;
    STARTED.call_once(|| first = true);
    if !first {
        return;
    }
    let _ = std::thread::Builder::new()
        .name("pm-child-reaper".to_string())
        .spawn(move || loop {
            // Snapshot so the lock is not held across waitpid.
            let pending: Vec<i32> = match disowned_pids().lock() {
                Ok(set) => set.iter().copied().collect(),
                Err(_) => Vec::new(),
            };
            let mut done: Vec<i32> = Vec::new();
            for pid in pending {
                match waitpid(Pid::from_raw(pid), Some(WaitPidFlag::WNOHANG)) {
                    // Still running: leave it registered.
                    Ok(WaitStatus::StillAlive) => {}
                    // Reaped, or no longer ours (ECHILD): stop tracking either way.
                    Ok(_) | Err(_) => done.push(pid),
                }
            }
            if !done.is_empty() {
                if let Ok(mut set) = disowned_pids().lock() {
                    for pid in done {
                        set.remove(&pid);
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        });
}
