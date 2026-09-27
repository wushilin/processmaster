//! End-to-end supervision scenarios against a real daemon.
//!
//! Each test is self-contained: it writes its master config and service definition
//! from code into a private temp directory, starts its own `processmaster` daemon on
//! its own socket and cgroup (`pmtest-<pid>-<n>`), drives it over the real RPC, and
//! tears everything down (daemon, cgroups, files) when it finishes, even on failure.
//!
//! The service scripts cover the temperaments a supervisor meets in practice: quick
//! failure, clean exit under `never`, daemonizing (fork to background and exit),
//! background children that die later, SIGTERM-immune processes, graceful shutdown
//! handlers, process fan-out, and chatty output.
//!
//! They need root and cgroup v2, so they are `#[ignore]`d in a normal `cargo test`.
//! Run them with:
//!
//! ```sh
//! cargo test --test supervisor_scenarios --no-run
//! sudo "$(ls -t target/debug/deps/supervisor_scenarios-* | grep -v '\.d$' | head -1)" --ignored
//! ```

use processmaster::pm::rpc::{self, Request, Response, StatusEntry};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const APP: &str = "svc";

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

/// Knobs for the one service each scenario runs.
struct Service {
    script: &'static str,
    policy: &'static str,
    max_restarts: usize,
    stop_grace_period_ms: u64,
}

impl Service {
    fn new(script: &'static str) -> Self {
        Service { script, policy: "always", max_restarts: 50, stop_grace_period_ms: 2_000 }
    }
    fn policy(mut self, p: &'static str) -> Self {
        self.policy = p;
        self
    }
    fn max_restarts(mut self, n: usize) -> Self {
        self.max_restarts = n;
        self
    }
    fn grace_ms(mut self, ms: u64) -> Self {
        self.stop_grace_period_ms = ms;
        self
    }
}

/// A private daemon with one service. Dropping it stops the daemon and removes its
/// cgroups and files.
struct Harness {
    dir: PathBuf,
    sock: PathBuf,
    cgroup: PathBuf,
    daemon: Option<Child>,
}

impl Harness {
    fn start(svc: Service) -> Harness {
        assert!(
            nix::unistd::geteuid().is_root(),
            "supervisor scenarios need root and cgroup v2; see the module docs for how to run them"
        );
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let name = format!("pmtest-{}-{id}", std::process::id());
        // Short path: unix socket paths are limited to ~108 bytes.
        let dir = PathBuf::from(format!("/tmp/{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        let work = dir.join("work");
        std::fs::create_dir_all(dir.join("conf.d")).unwrap();
        std::fs::create_dir_all(&work).unwrap();
        let sock = dir.join("pm.sock");

        write_trusted(
            &dir.join("config.yaml"),
            &format!(
                "cgroup: {{root: /sys/fs/cgroup, name: {name}}}\n\
                 unix_socket: {{path: {}, owner: root, group: root, mode: \"0600\"}}\n\
                 global: {{config_directory: ./conf.d}}\n\
                 web_console: {{enabled: false}}\n",
                sock.display()
            ),
        );
        // JSON strings are valid YAML scalars, so this quotes the script safely.
        let script = serde_json::to_string(svc.script).unwrap();
        let tolerance = if svc.policy == "always" {
            format!(
                "  restart_backoff_ms: 100\n  tolerance: {{max_restarts: {}, duration: 60s}}\n",
                svc.max_restarts
            )
        } else {
            String::new()
        };
        write_trusted(
            &dir.join("conf.d").join(format!("{APP}.yaml")),
            &format!(
                "application: {APP}\n\
                 process:\n  working_directory: {}\n  start_command: [\"/bin/sh\", \"-c\", {script}]\n  \
                 stop_grace_period_ms: {}\n\
                 restart_policy:\n  policy: {}\n{tolerance}",
                work.display(),
                svc.stop_grace_period_ms,
                svc.policy,
            ),
        );

        let log = std::fs::File::create(dir.join("daemon.out")).unwrap();
        let daemon = Command::new(env!("CARGO_BIN_EXE_processmaster"))
            .arg("-c")
            .arg(dir.join("config.yaml"))
            .current_dir(&dir)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn processmaster");
        let h = Harness {
            dir,
            sock,
            cgroup: PathBuf::from("/sys/fs/cgroup").join(&name),
            daemon: Some(daemon),
        };
        h.wait_for("the daemon to answer", Duration::from_secs(15), || {
            rpc::client_call(&h.sock, Request::ServerVersion).map(|r| r.ok).unwrap_or(false)
        });
        h
    }

    fn work(&self) -> PathBuf {
        self.dir.join("work")
    }

    fn call(&self, req: Request) -> Response {
        rpc::client_call(&self.sock, req).expect("rpc")
    }

    fn status(&self) -> StatusEntry {
        let mut r = self.call(Request::Status { name: Some(APP.to_string()) });
        assert_eq!(r.statuses.len(), 1, "status: {}", r.message);
        r.statuses.remove(0)
    }

    fn stop(&self) {
        let r = self.call(Request::Stop { name: APP.to_string() });
        assert!(r.ok, "stop: {}", r.message);
    }

    /// Number of lines the service appended to `work/<file>` (one per start, etc.).
    fn count_lines(&self, file: &str) -> usize {
        std::fs::read_to_string(self.work().join(file)).map(|s| s.lines().count()).unwrap_or(0)
    }

    /// Poll `cond` until true; on timeout, fail with the daemon's recent events.
    fn wait_for(&self, what: &str, timeout: Duration, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if cond() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("timed out after {timeout:?} waiting for {what}\n--- daemon output ---\n{}", self.daemon_output());
    }

    fn daemon_output(&self) -> String {
        let s = std::fs::read_to_string(self.dir.join("daemon.out")).unwrap_or_default();
        let lines: Vec<&str> = s.lines().collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(mut d) = self.daemon.take() {
            // SIGTERM runs the daemon's graceful shutdown (stop all, drain cgroups).
            let pid = nix::unistd::Pid::from_raw(d.id() as i32);
            let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM);
            let deadline = Instant::now() + Duration::from_secs(20);
            while Instant::now() < deadline && matches!(d.try_wait(), Ok(None)) {
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = d.kill();
            let _ = d.wait();
        }
        // Anything left behind in our cgroup tree is killed, then the tree is removed.
        let _ = std::fs::write(self.cgroup.join("cgroup.kill"), "1");
        for _ in 0..50 {
            if remove_cgroup_tree(&self.cgroup) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Root-owned, 0644, as the daemon requires for anything it trusts.
fn write_trusted(path: &Path, contents: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

/// rmdir the cgroup tree depth-first; true when it is gone.
fn remove_cgroup_tree(dir: &Path) -> bool {
    if !dir.exists() {
        return true;
    }
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                remove_cgroup_tree(&e.path());
            }
        }
    }
    std::fs::remove_dir(dir).is_ok() || !dir.exists()
}

fn pid_alive(pid: i32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn has_flag(s: &StatusEntry, flag: &str) -> bool {
    s.system_flags.iter().any(|f| f.eq_ignore_ascii_case(flag))
}

// ---------------------------------------------------------------------------------

/// Crashes immediately, every time. The supervisor restarts it until the tolerance
/// (2 restarts) is used up, then marks it FAILED and stops trying.
#[test]
#[ignore = "needs root + cgroup v2"]
fn quick_failing_service_is_restarted_then_marked_failed() {
    let h = Harness::start(Service::new("echo start >> starts; exit 3").max_restarts(2));
    h.wait_for("FAILED", Duration::from_secs(20), || h.status().phase == "FAILED");

    let s = h.status();
    assert!(has_flag(&s, "failed"), "flags: {:?}", s.system_flags);
    assert!(!s.running && s.pids.is_empty());
    // The first start plus max_restarts restarts, and no more.
    assert_eq!(h.count_lines("starts"), 3, "--- daemon output ---\n{}", h.daemon_output());
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(h.count_lines("starts"), 3, "FAILED must stop the restart loop");
}

/// With `policy: never`, a single exit -- even a clean one -- is final.
#[test]
#[ignore = "needs root + cgroup v2"]
fn never_policy_is_not_restarted_after_a_clean_exit() {
    let h = Harness::start(Service::new("echo start >> starts; exit 0").policy("never"));
    h.wait_for("FAILED", Duration::from_secs(15), || h.status().phase == "FAILED");
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(h.count_lines("starts"), 1);
}

/// A classic daemon: forks into the background (new session, stdio detached) and the
/// launching process exits at once. Liveness comes from the cgroup, not the process
/// tree, so the service stays RUNNING, is not restarted, and stop still finds and
/// kills the detached child.
#[test]
#[ignore = "needs root + cgroup v2"]
fn daemonizing_service_is_tracked_through_its_cgroup() {
    let h = Harness::start(Service::new(
        "echo start >> starts; setsid sleep 300 </dev/null >/dev/null 2>&1 & echo $! > bg.pid; exit 0",
    ));
    h.wait_for("the background pid", Duration::from_secs(10), || h.count_lines("bg.pid") == 1);
    std::thread::sleep(Duration::from_secs(2)); // give a wrong "exited" verdict time to show

    let bg: i32 = std::fs::read_to_string(h.work().join("bg.pid")).unwrap().trim().parse().unwrap();
    let s = h.status();
    assert_eq!(s.actual, "RUNNING", "{s:?}");
    assert_eq!(s.pids, vec![bg], "only the detached child should remain");
    assert_eq!(h.count_lines("starts"), 1, "the launcher exiting must not count as a crash");

    h.stop();
    h.wait_for("the detached child to be killed", Duration::from_secs(15), || !pid_alive(bg));
    h.wait_for("STOPPED", Duration::from_secs(5), || h.status().pids.is_empty());
}

/// The launcher exits and leaves a background worker that dies a second later. The
/// service is only considered exited when its cgroup empties -- and then it is
/// restarted like any other crash.
#[test]
#[ignore = "needs root + cgroup v2"]
fn background_worker_dying_later_triggers_a_restart() {
    let h = Harness::start(Service::new("echo start >> starts; (sleep 1; exit 1) & exit 0"));
    h.wait_for("a restart", Duration::from_secs(15), || h.count_lines("starts") >= 2);
    assert!(h.status().restarts_10m >= 1);
}

/// Ignores SIGTERM. Stop must escalate to killing the cgroup once the grace period
/// runs out -- not hang, and not give up early.
#[test]
#[ignore = "needs root + cgroup v2"]
fn sigterm_immune_service_is_killed_after_the_grace_period() {
    let h = Harness::start(
        Service::new("trap '' TERM; echo $$ > main.pid; while :; do sleep 0.2; done").grace_ms(1_500),
    );
    h.wait_for("the service to start", Duration::from_secs(10), || h.count_lines("main.pid") == 1);
    let main: i32 = std::fs::read_to_string(h.work().join("main.pid")).unwrap().trim().parse().unwrap();

    let t0 = Instant::now();
    h.stop();
    h.wait_for("the SIGTERM-immune process to die", Duration::from_secs(15), || !pid_alive(main));
    let took = t0.elapsed();
    assert!(took >= Duration::from_millis(1_000), "killed before the grace period ran out ({took:?})");
    h.wait_for("an empty cgroup", Duration::from_secs(5), || h.status().pids.is_empty());
    assert!(!has_flag(&h.status(), "failed"), "a user stop is not a failure");
}

/// Handles SIGTERM by cleaning up and exiting. It must get the signal (its handler
/// runs) and stop long before the generous grace period would force a kill.
#[test]
#[ignore = "needs root + cgroup v2"]
fn graceful_service_runs_its_term_handler_and_stops_promptly() {
    let h = Harness::start(
        Service::new("trap 'echo bye >> out; exit 0' TERM; echo up > ready; while :; do sleep 0.2; done")
            .grace_ms(30_000),
    );
    h.wait_for("the service to start", Duration::from_secs(10), || h.count_lines("ready") == 1);

    let t0 = Instant::now();
    h.stop();
    h.wait_for("the service to stop", Duration::from_secs(10), || h.status().pids.is_empty());
    assert!(t0.elapsed() < Duration::from_secs(10), "should not wait for the 30s grace");
    assert_eq!(h.count_lines("out"), 1, "the TERM handler should have run exactly once");
    assert_eq!(h.status().phase, "STOPPED");
}

/// Fans out into many children. All of them live in the service's cgroup, so status
/// sees every one and stop reaps the whole tree.
#[test]
#[ignore = "needs root + cgroup v2"]
fn fan_out_children_are_all_tracked_and_all_killed() {
    let h = Harness::start(Service::new(
        "for i in $(seq 1 20); do sleep 300 & echo $! >> kids; done; wait",
    ));
    h.wait_for("20 children", Duration::from_secs(10), || h.count_lines("kids") == 20);
    h.wait_for("status to list them", Duration::from_secs(5), || h.status().pids.len() >= 21);
    let kids: Vec<i32> = std::fs::read_to_string(h.work().join("kids"))
        .unwrap()
        .lines()
        .map(|l| l.trim().parse().unwrap())
        .collect();

    h.stop();
    h.wait_for("every child to die", Duration::from_secs(15), || kids.iter().all(|&p| !pid_alive(p)));
    h.wait_for("an empty cgroup", Duration::from_secs(5), || h.status().pids.is_empty());
}

/// Output on both streams is captured by the log pumps and served by `logs`.
#[test]
#[ignore = "needs root + cgroup v2"]
fn chatty_service_output_is_captured_on_both_streams() {
    let h = Harness::start(Service::new(
        "i=0; while [ $i -lt 50 ]; do echo out-$i; echo err-$i >&2; i=$((i+1)); done; exec sleep 300",
    ));
    h.wait_for("the logs to be captured", Duration::from_secs(10), || {
        let r = h.call(Request::Logs { name: APP.to_string(), n: 100 });
        r.message.contains("out-49") && r.message.contains("err-49")
    });
    assert_eq!(h.status().actual, "RUNNING");
}

/// A FAILED service stays down until an operator starts it; a manual start clears
/// the failure and the service gets a fresh restart budget (2 more attempts here).
#[test]
#[ignore = "needs root + cgroup v2"]
fn manual_start_recovers_a_failed_service() {
    let h = Harness::start(Service::new("echo start >> starts; exit 1").max_restarts(1));
    h.wait_for("FAILED", Duration::from_secs(15), || h.status().phase == "FAILED");
    let before = h.count_lines("starts");

    // The start itself reports that the process exited right away (it always does);
    // what matters is that the policy takes over again with a fresh budget.
    let r = rpc::client_call(&h.sock, Request::Start { name: APP.to_string(), force: false });
    if let Err(e) = &r {
        assert!(format!("{e:#}").contains("exited right after start"), "{e:#}");
    }
    // A fresh budget: the manual attempt plus max_restarts (1) automatic retry.
    h.wait_for("new attempts after the manual start", Duration::from_secs(15), || {
        h.count_lines("starts") >= before + 2
    });
    h.wait_for("FAILED again", Duration::from_secs(15), || h.status().phase == "FAILED");
}
