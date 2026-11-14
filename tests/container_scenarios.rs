//! End-to-end container (podman) scenarios against a real daemon.
//!
//! Like `supervisor_scenarios`, each test starts its own daemon on its own socket and
//! cgroup and tears everything down afterwards. All tests share one podman store,
//! `/var/lib/pm-compat/store` (runtime state `/run/pm-compat2`), so images are pulled or
//! built once. Prepare it first (network needed):
//!
//! ```sh
//! P="podman --root /var/lib/pm-compat/store --runroot /run/pm-compat2 --tmpdir /run/pm-compat2/libpod"
//! sudo $P pull docker.io/library/busybox:1.37 docker.io/library/nginx:1.27-alpine docker.io/apache/kafka:3.9.0
//! git clone https://github.com/wushilin/rust-s3-server && sudo $P build -t localhost/rusts3:test rust-s3-server
//! ```
//!
//! They need root, cgroup v2 and podman, so they are `#[ignore]`d. Run them with:
//!
//! ```sh
//! cargo test --test container_scenarios --no-run
//! sudo "$(ls -t target/debug/deps/container_scenarios-* | grep -v '\.d$' | head -1)" --ignored --test-threads=4
//! ```

use processmaster::pm::rpc::{self, Request, Response, StatusEntry};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const APP: &str = "ctr";
const STORE: &str = "/var/lib/pm-compat/store";
const RUN_ROOT: &str = "/run/pm-compat2";
const BUSYBOX: &str = "docker.io/library/busybox:1.37";

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

struct Harness {
    /// podman --root/--runroot of this daemon's store.
    store: (String, String),
    /// A private store is deleted with the harness.
    private_store: bool,
    dir: PathBuf,
    sock: PathBuf,
    cgroup: PathBuf,
    instance: String,
    daemon: Option<Child>,
}

fn podman(args: &[&str]) -> std::process::Output {
    podman_in((STORE, RUN_ROOT), args)
}

fn podman_in(store: (&str, &str), args: &[&str]) -> std::process::Output {
    Command::new("podman")
        .args(["--root", store.0, "--runroot", store.1, "--tmpdir", &format!("{}/libpod", store.1)])
        .args(args)
        .output()
        .expect("run podman")
}

impl Harness {
    /// `service` is the YAML body after `application:`; `{work}` is replaced with the
    /// service's working directory.
    /// Shared image store; image cleanup off (other tests' images live there too).
    fn start(service: &str) -> Harness {
        Self::start_in(service, None, None)
    }

    /// Private, initially empty store under /var/lib (deleted afterwards); image
    /// cleanup on.
    fn start_private(service: &str) -> Harness {
        let id = format!("pmctest-store-{}-{}", std::process::id(), NEXT_ID.fetch_add(1, Ordering::Relaxed));
        Self::start_in(service, Some((format!("/var/lib/{id}"), format!("/run/{id}"))), None)
    }

    fn start_in(service: &str, private: Option<(String, String)>, auto_dir: Option<&Path>) -> Harness {
        assert!(nix::unistd::geteuid().is_root(), "container scenarios need root; see the module docs");
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let name = format!("pmctest-{}-{id}", std::process::id());
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
                 global: {{config_directory: ./conf.d{}}}\n\
                 web_console: {{enabled: false}}\n\
                 containers: {{storage_root: {}, run_root: {}, prune_unused_images: {}}}\n",
                sock.display(),
                auto_dir.map(|d| format!(", auto_service_directory: {}", d.display())).unwrap_or_default(),
                private.as_ref().map(|p| p.0.as_str()).unwrap_or(STORE),
                private.as_ref().map(|p| p.1.as_str()).unwrap_or(RUN_ROOT),
                private.is_some(),
            ),
        );
        write_trusted(&dir.join("conf.d").join(format!("{APP}.yaml")), &compose(&work, service));
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
        let private_store = private.is_some();
        let store = private.unwrap_or_else(|| (STORE.to_string(), RUN_ROOT.to_string()));
        let h = Harness {
            store,
            private_store,
            dir,
            sock,
            cgroup: PathBuf::from("/sys/fs/cgroup").join(&name),
            instance: name,
            daemon: Some(daemon),
        };
        h.wait_for("the daemon to answer", Duration::from_secs(15), || {
            rpc::client_call(&h.sock, Request::ServerVersion).map(|r| r.ok).unwrap_or(false)
        });
        h
    }

    /// Replace the service definition (same `{work}` substitution) and reload.
    fn redefine(&self, service: &str) {
        write_trusted(&self.dir.join("conf.d").join(format!("{APP}.yaml")), &compose(&self.work(), service));
        // The reload restarts definitions whose file is newer than the loaded one.
        std::thread::sleep(Duration::from_millis(20));
        let r = self.call(Request::Update);
        assert!(r.ok, "update: {}", r.message);
    }

    fn work(&self) -> PathBuf {
        self.dir.join("work")
    }
    fn container(&self) -> String {
        format!("pm-{}-{APP}", self.instance)
    }
    fn call(&self, req: Request) -> Response {
        rpc::client_call(&self.sock, req).expect("rpc")
    }
    fn status(&self) -> StatusEntry {
        let mut r = self.call(Request::Status { name: Some(APP.to_string()) });
        assert_eq!(r.statuses.len(), 1, "status: {}", r.message);
        r.statuses.remove(0)
    }
    fn start_svc(&self) -> Response {
        self.call(Request::Start { name: APP.to_string(), force: false })
    }
    fn stop_svc(&self) -> Duration {
        let t0 = Instant::now();
        let r = self.call(Request::Stop { name: APP.to_string() });
        assert!(r.ok, "stop: {}\n{}", r.message, self.daemon_output());
        t0.elapsed()
    }
    fn stdout_log(&self) -> String {
        std::fs::read_to_string(self.work().join("logs/stdout.log")).unwrap_or_default()
    }
    fn podman(&self, args: &[&str]) -> std::process::Output {
        podman_in((&self.store.0, &self.store.1), args)
    }
    fn image_present(&self, image: &str) -> bool {
        self.podman(&["image", "exists", image]).status.success()
    }
    fn container_exists(&self) -> bool {
        let out = self.podman(&["ps", "-a", "--format", "{{.Names}}"]);
        String::from_utf8_lossy(&out.stdout).lines().any(|l| l.trim() == self.container())
    }
    fn wait_running(&self, timeout: Duration) {
        self.wait_for("the service to run", timeout, || self.status().running);
    }
    fn wait_for(&self, what: &str, timeout: Duration, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if cond() {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!("timed out after {timeout:?} waiting for {what}\n--- daemon output ---\n{}", self.daemon_output());
    }
    fn daemon_output(&self) -> String {
        let s = std::fs::read_to_string(self.dir.join("daemon.out")).unwrap_or_default();
        let lines: Vec<&str> = s.lines().collect();
        lines[lines.len().saturating_sub(60)..].join("\n")
    }
    /// All pids in the service cgroup subtree.
    fn service_pids(&self) -> Vec<i32> {
        fn walk(d: &Path, out: &mut Vec<i32>) {
            if let Ok(s) = std::fs::read_to_string(d.join("cgroup.procs")) {
                out.extend(s.lines().filter_map(|l| l.trim().parse::<i32>().ok()));
            }
            if let Ok(rd) = std::fs::read_dir(d) {
                for e in rd.flatten() {
                    if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        walk(&e.path(), out);
                    }
                }
            }
        }
        let mut v = vec![];
        walk(&self.cgroup.join(format!("pm-{APP}")), &mut v);
        v
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(mut d) = self.daemon.take() {
            let pid = nix::unistd::Pid::from_raw(d.id() as i32);
            let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM);
            let deadline = Instant::now() + Duration::from_secs(60);
            while Instant::now() < deadline && matches!(d.try_wait(), Ok(None)) {
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = d.kill();
            let _ = d.wait();
        }
        let _ = std::fs::write(self.cgroup.join("cgroup.kill"), "1");
        let _ = self.podman(&["rm", "-f", "--volumes", "--ignore", "-t", "0", &self.container()]);
        if self.private_store {
            let _ = self.podman(&["system", "reset", "--force"]);
            let _ = std::fs::remove_dir_all(&self.store.0);
            let _ = std::fs::remove_dir_all(&self.store.1);
        }
        for _ in 0..50 {
            if remove_cgroup_tree(&self.cgroup) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The service file. `service` is the YAML after `application:`; lines indented by two
/// spaces before `container:` are lifecycle keys (stop_grace_period_ms, schedule, ...)
/// and go under `container:` (or under `process:` for a plain service).
fn compose(work: &Path, service: &str) -> String {
    let body = service.replace("{work}", &work.display().to_string());
    match body.split_once("container:\n") {
        Some((pre, rest)) => format!(
            "application: {APP}\ncontainer:\n  working_directory: {}\n{pre}{rest}",
            work.display()
        ),
        None => format!("application: {APP}\nprocess:\n  working_directory: {}\n{body}", work.display()),
    }
}

fn write_trusted(path: &Path, contents: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

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

fn has_flag(s: &StatusEntry, flag: &str) -> bool {
    s.system_flags.iter().any(|f| f.eq_ignore_ascii_case(flag))
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// One HTTP/1.0 GET; returns the raw response, or "" if the connection failed.
fn http_get(port: u16, path: &str) -> String {
    let Ok(mut s) = std::net::TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_secs(2)) else {
        return String::new();
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = write!(s, "GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn sh(script: &str) -> String {
    format!("  command: [/bin/sh, -c, {}]\n", serde_json::to_string(script).unwrap())
}

// ---------------------------------------------------------------------------------

/// The restart blocker from the design review: podman leaves `run/runtime` and
/// enabled controllers behind, which made the second start fail with EBUSY.
#[test]
#[ignore = "needs root + podman"]
fn start_stop_start_stop_with_graceful_handler() {
    let h = Harness::start(&format!(
        "  stop_grace_period_ms: 10000\ncontainer:\n  image: {BUSYBOX}\n  pull: never\n{}",
        sh("trap 'echo bye; exit 0' TERM; echo started; while :; do sleep 0.2; done")
    ));
    h.wait_running(Duration::from_secs(30));
    h.wait_for("startup output", Duration::from_secs(10), || h.stdout_log().contains("started"));
    for round in 0..2 {
        let took = h.stop_svc();
        assert!(!h.status().running, "round {round}: still running");
        assert!(took < Duration::from_secs(8), "round {round}: graceful stop took {took:?}");
        assert!(!h.container_exists(), "round {round}: container record left behind");
        let r = h.start_svc();
        assert!(r.ok, "round {round}: restart failed: {}\n{}", r.message, h.daemon_output());
        h.wait_running(Duration::from_secs(30));
    }
    h.wait_for("TERM handler output", Duration::from_secs(5), || h.stdout_log().matches("bye").count() >= 2);
}

/// A container whose init ignores the stop signal is killed after the grace period.
#[test]
#[ignore = "needs root + podman"]
fn sigterm_immune_container_is_killed_after_grace() {
    let h = Harness::start(&format!(
        "  stop_grace_period_ms: 2000\ncontainer:\n  image: {BUSYBOX}\n  pull: never\n{}",
        sh("trap '' TERM; while :; do sleep 0.2; done")
    ));
    h.wait_running(Duration::from_secs(30));
    let took = h.stop_svc();
    assert!(!h.status().running);
    assert!(took >= Duration::from_secs(2) && took < Duration::from_secs(15), "stop took {took:?}");
    assert!(!h.container_exists());
}

/// Exits non-zero at once: restarted per policy until the tolerance is used up.
#[test]
#[ignore = "needs root + podman"]
fn crashing_container_is_restarted_then_marked_failed() {
    let h = Harness::start(&format!(
        "container:\n  image: {BUSYBOX}\n  pull: never\n  volumes: ['./:/w:Z']\n{}\
         restart_policy:\n  policy: always\n  restart_backoff_ms: 100\n  tolerance: {{max_restarts: 2, duration: 60s}}\n",
        sh("echo x >> /w/starts; exit 3")
    ));
    h.wait_for("FAILED", Duration::from_secs(60), || has_flag(&h.status(), "failed"));
    let starts = std::fs::read_to_string(h.work().join("starts")).unwrap_or_default().lines().count();
    assert_eq!(starts, 3, "initial start + 2 restarts");
    assert!(!h.container_exists());
}

/// Killing everything in the service cgroup (as an OOM or `cgroup.kill` would) leaves
/// podman's record behind; the automatic restart must still succeed.
#[test]
#[ignore = "needs root + podman"]
fn restart_after_cgroup_kill_succeeds() {
    let h = Harness::start(&format!(
        "container:\n  image: {BUSYBOX}\n  pull: never\n  volumes: ['./:/w:Z']\n{}\
         restart_policy:\n  policy: always\n  restart_backoff_ms: 100\n",
        sh("echo x >> /w/starts; while :; do sleep 0.2; done")
    ));
    // Kill only once the container itself is up (it wrote its line), not podman mid-create.
    h.wait_for("the first start", Duration::from_secs(30), || {
        std::fs::read_to_string(h.work().join("starts")).unwrap_or_default().lines().count() >= 1
    });
    std::fs::write(h.cgroup.join(format!("pm-{APP}")).join("cgroup.kill"), "1").unwrap();
    h.wait_for("a second start", Duration::from_secs(30), || {
        std::fs::read_to_string(h.work().join("starts")).unwrap_or_default().lines().count() >= 2
    });
    h.wait_running(Duration::from_secs(30));
    h.stop_svc();
}

/// Environment values reach the container but not any command line in the cgroup.
#[test]
#[ignore = "needs root + podman"]
fn env_values_reach_the_container_but_not_argv() {
    // "s3cr3t-value" base64-encoded, plus a reserved name passed inline.
    let h = Harness::start(&format!(
        "container:\n  image: {BUSYBOX}\n  pull: never\n  env:\n    SECRET: \"@base64://czNjcjN0LXZhbHVl\"\n    HOME: /tmp\n    PORT: 8080\n{}",
        sh("echo \"secret=$SECRET home=$HOME port=$PORT\"; while :; do sleep 0.2; done")
    ));
    h.wait_running(Duration::from_secs(30));
    h.wait_for("env output", Duration::from_secs(10), || h.stdout_log().contains("secret=s3cr3t-value home=/tmp port=8080"));
    for pid in h.service_pids() {
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        assert!(
            !String::from_utf8_lossy(&cmdline).contains("s3cr3t-value"),
            "secret visible in argv of pid {pid}"
        );
    }
    h.stop_svc();
}

/// The container's processes are in the service cgroup, under its memory limit.
#[test]
#[ignore = "needs root + podman"]
fn container_runs_inside_the_service_cgroup_with_limits() {
    let h = Harness::start(&format!(
        "container:\n  image: {BUSYBOX}\n  pull: never\n{}resources:\n  max_memory: 96MiB\n  max_pids: 128\n",
        sh("while :; do sleep 0.2; done")
    ));
    h.wait_running(Duration::from_secs(30));
    let svc_cg = h.cgroup.join(format!("pm-{APP}"));
    assert_eq!(std::fs::read_to_string(svc_cg.join("memory.max")).unwrap().trim(), (96 * 1024 * 1024).to_string());
    assert_eq!(std::fs::read_to_string(svc_cg.join("memory.oom.group")).unwrap().trim(), "1");
    // RUNNING means podman is in the cgroup; the container may still be being created.
    let mut pid = String::new();
    h.wait_for("the container to exist", Duration::from_secs(10), || {
        let out = podman(&["inspect", "--format", "{{.State.Pid}}", &h.container()]);
        pid = String::from_utf8_lossy(&out.stdout).trim().to_string();
        !pid.is_empty() && pid != "0"
    });
    let cg = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
    assert!(cg.contains(&format!("/{}/pm-{APP}/run/", h.instance)), "container pid {pid} cgroup {cg}");
    h.stop_svc();
}

/// Cron-style services get the container's real exit code.
#[test]
#[ignore = "needs root + podman"]
fn scheduled_container_reports_its_exit_code() {
    let h = Harness::start(&format!(
        "  schedule: '0 0 1 1 *'\ncontainer:\n  image: {BUSYBOX}\n  pull: never\n{}",
        sh("echo job-ran; exit 7")
    ));
    let r = h.start_svc();
    assert!(r.ok, "{}", r.message);
    h.wait_for("exit code 7", Duration::from_secs(30), || h.status().last_exit_code == Some(7));
    assert!(h.stdout_log().contains("job-ran"));
    h.wait_for("the container record to go", Duration::from_secs(10), || !h.container_exists());
}

/// `pull: never` with a missing image is refused with a clear error.
#[test]
#[ignore = "needs root + podman"]
fn missing_image_with_pull_never_fails_to_start() {
    let h = Harness::start("  schedule: '0 0 1 1 *'\ncontainer:\n  image: localhost/does-not-exist:1\n  pull: never\n");
    let err = rpc::client_call(&h.sock, Request::Start { name: APP.to_string(), force: false })
        .expect_err("start must fail");
    assert!(format!("{err:#}").contains("not in processmaster's container store"), "{err:#}");
}

/// An image archive is loaded into the store on first start, then runs.
#[test]
#[ignore = "needs root + podman"]
fn image_archive_is_loaded_then_run() {
    let tag = format!("localhost/pmctest-archive:{}", std::process::id());
    // Root-owned, not group/other-writable all the way up: the daemon refuses an
    // archive that a non-root user could replace (it decides what root runs).
    let dir = PathBuf::from("/var/lib/pmctest-archives");
    std::fs::create_dir_all(&dir).unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let tar = dir.join(format!("pmctest-archive-{}.tar", std::process::id()));
    assert!(podman(&["tag", BUSYBOX, &tag]).status.success());
    assert!(podman(&["save", "-o", tar.to_str().unwrap(), &tag]).status.success());
    assert!(podman(&["rmi", &tag]).status.success());
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&tar, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let h = Harness::start(&format!(
        "container:\n  image: {tag}\n  image_archive: {}\n{}",
        tar.display(),
        sh("echo from-archive; while :; do sleep 0.2; done")
    ));
    h.wait_running(Duration::from_secs(60));
    h.wait_for("output", Duration::from_secs(10), || h.stdout_log().contains("from-archive"));
    h.stop_svc();
    let _ = podman(&["rmi", "-f", &tag]);
    let _ = std::fs::remove_file(&tar);
}

/// Changing a container service into a plain one: the old container is stopped as a
/// container (and removed), and the plain process starts despite podman's leftover
/// sub-cgroups in the launch leaf.
#[test]
#[ignore = "needs root + podman"]
fn container_service_converted_to_plain_process() {
    let h = Harness::start(&format!(
        "  stop_grace_period_ms: 10000\ncontainer:\n  image: {BUSYBOX}\n  pull: never\n{}",
        sh("trap 'echo bye; exit 0' TERM; echo started; while :; do sleep 0.2; done")
    ));
    h.wait_for("the container", Duration::from_secs(30), || h.stdout_log().contains("started"));
    h.redefine(&format!(
        "  start_command: [/bin/sh, -c, {}]\n",
        serde_json::to_string("echo plain-started; exec sleep 1000").unwrap()
    ));
    h.wait_for("the plain process", Duration::from_secs(30), || h.stdout_log().contains("plain-started"));
    assert!(h.stdout_log().contains("bye"), "old container was not stopped gracefully");
    assert!(!h.container_exists(), "old container record left behind");
    assert!(h.status().running);
    h.stop_svc();
}

/// Deleting a container service's definition stops and removes the container.
#[test]
#[ignore = "needs root + podman"]
fn removed_container_service_is_stopped_and_removed() {
    let h = Harness::start(&format!("container:\n  image: {BUSYBOX}\n  pull: never\n{}", sh("echo up; while :; do sleep 0.2; done")));
    h.wait_for("the container", Duration::from_secs(30), || h.stdout_log().contains("up") && h.container_exists());
    std::fs::remove_file(h.dir.join("conf.d").join(format!("{APP}.yaml"))).unwrap();
    let r = h.call(Request::Update);
    assert!(r.ok, "update: {}", r.message);
    h.wait_for("the container to go", Duration::from_secs(30), || !h.container_exists() && h.service_pids().is_empty());
}

/// A restart while the image is still loading must cancel that load and start a new one
/// without the cancellation killing the new helper.
#[test]
#[ignore = "needs root + podman + images"]
fn restart_during_pulling_loads_again_and_runs() {
    let (tag, tar) = kafka_archive();
    let h = Harness::start_private(&format!(
        "container:\n  image: {tag}\n  image_archive: {}\n  command: [/bin/sh, -c, 'echo loaded-and-running; exec sleep 1000']\n",
        tar.display()
    ));
    h.wait_for("PULLING", Duration::from_secs(20), || h.status().phase == "PULLING");
    let r = h.call(Request::Restart { name: APP.to_string(), force: false });
    assert!(r.ok, "restart: {}", r.message);
    h.wait_for("the container to run", Duration::from_secs(120), || h.stdout_log().contains("loaded-and-running"));
    let s = h.status();
    assert!(s.running && !has_flag(&s, "failed") && !has_flag(&s, "backoff"), "{s:?}");
    h.stop_svc();
}

/// A cached Kafka archive (root-owned path): large enough that loading it takes a while.
fn kafka_archive() -> (&'static str, PathBuf) {
    const TAG: &str = "localhost/pmctest-kafka:load";
    static ONCE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _g = ONCE.lock().unwrap_or_else(|p| p.into_inner());
    let dir = PathBuf::from("/var/lib/pmctest-archives");
    std::fs::create_dir_all(&dir).unwrap();
    let tar = dir.join("pmctest-kafka.tar");
    if !tar.exists() {
        assert!(podman(&["tag", "docker.io/apache/kafka:3.9.0", TAG]).status.success());
        assert!(podman(&["save", "-o", tar.to_str().unwrap(), TAG]).status.success());
        let _ = podman(&["rmi", TAG]);
    }
    (TAG, tar)
}

/// extra_args cannot move the container to another podman store (it would escape stop/rm).
#[test]
#[ignore = "needs root + podman"]
fn extra_args_store_override_is_refused_at_load() {
    let h = Harness::start(&format!(
        "container:\n  image: {BUSYBOX}\n  pull: never\n  extra_args: ['--root=/var/lib/containers/storage']\n{}",
        sh("sleep 1000")
    ));
    let r = rpc::client_call(&h.sock, Request::Status { name: Some(APP.to_string()) });
    let msg = match r {
        Ok(r) => format!("{} {:?}", r.message, r.statuses.iter().map(|s| &s.application).collect::<Vec<_>>()),
        Err(e) => format!("{e:#}"),
    };
    assert!(!msg.contains(&format!("\"{APP}\"")), "definition with --root was loaded: {msg}");
    assert!(h.daemon_output().contains("--root is not allowed"), "{}", h.daemon_output());
}

/// A cached busybox archive (root-owned path) to seed private stores.
fn busybox_archive() -> PathBuf {
    let dir = PathBuf::from("/var/lib/pmctest-archives");
    std::fs::create_dir_all(&dir).unwrap();
    let tar = dir.join("busybox-1.37.tar");
    if !tar.exists() {
        assert!(podman(&["save", "-o", tar.to_str().unwrap(), BUSYBOX]).status.success());
    }
    tar
}

/// Images no definition uses are removed; the one in use is kept; and once its service
/// is gone, it is removed too.
#[test]
#[ignore = "needs root + podman"]
fn unused_images_are_cleaned_up() {
    let tar = busybox_archive();
    let h = Harness::start_private(&format!(
        "container:\n  image: {BUSYBOX}\n  image_archive: {}\n{}",
        tar.display(),
        sh("echo up; while :; do sleep 0.2; done")
    ));
    h.wait_for("the container", Duration::from_secs(60), || h.stdout_log().contains("up"));
    // A distinct image nobody uses (a commit of a throwaway container: new image id).
    for args in [
        vec!["create", "--name", "pmctest-scratch", BUSYBOX, "true"],
        vec!["commit", "-q", "pmctest-scratch", "localhost/unused:1"],
        vec!["rm", "pmctest-scratch"],
    ] {
        let out = h.podman(&args);
        assert!(out.status.success(), "podman {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }
    let r = h.call(Request::Update);
    assert!(r.ok);
    h.wait_for("the unused tag to go", Duration::from_secs(30), || !h.image_present("localhost/unused:1"));
    assert!(h.image_present(BUSYBOX), "image in use was removed");
    // Remove the service: its image goes too.
    std::fs::remove_file(h.dir.join("conf.d").join(format!("{APP}.yaml"))).unwrap();
    assert!(h.call(Request::Update).ok);
    h.wait_for("the container to go", Duration::from_secs(30), || !h.container_exists());
    // The cleanup after this update may have run while the container was still there.
    assert!(h.call(Request::Update).ok);
    h.wait_for("the image to go", Duration::from_secs(30), || !h.image_present(BUSYBOX));
}

/// A stop while the image is loading abandons the start, and the store stays consistent
/// (the half-loaded image is never usable, and a later load works).
#[test]
#[ignore = "needs root + podman + images"]
fn stop_during_load_abandons_the_start_and_store_stays_consistent() {
    let (tag, tar) = kafka_archive();
    let h = Harness::start_private(&format!(
        "container:\n  image: {tag}\n  image_archive: {}\n  command: [/bin/sh, -c, 'echo should-not-run; exec sleep 1000']\n",
        tar.display()
    ));
    h.wait_for("PULLING", Duration::from_secs(20), || h.status().phase == "PULLING");
    std::thread::sleep(Duration::from_millis(300)); // let the load get going
    h.stop_svc();
    let s = h.status();
    assert!(!s.running && s.phase == "STOPPED", "{s:?}");
    // Long enough for the load to have finished had it not been cancelled.
    std::thread::sleep(Duration::from_secs(15));
    let s = h.status();
    assert!(!s.running && s.phase == "STOPPED", "service came back after stop: {s:?}");
    assert!(!h.stdout_log().contains("should-not-run"));
    let check = h.podman(&["system", "check"]);
    assert!(
        check.status.success(),
        "storage check: {}\n{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
    // A fresh start loads and runs normally.
    assert!(h.start_svc().ok);
    h.wait_for("the container", Duration::from_secs(120), || h.stdout_log().contains("should-not-run"));
    h.stop_svc();
}

/// Auto services: a folder is a default (`./run.sh`) service only if it has a run.sh. An
/// empty folder is skipped (nothing generated), and a hand-written container service.yml
/// is loaded as is.
#[test]
#[ignore = "needs root + podman"]
fn auto_service_folders_need_run_sh_or_service_yml() {
    use std::os::unix::fs::PermissionsExt as _;
    // Root-controlled all the way up, or auto-service folders are not loaded at all.
    let auto = PathBuf::from(format!("/var/lib/pmctest-auto-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&auto);
    for d in ["", "empty", "plain", "web"] {
        std::fs::create_dir_all(auto.join(d)).unwrap();
        std::fs::set_permissions(auto.join(d), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::write(auto.join("plain/run.sh"), "#!/bin/sh\nexec sleep 1000\n").unwrap();
    std::fs::set_permissions(auto.join("plain/run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
    write_trusted(
        &auto.join("web/service.yml"),
        &format!("application: web\ncontainer:\n  image: {BUSYBOX}\n  pull: never\n  command: [/bin/sh, -c, 'echo web-up; exec sleep 1000']\n"),
    );
    // A regeneration marker in a folder without run.sh must not replace the container
    // definition with the run.sh default.
    write_trusted(&auto.join("web/.regen_pm_config"), "");
    let h = Harness::start_in(&format!("container:\n  image: {BUSYBOX}\n  pull: never\n{}", sh("sleep 1000")), None, Some(&auto));
    assert!(
        std::fs::read_to_string(auto.join("web/service.yml")).unwrap().contains("container:"),
        "the regen marker replaced the container definition"
    );
    assert!(!auto.join("web/service.yml.bak").exists());
    let names = || -> Vec<String> {
        let r = h.call(Request::Status { name: None });
        r.statuses.into_iter().map(|s| s.application).collect()
    };
    let n = names();
    assert!(n.contains(&"plain".to_string()) && n.contains(&"web".to_string()), "{n:?}");
    assert!(!n.contains(&"empty".to_string()), "an empty folder was loaded: {n:?}");
    assert!(!auto.join("empty/service.yml").exists(), "a default was generated for a folder without run.sh");
    assert!(auto.join("plain/service.yml").exists(), "the run.sh default is still generated");
    let web_log = auto.join("web/logs/stdout.log");
    h.wait_for("the auto container service", Duration::from_secs(30), || {
        std::fs::read_to_string(&web_log).unwrap_or_default().contains("web-up")
    });
    // Once run.sh appears, the folder becomes a service on the next update.
    std::fs::write(auto.join("empty/run.sh"), "#!/bin/sh\nexec sleep 1000\n").unwrap();
    std::fs::set_permissions(auto.join("empty/run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(h.call(Request::Update).ok);
    assert!(names().contains(&"empty".to_string()));
    drop(h);
    let _ = std::fs::remove_dir_all(&auto);
}

/// A named network starts podman's shared DNS helper (aardvark-dns). It must not stay in
/// the service's cgroup: the service would look running after its container stopped,
/// and every stop would end in cgroup.kill.
#[test]
#[ignore = "needs root + podman"]
fn named_network_dns_helper_does_not_hold_the_service() {
    let net = format!("pmctest-net-{}", std::process::id());
    let _ = podman(&["network", "rm", "-f", &net]);
    assert!(podman(&["network", "create", &net]).status.success());
    let h = Harness::start(&format!(
        "  stop_grace_period_ms: 10000\ncontainer:\n  image: {BUSYBOX}\n  pull: never\n  network: {net}\n{}",
        sh("trap 'exit 0' TERM; echo up; while :; do sleep 0.2; done")
    ));
    h.wait_for("the container", Duration::from_secs(30), || h.stdout_log().contains("up") && h.container_exists());
    let in_cgroup: Vec<String> = h
        .service_pids()
        .iter()
        .map(|p| std::fs::read_to_string(format!("/proc/{p}/comm")).unwrap_or_default().trim().to_string())
        .collect();
    // Where the helper actually runs (evidence that it started at all).
    let helper = Command::new("sh")
        .args(["-c", "for p in $(pgrep -x aardvark-dns); do echo \"$p $(cat /proc/$p/cgroup)\"; done"])
        .output()
        .unwrap();
    let helper = String::from_utf8_lossy(&helper.stdout).trim().to_string();
    eprintln!("aardvark-dns: {helper:?}");
    assert!(!helper.is_empty(), "aardvark-dns did not start; the test does not exercise it");
    assert!(!helper.contains(&h.instance), "aardvark-dns runs inside this daemon's cgroups: {helper}");
    let took = h.stop_svc();
    let _ = podman(&["network", "rm", "-f", &net]);
    assert!(!in_cgroup.iter().any(|c| c.contains("aardvark")), "aardvark-dns in the service cgroup: {in_cgroup:?}");
    assert!(took < Duration::from_secs(5), "stop took {took:?} (something kept the cgroup busy)");
    assert!(h.service_pids().is_empty());
}

// ---- compatibility with real images -------------------------------------------------

#[test]
#[ignore = "needs root + podman + images"]
fn compat_nginx_serves_a_mounted_site_across_restarts() {
    let port = free_port();
    let h = Harness::start(&format!(
        "  stop_grace_period_ms: 10000\ncontainer:\n  image: docker.io/library/nginx:1.27-alpine\n  pull: never\n  \
         ports: ['127.0.0.1:{port}:80']\n  volumes: ['./html:/usr/share/nginx/html:ro,Z']\n"
    ));
    std::fs::create_dir_all(h.work().join("html")).unwrap();
    std::fs::write(h.work().join("html/index.html"), "pm-nginx-ok\n").unwrap();
    let r = h.call(Request::Restart { name: APP.to_string(), force: false });
    assert!(r.ok, "{}", r.message);
    for round in 0..2 {
        h.wait_for("nginx to serve", Duration::from_secs(30), || http_get(port, "/").contains("pm-nginx-ok"));
        let took = h.stop_svc();
        assert!(took < Duration::from_secs(8), "round {round}: nginx stop took {took:?}");
        assert!(http_get(port, "/").is_empty(), "round {round}: port still served after stop");
        assert!(!h.container_exists());
        assert!(h.start_svc().ok);
    }
}

#[test]
#[ignore = "needs root + podman + images"]
fn compat_rust_s3_server_answers_and_restarts() {
    let port = free_port();
    let h = Harness::start(&format!(
        "  stop_grace_period_ms: 15000\ncontainer:\n  image: localhost/rusts3:test\n  pull: never\n  \
         ports: ['127.0.0.1:{port}:8002']\n  volumes: ['./data:/data:Z,U']\n"
    ));
    std::fs::create_dir_all(h.work().join("data")).unwrap();
    let r = h.call(Request::Restart { name: APP.to_string(), force: false });
    assert!(r.ok, "{}", r.message);
    for _ in 0..2 {
        h.wait_for("rusts3 to answer HTTP", Duration::from_secs(60), || http_get(port, "/").starts_with("HTTP/"));
        let took = h.stop_svc();
        assert!(took < Duration::from_secs(20), "rusts3 stop took {took:?}");
        assert!(!h.container_exists());
        assert!(h.start_svc().ok);
    }
}

/// Kafka: a JVM that takes a while to start and to shut down.
#[test]
#[ignore = "needs root + podman + images"]
fn compat_kafka_starts_and_stops_gracefully() {
    let port = free_port();
    let h = Harness::start(&format!(
        "  stop_grace_period_ms: 60000\ncontainer:\n  image: docker.io/apache/kafka:3.9.0\n  pull: never\n  \
         ports: ['127.0.0.1:{port}:9092']\nresources:\n  max_memory: 1GiB\n"
    ));
    h.wait_for("kafka to start", Duration::from_secs(120), || {
        h.stdout_log().contains("Kafka Server started") || h.stdout_log().contains("started (kafka.server")
    });
    // The broker listener may come up just after the log line; the forwarded port must work.
    h.wait_for("the forwarded kafka port", Duration::from_secs(30), || {
        std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
    });
    let took = h.stop_svc();
    assert!(!h.status().running);
    assert!(!h.container_exists());
    assert!(
        h.stdout_log().contains("shut down completed") || h.stdout_log().contains("Kafka Server shut down"),
        "kafka did not shut down gracefully (stop took {took:?})"
    );
    eprintln!("kafka graceful stop took {took:?}");
}
