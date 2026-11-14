//! Podman operations for container services: image pull/load, stop, cleanup, and the
//! boot sweep. Every podman call uses processmaster's own store (`--root`/`--runroot`).
//!
//! Helpers run in `container_ctl/pm-<app>/<leaf>`, outside the service cgroup, so a pull
//! or `podman rm` never makes the service look running and never trips cgroup v2's
//! "no internal processes" rule on the service's launch leaf.

use super::*;
use crate::pm::container::{self, ContainerSpec, PullPolicy};

/// Image fetches (pull/load) hold this shared; image cleanup and store repair hold it
/// exclusively. So cleanup never sees a half-fetched image (which it would not know a
/// definition wants), and repair never touches the layers of a fetch in flight.
static STORE_LOCK: std::sync::RwLock<()> = std::sync::RwLock::new(());

/// Upper bound for `podman pull` / `podman load`.
pub(super) const FETCH_TIMEOUT: Duration = Duration::from_secs(600);
/// Upper bound for quick bookkeeping calls (image exists, rm, ps).
const OP_TIMEOUT: Duration = Duration::from_secs(60);
/// Captured helper output kept for error messages.
const MAX_CAPTURE: usize = 16 * 1024;

pub(super) fn instance(cfg: &MasterConfig) -> String {
    container::instance_id(&cfg.cgroup_name)
}

pub(super) fn container_name(cfg: &MasterConfig, app: &str) -> String {
    container::container_name(&instance(cfg), app)
}

/// `--root <storage> --runroot <run> --tmpdir <run>/libpod`: processmaster's own store.
///
/// `--tmpdir` matters as much as the other two: podman otherwise keeps its runtime state
/// (the "alive" marker that detects a reboot, container exit files) in `/run/libpod`,
/// shared with every other rootful podman on the host, so e.g. `podman system reset` on
/// the host's default store would disrupt processmaster's containers. Podman records
/// the tmpdir in the store's database on first use, so this must be passed from the
/// very first call.
pub(super) fn global_args(cfg: &MasterConfig) -> Vec<OsString> {
    let (storage, run) = crate::pm::config::container_store(cfg);
    let tmp = crate::pm::config::container_tmp_dir(&run);
    vec!["--root".into(), storage.into(), "--runroot".into(), run.into(), "--tmpdir".into(), tmp.into()]
}

/// Create the store directories root-only (they hold container configs, which carry
/// environment values, and volume data).
pub(super) fn ensure_store(cfg: &MasterConfig) -> anyhow::Result<()> {
    let (storage, run) = crate::pm::config::container_store(cfg);
    for d in [&storage, &run] {
        if !d.exists() {
            fs::create_dir_all(d).with_context(|| format!("create container store {}", d.display()))?;
            fs::set_permissions(d, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod 0700 {}", d.display()))?;
        }
        // Whoever can replace the store decides what root runs.
        crate::pm::config::ensure_root_controlled(d)
            .with_context(|| format!("refusing container store {}", d.display()))?;
    }
    Ok(())
}

pub(super) struct HelperResult {
    /// `None` when the helper was cancelled or timed out (and killed).
    pub(super) status: Option<std::process::ExitStatus>,
    pub(super) stdout: String,
    pub(super) stderr: String,
}

impl HelperResult {
    fn success(&self) -> bool {
        self.status.is_some_and(|s| s.success())
    }
    fn describe(&self) -> String {
        let code = match self.status {
            Some(s) => s.code().map(|c| c.to_string()).unwrap_or_else(|| "signal".into()),
            None => "killed".into(),
        };
        format!("exit={code} output={:?}", format!("{}{}", self.stdout, self.stderr).trim())
    }
}

/// Read a pipe to EOF, keeping the first `MAX_CAPTURE` bytes. Reading past the cap
/// keeps the helper from blocking on a full pipe.
fn capture(mut r: impl std::io::Read + Send + 'static) -> std::sync::mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(n) = r.read(&mut buf) {
            if n == 0 {
                break;
            }
            let room = MAX_CAPTURE.saturating_sub(kept.len());
            kept.extend_from_slice(&buf[..n.min(room)]);
        }
        let _ = tx.send(kept);
    });
    rx
}

/// Distinct helper cgroups: a cancelled helper's kill must never reach the next one.
static HELPER_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Run `podman <global args> <args>` in its own cgroup under the app's helper directory.
///
/// With `log_def`, stderr (pull/load progress) goes to the service's stderr log;
/// otherwise stdout and stderr are captured. `cancel` and `timeout` kill the helper.
pub(super) fn run_helper(
    cfg: &MasterConfig,
    app: &str,
    kind: &str,
    args: &[OsString],
    timeout: Duration,
    cancel: Option<&AtomicBool>,
    log_def: Option<&AppDefinition>,
) -> anyhow::Result<HelperResult> {
    let mut argv: Vec<OsString> = vec!["podman".into()];
    argv.extend(global_args(cfg));
    argv.extend(args.iter().cloned());
    let ctl = cgroup::container_ctl_dir(cfg, app);
    let leaf = format!("{kind}-{}", HELPER_SEQ.fetch_add(1, Ordering::Relaxed));
    let leaf_dir = ctl.join(&leaf);
    let mut lp = cgroup::LaunchParams::new(argv, PathBuf::from("/"), ctl.clone());
    lp.leaf = leaf;
    let result = run_helper_in(lp, &leaf_dir, timeout, cancel, log_def);
    // Empty once the helper is gone; harmless if something lingers.
    let _ = fs::remove_dir(&leaf_dir);
    result
}

fn run_helper_in(
    lp: cgroup::LaunchParams,
    leaf_dir: &Path,
    timeout: Duration,
    cancel: Option<&AtomicBool>,
    log_def: Option<&AppDefinition>,
) -> anyhow::Result<HelperResult> {
    let mut cmd = cgroup::build_command(&lp)?;
    cmd.stdin(Stdio::null());
    let log_path = log_def.map(|d| resolve_log_paths(d).1);
    cmd.stdout(if log_path.is_some() { Stdio::null() } else { Stdio::piped() });
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().context("spawn podman (is podman installed?)")?;
    let out_rx = child.stdout.take().map(capture);
    let mut err_rx = None;
    if let Some(err) = child.stderr.take() {
        match (&log_path, log_def) {
            (Some(path), Some(def)) => spawn_log_pump_stderr_async(def.clone(), path.clone(), err),
            _ => err_rx = Some(capture(err)),
        }
    }

    let deadline = Instant::now() + timeout;
    let mut killed_at: Option<Instant> = None;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break if killed_at.is_some() { None } else { Some(st) },
            Ok(None) => {}
            Err(e) => {
                disown_child_pid(child.id());
                return Err(e).context("wait for podman helper");
            }
        }
        match killed_at {
            None if Instant::now() >= deadline || cancel.is_some_and(|c| c.load(Ordering::Relaxed)) => {
                let _ = cgroup::kill_all_pids(leaf_dir);
                killed_at = Some(Instant::now());
            }
            // The kill did not take: leave the child to the reaper rather than hang.
            Some(t) if t.elapsed() > Duration::from_secs(5) => {
                disown_child_pid(child.id());
                break None;
            }
            _ => {}
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let collect = |rx: Option<std::sync::mpsc::Receiver<Vec<u8>>>| {
        rx.and_then(|r| r.recv_timeout(Duration::from_secs(2)).ok())
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default()
    };
    Ok(HelperResult { status, stdout: collect(out_rx), stderr: collect(err_rx) })
}

fn os(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

pub(super) fn image_exists(cfg: &MasterConfig, app: &str, image: &str) -> anyhow::Result<bool> {
    let r = run_helper(cfg, app, "op", &os(&["image", "exists", image]), OP_TIMEOUT, None, None)?;
    match r.status.and_then(|s| s.code()) {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => anyhow::bail!("podman image exists {image}: {}", r.describe()),
    }
}

/// Identity of an image archive, to notice when it was replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ArchiveStamp {
    ino: u64,
    size: u64,
    mtime_ns: i128,
}

fn archive_stamp(p: &Path) -> anyhow::Result<ArchiveStamp> {
    use std::os::unix::fs::MetadataExt as _;
    let md = fs::metadata(p).with_context(|| format!("image_archive {}", p.display()))?;
    anyhow::ensure!(md.is_file(), "image_archive {} is not a regular file", p.display());
    Ok(ArchiveStamp {
        ino: md.ino(),
        size: md.size(),
        mtime_ns: md.mtime() as i128 * 1_000_000_000 + md.mtime_nsec() as i128,
    })
}

/// What has to happen to the image before the container can start.
#[derive(Debug, Clone)]
pub(super) enum ImagePlan {
    Ready,
    Pull,
    Load { path: PathBuf, stamp: ArchiveStamp },
}

/// Decide whether the image must be pulled or loaded. `loaded` is the archive stamp
/// this daemon last loaded for the service (an archive is reloaded once per daemon run,
/// and whenever it changes).
pub(super) fn plan_image(
    cfg: &MasterConfig,
    app: &str,
    spec: &ContainerSpec,
    loaded: Option<ArchiveStamp>,
) -> anyhow::Result<ImagePlan> {
    ensure_store(cfg)?;
    if let Some(path) = &spec.image_archive {
        let stamp = archive_stamp(path)?;
        if loaded == Some(stamp) && image_exists(cfg, app, &spec.image)? {
            return Ok(ImagePlan::Ready);
        }
        return Ok(ImagePlan::Load { path: path.clone(), stamp });
    }
    match spec.pull {
        PullPolicy::Always => Ok(ImagePlan::Pull),
        PullPolicy::Missing if image_exists(cfg, app, &spec.image)? => Ok(ImagePlan::Ready),
        PullPolicy::Missing => Ok(ImagePlan::Pull),
        PullPolicy::Never if image_exists(cfg, app, &spec.image)? => Ok(ImagePlan::Ready),
        PullPolicy::Never => anyhow::bail!(
            "image {} is not in processmaster's container store and container.pull is never \
             (load it with `pmctl podman pull` / `pmctl podman load`)",
            spec.image
        ),
    }
}

/// Carry out a pull or load. Blocking; cancellable through `cancel`.
pub(super) fn fetch_image(
    cfg: &MasterConfig,
    def: &AppDefinition,
    spec: &ContainerSpec,
    plan: &ImagePlan,
    cancel: &AtomicBool,
) -> anyhow::Result<()> {
    let app = &def.application;
    let args = match plan {
        ImagePlan::Ready => return Ok(()),
        ImagePlan::Pull => os(&["pull", &spec.image]),
        ImagePlan::Load { path, .. } => {
            // Root loads whatever the archive holds and then runs it: a non-root user able
            // to replace the file would choose what root runs. Check (and load) the
            // resolved file, so a symlink cannot point the check somewhere else.
            let real = fs::canonicalize(path).with_context(|| format!("image_archive {}", path.display()))?;
            crate::pm::config::ensure_root_controlled(&real)
                .with_context(|| format!("refusing image_archive {}", path.display()))?;
            vec!["load".into(), "-i".into(), real.into()]
        }
    };
    let r = {
        let _shared = STORE_LOCK.read().unwrap_or_else(|p| p.into_inner());
        run_helper(cfg, app, "fetch", &args, FETCH_TIMEOUT, Some(cancel), Some(def))?
    };
    if r.status.is_none() {
        // Killed mid-write: the layer being written may be left behind with no image
        // referring to it. Repair what podman already counts as damaged.
        repair_store(cfg, app);
        if cancel.load(Ordering::Relaxed) {
            anyhow::bail!("cancelled");
        }
        anyhow::bail!("timed out after {}s", FETCH_TIMEOUT.as_secs());
    }
    anyhow::ensure!(r.success(), "podman {} failed ({}); see the service's stderr log", args[0].to_string_lossy(), r.describe());
    if matches!(plan, ImagePlan::Load { .. }) {
        let _shared = STORE_LOCK.read().unwrap_or_else(|p| p.into_inner());
        anyhow::ensure!(
            image_exists(cfg, app, &spec.image)?,
            "the archive loaded, but it does not provide {} (check the tag inside the archive)",
            spec.image
        );
    }
    Ok(())
}

/// `podman stop -t <grace>`: signals only the container's init with the stop signal and
/// escalates to SIGKILL itself after the grace period.
///
/// `Ok(true)`: podman reported success. `Ok(false)`: podman ran but failed (e.g. the
/// container is still being set up); worth retrying. `Err`: podman could not be run or
/// hung.
pub(super) fn stop_container(cfg: &MasterConfig, app: &str, grace: Duration) -> anyhow::Result<bool> {
    let secs = grace.as_millis().div_ceil(1000).to_string();
    let name = container_name(cfg, app);
    let r = run_helper(
        cfg,
        app,
        "op",
        &os(&["stop", "--ignore", "-t", &secs, &name]),
        grace + Duration::from_secs(15),
        None,
        None,
    )?;
    anyhow::ensure!(r.status.is_some(), "podman stop {name} timed out");
    if !r.success() {
        pm_event("stop", Some(app), format!("podman_stop_failed {}", r.describe()));
    }
    Ok(r.success())
}

/// Remove the container record and what podman set up around it (mounts, network
/// namespace, firewall rules, and anonymous volumes for the image's VOLUME paths). Needed after every stop: a killed conmon leaves podman
/// believing the container is still up, and the next `run --name` would fail.
pub(super) fn remove_container(cfg: &MasterConfig, app: &str) -> anyhow::Result<()> {
    let name = container_name(cfg, app);
    let r = run_helper(cfg, app, "op", &os(&["rm", "-f", "--volumes", "--ignore", "-t", "0", &name]), OP_TIMEOUT, None, None)?;
    anyhow::ensure!(r.success(), "podman rm {name}: {}", r.describe());
    Ok(())
}

/// Containers of this instance: `(container name, app label)`.
pub(super) fn list_own_containers(cfg: &MasterConfig) -> anyhow::Result<Vec<(String, String)>> {
    ensure_store(cfg)?;
    let filter = format!("label={}={}", container::LABEL_INSTANCE, instance(cfg));
    let format = format!("{{{{.Names}}}}\t{{{{index .Labels \"{}\"}}}}", container::LABEL_APP);
    let r = run_helper(cfg, "_sweep", "op", &os(&["ps", "-a", "--filter", &filter, "--format", &format]), OP_TIMEOUT, None, None)?;
    anyhow::ensure!(r.success(), "podman ps: {}", r.describe());
    Ok(r
        .stdout
        .lines()
        .filter_map(|l| l.split_once('\t'))
        .map(|(n, a)| (n.trim().to_string(), a.trim().to_string()))
        .filter(|(n, _)| !n.is_empty())
        .collect())
}

/// Boot sweep: remove this instance's containers whose service is not running. They
/// are records left behind by a crash (conmon lives in the service cgroup, so an empty
/// cgroup means the container is gone).
pub(super) fn sweep_stale_containers(cfg: &MasterConfig) {
    let list = match list_own_containers(cfg) {
        Ok(l) => l,
        Err(e) => {
            pm_event("container", None, format!("sweep outcome=error err={e:#}"));
            return;
        }
    };
    for (name, app) in list {
        if crate::pm::app::validate_application_name(&app).is_err() {
            continue;
        }
        if cgroup_running(cfg, &app).unwrap_or(true) {
            continue;
        }
        let r = remove_container(cfg, &app);
        pm_event(
            "container",
            Some(&app),
            format!("sweep removed={name} outcome={}", if r.is_ok() { "ok".to_string() } else { format!("{r:?}") }),
        );
    }
}

/// Prepare the service cgroup and podman for a fresh `podman run`.
pub(super) fn prepare_start(cfg: &MasterConfig, def: &AppDefinition) -> anyhow::Result<()> {
    let app = &def.application;
    ensure_store(cfg)?;
    remove_container(cfg, app).context("remove stale container")?;
    let app_cg = cgroup::app_dir(cfg, app);
    fs::create_dir_all(&app_cg).with_context(|| format!("create {}", app_cg.display()))?;
    cgroup::reset_leaf(&app_cg.join("run"))?;
    // An OOM kill of podman/conmon alone would leave the container running with no
    // log pipes; take down the whole service instead. Best effort (needs memory ctl).
    let _ = fs::write(app_cg.join("memory.oom.group"), "1\n");
    Ok(())
}

/// Launch parameters for `podman run` of a container service, after preparing the
/// cgroup and removing any stale container.
pub(super) fn container_launch_params(
    cfg: &MasterConfig,
    def: &AppDefinition,
    spec: &ContainerSpec,
) -> anyhow::Result<cgroup::LaunchParams> {
    // Podman refuses a missing bind source too, but only in the service's stderr log;
    // say it in the start error instead.
    for v in &spec.volumes {
        let container::VolumeSource::Host(p) = &v.source;
        anyhow::ensure!(p.exists(), "volume source {} does not exist (refuse to start)", p.display());
    }
    prepare_start(cfg, def)?;

    let mut env = Vec::with_capacity(spec.env.len());
    for ev in &spec.env {
        let v = decode_env_value(&ev.value)
            .with_context(|| format!("decode container.env value app={} name={}", def.application, ev.name))?;
        env.push((ev.name.clone(), v));
    }
    // Canonical name (SIGTERM, ...) so podman parses exactly what processmaster accepted.
    let stop_signal = parse_signal(def.stop_signal.as_deref().unwrap_or("SIGTERM"))?;
    let inv = container::podman_run_invocation(spec, &instance(cfg), &def.application, stop_signal.as_str(), &env);
    // podman <global args> run ...
    let mut argv: Vec<OsString> = vec![inv.argv[0].clone()];
    argv.extend(global_args(cfg));
    argv.extend(inv.argv[1..].iter().cloned());

    let mut lp = cgroup::LaunchParams::new(argv, def.working_directory.clone(), cgroup::app_dir(cfg, &def.application));
    lp.environment = inv.process_env;
    lp.resources = resources_for_app(def)?;
    Ok(lp)
}

/// `podman system check --quick --repair`: removes what podman counts as damaged. That
/// covers layer data no layer record accounts for (as a pull or load killed mid-write
/// leaves) at once, and layers no image refers to once they are older than podman's
/// `--max` (24h). The age limit is kept: it is what protects the layers of a pull that
/// is running at the same moment outside processmaster (`pmctl podman pull`). Never
/// removes an image a container uses (that would need `--force`).
pub(super) fn repair_store(cfg: &MasterConfig, app: &str) {
    let _exclusive = STORE_LOCK.write().unwrap_or_else(|p| p.into_inner());
    repair_store_locked(cfg, app);
}

fn repair_store_locked(cfg: &MasterConfig, app: &str) {
    match run_helper(cfg, app, "op", &os(&["system", "check", "--quick", "--repair"]), FETCH_TIMEOUT, None, None) {
        Ok(r) if r.success() => {
            let out = format!("{}{}", r.stdout, r.stderr);
            if !out.trim().is_empty() {
                pm_event("container", Some(app), format!("store_repair output={:?}", out.trim()));
            }
        }
        Ok(r) => pm_event("container", Some(app), format!("store_repair outcome=error {}", r.describe())),
        Err(e) => pm_event("container", Some(app), format!("store_repair outcome=error err={e:#}")),
    }
}

/// Remove images in processmaster's store that no service definition uses: images of
/// removed services, and the old untagged versions a re-pull leaves behind.
///
/// Never forced, so an image a container still uses (or that one is being created
/// from) cannot be removed. Mounted host folders are never touched. Returns the number of
/// images removed.
///
/// `defs` is read only once no fetch is in flight (under the store lock), so a definition
/// added meanwhile, or an image a fetch just finished, is always counted.
pub(super) fn gc_images(cfg: &MasterConfig, defs: impl FnOnce() -> Vec<AppDefinition>) -> anyhow::Result<usize> {
    let (storage, _) = crate::pm::config::container_store(cfg);
    if !storage.exists() {
        return Ok(0);
    }
    ensure_store(cfg)?;
    let _exclusive = STORE_LOCK.write().unwrap_or_else(|p| p.into_inner());
    // Leftovers of interrupted pulls/loads are not images; always look after them.
    repair_store_locked(cfg, "_gc");
    if !cfg.container_prune_unused_images {
        return Ok(0);
    }
    let defs = defs();
    let strip = |id: &str| id.trim().trim_start_matches("sha256:").to_string();

    // Images definitions use: by id (a short name and its fully qualified form resolve
    // to the same image) and, as a second guard, by the name as written.
    let mut keep = std::collections::HashSet::new();
    let mut keep_names = std::collections::HashSet::new();
    for d in &defs {
        let Some(c) = &d.container else { continue };
        keep_names.insert(c.image.clone());
        if !image_exists(cfg, "_gc", &c.image)? {
            continue; // not pulled yet: nothing to keep
        }
        let r = run_helper(cfg, "_gc", "op", &os(&["image", "inspect", "--format", "{{.Id}}", &c.image]), OP_TIMEOUT, None, None)?;
        // It exists, so any failure here means we cannot tell what is in use.
        anyhow::ensure!(r.success(), "podman image inspect {}: {}", c.image, r.describe());
        keep.insert(strip(&r.stdout));
    }

    let r = run_helper(
        cfg,
        "_gc",
        "op",
        &os(&["images", "--no-trunc", "--format", "{{.ID}}\t{{.Repository}}:{{.Tag}}"]),
        OP_TIMEOUT,
        None,
        None,
    )?;
    anyhow::ensure!(r.success(), "podman images: {}", r.describe());
    // id -> every name it carries (all must go for the image to go).
    let mut unused: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for line in r.stdout.lines() {
        let Some((id, name)) = line.split_once('\t') else { continue };
        let id = strip(id);
        let name = name.trim();
        if id.is_empty() || keep.contains(&id) || keep_names.contains(name) {
            keep.insert(id); // every name of a kept image stays
            continue;
        }
        let refs = unused.entry(id.clone()).or_default();
        // By id, never by name: a name is resolved again at removal time and could point
        // at a different image by then.
        if !refs.contains(&id) {
            refs.push(id);
        }
        if !name.contains("<none>") {
            refs.push(name.to_string());
        }
    }
    unused.retain(|id, _| !keep.contains(id));
    let mut removed = 0;
    for (id, refs) in unused {
        // All its names together (an id alone is refused for a multi-name image), or the
        // id for an untagged one. Under the store lock no fetch can move a name to a
        // different image meanwhile. Never forced: refused (kept) if a container uses it.
        let names: Vec<String> = refs.iter().filter(|r| **r != id).cloned().collect();
        let mut args = vec!["rmi".to_string()];
        if names.is_empty() {
            args.push(id.clone());
        } else {
            args.extend(names);
        }
        let r = run_helper(cfg, "_gc", "op", &args.iter().map(OsString::from).collect::<Vec<_>>(), OP_TIMEOUT, None, None)?;
        if r.success() {
            removed += 1;
            pm_event("container", None, format!("image_gc removed id={} refs={refs:?}", &id[..id.len().min(12)]));
        } else {
            pm_event("container", None, format!("image_gc kept id={} reason={}", &id[..id.len().min(12)], r.describe()));
        }
    }
    Ok(removed)
}
