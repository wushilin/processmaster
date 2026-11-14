//! Container (podman) services: the `container:` section of a service definition, its
//! load-time validation, and the `podman run` argv it lowers to.
//!
//! Runtime operations (pull, stop, cleanup) live in `daemon::podman`; everything here is
//! pure so it can be tested without root or podman.

use crate::pm::app::EnvironmentVar;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// Podman itself (CLI + conmon + netavark) runs inside the service cgroup and needs about
/// 20 MB and ~20 tasks to start a container. Below these floors the start fails in
/// confusing ways (OOM-killed podman, netavark panics), so they are refused at load.
pub const MIN_CONTAINER_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
pub const MIN_CONTAINER_PIDS: u64 = 64;

/// The image source is checked before each start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PullPolicy {
    /// Pull before every start.
    Always,
    /// Pull only when the image is not in local storage.
    #[default]
    Missing,
    /// Never pull; the image must already be in local storage.
    Never,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContainerSection {
    pub(crate) image: String,
    #[serde(default)]
    pub(crate) image_archive: Option<PathBuf>,
    #[serde(default)]
    pub(crate) pull: Option<PullPolicy>,
    #[serde(default)]
    pub(crate) command: Option<Vec<String>>,
    #[serde(default, deserialize_with = "crate::pm::app::deserialize_environment")]
    pub(crate) env: Vec<EnvironmentVar>,
    #[serde(default)]
    pub(crate) volumes: Vec<String>,
    #[serde(default)]
    pub(crate) ports: Vec<String>,
    #[serde(default)]
    pub(crate) network: Option<String>,
    #[serde(default)]
    pub(crate) user: Option<String>,
    #[serde(default)]
    pub(crate) extra_args: Vec<String>,

    // Lifecycle settings. A container service has no `process:` section; these mean the
    // same as their `process.*` namesakes.
    /// Host directory that relative volume sources, `image_archive` and log paths
    /// resolve under. (Inside the container the image's WORKDIR applies.)
    #[serde(default)]
    pub(crate) working_directory: Option<PathBuf>,
    #[serde(default)]
    pub(crate) stop_signal: Option<String>,
    #[serde(default)]
    pub(crate) stop_grace_period_ms: Option<u64>,
    #[serde(default)]
    pub(crate) schedule: Option<String>,
    #[serde(default)]
    pub(crate) not_before: Option<String>,
    #[serde(default)]
    pub(crate) not_after: Option<String>,
    #[serde(default)]
    pub(crate) max_time_per_run: Option<String>,
}

impl ContainerSection {
    /// The lifecycle settings, as the `process:` section a plain service would have.
    pub(crate) fn take_process(&mut self) -> crate::pm::app::ProcessSection {
        crate::pm::app::ProcessSection::lifecycle(
            self.working_directory.take(),
            self.stop_signal.take(),
            self.stop_grace_period_ms.take(),
            self.schedule.take(),
            self.not_before.take(),
            self.not_after.take(),
            self.max_time_per_run.take(),
        )
    }
}

/// A validated `container:` section.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContainerSpec {
    pub image: String,
    /// Absolute path of an image archive (`podman save` output) to load instead of pulling.
    pub image_archive: Option<PathBuf>,
    pub pull: PullPolicy,
    /// Replaces the image's CMD.
    pub command: Option<Vec<String>>,
    /// Environment inside the container. Values may be `@file://` etc. indirections.
    pub env: Vec<EnvironmentVar>,
    pub volumes: Vec<VolumeSpec>,
    pub ports: Vec<String>,
    pub network: Option<String>,
    /// User inside the container (`--user`).
    pub user: Option<String>,
    pub extra_args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VolumeSpec {
    pub source: VolumeSource,
    /// Absolute path inside the container.
    pub target: String,
    /// Comma-separated mount options (`ro`, `z`, ...), if any.
    pub options: Option<String>,
}

/// Mounts are always explicit host folders or files; podman named volumes are not
/// supported (their data would live inside the container store, out of sight).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VolumeSource {
    /// A host path (absolute after resolution).
    Host(PathBuf),
}

impl VolumeSpec {
    pub fn to_arg(&self) -> String {
        let VolumeSource::Host(p) = &self.source;
        let src = p.display().to_string();
        match &self.options {
            Some(o) => format!("{src}:{}:{o}", self.target),
            None => format!("{src}:{}", self.target),
        }
    }
}

/// Lower and validate a `container:` section.
///
/// `expand` applies `%app_dir%` expansion; relative host paths resolve under
/// `working_directory`.
pub(crate) fn lower_container_section(
    sec: ContainerSection,
    working_directory: &Path,
    expand: &dyn Fn(&str) -> anyhow::Result<String>,
) -> anyhow::Result<ContainerSpec> {
    let image = sec.image.trim().to_string();
    validate_image_ref(&image)?;

    let image_archive = match sec.image_archive {
        None => None,
        Some(p) => {
            let s = p
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("container.image_archive is not valid UTF-8"))?;
            Some(resolve_host_path(&expand(s)?, working_directory, "container.image_archive")?)
        }
    };
    let pull = match (sec.pull, &image_archive) {
        (Some(p), Some(_)) if p != PullPolicy::Never => anyhow::bail!(
            "container.pull: {p:?} cannot be combined with container.image_archive \
             (the archive is the image source; omit pull)"
        ),
        (_, Some(_)) => PullPolicy::Never,
        (p, None) => p.unwrap_or_default(),
    };

    if let Some(cmd) = &sec.command {
        anyhow::ensure!(!cmd.is_empty(), "container.command must not be empty (omit it to use the image's CMD)");
    }
    let command = sec
        .command
        .map(|v| v.iter().map(|a| expand(a)).collect::<anyhow::Result<Vec<_>>>())
        .transpose()?;

    let mut env = Vec::with_capacity(sec.env.len());
    for v in sec.env {
        validate_container_env_name(&v.name)?;
        anyhow::ensure!(
            !env.iter().any(|e: &EnvironmentVar| e.name == v.name),
            "container.env: {} is set twice",
            v.name
        );
        env.push(EnvironmentVar { value: expand(&v.value)?, name: v.name });
    }

    let volumes = sec
        .volumes
        .iter()
        .map(|v| parse_volume(&expand(v)?, working_directory))
        .collect::<anyhow::Result<Vec<_>>>()?;

    for p in &sec.ports {
        validate_port(p)?;
    }

    if let Some(n) = &sec.network {
        anyhow::ensure!(
            !n.is_empty() && n.chars().all(|c| c.is_ascii_alphanumeric() || "_.-:/".contains(c)),
            "container.network {n:?} is not a valid network name or mode"
        );
    }
    if let Some(u) = &sec.user {
        anyhow::ensure!(
            !u.is_empty() && u.chars().all(|c| c.is_ascii_alphanumeric() || "_.-:".contains(c)),
            "container.user {u:?} must be a name or uid[:gid]"
        );
    }

    let extra_args = sec.extra_args.iter().map(|a| expand(a)).collect::<anyhow::Result<Vec<_>>>()?;
    validate_extra_args(&extra_args)?;

    Ok(ContainerSpec {
        image,
        image_archive,
        pull,
        command,
        env,
        volumes,
        ports: sec.ports,
        network: sec.network,
        user: sec.user,
        extra_args,
    })
}

fn validate_image_ref(image: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!image.is_empty(), "container.image must not be empty");
    anyhow::ensure!(
        !image.starts_with('-') && !image.chars().any(|c| c.is_whitespace() || c.is_control()),
        "container.image {image:?} is not a valid image reference"
    );
    for transport in ["oci-archive:", "docker-archive:", "oci:", "dir:"] {
        anyhow::ensure!(
            !image.starts_with(transport),
            "container.image {image:?}: running from {transport} leaves an untagged image behind on \
             every start; set container.image to the archive's tag and container.image_archive to the file"
        );
    }
    Ok(())
}

/// Names that the podman process itself depends on. Values for these cannot be handed
/// over through podman's own environment (`-e NAME`), so they go on the command line.
fn podman_reserved_env(name: &str) -> bool {
    // Exact names wherever possible: a reserved name's value goes on the command line, so
    // a broad prefix would put unrelated secrets (GOOGLE_API_KEY, ...) where `ps` shows them.
    const EXACT: &[&str] = &[
        "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "NOTIFY_SOCKET", "REGISTRY_AUTH_FILE",
        // podman's Go runtime
        "GODEBUG", "GOGC", "GOMAXPROCS", "GOMEMLIMIT", "GOTRACEBACK",
        // podman remote connections
        "CONTAINER_HOST", "CONTAINER_CONNECTION", "CONTAINER_SSHKEY", "CONTAINER_PASSPHRASE",
        "STORAGE_DRIVER", "STORAGE_OPTS", "SSL_CERT_FILE", "SSL_CERT_DIR",
    ];
    // LISTEN_*: socket activation, which podman would hand on to the container.
    const PREFIX: &[&str] = &["XDG_", "CONTAINERS_", "_CONTAINERS_", "PODMAN_", "BUILDAH_", "LD_", "DBUS_", "LISTEN_"];
    EXACT.contains(&name) || PREFIX.iter().any(|p| name.starts_with(p))
}

fn validate_container_env_name(name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!name.is_empty(), "container.env: variable name must not be empty");
    anyhow::ensure!(
        !name.chars().any(|c| matches!(c, '=' | '\0' | '*' | '?' | '[')),
        "container.env: variable name {name:?} must not contain '=', NUL or glob characters"
    );
    Ok(())
}

fn resolve_host_path(s: &str, working_directory: &Path, field: &str) -> anyhow::Result<PathBuf> {
    let p = PathBuf::from(s);
    anyhow::ensure!(
        !p.components().any(|c| matches!(c, Component::ParentDir)),
        "{field} {s:?} must not contain '..'"
    );
    let joined = if p.is_absolute() { p } else { working_directory.join(p) };
    // Drop `.` components so `./data` shows as `<wd>/data`.
    Ok(joined.components().filter(|c| !matches!(c, Component::CurDir)).collect())
}

/// Host paths that must never be relabelled (`:z`/`:Z`) or chowned (`:U`, recursive):
/// changing system content breaks other services (see podman-run(1), "Labeling Volume
/// Mounts").
fn is_system_path(p: &Path) -> bool {
    // `/var/lib/<app>` is ordinary application data and may be relabelled; `/var/lib`
    // itself and podman's own state are not.
    const TREES: &[&str] = &[
        "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/proc", "/sys", "/dev", "/run", "/var/run",
        "/var/lib/containers",
    ];
    const EXACT: &[&str] = &["/", "/home", "/root", "/var", "/var/lib", "/opt", "/srv", "/tmp", "/mnt", "/media"];
    EXACT.iter().any(|e| p == Path::new(e)) || TREES.iter().any(|t| p.starts_with(t))
}

/// `host:container[:options]`. The host side is a path: absolute, or relative to
/// working_directory (`./data`, `data/x`). A bare name would be a podman named volume,
/// which is not supported.
fn parse_volume(raw: &str, working_directory: &Path) -> anyhow::Result<VolumeSpec> {
    let parts: Vec<&str> = raw.split(':').collect();
    anyhow::ensure!(
        (2..=3).contains(&parts.len()) && parts.iter().all(|p| !p.is_empty()),
        "container.volumes {raw:?} must be host:container or host:container:options"
    );
    let (src, target) = (parts[0], parts[1]);
    anyhow::ensure!(
        target.starts_with('/') && !Path::new(target).components().any(|c| matches!(c, Component::ParentDir)),
        "container.volumes {raw:?}: the container path must be absolute without '..'"
    );
    anyhow::ensure!(
        src.starts_with('/') || src.starts_with('.') || src.contains('/'),
        "container.volumes {raw:?}: {src:?} would be a podman named volume, which is not supported; \
         mount a host folder instead (e.g. ./{src}:{target})"
    );
    let source = VolumeSource::Host(resolve_host_path(src, working_directory, "container.volumes")?);
    let options = parts.get(2).map(|o| o.to_string());
    if let Some(o) = &options {
        for opt in o.split(',') {
            anyhow::ensure!(
                !opt.is_empty() && opt.chars().all(|c| c.is_ascii_alphanumeric() || "_=-".contains(c)),
                "container.volumes {raw:?}: invalid option {opt:?}"
            );
            if let (VolumeSource::Host(h), "z" | "Z" | "U") = (&source, opt) {
                anyhow::ensure!(
                    !is_system_path(h),
                    "container.volumes {raw:?}: refusing to {} ({opt}) system path {}",
                    if opt == "U" { "chown" } else { "relabel" },
                    h.display()
                );
            }
        }
    }
    Ok(VolumeSpec { source, target: target.to_string(), options })
}

fn valid_port_range(s: &str) -> bool {
    let ok = |p: &str| p.parse::<u16>().is_ok_and(|n| n > 0);
    match s.split_once('-') {
        Some((a, b)) => ok(a) && ok(b),
        None => ok(s),
    }
}

/// `[ip:][host_port:]container_port[/tcp|udp|sctp]`, ports may be ranges (`8000-8010`),
/// an IPv6 address must be bracketed, and the host port may be empty (`127.0.0.1::80`).
fn validate_port(raw: &str) -> anyhow::Result<()> {
    let bad = || anyhow::anyhow!("container.ports {raw:?} must look like [ip:][host_port:]container_port[/tcp|udp|sctp]");
    let (spec, proto) = match raw.rsplit_once('/') {
        Some((s, p)) => (s, Some(p)),
        None => (raw, None),
    };
    if let Some(p) = proto {
        anyhow::ensure!(matches!(p, "tcp" | "udp" | "sctp"), bad());
    }
    let (ip, rest) = if let Some(r) = spec.strip_prefix('[') {
        let (ip, rest) = r.split_once("]:").ok_or_else(bad)?;
        anyhow::ensure!(ip.parse::<std::net::Ipv6Addr>().is_ok(), bad());
        (Some(ip), rest)
    } else {
        (None, spec)
    };
    let parts: Vec<&str> = rest.split(':').collect();
    match (ip, parts.as_slice()) {
        (None, [c]) => anyhow::ensure!(valid_port_range(c), bad()),
        (None, [h, c]) | (Some(_), [h, c]) => {
            anyhow::ensure!(valid_port_range(h) && valid_port_range(c), bad())
        }
        (Some(_), [c]) => anyhow::ensure!(valid_port_range(c), bad()),
        (None, [ip, h, c]) => {
            anyhow::ensure!(ip.parse::<std::net::Ipv4Addr>().is_ok(), bad());
            anyhow::ensure!((h.is_empty() || valid_port_range(h)) && valid_port_range(c), bad())
        }
        _ => anyhow::bail!(bad()),
    }
    Ok(())
}

/// Long options processmaster sets itself or that break supervision.
const DENIED_LONG: &[(&str, &str)] = &[
    ("--detach", "processmaster runs the container attached"),
    ("--rm", "processmaster always removes the container"),
    ("--name", "the name is pm-<instance>-<app>"),
    ("--replace", "processmaster removes stale containers itself"),
    ("--cgroups", "the container must stay in the service cgroup"),
    ("--cgroup-parent", "the container must stay in the service cgroup"),
    ("--cgroupns", "the container must stay in the service cgroup"),
    ("--restart", "restarts are handled by restart_policy"),
    ("--pod", "pods are not supported"),
    ("--pod-id-file", "pods are not supported"),
    ("--tty", "output goes through processmaster's log pumps"),
    ("--interactive", "stdin is not attached"),
    ("--attach", "processmaster attaches stdout and stderr"),
    ("--sig-proxy", "processmaster stops containers with podman stop"),
    ("--cidfile", "processmaster tracks the container by name"),
    ("--conmon-pidfile", "processmaster tracks the container by name"),
    ("--log-driver", "output goes through processmaster's log pumps"),
    ("--stop-signal", "use container.stop_signal"),
    ("--stop-timeout", "use container.stop_grace_period_ms"),
    ("--pull", "use container.pull"),
    ("--rmi", "images are managed with pmctl podman"),
    ("--cgroup-conf", "the service cgroup is managed by processmaster"),
    ("--sdnotify", "readiness is not tracked through sd_notify"),
    // podman's global options are also accepted after `run`; they would move the
    // container to a store or runtime processmaster does not manage.
    ("--root", "processmaster uses its own container store"),
    ("--runroot", "processmaster uses its own container store"),
    ("--storage-driver", "processmaster uses its own container store"),
    ("--storage-opt", "processmaster uses its own container store"),
    ("--imagestore", "processmaster uses its own container store"),
    ("--transient-store", "processmaster uses its own container store"),
    ("--volumepath", "processmaster uses its own container store"),
    ("--db-backend", "processmaster uses its own container store"),
    ("--tmpdir", "processmaster uses its own container store"),
    ("--cgroup-manager", "the container must stay in the service cgroup"),
    ("--runtime", "processmaster uses podman's configured runtime"),
    ("--runtime-flag", "processmaster uses podman's configured runtime"),
    ("--conmon", "processmaster uses podman's configured runtime"),
    ("--network-backend", "processmaster uses podman's configured network backend"),
    ("--network-config-dir", "processmaster uses podman's configured network backend"),
    ("--events-backend", "processmaster uses podman's configured events backend"),
    ("--hooks-dir", "processmaster uses podman's configured hooks"),
    ("--module", "processmaster uses podman's configuration"),
    ("--config", "processmaster uses podman's configuration"),
    ("--remote", "the container must run locally, in the service cgroup"),
    ("--url", "the container must run locally, in the service cgroup"),
    ("--connection", "the container must run locally, in the service cgroup"),
    ("--identity", "the container must run locally, in the service cgroup"),
    ("--ssh", "the container must run locally, in the service cgroup"),
    ("--rootfs", "the image comes from container.image"),
    ("--label-file", "use --label (processmaster.* labels are reserved)"),
    ("--help", "not an option for a service"),
    ("--syslog", "podman's own logging is not configured per service"),
    ("--trace", "podman's own logging is not configured per service"),
    ("--volume", "mounts come from container.volumes (host folders only)"),
    ("--mount", "mounts come from container.volumes (host folders only)"),
    ("--volumes-from", "mounts come from container.volumes (host folders only)"),
    ("--out", "output goes through processmaster's log pumps"),
    ("--noout", "output goes through processmaster's log pumps"),
];
/// Prefixes of refused long options. Health checks run from systemd timers outside the
/// service cgroup; processmaster disables them (`--health-cmd=none`).
const DENIED_LONG_PREFIX: &[(&str, &str)] = &[("--health-", "health checks run outside the service cgroup and are not supported")];
/// Refused short flags: -d, -t, -i, -a, and -v (mounts come from container.volumes).
const DENIED_SHORT: &[(char, &str)] = &[
    ('v', "mounts come from container.volumes (host folders only)"),
    ('d', "processmaster runs the container attached"),
    ('t', "output goes through processmaster's log pumps"),
    ('i', "stdin is not attached"),
    ('a', "processmaster attaches stdout and stderr"),
];
/// podman-run long options that take no value (podman 5.x `podman run --help`); every
/// other long option given without `=` consumes the next argument.
const BOOL_LONG: &[&str] = &[
    "--detach", "--disable-content-trust", "--env-host", "--http-proxy", "--init", "--interactive",
    "--no-healthcheck", "--no-hostname", "--no-hosts", "--oom-kill-disable", "--passwd", "--privileged",
    "--publish-all", "--quiet", "--read-only", "--read-only-tmpfs", "--replace", "--rm", "--rmi", "--rootfs",
    "--sig-proxy", "--tls-verify", "--tty", "--unsetenv-all",
];
/// podman-run short options that consume a value (the rest of the cluster).
const SHORT_WITH_VALUE: &str = "acehlmpuvw";

fn validate_extra_args(args: &[String]) -> anyhow::Result<()> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            anyhow::bail!("container.extra_args: '--' is not allowed (the image comes from container.image)");
        }
        if !a.starts_with('-') {
            // Only a value for the option before it. Anything else would become the image
            // (and container.image its command).
            let prev = i.checked_sub(1).map(|j| args[j].as_str()).unwrap_or("");
            let prev_takes_value = prev.starts_with('-') && !prev.contains('=') && prev != "-" && {
                if prev.starts_with("--") {
                    !BOOL_LONG.contains(&prev)
                } else {
                    // A short cluster takes the next token only if its value letter ends it.
                    prev[1..].chars().last().is_some_and(|c| SHORT_WITH_VALUE.contains(c))
                }
            };
            anyhow::ensure!(
                prev_takes_value,
                "container.extra_args: {a:?} is not an option or an option's value \
                 (use --flag=value for options; the image and command come from container.image / container.command)"
            );
            i += 1;
            continue;
        }
        if let Some(long) = a.strip_prefix("--") {
            let name = format!("--{}", long.split('=').next().unwrap_or(""));
            if let Some((_, why)) = DENIED_LONG.iter().find(|(d, _)| *d == name) {
                anyhow::bail!("container.extra_args: {name} is not allowed ({why})");
            }
            if let Some((_, why)) = DENIED_LONG_PREFIX.iter().find(|(d, _)| name.starts_with(d)) {
                anyhow::bail!("container.extra_args: {name} is not allowed ({why})");
            }
            if name == "--label" {
                let v = a.split_once('=').map(|(_, v)| v).or(args.get(i + 1).map(String::as_str));
                anyhow::ensure!(
                    !v.unwrap_or("").starts_with("processmaster."),
                    "container.extra_args: processmaster.* labels are reserved"
                );
            }
        } else if let Some(cluster) = a.strip_prefix('-') {
            for c in cluster.chars() {
                if let Some((_, why)) = DENIED_SHORT.iter().find(|(d, _)| *d == c) {
                    anyhow::bail!("container.extra_args: -{c} is not allowed ({why})");
                }
                if c == 'l' {
                    let rest = &cluster[cluster.find('l').map(|p| p + 1).unwrap_or(cluster.len())..];
                    let v = if rest.is_empty() { args.get(i + 1).map(String::as_str).unwrap_or("") } else { rest };
                    anyhow::ensure!(
                        !v.trim_start_matches('=').starts_with("processmaster."),
                        "container.extra_args: processmaster.* labels are reserved"
                    );
                }
                if SHORT_WITH_VALUE.contains(c) {
                    break;
                }
            }
        }
        i += 1;
    }
    Ok(())
}

/// Instance id used in container names and labels: the master cgroup name with
/// characters podman does not accept in names replaced by '-'.
///
/// When characters had to be replaced, a hash of the original name is appended so that
/// e.g. `a/b` and `a-b` (two different daemons) never share containers or labels.
pub fn instance_id(cgroup_name: &str) -> String {
    let orig = cgroup_name.trim().trim_matches('/');
    let s: String = orig
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || "_.-".contains(c) { c } else { '-' })
        .collect();
    if s.is_empty() {
        return "processmaster".to_string();
    }
    if s == orig {
        return s;
    }
    // FNV-1a: stable across builds and platforms.
    let mut h: u32 = 0x811c9dc5;
    for b in orig.bytes() {
        h = (h ^ b as u32).wrapping_mul(0x01000193);
    }
    format!("{s}-{h:08x}")
}

pub fn container_name(instance: &str, app: &str) -> String {
    format!("pm-{instance}-{app}")
}

pub const LABEL_INSTANCE: &str = "processmaster.instance";
pub const LABEL_APP: &str = "processmaster.app";

/// The `podman run` invocation for a container service.
pub struct RunInvocation {
    pub argv: Vec<OsString>,
    /// Environment for the podman process: carries the values of `-e NAME` arguments.
    pub process_env: Vec<(OsString, OsString)>,
}

/// Build `podman run ...`. `env` holds decoded values in definition order.
///
/// Values travel through podman's own environment and argv only names them (`-e NAME`),
/// so they do not show in `ps` or the process view. Names podman itself depends on
/// (PATH, HOME, ...) are passed inline instead.
pub fn podman_run_invocation(
    spec: &ContainerSpec,
    instance: &str,
    app: &str,
    stop_signal: &str,
    env: &[(String, OsString)],
) -> RunInvocation {
    let mut argv: Vec<OsString> = Vec::new();
    let mut push = |s: &str| argv.push(OsString::from(s));
    for a in [
        "podman",
        "run",
        "--rm",
        "--name",
        &container_name(instance, app),
        "--cgroups=split",
        "--log-driver=none",
        "--pull=never",
        "--health-cmd=none",
        "--label",
        &format!("{LABEL_INSTANCE}={instance}"),
        "--label",
        &format!("{LABEL_APP}={app}"),
        "--stop-signal",
        stop_signal,
    ] {
        push(a);
    }
    let mut process_env = Vec::new();
    for (name, value) in env {
        argv.push("-e".into());
        if podman_reserved_env(name) {
            let mut kv = OsString::from(format!("{name}="));
            kv.push(value);
            argv.push(kv);
        } else {
            argv.push(name.into());
            process_env.push((OsString::from(name), value.clone()));
        }
    }
    for v in &spec.volumes {
        argv.push("-v".into());
        argv.push(v.to_arg().into());
    }
    for p in &spec.ports {
        argv.push("-p".into());
        argv.push(p.into());
    }
    if let Some(n) = &spec.network {
        argv.push(format!("--network={n}").into());
    }
    if let Some(u) = &spec.user {
        argv.push(format!("--user={u}").into());
    }
    argv.extend(spec.extra_args.iter().map(OsString::from));
    argv.push(spec.image.clone().into());
    if let Some(cmd) = &spec.command {
        argv.extend(cmd.iter().map(OsString::from));
    }
    RunInvocation { argv, process_env }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sec(yaml: &str) -> ContainerSection {
        serde_yaml::from_str(yaml).unwrap()
    }
    fn lower(yaml: &str) -> anyhow::Result<ContainerSpec> {
        lower_container_section(sec(yaml), Path::new("/srv/app"), &|s| Ok(s.replace("%app_dir%", "/srv/app")))
    }

    #[test]
    fn minimal_and_defaults() {
        let s = lower("image: nginx:1.27").unwrap();
        assert_eq!(s.image, "nginx:1.27");
        assert_eq!(s.pull, PullPolicy::Missing);
        assert!(s.command.is_none() && s.volumes.is_empty() && s.env.is_empty());
    }

    #[test]
    fn image_refs() {
        assert!(lower("image: ''").is_err());
        assert!(lower("image: '-it'").is_err());
        assert!(lower("image: 'a b'").is_err());
        let e = lower("image: oci-archive:/tmp/x.tar").unwrap_err().to_string();
        assert!(e.contains("image_archive"), "{e}");
        assert!(lower("image: docker.io/library/redis@sha256:abc").is_ok());
    }

    #[test]
    fn image_archive_resolves_and_forces_pull_never() {
        let s = lower("image: localhost/x:1\nimage_archive: images/x.tar").unwrap();
        assert_eq!(s.image_archive.unwrap(), Path::new("/srv/app/images/x.tar"));
        assert_eq!(s.pull, PullPolicy::Never);
        assert!(lower("image: x\nimage_archive: x.tar\npull: always").is_err());
        assert!(lower("image: x\nimage_archive: x.tar\npull: never").is_ok());
        assert!(lower("image: x\nimage_archive: ../x.tar").is_err());
    }

    #[test]
    fn volumes() {
        let s = lower(
            "image: x\nvolumes:\n  - ./data:/data\n  - logs/a:/logs:ro\n  - /etc/x.conf:/x.conf:ro\n  - '%app_dir%/y:/y:Z'",
        )
        .unwrap();
        let args: Vec<String> = s.volumes.iter().map(VolumeSpec::to_arg).collect();
        assert_eq!(
            args,
            ["/srv/app/data:/data", "/srv/app/logs/a:/logs:ro", "/etc/x.conf:/x.conf:ro", "/srv/app/y:/y:Z"]
        );
        for bad in ["data", "cache:/cache", "a:b", "./x:/y:ro:z", "../x:/y", "./x:/../y", "/etc:/etc:Z", "/etc/ssl:/s:z", "/:/host:z", "./x:/y:r o"] {
            assert!(lower(&format!("image: x\nvolumes: ['{bad}']")).is_err(), "{bad}");
        }
        assert!(lower("image: x\nvolumes: ['/srv/data:/d:Z']").is_ok());
    }

    #[test]
    fn ports() {
        for ok in ["80", "8080:80", "127.0.0.1:8080:80", "127.0.0.1::80", "[::1]:8080:80", "8000-8010:8000-8010/udp", "53:53/udp"] {
            assert!(validate_port(ok).is_ok(), "{ok}");
        }
        for bad in ["", "0", "x:80", "1.2.3:80:80", "80/icmp", "::1:80:80", "70000:80", "a:b:c:d"] {
            assert!(validate_port(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn extra_args_deny_list() {
        for ok in [
            vec!["--init"],
            vec!["--cap-add", "NET_ADMIN"],
            vec!["--userns=auto"],
            vec!["-e", "X=1"],
            vec!["-eDEBUG=1"],
            vec!["--label", "team=infra"],
            vec!["-m", "1g"],
            vec!["--entrypoint", "/bin/sh"],
            vec!["--init", "--cap-add=SYS_PTRACE"],
        ] {
            let v: Vec<String> = ok.iter().map(|s| s.to_string()).collect();
            assert!(validate_extra_args(&v).is_ok(), "{ok:?}");
        }
        for bad in [
            vec!["-d"],
            vec!["-it"],
            vec!["--detach"],
            vec!["--rm=false"],
            vec!["--name", "x"],
            vec!["--cgroups=enabled"],
            vec!["--restart=always"],
            vec!["--label", "processmaster.app=other"],
            vec!["--label=processmaster.instance=x"],
            vec!["-l", "processmaster.app=x"],
            vec!["--health-cmd", "true"],
            vec!["--pull=always"],
            vec!["--root=/var/lib/containers/storage"],
            vec!["--runroot", "/run/containers"],
            vec!["--cgroup-manager=systemd"],
            vec!["--health-interval=10s"],
            vec!["--rmi"],
            vec!["--"],
            vec!["alpine"],
            vec!["--init", "alpine"],
            vec!["--cap-add=X", "alpine"],
            vec!["-v", "/srv/x:/x"],
            vec!["--volume=data:/x"],
            vec!["--mount", "type=volume,src=x,dst=/x"],
            vec!["--volumes-from", "other"],
            vec!["--syslog", "alpine"],
            vec!["--help"],
            vec!["--label-file", "/tmp/labels"],
        ] {
            let v: Vec<String> = bad.iter().map(|s| s.to_string()).collect();
            assert!(validate_extra_args(&v).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn env_and_user_and_network() {
        let s = lower("image: x\nenv: {A: '1', PATH: /bin}\nuser: '999:999'\nnetwork: host").unwrap();
        assert_eq!(s.env.len(), 2);
        assert!(lower("image: x\nenv: [{name: A, value: '1'}, {name: A, value: '2'}]").is_err());
        assert!(lower("image: x\nuser: 'a b'").is_err());
        assert!(lower("image: x\nnetwork: 'a b'").is_err());
        assert!(lower("image: x\ncommand: []").is_err());
        assert!(lower("image: x\nenv: {'A*': '1'}").is_err());
        assert!(lower("image: x\nvolumes: ['/etc/app:/x:U']").is_err());
        assert!(lower("image: x\nvolumes: ['/var/lib:/x:Z']").is_err());
        assert!(lower("image: x\nvolumes: ['/var/lib/containers/storage:/x:U']").is_err());
        assert!(lower("image: x\nvolumes: ['/var/lib/myapp:/x:Z,U']").is_ok());
    }

    #[test]
    fn run_invocation_keeps_secret_values_out_of_argv() {
        let s = lower("image: redis:7\ncommand: [redis-server, --appendonly, 'yes']\nports: ['6379:6379']\nvolumes: ['./d:/data']").unwrap();
        let env = vec![
            ("SECRET".to_string(), OsString::from("hunter2")),
            ("HOME".to_string(), OsString::from("/data")),
        ];
        let inv = podman_run_invocation(&s, "processmaster", "redis", "SIGTERM", &env);
        let argv: Vec<String> = inv.argv.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        assert!(!argv.iter().any(|a| a.contains("hunter2")), "{argv:?}");
        assert!(argv.windows(2).any(|w| w[0] == "-e" && w[1] == "SECRET"));
        assert!(argv.windows(2).any(|w| w[0] == "-e" && w[1] == "HOME=/data"));
        assert_eq!(inv.process_env, [(OsString::from("SECRET"), OsString::from("hunter2"))]);
        assert!(argv.windows(2).any(|w| w[0] == "--name" && w[1] == "pm-processmaster-redis"));
        assert!(argv.contains(&"--cgroups=split".to_string()));
        let img = argv.iter().position(|a| a == "redis:7").unwrap();
        assert_eq!(&argv[img + 1..], ["redis-server", "--appendonly", "yes"]);
    }

    #[test]
    fn instance_ids() {
        assert_eq!(instance_id("processmaster"), "processmaster");
        assert!(instance_id("/a/b c").starts_with("a-b-c-"));
        assert_ne!(instance_id("a/b"), instance_id("a-b"));
        assert_eq!(instance_id("a-b"), "a-b");
        assert_eq!(instance_id(""), "processmaster");
    }
}
