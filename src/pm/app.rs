#![allow(private_interfaces)]

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::path::PathBuf;
use std::time::UNIX_EPOCH;
use chrono::{Local, NaiveDate, NaiveDateTime, TimeZone};

// ---------------- Restart strategy (used by processmaster supervisor) ----------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartConfig {
    #[serde(default)]
    pub policy: RestartPolicy,
    #[serde(default = "default_restart_backoff_ms")]
    pub restart_backoff_ms: u64,
    #[serde(default)]
    pub tolerance: RestartTolerance,
}

fn default_restart_backoff_ms() -> u64 {
    1000
}

impl Default for RestartConfig {
    fn default() -> Self {
        Self {
            policy: RestartPolicy::default(),
            restart_backoff_ms: default_restart_backoff_ms(),
            tolerance: RestartTolerance::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartTolerance {
    #[serde(default = "default_tolerance_max_restarts")]
    pub max_restarts: usize,
    /// Window duration in milliseconds.
    #[serde(default = "default_tolerance_duration_ms", deserialize_with = "deserialize_duration_ms")]
    pub duration: u64,
}

fn default_tolerance_max_restarts() -> usize {
    3
}
fn default_tolerance_duration_ms() -> u64 {
    3 * 60_000
}

impl Default for RestartTolerance {
    fn default() -> Self {
        Self {
            max_restarts: default_tolerance_max_restarts(),
            duration: default_tolerance_duration_ms(),
        }
    }
}

fn deserialize_duration_ms<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    let v = serde_yaml::Value::deserialize(deserializer)?;
    match v {
        serde_yaml::Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| D::Error::custom("duration must be a positive integer (ms)")),
        serde_yaml::Value::String(s) => parse_duration_str(&s).map_err(D::Error::custom),
        _ => Err(D::Error::custom(
            "duration must be an integer milliseconds or string like \"1m\"",
        )),
    }
}

fn parse_duration_str(s: &str) -> Result<u64, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("empty duration".to_string());
    }
    // e.g. 1000ms, 10s, 1m, 2h
    let mut idx = 0usize;
    for (i, ch) in t.char_indices() {
        if !(ch.is_ascii_digit() || ch == '.') {
            idx = i;
            break;
        }
    }
    if idx == 0 {
        return Err(format!("invalid duration: {s}"));
    }
    let (num_s, unit_s) = t.split_at(idx);
    let num: f64 = num_s.parse().map_err(|e| format!("invalid duration number: {e}"))?;
    if num < 0.0 {
        return Err("duration must be >= 0".to_string());
    }
    let unit = unit_s.trim().to_ascii_lowercase();
    let mult: f64 = match unit.as_str() {
        "ms" => 1.0,
        "s" => 1000.0,
        "m" => 60_000.0,
        "h" => 3_600_000.0,
        _ => return Err(format!("unknown duration unit {unit_s:?} (use ms/s/m/h)")),
    };
    Ok((num * mult).round() as u64)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RestartPolicy {
    /// String form like "never" or "always"
    String(String),
}

impl Default for RestartPolicy {
    fn default() -> Self {
        RestartPolicy::String("always".to_string())
    }
}

impl RestartPolicy {
    pub fn parsed(&self) -> anyhow::Result<RestartPolicyParsed> {
        let RestartPolicy::String(s) = self;
        let t = s.trim().to_ascii_lowercase();
        if t == "never" {
            return Ok(RestartPolicyParsed::Never);
        }
        if t == "always" {
            return Ok(RestartPolicyParsed::Always);
        }
        anyhow::bail!("unknown restart.policy: {s:?} (supported: \"never\" | \"always\")");
    }
}

#[derive(Debug, Clone)]
pub enum RestartPolicyParsed {
    Never,
    Always,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogRotation {
    Minutely,
    Hourly,
    Daily,
    Weekly,
    Monthly,
    None,
}

fn default_log_rotation() -> LogRotation {
    LogRotation::Daily
}

fn default_stop_command_stdout_path() -> Option<PathBuf> {
    Some("./logs/stop_command_stdout.log".into())
}

fn default_stop_command_stderr_path() -> Option<PathBuf> {
    Some("./logs/stop_command_stderr.log".into())
}

fn default_rotation_max_age_ms() -> u64 {
    // 30 days
    30 * 24 * 60 * 60 * 1000
}

fn default_rotation_backups() -> usize {
    10
}

fn default_log_compression_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogRotationMode {
    Time,
    Size,
}

impl Default for LogRotationMode {
    fn default() -> Self {
        // Prefer size-based rotation by default to keep disk usage bounded.
        LogRotationMode::Size
    }
}

fn default_rotation_size() -> String {
    // Accepts base10 suffixes; "10m" => 10 MB.
    "10m".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppDefinition {
    pub application: String,

    /// Required: working directory for the job.
    pub working_directory: PathBuf,

    /// Optional: path to stdout log file (absolute or relative to working_directory).
    #[serde(default)]
    pub log_stdout: Option<PathBuf>,
    /// Optional: path to stderr log file (absolute or relative to working_directory).
    #[serde(default)]
    pub log_stderr: Option<PathBuf>,

    /// Optional: where to redirect `stop_command` stdout (absolute or relative to working_directory).
    /// If unset, stop_command stdout is discarded.
    #[serde(default)]
    pub stop_command_stdout: Option<PathBuf>,
    /// Optional: where to redirect `stop_command` stderr (absolute or relative to working_directory).
    /// If unset, stop_command stderr is discarded.
    #[serde(default)]
    pub stop_command_stderr: Option<PathBuf>,

    /// Optional: additional log files the application writes to (absolute or relative to working_directory).
    #[serde(default)]
    pub alt_log_file_hint: Vec<PathBuf>,

    /// Command argv list (same shape as stop_command).
    pub start_command: Vec<String>,

    /// Environment variables for the service.
    /// Values may be plain strings or indirections like `@file://...`, `@base64://...`, `@hex://...`.
    #[serde(default)]
    pub environment: Vec<EnvironmentVar>,

    /// Optional restart strategy configuration.
    #[serde(default)]
    pub restart: Option<RestartConfig>,

    #[serde(default)]
    pub stop_signal: Option<String>,

    #[serde(default)]
    /// Command argv list.
    pub stop_command: Option<Vec<String>>,

    /// How long to wait (in ms) for the app to exit after stop_command / stop_signal before force-kill.
    #[serde(default = "default_stop_grace_period_ms")]
    pub stop_grace_period_ms: u64,

    /// CPU limit, e.g. "100m" or "1.5"
    #[serde(default)]
    pub max_cpu: Option<String>,

    /// Memory limit, e.g. "4GiB"
    #[serde(default)]
    pub max_memory: Option<String>,

    /// Swap limit, e.g. "0" (default no swap)
    #[serde(default)]
    pub max_swap: Option<String>,

    /// Optional: cgroup v2 io.weight (1..=10000). Proportional I/O share under contention.
    #[serde(default)]
    pub io_weight: Option<u16>,

    /// Optional: cgroup v2 io.max bandwidth cap (per block device).
    ///
    /// Example:
    ///   io_bandwidth:
    ///     - device: "253:8"
    ///       max_read_bytes_per_second: 75MiB   # rbps
    ///       max_write_bytes_per_second: 75MiB  # wbps
    ///       max_read_iops: 5000                # riops (optional)
    ///       max_write_iops: 2000               # wiops (optional)
    #[serde(default)]
    pub io_bandwidth: Option<IoBandwidthConfig>,

    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub group: Option<String>,

    /// Rotation mode for logs.
    #[serde(default)]
    pub rotation_mode: LogRotationMode,
    /// Time-based rotation frequency (only used when rotation_mode=time).
    #[serde(default = "default_log_rotation")]
    pub rotation_frequency: LogRotation,
    /// Time-based rotation max age (only used when rotation_mode=time).
    #[serde(default = "default_rotation_max_age_ms")]
    pub rotation_max_age_ms: u64,
    /// Size-based rotation threshold in bytes (only used when rotation_mode=size).
    #[serde(default)]
    pub rotation_size_bytes: Option<u64>,
    /// Size-based rotation backups to keep (only used when rotation_mode=size).
    #[serde(default)]
    pub rotation_backups: Option<usize>,

    /// Whether to compress rotated log files (best-effort using `gzip`).
    #[serde(default = "default_log_compression_enabled")]
    pub log_compression_enabled: bool,

    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Cron expression (future).
    #[serde(default)]
    pub schedule: Option<String>,
    /// Optional: do not trigger scheduled runs before this local time.
    /// Supports: "YYYY-MM-DD" or "YYYY-MM-DD HH:MM:SS".
    #[serde(default)]
    pub schedule_not_before_ms: Option<i64>,
    /// Optional: do not trigger scheduled runs after this local time.
    /// Supports: "YYYY-MM-DD" or "YYYY-MM-DD HH:MM:SS".
    #[serde(default)]
    pub schedule_not_after_ms: Option<i64>,
    /// Optional: maximum runtime per scheduled run (ms). If exceeded, daemon will attempt an OverTimeStop.
    /// Default: None (never).
    #[serde(default)]
    pub schedule_max_time_per_run_ms: Option<u64>,

    /// Optional: provisioning actions applied once per working_directory, guarded by `.pm_provisioned`.
    #[serde(default)]
    pub provisioning: Vec<ProvisioningEntry>,

    #[serde(skip)]
    pub source_file: Option<PathBuf>,

    /// Last modified time of `source_file` (ms since UNIX epoch), if known.
    /// Used for "update defs then restart modified services" semantics.
    #[serde(skip)]
    pub source_mtime_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IoBandwidthConfig(pub Vec<IoBandwidthRule>);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IoBandwidthRule {
    /// Block device identifier (major:minor), e.g. "253:8".
    ///
    /// This is written into cgroup v2 `io.max` exactly as provided.
    pub device: String,
    /// Optional cap for reads (rbps). Human size allowed (e.g. 75MiB, 10MB).
    #[serde(default)]
    pub max_read_bytes_per_second: Option<String>,
    /// Optional cap for writes (wbps). Human size allowed (e.g. 75MiB, 10MB).
    #[serde(default)]
    pub max_write_bytes_per_second: Option<String>,
    /// Optional cap for read IOPS (riops).
    #[serde(default)]
    pub max_read_iops: Option<u64>,
    /// Optional cap for write IOPS (wiops).
    #[serde(default)]
    pub max_write_iops: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningEntry {
    /// Target path (absolute or relative to `working_directory`).
    pub path: PathBuf,
    #[serde(default)]
    pub ownership: Option<ProvisioningOwnership>,
    /// File mode (octal), e.g. 0700. Applies to this path only (not recursive).
    #[serde(default, deserialize_with = "deserialize_mode_octal_opt")]
    pub mode: Option<u32>,
    /// Apply `cap_net_bind_service` file capability to this path (requires root / CAP_SETFCAP).
    #[serde(default)]
    pub add_net_bind_capability: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningOwnership {
    /// Owner username (or numeric id as string). Default: none.
    #[serde(default)]
    pub owner: Option<String>,
    /// Group name (or numeric id as string). Default: none.
    #[serde(default)]
    pub group: Option<String>,
    /// If true, apply ownership recursively under `path` (best-effort; symlinks are not followed).
    #[serde(default)]
    pub recursive: bool,
}

fn deserialize_mode_octal_opt<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    let v = Option::<serde_yaml::Value>::deserialize(deserializer)?;
    let Some(v) = v else { return Ok(None) };
    match v {
        serde_yaml::Value::Number(n) => {
            let u = n
                .as_u64()
                .ok_or_else(|| D::Error::custom("mode must be a non-negative integer or octal string like \"0700\""))?;
            Ok(Some(u as u32))
        }
        serde_yaml::Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                return Ok(None);
            }
            let t = t.strip_prefix("0o").unwrap_or(t);
            let parsed = u32::from_str_radix(t, 8).map_err(|e| D::Error::custom(format!("invalid mode {s:?}: {e}")))?;
            Ok(Some(parsed))
        }
        _ => Err(D::Error::custom("mode must be an integer or octal string like \"0700\"")),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentVar {
    pub name: String,
    pub value: String,
}

fn default_enabled() -> bool {
    true
}

fn default_stop_grace_period_ms() -> u64 {
    5_000
}

fn default_start_command() -> Vec<String> {
    vec!["./run.sh".to_string()]
}

fn default_max_str() -> Option<String> {
    Some("MAX".to_string())
}

// ---------------- App YAML (grouped; strict) ----------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LogsSection {
    #[serde(default)]
    stdout: Option<PathBuf>,
    #[serde(default)]
    stderr: Option<PathBuf>,
    #[serde(default)]
    rotation_mode: LogRotationMode,
    // size-mode config
    #[serde(default)]
    rotation_size: Option<String>,
    #[serde(default)]
    rotation_backups: Option<usize>,
    // time-mode config
    #[serde(default)]
    rotation_frequency: Option<LogRotation>,
    #[serde(default)]
    rotation_max_age_ms: Option<u64>,
    #[serde(default = "default_log_compression_enabled")]
    compression_enabled: bool,
    #[serde(default = "default_stop_command_stdout_path")]
    stop_command_stdout: Option<PathBuf>,
    #[serde(default = "default_stop_command_stderr_path")]
    stop_command_stderr: Option<PathBuf>,
    /// Additional log files the app writes to.
    #[serde(default)]
    hints: Vec<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessSection {
    #[serde(default)]
    start_command: Option<Vec<String>>,
    #[serde(default)]
    stop_command: Option<Vec<String>>,
    #[serde(default)]
    stop_signal: Option<String>,
    #[serde(default)]
    stop_grace_period_ms: Option<u64>,
    /// Optional cron schedule, e.g. "* * * * *"
    #[serde(default)]
    schedule: Option<String>,
    /// Optional: do not trigger scheduled runs before this local time.
    /// Supports: "YYYY-MM-DD" or "YYYY-MM-DD HH:MM:SS".
    #[serde(default)]
    not_before: Option<String>,
    /// Optional: do not trigger scheduled runs after this local time.
    /// Supports: "YYYY-MM-DD" or "YYYY-MM-DD HH:MM:SS".
    #[serde(default)]
    not_after: Option<String>,
    /// Optional: maximum runtime per scheduled run (e.g. "30s"). Default: never.
    #[serde(default)]
    max_time_per_run: Option<String>,
    #[serde(default)]
    working_directory: Option<PathBuf>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    environment: Vec<EnvironmentVar>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GlobalSection {
    #[serde(default = "default_enabled")]
    enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResourcesSection {
    #[serde(default)]
    max_cpu: Option<String>,
    #[serde(default)]
    max_memory: Option<String>,
    #[serde(default)]
    max_swap: Option<String>,
    /// Optional: cgroup v2 io.weight (1..=10000).
    #[serde(default)]
    io_weight: Option<u16>,
    /// Optional: cgroup v2 io.max bandwidth cap (see `AppDefinition.io_bandwidth`).
    #[serde(default)]
    io_bandwidth: Option<IoBandwidthConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestartPolicySection {
    policy: String, // "always" | "never"
    #[serde(default)]
    restart_backoff_ms: Option<u64>,
    #[serde(default)]
    tolerance: Option<RestartTolerance>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(private_interfaces)]
struct AppConfigFile {
    #[serde(default)]
    application: Option<String>,
    #[serde(default)]
    logs: Option<LogsSection>,
    process: ProcessSection,
    #[serde(default)]
    global: Option<GlobalSection>,
    #[serde(default)]
    resources: Option<ResourcesSection>,
    #[serde(default)]
    restart_policy: Option<RestartPolicySection>,
    #[serde(default)]
    provisioning: Vec<ProvisioningEntry>,
}

impl AppConfigFile {
    pub fn into_definition(
        self,
        source_file: Option<PathBuf>,
        auto_service_directory: Option<&Path>,
    ) -> anyhow::Result<AppDefinition> {
        let application: String = match self.application {
            Some(a) if !a.trim().is_empty() => a.trim().to_string(),
            _ => {
                let sf = source_file
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("missing application and no source_file to derive it from"))?;

                // Special-case: `<app>/service.yml` should default to the parent folder name, not "service".
                let stem = sf.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                let derived = if stem.trim().eq_ignore_ascii_case("service") {
                    sf.parent()
                        .and_then(|p| p.file_name())
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default()
                } else {
                    stem
                };

                anyhow::ensure!(
                    !derived.trim().is_empty(),
                    "missing application and could not derive from filename {}",
                    sf.display()
                );
                derived
            }
        };

        // Mutual exclusivity: schedule vs restart_policy
        if self.process.schedule.is_some() && self.restart_policy.is_some() {
            anyhow::bail!(
                "service {}: `process.schedule` and `restart_policy` are mutually exclusive",
                application
            );
        }

        fn parse_schedule_boundary_ms(spec: Option<String>, kind: &str, end_of_day: bool) -> anyhow::Result<Option<i64>> {
            let Some(raw) = spec else { return Ok(None) };
            let t = raw.trim();
            if t.is_empty() {
                return Ok(None);
            }
            // Date only
            if let Ok(d) = NaiveDate::parse_from_str(t, "%Y-%m-%d") {
                let dt = if end_of_day {
                    // inclusive end of day: 23:59:59.999
                    d.and_hms_milli_opt(23, 59, 59, 999).ok_or_else(|| anyhow::anyhow!("invalid {kind} date"))?
                } else {
                    d.and_hms_opt(0, 0, 0).ok_or_else(|| anyhow::anyhow!("invalid {kind} date"))?
                };
                let local = Local
                    .from_local_datetime(&dt)
                    .single()
                    .ok_or_else(|| anyhow::anyhow!("ambiguous local time for {kind}: {t:?}"))?;
                return Ok(Some(local.timestamp_millis()));
            }
            // Date-time
            let dt = NaiveDateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S")
                .or_else(|_| NaiveDateTime::parse_from_str(t, "%Y-%m-%d_%H:%M:%S"))
                .map_err(|e| anyhow::anyhow!("invalid {kind}: {t:?} (expected YYYY-MM-DD or YYYY-MM-DD HH:MM:SS): {e}"))?;
            let local = Local
                .from_local_datetime(&dt)
                .single()
                .ok_or_else(|| anyhow::anyhow!("ambiguous local time for {kind}: {t:?}"))?;
            Ok(Some(local.timestamp_millis()))
        }

        let schedule_not_before_ms = parse_schedule_boundary_ms(self.process.not_before.clone(), "process.not_before", false)?;
        let schedule_not_after_ms = parse_schedule_boundary_ms(self.process.not_after.clone(), "process.not_after", true)?;
        if let (Some(nb), Some(na)) = (schedule_not_before_ms, schedule_not_after_ms) {
            anyhow::ensure!(
                na >= nb,
                "service {}: process.not_after must be >= process.not_before",
                application
            );
        }

        let schedule_max_time_per_run_ms: Option<u64> = match self.process.max_time_per_run.clone() {
            None => None,
            Some(s) => {
                let t = s.trim();
                if t.is_empty() || t.eq_ignore_ascii_case("never") {
                    None
                } else {
                    Some(parse_duration_str(t).map_err(|e| {
                        anyhow::anyhow!(
                            "service {}: invalid process.max_time_per_run {:?}: {e}",
                            application,
                            t
                        )
                    })?)
                }
            }
        };

        // Stop behavior: stop_command vs stop_signal cannot both be set.
        if self.process.stop_command.is_some() && self.process.stop_signal.is_some() {
            anyhow::bail!(
                "service {}: choose exactly one of process.stop_command or process.stop_signal",
                application
            );
        }

        let logs = self.logs.unwrap_or(LogsSection {
            stdout: None,
            stderr: None,
            rotation_mode: LogRotationMode::default(),
            rotation_size: None,
            rotation_backups: None,
            rotation_frequency: None,
            rotation_max_age_ms: None,
            compression_enabled: default_log_compression_enabled(),
            stop_command_stdout: default_stop_command_stdout_path(),
            stop_command_stderr: default_stop_command_stderr_path(),
            hints: vec![],
        });
        let global = self.global.unwrap_or(GlobalSection { enabled: default_enabled() });
        let resources = self.resources.unwrap_or(ResourcesSection {
            max_cpu: default_max_str(),
            max_memory: default_max_str(),
            max_swap: default_max_str(),
            io_weight: None,
            io_bandwidth: None,
        });
        // Derive working directory if omitted: ${auto_service_directory}/${application}
        let working_directory = match self.process.working_directory {
            Some(wd) => wd,
            None => {
                let base = auto_service_directory.ok_or_else(|| {
                    anyhow::anyhow!(
                        "service {}: missing process.working_directory and global.auto_service_directory is not set",
                        application
                    )
                })?;
                base.join(&application)
            }
        };

        // Default start command if omitted.
        let start_command = self.process.start_command.unwrap_or_else(default_start_command);

        // Default restart config for non-scheduled apps if omitted.
        let restart = if self.process.schedule.is_some() {
            None
        } else {
            match self.restart_policy {
                None => Some(RestartConfig {
                    policy: RestartPolicy::default(),
                    restart_backoff_ms: default_restart_backoff_ms(),
                    tolerance: RestartTolerance::default(),
                }),
                Some(rp) => {
                    let parsed = RestartPolicy::String(rp.policy.clone()).parsed().map_err(|e| {
                        anyhow::anyhow!(
                            "service {}: invalid restart_policy.policy {:?}: {e}",
                            application,
                            rp.policy
                        )
                    })?;
                    if matches!(parsed, RestartPolicyParsed::Never) {
                        if rp.restart_backoff_ms.is_some() || rp.tolerance.is_some() {
                            anyhow::bail!(
                                "service {}: restart_policy.policy=never must not set restart_backoff_ms or tolerance",
                                application
                            );
                        }
                    }
                    if let Some(t) = rp.tolerance.as_ref() {
                        if t.max_restarts > 500 {
                            anyhow::bail!(
                                "service {}: restart_policy.tolerance.max_restarts={} exceeds limit 500",
                                application,
                                t.max_restarts
                            );
                        }
                    }
                    Some(RestartConfig {
                        policy: RestartPolicy::String(rp.policy),
                        restart_backoff_ms: rp.restart_backoff_ms.unwrap_or_else(default_restart_backoff_ms),
                        tolerance: rp.tolerance.unwrap_or_default(),
                    })
                }
            }
        };


        // Rotation config: exactly one mode.
        let rotation_mode = logs.rotation_mode;
        let (rotation_frequency, rotation_max_age_ms, rotation_size_bytes, rotation_backups) = match rotation_mode {
            LogRotationMode::Time => {
                if logs.rotation_size.is_some() || logs.rotation_backups.is_some() {
                    anyhow::bail!(
                        "service {}: logs.rotation_mode=time cannot set logs.rotation_size/rotation_backups",
                        application
                    );
                }
                let freq = logs.rotation_frequency.unwrap_or(default_log_rotation());
                let max_age = logs.rotation_max_age_ms.unwrap_or(default_rotation_max_age_ms());
                (freq, max_age, None, None)
            }
            LogRotationMode::Size => {
                if logs.rotation_frequency.is_some() || logs.rotation_max_age_ms.is_some() {
                    anyhow::bail!(
                        "service {}: logs.rotation_mode=size cannot set logs.rotation_frequency/rotation_max_age_ms",
                        application
                    );
                }
                let sz: String = logs.rotation_size.clone().unwrap_or_else(default_rotation_size);
                let bytes = crate::pm::daemon::parse_size_spec_bytes(&sz).map_err(|e| {
                    anyhow::anyhow!(
                        "service {}: invalid logs.rotation_size {sz:?}: {e}",
                        application
                    )
                })?;
                let backups = logs.rotation_backups.unwrap_or(default_rotation_backups());
                (default_log_rotation(), default_rotation_max_age_ms(), Some(bytes), Some(backups))
            }
        };

        let restart = restart;

        // If neither stop_command nor stop_signal provided, default to SIGTERM.
        let stop_signal = if self.process.stop_command.is_none() {
            Some(self.process.stop_signal.unwrap_or_else(|| "SIGTERM".to_string()))
        } else {
            None
        };

        Ok(AppDefinition {
            application,
            working_directory,
            log_stdout: logs.stdout,
            log_stderr: logs.stderr,
            stop_command_stdout: logs.stop_command_stdout,
            stop_command_stderr: logs.stop_command_stderr,
            alt_log_file_hint: logs.hints,
            start_command,
            environment: self.process.environment,
            restart,
            stop_signal,
            stop_command: self.process.stop_command,
            stop_grace_period_ms: self
                .process
                .stop_grace_period_ms
                .unwrap_or_else(default_stop_grace_period_ms),
            max_cpu: resources.max_cpu,
            max_memory: resources.max_memory,
            max_swap: resources.max_swap,
            io_weight: resources.io_weight,
            io_bandwidth: resources.io_bandwidth,
            user: self.process.user,
            group: self.process.group,
            rotation_mode,
            rotation_frequency,
            rotation_max_age_ms,
            rotation_size_bytes,
            rotation_backups,
            log_compression_enabled: logs.compression_enabled,
            enabled: global.enabled,
            schedule: self.process.schedule,
            schedule_not_before_ms,
            schedule_not_after_ms,
            schedule_max_time_per_run_ms,
            provisioning: self.provisioning,
            source_file,
            source_mtime_ms: None,
        })
    }
}

pub fn parse_app_definition_yaml(
    raw: &str,
    source_file: &Path,
    auto_service_directory: Option<&Path>,
) -> anyhow::Result<AppDefinition> {
    let file: AppConfigFile = serde_yaml::from_str(raw)
        .map_err(|e| anyhow::anyhow!("failed to parse app def {}: {e}", source_file.display()))?;
    let mut def = file.into_definition(Some(source_file.to_path_buf()), auto_service_directory)?;
    // Best-effort mtime capture for update/restart logic.
    def.source_mtime_ms = source_file
        .metadata()
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|mt| mt.duration_since(UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_millis()).ok());
    Ok(def)
}

/// Render a full `service.yml` for an auto-discovered service using canonical defaults.
///
/// This is intentionally centralized in `app.rs` so future config additions don’t require
/// remembering to update generation logic in `daemon.rs`.
pub(crate) fn render_auto_service_yaml(app: &str, working_directory: &Path) -> anyhow::Result<String> {
    #[derive(Debug, Clone, Serialize)]
    #[serde(deny_unknown_fields)]
    struct YamlFile {
        application: String,
        global: YamlGlobal,
        process: YamlProcess,
        logs: YamlLogs,
        resources: YamlResources,
        restart_policy: YamlRestartPolicy,
    }
    #[derive(Debug, Clone, Serialize)]
    #[serde(deny_unknown_fields)]
    struct YamlGlobal {
        enabled: bool,
    }
    impl Default for YamlGlobal {
        fn default() -> Self {
            Self {
                enabled: default_enabled(),
            }
        }
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(deny_unknown_fields)]
    struct YamlProcess {
        start_command: Vec<String>,
        stop_signal: String,
        stop_grace_period_ms: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schedule: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        user: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        group: Option<String>,
        working_directory: String,
        #[serde(default)]
        environment: Vec<EnvironmentVar>,
    }
    impl Default for YamlProcess {
        fn default() -> Self {
            Self {
                start_command: default_start_command(),
                stop_signal: "SIGTERM".to_string(),
                stop_grace_period_ms: default_stop_grace_period_ms(),
                schedule: None,
                user: None,
                group: None,
                working_directory: String::new(),
                environment: vec![],
            }
        }
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(deny_unknown_fields)]
    struct YamlLogs {
        stdout: String,
        stderr: String,
        rotation_mode: LogRotationMode,
        rotation_size: String,
        rotation_backups: usize,
        compression_enabled: bool,
        stop_command_stdout: String,
        stop_command_stderr: String,
        #[serde(default)]
        hints: Vec<String>,
    }
    impl Default for YamlLogs {
        fn default() -> Self {
            Self {
                stdout: "./logs/stdout.log".to_string(),
                stderr: "./logs/stderr.log".to_string(),
                rotation_mode: LogRotationMode::default(),
                rotation_size: default_rotation_size(),
                rotation_backups: default_rotation_backups(),
                compression_enabled: default_log_compression_enabled(),
                stop_command_stdout: default_stop_command_stdout_path()
                    .unwrap_or_else(|| "./stop_command_stdout.log".into())
                    .display()
                    .to_string(),
                stop_command_stderr: default_stop_command_stderr_path()
                    .unwrap_or_else(|| "./stop_command_stderr.log".into())
                    .display()
                    .to_string(),
                hints: vec![],
            }
        }
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(deny_unknown_fields)]
    struct YamlResources {
        max_cpu: String,
        max_memory: String,
        max_swap: String,
    }
    impl Default for YamlResources {
        fn default() -> Self {
            Self {
                max_cpu: default_max_str().unwrap_or_else(|| "MAX".to_string()),
                max_memory: default_max_str().unwrap_or_else(|| "MAX".to_string()),
                max_swap: default_max_str().unwrap_or_else(|| "MAX".to_string()),
            }
        }
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(deny_unknown_fields)]
    struct YamlRestartTolerance {
        max_restarts: usize,
        /// Window duration in milliseconds.
        duration: u64,
    }
    impl Default for YamlRestartTolerance {
        fn default() -> Self {
            Self {
                max_restarts: default_tolerance_max_restarts(),
                duration: default_tolerance_duration_ms(),
            }
        }
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(deny_unknown_fields)]
    struct YamlRestartPolicy {
        policy: String,
        restart_backoff_ms: u64,
        tolerance: YamlRestartTolerance,
    }
    impl Default for YamlRestartPolicy {
        fn default() -> Self {
            Self {
                policy: match RestartPolicy::default() {
                    RestartPolicy::String(s) => s,
                },
                restart_backoff_ms: default_restart_backoff_ms(),
                tolerance: YamlRestartTolerance::default(),
            }
        }
    }

    let mut process = YamlProcess::default();
    process.working_directory = working_directory.display().to_string();

    let out = YamlFile {
        application: app.to_string(),
        global: YamlGlobal::default(),
        process,
        logs: YamlLogs::default(),
        resources: YamlResources::default(),
        restart_policy: YamlRestartPolicy::default(),
    };

    serde_yaml::to_string(&out).map_err(|e| anyhow::anyhow!("failed to render auto service.yml: {e}"))
}

pub fn parse_cpu_millicores(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    if let Some(m) = s.strip_suffix('m').or_else(|| s.strip_suffix('M')) {
        return Ok(m.trim().parse()?);
    }
    let v: f64 = s.parse()?;
    if v < 0.0 {
        anyhow::bail!("cpu must be >= 0");
    }
    Ok((v * 1000.0).round() as u64)
}

pub fn normalize_swap_string(swap: Option<&str>) -> anyhow::Result<String> {
    // For historical compatibility with earlier examples, treat "0" as "no swap".
    let s = swap.unwrap_or("0").trim();
    if s == "0" {
        return Ok("0MiB".to_string());
    }
    normalize_memory_string(s)
}

pub fn normalize_memory_string(mem: &str) -> anyhow::Result<String> {
    let s = mem.trim();
    if s.eq_ignore_ascii_case("max") {
        // Accept MAX/max as a generic "no limit" marker.
        return Ok("MAX".to_string());
    }
    // If already ends with B/KB/KiB/MB/MiB/... just pass through after trimming.
    // This is intentionally permissive; validation can tighten later.
    Ok(s.to_string())
}

// Back-compat aliases (internal): kept temporarily to avoid any lingering references.
#[deprecated(note = "use normalize_memory_string")]
#[allow(dead_code)]
pub fn normalize_mem_for_launcher(mem: &str) -> anyhow::Result<String> {
    normalize_memory_string(mem)
}

#[deprecated(note = "use normalize_swap_string")]
#[allow(dead_code)]
pub fn normalize_swap_for_launcher(swap: Option<&str>) -> anyhow::Result<String> {
    normalize_swap_string(swap)
}


