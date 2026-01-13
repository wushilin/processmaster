use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MasterConfig {
    #[serde(default = "default_cgroup_root")]
    pub cgroup_root: String,

    #[serde(default = "default_cgroup_name")]
    pub cgroup_name: String,

    #[serde(default = "default_max")]
    pub cgroup_memory_max: String,
    #[serde(default = "default_max")]
    pub cgroup_memory_swap_max: String,
    #[serde(default = "default_max")]
    pub cgroup_cpu_max: String,

    /// If true (default), enable all controllers listed in `cgroup.controllers` into `cgroup.subtree_control`
    /// for the master cgroup. This allows child cgroups to use any available controllers.
    #[serde(default = "default_subtree_control_allow")]
    pub cgroup_subtree_control_allow: bool,

    #[serde(default = "default_sock")]
    pub sock: PathBuf,

    /// Unix socket owner (username). Applied on daemon start (requires root to chown).
    #[serde(default = "default_sock_owner")]
    pub sock_owner: Option<String>,
    /// Unix socket group (group name). Applied on daemon start (requires root to chown).
    #[serde(default = "default_sock_group")]
    pub sock_group: Option<String>,
    /// Unix socket mode (octal), e.g. 660 or "660" or "0660".
    #[serde(default = "default_sock_mode", deserialize_with = "deserialize_sock_mode")]
    pub sock_mode: u32,

    #[serde(default = "default_config_directory")]
    pub config_directory: PathBuf,

    /// Optional "implicit services" directory: each direct child directory is treated as a service
    /// definition with defaults (working dir = that directory, start = ./run.sh, etc).
    ///
    /// This also serves as the default base directory for app configs that omit
    /// `process.working_directory`: `${auto_service_directory}/${application}`.
    #[serde(default)]
    pub auto_service_directory: Option<PathBuf>,

    /// Default user for newly auto-generated `service.yml` under `global.auto_service_directory`.
    ///
    /// Semantics:
    /// - missing: "root"
    /// - null: "root"
    /// - non-empty string: used as-is (trimmed)
    pub default_service_user: String,

    /// Default group for newly auto-generated `service.yml` under `global.auto_service_directory`.
    ///
    /// Semantics:
    /// - missing: "root"
    /// - null: "root"
    /// - non-empty string: used as-is (trimmed)
    pub default_service_group: String,

    /// Optional embedded web console (axum) configuration.
    #[serde(default)]
    pub web_console: WebConsoleConfig,

    /// Optional: operator-triggered admin commands (run as root, from working dir '.').
    #[serde(default)]
    pub admin_actions: BTreeMap<String, AdminActionConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminActionConfig {
    /// Optional button label; defaults to the map key.
    #[serde(default)]
    pub label: Option<String>,
    /// Command argv list.
    pub command: Vec<String>,
}

// -------- YAML file schema (grouped only; strict) --------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CgroupConfigFile {
    #[serde(default = "default_cgroup_root")]
    root: String,
    #[serde(default = "default_cgroup_name")]
    name: String,
    #[serde(default = "default_max")]
    memory_max: String,
    #[serde(default = "default_max")]
    memory_swap_max: String,
    #[serde(default = "default_max")]
    cpu_max: String,
    #[serde(default = "default_subtree_control_allow")]
    subtree_control_allow: bool,
}

fn default_unix_socket_path() -> PathBuf {
    default_sock()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnixSocketConfigFile {
    #[serde(default = "default_unix_socket_path")]
    path: PathBuf,
    #[serde(default = "default_sock_owner")]
    owner: Option<String>,
    #[serde(default = "default_sock_group")]
    group: Option<String>,
    #[serde(default = "default_sock_mode", deserialize_with = "deserialize_sock_mode")]
    mode: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct GlobalConfigFile {
    #[serde(default)]
    config_directory: Option<PathBuf>,
    #[serde(default)]
    auto_service_directory: Option<PathBuf>,
    #[serde(default)]
    default_service_user: Option<String>,
    #[serde(default)]
    default_service_group: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebConsoleConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_web_bind")]
    pub bind: String,
    #[serde(default = "default_web_port")]
    pub port: u16,
    #[serde(default)]
    pub tls: WebConsoleTlsConfig,
    #[serde(default)]
    pub auth: WebConsoleAuthConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebConsoleTlsConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Path to a CA bundle PEM (required for mTLS).
    #[serde(default)]
    pub ca_pem: Option<String>,
    /// Path to server certificate PEM.
    #[serde(default)]
    pub server_cert_pem: Option<String>,
    /// Path to server private key PEM.
    #[serde(default)]
    pub server_key_pem: Option<String>,
    /// Optional extra host to include in TLS auto-generated server certificate SANs.
    /// Use this when clients access the web console via a stable hostname, e.g. `some-domain.com`.
    #[serde(default)]
    pub client_host: Option<String>,
    #[serde(default)]
    pub mtls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct WebConsoleAuthConfig {
    #[serde(default)]
    pub basic: WebConsoleBasicAuthConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebConsoleBasicAuthConfig {
    /// List of htpasswd entries, e.g. `user:$2y$05$...`
    #[serde(default)]
    pub users: Vec<String>,
}

impl Default for WebConsoleBasicAuthConfig {
    fn default() -> Self {
        // Default admin/admin for initial bootstrapping.
        // NOTE: operators should override this in config.yaml.
        Self {
            users: vec![
                "admin:$2a$10$jqNWtAzhWEVlPnvJwyI6g.Nwb8YPU5ypCED9lBEhahUSs13ac1MPe".to_string(),
            ],
        }
    }
}

impl Default for WebConsoleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_web_bind(),
            port: default_web_port(),
            tls: WebConsoleTlsConfig::default(),
            auth: WebConsoleAuthConfig::default(),
        }
    }
}

impl Default for WebConsoleTlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ca_pem: None,
            server_cert_pem: None,
            server_key_pem: None,
            client_host: None,
            mtls: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MasterConfigFile {
    #[serde(default)]
    cgroup: Option<CgroupConfigFile>,
    #[serde(default)]
    unix_socket: Option<UnixSocketConfigFile>,
    #[serde(default)]
    global: Option<GlobalConfigFile>,
    #[serde(default)]
    web_console: Option<WebConsoleConfigFile>,
    #[serde(default)]
    admin_actions: Option<BTreeMap<String, AdminActionConfigFile>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminActionConfigFile {
    #[serde(default)]
    label: Option<String>,
    command: Vec<String>,
}


fn default_cgroup_root() -> String {
    "/sys/fs/cgroup".to_string()
}
fn default_cgroup_name() -> String {
    "processmaster".to_string()
}
fn default_max() -> String {
    "MAX".to_string()
}
fn default_subtree_control_allow() -> bool {
    true
}
fn default_sock() -> PathBuf {
    "/tmp/processmaster.sock".into()
}
fn default_sock_mode() -> u32 {
    0o600
}
fn default_sock_owner() -> Option<String> {
    Some("root".to_string())
}
fn default_sock_group() -> Option<String> {
    Some("root".to_string())
}
fn default_config_directory() -> PathBuf {
    "config.d".into()
}

fn default_web_bind() -> String {
    "0.0.0.0".to_string()
}

fn default_web_port() -> u16 {
    9001
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebConsoleConfigFile {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_web_bind")]
    bind: String,
    #[serde(default = "default_web_port")]
    port: u16,
    #[serde(default)]
    tls: Option<WebConsoleTlsConfigFile>,
    #[serde(default)]
    auth: Option<WebConsoleAuthConfigFile>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebConsoleTlsConfigFile {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    ca_pem: Option<String>,
    #[serde(default)]
    server_cert_pem: Option<String>,
    #[serde(default)]
    server_key_pem: Option<String>,
    #[serde(default)]
    client_host: Option<String>,
    #[serde(default)]
    mtls: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebConsoleAuthConfigFile {
    #[serde(default)]
    basic: Option<WebConsoleBasicAuthConfigFile>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebConsoleBasicAuthConfigFile {
    #[serde(default)]
    users: Vec<String>,
}

fn deserialize_sock_mode<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    let v = serde_yaml::Value::deserialize(deserializer)?;
    match v {
        serde_yaml::Value::Number(n) => n
            .as_u64()
            .map(|x| x as u32)
            .ok_or_else(|| D::Error::custom("sock_mode must be an integer")),
        serde_yaml::Value::String(s) => parse_mode_str(&s).map_err(D::Error::custom),
        _ => Err(D::Error::custom(
            "sock_mode must be an integer or string (e.g. 660 or \"0660\")",
        )),
    }
}

fn parse_mode_str(s: &str) -> Result<u32, String> {
    let t = s.trim();
    let t = t.strip_prefix("0o").unwrap_or(t);
    let t = t.strip_prefix("0O").unwrap_or(t);
    let t = t.strip_prefix("0").unwrap_or(t);
    u32::from_str_radix(t, 8).map_err(|e| format!("invalid sock_mode {s:?}: {e}"))
}

pub fn load_master_config(config_path: &Path) -> anyhow::Result<MasterConfig> {
    let raw = std::fs::read_to_string(config_path)
        .map_err(|e| anyhow::anyhow!("failed to read config {}: {e}", config_path.display()))?;
    let file_cfg: MasterConfigFile = serde_yaml::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("failed to parse config {}: {e}", config_path.display()))?;

    // Start from defaults (processmaster + MAX all the way) and overlay provided groups.
    let mut cfg = MasterConfig {
        cgroup_root: default_cgroup_root(),
        cgroup_name: default_cgroup_name(),
        cgroup_memory_max: default_max(),
        cgroup_memory_swap_max: default_max(),
        cgroup_cpu_max: default_max(),
        cgroup_subtree_control_allow: default_subtree_control_allow(),
        sock: default_sock(),
        sock_owner: default_sock_owner(),
        sock_group: default_sock_group(),
        sock_mode: default_sock_mode(),
        config_directory: default_config_directory(),
        auto_service_directory: None,
        default_service_user: "root".to_string(),
        default_service_group: "root".to_string(),
        web_console: WebConsoleConfig::default(),
        admin_actions: BTreeMap::new(),
    };

    if let Some(cg) = file_cfg.cgroup {
        cfg.cgroup_root = cg.root;
        cfg.cgroup_name = cg.name;
        cfg.cgroup_memory_max = cg.memory_max;
        cfg.cgroup_memory_swap_max = cg.memory_swap_max;
        cfg.cgroup_cpu_max = cg.cpu_max;
        cfg.cgroup_subtree_control_allow = cg.subtree_control_allow;
    }
    if let Some(us) = file_cfg.unix_socket {
        cfg.sock = us.path;
        cfg.sock_owner = us.owner;
        cfg.sock_group = us.group;
        cfg.sock_mode = us.mode;
    }
    if let Some(gl) = file_cfg.global {
        anyhow::ensure!(
            gl.config_directory.is_some() || gl.auto_service_directory.is_some(),
            "global must define at least one of: config_directory, auto_service_directory"
        );
        cfg.auto_service_directory = gl.auto_service_directory;
        cfg.default_service_user = gl.default_service_user.unwrap_or_else(|| "root".to_string());
        cfg.default_service_group = gl.default_service_group.unwrap_or_else(|| "root".to_string());

        cfg.default_service_user = cfg.default_service_user.trim().to_string();
        cfg.default_service_group = cfg.default_service_group.trim().to_string();
        anyhow::ensure!(
            !cfg.default_service_user.is_empty(),
            "global.default_service_user must not be empty (use null for default \"root\")"
        );
        anyhow::ensure!(
            !cfg.default_service_group.is_empty(),
            "global.default_service_group must not be empty (use null for default \"root\")"
        );
        if let Some(cd) = gl.config_directory {
            cfg.config_directory = cd;
        }
    } else {
        anyhow::bail!("missing required config section: global (must define config_directory and/or auto_service_directory)");
    }
    if let Some(wc) = file_cfg.web_console {
        cfg.web_console.enabled = wc.enabled;
        cfg.web_console.bind = wc.bind;
        cfg.web_console.port = wc.port;

        if let Some(tls) = wc.tls {
            cfg.web_console.tls.enabled = tls.enabled;
            cfg.web_console.tls.ca_pem = tls.ca_pem;
            cfg.web_console.tls.server_cert_pem = tls.server_cert_pem;
            cfg.web_console.tls.server_key_pem = tls.server_key_pem;
            cfg.web_console.tls.client_host = tls.client_host;
            cfg.web_console.tls.mtls = tls.mtls;
        }

        if let Some(auth) = wc.auth {
            if let Some(basic) = auth.basic {
                cfg.web_console.auth.basic.users = basic.users;
            }
        }
    }

    if let Some(actions) = file_cfg.admin_actions {
        for (name, a) in actions {
            anyhow::ensure!(!name.trim().is_empty(), "admin_actions: action name must not be empty");
            anyhow::ensure!(
                name.trim() == name,
                "admin_actions: action name must not have leading/trailing whitespace: {name:?}"
            );
            anyhow::ensure!(
                !a.command.is_empty(),
                "admin_actions.{name}.command must not be empty"
            );
            if let Some(label) = a.label.as_deref() {
                anyhow::ensure!(
                    !label.trim().is_empty(),
                    "admin_actions.{name}.label must not be empty if provided"
                );
            }
            cfg.admin_actions.insert(
                name,
                AdminActionConfig {
                    label: a.label,
                    command: a.command,
                },
            );
        }
    }

    // Validate uniqueness of action ids (names) in a canonicalized form.
    // This prevents confusing configs like `Foo` vs `foo` or trailing whitespace variants.
    let mut seen: HashMap<String, String> = HashMap::new(); // canonical -> original
    for name in cfg.admin_actions.keys() {
        let canon = name.trim().to_ascii_lowercase();
        if let Some(prev) = seen.insert(canon.clone(), name.clone()) {
            anyhow::bail!(
                "duplicate admin action id (case-insensitive) {canon:?} for actions {prev:?} and {name:?}"
            );
        }
    }

    // Resolve relative paths against the config file directory.
    let base = config_path.parent().unwrap_or_else(|| Path::new("."));
    if cfg.sock.is_relative() {
        cfg.sock = base.join(&cfg.sock);
    }
    if cfg.config_directory.is_relative() {
        cfg.config_directory = base.join(&cfg.config_directory);
    }
    if let Some(p) = cfg.auto_service_directory.clone() {
        if p.is_relative() {
            cfg.auto_service_directory = Some(base.join(p));
        }
    }

    // Resolve relative web_console TLS paths against the config file directory.
    if let Some(p) = cfg.web_console.tls.ca_pem.clone() {
        let pb = PathBuf::from(&p);
        if pb.is_relative() {
            cfg.web_console.tls.ca_pem = Some(base.join(pb).display().to_string());
        }
    }
    if let Some(p) = cfg.web_console.tls.server_cert_pem.clone() {
        let pb = PathBuf::from(&p);
        if pb.is_relative() {
            cfg.web_console.tls.server_cert_pem = Some(base.join(pb).display().to_string());
        }
    }
    if let Some(p) = cfg.web_console.tls.server_key_pem.clone() {
        let pb = PathBuf::from(&p);
        if pb.is_relative() {
            cfg.web_console.tls.server_key_pem = Some(base.join(pb).display().to_string());
        }
    }

    Ok(cfg)
}


