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
    /// Opt-in to serving the console over plain HTTP on a non-loopback address.
    ///
    /// Basic auth transmits the password base64-encoded, not encrypted, and this console
    /// is root-equivalent, so the daemon refuses that combination unless an operator has
    /// deliberately accepted it (e.g. a TLS-terminating reverse proxy on the same host).
    #[serde(default)]
    pub allow_plaintext_remote: bool,
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

/// Build a socket address from a bare IP string plus a port.
///
/// Deliberately not `format!("{bind}:{port}").parse()`: that syntax requires IPv6
/// literals to be bracketed, so a perfectly ordinary `bind: "::1"` would be rejected
/// as malformed. Parsing the address and the port separately accepts v4 and v6 alike.
pub fn parse_bind_addr(bind: &str, port: u16) -> Result<std::net::SocketAddr, String> {
    let host = bind.trim();
    if host.is_empty() {
        return Err("bind address is empty".to_string());
    }
    // Tolerate a bracketed IPv6 literal, since operators reasonably write both forms.
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let ip: std::net::IpAddr = host
        .parse()
        .map_err(|e| format!("invalid bind address {bind:?}: {e}"))?;
    Ok(std::net::SocketAddr::new(ip, port))
}

impl Default for MasterConfig {
    /// The configuration the daemon runs with when a YAML file sets nothing:
    /// `processmaster` under the cgroup root, no limits, an owner-only control socket,
    /// and the web console switched off.
    fn default() -> Self {
        Self {
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
        }
    }
}

/// The `admin`/`admin` bootstrap entry.
///
/// This hash is published in the README and in `examples/`, so it is public knowledge
/// and provides no security whatsoever. The daemon recognises it on startup and
/// refuses to serve the console on a non-loopback address while it is in use — see
/// `daemon::validate_web_console_config`.
pub const DEFAULT_BOOTSTRAP_BASIC_AUTH_ENTRY: &str =
    "admin:$2a$10$jqNWtAzhWEVlPnvJwyI6g.Nwb8YPU5ypCED9lBEhahUSs13ac1MPe";

impl Default for WebConsoleBasicAuthConfig {
    fn default() -> Self {
        // Default admin/admin for initial bootstrapping.
        // NOTE: operators must override this in config.yaml; the daemon will not expose
        // the console beyond loopback while this entry is present.
        Self {
            users: vec![DEFAULT_BOOTSTRAP_BASIC_AUTH_ENTRY.to_string()],
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
            allow_plaintext_remote: false,
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
/// Default control-socket path.
///
/// `/run/processmaster/` rather than `/tmp`: `/tmp` is world-writable, so any local user
/// can pre-create the socket path before the daemon starts. That both denies service
/// (the daemon sees a live socket and refuses to start a second instance) and lets the
/// squatter answer `pmctl` with fabricated status. `/run` is root-owned, and the daemon
/// creates its subdirectory 0700.
///
/// NOTE: this changes the default. Deployments that relied on the old default must set
/// `unix_socket.path: /tmp/processmaster.sock` explicitly, and point `PMCTL_SOCK` at
/// whichever path they choose.
fn default_sock() -> PathBuf {
    "/run/processmaster/processmaster.sock".into()
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
    #[serde(default)]
    allow_plaintext_remote: bool,
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
        serde_yaml::Value::Number(n) => {
            let raw = n
                .as_u64()
                .ok_or_else(|| D::Error::custom("sock_mode must be a non-negative integer"))?;
            parse_mode_number(raw).map_err(D::Error::custom)
        }
        serde_yaml::Value::String(s) => parse_mode_str(&s).map_err(D::Error::custom),
        _ => Err(D::Error::custom(
            "sock_mode must be an integer or string (e.g. 660 or \"0660\")",
        )),
    }
}

/// Highest bit pattern a file mode may carry (setuid/setgid/sticky + rwxrwxrwx).
pub(crate) const MAX_MODE: u32 = 0o7777;

/// Interpret a YAML *number* as an octal mode.
///
/// YAML 1.2 only treats `0o`-prefixed scalars as octal, so an unquoted `660` reaches
/// serde as decimal 660 — which as a raw mode is `0o1224`, not the `rw-rw----` the
/// operator meant. Modes are octal by universal convention, so re-read the decimal
/// digits as octal and `660`, `"660"`, and `0660` all agree.
pub(crate) fn parse_mode_number(n: u64) -> Result<u32, String> {
    parse_mode_str(&n.to_string())
}

pub(crate) fn parse_mode_str(s: &str) -> Result<u32, String> {
    let t = s.trim();
    let t = t
        .strip_prefix("0o")
        .or_else(|| t.strip_prefix("0O"))
        .unwrap_or(t);
    if t.is_empty() {
        return Err(format!("invalid mode {s:?}: empty"));
    }
    let v = u32::from_str_radix(t, 8)
        .map_err(|e| format!("invalid mode {s:?}: {e} (modes are octal, e.g. 0640)"))?;
    if v > MAX_MODE {
        return Err(format!(
            "invalid mode {s:?}: 0o{v:o} exceeds the maximum 0o{MAX_MODE:o}"
        ));
    }
    Ok(v)
}

pub fn load_master_config(config_path: &Path) -> anyhow::Result<MasterConfig> {
    let raw = std::fs::read_to_string(config_path)
        .map_err(|e| anyhow::anyhow!("failed to read config {}: {e}", config_path.display()))?;
    let file_cfg: MasterConfigFile = serde_yaml::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("failed to parse config {}: {e}", config_path.display()))?;

    // Start from defaults (processmaster + MAX all the way) and overlay provided groups.
    let mut cfg = MasterConfig::default();

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
        cfg.web_console.allow_plaintext_remote = wc.allow_plaintext_remote;

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



#[cfg(test)]
mod tests {
    use super::*;

    fn sock_mode_from_yaml(y: &str) -> Result<u32, String> {
        #[derive(Deserialize)]
        struct Holder {
            #[serde(deserialize_with = "deserialize_sock_mode")]
            mode: u32,
        }
        serde_yaml::from_str::<Holder>(y)
            .map(|h| h.mode)
            .map_err(|e| e.to_string())
    }

    // ---- octal mode parsing ----------------------------------------------------
    //
    // Security regression: YAML 1.2 only treats `0o`-prefixed scalars as octal, so an
    // unquoted `750` arrives as decimal 750 == 0o1356, whose "other" bits are `rw-`.
    // Since connect(2) on a unix socket requires *write* permission, that silently
    // published the root control socket to every local user.

    #[test]
    fn unquoted_yaml_integers_are_read_as_octal() {
        assert_eq!(sock_mode_from_yaml("mode: 660").unwrap(), 0o660);
        assert_eq!(sock_mode_from_yaml("mode: 750").unwrap(), 0o750);
        assert_eq!(sock_mode_from_yaml("mode: 700").unwrap(), 0o700);
        assert_eq!(sock_mode_from_yaml("mode: 600").unwrap(), 0o600);
    }

    #[test]
    fn all_spellings_of_a_mode_agree() {
        // The README promises `0660`, `"0660"` and `660` are interchangeable.
        let expected = 0o660;
        for y in ["mode: 0660", "mode: \"0660\"", "mode: 660", "mode: \"660\"", "mode: \"0o660\""] {
            assert_eq!(sock_mode_from_yaml(y).unwrap(), expected, "for {y}");
        }
    }

    #[test]
    fn mode_never_silently_widens_permissions() {
        // Whatever the spelling, "other" must not gain write access unless asked for.
        for y in ["mode: 0600", "mode: 600", "mode: 0640", "mode: 640", "mode: 0750", "mode: 750"] {
            let m = sock_mode_from_yaml(y).unwrap();
            assert_eq!(m & 0o002, 0, "{y} unexpectedly granted world-write (got 0o{m:o})");
        }
    }

    #[test]
    fn mode_rejects_non_octal_digits_and_oversized_values() {
        assert!(parse_mode_str("680").is_err(), "8 is not an octal digit");
        assert!(parse_mode_str("999").is_err());
        assert!(parse_mode_str("").is_err());
        assert!(parse_mode_str("rwx").is_err());
        // Above the setuid/setgid/sticky + rwxrwxrwx range.
        assert!(parse_mode_str("77777").is_err());
        assert_eq!(parse_mode_str("7777").unwrap(), 0o7777);
    }

    #[test]
    fn mode_accepts_the_full_legal_range() {
        assert_eq!(parse_mode_str("0").unwrap(), 0);
        assert_eq!(parse_mode_str("0000").unwrap(), 0);
        assert_eq!(parse_mode_str("777").unwrap(), 0o777);
        assert_eq!(parse_mode_number(4755).unwrap(), 0o4755);
    }

    // ---- bind address parsing --------------------------------------------------

    #[test]
    fn bind_accepts_ipv4_and_ipv6_alike() {
        // Regression: `format!("{bind}:{port}").parse()` rejected every IPv6 address,
        // because that syntax requires brackets. `bind: "::1"` is a normal thing to write.
        for (bind, port) in [
            ("127.0.0.1", 9001u16),
            ("0.0.0.0", 9001),
            ("::1", 9001),
            ("::", 9001),
            ("[::1]", 9001),
            ("  127.0.0.1  ", 80),
        ] {
            let a = parse_bind_addr(bind, port)
                .unwrap_or_else(|e| panic!("{bind:?} should parse: {e}"));
            assert_eq!(a.port(), port);
        }
    }

    #[test]
    fn bind_preserves_the_address_family() {
        assert!(parse_bind_addr("127.0.0.1", 1).unwrap().is_ipv4());
        assert!(parse_bind_addr("::1", 1).unwrap().is_ipv6());
        assert_eq!(parse_bind_addr("::1", 8080).unwrap().to_string(), "[::1]:8080");
    }

    #[test]
    fn bind_rejects_hostnames_and_junk() {
        // Only literal addresses: resolving a name here would be a surprising
        // network dependency during config validation.
        assert!(parse_bind_addr("localhost", 9001).is_err());
        assert!(parse_bind_addr("", 9001).is_err());
        assert!(parse_bind_addr("   ", 9001).is_err());
        assert!(parse_bind_addr("999.999.999.999", 9001).is_err());
        assert!(parse_bind_addr("127.0.0.1:9001", 9001).is_err());
    }

    // ---- defaults --------------------------------------------------------------

    #[test]
    fn default_socket_lives_outside_world_writable_directories() {
        // Regression: the default used to be /tmp/processmaster.sock, which any local
        // user could pre-create to deny service or to impersonate the daemon to pmctl.
        let p = default_sock();
        assert!(
            !p.starts_with("/tmp"),
            "default socket must not live in a world-writable directory, got {}",
            p.display()
        );
        assert!(p.is_absolute(), "socket path must be absolute");
        assert!(p.parent().is_some(), "socket must have a parent directory to lock down");
    }

    #[test]
    fn plaintext_remote_is_opt_in() {
        // The console can run admin_actions as root; serving basic auth in the clear on
        // a non-loopback address must require an explicit acknowledgement.
        let cfg = WebConsoleConfig::default();
        assert!(!cfg.allow_plaintext_remote);
        assert!(!cfg.tls.enabled, "TLS default is unchanged");
    }

    #[test]
    fn socket_defaults_are_owner_only() {
        // The socket is the only access control on the RPC protocol; if this test
        // starts failing, someone has widened the default reach of the daemon.
        assert_eq!(default_sock_mode(), 0o600);
        assert_eq!(default_sock_owner().as_deref(), Some("root"));
        assert_eq!(default_sock_group().as_deref(), Some("root"));
    }
}
