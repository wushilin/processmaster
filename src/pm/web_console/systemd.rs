//! systemd units shown in the web console: listing, actions, logs and resource details.

use super::*;

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct SystemdServiceStatus {
    unit: String,
    phase: String, // RUNNING/STOPPED
    enabled: bool,
    unit_file_state: String,
    fragment_path: String,
    exec_start_path: String,
    main_pid: i32,
    cgroup_dir: String,
    pids: Vec<u32>,
    pid_uptimes_ms: Vec<i64>,
}

pub(super) fn validate_systemd_unit(unit: &str) -> anyhow::Result<()> {
    let t = unit.trim();
    anyhow::ensure!(!t.is_empty(), "unit is empty");
    anyhow::ensure!(t.ends_with(".service"), "only .service units are supported (got {t:?})");
    // A leading '-' would be parsed by root's systemctl as an option (`-H user@host`
    // opens SSH with root's keys). Callers also pass "--"; this is the belt.
    anyhow::ensure!(!t.starts_with('-'), "invalid unit name (leading '-'): {t:?}");
    anyhow::ensure!(
        t.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@' | ':' | '\\')),
        "invalid unit name (unsupported characters): {t:?}"
    );
    Ok(())
}

pub(super) fn validate_systemd_action(action: &str) -> anyhow::Result<&'static str> {
    match action {
        "start" => Ok("start"),
        "stop" => Ok("stop"),
        "restart" => Ok("restart"),
        _ => anyhow::bail!("unsupported action: {action:?} (allowed: start|stop|restart)"),
    }
}

pub(super) async fn run_cmd_timeout(mut cmd: Command, ms: u64) -> anyhow::Result<std::process::Output> {
    let fut = cmd.output();
    let out = tokio::time::timeout(std::time::Duration::from_millis(ms), fut)
        .await
        .map_err(|_| anyhow::anyhow!("command timed out after {ms}ms"))??;
    Ok(out)
}

pub(super) fn sysfs_cgroup_dir_from_control_group(control_group: &str) -> Option<PathBuf> {
    let cg = control_group.trim();
    if cg.is_empty() {
        return None;
    }
    // systemctl show ControlGroup is typically like "/system.slice/sshd.service"
    let rel = cg.trim_start_matches('/');
    if rel.is_empty() {
        return None;
    }
    Some(PathBuf::from("/sys/fs/cgroup").join(rel))
}






pub(super) async fn systemd_list_services() -> anyhow::Result<Vec<SystemdServiceStatus>> {
    // Bulk query for all service units. This is dramatically faster than per-unit `systemctl show`.
    let mut cmd = Command::new("systemctl");
    cmd.arg("show")
        .arg("--type=service")
        .arg("--all")
        .arg("--no-pager")
        .arg("--property=Id,ActiveState,SubState,MainPID,ControlGroup,UnitFileState,FragmentPath,ExecStart");
    // Generous: the first full listing after boot can take several seconds while systemd
    // loads every unit file; 3s made the console's first systemd view fail.
    let out = run_cmd_timeout(cmd, 10_000).await?;

    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        anyhow::bail!("systemctl show failed: {}", if err.is_empty() { out.status.to_string() } else { err });
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let clock = crate::pm::procfs::ProcClock::now();

    let mut services = vec![];
    for block in text.split("\n\n") {
        let mut id: Option<String> = None;
        let mut active: Option<String> = None;
        let mut sub: Option<String> = None;
        let mut main_pid: Option<i32> = None;
        let mut cg: Option<String> = None;
        let mut ufs: Option<String> = None;
        let mut frag: Option<String> = None;
        let mut exec_start: Option<String> = None;

        for line in block.lines() {
            let (k, v) = match line.split_once('=') {
                Some(kv) => kv,
                None => continue,
            };
            let v = v.trim().to_string();
            match k.trim() {
                "Id" => id = Some(v),
                "ActiveState" => active = Some(v),
                "SubState" => sub = Some(v),
                "MainPID" => {
                    let p = v.parse::<i32>().unwrap_or(0);
                    main_pid = Some(p);
                }
                "ControlGroup" => cg = Some(v),
                "UnitFileState" => ufs = Some(v),
                "FragmentPath" => frag = Some(v),
                "ExecStart" => exec_start = Some(v),
                _ => {}
            }
        }

        let Some(unit) = id else { continue };
        if !unit.ends_with(".service") {
            continue;
        }
        // Avoid odd corner cases: only list units we can later act on.
        if validate_systemd_unit(&unit).is_err() {
            continue;
        }

        let active_state = active.unwrap_or_else(|| "unknown".to_string());
        let sub_state = sub.unwrap_or_else(|| "".to_string());
        let mpid = main_pid.unwrap_or(0);
        let unit_file_state = ufs.unwrap_or_else(|| "unknown".to_string());
        let fragment_path = frag.unwrap_or_default();
        let exec_start_path = exec_start
            .as_deref()
            .and_then(parse_systemd_execstart_path)
            .unwrap_or_default();
        let enabled = unit_file_state.starts_with("enabled");
        let phase = if active_state == "active" && sub_state == "exited" {
            "EXITED"
        } else if active_state == "active" {
            "RUNNING"
        } else if active_state == "failed" {
            "FAILED"
        } else {
            "STOPPED"
        }
        .to_string();

        let cgroup_dir = cg.clone().unwrap_or_default();
        let sysfs_dir = cg.as_deref().and_then(sysfs_cgroup_dir_from_control_group);
        let pids = match sysfs_dir.as_deref() {
            Some(dir) if std::fs::metadata(dir).is_ok() => cgroup::list_pids(dir).unwrap_or_default(),
            _ => vec![],
        };
        let pid_uptimes_ms = clock.uptimes_ms(&pids);

        services.push(SystemdServiceStatus {
            unit,
            phase,
            enabled,
            unit_file_state,
            fragment_path,
            exec_start_path,
            main_pid: mpid,
            cgroup_dir,
            pids,
            pid_uptimes_ms,
        });
    }

    services.sort_by(|a, b| a.unit.cmp(&b.unit));
    Ok(services)
}

pub(super) fn parse_systemd_execstart_path(raw: &str) -> Option<String> {
    // `systemctl show -p ExecStart` commonly yields strings like:
    //   ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ... ; ... }
    // There may be multiple `{...}{...}` entries; we just take the first `path=...`.
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    let idx = t.find("path=")?;
    let rest = &t[idx + "path=".len()..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == ';' || c == '}' || c == ',' )
        .unwrap_or(rest.len());
    let p = rest[..end].trim().trim_matches('"').to_string();
    if p.is_empty() { None } else { Some(p) }
}

pub(super) async fn systemd_action(unit: &str, action: &str) -> anyhow::Result<String> {
    validate_systemd_unit(unit)?;
    let action = validate_systemd_action(action)?;
    let mut cmd = Command::new("systemctl");
    cmd.arg("--no-pager").arg(action).arg("--").arg(unit);
    let out = run_cmd_timeout(cmd, 10_000).await?;
    if out.status.success() {
        return Ok(format!("{action} {unit}: ok"));
    }
    let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
    anyhow::bail!(
        "systemctl {} {} failed: {}",
        action,
        unit,
        if err.is_empty() { out.status.to_string() } else { err }
    );
}

pub(super) async fn systemd_logs(unit: &str, n: usize) -> anyhow::Result<String> {
    validate_systemd_unit(unit)?;
    let n = n.clamp(1, 5000);
    let mut cmd = Command::new("journalctl");
    cmd.arg("-u")
        .arg(unit)
        .arg("-n")
        .arg(n.to_string())
        .arg("--no-pager")
        .arg("--output=short-iso");
    let out = run_cmd_timeout(cmd, 5000).await?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        anyhow::bail!(
            "journalctl -u {unit} failed: {}",
            if err.is_empty() { out.status.to_string() } else { err }
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

pub(super) async fn systemd_service_details(unit: &str) -> anyhow::Result<(PathBuf, cgroup::CgroupResourceSnapshot)> {
    validate_systemd_unit(unit)?;
    let mut cmd = Command::new("systemctl");
    cmd.arg("show")
        .arg("--no-pager")
        .arg("--property=ControlGroup")
        .arg("--")
        .arg(unit);
    let out = run_cmd_timeout(cmd, 3000).await?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        anyhow::bail!(
            "systemctl show {unit} failed: {}",
            if err.is_empty() { out.status.to_string() } else { err }
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let cg = text
        .lines()
        .find_map(|line| line.strip_prefix("ControlGroup="))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let dir = sysfs_cgroup_dir_from_control_group(&cg)
        .ok_or_else(|| anyhow::anyhow!("systemd unit has no ControlGroup: {unit}"))?;
    if let Err(e) = std::fs::metadata(&dir) {
        anyhow::bail!("cgroup dir not found for {unit}: {}: {e}", dir.display());
    }
    let snap = cgroup::read_resource_snapshot(&dir)?;
    Ok((dir, snap))
}
