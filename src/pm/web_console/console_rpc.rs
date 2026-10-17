//! JSON-RPC methods that exist only for the web console (not routed through the
//! daemon's dispatcher): resource details, the host's systemd units, and admin-action
//! process control. Each returns the JSON-RPC `result` object (`ok`/`message`/...).

use super::*;
use serde_json::{json, Value};

/// Runs `method` if it is a console-only method; `None` means it is not one.
pub(super) async fn console_method(st: &WebState, method: &str, params: &Value) -> Option<Value> {
    let str_param = |name: &str| params.get(name).and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let cfg = || st.daemon.lock().unwrap_or_else(|p| p.into_inner()).cfg.clone();

    let result = match method {
        "service_details" => {
            let app = str_param("app");
            if app.is_empty() {
                return Some(json!({ "ok": false, "message": "missing/empty param: app" }));
            }
            service_details(&cfg(), &app)
        }
        "systemd_list" => match systemd_list_services().await {
            Ok(v) => json!({ "ok": true, "message": "", "services": v }),
            Err(e) => json!({ "ok": false, "message": e.to_string(), "services": [] }),
        },
        "systemd_action" => {
            let (unit, action) = (str_param("unit"), str_param("action"));
            if unit.is_empty() || action.is_empty() {
                return Some(json!({ "ok": false, "message": "missing/empty params: unit/action" }));
            }
            match systemd_action(&unit, &action).await {
                Ok(msg) => json!({ "ok": true, "message": msg }),
                Err(e) => json!({ "ok": false, "message": e.to_string() }),
            }
        }
        "systemd_logs" => {
            let unit = str_param("unit");
            let n = params.get("n").and_then(|v| v.as_u64()).map(|x| x as usize).unwrap_or(200);
            if unit.is_empty() {
                return Some(json!({ "ok": false, "message": "missing/empty param: unit" }));
            }
            match systemd_logs(&unit, n).await {
                Ok(text) => json!({ "ok": true, "message": text }),
                Err(e) => json!({ "ok": false, "message": e.to_string() }),
            }
        }
        "systemd_service_details" => {
            let unit = str_param("unit");
            if unit.is_empty() {
                return Some(json!({ "ok": false, "message": "missing/empty param: unit" }));
            }
            match systemd_service_details(&unit).await {
                Ok((cg, snap)) => json!({
                    "ok": true,
                    "message": "",
                    "unit": unit,
                    "cgroup_dir": cg.display().to_string(),
                    "snapshot": snap,
                }),
                Err(e) => json!({ "ok": false, "message": e.to_string(), "unit": unit }),
            }
        }
        "admin_actions_pids" => {
            // Grouped by action id: "<id>: <pid>" per running process.
            match crate::pm::daemon::admin_action_pids_by_id(&cfg()) {
                Ok(running) => {
                    let pids: Vec<String> = running
                        .into_iter()
                        .flat_map(|(id, pids)| pids.into_iter().map(move |p| format!("{id}: {p}")))
                        .collect();
                    json!({ "ok": true, "message": "", "pids": pids })
                }
                Err(e) => json!({ "ok": false, "message": e.to_string(), "pids": [] }),
            }
        }
        "admin_actions_kill" => {
            let admin_cg = cgroup::admin_actions_dir(&cfg());
            let before = cgroup::list_pids(&admin_cg).unwrap_or_default();
            match cgroup::kill_all_pids(&admin_cg) {
                Ok(()) => json!({
                    "ok": true,
                    "message": format!("sent cgroup.kill to {} (pids_before={})", admin_cg.display(), before.len()),
                }),
                Err(e) => json!({ "ok": false, "message": e.to_string() }),
            }
        }
        _ => return None,
    };
    Some(result)
}

/// Resource snapshot of one service's cgroup.
fn service_details(cfg: &crate::pm::config::MasterConfig, app: &str) -> Value {
    let cg_dir = match service_cgroup_dir(cfg, app) {
        Ok(p) => p,
        Err(e) => return json!({ "ok": false, "message": e.to_string() }),
    };
    if let Err(e) = std::fs::metadata(&cg_dir) {
        return json!({
            "ok": false,
            "message": format!("cgroup dir not found: {}: {e}", cg_dir.display()),
            "app": app,
            "cgroup_dir": cg_dir.display().to_string(),
        });
    }
    match cgroup::read_resource_snapshot(&cg_dir) {
        Ok(snap) => json!({ "ok": true, "message": "", "app": app, "snapshot": snap }),
        Err(e) => json!({
            "ok": false,
            "message": e.to_string(),
            "app": app,
            "cgroup_dir": cg_dir.display().to_string(),
        }),
    }
}

pub(super) fn service_cgroup_dir(cfg: &crate::pm::config::MasterConfig, app: &str) -> anyhow::Result<PathBuf> {
    let app = app.trim();
    // Same rules as service definitions: rules out '/', '.', '..' and leading dots, while
    // still allowing names such as `db..backup` that a config can legitimately define.
    crate::pm::app::validate_application_name(app)?;
    Ok(cgroup::app_dir(cfg, app))
}
