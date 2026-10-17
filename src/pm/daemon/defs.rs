//! Loading service definitions from the config directory, including auto-services.

use super::*;

pub(super) const MAX_APPS: usize = 10_000;
pub(super) const MAX_APP_CONFIG_BYTES: u64 = 1024 * 1024; // 1 MiB
/// Write `contents` to `path` atomically, without ever following a symlink.
///
/// Used for operator-facing YAML the daemon rewrites as root inside directories that a
/// service user may own. Writing to a fresh `O_EXCL|O_NOFOLLOW` temp file and renaming
/// means a planted symlink is never written through, a partially written file is never
/// observable, and the rename replaces the directory entry itself rather than whatever
/// a link happened to point at.
pub(super) fn write_yaml_atomically(path: &Path, contents: &str) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut nonce = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "out".to_string());
    let tmp = parent.join(format!(
        ".{}.tmp.{}.{}",
        file_name,
        std::process::id(),
        nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));

    let write_result = (|| -> anyhow::Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o644)
            .open(&tmp)
            .with_context(|| format!("create temp file {}", tmp.display()))?;
        f.write_all(contents.as_bytes())
            .with_context(|| format!("write {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("rename into {}", path.display()));
    }
    Ok(())
}

pub(super) fn preflight_validate_and_load_defs(cfg: &MasterConfig) -> anyhow::Result<HashMap<String, AppDefinition>> {
    // Best-effort load: keep daemon up even if some services cannot be loaded.
    // Rules:
    // - parse/misconfig failures: skip that service
    // - duplicates: do not load ambiguous new defs (best-effort keeps old elsewhere; at boot there is no old)
    let empty: HashMap<String, AppDefinition> = HashMap::new();
    let (defs, warnings, _outdated) = load_app_definitions_best_effort(
        &cfg.config_directory,
        &empty,
        cfg.auto_service_directory.as_deref(),
        &cfg.default_service_user,
        &cfg.default_service_group,
    )?;
    for w in warnings {
        pm_event("config", None, format!("load_warning {w}"));
    }
    Ok(defs)
}

/// Loaded definitions, load warnings, and the services whose new definition was
/// rejected (they keep their previous one).
pub(super) type LoadedDefs = (HashMap<String, AppDefinition>, Vec<String>, Vec<String>);

pub(super) fn load_app_definitions_best_effort(
    dir: &Path,
    old_defs: &HashMap<String, AppDefinition>,
    auto_service_directory: Option<&Path>,
    default_service_user: &str,
    default_service_group: &str,
) -> anyhow::Result<LoadedDefs> {
    if !dir.exists() {
        return Ok((
            old_defs.clone(),
            vec![format!("config_directory_missing dir={} kept_last_known_good=true", dir.display())],
            vec![],
        ));
    }
    if !dir.is_dir() {
        return Ok((
            old_defs.clone(),
            vec![format!("config_directory_not_dir dir={} kept_last_known_good=true", dir.display())],
            vec![],
        ));
    }

    // Non-recursive: only load direct children of the directory.
    let mut files: Vec<PathBuf> = vec![];
    let rd = fs::read_dir(dir).map_err(|e| anyhow::anyhow!("failed to read config_directory {}: {e}", dir.display()))?;
    for e in rd.flatten() {
        if files.len() >= MAX_APPS {
            anyhow::bail!("too many app definitions (max {MAX_APPS})");
        }
        let p = e.path();
        let meta = match e.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_file() {
            continue;
        }
        let Some(ext) = p.extension().and_then(|s| s.to_str()) else { continue };
        let ext = ext.to_ascii_lowercase();
        if ext != "yaml" && ext != "yml" {
            continue;
        }
        files.push(p);
    }

    let mut defs: HashMap<String, AppDefinition> = HashMap::new();
    let mut warnings: Vec<String> = vec![];
    let mut outdated: Vec<String> = vec![];
    let mut seen_sources: HashMap<String, Vec<PathBuf>> = HashMap::new();
    let mut dup_apps: HashMap<String, Vec<PathBuf>> = HashMap::new();

    for path in &files {
        // Enforce per-file size limit (best-effort: keep previous if possible).
        if let Ok(m) = fs::metadata(path)
            && m.is_file() && m.len() > MAX_APP_CONFIG_BYTES {
                if let Some((app, old)) = old_defs
                    .iter()
                    .find(|(_, d)| d.source_file.as_deref() == Some(path.as_path()))
                {
                    defs.insert(app.clone(), old.clone());
                    warnings.push(format!(
                        "file_too_large file={} kept_previous_app={} bytes={} limit_bytes={}",
                        path.display(),
                        app,
                        m.len(),
                        MAX_APP_CONFIG_BYTES
                    ));
                    outdated.push(app.clone());
                } else {
                    warnings.push(format!(
                        "file_too_large file={} bytes={} limit_bytes={}",
                        path.display(),
                        m.len(),
                        MAX_APP_CONFIG_BYTES
                    ));
                }
                continue;
            }
        // Definitions are executed as root (they choose `user:`, commands, paths), so
        // only a root-owned, single-link, non-group/other-writable file is loaded.
        let raw = match crate::pm::safefs::read_trusted_file(path, MAX_APP_CONFIG_BYTES) {
            Ok(s) => s,
            Err(e) => {
                // Keep old definition for this file if possible.
                if let Some((app, old)) = old_defs
                    .iter()
                    .find(|(_, d)| d.source_file.as_deref() == Some(path.as_path()))
                {
                    defs.insert(app.clone(), old.clone());
                    warnings.push(format!(
                        "read_failed file={} kept_previous_app={} err={e:#}",
                        path.display(),
                        app
                    ));
                    outdated.push(app.clone());
                } else {
                    warnings.push(format!("read_failed file={} err={e:#}", path.display()));
                }
                continue;
            }
        };

        match parse_app_definition_yaml(&raw, path, auto_service_directory, None) {
            Ok(def) => {
                // Misconfig check: working directory must exist (otherwise skip/keep old).
                if !def.working_directory.exists() || !def.working_directory.is_dir() {
                    if let Some((app, old)) = old_defs
                        .iter()
                        .find(|(_, d)| d.source_file.as_deref() == Some(path.as_path()))
                    {
                        defs.insert(app.clone(), old.clone());
                        warnings.push(format!(
                            "misconfigured_workdir file={} kept_previous_app={} workdir={}",
                            path.display(),
                            app,
                            def.working_directory.display()
                        ));
                        outdated.push(app.clone());
                    } else {
                        warnings.push(format!(
                            "misconfigured_workdir file={} dropped_app={} workdir={}",
                            path.display(),
                            def.application,
                            def.working_directory.display()
                        ));
                    }
                    continue;
                }

                // Provisioning is an optional, one-time setup step. If defined and not yet provisioned
                // (marker missing), provisioning must succeed for the app to be loadable.
                // If provisioning fails, we drop the app from this load (do NOT keep last-known-good),
                // so a subsequent reload will retry provisioning.
                if !def.provisioning.is_empty()
                    && let Err(e) = maybe_provision_workdir(&def) {
                        pm_event(
                            "provision",
                            Some(&def.application),
                            format!(
                                "decision=drop_load reason=provision_failed file={} err={e}",
                                path.display()
                            ),
                        );
                        warnings.push(format!(
                            "provision_failed file={} dropped_app={} err={e}",
                            path.display(),
                            def.application
                        ));
                        continue;
                    }

                let app = def.application.clone();
                seen_sources.entry(app.clone()).or_default().push(path.to_path_buf());
                if defs.contains_key(&app) {
                    dup_apps.entry(app.clone()).or_default().push(path.to_path_buf());
                }
                defs.insert(app, def);
            }
            Err(e) => {
                if let Some((app, old)) = old_defs
                    .iter()
                    .find(|(_, d)| d.source_file.as_deref() == Some(path.as_path()))
                {
                    defs.insert(app.clone(), old.clone());
                    warnings.push(format!(
                        "parse_failed file={} kept_previous_app={} err={e}",
                        path.display(),
                        app
                    ));
                    outdated.push(app.clone());
                } else {
                    warnings.push(format!("parse_failed file={} err={e}", path.display()));
                }
            }
        }
    }

    // Preserve any in-memory definitions that have no source_file (should be rare).
    for (app, def) in old_defs {
        if def.source_file.is_none() && !defs.contains_key(app) {
            defs.insert(app.clone(), def.clone());
            warnings.push(format!("kept_in_memory_definition app={app} reason=no_source_file"));
        }
    }

    // Merge implicit services from auto_service_directory (best-effort: report read errors as warnings,
    // but treat name collisions as hard errors).
    merge_auto_services_best_effort(
        &mut defs,
        old_defs,
        auto_service_directory,
        default_service_user,
        default_service_group,
        warnings.as_mut(),
        &mut outdated,
    )?;

    // Handle duplicates: if multiple sources define the same app name, do not pick one arbitrarily.
    // Best-effort rule: keep last-known-good if available; otherwise drop the app from this load.
    for (app, dups) in &dup_apps {
        let mut sources = seen_sources.get(app).cloned().unwrap_or_default();
        sources.extend_from_slice(dups);
        sources.sort();
        sources.dedup();

        if let Some(old) = old_defs.get(app) {
            defs.insert(app.clone(), old.clone());
            warnings.push(format!(
                "duplicate_application app={} action=kept_previous sources={}",
                app,
                sources
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ));
            outdated.push(app.clone());
        } else {
            defs.remove(app);
            warnings.push(format!(
                "duplicate_application app={} action=dropped sources={}",
                app,
                sources
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
    }

    outdated.sort();
    outdated.dedup();
    Ok((defs, warnings, outdated))
}

pub(super) fn build_auto_service_def(
    app: &str,
    workdir: &Path,
    source_file: PathBuf,
    default_service_user: &str,
    default_service_group: &str,
) -> anyhow::Result<AppDefinition> {
    let rotation_size_bytes = parse_size_spec_bytes("10m").ok();
    let source_mtime_ms = source_file
        .metadata()
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|mt| mt.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_millis()).ok());
    Ok(AppDefinition {
        application: app.to_string(),
        working_directory: workdir.to_path_buf(),
        log_stdout: None,
        log_stderr: None,
        stop_command_stdout: Some("./logs/stop_command_stdout.log".into()),
        stop_command_stderr: Some("./logs/stop_command_stderr.log".into()),
        alt_log_file_hint: vec![],
        inherit_environment: false,
        start_command: vec!["./run.sh".to_string()],
        environment: vec![],
        restart: Some(RestartConfig {
            policy: RestartPolicy::default(),
            restart_backoff_ms: 1000,
            tolerance: RestartTolerance::default(),
        }),
        stop_signal: Some("SIGTERM".to_string()),
        stop_command: None,
        stop_grace_period_ms: 5_000,
        max_cpu: Some("MAX".to_string()),
        max_memory: Some("MAX".to_string()),
        max_swap: Some("MAX".to_string()),
        max_pids: None,
        io_weight: None,
        io_bandwidth: None,
        user: Some(default_service_user.to_string()),
        group: Some(default_service_group.to_string()),
        rotation_mode: LogRotationMode::Size,
        rotation_frequency: LogRotation::Daily,
        rotation_max_age_ms: 30 * 24 * 60 * 60 * 1000,
        rotation_size_bytes,
        rotation_backups: Some(10),
        log_compression_enabled: true,
        enabled: true,
        schedule: None,
        schedule_not_before_ms: None,
        schedule_not_after_ms: None,
        schedule_max_time_per_run_ms: None,
        provisioning: vec![],
        source_file: Some(source_file),
        source_mtime_ms,
    })
}

pub(super) fn merge_auto_services_best_effort(
    defs: &mut HashMap<String, AppDefinition>,
    old_defs: &HashMap<String, AppDefinition>,
    auto_service_directory: Option<&Path>,
    default_service_user: &str,
    default_service_group: &str,
    warnings: &mut Vec<String>,
    outdated: &mut Vec<String>,
) -> anyhow::Result<()> {
    let Some(dir) = auto_service_directory else { return Ok(()) };
    if !dir.exists() {
        warnings.push(format!("auto_service_directory_missing dir={}", dir.display()));
        return Ok(());
    }
    if !dir.is_dir() {
        warnings.push(format!("auto_service_directory_not_dir dir={}", dir.display()));
        return Ok(());
    }
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            warnings.push(format!("auto_service_directory_read_failed dir={} err={e}", dir.display()));
            return Ok(());
        }
    };
    for e in rd.flatten() {
        if defs.len() >= MAX_APPS {
            anyhow::bail!("too many app definitions (max {MAX_APPS})");
        }
        let path = e.path();
        let meta = match e.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else { continue };
        let app = name.trim();
        if app.is_empty() {
            continue;
        }
        // Quick disable: any auto-service directory ending with ".disabled" is ignored.
        if app.ends_with(".disabled") {
            continue;
        }
        // The auto-service directory is also the service's working directory, and a
        // definition inside a directory the service user can write can never be trusted:
        // the user can rename any root-owned file into place -- including a log the
        // daemon wrote with the service's own output. Such directories are not loaded;
        // their definition belongs in config_directory (root-controlled), with
        // working_directory pointing here.
        let dir_trusted = crate::pm::safefs::is_root_controlled_dir(&path);
        if !dir_trusted {
            if defs.contains_key(app) {
                // Already migrated: the config_directory definition is the one to use.
                continue;
            }
            warnings.push(format!(
                "auto_service_dir_not_root_controlled app={} dir={} not_loaded=true \
                 hint=\"a directory a non-root user can write cannot hold a trusted definition; \
                 move it to config_directory with process.working_directory: {}\"",
                app,
                path.display(),
                path.display()
            ));
            continue;
        }
        if defs.contains_key(app) {
            anyhow::bail!(
                "auto_service_directory conflict: application {} is already defined in config_directory",
                app
            );
        }
        let svc_yml = path.join("service.yml");
        let svc_yaml = path.join("service.yaml");

        // Optional regeneration marker for lazy upgrades:
        // If `.regen_pm_config` exists, we rotate any existing service.{yml,yaml} to `service.yml.bak*`,
        // generate a fresh `service.yml` from defaults, and load it. Finally remove the marker.
        let regen_marker = path.join(".regen_pm_config");
        let mut svc_file = if svc_yml.is_file() {
            Some(svc_yml.clone())
        } else if svc_yaml.is_file() {
            Some(svc_yaml.clone())
        } else {
            None
        };
        // Regeneration writes a definition with the *default* user (root unless
        // configured otherwise), so only honour a marker root placed.
        let regen_requested = match fs::symlink_metadata(&regen_marker) {
            Ok(m) => {
                use std::os::unix::fs::MetadataExt as _;
                let ok = m.is_file() && crate::pm::safefs::trusted_uids().contains(&m.uid());
                if !ok {
                    warnings.push(format!(
                        "auto_service_regen_marker_ignored app={} file={} reason=not_a_root_owned_file",
                        app,
                        regen_marker.display()
                    ));
                }
                ok
            }
            Err(_) => false,
        };
        if regen_requested {
            fn next_bak_path(dir: &Path) -> PathBuf {
                let base = dir.join("service.yml.bak");
                if !base.exists() {
                    return base;
                }
                for i in 1..10_000usize {
                    let c = dir.join(format!("service.yml.bak.{i}"));
                    if !c.exists() {
                        return c;
                    }
                }
                // Extremely unlikely; fall back.
                dir.join(format!("service.yml.bak.{}", std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis())
                    .unwrap_or(0)))
            }

            let mut regen_ok = true;

            // Rotate existing service.yml/service.yaml (if any) into service.yml.bak(.N).
            for old in [&svc_yml, &svc_yaml] {
                if old.is_file() {
                    let bak = next_bak_path(&path);
                    if let Err(e) = std::fs::rename(old, &bak) {
                        warnings.push(format!(
                            "auto_service_regen_backup_failed app={} from={} to={} err={e}",
                            app,
                            old.display(),
                            bak.display()
                        ));
                        regen_ok = false;
                    } else {
                        warnings.push(format!(
                            "auto_service_regen_backed_up app={} from={} to={}",
                            app,
                            old.display(),
                            bak.display()
                        ));
                    }
                }
            }

            // Generate a fresh service.yml.
            let yaml_text = match crate::pm::app::render_auto_service_yaml(
                app,
                default_service_user,
                default_service_group,
            ) {
                Ok(s) => s,
                Err(e) => {
                    warnings.push(format!(
                        "auto_service_regen_generate_failed app={} file={} err={e}",
                        app,
                        svc_yml.display()
                    ));
                    regen_ok = false;
                    String::new()
                }
            };
            if regen_ok {
                // Write to a fresh temp file and rename into place, rather than
                // truncating svc_yml directly. An auto-service directory is often owned
                // by the service user, who could otherwise race the window after the
                // .bak rename and plant a symlink for root to truncate and rewrite.
                // O_EXCL|O_NOFOLLOW means we never write through a link and never reuse
                // a planted file; rename() is atomic and replaces the target itself,
                // not whatever a link points at.
                match write_yaml_atomically(&svc_yml, &yaml_text) {
                    Ok(()) => {
                        warnings.push(format!(
                            "auto_service_regen_written app={} file={}",
                            app,
                            svc_yml.display()
                        ));
                    }
                    Err(e) => {
                        warnings.push(format!(
                            "auto_service_regen_write_failed app={} file={} err={e:#}",
                            app,
                            svc_yml.display()
                        ));
                        regen_ok = false;
                    }
                }
            }
            // Set to load the regenerated `service.yml` (even if the backup step failed; user asked for regen).
            svc_file = Some(svc_yml.clone());

            // Remove marker only if generation + write succeeded.
            if regen_ok
                && let Err(e) = std::fs::remove_file(&regen_marker)
                    && e.kind() != std::io::ErrorKind::NotFound {
                        warnings.push(format!(
                            "auto_service_regen_marker_remove_failed app={} file={} err={e}",
                            app,
                            regen_marker.display()
                        ));
                    }
        }

        let def = if let Some(sf) = svc_file.as_ref() {
            match fs::metadata(sf) {
                Ok(m) if m.len() > MAX_APP_CONFIG_BYTES => {
                    if let Some(old) = old_defs.get(app) {
                        defs.insert(app.to_string(), old.clone());
                        warnings.push(format!(
                            "auto_service_yml_too_large app={} file={} bytes={} limit_bytes={} kept_previous=true",
                            app,
                            sf.display(),
                            m.len(),
                            MAX_APP_CONFIG_BYTES
                        ));
                        outdated.push(app.to_string());
                    } else {
                        warnings.push(format!(
                            "auto_service_yml_too_large app={} file={} bytes={} limit_bytes={} kept_previous=false",
                            app,
                            sf.display(),
                            m.len(),
                            MAX_APP_CONFIG_BYTES
                        ));
                    }
                    continue;
                }
                _ => {
                    match crate::pm::safefs::read_trusted_file(sf, MAX_APP_CONFIG_BYTES) {
                        Ok(raw) => match parse_app_definition_yaml(&raw, sf, Some(dir), Some(&path)) {
                            Ok(def) => {
                                if def.application != app {
                                    // Best-effort: treat as malconfigured; keep previous if any.
                                    if let Some(old) = old_defs.get(app) {
                                        defs.insert(app.to_string(), old.clone());
                                        warnings.push(format!(
                                            "auto_service_yml_app_mismatch app={} parsed_application={} file={} kept_previous=true",
                                            app,
                                            def.application,
                                            sf.display()
                                        ));
                                        outdated.push(app.to_string());
                                    } else {
                                        warnings.push(format!(
                                            "auto_service_yml_app_mismatch app={} parsed_application={} file={} kept_previous=false",
                                            app,
                                            def.application,
                                            sf.display()
                                        ));
                                    }
                                    continue;
                                }
                                def
                            }
                            Err(e) => {
                                if let Some(old) = old_defs.get(app) {
                                    defs.insert(app.to_string(), old.clone());
                                    warnings.push(format!(
                                        "auto_service_yml_parse_failed app={} file={} err={e} kept_previous=true",
                                        app,
                                        sf.display()
                                    ));
                                    outdated.push(app.to_string());
                                } else {
                                    warnings.push(format!(
                                        "auto_service_yml_parse_failed app={} file={} err={e} kept_previous=false",
                                        app,
                                        sf.display()
                                    ));
                                }
                                continue;
                            }
                        },
                        Err(e) => {
                            if let Some(old) = old_defs.get(app) {
                                defs.insert(app.to_string(), old.clone());
                                warnings.push(format!(
                                    "auto_service_yml_read_failed app={} file={} err={e:#} kept_previous=true",
                                    app,
                                    sf.display()
                                ));
                                outdated.push(app.to_string());
                            } else {
                                warnings.push(format!(
                                    "auto_service_yml_read_failed app={} file={} err={e:#} kept_previous=false",
                                    app,
                                    sf.display()
                                ));
                            }
                            continue;
                        }
                    }
                }
            }
        } else {
            // No service.yml: synthesize a default service AND (best-effort) auto-generate
            // a full `service.yml` for convenience.
            //
            // We only create the file if missing; we never overwrite.
            let target = path.join("service.yml");

            let yaml_text = match crate::pm::app::render_auto_service_yaml(
                app,
                default_service_user,
                default_service_group,
            ) {
                Ok(s) => Some(s),
                Err(e) => {
                    warnings.push(format!(
                        "auto_service_generate_failed app={} file={} err={e}",
                        app,
                        target.display()
                    ));
                    None
                }
            };

            if let Some(yaml_text) = yaml_text {
                // Best-effort write: only if missing (no overwrite).
                if !target.exists() {
                    use std::os::unix::fs::OpenOptionsExt as _;
                    match std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        // Must come out root-owned and not group/other-writable, or the
                        // next load refuses it (read_trusted_file).
                        .mode(0o644)
                        .custom_flags(libc::O_NOFOLLOW)
                        .open(&target)
                    {
                        Ok(mut f) => {
                            if let Err(e) = f.write_all(yaml_text.as_bytes()) {
                                warnings.push(format!(
                                    "auto_service_write_failed app={} file={} err={e}",
                                    app,
                                    target.display()
                                ));
                            } else {
                                warnings.push(format!(
                                    "auto_service_generated app={} file={}",
                                    app,
                                    target.display()
                                ));
                            }
                        }
                        Err(e) => {
                            // If another actor created it concurrently, that's fine.
                            if e.kind() != std::io::ErrorKind::AlreadyExists {
                                warnings.push(format!(
                                    "auto_service_write_failed app={} file={} err={e}",
                                    app,
                                    target.display()
                                ));
                            }
                        }
                    }
                }

                // Parse the generated YAML so runtime behavior matches the file.
                match parse_app_definition_yaml(&yaml_text, &target, Some(dir), Some(&path)) {
                    Ok(def) => def,
                    Err(e) => {
                        warnings.push(format!(
                            "auto_service_generated_parse_failed app={} file={} err={e}",
                            app,
                            target.display()
                        ));
                        build_auto_service_def(app, &path, target, default_service_user, default_service_group)?
                    }
                }
            } else {
                // Still load defaults in-memory if we couldn't generate YAML.
                build_auto_service_def(app, &path, target, default_service_user, default_service_group)?
            }
        };

        // Provisioning gate (auto services too): if provisioning is defined and marker is missing,
        // provisioning must succeed for the app to be loadable. If it fails, do NOT keep any old def;
        // the next reload will retry.
        if !def.provisioning.is_empty()
            && let Err(e) = maybe_provision_workdir(&def) {
                let file_s = def
                    .source_file
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(none)".to_string());
                pm_event(
                    "provision",
                    Some(&def.application),
                    format!("decision=drop_load reason=provision_failed auto_service=true file={} err={e}", file_s),
                );
                warnings.push(format!(
                    "auto_service_provision_failed app={} file={} err={e}",
                    def.application, file_s
                ));
                continue;
            }

        defs.insert(app.to_string(), def);
    }
    Ok(())
}
