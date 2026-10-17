//! Persisting the small part of run state that survives a daemon restart (user flags).

use super::*;

pub(super) const MAX_APPSTATE_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB (guard against corrupted/malicious file)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PersistedAppState {
    #[serde(default)]
    user_flags: BTreeMap<String, Option<i64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PersistedStateFile {
    version: u32,
    #[serde(default)]
    apps: HashMap<String, PersistedAppState>,
}

pub(super) fn restore_app_state_best_effort(state: Arc<Mutex<DaemonState>>) {
    let (path, run_info, events) = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        (st.appstate_path.clone(), Arc::clone(&st.run_info), Arc::clone(&st.events))
    };
    if let Ok(m) = fs::metadata(&path) {
        if m.is_file() && m.len() > MAX_APPSTATE_BYTES {
            push_event(
                &events,
                "appstate",
                None,
                format!(
                    "discard_too_large path={} bytes={} limit_bytes={}",
                    path.display(),
                    m.len(),
                    MAX_APPSTATE_BYTES
                ),
            );
            return;
        }
    }
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                push_event(&events, "appstate", None, format!("load_failed path={} err={e}", path.display()));
            }
            return;
        }
    };
    let parsed: PersistedStateFile = match serde_json::from_str(&text) {
        Ok(p) => p,
        Err(e) => {
            push_event(&events, "appstate", None, format!("discard_unreadable path={} err={e}", path.display()));
            return;
        }
    };
    // version 2 used to include a stopped_by_user field; we now express intent via user_flags instead.
    if parsed.version != 1 && parsed.version != 2 {
        push_event(&events, "appstate", None, format!("discard_version_mismatch path={} version={}", path.display(), parsed.version));
        return;
    }
    let now_ms = Local::now().timestamp_millis();
    let mut applied = 0usize;
    {
        let mut ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
        for (app, st) in parsed.apps {
            let e = ri.entry(app).or_default();
            // Restore persisted app state (only user flags; system flags are derived).
            e.user_flags = st.user_flags;
            // prune expired immediately
            e.user_flags.retain(|_, v| v.map(|d| now_ms < d).unwrap_or(true));
            // enforce caps
            e.user_flags.retain(|k, _| !k.is_empty() && k.len() <= MAX_USER_FLAG_LEN);
            if e.user_flags.len() > MAX_USER_FLAGS_PER_APP {
                // Keep first N keys in sorted order (BTreeMap order) and drop the rest.
                let keep: Vec<String> = e
                    .user_flags
                    .keys()
                    .take(MAX_USER_FLAGS_PER_APP)
                    .cloned()
                    .collect();
                e.user_flags.retain(|k, _| keep.binary_search(k).is_ok());
            }
            applied += 1;
        }
    }
    if applied > 0 {
        push_event(&events, "appstate", None, format!("restored apps={applied} path={}", path.display()));
    }
}

pub(super) fn start_appstate_flush_thread(state: Arc<Mutex<DaemonState>>) {
    tasks().spawn(async move {
        loop {
            let (dirty, path, run_info, events, shutting_down) = {
                let st = state.lock().unwrap_or_else(|p| p.into_inner());
                (
                    Arc::clone(&st.appstate_dirty),
                    st.appstate_path.clone(),
                    Arc::clone(&st.run_info),
                    Arc::clone(&st.events),
                    Arc::clone(&st.shutting_down),
                )
            };

            if shutting_down.load(Ordering::Relaxed) {
                // One last best-effort flush.
                if dirty.swap(false, Ordering::Relaxed) {
                    let _ = write_appstate_atomic(&path, &run_info, &events);
                }
                break;
            }

            if dirty.swap(false, Ordering::Relaxed) {
                let _ = write_appstate_atomic(&path, &run_info, &events);
            }
            tokio_time::sleep(Duration::from_millis(500)).await;
        }
    });
}

pub(super) fn write_appstate_atomic(path: &Path, run_info: &Arc<Mutex<HashMap<String, RunInfo>>>, events: &Arc<Mutex<VecDeque<EventEntry>>>) -> anyhow::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if let Err(e) = fs::create_dir_all(parent) {
        push_event(events, "appstate", None, format!("flush_failed mkdir {} err={e}", parent.display()));
        return Ok(());
    }

    let snapshot: PersistedStateFile = {
        let ri = run_info.lock().unwrap_or_else(|p| p.into_inner());
        let mut apps: HashMap<String, PersistedAppState> = HashMap::new();
        for (app, info) in ri.iter() {
            if info.user_flags.is_empty() {
                continue;
            }
            apps.insert(
                app.clone(),
                PersistedAppState {
                    user_flags: info.user_flags.clone(),
                },
            );
        }
        PersistedStateFile { version: 1, apps }
    };

    let json = serde_json::to_vec_pretty(&snapshot)?;
    // A predictable temp name in a directory that may not be root-exclusive lets an
    // attacker pre-plant a symlink there and redirect this write. Randomise the name,
    // refuse to follow a link, and refuse to reuse an existing file.
    let mut nonce = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let tmp = parent.join(format!(
        ".appstate.json.tmp.{}.{}",
        std::process::id(),
        nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(&json)?;
        // Durability: without this the rename can land while the contents have not,
        // leaving a zero-length appstate after a crash.
        f.sync_all()?;
    }
    // Atomic replace on POSIX.
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}
