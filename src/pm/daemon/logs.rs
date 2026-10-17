//! Service output: the pumps that write stdout/stderr to disk, rotation and retention, and
//! reading logs back (`pmctl logs`, including follow mode).

use super::*;

pub(super) const LOGSFOLLOW_LINE_MAX_BYTES: usize = 4096;
pub(super) const LOGSFOLLOW_READ_CHUNK_BYTES: usize = 64 * 1024;
pub(super) fn start_log_maintenance_thread(state: Arc<Mutex<DaemonState>>) {
    tasks().spawn(async move {
        loop {
            if let Err(e) = run_log_maintenance_tick_async(&state).await {
                eprintln!("log maintenance error: {e}");
            }
            // Sleep until the wall-clock minute identity actually changes.
            // (Some platforms can wake early; this avoids running a "next minute" tick too soon.)
            let start_minute = Local::now().timestamp_millis() / 60_000;
            loop {
                let now_ms = Local::now().timestamp_millis();
                let cur_minute = now_ms / 60_000;
                if cur_minute != start_minute {
                    break;
                }
                let next_minute_ms = (start_minute + 1) * 60_000;
                let mut sleep_ms = (next_minute_ms - now_ms).max(1);
                // Clamp to avoid pathological sleeps if the clock jumps.
                if sleep_ms > 60_000 {
                    sleep_ms = 60_000;
                }
                tokio_time::sleep(Duration::from_millis(sleep_ms as u64)).await;
            }
        }
    });
}

pub(super) async fn run_log_maintenance_tick_async(state: &Arc<Mutex<DaemonState>>) -> anyhow::Result<()> {
    let defs: Vec<AppDefinition> = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        st.defs.values().cloned().collect()
    };

    let now_sys = std::time::SystemTime::now();

    for def in defs {
        let (stdout_path, stderr_path) = resolve_log_paths(&def);
        // capture-only: rotation is done by log pumps; maintenance only does cleanup/pruning.
        let _ = cleanup_or_prune_rotated_logs_async(&def, &stdout_path, now_sys).await;
        let _ = cleanup_or_prune_rotated_logs_async(&def, &stderr_path, now_sys).await;

        // Optional: rotate/cleanup stop_command stdout/stderr logs too.
        if let Some(p) = resolve_stop_command_log(def.stop_command_stdout.as_ref(), &def.working_directory) {
            let _ = cleanup_or_prune_rotated_logs_async(&def, &p, now_sys).await;
        }
        if let Some(p) = resolve_stop_command_log(def.stop_command_stderr.as_ref(), &def.working_directory) {
            let _ = cleanup_or_prune_rotated_logs_async(&def, &p, now_sys).await;
        }
    }
    Ok(())
}

pub(super) async fn cleanup_or_prune_rotated_logs_async(def: &AppDefinition, base_path: &Path, now: std::time::SystemTime) -> anyhow::Result<()> {
    // Deletes files as root in a directory the service can usually write: go through
    // the pinned directory, never through a path it could redirect.
    let log = match pin_log(base_path, false) {
        Ok(l) => l,
        Err(_) => return Ok(()), // no log directory yet: nothing to prune
    };
    match def.rotation_mode {
        LogRotationMode::Time => cleanup_rotated_logs_async(&log.base, def.rotation_max_age_ms, now).await,
        LogRotationMode::Size => {
            let keep = def.rotation_backups.unwrap_or(10);
            prune_numbered_backups_async(&log.base, keep).await
        }
    }
}

pub(super) async fn prune_numbered_backups_async(base_path: &Path, keep: usize) -> anyhow::Result<()> {
    let Some(dir) = base_path.parent() else { return Ok(()) };
    let Some(base_name) = base_path.file_name().and_then(|s| s.to_str()) else { return Ok(()) };
    let prefix = format!("{base_name}.");

    let mut rd = match tokio::fs::read_dir(dir).await {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };
    let mut nums: Vec<(u64, PathBuf)> = vec![];
    while let Ok(Some(e)) = rd.next_entry().await {
        let p = e.path();
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else { continue };
        if !name.starts_with(&prefix) {
            continue;
        }
        // Only prune numeric suffix backups: base.<N> or base.<N>.gz
        let mut suffix = &name[prefix.len()..];
        if let Some(s) = suffix.strip_suffix(".gz") {
            suffix = s;
        }
        if suffix.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(n) = suffix.parse::<u64>() {
                nums.push((n, p));
            }
        }
    }
    // delete any backups with N > keep
    for (n, p) in nums {
        if n as usize > keep {
            let _ = tokio::fs::remove_file(&p).await;
        }
    }
    Ok(())
}

pub(super) async fn cleanup_rotated_logs_async(base_path: &Path, max_age_ms: u64, now: std::time::SystemTime) -> anyhow::Result<()> {
    let Some(dir) = base_path.parent() else { return Ok(()) };
    let Some(base_name) = base_path.file_name().and_then(|s| s.to_str()) else { return Ok(()) };
    let prefix = format!("{base_name}.");
    let cutoff = if max_age_ms == 0 {
        std::time::SystemTime::UNIX_EPOCH
    } else {
        now.checked_sub(Duration::from_millis(max_age_ms))
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
    };

    let mut rd = match tokio::fs::read_dir(dir).await {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };
    while let Ok(Some(e)) = rd.next_entry().await {
        let p = e.path();
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else { continue };
        if !name.starts_with(&prefix) {
            continue;
        }
        let m = match e.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        let mt = match m.modified() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if mt < cutoff {
            let _ = tokio::fs::remove_file(&p).await;
        }
    }
    Ok(())
}

/// Resolve a `logs.hints` entry, refusing anything that escapes the working directory.
///
/// Hints are displayed by `pmctl logs` and the web console, and the daemon reads them
/// as **root**. Without containment, `hints: ["/etc/shadow"]` in any service definition
/// turns the log viewer into an arbitrary root-file read for every console user.
/// Absolute paths and `..` traversal are both rejected.
pub(super) fn resolve_hint_under_workdir(workdir: &Path, hint: &Path) -> Option<PathBuf> {
    // Lexical containment only; symlinks are handled at open time, where
    // open_regular_for_read refuses to follow any link below the root-controlled
    // prefix. (Canonicalizing here and opening later was a check-then-use race.)
    if hint.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return None;
    }
    let candidate = resolve_under_workdir(workdir, hint);
    candidate.starts_with(workdir).then_some(candidate)
}

/// Ceiling on simultaneous `pmctl logs -f` sessions. Deliberately a small fraction of
/// the blocking pool: even a client that opens connections and never reads cannot
/// starve stops, status or reconciliation.
pub(super) const MAX_CONCURRENT_LOG_FOLLOWS: usize = 64;

pub(super) fn log_follow_semaphore() -> &'static Arc<tokio::sync::Semaphore> {
    static SEM: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    SEM.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_LOG_FOLLOWS)))
}

pub(super) fn do_logs(state: &Arc<Mutex<DaemonState>>, name: &str, n: usize) -> anyhow::Result<Response> {
    let def = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        st.defs
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown service: {name}"))?
    };

    let (stdout_path, stderr_path) = resolve_log_paths(&def);
    let mut files: Vec<PathBuf> = vec![stdout_path, stderr_path];
    for p in &def.alt_log_file_hint {
        match resolve_hint_under_workdir(&def.working_directory, p) {
            Some(path) => files.push(path),
            None => pm_event(
                "logs",
                Some(&def.application),
                format!("hint_rejected reason=outside_working_directory path={}", p.display()),
            ),
        }
    }

    let mut out = String::new();
    for p in files {
        if fs::symlink_metadata(&p).is_err() {
            continue;
        }
        let display_path = canonicalize_for_display(&p);
        out.push_str(&format!("==> {} <==\n", display_path.display()));
        match tail_lines(&p, n) {
            Ok(s) => {
                out.push_str(&s);
                if !s.ends_with('\n') {
                    out.push('\n');
                }
            }
            Err(e) => {
                out.push_str(&format!("(failed to read: {e})\n"));
            }
        }
        out.push('\n');
    }
    if out.trim().is_empty() {
        out = format!("{name}: no log files found");
    }

    Ok(Response::message(true, out.trim_end().to_string()))
}

pub(super) fn handle_logs_follow(
    state: Arc<Mutex<DaemonState>>,
    mut stream: UnixStream,
    name: Option<String>,
    filename: Option<String>,
    n: usize,
) -> anyhow::Result<()> {
    fn write_wrapped(stream: &mut UnixStream, display: &str, bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            let out_line = format!("{display}: \n");
            return stream.write_all(out_line.as_bytes()).is_ok();
        }
        let mut i = 0usize;
        while i < bytes.len() {
            let end = (i + LOGSFOLLOW_LINE_MAX_BYTES).min(bytes.len());
            let s = String::from_utf8_lossy(&bytes[i..end]);
            let out_line = format!("{display}: {s}\n");
            if stream.write_all(out_line.as_bytes()).is_err() {
                return false;
            }
            i = end;
        }
        true
    }

    // Send initial OK response as JSON line.
    let resp = Response::message(true, String::new());
    let resp_line = serde_json::to_string(&resp)? + "\n";
    stream.write_all(resp_line.as_bytes())?;
    stream.flush()?;

    // Collect candidate files across apps (or one app if specified).
    let defs: Vec<AppDefinition> = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ref n) = name {
            vec![st
                .defs
                .get(n)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("unknown service: {n}"))?]
        } else {
            st.defs.values().cloned().collect()
        }
    };

    let mut paths: Vec<PathBuf> = vec![];
    for def in defs {
        let (stdout_path, stderr_path) = resolve_log_paths(&def);
        paths.push(stdout_path);
        paths.push(stderr_path);
        for p in &def.alt_log_file_hint {
            if let Some(path) = resolve_hint_under_workdir(&def.working_directory, p) {
                paths.push(path);
            }
        }
    }

    // Filter + canonicalize existing files, dedup.
    let mut selected: Vec<PathBuf> = vec![];
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for p in paths {
        if !p.exists() {
            continue;
        }
        let canon = std::fs::canonicalize(&p).unwrap_or(p);
        if let Some(ref want) = filename {
            let base = canon.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if base != want {
                continue;
            }
        }
        if seen.insert(canon.clone()) {
            selected.push(canon);
        }
    }
    selected.sort();

    if selected.is_empty() {
        let msg = if let Some(want) = filename {
            format!("no log files found matching filename {want}")
        } else {
            "no log files found".to_string()
        };
        stream.write_all(msg.as_bytes())?;
        stream.write_all(b"\n")?;
        stream.flush()?;
        return Ok(());
    }

    // Initial tail per file.
    for p in &selected {
        let header = format!("==> {} <==\n", p.display());
        stream.write_all(header.as_bytes())?;
        if n > 0 {
            if let Ok(s) = tail_lines(p, n) {
                if !s.is_empty() {
                    // Keep the "tail" output plain (no per-line prefix), but still wrap long lines.
                    for line in s.split_terminator('\n') {
                        let b = line.as_bytes();
                        let mut i = 0usize;
                        while i < b.len() {
                            let end = (i + LOGSFOLLOW_LINE_MAX_BYTES).min(b.len());
                            if stream.write_all(&b[i..end]).is_err() {
                                return Ok(());
                            }
                            if stream.write_all(b"\n").is_err() {
                                return Ok(());
                            }
                            i = end;
                        }
                        if b.is_empty() {
                            let _ = stream.write_all(b"\n");
                        }
                    }
                }
            }
        }
        stream.write_all(b"\n")?;
    }
    stream.flush()?;

    // Follow: keep offsets and partial line buffers.
    struct FollowState {
        path: PathBuf,
        display: String,
        offset: u64,
        partial: Vec<u8>,
    }

    let mut fs = vec![];
    for p in selected {
        let len = crate::pm::safefs::open_regular_for_read(&p)
            .and_then(|f| Ok(f.metadata()?.len()))
            .unwrap_or(0);
        fs.push(FollowState {
            display: p.display().to_string(),
            path: p,
            offset: len,
            partial: vec![],
        });
    }

    loop {
        for st in fs.iter_mut() {
            // Read as root from a directory the service may control: never through a
            // symlink (it could point at /etc/shadow) and never block on a FIFO.
            let mut f = match crate::pm::safefs::open_regular_for_read(&st.path) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let len = match f.metadata() {
                Ok(m) => m.len(),
                Err(_) => continue,
            };
            if len < st.offset {
                // truncated (copytruncate rotation) -> start over
                st.offset = 0;
                st.partial.clear();
            }
            if len == st.offset {
                continue;
            }
            f.seek(SeekFrom::Start(st.offset))?;
            // Read the appended delta in bounded chunks to avoid allocating (len - offset) all at once.
            // This also keeps memory bounded if a file grows very quickly.
            let mut remaining = (len - st.offset) as usize;
            let mut carry = std::mem::take(&mut st.partial);
            while remaining > 0 {
                let take = remaining.min(LOGSFOLLOW_READ_CHUNK_BYTES);
                let mut buf = vec![0u8; take];
                if let Err(_) = std::io::Read::read_exact(&mut f, &mut buf) {
                    break;
                }
                st.offset += take as u64;
                remaining -= take;

                carry.extend_from_slice(&buf);

                // Emit complete lines from carry.
                let mut start = 0usize;
                for i in 0..carry.len() {
                    if carry[i] == b'\n' {
                        let line_bytes = &carry[start..i];
                        start = i + 1;
                        if !write_wrapped(&mut stream, &st.display, line_bytes) {
                            return Ok(());
                        }
                    }
                }

                // Keep remainder, but cap it (wrap-around) so we never buffer an unbounded "no newline" line.
                if start < carry.len() {
                    let mut rem = &carry[start..];
                    while rem.len() > LOGSFOLLOW_LINE_MAX_BYTES {
                        if !write_wrapped(&mut stream, &st.display, &rem[..LOGSFOLLOW_LINE_MAX_BYTES]) {
                            return Ok(());
                        }
                        rem = &rem[LOGSFOLLOW_LINE_MAX_BYTES..];
                    }
                    carry = rem.to_vec();
                } else {
                    carry.clear();
                }
            }
            st.partial = carry;
        }
        if stream.flush().is_err() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

pub(super) fn canonicalize_for_display(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

pub(super) fn tail_lines(path: &Path, n: usize) -> anyhow::Result<String> {
    if n == 0 {
        return Ok(String::new());
    }
    // Root reading a service-controlled directory: see open_regular_for_read.
    let mut f = crate::pm::safefs::open_regular_for_read(path)?;
    let len = f.metadata()?.len();
    if len == 0 {
        return Ok(String::new());
    }

    // Read from the end in chunks until we have enough newlines.
    let mut pos = len;
    let mut newline_count: usize = 0;
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    while pos > 0 && newline_count <= n {
        let read_size = std::cmp::min(8192u64, pos) as usize;
        pos -= read_size as u64;
        f.seek(SeekFrom::Start(pos))?;
        let mut buf = vec![0u8; read_size];
        std::io::Read::read_exact(&mut f, &mut buf)?;
        newline_count += buf.iter().filter(|&&b| b == b'\n').count();
        chunks.push(buf);
        if chunks.len() > 512 {
            // Safety cap (~4MB) to avoid unbounded memory on huge line counts.
            break;
        }
    }
    chunks.reverse();
    let data = chunks.concat();
    let s = String::from_utf8_lossy(&data);
    let mut lines: Vec<&str> = s.split_terminator('\n').collect();
    if lines.len() > n {
        lines = lines[lines.len() - n..].to_vec();
    }
    Ok(lines.join("\n"))
}

/// Open a service log file for appending, as root.
///
/// `O_NOFOLLOW` is essential here, not defensive polish. The log directory normally
/// lives inside a working directory owned by the *service* user (provisioning chowns
/// it), so without it that user can replace `logs/stdout.log` with a symlink to
/// `/etc/cron.d/x` or `/root/.ssh/authorized_keys` and have the root daemon append
/// application-controlled bytes there. `O_NOFOLLOW` makes such an open fail with
/// `ELOOP` instead.
///
/// `path` must be inside a directory pinned with [`pin_log`]: `O_NOFOLLOW` covers only
/// the final component, and the pin is what covers the directories above it.
pub(super) async fn open_append_log_async(path: &Path) -> anyhow::Result<tokio::fs::File> {
    let f = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .write(true)
        // 0640, not the umask default of 0644: a service's stdout routinely carries
        // connection strings and tokens, and every other local user could read them.
        // Group is kept readable so an operator group can tail logs without root.
        .mode(0o640)
        // O_NONBLOCK: a FIFO planted at the log path would otherwise block this open
        // forever, pinning a blocking-pool thread on every restart.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .await
        .with_context(|| {
            format!(
                "open log {} (note: refusing to follow a symlink here is intentional)",
                path.display()
            )
        })?;
    let md = f.metadata().await?;
    anyhow::ensure!(md.is_file(), "log {} is not a regular file; refusing to write to it", path.display());
    {
        use std::os::unix::fs::MetadataExt as _;
        // A hard link to a root file (hosts without fs.protected_hardlinks) would have
        // root append service output to it.
        anyhow::ensure!(md.nlink() == 1, "log {} has {} hard links; refusing to write to it", path.display(), md.nlink());
    }
    // SAFETY: valid fd; regular-file I/O ignores O_NONBLOCK, but clear it anyway.
    unsafe {
        let fd = f.as_raw_fd();
        let fl = libc::fcntl(fd, libc::F_GETFL);
        if fl >= 0 {
            libc::fcntl(fd, libc::F_SETFL, fl & !libc::O_NONBLOCK);
        }
    }
    Ok(f)
}

pub(super) struct RotatedReopen {
    pub(super) f: tokio::fs::File,
    pub(super) rotated: Option<PathBuf>,
}

/// A log file whose parent directory is pinned by descriptor. `base` is the log's path
/// through `/proc/self/fd/N`, so every rename/unlink/open done with it lands in the
/// pinned directory even if the service later swaps a path component for a symlink.
/// Keep `dir` alive for as long as `base` is used.
pub(super) struct PinnedLog {
    pub(super) dir: Arc<OwnedFd>,
    pub(super) base: PathBuf,
}

pub(super) fn pin_log(path: &Path, create: bool) -> anyhow::Result<PinnedLog> {
    let (dir, name) = crate::pm::safefs::open_parent_safely(path, create)
        .with_context(|| format!("open log directory for {}", path.display()))?;
    let base = crate::pm::safefs::proc_fd_path(&dir).join(name);
    Ok(PinnedLog { dir: Arc::new(dir), base })
}

pub(super) fn maybe_compress_rotated_best_effort(app: &str, enabled: bool, dir: &Arc<OwnedFd>, rotated: &Path) {
    if !enabled {
        return;
    }
    if rotated.extension().and_then(|s| s.to_str()) == Some("gz") {
        return;
    }
    let Some(name) = rotated.file_name().map(|n| n.to_os_string()) else { return };
    let app = app.to_string();
    let dir = Arc::clone(dir);
    tasks().spawn_blocking(move || {
        if let Err(e) = gzip_in_dir(&dir, &name) {
            pm_event(
                "logrotate",
                Some(&app),
                format!("gzip_failed file={} err={e:#}", Path::new(&name).display()),
            );
        }
    });
}

/// gzip `name` inside `dir` to `name.gz`, then remove `name` (what `gzip -f` did).
///
/// In-process rather than exec'ing gzip: `gzip -f` follows a symlink, so a service
/// that swapped its rotated log for a link to /etc/shadow got root to compress that
/// file into the service's own directory.
pub(super) fn gzip_in_dir(dir: &OwnedFd, name: &std::ffi::OsStr) -> anyhow::Result<()> {
    use crate::pm::safefs;
    let src = safefs::openat(dir, name, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK, 0)
        .context("open rotated log")?;
    let st = safefs::fstat(&src)?;
    anyhow::ensure!(safefs::is_reg_mode(st.st_mode), "rotated log is not a regular file");
    anyhow::ensure!(st.st_nlink == 1, "rotated log has {} hard links", st.st_nlink);
    let mut gz_name = name.to_os_string();
    gz_name.push(".gz");
    let create = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW;
    let dst = match safefs::openat(dir, &gz_name, create, 0o640) {
        Ok(fd) => fd,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // `gzip -f` semantics: replace. unlinkat never follows a link.
            let c = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(gz_name.as_os_str()))?;
            // SAFETY: valid dirfd and NUL-terminated name.
            unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) };
            safefs::openat(dir, &gz_name, create, 0o640).context("create .gz")?
        }
        Err(e) => return Err(e).context("create .gz"),
    };
    let mut src = fs::File::from(src);
    let dst = fs::File::from(dst);
    let mut enc = flate2::write::GzEncoder::new(dst, flate2::Compression::default());
    let compressed = std::io::copy(&mut src, &mut enc)
        .context("compress")
        .and_then(|_| enc.finish().context("finish gzip"));
    let dst = match compressed {
        Ok(f) => f,
        Err(e) => {
            // Never leave a truncated .gz beside the original (e.g. on ENOSPC); rotation
            // would shift it along as if it were a good backup.
            if let Ok(c) = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(gz_name.as_os_str())) {
                // SAFETY: valid dirfd and NUL-terminated name.
                unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) };
            }
            return Err(e);
        }
    };
    // Keep the rotated file's mtime: time-based cleanup ages logs by it.
    let times = [
        libc::timespec { tv_sec: st.st_atime, tv_nsec: st.st_atime_nsec },
        libc::timespec { tv_sec: st.st_mtime, tv_nsec: st.st_mtime_nsec },
    ];
    // SAFETY: valid fd and a two-element timespec array.
    unsafe { libc::futimens(dst.as_raw_fd(), times.as_ptr()) };
    let c = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(name))?;
    // SAFETY: valid dirfd and NUL-terminated name.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error()).context("remove uncompressed rotated log");
    }
    Ok(())
}

pub(super) async fn rotate_rename_reopen_async(base_path: &Path) -> anyhow::Result<RotatedReopen> {
    let now = Local::now();
    let ts = now.format("%Y-%m-%d_%H:%M:%S%.3f").to_string();
    let rotated = PathBuf::from(format!("{}.{}", base_path.display(), ts));
    // Best-effort: rename base -> rotated if it exists.
    let rotated_path = if tokio::fs::metadata(base_path).await.is_ok() {
        let _ = tokio::fs::rename(base_path, &rotated).await;
        Some(rotated)
    } else {
        None
    };
    let f = open_append_log_async(base_path).await?;
    Ok(RotatedReopen { f, rotated: rotated_path })
}

pub(super) async fn rotate_numbered_reopen_async(base_path: &Path, backups: usize) -> anyhow::Result<RotatedReopen> {
    // Size-based rotation:
    // base -> base.1 -> base.2 ...
    if backups == 0 {
        // keep no backups; just recreate base
        if tokio::fs::metadata(base_path).await.is_ok() {
            let _ = tokio::fs::remove_file(base_path).await;
        }
        let f = open_append_log_async(base_path).await?;
        return Ok(RotatedReopen { f, rotated: None });
    }

    // Delete oldest first.
    let oldest = PathBuf::from(format!("{}.{}", base_path.display(), backups));
    if tokio::fs::metadata(&oldest).await.is_ok() {
        let _ = tokio::fs::remove_file(&oldest).await;
    }
    let oldest_gz = PathBuf::from(format!("{}.{}.gz", base_path.display(), backups));
    if tokio::fs::metadata(&oldest_gz).await.is_ok() {
        let _ = tokio::fs::remove_file(&oldest_gz).await;
    }

    // Shift: (backups-1 ..= 1)
    for i in (1..backups).rev() {
        let from = PathBuf::from(format!("{}.{}", base_path.display(), i));
        let to = PathBuf::from(format!("{}.{}", base_path.display(), i + 1));
        if tokio::fs::metadata(&from).await.is_ok() {
            let _ = tokio::fs::rename(&from, &to).await;
        }
        let from_gz = PathBuf::from(format!("{}.{}.gz", base_path.display(), i));
        let to_gz = PathBuf::from(format!("{}.{}.gz", base_path.display(), i + 1));
        if tokio::fs::metadata(&from_gz).await.is_ok() {
            let _ = tokio::fs::rename(&from_gz, &to_gz).await;
        }
    }

    // Move base -> base.1
    let to1 = PathBuf::from(format!("{}.1", base_path.display()));
    let rotated_path = if tokio::fs::metadata(base_path).await.is_ok() {
        let _ = tokio::fs::rename(base_path, &to1).await;
        Some(to1)
    } else {
        None
    };

    let f = open_append_log_async(base_path).await?;
    Ok(RotatedReopen { f, rotated: rotated_path })
}

pub(super) fn log_rotation_key(rot: LogRotation, now: chrono::DateTime<Local>) -> String {
    match rot {
        LogRotation::Minutely => now.format("%Y-%m-%d_%H:%M").to_string(),
        LogRotation::Hourly => now.format("%Y-%m-%d_%H").to_string(),
        LogRotation::Daily => now.format("%Y-%m-%d").to_string(),
        LogRotation::Weekly => now.format("%G-W%V").to_string(),
        LogRotation::Monthly => now.format("%Y-%m").to_string(),
        LogRotation::None => "none".to_string(),
    }
}

pub(super) fn spawn_log_pump_stdout_async(def: AppDefinition, base_path: PathBuf, pipe: ChildStdout) {
    tasks().spawn(async move {
        if let Err(e) = log_pump_async(def.clone(), base_path, pipe).await {
            pm_event("logpump", Some(&def.application), format!("stream=stdout outcome=error err={e:#}"));
        }
    });
}

pub(super) fn spawn_log_pump_stderr_async(def: AppDefinition, base_path: PathBuf, pipe: ChildStderr) {
    tasks().spawn(async move {
        if let Err(e) = log_pump_async(def.clone(), base_path, pipe).await {
            pm_event("logpump", Some(&def.application), format!("stream=stderr outcome=error err={e:#}"));
        }
    });
}

pub(super) fn set_nonblocking_fd(fd: i32) -> anyhow::Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    let flags = OFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFL)?);
    let new_flags = flags | OFlag::O_NONBLOCK;
    fcntl(fd, FcntlArg::F_SETFL(new_flags))?;
    Ok(())
}

pub(super) async fn read_from_asyncfd(fd: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> anyhow::Result<usize> {
    loop {
        let mut guard = fd.readable().await?;
        let r = guard.try_io(|inner| {
            // SAFETY: fd is a valid pipe fd; buf is valid.
            let n = unsafe {
                libc::read(
                    inner.get_ref().as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n < 0 {
                let errno = nix::errno::Errno::last();
                if errno == nix::errno::Errno::EAGAIN || errno == nix::errno::Errno::EWOULDBLOCK {
                    return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                }
                return Err(std::io::Error::from_raw_os_error(errno as i32));
            }
            Ok(n as usize)
        });
        match r {
            Ok(Ok(n)) => return Ok(n),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Ok(Err(e)) => return Err(anyhow::anyhow!("read failed: {e}")),
            Err(_would_block) => continue,
        }
    }
}

pub(super) async fn log_pump_async<P: IntoRawFd>(
    def: AppDefinition,
    base_path: PathBuf,
    pipe: P,
) -> anyhow::Result<()> {
    // Convert pipe into an owned fd and make it non-blocking for AsyncFd.
    let raw = pipe.into_raw_fd();
    set_nonblocking_fd(raw)?;
    // SAFETY: we just took ownership via into_raw_fd.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    let afd = AsyncFd::new(owned)?;

    // Pin the log directory for the life of the pump; `base_path` below goes through it.
    // If the log cannot be opened safely, keep draining the pipe anyway: dropping the
    // read end would SIGPIPE the service on its first write and restart-loop it.
    let log = match pin_log(&base_path, true) {
        Ok(log) => log,
        Err(e) => {
            pm_event(
                "logpump",
                Some(&def.application),
                format!("outcome=discarding_output log={} err={e:#}", base_path.display()),
            );
            let mut sink = vec![0u8; 16 * 1024];
            while read_from_asyncfd(&afd, &mut sink).await? > 0 {}
            return Ok(());
        }
    };
    let mut out = PumpOutput {
        display_path: base_path.clone(),
        failing: false,
        base_path: log.base.clone(),
        dir: Arc::clone(&log.dir),
        f: None,
        bytes_written: 0,
        last_key: log_rotation_key(def.rotation_frequency, Local::now()),
        retry_at: None,
    };
    if let Err(e) = out.open().await {
        pm_event(
            "logpump",
            Some(&def.application),
            format!("outcome=discarding_output log={} err={e:#}", out.display_path.display()),
        );
        out.failing = true;
        out.retry_at = Some(Instant::now() + LOG_REOPEN_RETRY);
    }
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = read_from_asyncfd(&afd, &mut buf).await?;
        if n == 0 {
            break;
        }
        // A write or rotation error (disk full, the service tampering with its own log
        // directory) must not end the pump: dropping the read end would SIGPIPE the
        // service on its next write. On a shared full disk that would kill every
        // service at once. Discard output until the log can be reopened instead.
        if out.f.is_none() && !out.try_reopen().await {
            continue;
        }
        match out.write_chunk(&def, &buf[..n]).await {
            // Only transitions are logged: a disk that stays full would otherwise add
            // two events per retry for as long as the service runs.
            Ok(()) if out.failing => {
                out.failing = false;
                pm_event("logpump", Some(&def.application), format!("outcome=resumed log={}", out.display_path.display()));
            }
            Ok(()) => {}
            Err(e) => {
                if !out.failing {
                    out.failing = true;
                    pm_event(
                        "logpump",
                        Some(&def.application),
                        format!(
                            "outcome=write_error log={} action=discarding_until_writable err={e:#}",
                            out.display_path.display()
                        ),
                    );
                }
                out.f = None;
                out.retry_at = Some(Instant::now() + LOG_REOPEN_RETRY);
            }
        }
    }
    if let Some(f) = out.f.as_mut() {
        let _ = f.flush().await;
    }
    Ok(())
}

/// How long a pump discards output before trying to reopen a log it could not write.
pub(super) const LOG_REOPEN_RETRY: Duration = if cfg!(test) { Duration::from_millis(100) } else { Duration::from_secs(5) };

/// The writing side of a log pump: the open log (if any) and its rotation state.
struct PumpOutput {
    /// The configured log path, for messages (`base_path` goes through /proc/self/fd).
    display_path: PathBuf,
    /// Writes are failing; set until one succeeds again.
    failing: bool,
    base_path: PathBuf,
    dir: Arc<OwnedFd>,
    /// `None` while output is being discarded after a write error.
    f: Option<tokio::fs::File>,
    bytes_written: u64,
    last_key: String,
    retry_at: Option<Instant>,
}

impl PumpOutput {
    /// Reopens the log once the retry delay has passed. Returns whether it is open.
    async fn try_reopen(&mut self) -> bool {
        if self.retry_at.is_some_and(|t| Instant::now() < t) {
            return false;
        }
        match self.open().await {
            Ok(()) => true,
            Err(_) => {
                self.retry_at = Some(Instant::now() + LOG_REOPEN_RETRY);
                false
            }
        }
    }

    async fn open(&mut self) -> anyhow::Result<()> {
        self.f = Some(open_append_log_async(&self.base_path).await?);
        self.bytes_written = 0;
        self.retry_at = None;
        Ok(())
    }

    async fn write_chunk(&mut self, def: &AppDefinition, chunk: &[u8]) -> anyhow::Result<()> {
        match def.rotation_mode {
            LogRotationMode::Time => {
                let key = log_rotation_key(def.rotation_frequency, Local::now());
                if key != self.last_key && !matches!(def.rotation_frequency, LogRotation::None) {
                    self.last_key = key;
                    self.rotate(def, None).await?;
                }
            }
            LogRotationMode::Size => {
                if self.size_limit_reached(def) {
                    self.rotate_numbered(def).await?;
                }
            }
        }

        let f = self.f.as_mut().ok_or_else(|| anyhow::anyhow!("log is not open"))?;
        f.write_all(chunk).await?;
        self.bytes_written = self.bytes_written.saturating_add(chunk.len() as u64);

        // For size-based rotation, also rotate *after* writing if we crossed the threshold.
        // This fixes the case where the process writes once (one chunk), exceeds the limit,
        // and then goes quiet/EOF—without this, we'd never rotate.
        if matches!(def.rotation_mode, LogRotationMode::Size) && self.size_limit_reached(def) {
            self.rotate_numbered(def).await?;
        }
        Ok(())
    }

    fn size_limit_reached(&self, def: &AppDefinition) -> bool {
        def.rotation_size_bytes.is_some_and(|max| max > 0 && self.bytes_written >= max)
    }

    async fn rotate_numbered(&mut self, def: &AppDefinition) -> anyhow::Result<()> {
        self.rotate(def, Some(def.rotation_backups.unwrap_or(10))).await
    }

    /// Rotates by renaming with a timestamp (`numbered: None`, time-based rotation) or
    /// by shifting numbered backups (`Some(backups)`, size-based rotation).
    async fn rotate(&mut self, def: &AppDefinition, numbered: Option<usize>) -> anyhow::Result<()> {
        if let Some(f) = self.f.as_mut() {
            let _ = f.flush().await;
        }
        // The old handle is gone whatever happens next: a failed reopen leaves the
        // pump discarding rather than writing to a file that was renamed away.
        self.f = None;
        let rr = match numbered {
            None => rotate_rename_reopen_async(&self.base_path).await?,
            Some(backups) => rotate_numbered_reopen_async(&self.base_path, backups).await?,
        };
        if let Some(rotated) = rr.rotated.as_deref() {
            maybe_compress_rotated_best_effort(&def.application, def.log_compression_enabled, &self.dir, rotated);
        }
        self.f = Some(rr.f);
        self.bytes_written = 0;
        Ok(())
    }
}

// We intentionally do not keep per-child process handles; liveness is derived from cgroup PIDs.

// start_one removed: starts are driven by the per-app controller reconcile loop.

pub(super) fn resolve_log_paths(def: &AppDefinition) -> (PathBuf, PathBuf) {
    let stdout = def
        .log_stdout
        .as_ref()
        .map(|p| resolve_under_workdir(&def.working_directory, p))
        .unwrap_or_else(|| def.working_directory.join("logs").join("stdout.log"));
    let stderr = def
        .log_stderr
        .as_ref()
        .map(|p| resolve_under_workdir(&def.working_directory, p))
        .unwrap_or_else(|| def.working_directory.join("logs").join("stderr.log"));
    (stdout, stderr)
}
