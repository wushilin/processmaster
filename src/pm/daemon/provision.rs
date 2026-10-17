//! Working-directory provisioning and the marker that records what was provisioned.

use super::*;

pub(super) fn maybe_provision_workdir(def: &AppDefinition) -> anyhow::Result<()> {
    if def.provisioning.is_empty() {
        return Ok(());
    }
    let marker = def.working_directory.join(".pm_provisioned");
    let reason = match provisioning_staleness(def, &marker) {
        None => {
            pm_event(
                "provision",
                Some(&def.application),
                format!("decision=skip reason=marker_current marker={}", marker.display()),
            );
            return Ok(());
        }
        Some(r) => r,
    };
    pm_event(
        "provision",
        Some(&def.application),
        format!(
            "decision=run reason={reason} marker={} workdir={} entries={}",
            marker.display(),
            def.working_directory.display(),
            def.provisioning.len()
        ),
    );

    // If we need root-only actions, fail fast with a clear error.
    if !geteuid().is_root() {
        for p in &def.provisioning {
            let wants_chown = p
                .ownership
                .as_ref()
                .map(|o| o.owner.as_ref().is_some() || o.group.as_ref().is_some())
                .unwrap_or(false);
            if wants_chown || p.add_net_bind_capability {
                anyhow::bail!(
                    "service {} provisioning requires root for ownership/capabilities (pm is not root)",
                    def.application
                );
            }
        }
    }

    use crate::pm::safefs;
    // (dev, ino) of the working directory: a recursive chown of it must skip the
    // definition files, which have to stay root-owned (see load_trusted_definition).
    let workdir_id = {
        use std::os::unix::fs::MetadataExt as _;
        fs::metadata(&def.working_directory).ok().map(|m| (m.dev(), m.ino()))
    };
    for (idx, p) in def.provisioning.iter().enumerate() {
        let target = resolve_under_workdir(&def.working_directory, &p.path);
        let what = |msg: &str| {
            format!("service {} provisioning[{}]: {msg} {}", def.application, idx, target.display())
        };
        anyhow::ensure!(
            !p.path.components().any(|c| matches!(c, std::path::Component::ParentDir)),
            "{}",
            what("path must not contain '..':")
        );

        // Everything below goes through descriptors (see safefs): a symlink in *any*
        // component below the root-controlled prefix is refused, not just in the last
        // one, and nothing can be swapped between check and use.
        let (parent, name) = safefs::open_parent_safely(&target, !p.add_net_bind_capability)
            .with_context(|| what("cannot safely open the parent of"))?;
        match safefs::lstat_at(&parent, &name)? {
            Some(st) if safefs::is_lnk_mode(st.st_mode) => {
                anyhow::bail!("{}", what("target is a symlink; refusing to provision through it:"))
            }
            Some(_) => {}
            None => {
                anyhow::ensure!(!p.add_net_bind_capability, "{}", what("target does not exist (needed for setcap):"));
                match safefs::mkdirat(&parent, &name, 0o755) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e).with_context(|| what("failed to create directory")),
                }
            }
        }
        // O_PATH names the inode without opening it for I/O, so a FIFO or device node
        // at the target has no side effects.
        let fd = safefs::openat(&parent, &name, libc::O_PATH | libc::O_NOFOLLOW, 0)
            .with_context(|| what("open"))?;
        let st = safefs::fstat(&fd)?;
        anyhow::ensure!(!safefs::is_lnk_mode(st.st_mode), "{}", what("target became a symlink:"));
        // A hard link to a root file (possible where protected_hardlinks is off) would
        // otherwise hand that file to the service.
        anyhow::ensure!(
            !safefs::is_reg_mode(st.st_mode) || st.st_nlink == 1,
            "{}",
            what("target has multiple hard links; refusing:")
        );

        // Ownership (optional)
        if let Some(own) = p.ownership.as_ref() {
            let uid_opt: Option<u32> = match own.owner.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(s) => Some(match s.parse::<u32>() {
                    Ok(n) => n,
                    Err(_) => get_user_by_name(s).ok_or_else(|| anyhow::anyhow!("unknown user: {s}"))?.uid(),
                }),
            };
            let gid_opt: Option<u32> = match own.group.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                None => None,
                Some(s) => Some(match s.parse::<u32>() {
                    Ok(n) => n,
                    Err(_) => get_group_by_name(s).ok_or_else(|| anyhow::anyhow!("unknown group: {s}"))?.gid(),
                }),
            };
            if uid_opt.is_some() || gid_opt.is_some() {
                safefs::chown_fd(&fd, uid_opt, gid_opt).with_context(|| what("chown failed for"))?;
                if own.recursive && safefs::is_dir_mode(st.st_mode) {
                    let is_workdir = workdir_id == Some((st.st_dev as u64, st.st_ino as u64));
                    let skip: &[&str] = if is_workdir { DEFINITION_FILE_NAMES } else { &[] };
                    let dir = safefs::openat(&fd, std::ffi::OsStr::new("."), libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
                    let skipped = chown_tree(&dir, uid_opt, gid_opt, skip, 0)
                        .with_context(|| what("recursive chown failed under"))?;
                    if skipped > 0 {
                        pm_event(
                            "provision",
                            Some(&def.application),
                            format!("chown_skipped_hardlinked_files count={skipped} target={}", target.display()),
                        );
                    }
                }
            }
        }

        // Mode (optional; non-recursive)
        if let Some(mode) = p.mode {
            safefs::chmod_fd(&fd, mode).with_context(|| what(&format!("chmod {mode:o} failed for")))?;
        }

        // Capabilities (optional)
        if p.add_net_bind_capability {
            anyhow::ensure!(safefs::is_reg_mode(st.st_mode), "{}", what("setcap target is not a regular file:"));
            // Set the capability on the pinned inode itself. The setcap binary only takes
            // a path (and refuses a /proc/<pid>/fd magic link), which reopens the
            // check-then-use window this descriptor exists to close.
            let file = safefs::openat(&parent, &name, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK, 0)
                .with_context(|| what("open for setcap"))?;
            let fst = safefs::fstat(&file)?;
            anyhow::ensure!(
                (fst.st_dev, fst.st_ino) == (st.st_dev, st.st_ino),
                "{}",
                what("target changed during provisioning:")
            );
            safefs::set_net_bind_capability(&file).with_context(|| what("setting cap_net_bind_service failed for"))?;
        }

        pm_event(
            "provision",
            Some(&def.application),
            format!("effect=applied idx={idx} target={}", target.display()),
        );
    }

    // Fingerprint *after* every chown/chmod/setcap, since each of those bumps ctime.
    let record = ProvisioningMarker {
        version: PROVISIONING_MARKER_VERSION,
        provisioned_at_ms: Local::now().timestamp_millis(),
        entries: def
            .provisioning
            .iter()
            .map(|p| ProvisionedEntryRecord {
                spec: serde_json::to_value(p).unwrap_or(serde_json::Value::Null),
                file: file_fingerprint(&resolve_under_workdir(&def.working_directory, &p.path)),
            })
            .collect(),
    };
    write_marker_atomically(&marker, &record)
        .with_context(|| format!("service {}: failed to write marker {}", def.application, marker.display()))?;

    pm_event(
        "provision",
        Some(&def.application),
        format!("decision=done marker={}", marker.display()),
    );
    Ok(())
}

// ---------------- provisioning marker ------------------------------------------------
//
// The marker records what was provisioned and a stat fingerprint of every regular-file
// target, taken after provisioning finished. Provisioning is re-run when the spec
// changes or a file target no longer matches its fingerprint.
//
// Why stat identity rather than a content hash: file capabilities (and mode/owner) live
// on the *inode*, not the bytes. Deploying a byte-identical build via copy-and-rename
// yields a matching hash but a fresh inode with no capability; an in-place write keeps
// the inode but the kernel strips `security.capability` and bumps ctime. (dev, ino,
// ctime) catches both; size and mtime are recorded for readable diagnostics. A false
// positive (e.g. `touch`) only costs an idempotent reprovision.
//
// Directory targets are not fingerprinted: their mtime/ctime move whenever an entry is
// created inside them, which would reprovision on every start.

pub(super) const PROVISIONING_MARKER_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct FileFingerprint {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_ns: i128,
    ctime_ns: i128,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct ProvisionedEntryRecord {
    spec: serde_json::Value,
    #[serde(default)]
    file: Option<FileFingerprint>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct ProvisioningMarker {
    version: u32,
    provisioned_at_ms: i64,
    entries: Vec<ProvisionedEntryRecord>,
}

/// Fingerprint a regular-file target without following a final symlink. `None` for
/// directories, symlinks and missing paths.
pub(super) fn file_fingerprint(path: &Path) -> Option<FileFingerprint> {
    use std::os::unix::fs::MetadataExt as _;
    let md = fs::symlink_metadata(path).ok()?;
    if !md.file_type().is_file() {
        return None;
    }
    Some(FileFingerprint {
        dev: md.dev(),
        ino: md.ino(),
        size: md.size(),
        mtime_ns: md.mtime() as i128 * 1_000_000_000 + md.mtime_nsec() as i128,
        ctime_ns: md.ctime() as i128 * 1_000_000_000 + md.ctime_nsec() as i128,
    })
}

/// Why provisioning must (re)run, or `None` when the marker still matches reality.
pub(super) fn provisioning_staleness(def: &AppDefinition, marker: &Path) -> Option<String> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    // The marker sits in a service-writable workdir, so treat it as hostile input:
    // O_NOFOLLOW (no planted symlink), O_NONBLOCK (a FIFO would otherwise block this
    // open forever -- at daemon boot, on every reload and every start), a regular-file
    // check on the opened fd, and a hard size cap (a sparse 200G file must not OOM the
    // daemon). Any unreadable, legacy or malformed marker just means "reprovision".
    const MAX_MARKER_BYTES: u64 = 64 * 1024;
    let mut text = String::new();
    match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(marker)
    {
        Ok(f) => {
            let regular = f.metadata().map(|m| m.file_type().is_file()).unwrap_or(false);
            if !regular {
                return Some("marker_not_regular_file".to_string());
            }
            if f.take(MAX_MARKER_BYTES + 1).read_to_string(&mut text).is_err()
                || text.len() as u64 > MAX_MARKER_BYTES
            {
                return Some("marker_unreadable".to_string());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Some("marker_missing".to_string());
        }
        Err(_) => return Some("marker_unreadable".to_string()),
    }
    let Ok(rec) = serde_json::from_str::<ProvisioningMarker>(&text) else {
        return Some("marker_legacy_or_malformed".to_string());
    };
    if rec.version != PROVISIONING_MARKER_VERSION {
        return Some(format!("marker_version={}", rec.version));
    }
    if rec.entries.len() != def.provisioning.len() {
        return Some("spec_changed".to_string());
    }
    for (idx, (p, r)) in def.provisioning.iter().zip(&rec.entries).enumerate() {
        if serde_json::to_value(p).ok().as_ref() != Some(&r.spec) {
            return Some(format!("spec_changed idx={idx}"));
        }
        let target = resolve_under_workdir(&def.working_directory, &p.path);
        let now = file_fingerprint(&target);
        // Only compare when a file was fingerprinted; a directory target stays None.
        if r.file.is_some() && now != r.file {
            return Some(format!("target_changed idx={idx} target={}", target.display()));
        }
        // A target that was a directory (or absent) but is now a regular file also
        // needs a fresh pass, e.g. a setcap entry whose binary was replaced by a file.
        if r.file.is_none() && now.is_some() {
            return Some(format!("target_changed idx={idx} target={}", target.display()));
        }
    }
    None
}

/// Write the marker via a fresh temp file + rename. The temp file is opened
/// `O_CREAT|O_EXCL|O_NOFOLLOW`, so a planted symlink is never written through, and
/// `rename(2)` replaces a symlink at the destination rather than following it.
pub(super) fn write_marker_atomically(marker: &Path, rec: &ProvisioningMarker) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let name = format!(
        ".pm_provisioned.tmp.{}.{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let tmp = marker.with_file_name(name);
    let body = serde_json::to_string_pretty(rec)?;
    let res = (|| -> anyhow::Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o644)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(body.as_bytes())?;
        f.write_all(b"\n")?;
        fs::rename(&tmp, marker).with_context(|| format!("rename {} -> {}", tmp.display(), marker.display()))?;
        Ok(())
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

/// Files in a working directory that the daemon loads as trusted service definitions
/// (auto services). They must stay root-owned, so a recursive chown of the working
/// directory leaves them alone.
pub(super) const DEFINITION_FILE_NAMES: &[&str] = &["service.yml", "service.yaml", ".regen_pm_config"];

/// Recursive chown below the directory `dir`, entirely through descriptors: each
/// subdirectory is opened `O_NOFOLLOW` relative to its parent's descriptor, so swapping
/// a directory for a symlink mid-walk cannot redirect it. Symlinks are skipped, and so
/// are regular files with more than one hard link. Returns how many of those were
/// skipped. `skip` names are ignored at the top level only.
pub(super) fn chown_tree(dir: &OwnedFd, uid: Option<u32>, gid: Option<u32>, skip: &[&str], depth: usize) -> anyhow::Result<usize> {
    use crate::pm::safefs;
    anyhow::ensure!(depth < 256, "directory tree deeper than 256 levels");
    let mut skipped = 0;
    for name in safefs::list_dir(dir)? {
        if depth == 0 && skip.iter().any(|s| name == std::ffi::OsStr::new(s)) {
            continue;
        }
        // Pin the entry first, then decide from the pinned inode: checking by name and
        // chowning by name leaves a window to swap in a hard link to a root file.
        let fd = match safefs::openat(dir, &name, libc::O_PATH | libc::O_NOFOLLOW, 0) {
            Ok(fd) => fd,
            Err(_) => continue, // vanished meanwhile
        };
        let st = safefs::fstat(&fd)?;
        if safefs::is_lnk_mode(st.st_mode) {
            continue;
        }
        if !safefs::is_dir_mode(st.st_mode) && st.st_nlink > 1 {
            skipped += 1;
            continue;
        }
        safefs::chown_fd(&fd, uid, gid)?;
        if safefs::is_dir_mode(st.st_mode) {
            // Recurse through the pinned directory itself, never by name.
            let sub = safefs::openat(&fd, std::ffi::OsStr::new("."), libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            skipped += chown_tree(&sub, uid, gid, skip, depth + 1)?;
        }
    }
    Ok(skipped)
}
