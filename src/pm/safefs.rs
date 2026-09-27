//! Symlink-safe filesystem access for the root daemon.
//!
//! The daemon works as root inside directories that service users can write: working
//! directories (provisioning chowns them to the service), their `logs/`, auto-service
//! directories. Any *path*-based operation there can be redirected by swapping a
//! directory component for a symlink -- `O_NOFOLLOW` only protects the last component.
//!
//! Everything here splits a path into:
//! - a **root-controlled prefix**: directories owned by root (or the daemon's own uid)
//!   and not group/other-writable. Only root can change what is in them, so symlinks
//!   there are the operator's and are followed normally;
//! - the **rest**, walked one component at a time with `openat(O_NOFOLLOW)`, so a
//!   symlink anywhere in it is refused rather than followed.
//!
//! The result is a directory file descriptor. Operations then go through it (directly,
//! or via its `/proc/self/fd/N` magic link, which names the pinned directory itself and
//! is never re-resolved by path), so a later swap of any component changes nothing.

use anyhow::Context as _;
use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

/// Owners whose files and directories the daemon trusts: root, plus the daemon's own
/// uid when it runs unprivileged (development).
pub(crate) fn trusted_uids() -> Vec<u32> {
    let me = nix::unistd::geteuid().as_raw();
    if me == 0 { vec![0] } else { vec![0, me] }
}

fn is_trusted_meta(md: &fs::Metadata, trusted: &[u32]) -> bool {
    trusted.contains(&md.uid()) && mode_is_trusted(md.mode(), md.gid())
}

/// No write for others; group write only for group root (whose members can become
/// root anyway), so root:root 0664/0775 from a 002 umask is still accepted.
pub(crate) fn mode_is_trusted(mode: u32, gid: u32) -> bool {
    mode & 0o002 == 0 && (mode & 0o020 == 0 || gid == 0)
}

/// Is `dir` itself and every directory on the way to it root-controlled -- with every
/// symlink on the way placed by root and resolved through root-controlled directories?
pub(crate) fn is_root_controlled_dir(dir: &Path) -> bool {
    match split_trusted_prefix(dir) {
        Ok((anchor, rest)) => rest.is_empty() && anchor.is_dir(),
        Err(_) => false,
    }
}

/// `/proc/self/fd/N` for a descriptor: a path naming exactly the pinned inode.
pub(crate) fn proc_fd_path(fd: &impl AsRawFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

fn cstr(s: &OsStr) -> io::Result<CString> {
    CString::new(s.as_bytes()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

fn check_rc(rc: libc::c_int) -> io::Result<libc::c_int> {
    if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(rc) }
}

/// `openat(dir, name, flags)`; `name` must be a single component.
pub(crate) fn openat(dir: &impl AsRawFd, name: &OsStr, flags: libc::c_int, mode: libc::mode_t) -> io::Result<OwnedFd> {
    let c = cstr(name)?;
    // SAFETY: valid dirfd and NUL-terminated name; the kernel does not keep the pointer.
    let fd = check_rc(unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags | libc::O_CLOEXEC, mode as libc::c_uint) })?;
    // SAFETY: fd was just returned by the kernel and is owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Open the directory `name` inside `dir`, refusing a symlink (ELOOP).
pub(crate) fn open_subdir_nofollow(dir: &impl AsRawFd, name: &OsStr) -> io::Result<OwnedFd> {
    openat(dir, name, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW, 0)
}

/// `fstatat(dir, name, AT_SYMLINK_NOFOLLOW)`; `None` when the entry does not exist.
pub(crate) fn lstat_at(dir: &impl AsRawFd, name: &OsStr) -> io::Result<Option<libc::stat>> {
    let c = cstr(name)?;
    // SAFETY: zeroed stat is a valid out-buffer; valid dirfd and name.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatat(dir.as_raw_fd(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        return if e.kind() == io::ErrorKind::NotFound { Ok(None) } else { Err(e) };
    }
    Ok(Some(st))
}

pub(crate) fn fstat(fd: &impl AsRawFd) -> io::Result<libc::stat> {
    // SAFETY: as above.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    check_rc(unsafe { libc::fstat(fd.as_raw_fd(), &mut st) })?;
    Ok(st)
}

pub(crate) fn is_dir_mode(m: libc::mode_t) -> bool {
    m & libc::S_IFMT == libc::S_IFDIR
}
pub(crate) fn is_reg_mode(m: libc::mode_t) -> bool {
    m & libc::S_IFMT == libc::S_IFREG
}
pub(crate) fn is_lnk_mode(m: libc::mode_t) -> bool {
    m & libc::S_IFMT == libc::S_IFLNK
}

pub(crate) fn mkdirat(dir: &impl AsRawFd, name: &OsStr, mode: libc::mode_t) -> io::Result<()> {
    let c = cstr(name)?;
    // SAFETY: valid dirfd and name.
    check_rc(unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), mode) }).map(|_| ())
}

/// Resolve `path` to the longest root-controlled prefix plus the remaining components,
/// which must then be walked without following anything.
///
/// A symlink met inside the root-controlled prefix was placed by root, so it is
/// followed -- but one hop at a time: its target's components are pushed back onto the
/// work list and trust-checked like any others. A target that passes through a
/// directory some user controls therefore stops the prefix right there, and the rest
/// (including any further links that user could re-point) goes through the no-follow
/// walk. Checking only where a link finally lands is not enough: a user-owned hop in
/// the middle would choose the destination.
fn split_trusted_prefix(path: &Path) -> anyhow::Result<(PathBuf, Vec<OsString>)> {
    anyhow::ensure!(path.is_absolute(), "{} is not absolute", path.display());
    let trusted = trusted_uids();
    // Work list, top of stack = next component. ".." only ever appears here from a
    // symlink target; the caller's own path may not contain it.
    let mut stack: Vec<OsString> = Vec::new();
    push_components(&mut stack, path, false)?;

    let mut anchor = PathBuf::from("/");
    let mut hops = 0;
    while let Some(c) = stack.last().cloned() {
        if c == ".." {
            // Only reachable from a root-placed link target; the anchor is a chain of
            // real directories, so its lexical parent is its physical parent.
            stack.pop();
            anchor.pop();
            continue;
        }
        let cand = anchor.join(&c);
        let Ok(md) = fs::symlink_metadata(&cand) else { break };
        if md.file_type().is_symlink() {
            hops += 1;
            anyhow::ensure!(hops <= 40, "too many symlinks resolving {}", path.display());
            let target = fs::read_link(&cand).with_context(|| format!("readlink {}", cand.display()))?;
            stack.pop();
            if target.is_absolute() {
                anchor = PathBuf::from("/");
            }
            push_components(&mut stack, &target, true)?;
        } else if md.is_dir() && is_trusted_meta(&md, &trusted) {
            anchor = cand;
            stack.pop();
        } else {
            break;
        }
    }
    stack.reverse();
    anyhow::ensure!(
        !stack.iter().any(|c| c == ".."),
        "{} resolves through '..' below a non-root-controlled directory",
        path.display()
    );
    Ok((anchor, stack))
}

/// Push `p`'s components so that the first one ends up on top of `stack`.
fn push_components(stack: &mut Vec<OsString>, p: &Path, allow_parent: bool) -> anyhow::Result<()> {
    let mut comps: Vec<OsString> = Vec::new();
    for c in p.components() {
        match c {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(s) => comps.push(s.to_os_string()),
            Component::ParentDir if allow_parent => comps.push(OsString::from("..")),
            Component::ParentDir => anyhow::bail!("{} contains '..'", p.display()),
            Component::Prefix(_) => anyhow::bail!("unsupported path {}", p.display()),
        }
    }
    stack.extend(comps.into_iter().rev());
    Ok(())
}

/// Open directory `path` without following any symlink outside its root-controlled
/// prefix. With `create`, missing components are created (mode 0755, owned by the
/// daemon) -- also without following anything.
pub(crate) fn open_dir_safely(path: &Path, create: bool) -> anyhow::Result<OwnedFd> {
    let (anchor, rest) = split_trusted_prefix(path)?;
    let anchor_c = cstr(anchor.as_os_str())?;
    // SAFETY: valid NUL-terminated path.
    let fd = check_rc(unsafe {
        libc::open(anchor_c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
    })
    .with_context(|| format!("open {}", anchor.display()))?;
    // SAFETY: freshly returned fd.
    let mut dir = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut walked = anchor;
    for c in rest {
        walked.push(&c);
        let next = match open_subdir_nofollow(&dir, &c) {
            Ok(fd) => fd,
            Err(e) if e.kind() == io::ErrorKind::NotFound && create => {
                match mkdirat(&dir, &c, 0o755) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e).with_context(|| format!("mkdir {}", walked.display())),
                }
                open_subdir_nofollow(&dir, &c).with_context(|| format!("open {}", walked.display()))?
            }
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) || e.raw_os_error() == Some(libc::ENOTDIR) => {
                return Err(e).with_context(|| {
                    format!(
                        "{} is a symlink or not a directory inside a non-root-controlled directory; \
                         refusing to follow it as root",
                        walked.display()
                    )
                });
            }
            Err(e) => return Err(e).with_context(|| format!("open {}", walked.display())),
        };
        dir = next;
    }
    Ok(dir)
}

/// Safely open the parent directory of `path` and return it with the final component.
pub(crate) fn open_parent_safely(path: &Path, create: bool) -> anyhow::Result<(OwnedFd, OsString)> {
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} has no final component", path.display()))?
        .to_os_string();
    let parent = path.parent().unwrap_or(Path::new("/"));
    Ok((open_dir_safely(parent, create)?, name))
}

/// Open an existing regular file for reading as root without following any symlink
/// outside the root-controlled prefix. Non-blocking open, so a FIFO cannot hang the
/// caller; anything but a regular file is refused. The returned file is blocking.
pub(crate) fn open_regular_for_read(path: &Path) -> anyhow::Result<fs::File> {
    let (dir, name) = open_parent_safely(path, false)?;
    let fd = openat(&dir, &name, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK, 0)
        .with_context(|| format!("open {} (symlinks are refused here)", path.display()))?;
    let st = fstat(&fd)?;
    anyhow::ensure!(is_reg_mode(st.st_mode), "{} is not a regular file", path.display());
    // A second name could be a hard link to a root-only file (on hosts without
    // fs.protected_hardlinks); nothing the daemon reads this way legitimately has one.
    anyhow::ensure!(st.st_nlink == 1, "{} has {} hard links; refusing to read it as root", path.display(), st.st_nlink);
    // SAFETY: fd is valid; clear O_NONBLOCK now that we know it is a regular file.
    unsafe {
        let fl = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        if fl >= 0 {
            libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, fl & !libc::O_NONBLOCK);
        }
    }
    Ok(fs::File::from(fd))
}

/// Read a file the daemon will *trust* (a service definition): it must be a regular
/// file owned by root (or the daemon's uid), not group/other-writable, with a single
/// hard link, and at most `max_bytes`. All checks run on the opened descriptor, so the
/// file cannot be swapped between check and read.
pub(crate) fn read_trusted_file(path: &Path, max_bytes: u64) -> anyhow::Result<String> {
    use std::io::Read as _;
    let f = open_regular_for_read(path)?;
    let md = f.metadata()?;
    let trusted = trusted_uids();
    anyhow::ensure!(
        trusted.contains(&md.uid()),
        "{} is owned by uid {}, not root; the daemon will not load a definition that a \
         non-root user could have written",
        path.display(),
        md.uid()
    );
    anyhow::ensure!(
        mode_is_trusted(md.mode(), md.gid()),
        "{} is writable by a non-root group or by others (mode {:o}); refusing to load it",
        path.display(),
        md.mode() & 0o7777
    );
    anyhow::ensure!(md.len() <= max_bytes, "{} is larger than {max_bytes} bytes", path.display());
    let mut s = String::new();
    f.take(max_bytes + 1).read_to_string(&mut s)?;
    anyhow::ensure!(s.len() as u64 <= max_bytes, "{} is larger than {max_bytes} bytes", path.display());
    Ok(s)
}

/// `fchownat(fd, "", AT_EMPTY_PATH)`: change ownership of exactly the inode `fd` names
/// (works on `O_PATH` descriptors). `None` leaves that id unchanged.
pub(crate) fn chown_fd(fd: &impl AsRawFd, uid: Option<u32>, gid: Option<u32>) -> io::Result<()> {
    // SAFETY: valid fd and an empty NUL-terminated name with AT_EMPTY_PATH.
    check_rc(unsafe {
        libc::fchownat(
            fd.as_raw_fd(),
            c"".as_ptr(),
            uid.unwrap_or(u32::MAX),
            gid.unwrap_or(u32::MAX),
            libc::AT_EMPTY_PATH,
        )
    })
    .map(|_| ())
}

/// chmod exactly the inode `fd` names (also for `O_PATH` descriptors) via its
/// `/proc/self/fd` magic link. Callers must have refused symlinks already.
pub(crate) fn chmod_fd(fd: &impl AsRawFd, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(proc_fd_path(fd), fs::Permissions::from_mode(mode))
}

/// Give the open file `cap_net_bind_service` in its permitted and effective sets --
/// exactly what `setcap cap_net_bind_service=+ep` writes -- by setting the
/// `security.capability` xattr on the descriptor.
pub(crate) fn set_net_bind_capability(file: &impl AsRawFd) -> io::Result<()> {
    // struct vfs_cap_data, revision 2 (linux/capability.h):
    //   le32 magic_etc = VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE
    //   { le32 permitted; le32 inheritable; } data[2]   (capabilities 0-31, 32-63)
    const VFS_CAP_REVISION_2: u32 = 0x0200_0000;
    const VFS_CAP_FLAGS_EFFECTIVE: u32 = 0x0000_0001;
    const CAP_NET_BIND_SERVICE: u32 = 10;
    let mut data = Vec::with_capacity(20);
    for word in [VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE, 1 << CAP_NET_BIND_SERVICE, 0, 0, 0] {
        data.extend_from_slice(&word.to_le_bytes());
    }
    // SAFETY: valid fd, NUL-terminated name, and a buffer of the given length.
    check_rc(unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            c"security.capability".as_ptr(),
            data.as_ptr() as *const libc::c_void,
            data.len(),
            0,
        )
    })
    .map(|_| ())
}

/// Entry names in the directory `dir` (excluding `.`/`..`).
pub(crate) fn list_dir(dir: &impl AsRawFd) -> io::Result<Vec<OsString>> {
    let mut out = Vec::new();
    for e in fs::read_dir(proc_fd_path(dir))? {
        out.push(e?.file_name());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("pm-safefs-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn symlinked_directory_component_is_refused() {
        let d = tmp("dirlink");
        let target = d.join("elsewhere");
        fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, d.join("logs")).unwrap();
        // /tmp is not root-controlled, so the walk below it must not follow `logs`.
        let e = open_dir_safely(&d.join("logs"), true).unwrap_err();
        assert!(format!("{e:#}").contains("symlink"), "{e:#}");
        // And with create, nothing gets created through the link.
        assert!(open_dir_safely(&d.join("logs").join("sub"), true).is_err());
        assert!(!target.join("sub").exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn missing_components_are_created_without_following() {
        let d = tmp("create");
        let fd = open_dir_safely(&d.join("a").join("b"), true).unwrap();
        assert!(d.join("a").join("b").is_dir());
        assert!(is_dir_mode(fstat(&fd).unwrap().st_mode));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn root_controlled_symlinks_are_followed() {
        // Root-placed links in a root-controlled prefix must keep working, e.g. the
        // usrmerge /bin -> usr/bin or /var/run -> /run.
        for p in ["/bin", "/var/run"] {
            let p = Path::new(p);
            if fs::symlink_metadata(p).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
                assert!(open_dir_safely(p, false).is_ok(), "{}", p.display());
                assert!(is_root_controlled_dir(p), "{}", p.display());
            }
        }
    }

    // Regression: a link was trusted if its *final* target was root-controlled, so a
    // user-owned directory in the middle of the chain chose the destination.
    #[test]
    fn a_link_resolving_through_a_user_directory_is_not_trusted() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tmp("hop");
        let user = d.join("u");
        fs::create_dir(&user).unwrap();
        fs::set_permissions(&user, fs::Permissions::from_mode(0o777)).unwrap();
        // x -> u/l -> /usr (trusted); u is world-writable, so l can be re-pointed.
        std::os::unix::fs::symlink(&user.join("l"), d.join("x")).unwrap();
        std::os::unix::fs::symlink("/usr", user.join("l")).unwrap();
        assert!(!is_root_controlled_dir(&d.join("x")));
        // And the no-follow walk refuses the user's link instead of creating through it.
        assert!(open_dir_safely(&d.join("x").join("pmtest-should-not-exist"), true).is_err());
        assert!(!Path::new("/usr/pmtest-should-not-exist").exists());
        let _ = fs::remove_dir_all(&d);
    }

    // Regression: a working directory reached through a root link into a user-owned
    // tree (/opt/app -> /home/svc/app) stopped working; it must resolve, safely. Needs a
    // trusted directory to hold the link: $HOME counts as one for an unprivileged run
    // (the daemon's own uid is trusted then), /tmp never does.
    #[test]
    fn a_link_into_a_user_tree_resolves_and_walks_the_rest_without_following() {
        use std::os::unix::fs::PermissionsExt as _;
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else { return };
        if nix::unistd::geteuid().is_root() || !is_root_controlled_dir(&home) {
            return; // no trusted scratch location in this environment
        }
        let d = home.join(format!(".pm-safefs-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir(&d).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        let user_tree = d.join("users").join("app");
        fs::create_dir_all(&user_tree).unwrap();
        fs::set_permissions(&user_tree, fs::Permissions::from_mode(0o777)).unwrap();
        std::os::unix::fs::symlink(&user_tree, d.join("app")).unwrap(); // the "root" link

        let r = open_dir_safely(&d.join("app").join("logs"), true);
        let ok = r.is_ok() && user_tree.join("logs").is_dir();
        // ...while a link *inside* the user tree is still refused.
        std::os::unix::fs::symlink("/usr", user_tree.join("evil")).unwrap();
        let refused = open_dir_safely(&d.join("app").join("evil").join("x"), true).is_err();
        let _ = fs::remove_dir_all(&d);
        assert!(ok, "{:?}", r.err());
        assert!(refused);
    }

    #[test]
    fn read_for_read_refuses_fifo_and_final_symlink() {
        let d = tmp("reads");
        let fifo = d.join("p");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        assert!(open_regular_for_read(&fifo).is_err(), "must not block or accept a FIFO");
        fs::write(d.join("real"), b"x").unwrap();
        std::os::unix::fs::symlink(d.join("real"), d.join("link")).unwrap();
        assert!(open_regular_for_read(&d.join("link")).is_err());
        assert!(open_regular_for_read(&d.join("real")).is_ok());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn trusted_file_rules() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = tmp("trusted");
        let f = d.join("svc.yml");
        fs::write(&f, b"a: 1\n").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();
        // Owned by the test user; trusted only when that is the daemon's own uid.
        let me = nix::unistd::geteuid().as_raw();
        if me != 0 {
            assert_eq!(read_trusted_file(&f, 100).unwrap(), "a: 1\n");
        }
        fs::set_permissions(&f, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_trusted_file(&f, 100).is_err(), "world-writable must be refused");
        fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();
        fs::hard_link(&f, d.join("second")).unwrap();
        assert!(read_trusted_file(&f, 100).is_err(), "extra hard link must be refused");
        let _ = fs::remove_dir_all(&d);
    }
}
