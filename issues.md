# processmaster — code audit

Audit of the `processmaster` daemon and `pmctl` client, targeting **code safety**, **code cleanliness**, and **architecture / modularity / efficiency**.

Scope: all of `src/` (13,087 lines), `templates/`, shipped configs, and dependency health, at commit `eacc508` on `master`.

Method: manual code review across five parallel passes (privilege/spawn, web console, config/provisioning/filesystem, cgroup/RPC, maintainability), plus `cargo check`, dependency review, and targeted empirical verification of the highest-impact claims. Every issue below was confirmed by reading the code; speculative findings were dropped. Where a claim was surprising, it was verified by running it — see [Issue 8](#8-high--unquoted-octal-file-modes-are-parsed-as-decimal) in particular.

**Threat model.** The daemon runs as root by design. The trust boundaries that matter are therefore:

1. **Supervised services → daemon.** A service may run as an unprivileged user and owns its own working directory. It must not be able to influence the root daemon into acting on its behalf.
2. **Network → web console.** The console binds `0.0.0.0:9001` by default and can run arbitrary root commands via `admin_actions`.
3. **Local users → RPC socket.** The socket's file permissions are the only access control on the RPC protocol.
4. **Config authors → daemon.** Service YAML is assumed to be written by an administrator, but it is loaded from directories that provisioning may have chowned to a service user.

Issues 3, 4, 5, and 6 all cross boundary 1, which is the weakest area of the codebase.

---

## Summary

| Severity | Count |
|---|---|
| Critical | 6 |
| High | 11 |
| Medium | 14 |
| Low | 12 |
| **Total (safety)** | **43** |
| Cleanliness / maintainability | 10 themes — see [Part 2](#part-2--code-cleanliness) |
| Architecture / modularity / efficiency | 12 themes — see [Part 3](#part-3--architecture-modularity-and-efficiency) |
| **Test coverage** | was **0%**; now 58 tests. See [A11](#a11-test-architecture--the-coverage-gap) |

`cargo check --all-targets` is **completely clean** — zero compiler warnings. Clippy is not installed on this machine and could not be run; installing it (`rustup component add clippy`) and wiring it into CI is recommended.

The recurring root causes, in order of how much they cost:

- **Filesystem operations performed as root on paths that a lower-privileged user controls, without `O_NOFOLLOW` or fd anchoring.** Issues 3, 4, 24, 25, 26, 39, 40.
- **No validation of the `application` name** before it is interpolated into filesystem and cgroup paths. Issues 5, 23. Notably, `web_console.rs:828` already implements exactly the missing check — the privileged path in `daemon.rs` just doesn't use it.
- **Errors coerced into "safe-looking" values** (`unwrap_or(false)`, discarded `Result`, hardcoded `ok: true`). Issues 10, 11, 19, 28, 29. These directly undermine the project's headline "stops are DEFINITIVE" guarantee.
- **Insecure defaults** chosen for convenience. Issues 2, 16, 20.

---

## Status: what has been fixed

The `hardening-and-tests` branch fixes the issues marked **[FIXED]** below and adds the
first test suite (58 tests). Two further bugs were found *by* that work and are also
fixed; both are recorded here because neither was visible from code reading alone.

**Found while smoke-testing the privilege-drop fix.** `users` 0.11 — the unmaintained
crate flagged under [Dependency health](#dependency-health) — returns a bogus trailing
entry from `get_user_groups`: on this host it reports `nobody` as a member of **gid 0**.
The first version of the `setgroups` fix passed that list straight through, so a service
configured `user: nobody` still launched with `groups=65534(nogroup),0(root)`. Calling
`getgrouplist(3)` directly fixes it; verified end to end, a dropped-privilege service now
reports `groups=65534(nogroup)`. This is a good argument for retiring the dependency.

**Found by the new config test.** The repo's own `config.yaml` — the file the daemon
loads when started with no `-c` flag — did not parse at all. It set
`web_console.client_host`, `web_console.client_port`, `web_console.cookie_secure` and
`web_console.tls.cookie_secure`; only `tls.client_host` exists in the schema, and
`deny_unknown_fields` makes the rest fatal. The daemon would refuse to start. Fixed, and
`tests/shipped_configs_load.rs` now loads every shipped config so it cannot regress.

**Also fixed:** the web console could not bind to any IPv6 address. Validation built the
socket address with `format!("{bind}:{port}").parse()`, which requires IPv6 literals to
be bracketed, so `bind: "::1"` was rejected as malformed. Both call sites now go through
`config::parse_bind_addr`, which parses the IP and port separately.

Everything not marked `[FIXED]` remains open.

---

# Part 1 — Code safety

## Critical

### 1. CRITICAL — CSRF protection never executes (path comparison can't match after `nest`)  **[FIXED]**

**`src/pm/web_console.rs:300`**, with the router at `:151-176`.

```rust
if method == axum::http::Method::POST && uri == "/processmaster/rpc" {
```

`uri` is `req.uri().path()` **as seen inside the nested router**. In axum 0.7, `Router::nest` wraps endpoints in `StripPrefix` *outside* the layers attached with `Router::layer`, so this middleware observes `/rpc`, never `/processmaster/rpc`. The condition is never true and **no POST is ever CSRF-checked**. The feature is dead code.

A second bug in the same feature corroborates that it has never fired: `status_page` (`:365`) reads the CSRF cookie from the *request*, but the cookie is only set on the *response* (`:312-322`). On a fresh visit the rendered `<meta name="csrf-token">` is empty, so the JS sends an empty `X-CSRF-Token`. If the check worked, every action on first page load would 403.

**Failure scenario:** a logged-in operator visits a malicious page, which submits a cross-origin POST to `/processmaster/rpc`. Today the only thing standing in the way is axum's `Json` content-type requirement forcing a CORS preflight — an incidental mitigation that disappears the moment a reverse proxy adds CORS headers or a form-encoded/GET action is introduced. The endpoint reaches `admin_action`, which runs arbitrary configured argv **as root**.

**Fix:** compare against the stripped path (`"/rpc"`), or better, key off the method — reject any non-`GET`/`HEAD`/`OPTIONS` request lacking a matching token. Compare tokens with a constant-time equality. Generate the token in the handler so it is present on first render. Add a regression test that POSTs with no token and asserts 403.

### 2. CRITICAL — Built-in `admin`/`admin` credentials, silently active, on all interfaces  **[FIXED]**

**`src/pm/config.rs:187-198`** (default), **`:434-439`** (only overridden when both `auth:` and `basic:` are present), **`daemon.rs:951-961`** (validation does not reject the default).

The hardcoded default is `admin:$2a$10$jqNWtAzhWEVlPnvJwyI6g...`, which verifies against the password `admin`. That exact hash is committed in `config.yaml:69`, `examples/config.full.yaml:68`, and `README.md:138`, so it is public. Defaults are `bind = 0.0.0.0` (`config.rs:276`), `port = 9001`, `tls.enabled = false`.

`validate_web_console_config` only asserts `!users.is_empty()`, which the built-in default satisfies. An operator who writes `web_console: {enabled: true}` and omits `auth:` gets a root-equivalent control API on every interface, with a publicly known password, and **no warning is logged**.

**Fix:** make `auth.basic.users` mandatory when the console is enabled. At minimum, detect that the configured hash equals the shipped default and refuse to start (or log a loud warning every startup). Consider defaulting `bind` to `127.0.0.1`.

### 3. CRITICAL — Root log writer follows symlinks: arbitrary file append as root  **[FIXED]**

**`src/pm/daemon.rs:5010-5024`** (`open_append_log_async`), reached via **`:4789`, `:4813-4816`** and **`:5300-5325`** (`resolve_log_paths` → `resolve_under_workdir`).

The daemon keeps service stdout/stderr as pipes and writes the log files itself, **as root**:

```rust
let f = tokio::fs::OpenOptions::new().create(true).append(true).write(true).open(path).await?;
```

No `O_NOFOLLOW`, no fd anchoring, no containment check, and `create_dir_all(parent)` runs first. `resolve_under_workdir` (`:5319`) explicitly passes absolute paths through unchanged.

**Failure scenario:** a service runs as an unprivileged user and owns its working directory — the normal arrangement, which provisioning actively creates by chowning the workdir to the service user. The service runs `rm logs/stdout.log; ln -s /etc/cron.d/pwn logs/stdout.log`, then exits so the supervisor restarts it. Root follows the symlink, creates `/etc/cron.d/pwn`, and appends whatever the service prints to stdout — bytes the attacker fully controls. That is root code execution from an unprivileged service. `/root/.ssh/authorized_keys` works equally well; append-only is sufficient for both. No race is required.

**Fix:** open log files with `O_NOFOLLOW`, ideally via `openat` relative to an `O_PATH` fd for the log directory; reject absolute or `..`-escaping log paths unless explicitly opted in; verify with `fstat` that the opened file is a regular file.

### 4. CRITICAL — Provisioning `chown`/`chmod`/`setcap` follow symlinks on the target

**`src/pm/daemon.rs:4869`** (target resolution), **`:4920`** (`chown`), **`:4935`** (`set_permissions`), **`:4948-4950`** (`setcap`), **`:4986`** (`chown_recursive` root).

`chown_recursive`'s *walk* correctly skips symlinks (`:4995-4999`), but **the root target itself is never checked**. Line 4986 calls `nix::unistd::chown`, which is `chown(2)` and follows symlinks — `lchown`/`fchownat(AT_SYMLINK_NOFOLLOW)` is never used. `fs::set_permissions` is `chmod(2)` (follows), and `setcap` follows too. The `symlink_metadata` call at `:4987` happens *after* the chown and only controls recursion.

**Failure scenario**, using the README's own documented example (`README.md:415-424`) and re-provisioning flow (`README.md:405-410`): a service has `provisioning: [{path: ./bin/myserver, mode: "0755", add_net_bind_capability: true}]`. The unprivileged service deletes `.pm_provisioned`, replaces `./bin/myserver` with a symlink to `/etc/shadow`, and waits for the next `pmctl update`. Root then runs `chmod 0755 /etc/shadow`. With an `ownership:` entry aimed at a symlink to `/etc`, root chowns `/etc` to the service user — trivial full root. `setcap` on a symlink grants file capabilities to any binary on the system.

**Fix:** open each target `O_PATH|O_NOFOLLOW` and operate via `/proc/self/fd/N`; at minimum `lstat` and bail on symlinks. Use `fchownat(..., AT_SYMLINK_NOFOLLOW)` and `fchmodat`. Run `setcap` only after confirming a regular non-symlink file. Reject provisioning paths that escape `working_directory`.

### 5. CRITICAL — `application` name is unvalidated and reaches cgroup paths  **[FIXED]**

**`src/pm/app.rs:565-568`** (accepted after only `trim()`), **`daemon.rs:4707-4711`** (`app_cgroup_dir`).

```rust
master_cgroup_dir(cfg).join(format!("pm-{app}"))
```

`PathBuf::join` splits on `/`, so an app name containing `/../` escapes the master cgroup root. Every privileged cgroup operation flows through this helper: `launcher_kill_all` → `cgroup::kill_all_pids` (`:7567`), `launcher_kill_signal` (`:7560`), `launcher_pids` (`:7539`), and `ensure_dir`/`create_dir_all` on start (`:4447`).

**Failure scenario:** a service definition with `application: "x/../../system.slice"` yields `/sys/fs/cgroup/<master>/pm-x/../../system.slice`. `create_dir_all` materialises `pm-x`, the kernel resolves the `..` components, and `pmctl stop <app>` writes `1` to `/sys/fs/cgroup/system.slice/cgroup.kill` — SIGKILL to every systemd service on the host, issued by a root daemon.

This is demonstrably an oversight rather than a decision: **`web_console.rs:828-843` already implements the exact missing check** (rejecting `..` and empty segments), but the daemon's privileged path does not use it.

**Fix:** validate app names at load time against something like `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, rejecting `.`, `..`, `/`, empty, and control characters. Additionally assert in `app_cgroup_dir` that the canonicalised result is still under `master_cgroup_dir`.

### 6. CRITICAL — Privilege drop is incomplete: no `setgroups`, and `setuid` can run without `setgid`  **[FIXED]**

**`src/pm/cgroup.rs:512-527`**, reached from `daemon.rs:5576-5579`.

Two independent defects in the same block:

**(a) Supplementary groups are never cleared.** `grep -rn "setgroups\|initgroups" src/` returns nothing. After `fork`, the child inherits the daemon's supplementary group list. `setuid()` does *not* reset it — only an explicit `setgroups()` does. A service configured `user: appuser, group: appgroup` execs with uid/gid set but `groups=[0, ...]`. On a host where root is also in `docker`, that "unprivileged" service can reach `/var/run/docker.sock` and regain root immediately; `disk` gives raw block-device access, `adm` gives log access.

**(b) `setgid` is conditional on `group` being set, independently of `user`.** The two are separate `Option<String>` fields (`app.rs:278-280`) with no cross-validation anywhere. A service specifying only `process.user: appuser` executes `setuid(appuser)` while **still holding gid 0**. The daemon reports a normal, "unprivileged" start.

**Fix:** resolve the target user's group list in the parent with `getgrouplist()`; in the child call `setgroups()` first, then `setgid()`, then `setuid()`, in that order. Reject configs that set `user` without `group` (or default `group` to the user's primary gid). Verify the drop actually took effect afterwards (see [Issue 17](#17-high--uidgid-drop-is-never-verified)).

---

## High

### 7. HIGH — `pre_exec` closure is not async-signal-safe  **[FIXED]**

**`src/pm/cgroup.rs:501-529`**, in a process running a multi-threaded tokio runtime (`daemon.rs:777`).

Between `fork()` and `exec()`, only async-signal-safe operations are permitted. This closure performs several that are not:

- `std::fs::OpenOptions::open` (`:509`) — allocates a `CString`.
- `users::get_group_by_name` / `get_user_by_name` (`:514`, `:521`) — these allocate (`vec![0; 2048]`) and call `getpwnam_r`/`getgrnam_r`, which take glibc-internal locks and may `dlopen` NSS modules (`nss_systemd`, `nss_sss`, `nss_ldap`) and open sockets.
- `format!` in every error path (`:515`, `:518`, `:522`, `:525`).

**Failure scenario:** a tokio worker or a `spawn_blocking` thread holds the glibc malloc arena lock or the NSS module lock at the moment another thread calls `spawn()`. In the forked child, that lock is held by a thread that does not exist, so the allocation or NSS lookup **deadlocks forever**. The child hangs before `exec`, never enters its cgroup, is never reaped, and the parent's waiter thread (`daemon.rs:6825`) blocks permanently, wedging that app's supervisor. On hosts using `nss_sss`/`nss_ldap` this shifts from theoretical to likely, since those lookups involve socket I/O and further locks.

The comment at `:496-500` documents the *ordering* but never states the async-signal-safety invariant, and the `unsafe` block carries no `// SAFETY:` justification.

**Fix:** resolve uid, gid, the supplementary group list, and open the `cgroup.procs` fd **in the parent** (`build_command` already opens it at `:489` as a preflight — keep that fd). In the child use only raw `libc::write`, `libc::setgroups`, `libc::setgid`, `libc::setuid`, returning bare `io::Error::from_raw_os_error(errno)` with no allocation.

### 8. HIGH — Unquoted octal file modes are parsed as decimal  **[FIXED]**

**`src/pm/config.rs:330-346`** (numeric branch at `:337-340`) and **`src/pm/app.rs:389-414`** (numeric branch at `:397-401`).

The string branch parses base-8 correctly (`parse_mode_str`, `config.rs:348-354`), but the **number** branch takes the YAML integer verbatim as a mode.

I verified the exact behaviour empirically against serde_yaml 0.9.34 (the pinned version). Results:

| YAML | Parsed as | Resulting mode | Correct? |
|---|---|---|---|
| `mode: 0600` | String | `0o600` | ✅ |
| `mode: 0660` | String | `0o660` | ✅ |
| `mode: 0770` | String | `0o770` | ✅ |
| `mode: "660"` | String | `0o660` | ✅ |
| `mode: 660` | Number | **`0o1224`** | ❌ |
| `mode: 700` | Number | **`0o1274`** | ❌ |
| `mode: 750` | Number | **`0o1356`** | ❌ |
| `mode: 666` | Number | **`0o1232`** | ❌ |

Leading-zero forms are safe: YAML 1.2 treats `0600` as a *string* (serde_yaml's `digits_but_not_number`), so it reaches the correct base-8 path. The bug is confined to forms **without** a leading zero — which the README explicitly advertises as valid (`README.md:121`: `mode: 0660 # octal; accepts 660, "660", or "0660"`) and which **`examples/config.yaml:12` actually ships** (`mode: 660`).

**Failure scenario:** `connect(2)` on a unix socket requires *write* permission. An operator writes `unix_socket: {mode: 750}` intending owner-only access; the result is `0o1356` — other = `6` (`rw-`) — so **every local user can connect to the root RPC socket** and invoke `admin_actions`, which run arbitrary root argv. `mode: 700` yields `0o1274`, granting the group `rwx`. The shipped `mode: 660` yields `0o1224` (sticky bit set, owner write-only) — not directly exploitable, but silently wrong.

There is also no range validation: `mode: 2500` → `0o4704` sets **setuid** on a provisioned file, and values exceeding `u32` truncate silently (`as u32` at `config.rs:339`, `app.rs:401`).

**Fix:** parse numeric modes as octal digits, or reject non-string modes with an error telling the operator to quote the value. Reject modes `> 0o777` unless setuid/setgid/sticky is explicitly intended. Warn at startup if the resulting socket mode grants non-owner write. Fix `examples/config.yaml:12` and the README.

### 9. HIGH — Global `waitpid(-1)` reaper races every `Child::wait`/`try_wait`

**`src/pm/daemon.rs:2286-2299`** (started unconditionally at `:877`), racing **`:5640`** (`try_wait` for `stop_command`) and **`:6825`** (`child.wait()` in the per-app waiter thread).

```rust
match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
```

`waitpid(None, ...)` reaps **any** child, including those still owned by live `std::process::Child` handles.

**Failure scenario:** a `stop_command` exits; the reaper wakes within 500 ms and consumes its status. The polling loop at `:5638-5646` then gets `ECHILD` from `try_wait`, which `?`-propagates and is handled at `:5389-5396` as `stop_command_error`. The daemon concludes the stop helper failed, falls back to signalling, and on grace expiry escalates to `cgroup.kill` — **a cleanly-succeeding stop command gets the whole app SIGKILLed**. The same race at `:6825` makes `child.wait()` return `Err`, which is mapped to `code: Some(1)`, so a clean `exit(0)` is misreported as a crash, driving spurious restarts and `failed` flags. Additionally, once the reaper reaps a pid, the kernel may recycle it while the `Child` still holds it.

**Fix:** remove the blanket reaper. Reap only genuinely disowned children (the admin-action path at `:2736-2740` that drops the `Child`), tracking their pids in a set the reaper consults — or double-fork admin actions so they reparent to init.

### 10. HIGH — `stop` reports success without attempting a kill when the cgroup read fails  **[FIXED]**

**`src/pm/daemon.rs:6042`** (ManualStop), **`:6087`** (ShutdownStop), **`:6106`** (OverTimeStop), **`:3899`/`:3912`** (stop-all pre-filter).

```rust
if !cgroup_running_async(&cfg, &app).await.unwrap_or(false) {
    set_phase_and_emit(..., Phase::Stopped, "stop_noop_already_stopped");
    let _ = resp.send(Ok(()));   // reported as a successful stop
```

An **error** reading the cgroup is coerced to "not running". `list_pids` returns `Err` on `read_dir` failure (`cgroup.rs:114`), on the `MAX_DIRS` guard (`:102-107`, >50,000 descendants), on pid parse failure (`:75-77`), and on `spawn_blocking` join errors (`:141`).

**Failure scenario:** a service that manages its own cgroups creates >50,000 descendants, or the daemon hits EMFILE under fd pressure (see [Issue 14](#14-high--logs--f-sessions-pin-the-blocking-pool)). `list_pids` bails, the supervisor declares "already stopped", `exec_stop_blocking` is never called, no signal and no `cgroup.kill` is ever issued — and `pmctl stop` prints success while the service keeps running. This directly contradicts `README.md:18` ("it is **DEFINITELY** not running").

The same coercion at `:6144` (ManualRestart) and `:6260` (ReloadRestart) skips the stop step entirely, so the start step launches a **second copy** of a still-running service.

The codebase gets this right elsewhere — `wait_until_empty` (`:2003`) uses `unwrap_or(true)` and `stop_common` (`:5356`) uses `?`. Only the supervisor pre-checks fail open.

**Fix:** treat `Err` as "possibly running" (`unwrap_or(true)`) at all these sites, or propagate the error.

### 11. HIGH — `Stop`/`Restart` RPC always returns `ok: true`, so a failed stop exits 0  **[FIXED]**

**`src/pm/daemon.rs:3736`** and **`:3800`**; **`rpc.rs:485-487`**; **`pmctl_cli.rs:490-496`**.

`do_stop_async` collects per-target errors into the message but hardcodes `ok: true` — unlike `do_start_async`, which correctly uses `ok: !any_err` (`:3675`).

**Failure scenario:** `stop_common` gives up with `bail!("{name}: still running after kill-all")` (`:5457`) — e.g. tasks wedged in uninterruptible D-state on a hung NFS mount. The response still says `ok: true`; `rpc::client_call` only bails when `!resp.ok`. So `pmctl stop foo` prints `error: foo: still running after kill-all` **and exits 0**. A deploy script running `pmctl stop foo && rm -rf /data/foo` proceeds against a live process.

**Fix:** derive `ok` from whether any target failed, matching `do_start_async`.

### 12. HIGH — `bcrypt::verify` runs inline on the async runtime: unauthenticated DoS  **[FIXED]**

**`src/pm/web_console.rs:272`**, called from `:227` (an `async fn` middleware).

The daemon uses one shared multi-thread runtime (`daemon.rs:777`) for both the web server and all supervision work. `bcrypt::verify` at cost 10 burns 60–100 ms of CPU synchronously on a tokio worker. The `AuthCache` caches only *successes* (`:37-41`), so every failed attempt pays full cost. There is no rate limiting, lockout, or per-IP throttle anywhere.

**Failure scenario:** an unauthenticated attacker opens `4 × num_cpus` connections looping `POST /processmaster/rpc` with random Basic credentials. Every worker parks in bcrypt, the runtime stops making progress, crashed services are not restarted, and stop/start requests hang. No credentials needed.

**Fix:** wrap the verify in `spawn_blocking`, add a per-IP failed-attempt limiter with backoff, and bound verification concurrency with a semaphore.

### 13. HIGH — Children inherit the root daemon's entire environment

**`src/pm/cgroup.rs:475-477`** — `for (k, v) in &p.environment { cmd.env(k, v); }`, with no `cmd.env_clear()` anywhere in the repo.

`std::process::Command` starts from the parent's environment; `.env()` only adds to it. Every service and admin action therefore inherits the full environment of the root daemon.

**Failure scenario:** the daemon is started by systemd with `Environment=` secrets, or from an operator shell holding `AWS_SECRET_ACCESS_KEY`, `VAULT_TOKEN`, or `KUBECONFIG`. Those are handed verbatim to a service that has just dropped to `appuser`, which reads them from its own `/proc/self/environ`. In the other direction, anyone who can restart the daemon with a modified environment injects `LD_PRELOAD`/`PATH` into every child — and since `Command::new` does `execvp`-style `PATH` resolution when `argv[0]` is not absolute (`cgroup.rs:469-470`), a poisoned `PATH` redirects every `start_command` that uses a bare program name.

**Fix:** call `cmd.env_clear()` before the `.env()` loop and set an explicit minimal base (`PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`) derived from the resolved target user. Require `start_command[0]` to be absolute.

### 14. HIGH — `logs -f` sessions pin the blocking pool

**`src/pm/daemon.rs:2368-2377`**, **`:3041-3110`**, runtime builder at **`:777-780`**.

`Request::LogsFollow` is dispatched via `spawn_blocking`, and `handle_logs_follow` is an infinite `loop { ...; std::thread::sleep(500ms) }` that returns only when the client's socket write fails. `max_blocking_threads` is never set, so the pool caps at tokio's default of **512**.

**Failure scenario:** 512 idle `pmctl logs -f` connections — or 512 half-open connections whose peers never read and never close — pin the entire pool. Every other `spawn_blocking` call then queues indefinitely: `do_status`, `do_logs`, `do_events`, `do_flag`, `do_perf_metrics`, and critically `exec_stop_blocking` (`:5781-5784`) and `cgroup::list_pids_async` (`cgroup.rs:139`). The root supervisor can no longer stop, inspect, or reconcile anything while supervised services keep running. This is also a plausible route to the fd exhaustion behind Issues 10 and 29.

**Fix:** bound concurrent follow sessions with a semaphore, set `max_blocking_threads` explicitly, run followers on a dedicated pool or as async tasks, and add an idle/write timeout.

### 15. HIGH — Unbounded `read_line` on the RPC socket  **[FIXED]**

**`src/pm/daemon.rs:2331-2337`**; accept loop at **`:908-923`**.

```rust
let n = reader.read_line(&mut line).await?;   // no cap
```

No length limit, no read timeout, and the accept loop spawns one task per connection with no concurrency cap (`TaskTracker` in `asyncutil.rs` only counts; it never bounds).

**Failure scenario:** any principal who can open the socket streams bytes without a newline across N connections; each connection's `String` grows until the root supervisor is OOM-killed, taking supervision of every managed service with it. The default `0600 root:root` socket limits this to root — but `sock_mode`/`sock_owner`/`sock_group` exist precisely to allow non-root operators, and that configuration turns this into a local unprivileged DoS. Note the co-build check (`:2343-2364`) is **not** a mitigation: it runs after the read and parse.

**Fix:** `AsyncBufReadExt::take(MAX_REQ_BYTES)` (e.g. 1 MiB) before `read_line`, plus a read timeout and a `Semaphore` on the accept loop.

### 16. HIGH — Credentials sent in cleartext by default

**`src/pm/config.rs:211-222`** (`tls.enabled: false`), **`:276`** (`bind: 0.0.0.0`), **`web_console.rs:1257-1266`** (plain TCP path), **`:316-318`** (`Secure` omitted when TLS is off).

The shipped default binds a root-equivalent console to all interfaces over plain HTTP. Basic-auth base64 is trivially recovered from any capture, and the CSRF cookie travels without `Secure`. There is no HSTS and no redirect-to-TLS.

**Failure scenario:** an attacker on the same L2 segment or any transit hop passively captures `Authorization: Basic ...`, decodes it, and gains full root process control.

**Fix:** default `tls.enabled` to true, or refuse to bind a non-loopback address when TLS is disabled, with an explicit `insecure_allow_plaintext: true` opt-out for reverse-proxy deployments.

### 17. HIGH — uid/gid drop is never verified  **[FIXED]**

**`src/pm/cgroup.rs:517-525`.**

`setgid`/`setuid` results are checked for `Err`, but there is no post-condition check that credentials actually changed, and no guard against uid/gid 0 being the *target*.

**Failure scenario:** a config specifies `user: root`, or a user that resolves to uid 0 (e.g. a second `/etc/passwd` entry with uid 0). `setuid(0)` succeeds, the daemon logs a normal start, and the operator believes the service is sandboxed while it runs as full root. Separately, note an inconsistency: `daemon.rs:4906-4925` accepts *numeric* ids for provisioning ownership, but `build_command` only does name lookup, so `user: "1000"` fails entirely here.

**Fix:** after dropping, assert `getuid()`/`geteuid()`/`getgid()`/`getegid()` match the targets and fail the spawn otherwise. Refuse target uid/gid 0 unless explicitly opted in. Align numeric-id handling with the provisioning path.

---

## Medium

### 18. MEDIUM — Stored XSS: `esc()` does not escape quotes but is used inside attributes  **[FIXED]**

**`templates/status.html:562-566`**; sinks at `:669`, `:699`, `:753`, `:763`, `:770`, `:785-786`, `:796`, `:803`, `:974`, `:1891`, `:1893`.

```js
function esc(s) { const div = document.createElement("div"); div.textContent = s; return div.innerHTML; }
```

HTML fragment serialization escapes `&`, `<`, `>`, and U+00A0 in **text** nodes — it escapes `"` only in *attribute* mode. So `esc()` leaves `"` intact, yet its output is interpolated into `title="${...}"`, `data-app="${...}"`, and `data-flag-remove="${...}"`, then assigned via `innerHTML` (`:809`, `:814`, `:983`, `:1889`).

**Failure scenario:** user flags reach `flagsCellFor` (`:699`), rendered on the always-visible status table. `do_flag` (`daemon.rs:4194-4204`) validates only length (≤50) and lowercases — no character allow-list — and flags are persisted across restarts. The 27-character lowercase payload `a" onmouseover=alert(1) x="` survives the round trip and emits `title="a" onmouseover=alert(1) x=""`. Any operator who hovers that row executes attacker JS in the console origin. Because browsers auto-attach cached Basic credentials to same-origin XHR, and CSRF is dead ([Issue 1](#1-critical--csrf-protection-never-executes-path-comparison-cant-match-after-nest)), the injected script can immediately call `admin_action` for root command execution.

**Fix:** use the existing `escapeHtmlFast` (`:1681-1693`), which escapes `&<>"'` correctly, everywhere `esc()` is used; and allow-list flag characters server-side in `do_flag` (e.g. `[a-z0-9_.-]`).

*Not vulnerable:* log content routes through `escapeHtmlFast` in `ansiToHtml` (`:1697`, `:1766`) before `innerHTML`. Askama templates contain no `|safe` or `escape("none")`.

### 19. MEDIUM — TLS private key written world-readable, then chmod'd; failure discarded  **[FIXED]**

**`src/pm/web_console.rs:1384`** (write) and **`:1392-1396`** (chmod).

```rust
tokio::fs::write(p, contents.as_bytes()).await?;                        // 0666 & ~umask → 0644
let _ = std::fs::set_permissions(&key, Permissions::from_mode(0o600));  // error discarded
```

The daemon never calls `umask()`, so under the usual systemd umask 022 the complete PEM private key exists at mode 0644 between the write and the chmod.

**Failure scenario:** a local unprivileged user — for instance one of the supervised services — holds an `inotify` watch for `IN_CLOSE_WRITE` on the key's directory and reads `server.key` inside the window. Worse, because the chmod result is discarded, if it ever fails the key stays 0644 permanently and nothing is logged.

**Fix:** create with `OpenOptions::new().write(true).create_new(true).mode(0o600)` so the key is never world-readable at any instant, and propagate permission errors.

### 20. MEDIUM — Default control socket in world-writable `/tmp`

**`src/pm/config.rs:260-262`** (`/tmp/processmaster.sock`), created at **`daemon.rs:2302-2325`**/**`:795`**, permissions applied only *after* bind at **`:802`** → `apply_socket_settings` (`:2097-2101`).

**Failure scenario A (DoS + spoofing):** any local user pre-binds a listening `AF_UNIX` socket at `/tmp/processmaster.sock` before the daemon starts. `prepare_socket` connects successfully, concludes "pm daemon already running", and the daemon refuses to boot — an unprivileged DoS against a root supervisor. Worse, `pmctl` (run as root) then connects to the attacker's socket and renders attacker-controlled JSON as authoritative daemon output, so the operator sees fabricated service status while nothing is running.

**Failure scenario B (permission window):** between `bind()` and `set_permissions`, the socket carries `0777 & ~umask`. The daemon never sets a umask, so it inherits whatever it was started with; a `UMask=0000` unit leaves a world-connectable root control socket open for that window.

**Fix:** default to `/run/processmaster/processmaster.sock` with a root-owned `0700` parent; `umask(0177)` around the bind; refuse to start if the socket's parent directory is writable by non-root.

### 21. MEDIUM — `@file://` env indirection: unbounded read on non-regular files

**`src/pm/daemon.rs:4737-4750`**, called from `:5586-5591`.

The 64 KiB cap (`MAX_ENV_FILE_BYTES`, `:83`) is guarded by `if m.is_file() && ...`, so it is **skipped entirely for non-regular files**, and `fs::read` then runs unconditionally.

**Failure scenario:** `environment: [{name: X, value: "@file:///dev/zero"}]` — `is_file()` is false, no cap applies, and `fs::read` grows a `Vec` until the root daemon is OOM-killed, taking down every supervised service. `@file:///path/to/fifo` blocks the launch path indefinitely instead. Even for regular files, the metadata-then-read sequence is a TOCTOU, so the cap can be bypassed by growing the file between the two calls.

Separately by design: the read happens as root with no path restriction and the bytes land in the environment of a child running as `process.user`, readable via `/proc/<pid>/environ` — so `@file:///etc/shadow` converts write access to a service definition into read access to any root-only file.

**Fix:** reject non-regular files up front and enforce the cap *during* the read (`File::open(...).take(MAX_ENV_FILE_BYTES)`) rather than trusting a prior `metadata` call.

### 22. MEDIUM — `logs.hints` is an arbitrary root file-read primitive exposed over RPC and the web console

**`src/pm/app.rs:466-468`** (no validation) → **`daemon.rs:2860-2862`** (`do_logs`) and **`:2957-2959`** (`handle_logs_follow`), both via `resolve_under_workdir`, which permits absolute paths.

**Failure scenario:** `logs: {hints: ["/etc/shadow", "/root/.ssh/id_rsa"]}` in any service definition. `pmctl logs <app>` or the web console log view then streams those files, read with root privileges, to any console user. Combined with [Issue 2](#2-critical--built-in-adminadmin-credentials-silently-active-on-all-interfaces), this is a remote root-file read.

**Fix:** constrain hint paths to `working_directory` (canonicalize and verify the prefix), or drop paths not readable by the service's own uid.

### 23. MEDIUM — `PerfMetrics` accepts an unvalidated remote-supplied name

**`src/pm/daemon.rs:2490-2497`.**

Unlike `Stop`/`Start`/`Logs`/`Status`, which resolve through `resolve_targets` or `st.defs.get(name)`, this handler only checks that the name is non-empty before building a cgroup path. Combined with [Issue 5](#5-critical--application-name-is-unvalidated-and-reaches-cgroup-paths), a client can read `memory.max`, `memory.current`, `cpu.stat`, `io.stat`, and PSI files of **any** cgroup via `{"name":"x/../../system.slice"}`. Read-only, hence Medium.

**Fix:** resolve the name against `st.defs` before constructing the path, and apply the containment check from Issue 5.

### 24. MEDIUM — `.pm_provisioned` marker write follows symlinks

**`src/pm/daemon.rs:4825-4826`** (`marker.exists()` follows symlinks) and **`:4970-4974`** (`fs::write`).

**Failure scenario:** the unprivileged service creates `${working_directory}/.pm_provisioned` as a **dangling** symlink to `/etc/nologin`. `exists()` returns false for a dangling link, so provisioning proceeds and `fs::write` follows the link, creating the target as root. Content is fixed, so this is file creation/DoS rather than content injection — but the path is fully attacker-chosen.

**Fix:** create the marker with `O_CREAT|O_EXCL|O_NOFOLLOW` and treat "marker is a symlink" as a hard provisioning failure.

### 25. MEDIUM — `.regen_pm_config` regeneration writes without `O_NOFOLLOW`/`O_EXCL`

**`src/pm/daemon.rs:7230-7341`**, rename at **`:7255`**, open at **`:7293-7298`**.

The rename to `service.yml.bak` is safe (rename operates on the link itself), but the write is `write(true).create(true).truncate(true)` with no `O_EXCL`/`O_NOFOLLOW`.

**Failure scenario:** an unprivileged owner of an auto-service directory drops `.regen_pm_config`, then races the window between the rename and the open to plant `service.yml` as a symlink to `/etc/crontab`. Root truncates and rewrites the target. Separately, `next_bak_path` (`:7231-7247`) uses a non-atomic `exists()` check, so two concurrent reloads can pick the same `.bak` name and one clobbers the other.

**Fix:** write to a temp file in the same directory with `O_EXCL`, then `rename` into place; open with `O_NOFOLLOW` and refuse if `service.yml` is a symlink.

### 26. MEDIUM — TOCTOU in `chown_recursive`'s walk

**`src/pm/daemon.rs:4991-5006`.**

```rust
let md = fs::symlink_metadata(&p)?;
if md.file_type().is_symlink() { continue; }
chown(&p, uid, gid)...   // path-based; re-resolves, follows symlinks
```

The lstat-then-chown-by-path pattern is racy — the chown is not anchored to the inode that was stat'd.

**Failure scenario:** the documented `path: .` + `recursive: true` entry walks a directory the service user owns. The attacker loops `rename("f","tmp"); symlink("/etc/shadow","f")` across many entries during re-provisioning; on a win, root chowns `/etc/shadow` to the service user. A directory swap between the `is_dir()` check (`:5001`) and `walk(&p)` (`:5002`) redirects the entire recursion outside the workdir.

**Fix:** walk with `openat`/`O_NOFOLLOW` directory fds and use `fchownat(dirfd, name, ..., AT_SYMLINK_NOFOLLOW)`. Never re-resolve a path after checking it.

### 27. MEDIUM — PID-reuse race in `kill_with_signal`

**`src/pm/cgroup.rs:193-201`.**

The pid set is snapshotted from `cgroup.procs`, then signalled with no re-verification of cgroup membership. The **graceful path of every stop** uses this (`launcher_kill_signal`, `daemon.rs:7560`); the race-free `cgroup.kill` is only used for escalation.

**Failure scenario:** a managed service forks and execs rapidly while `list_pids` walks a large subtree; a listed pid exits and the kernel recycles it for an unrelated process — including a system process, since the daemon is root and `kill(2)` has no cgroup scoping. The daemon then delivers the configured `stop_signal` to that innocent process. The existing comment ("Best-effort: ignore ESRCH races") shows the race was noticed but only the already-exited case was handled, not the reused case.

**Fix:** open a `pidfd` per pid, re-verify `/proc/<pid>/cgroup`, then `pidfd_send_signal`; or prefer `cgroup.kill` whenever the signal is SIGKILL.

### 28. MEDIUM — `write_file` destroys the errno, making a fail-safe branch dead code  **[FIXED]**

**`src/pm/cgroup.rs:28-51`** and **`:172-188`.**

`write_file` converts `io::Error` into a *formatted string* via `anyhow::anyhow!("... err={e}")`, so the error chain carries no `io::Error`. Consequently in `kill_all_pids`:

```rust
if let Some(ioe) = e.downcast_ref::<io::Error>() && ioe.kind() == io::ErrorKind::NotFound { return Ok(()); }
```

`downcast_ref::<io::Error>()` **never** matches and the branch is unreachable.

**Failure scenario:** the app cgroup directory is gone (removed during reconcile, or never created because `ensure_dir` failed and was only logged at `:4455`). `stop_common` escalates, `launcher_kill_all` propagates ENOENT (`:7569`), and the stop fails hard with a confusing "open for write … failed" instead of the intended no-op. The same lossy conversion defeats the errno diagnostics the module explicitly tries to preserve elsewhere (see the comment at `cgroup.rs:507-508`) for `apply_resources` failures like EBUSY or EINVAL.

**Fix:** return the `io::Error` (or `anyhow::Error::new(e).context(...)`) so `downcast_ref` works.

### 29. MEDIUM — cgroup waiter reports a live service as exited when the read errors

**`src/pm/daemon.rs:6798-6811`**, **`cgroup.rs:292-329`.**

```rust
Err(_) => tx2.send(WaiterExited { epoch, code: Some(1) }),   // indistinguishable from a real exit
```

**Failure scenario:** `wait_all_cancellable` calls `pidfd_open` on the first pid; under fd exhaustion it returns EMFILE — not the ESRCH that is normalised at `cgroup.rs:211-214` — so it returns `Err`. The supervisor records a crash for a still-running service (`:6650-6657`), triggers auto-restart, and now **two instances share the cgroup**. The `MAX_DIRS` bail produces the same outcome.

**Fix:** distinguish the error case (retry with backoff, emit a `watch=error` event); never synthesise an exit code from an I/O failure.

### 30. MEDIUM — Username enumeration via timing, with no rate limit  **[FIXED]**

**`src/pm/web_console.rs:260-262`.**

```rust
let Some(expected_hash) = users.get(user) else { return Err("invalid credentials".to_string()); };
```

An unknown username returns in microseconds; a known username with a wrong password costs a full bcrypt verify (~60–100 ms). Bodies are identical, but the timing gap is three orders of magnitude and there is no rate limiting to slow enumeration.

**Fix:** on unknown user, verify against a fixed dummy hash of the same cost so both paths take equal time. Combine with the limiter from Issue 12.

*Note:* the username itself is a `HashMap` lookup (SipHash with a per-process random key), not a byte comparison, so it is not a practical byte-level timing oracle. The leak is the early return.

### 31. MEDIUM — No authentication or authorization audit trail

**`src/pm/web_console.rs`** — `pm_event` appears only at `:87`, `:99`, `:118`, `:1248`, `:1290`, `:1398` (startup/shutdown/TLS), never in `basic_auth_middleware` or `jsonrpc`.

Failed logins are not recorded, and successful `/rpc` calls carry no identity — the authenticated username never reaches `dispatch_async`, so the event log for `stop_all` or `admin_action` cannot say who triggered it. After an intrusion via Issues 1 or 2, there is no evidence of the brute force and no attribution for the `admin_action` that ran attacker code as root.

**Fix:** log source IP and outcome for every auth decision (rate-limited), and thread the authenticated principal through request extensions so `pm_event` can record `actor=<user>` on every state-changing RPC.

---

## Low

### 32. LOW — Plaintext passwords retained in root process memory indefinitely
**`src/pm/web_console.rs:36-71`.** `AuthCache` stores `(expected_hash, plaintext_password)` for up to 1024 entries, never expired and never zeroized. The code comment acknowledges the tradeoff, but it converts any root-process memory disclosure — a core dump, a `/proc/pid/mem` read, hibernation to unencrypted swap — into credential disclosure, recoverable weeks later. **Fix:** cache a keyed HMAC of the password rather than the plaintext, wrap in a zeroizing type, add a TTL, and set `RLIMIT_CORE = 0`.

### 33. LOW — Auto-generated certificate: 20-year validity, `CN=test`, no SAN for the bind address
**`src/pm/web_console.rs:1302`, `:1330-1346`, `:1362-1366`.** A leaked key is valid for two decades with no revocation path — the CA key is generated at `:1310` and discarded, so no CRL/OCSP and no ability to issue a replacement. With `bind = 0.0.0.0`, remote operators connecting by hostname get a name mismatch unless `client_host` was set, training them to click through TLS warnings and re-opening MITM on the Basic credentials. **Fix:** cap validity near 397 days with regeneration on expiry, persist the CA key at 0600, derive SANs from the bind address/hostname, and warn loudly when the cert cannot cover the bind address.

### 34. LOW — `pmctl password` exposes secrets via argv and echoes stdin
**`src/pm/cli.rs:117-144`, `pmctl_cli.rs:65-78`.** `--password <value>` and `--secure <user:hash>` are ordinary clap args, so cleartext passwords and credential hashes land in world-readable `/proc/<pid>/cmdline` and shell history. The `-`/stdin fallback uses `read_line` without disabling terminal echo, so an interactively typed password is printed to screen and scrollback. **Fix:** drop the value form of `--password` in favour of stdin/`--password-file`, and clear `ECHO` when reading from a tty.

### 35. LOW — `password verify` leaks user-vs-password distinction, and echoes the credential on parse error
**`src/pm/pmctl_cli.rs:108-123`** — the username is compared with a short-circuiting `!=` and, on mismatch, exits without running bcrypt, giving the same timing oracle as Issue 30. **`:97-99`** — `anyhow!("invalid --secure entry (missing ':'): {t:?}")` prints the entire credential entry to stderr, which lands in CI logs and journald. **Fix:** always run bcrypt against a stored or dummy hash; never echo the value.

### 36. LOW — Client-side `read_line` is likewise unbounded
**`src/pm/rpc.rs:478-484`, `:510-530`.** `client_call`/`client_follow` read responses into an unbounded `String`. A hostile daemon — or an impostor socket at a path passed via `PMCTL_SOCK`, which is honoured with no ownership check (`pmctl_cli.rs:22-27`) — drives `pmctl` to OOM. **Fix:** `reader.take(MAX_RESP_BYTES)`.

### 37. LOW — `kill_orphan_pids_in_cgroup_procs_file` signals stale pids across a 300 ms sleep
**`src/pm/daemon.rs:1935-1996`.** Pids are read once (`:1941`), SIGTERM'd (`:1982`), then after a 300 ms sleep the **same stale list** is SIGKILL'd (`:1986`) with no re-read. If an orphan exits promptly and the kernel recycles its pid within the window, root SIGKILLs an unrelated process. Bounded impact — this runs only at startup against a cgroup that should be empty. **Fix:** re-read `cgroup.procs` before the SIGKILL pass, or use `cgroup.kill` here too.

### 38. LOW — Service children inherit the daemon's stdin  **[FIXED]**
**`src/pm/daemon.rs:4786-4793`** sets `stdout`/`stderr` to `piped()` but never sets `stdin`, so fd 0 is inherited. The other two spawn sites do this correctly (`:2730`, `:5614` use `Stdio::null()`). `setsid()` detaches the session but does not close the fd. **Fix:** add `cmd.stdin(Stdio::null())`.

### 39. LOW — `set_enabled_in_yaml` read/modify/write follows symlinks
**`src/pm/daemon.rs:2819-2846`.** `read_to_string` + `write` on `def.source_file` with no symlink check. Exploitation is constrained because the target must parse as a YAML mapping, but pointing an auto-service `service.yml` at, say, `/etc/netplan/50-cloud-init.yaml` means `pmctl disable <app>` makes root reserialize and inject `global.enabled` into that file. **Fix:** `O_NOFOLLOW` on read and write; write via temp file + rename.

### 40. LOW — Predictable appstate temp filename
**`src/pm/daemon.rs:1623-1626`.** `.appstate.json.tmp.<pid>` is written with `fs::write` (follows symlinks) then renamed. If `config_directory` is ever not root-exclusive, a pre-planted symlink at the predictable name redirects the write. **Fix:** `O_CREAT|O_EXCL|O_NOFOLLOW` with a random suffix, and `fsync` before rename.

### 41. LOW — File-descriptor leak on the error path of `wait_all_cancellable`  **[FIXED]**
**`src/pm/cgroup.rs:318-319.`** `wait_pidfd(fd, CANCEL_POLL_MS).with_context(...)?` returns early **without closing `fd`**. The cancellation and success paths both close it correctly (`:315`, `:325`); only the error path leaks. A `poll()` failure other than EINTR (EINVAL, ENOMEM) leaks one fd per stop attempt, and repeated failures exhaust the daemon's fd table — which in turn triggers Issues 10 and 29. **Fix:** wrap the raw fd in an `OwnedFd` so it closes on drop.

### 43. LOW — Captured service logs are created world-readable

**`src/pm/daemon.rs`** — `open_append_log_async`, reached from the log pumps at `:4866`/`:4869`.

Services get a pipe (`cmd.stdout(Stdio::piped())`, `:4840-4841`) and the **daemon** writes
the log file, so the file is created by root. That part is deliberate and desirable: the
service cannot truncate or rewrite its own audit trail, and root ownership is retained on
purpose.

The *mode* is the issue. The daemon never calls `umask()` anywhere in `src/`, so files land
at `0666 & ~umask` — 0644 under the usual systemd umask 022.

**Failure scenario:** a service prints a connection string, bearer token, or debug dump of
its configuration to stdout. Every local user on the host can read it out of
`logs/stdout.log`, including the other, less-trusted services this daemon supervises.
Observed directly: a service running as `nobody` had its captured logs created `root:root`
mode `-rw-r--r--`.

**Fix:** create captured log files with an explicit restrictive mode (`OpenOptionsExt::mode`)
or set `umask(0027)` for the daemon, and document the resulting mode so operators who *want*
group-readable logs can opt in. Note this is the same missing-umask root cause as
[Issue 19](#19-medium--tls-private-key-written-world-readable-then-chmodd-failure-discarded)
and [Issue 20](#20-medium--default-control-socket-in-world-writable-tmp).

### 42. LOW — Documented `global.user`/`global.group` do not exist and would break startup  **[FIXED]**
**`config.yaml:35-37`** documents:
```yaml
  # If you start processmaster as root and want it to drop privileges after binding the socket:
  # user: someuser
  # group: somegroup
```
But `GlobalConfigFile` (`config.rs:122-134`) has only `config_directory`, `auto_service_directory`, `default_service_user`, and `default_service_group`, and is `#[serde(deny_unknown_fields)]`. Uncommenting those lines makes the daemon **fail to start** with an unknown-field error. The daemon also hard-requires root (`daemon.rs:787`), so the described feature does not exist at all. **Fix:** delete the comment, or implement the feature.

---

## Dependency health

Not currently checkable in CI — `cargo-audit`/`cargo-deny` are not installed. Three dependencies carry known advisories or are formally unmaintained:

| Crate | Version | Status |
|---|---|---|
| `serde_yaml` | 0.9.34+deprecated | **Deprecated by its author**; no further releases. Its version string literally says so. |
| `unsafe-libyaml` | 0.2.11 | **Unmaintained** (RUSTSEC-2024-0320). Pulled in transitively by `serde_yaml`. |
| `users` | 0.11.0 | **Unmaintained** (RUSTSEC-2023-0040). Used for the uid/gid lookups in the privilege-drop path — see Issues 6 and 7. |

`axum` is on 0.7.9 while 0.8 is current. Note that migrating off `serde_yaml` would be a good moment to fix [Issue 8](#8-high--unquoted-octal-file-modes-are-parsed-as-decimal), since the octal-mode bug is a direct consequence of its scalar-typing rules.

**Recommendation:** add `cargo-deny` to CI; migrate `serde_yaml` → `serde_yml` or `serde_norway`; migrate `users` → `uzers` (the maintained fork).

---

# Part 2 — Code cleanliness

Two things are genuinely good and worth stating up front: the crate **compiles with zero warnings**, and it contains only **8 `unwrap()`/`expect()` calls in 13,000 lines**, every one of them defensible. The problems here are structural rather than local — one 7,606-line file, one 1,081-line function, and pervasive copy-paste that the compiler cannot see.

| # | Finding | Impact |
|---|---|---|
| C1 | Zero tests for a root daemon that spawns processes and writes cgroups | Critical |
| C2 | `daemon.rs` at 7,606 lines; `spawn_supervisor_thread` at 1,081 lines with a 6×-duplicated start sequence | Critical |
| C3 | `cli.rs::run()` is 192 lines of unreachable dead code duplicating `pmctl_cli::run()` | High |
| C4 | Five divergent cgroup-path builders; two skip validation (the cause of [Issue 5](#5-critical--application-name-is-unvalidated-and-reaches-cgroup-paths)) | High |
| C5 | 52 hand-written response literals; no constructors | High |
| C6 | Errors swallowed in ways that change supervisor behaviour | High |
| C7 | Verbatim duplication across files (`/proc` helpers, CLI handlers, formatters) | Medium |
| C8 | Large structs deep-cloned in per-tick loops | Medium |
| C9 | `pm` / `processmaster` / `pmctl` and app/service/job naming drift | Medium |
| C10 | Six unused dependencies; dead code hidden by module-wide `#![allow(dead_code)]` | Low |

## C1. No tests at all

`grep -rn "#\[test\]\|#\[cfg(test)\]" src/` returns **0**, and there is no `tests/` directory. This is the single highest-impact maintainability finding: 13,000 lines of code that runs as root, writes `/sys/fs/cgroup`, sends `SIGKILL` to process groups, `chown -R`s directories, and rewrites operator YAML in place — with no automated verification of any of it.

This section lists the cheapest units to test *today*, with no refactoring. For the coverage targets, the layers that need structural seams first, and the CI configuration to enforce any of it, see [A11](#a11-test-architecture--the-coverage-gap).

The cheapest high-value targets are all pure functions, testable today with no refactoring and no root:

1. **`daemon.rs:4078` `parse_flag_ttl_ms`** — 75 lines of hand-rolled parsing with descending-unit and no-repeat rules. Test `"3h1m"`, `"1m3h"` (must fail), `"5d4h3m2s1ms"`, `"1h1h"` (must fail), `"10"`, overflow, `""`.
2. **`daemon.rs:2047` `parse_size_spec_bytes`** — feeds both `memory.max` and log-rotation thresholds, so a wrong answer writes a wrong cgroup limit. Testing it immediately exposes the nine unreachable match arms noted in C10.
3. **`daemon.rs:1317` `normalize_cron_expr`** — a wrong answer means a job never fires, or fires 60× too often.
4. **`app.rs:79` `parse_duration_str`** — drives `stop_grace_period_ms`, `restart_backoff_ms`, `max_time_per_run`.
5. **`daemon.rs:289` `sysflag_set_with_rules`** — the 122-line BFS flag engine with cycle detection that decides whether a crashed service auto-restarts. Currently untestable only because it reads the `FLAG_RULES` global at `:304`; changing the signature to take `rules: &FlagRulesCompiled` makes it pure.

Also cheap and security-relevant: `web_console.rs:123` `parse_htpasswd_users`, `:238` `check_basic_auth`, `:861` `validate_systemd_unit`, and `config.rs:348` `parse_mode_str` — the last of which would have caught [Issue 8](#8-high--unquoted-octal-file-modes-are-parsed-as-decimal).

A first PR of roughly 80 lines of test code covering items 1–4 requires **zero production changes**.

## C2. `daemon.rs` is nine modules in a trench coat

At 7,606 lines it holds flag rules, event/logging plumbing, log rotation, cgroup setup, path building, process spawning, stop logic, the supervisor state machine, config loading, schedulers, appstate persistence, and all 20 RPC handlers. A `src/pm/daemon/` package split along those lines (`flags`, `events`, `logs`, `cgroup_setup`, `paths`, `spawn`, `stop`, `supervisor`, `config_load`, `schedulers`, `appstate`, `handlers`, `procstat`) would leave no module above ~950 lines.

Functions over 150 lines, longest first:

| Lines | Location |
|---|---|
| **1,081** | `daemon.rs:5707` `spawn_supervisor_thread` |
| 574 | `pmctl_cli.rs:56` `run` — the `PerfMetrics` arm alone is 329 lines containing 14 nested `fn`s |
| 396 | `web_console.rs:420` `jsonrpc` |
| 375 | `daemon.rs:7164` `merge_auto_services_best_effort` |
| 272 | `app.rs:560` `into_definition` |
| 239 | `web_console.rs:1242` `serve` — contains a 160-line nested `async fn`, which itself nests another |
| 237 | `daemon.rs:3155` `do_update_async` |
| 235 | `daemon.rs:6872` `load_app_definitions_best_effort` |
| 214 | `daemon.rs:2899` `handle_logs_follow` |
| 201 | `rpc.rs:237` `render_text` |
| 192 | `cli.rs:153` `run` — **dead**, see C3 |

Inside `spawn_supervisor_thread`, one 8-step start sequence (spawn → match join error → match spawn error → wait for cgroup non-empty → on timeout mark failed → record started → attach waiter → emit Running → reply) appears **six times**: `ReloadStart` (`:5875`), `ManualStart` (`:5955`), `ManualRestart` (`:6172`), `ReloadRestart` (`:6287`), `BootStart` (`:6363`), `ScheduledStart` (`:6424`), `FailureAutoRestart` (`:6521`). The restart-tolerance/backoff block is duplicated three more times, two of them byte-identically (`:6531`, `:6583`, `:6733`).

Extracting `start_once(ctx, kind, …)` over a `SupCtx` struct — which would also replace the seven separate `&mut` parameters currently threaded into `ensure_waiter_attached` — drops each match arm to 10–20 lines. This is the prerequisite for testing restart/backoff behaviour at all.

## C3. `cli.rs::run()` is unreachable

Verified: `cli::run()` is called only from `pm::mod::main()` (`mod.rs:12-14`), and **no binary calls that**. `src/bin/pmctl.rs` calls `pmctl_cli::run()`; `src/bin/processmaster.rs` calls the daemon directly; `src/main.rs` is literally `fn main() {}`. The compiler does not flag it because both are `pub` in a lib crate.

That is 192 lines duplicating `pmctl_cli::run()` handler-for-handler across 16 command pairs. It has already drifted: `cli.rs:274` — in the **`pm`** binary — emits `"pmctl logs requires an app name"`, and `cli.rs:170` destructures `Cmd::PerfMetrics { name, .. }`, silently discarding `interval_ms` and `once`.

Delete `cli.rs:153-344` and `mod.rs:12-14`, keeping `Args`/`Cmd`/`PasswordCmd`/`OutputFormat`, which `pmctl_cli.rs` still uses. Also fix `src/main.rs:1`, whose comment points at `src/bin/pm.rs` — a file that does not exist.

## C4. Five cgroup-path builders, two without validation

| Location | Rejects `..`/empty | Strips leading `/` |
|---|---|---|
| `daemon.rs:1760` `effective_master_cgroup_path` | yes | yes |
| `daemon.rs:4703` `master_cgroup_dir` | **no** | **no** |
| `daemon.rs:4707` `app_cgroup_dir` | **no** | — |
| `web_console.rs:817` `admin_actions_cgroup_dir` | yes | yes |
| `web_console.rs:828` `service_cgroup_dir` | yes | yes |

`daemon.rs:2567` and `web_console.rs:817` are the same function under the same name in two files. `master_cgroup_dir` joins an unvalidated `cgroup_name`, so an absolute `cgroup_name` silently discards `cgroup_root` — `effective_master_cgroup_path` guards against exactly that, and both feed real cgroup writes. Consolidating into one validating module in `daemon/paths.rs` is what fixes [Issue 5](#5-critical--application-name-is-unvalidated-and-reaches-cgroup-paths) properly.

## C5. Response boilerplate: 52 hand-written literals

`daemon.rs` contains **30 `Response { … }` literals**, each spelling out all seven fields; `perf_metrics: None` alone appears 29 times. `web_console.rs` contains **22 `JsonRpcResponse` envelope literals** (`:424` through `:804`), accounting for roughly 180 of `jsonrpc`'s 396 lines.

`rpc.rs:154` `Response` has no `Default` and no constructors. Adding `#[derive(Default)]` plus `Response::ok(msg)` / `Response::err(msg)` / `Response::with_statuses(v)`, and `rpc_ok(id, v)` / `rpc_err(id, code, msg)` on the web side, removes roughly 350 lines with no behaviour change. The `PerfPressure` mapping at `daemon.rs:2499` is the same 10-line closure written three times (cpu/memory/io).

## C6. Swallowed errors that change behaviour

There are 119 `let _ =` bindings. Most are fine; these are not:

1. **`cgroup_running_async(...).unwrap_or(false)` — 12 occurrences** (`daemon.rs:5853, 5931, 6042, 6087, 6106, 6144, 6158, 6260, 6271, 6349, 6410, 6506`). This is the root of [Issues 10](#10-high--stop-reports-success-without-attempting-a-kill-when-the-cgroup-read-fails) and 29 and deserves a single audited helper.
2. **`web_console.rs:1395`** — `let _ = set_permissions(&key, 0o600)` on a freshly generated **TLS private key**; if it fails the key stays world-readable and the next `pm_event` still logs success ([Issue 19](#19-medium--tls-private-key-written-world-readable-then-chmodd-failure-discarded)).
3. **`web_console.rs:1285-1287`** — `try_exists(...).unwrap_or(false)` ×3, so an EACCES on an existing cert is read as "missing" and silently triggers regeneration.
4. **`daemon.rs:5993, 6200`** — `let _ = spawn_process_waiter(...)`; if the waiter fails to spawn, a cron job's exit is never observed and it stays `Running` forever.
5. **`daemon.rs:1551, 1557`** — persisted user flags silently stop being written; the operator finds out after the next restart.
6. **`daemon.rs:1641-1649`** — four discarded log-retention calls; disks fill silently.
7. **`app.rs:843`** — `source_mtime_ms` silently `None` on metadata error, so "restart modified services" never detects that service as modified.

`thiserror` is declared in `Cargo.toml` but never used, and the absence of a typed error shows: `web_console.rs` hand-rolls `Result<_, String>` in two places because it has nothing to map to HTTP status codes, and every JSON-RPC failure collapses to `-32000` with a stringified anyhow chain.

Also worth a pass: three `unreachable!()`s (`pmctl_cli.rs:143`, `:627`, `cli.rs:342`) encode an invariant the type system could enforce by splitting `Cmd` into `LocalCmd` and `RemoteCmd`; and `std::process::exit(1)` at `pmctl_cli.rs:111, 123` bypasses the `anyhow::Result` flow used everywhere else.

## C7. Verbatim duplication across files

- **`/proc` uptime helpers are character-identical** in `daemon.rs:4636-4674` and `web_console.rs:903-941` (five functions, differing only in `u32` vs `i32` pid). Same for `clock_ticks_per_second`, which is the only other `unsafe` in each file.
- **Eight byte-identical supervisor wrappers** at `daemon.rs:4302-4408`, each 11 lines differing only in the `SupervisorCmd` variant → one generic `send_cmd`.
- **The bounded-parallelism `JoinSet` driver is written five times** (`daemon.rs:3634, 3699, 3763, 3820, 3892, 4029`), with an identical failure-summary tail three times.
- **`if !resp.message.trim().is_empty() { println!(…) }` appears 28 times** across `pmctl_cli.rs` and `cli.rs`.
- **Flag-list normalization** (split/trim/lowercase/non-empty) exists in six places.
- **The keep-last-known-good-on-load-failure block** appears eight times in `daemon.rs`.
- **Three different duration grammars** for one user-facing concept: `app.rs:79` (`ms/s/m/h`, single unit, floats), `daemon.rs:4078` (`d/h/m/s/ms`, multi-unit, integers), `rpc.rs:440` (formatter). `1d` is valid as a flag TTL and an error in `max_time_per_run`.
- **The timestamp format `"%Y-%m-%d_%H:%M:%S%.3f"`** is hardcoded in six places and parsed in a seventh.
- **`rpc.rs:462` and `:491`** — `client_call` and `client_follow` share ~30 identical lines and describe the same failure with two different wordings ("pm daemon socket" vs "processmaster socket").
- **Web-only JSON-RPC methods duplicate daemon handlers**: `web_console.rs:439` ↔ `do_perf_metrics`, `:673` ↔ `do_admin_ps`, `:719` ↔ `do_admin_kill`. The web path notably **skips the `pm_event` audit record** the daemon handler emits — a behavioural divergence, not just duplication, and relevant to [Issue 31](#31-medium--no-authentication-or-authorization-audit-trail).

The 15 nested `fn`s in `pmctl_cli.rs:149-434` deserve special mention: every one is pure and captures nothing, so they are nested purely by accident of where they were written. Two are already duplicates of each other (`delta` vs `delta_u64`; `fmt_bytes_per_s` vs `fmt_bytes`). Because a nested `fn` inside a match arm is unreachable from `#[cfg(test)]`, this is the densest concentration of untestable-but-trivially-testable code in the repo. Move them to a `pm::humanize` module.

## C8. Clones in hot paths

`MasterConfig` holds six `String`s, three `PathBuf`s, the entire `WebConsoleConfig` (including TLS PEM bodies and all bcrypt hashes), and a `BTreeMap` of admin actions. It is cloned **36 times in `daemon.rs`** and 3 in `web_console.rs`, including:

- `daemon.rs:1263` — inside the overtime scheduler loop, **every 5 seconds forever**, alongside a full `st.defs.clone()`.
- `daemon.rs:1160` — every minute in the cron scheduler, likewise cloning the whole definitions map.
- `daemon.rs:3897, 3910` — once **per app** inside `do_stop_all_async`.
- `daemon.rs:999` + `:1006` — cloned and then explicitly discarded (`let _ = cfg;`).
- `web_console.rs:460, 674, 720` — a full clone to read two `String` fields, on a UI polling path.

`AppDefinition` maps are cloned at eight sites, two of them into a discarded `_defs` binding (`daemon.rs:3938, 3977`), one inside a per-failure loop. Storing `Arc<AppDefinition>` in `DaemonState::defs` makes those pointer copies.

Smaller but in loops: `web_console.rs:937` and `daemon.rs:4670` collect a `Vec<&str>` per PID just to index field 19 (`.split_whitespace().nth(19)` suffices); `rpc.rs:385` allocates nine empty `String`s per continuation row.

One genuine bug in this area: **`rpc.rs:251, 256, 409` use `str::len()` (bytes) for column padding**, so any non-ASCII app name or flag misaligns the entire `pmctl status` table.

## C9. Naming drift

- **Binary naming:** `cli.rs:7` declares `name = "pm"` but the shipped binary is `processmaster`. Error strings mix "pm daemon" (`daemon.rs:2316`, `rpc.rs:465`) and "processmaster" (`rpc.rs:498`) for the same failure 30 lines apart.
- **Env prefixes:** three of them — `PROCESSMASTER_BUILD_*`, `PROCESSMASTER_ADMIN_ACTION`, and `PMCTL_SOCK`.
- **app / service / job / task:** the struct is `AppDefinition` with field `application`, but every error message inside `into_definition` says `"service {}"`, as do the ten `"unknown service: {name}"` messages in `daemon.rs`. Config keys mix both (`auto_service_directory`, `default_service_user` vs `app_cgroup_dir`, `pm-{app}`). "service" is already the user-facing term — committing to it and renaming `AppDefinition` → `ServiceDefinition` internally would settle it.
- **Command surface:** `Cmd::AdminRun { id }` maps to `Request::AdminAction { name: id }` — variant, field, and wire name all differ. `AdminList`/`AdminKill`/`AdminPs` are flat while `Password` uses a nested group. `Cmd::Password` exists in `cli.rs:108` purely so `:337` can reject it at runtime, while still appearing in `pm --help`.
- **API asymmetry:** `Request::StartAll`/`StopAll`/`RestartAll` are reachable only from the web console, never from `pmctl`. Either add the commands or document it.
- **JSON-RPC params:** web-only methods take `app` while every daemon-routed method takes `name`, for the same entity.

## C10. Dead code, stray files, and unused dependencies

**Six declared dependencies have zero uses** anywhere in `src/` — verified by plain-text grep: `thiserror`, `log`, `log4rs`, `signal-hook`, `tower`, `walkdir`. `daemon.rs:37` even documents one of them ("signal-hook kept as dependency for now, but daemon uses tokio signals"). Removing them cuts build time and audit surface.

**`cgroup.rs:1` carries a module-wide `#![allow(dead_code)]`** that hides four unused functions: `list_pids_self_only_async` (`:145`), `wait_all` (`:257`), `launch_process` (`:535`), and `resolve_device_major_minor` (`:436`). The last is ironic — it is exactly the helper that would spare operators from hand-writing `253:8` in `io_bandwidth.device`.

Other confirmed-dead items: `app.rs:1053-1064` (two `#[deprecated]` aliases with zero call sites), `daemon.rs:2471-2475`, `daemon.rs:1006` (`let _ = cfg;`), `app.rs:783` (`let restart = restart;`), `cgroup.rs:689` (`.or_else(|| None)`), and **nine unreachable match arms** in `parse_size_spec_bytes` (`daemon.rs:2081-2093`) — the `unit.pop()` at `:2078` means `"b"`, `"kb"`, `"mib"` and friends can never match. Related edge case worth pinning with a test: `"1.5"` with no unit is currently rejected.

**Stale comments that actively mislead:** `cgroup.rs:23-26` says "This module is currently not wired into the daemon. It's meant for evaluation and incremental rollout" — it is fully wired in and is the module that spawns every process. There are also seven tombstone comments describing code that no longer exists (`daemon.rs:69, 1113, 2471, 3507, 3581, 3744, 5298`).

**Files that should not be in version control:**

- **`test.log`** (13.6 KB, tracked) — a captured error transcript from a failed non-root run on someone's machine. Not a test, not a fixture.
- **`src/pm/reference.txt`** (tracked) — a scratch copy of the `SystemFlag::as_str` match arms, already stale (missing ten variants).
- **`conf.d/appstate.json`** (tracked) — daemon-generated runtime state.
- `.gitignore` contains only `/target` and `/dist`; add `*.log` and `appstate.json`.

Note also that `.sync` hardcodes a deployment-specific `oss://fleetman/prod/staging/` path, and that `conf.d/` doubles as both shipped example config and a live scratch directory (it contains `failure.sh`, `exit.sh`, `failure1.YmL`). Separating fixtures from examples would make it clearer which files an operator is meant to copy.

**Logging:** `pm_event` writing to stderr is a deliberate design, not a leftover. But `daemon.rs:900, 916, 921, 1349, 2900` use bare `eprintln!` **outside** `pm_event`, so those messages never reach the daemon log file or the event ring buffer that `pmctl events` reads. Route them through `pm_event`.

## Suggested sequencing (tactical)

This is the cleanup order for the code as it stands. For the structural changes that stop these problems recurring, see [What I would do first](#what-i-would-do-first) at the end of Part 3.

1. **Fix the criticals in Part 1** — Issues 1–6 first; they are all small, localized changes.
2. **Delete** (zero risk, ~500 lines): `cli.rs:153-344` + `mod.rs:12-14`, `app.rs:1053-1064`, the four dead `cgroup.rs` functions and its blanket `allow(dead_code)`, the tombstone comments, `test.log`, `src/pm/reference.txt`, `conf.d/appstate.json`, and the six unused dependencies.
3. **Add tests** (zero production risk): the five parsers in C1 — roughly 80 lines, pinning behaviour before any restructuring.
4. **Add constructors** (mechanical, ~350 lines removed): `Response::{default,ok,err}`, `rpc_ok`/`rpc_err`, `param_str`, `parse_flag_list`.
5. **Consolidate** (C4, C7): one validating cgroup-paths module, one `procstat` module, one `send_cmd`, one `for_each_bounded`. This is what closes Issue 5 structurally.
6. **Split `spawn_supervisor_thread`** via `SupCtx` + `start_once` + `note_restart_attempt` — the prerequisite for testing restart and backoff at all.
7. **Then** the file-level module splits, which are mostly `git mv`-shaped once steps 4–6 land.

---

# Part 3 — Architecture, modularity, and efficiency

Parts 1 and 2 describe defects and untidiness. This part is about the *shape* of the system — the decisions that make those defects likely in the first place, and that will keep producing new ones until they change.

The thesis in one sentence: **`processmaster` has a good design idea and no architecture to hold it.** The idea — one supervisor per service, cgroups as the source of truth, deterministic stops — is genuinely sound and better than the supervisord model it replaces. But it is implemented as a single 7,600-line file where domain logic, OS syscalls, transport encoding, and terminal rendering are interleaved, so nothing can be tested, every subsystem can reach every other, and the same concept is re-implemented wherever it is needed.

Note how much of Part 1 falls out of this directly. Issue 5 (cgroup path traversal) exists because a service name is a `String` instead of a validated type. Issue 10 (stop fails open) exists because a `Result` is coerced at 12 call sites instead of once in a typed API. Issues 3, 4, 24, 25, 26, 39, and 40 are all the same missing abstraction — "open a path as root, safely" — written seven times, unsafely, in seven places. **These are not seven bugs; they are one absent module, observed seven times.**

## A1. Make illegal states unrepresentable

Nearly everything in the domain is a `String` or a `PathBuf`. A service name, a cgroup path, a Unix user, a file mode, and a duration are all just text that happens to be flowing in the right direction. Validation is therefore something you must *remember* to do, and Part 1 documents six places where someone did not.

The fix is the oldest idea in typed programming: parse, don't validate. Give the domain nouns their own types with private fields and fallible constructors, so an unvalidated value cannot physically reach a syscall.

```rust
// core/src/name.rs
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct ServiceName(String);

impl ServiceName {
    pub fn parse(raw: &str) -> Result<Self, NameError> {
        let s = raw.trim();
        if s.is_empty() || s.len() > 64 { return Err(NameError::Length); }
        if !s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
            return Err(NameError::Charset);
        }
        if s == "." || s == ".." || s.starts_with('.') { return Err(NameError::Reserved); }
        Ok(Self(s.to_owned()))
    }
    pub fn as_str(&self) -> &str { &self.0 }
}

impl<'de> Deserialize<'de> for ServiceName { /* delegate to parse -> serde error */ }
```

With `app_cgroup_dir(cfg: &CgroupConfig, app: &ServiceName)`, Issue 5 stops being a bug that was fixed and becomes a bug that cannot be written. The same applies to:

| Today | Should be |
|---|---|
| `String` app name | `ServiceName` (above) |
| `PathBuf` cgroup dir | `CgroupPath` — constructed only by joining a validated `ServiceName` to a validated root |
| `u32` mode | `Mode` — parsed from octal, rejects `> 0o777`, `Display`s as `0o644`. Kills [Issue 8](#8-high--unquoted-octal-file-modes-are-parsed-as-decimal) outright |
| `Option<String>` user + `Option<String>` group | `enum RunAs { Root, User { uid: Uid, gid: Gid, groups: Vec<Gid> } }` — resolved once, in the parent. Makes [Issue 6](#6-critical--privilege-drop-is-incomplete-no-setgroups-and-setuid-can-run-without-setgid)(b) unrepresentable |
| three duration grammars | one `Duration` newtype with one parser |
| `PathBuf` log target | `WorkdirRelative` — carries its anchor directory, so it can only be opened via `openat` |

That last row deserves emphasis. If log and provisioning paths carried their anchor in the type, the *only* way to open one would be through a helper that does `openat(dirfd, …, O_NOFOLLOW)` — and Issues 3, 4, 24, 25, 39, and 40 would all be structurally impossible rather than individually patched.

## A2. Separate the pure core from the imperative shell

There is currently no seam between "deciding what to do" and "doing it." `stop_common` computes policy *and* signals processes *and* writes cgroup files *and* emits events. That is why the test count is zero: exercising any decision requires being root on a cgroup-v2 host with real processes.

The conventional remedy is a workspace with a strict dependency direction:

```
processmaster-core     pure. no std::fs, no libc, no tokio. config parsing,
                       validation, the supervisor state machine, restart policy,
                       cron evaluation, log-rotation policy.   → 100% unit-testable
        ↑
processmaster-sys      thin, honest wrappers over cgroup v2, /proc, fork/exec,
                       privilege drop — each behind a trait.
        ↑
processmaster-daemon   wiring: tokio runtime, supervisors, RPC server, web console.
processmaster-cli      pmctl.
```

`core` must not depend on `sys`. The daemon injects capabilities:

```rust
pub trait Cgroup {
    fn pids(&self, path: &CgroupPath) -> io::Result<Vec<Pid>>;
    fn kill_all(&self, path: &CgroupPath) -> io::Result<()>;
    fn apply_limits(&self, path: &CgroupPath, r: &Resources) -> io::Result<()>;
}
pub trait Spawner { fn spawn(&self, p: &LaunchSpec) -> io::Result<ChildHandle>; }
pub trait Clock    { fn now(&self) -> Instant; }
```

With a `FakeCgroup`, the entire restart-tolerance policy — "3 failures in 60 s marks the service failed" — becomes a table-driven test that runs in microseconds on any laptop. Today that logic is untestable, which is precisely why it is duplicated three times ([C2](#c2-daemonrs-is-nine-modules-in-a-trench-coat)) and why nobody has noticed.

This is also the honest answer to "we have no tests": you cannot bolt tests onto the current shape. **The seam has to exist first.**

## A3. The supervisor state machine should be data, not control flow

`spawn_supervisor_thread` is 1,081 lines because it encodes a state machine as nested `match` arms over an inlined command loop, with the state smeared across seven mutable locals (`restart_times`, `waiter_running`, `waiter_epoch`, `waiter_cancel`, `pending_failure_restart_at`, `def`, `app`). There is no single place where "what state is this service in, and what may happen next" is written down.

Make the machine explicit and pure:

```rust
pub enum State { Stopped, Starting { since: Instant }, Running { since: Instant },
                 Stopping { deadline: Instant }, Backoff { until: Instant }, Failed { reason: FailReason } }

pub enum Event { StartRequested { kind: StartKind }, StopRequested, CgroupEmpty,
                 ChildExited(ExitStatus), SpawnFailed(io::Error), Tick(Instant) }

pub enum Effect { Spawn(LaunchSpec), SignalCgroup(Signal), KillCgroup,
                  ArmTimer(Instant), Emit(EventRecord), Reply(Result<(), Error>) }

/// Pure. No I/O, no clock, no logging. Trivially testable.
pub fn step(state: State, ev: Event, policy: &RestartPolicy, now: Instant)
    -> (State, SmallVec<[Effect; 4]>);
```

The runtime becomes a small loop that receives an event, calls `step`, and executes the returned effects. The six duplicated start sequences ([C2](#c2-daemonrs-is-nine-modules-in-a-trench-coat)) collapse into one `Effect::Spawn`, because the *difference* between `ManualStart` and `BootStart` was only ever which flags to set — data, not control flow.

Two of Part 1's bugs are direct consequences of the current shape: [Issue 10](#10-high--stop-reports-success-without-attempting-a-kill-when-the-cgroup-read-fails) (fail-open at 12 sites) exists because the "is it running?" question is asked ad hoc in each arm rather than being a state the machine owns; [Issue 29](#29-medium--cgroup-waiter-reports-a-live-service-as-exited-when-the-read-errors) exists because an I/O error had nowhere to go except to be disguised as an exit event. In an explicit machine, `Event::WatchFailed` is simply a variant you must handle.

## A4. `DaemonState` is a god object with nested locks

```rust
pub(crate) struct DaemonState {
    cfg: MasterConfig,                                  // cloned 36× elsewhere
    defs: HashMap<String, AppDefinition>,               // cloned per scheduler tick
    supervisors: HashMap<String, SupervisorHandle>,
    run_info: Arc<Mutex<HashMap<String, RunInfo>>>,     // a lock inside a lock
    events: Arc<Mutex<VecDeque<EventEntry>>>,           // another
    shutting_down: Arc<AtomicBool>,
    appstate_path: PathBuf,
    appstate_dirty: Arc<AtomicBool>,
}
```

Everything is reachable from everything: 67 `Arc<Mutex<…>>` occurrences in `daemon.rs` alone, and two mutexes nested inside the outer one. There is no documented lock ordering, so the only reason this has not deadlocked is that the inner locks are held briefly. That is a property of the current code, not a guarantee.

Separate by lifetime and access pattern:

- **`Arc<Config>`** — immutable after load. Share the pointer; never clone the contents. This alone removes 39 deep clones including two in per-tick loops ([C8](#c8-clones-in-hot-paths)).
- **`Arc<Registry>`** — `RwLock<HashMap<ServiceName, Arc<ServiceDef>>>`, written only on reload.
- **Per-service state lives *inside* its supervisor task.** `RunInfo` should not be in a shared map at all; it belongs to the actor that owns the service. Status queries become a `Query` message, which also makes them consistent by construction instead of a snapshot of a map someone else is mutating.
- **Events** — an `Arc<EventBus>` with a broadcast channel, not a mutex around a `VecDeque` that every subsystem reaches into.

The rule to adopt: **shared mutable state is the exception and must be justified in a comment; message passing is the default.** The codebase already has the right instinct (one actor per service, commanded over an mpsc channel) — it just also kept the shared map.

## A5. One transport too many, one dispatcher too few

There are two front doors — the Unix socket RPC and the HTTP JSON-RPC console — and they do **not** share a handler layer. `web_console.rs` re-implements `do_perf_metrics`, `do_admin_ps`, and `do_admin_kill` (see [C7](#c7-verbatim-duplication-across-files)), and the re-implementations have already drifted: the web path **skips the `pm_event` audit record** that the daemon path emits, which is exactly [Issue 31](#31-medium--no-authentication-or-authorization-audit-trail).

The correct shape is one command/query bus with transports as thin adapters:

```rust
pub enum Command { Start(ServiceName, Force), Stop(ServiceName), Restart(ServiceName, Force),
                   SetFlags { name: ServiceName, flags: Vec<Flag>, ttl: Option<Duration> },
                   RunAdminAction(ActionId), … }
pub enum Query   { Status(Option<ServiceName>), Events { … }, Logs { … }, Metrics(ServiceName) }

pub async fn execute(ctx: &Ctx, actor: Principal, cmd: Command) -> Result<Outcome, DomainError>;
```

Every mutation flows through `execute`, which is the single place that enforces authorization, emits the audit record, and updates state. `pmctl` and the web console become serializers. Three consequences worth having: the audit gap closes structurally; `StartAll`/`StopAll`/`RestartAll` stop being web-only by accident ([C9](#c9-naming-drift)); and `Principal` finally has somewhere to live, so events can record *who*.

## A6. Adopt a typed error model at the core boundary

`anyhow` is used universally — including in library-ish code where the caller must make decisions. The cost is concrete and already visible: the web console hand-rolls `Result<_, String>` in two places because it has nothing to map to an HTTP status; every JSON-RPC failure collapses to `-32000` with a stringified chain; and [Issue 28](#28-medium--write_file-destroys-the-errno-making-a-fail-safe-branch-dead-code) is a *dead fail-safe branch* caused purely by an `io::Error` being flattened into a formatted string. `thiserror` is already a declared dependency with zero uses.

The convention: **`thiserror` enums in `core` and `sys`; `anyhow` only in the binaries.**

```rust
#[derive(Debug, thiserror::Error)]
pub enum StopError {
    #[error("service {0} is not defined")]            Unknown(ServiceName),
    #[error("stop command failed: {0}")]              StopCommand(#[source] io::Error),
    #[error("still running after kill: {n} pids")]    StillRunning { n: usize },
    #[error("cgroup unreadable: {0}")]                CgroupUnreadable(#[source] io::Error),
}
```

Now `StillRunning` maps to a non-zero exit ([Issue 11](#11-high--stoprestart-rpc-always-returns-ok-true-so-a-failed-stop-exits-0)) and HTTP 409, `Unknown` to 404, and `CgroupUnreadable` is a variant the compiler forces every caller to consider — which is [Issue 10](#10-high--stop-reports-success-without-attempting-a-kill-when-the-cgroup-read-fails) prevented by the type system rather than by discipline.

## A7. `Response` does three jobs; it should do one

`rpc::Response` is simultaneously the wire DTO, a kitchen-sink union of every possible result (seven fields, of which any given response populates one — `perf_metrics: None` appears 29 times), and a **terminal renderer**: `render_text` is 201 lines of hand-rolled ASCII table layout living on a serde struct. It even pads with `str::len()`, so any non-ASCII service name misaligns the whole table ([C8](#c8-clones-in-hot-paths)).

Split it three ways: `enum ResponsePayload { Ack { message }, Statuses(Vec<Status>), Events(Vec<Event>), Metrics(Metrics), AdminActions(Vec<Action>) }` for the wire; a `pmctl`-side `render` module owning presentation; and a `humanize` module for the formatters currently nested inside a match arm ([C7](#c7-verbatim-duplication-across-files)). Wire types should not know what a terminal is.

## A8. Stop polling; the kernel already has the events

This is the efficiency story, and it is also an elegance story — the current design burns timers to discover things the kernel would have told it for free.

| Where | Now | Should be |
|---|---|---|
| `daemon.rs:2298` child reaper | `waitpid(WNOHANG)` every 500 ms | `signalfd`/`SIGCHLD` stream, or drop it entirely ([Issue 9](#9-high--global-waitpid-1-reaper-races-every-childwaittry_wait)) |
| `daemon.rs:5646` stop-command wait | `try_wait()` every 50 ms | `pidfd` + the existing poll path |
| `daemon.rs:2009` cgroup drain | `list_pids` every 25 ms | `cgroup.events` `populated` field is `poll()`-able |
| `daemon.rs:3110` log follow | `read` + `sleep(500 ms)` per session | `inotify` on the log file — also fixes [Issue 14](#14-high--logs--f-sessions-pin-the-blocking-pool), since inotify is a *tokio task*, not a parked OS thread |
| `daemon.rs:1312` overtime scheduler | wake every 5 s, deep-clone `MasterConfig` + all defs | one timer armed at the next known deadline |

The cgroup-v2 `populated` notification is worth calling out: the project's central claim is deterministic stop, and the kernel offers an exact, edge-triggered signal for "this cgroup is now empty." Polling it every 25 ms is both slower and less precise than reading the primitive the design is built on.

The dominant cost today is not CPU, it is the *thread* budget — [Issue 14](#14-high--logs--f-sessions-pin-the-blocking-pool) shows 512 idle log-follow sessions can wedge the entire supervisor because each parks a blocking thread forever. Event-driven I/O removes the failure mode, not just the overhead.

## A9. Configuration: share it, segment it, and separate the file from the model

`MasterConfig` is one flat struct carrying cgroup settings, socket settings, directories, the entire web-console config (TLS PEM bodies and every bcrypt hash), and the admin-action map. Every subsystem receives all of it, so `cgroup.rs` can read password hashes and the TLS module can read the cron directory. It is then deep-cloned 39 times, twice inside per-tick loops.

Three changes:

1. **`Arc<Config>` everywhere.** Configuration is immutable after load; cloning it is pure waste.
2. **Segment by consumer** — `Arc<CgroupConfig>`, `Arc<SocketConfig>`, `Arc<WebConfig>`. A module should not be able to name what it does not need.
3. **Keep `…ConfigFile` (serde shape) separate from `Config` (validated domain shape)** — which is already the pattern in `config.rs`, but only for the *outer* type. Push it all the way down so `Config` contains `Mode`, `ServiceName`, and `RunAs` rather than `u32` and `String`. Then `deny_unknown_fields` plus typed fields means a bad config **cannot** load, and [Issue 42](#42-low--documented-globaluserglobalgroup-do-not-exist-and-would-break-startup) (documented keys that would crash startup) becomes a compile-time-visible mismatch between docs and struct.

## A10. Observability is an architectural feature, not `eprintln!`

Today: a bespoke `pm_event` writing to stderr plus a ring buffer, five bare `eprintln!` calls that bypass it entirely ([C10](#c10-dead-code-stray-files-and-unused-dependencies)), no request identity, no metrics, and `log`/`log4rs` declared but unused.

Adopt `tracing`: spans carry `service=`, `actor=`, `request_id=` automatically, so the audit record [Issue 31](#31-medium--no-authentication-or-authorization-audit-trail) asks for becomes a field rather than a new subsystem. Keep the ring buffer as a `tracing` layer feeding `pmctl events`, and add stderr/journald and file layers alongside. A supervisor's whole point is answering "what happened and when"; that deserves first-class support rather than a `format!` convention repeated in six places.

## A11. Test architecture — the coverage gap

Restating this as a first-class defect, since it is the one that makes every other item recur.

**Current coverage: 0%. Zero test functions, no `tests/` directory, no CI configuration in the repository, and clippy not installed.** For software that runs as root, sends `SIGKILL`, `chown -R`s directories, writes `/sys/fs/cgroup`, and rewrites operator YAML in place, this is the single largest risk in the audit — larger than any individual finding in Part 1, because it is why those findings survived to be found.

Consider what tests would have caught, at essentially zero cost:

- [Issue 8](#8-high--unquoted-octal-file-modes-are-parsed-as-decimal) (octal modes) — one table test over `parse_mode_str`. Four lines.
- [Issue 42](#42-low--documented-globaluserglobalgroup-do-not-exist-and-would-break-startup) (documented keys that break startup) — one test that loads every YAML under `examples/` and asserts success. That test also protects the README.
- [Issue 11](#11-high--stoprestart-rpc-always-returns-ok-true-so-a-failed-stop-exits-0) (`ok: true` on failed stop) — one assertion on the response.
- [Issue 28](#28-medium--write_file-destroys-the-errno-making-a-fail-safe-branch-dead-code) (dead `NotFound` branch) — one test asserting the `io::ErrorKind` survives the error conversion.
- The restart-tolerance policy — currently duplicated three times with no way to know the copies agree.

A proportionate target, in the order it should be built:

| Layer | Approach | Target | Prereq |
|---|---|---|---|
| Parsers & validators | table-driven unit tests, `#[cfg(test)]` in place | ~95% | none |
| Config loading | golden-file tests over `examples/` + malformed fixtures | ~90% | none |
| State machine / restart policy | pure `step()` tests with a fake clock | ~90% | [A3](#a3-the-supervisor-state-machine-should-be-data-not-control-flow) |
| `sys` wrappers | trait-level fakes; a few `#[ignore]`d root integration tests | ~60% | [A2](#a2-separate-the-pure-core-from-the-imperative-shell) |
| RPC / web handlers | `tower::ServiceExt::oneshot` against an in-memory router | ~70% | [A5](#a5-one-transport-too-many-one-dispatcher-too-few) |
| End-to-end | a container fixture: start daemon, run a service, stop it, assert the cgroup is empty | smoke only | — |

Three specific additions worth making beyond ordinary unit tests:

1. **Property tests** (`proptest`) for the parsers — `parse_size_spec_bytes`, `parse_duration_str`, `parse_flag_ttl_ms`, and `parse_mode_str` are exactly the shape that round-trip and monotonicity properties cover well, and property testing would have found the `"1.5"`-is-rejected edge and the nine unreachable match arms immediately.
2. **A security regression suite** — one test per Part 1 critical, asserting the *attack* fails: a symlinked `logs/stdout.log` is refused, a `..` service name is rejected at load, a POST without a CSRF token returns 403, the shipped default bcrypt hash refuses to start the console. These are the tests that must never be deleted.
3. **CI that fails the build**, not just runs: `cargo test`, `cargo clippy -- -D warnings` (the tree is already warning-clean, so this is free to adopt today), `cargo fmt --check`, and `cargo deny check advisories` to cover the three unmaintained dependencies noted above.

The dependency order matters and is encouraging: **the first two rows require no refactoring at all.** Roughly 150 lines of test code against existing pure functions would move coverage from 0% to meaningful, and would pin the behaviour that every later refactor risks changing.

## A12. Smaller architectural blemishes

- **`spawn_supervisor_thread` does not spawn a thread.** It calls `tasks().spawn` — a tokio task. Likewise `start_scheduler_thread`, `start_overtime_scheduler_thread`, `start_log_maintenance_thread`, `start_flag_maintenance_thread`, and `start_appstate_flush_thread` are all tasks; only `start_child_reaper_thread` is a real OS thread. Six names assert something false about the concurrency model, which is precisely the area where a reader most needs to trust the names. Rename to `spawn_*_task`.
- **Three concurrency idioms coexist without a stated rule**: tokio tasks, `spawn_blocking`, and raw OS threads (21 `spawn_blocking` sites in `daemon.rs`). Write the rule down — *async for I/O, `spawn_blocking` only for genuinely blocking syscalls with a bounded duration, OS threads never* — and [Issue 14](#14-high--logs--f-sessions-pin-the-blocking-pool) becomes a violation of a documented invariant instead of a surprise.
- **`templates/status.html` is ~1,900 lines of HTML with inline JavaScript**, including the hand-rolled `esc()` that causes [Issue 18](#18-medium--stored-xss-esc-does-not-escape-quotes-but-is-used-inside-attributes) and a second, *correct* escaper 1,000 lines away. Extract the JS to a served asset, keep exactly one escaping function, and the XSS class closes permanently.
- **`conf.d/` is simultaneously shipped example config and a live scratch directory** (`failure.sh`, `exit.sh`, `failure1.YmL`, a generated `appstate.json`). Split into `examples/` (documented, test-loaded) and a git-ignored runtime directory, so it is unambiguous which files an operator should copy.
- **`cgroup.rs` carries a module-wide `#![allow(dead_code)]`**, which is a standing instruction to the compiler to stop reporting exactly the signal this audit had to reconstruct by hand. Remove it and delete what it was hiding.

## What I would do first

If only three things happen, make them these — they are the ones that convert whole classes of future defect into compile errors:

1. **[A1](#a1-make-illegal-states-unrepresentable) — newtypes for `ServiceName`, `Mode`, `RunAs`, and anchored paths.** Small, mechanical, and it structurally closes Issues 5, 6(b), 8, and the seven-way symlink family.
2. **[A11](#a11-test-architecture--the-coverage-gap) rows 1–2 — parser and config-loading tests.** No refactoring required, ~150 lines, and it pins behaviour before anything else moves.
3. **[A3](#a3-the-supervisor-state-machine-should-be-data-not-control-flow) — extract the supervisor state machine as a pure `step()` function.** The largest single change proposed here, but it is what makes the 1,081-line function comprehensible, deletes the six duplicated start paths, and gives Issues 10 and 29 somewhere principled to be fixed.

Everything else in this part is worth doing and can be done incrementally afterwards.

---

## Appendix — verified as sound

These were specifically checked and found **not** to be problems. Recorded so future audits don't re-litigate them:

- **No shell injection anywhere.** `start_command`, `stop_command`, and `admin_actions.command` are all `Vec<String>` argv arrays executed via `Command::new(argv[0]).args(&argv[1..])` (`cgroup.rs:469-473`). No `sh -c`, no string concatenation, no `split_whitespace` on a command string. Admin-action names index an exact key in a config map (`daemon.rs:2658`) — a client selects a preconfigured action, it cannot supply one.
- **`chown_recursive`'s directory walk does not follow symlinks** (`daemon.rs:4995-4999`). The problems are the unchecked root target (Issue 4) and the TOCTOU (Issue 26), not `follow_links`.
- **The co-build version check is correctly placed** (`daemon.rs:2343-2364`): it runs before `match wire.request`, and no request variant bypasses it. Its only weakness is sitting *after* the unbounded read (Issue 15).
- **Post-kill verification exists and is bounded.** `stop_common` (`:5453-5459`) calls `wait_until_empty(..., 3000ms)`, re-checks, and bails if pids remain; `wait_until_empty` fails safe with `unwrap_or(true)`. The "definitive stop" guarantee is broken by its *callers* (Issues 10, 11), not by this routine.
- **CSRF tokens use a real CSPRNG** — `rand::rngs::OsRng.fill_bytes`, 32 bytes (`web_console.rs:328-332`). Cookies set `HttpOnly` and `SameSite=Strict`, with `Secure` correctly tied to TLS.
- **Path traversal via the log-viewing endpoints is not reachable**: `do_logs` resolves paths from the service definition, and the client only supplies a `HashMap` key.
- **`systemd_action`/`systemd_logs`** use `Command::arg` (no shell) and validate unit names against an allow-list (`web_console.rs:861-871`).
- **Tail/body limits are enforced**: `tail_lines` caps at 512 × 8 KiB regardless of `n` (`daemon.rs:3140`); `systemd_logs` clamps to `1..=5000`; axum's default 2 MB body limit applies.
- **No panicking index or cast from remote input.** `pids[0]` sites are guarded by `is_empty()`; `argv[0]` by an `ensure!`; `rpc.rs:409` `widths[i]` is safe by construction. `decode_hex`'s `to_digit(16).unwrap()` (`daemon.rs:4730`) is provably safe — the buffer only ever receives `is_ascii_hexdigit()` bytes.
- **All config value parsing returns `Result`** — sizes, durations, cron expressions, schedule boundaries. Malformed values fail one service's load, not the daemon. Float→int casts saturate rather than panic.
- **`TaskTracker` has no counter leak** — the RAII guard decrements on completion, panic, and cancellation. Its defect is the absence of a bound (Issues 14, 15), not accounting.
- **`list_pids`** skips symlinks, treats a missing cgroup as empty, caps the walk at 50,000 directories, and dedups.
- **No `std::env::set_var`/`set_current_dir`** anywhere — working directory is set per-`Command`, which is the sound approach in a multithreaded process.
- **The non-regen auto-service generation path uses `create_new(true)`** (`daemon.rs:7461`), which is `O_CREAT|O_EXCL` and therefore symlink-safe.
- **Log rotation** operates on symlinks rather than following them, and its numeric-suffix filter prevents pruning unrelated files.
- **Env indirection error paths never echo file contents** into logs or events.
- **The remaining `unsafe` blocks are sound**: `sysconf(_SC_CLK_TCK)` is a pure query; the `libc::read` on `AsyncFd<OwnedFd>` and `OwnedFd::from_raw_fd` after `into_raw_fd` (`daemon.rs:5179-5213`) transfer ownership exactly once.
