---
name: processmaster
description: Operate the processmaster daemon (a cgroup-v2 process supervisor + cron runner for Linux) and its CLI client pmctl. Use when starting/stopping/inspecting services, tailing logs, reloading service definitions, managing the unix socket, or deploying new processmaster/pmctl binaries.
---

# processmaster / pmctl operations

## What processmaster is

`processmaster` is a small, Rust-based, Linux-only supervisor and cron master built on **cgroup v2**. It must run as **root** (it bails out on startup otherwise — see `run_daemon_async` in `src/pm/daemon.rs`). Because every service runs inside its own cgroup, stops are deterministic: when a service is "stopped", nothing from it is still running (escalates to `cgroup.kill`).

Three ways to interact with it:

1. **`processmaster`** — the daemon: supervisor + JSON-RPC server over a unix socket + optional web console.
2. **`pmctl`** — the CLI client. Talks newline-delimited JSON-RPC over the unix socket.
3. **Web console** — `http(s)://<bind>:9001` if `web_console.enabled: true` (basic auth; default `admin/admin` if the auth section is omitted — change it).

Start the daemon:

```bash
sudo processmaster -c /etc/processmaster/config.yaml   # default config path: ./config.yaml
```

Key concepts:
- **Master config** (`config.yaml`): cgroup limits, unix socket, config directories, web console, `admin_actions`. Strict parsing (`deny_unknown_fields`).
- **Service definitions**: YAML files in `global.config_directory` (e.g. `conf.d/*.yaml`). Minimal service = just `process.working_directory`; defaults to running `./run.sh` as root, stop via SIGTERM.
- **Auto-services**: every direct child directory of `global.auto_service_directory` becomes a service (`run.sh` convention); processmaster generates a `service.yml` stub you can edit. Drop a `.regen_pm_config` marker file in the app dir to regenerate the stub (old one is saved as `service.yml.bak`).
- **Cron**: set `process.schedule` (5-field cron, 1-minute resolution). Cron jobs never overlap; `process.max_time_per_run` auto-kills overtime runs. Mutually exclusive with `restart_policy`.
- **Provisioning**: one-time workdir setup (chown/chmod/setcap) guarded by `${working_directory}/.pm_provisioned`; delete the marker + `pmctl update` to re-apply.

## pmctl: socket resolution (PMCTL_SOCK)

**`pmctl` does NOT read the processmaster config file.** It finds the daemon socket in this order (`resolve_sock` in `src/pm/pmctl_cli.rs`):

1. `--sock` / `-s` flag: `pmctl --sock /tmp/processmaster.sock status`
2. `PMCTL_SOCK` environment variable: `export PMCTL_SOCK=/tmp/processmaster.sock`
3. Neither set → hard error with usage help.

The value must match `unix_socket.path` in the daemon's master config. For interactive shells, export `PMCTL_SOCK` in the profile of whoever operates the box. Exceptions that need no socket: `pmctl version` and `pmctl password ...` (local-only).

```bash
export PMCTL_SOCK=/tmp/processmaster.sock
pmctl status            # no subcommand also defaults to status
```

## Unix socket permissions — who may use pmctl

There is no auth on the socket protocol; **filesystem permissions on the socket ARE the access control**. Configured in the master config:

```yaml
unix_socket:
  path: /tmp/processmaster.sock   # default if omitted
  owner: root                     # default root
  group: root                     # default root
  mode: 0600                      # DEFAULT IS 0600 (octal; accepts 660, "660", or "0660")
```

Behavior (see `apply_socket_settings` in `src/pm/daemon.rs`):
- The daemon binds the socket, then **always chmods** it to `mode` and **chowns** it to `owner:group` while still privileged (chown requires root; the daemon is root anyway).
- Default is `root:root 0600` → **only root can run pmctl**. To let a team operate without root, use e.g. `owner: root`, `group: ops`, `mode: 0660` — anyone in group `ops` can then connect.
- A stale socket file is removed on startup; if another daemon is actually listening on it, startup fails ("pm daemon already running").

## Binary co-build requirement (versioning)

The daemon **rejects any pmctl that was not built in the same build run**. At compile time, `build.rs` bakes two values into both binaries:

- `PROCESSMASTER_BUILD_TIME` — build timestamp (or `epoch:<SOURCE_DATE_EPOCH>` for reproducible builds)
- `PROCESSMASTER_BUILD_HOST` — `$HOSTNAME` / `hostname` of the build machine

On every RPC, pmctl sends its build info; the daemon compares both fields against its own and refuses on any mismatch with:

```
pmctl is not co-built with this daemon.
```

Implications:
- **Always deploy `processmaster` and `pmctl` as a pair from the same build.** Never mix a new pmctl with an old daemon or vice versa.
- Two separate `cargo build` runs (even same source, same machine) differ in build_time → not co-built.
- Diagnose with `pmctl version` (local build info, works offline) vs `pmctl server-version` (asks the daemon).

## Command reference

```bash
pmctl status [<app>] [--format text|json]   # state, pids, uptime, flags; json adds provisioning fields
pmctl events [-n 200] [<app>]               # daemon event history ("what happened")
pmctl logs <app> [-n 50]                    # recent stdout/stderr + hinted log files
pmctl logs -f [filename]                    # follow logs live (all apps, or filter by basename)
pmctl start|stop|restart <app> [--force]    # --force starts even if disabled (doesn't edit YAML)
pmctl enable|disable <app>                  # writes enabled: true/false into the service YAML
pmctl update                                # reload service definitions, reconcile, run pending provisioning
pmctl flag <app> <f1,f2> [--ttl 10m]        # set user flags; unflag to remove
pmctl perf-metrics <app> [--interval-ms N|--once]  # cgroup mem/swap/cpu/io + PSI + throttling
pmctl version | server-version              # local vs daemon build info (co-build check)
pmctl admin-list | admin-run <id> | admin-ps | admin-kill
pmctl password generate --user u --password p      # bcrypt htpasswd entry for web_console auth
pmctl password verify --secure "u:$2b$..." --user u --password   # no value after --password = read stdin
```

## Building and deploying a new binary

### Build

```bash
cargo build --release            # native: target/release/{processmaster,pmctl}
./build-musl-all.sh              # static musl builds via cross for x86_64 + aarch64
./package.bash v0.2              # tars target/release/{processmaster,pmctl} -> dist/processmaster-v0.2-<arch>.tar.gz
```

Both binaries come out of the same build → co-built. Set `SOURCE_DATE_EPOCH` if you need reproducible build stamps.

### Deploy procedure

1. Copy **both** `processmaster` and `pmctl` from the same build to the host (e.g. `/opt/processmaster/`). Keep them owned by `root:root`; the daemon runs as root, and root-owned binaries prevent a non-root user from swapping in a trojan that root then executes. `chmod 0755` is fine.
   ```bash
   tar -xzf processmaster-v0.2-x86_64.tar.gz -C /opt/processmaster/
   chown root:root /opt/processmaster/{processmaster,pmctl}
   chmod 0755 /opt/processmaster/{processmaster,pmctl}
   ```
2. Restart the daemon (running services are stopped gracefully on SIGTERM and restarted by the new daemon):
   ```bash
   sudo systemctl restart processmaster
   ```
3. Verify: `pmctl server-version` must succeed (proves co-build) and `pmctl status` shows services back up.

Run the daemon under systemd with `KillMode=process` so systemd doesn't kill the service processes that processmaster manages (see README for the full unit file).

### Remote/self-update via admin actions

`admin_actions` in the master config are operator-triggered root commands (fire-and-forget, cwd = daemon cwd, placed in the `<cgroup>/admin_actions` cgroup, output appended to `./logs/admin_action_std{out,err}.log`). Because the RPC returns before the command runs, **the daemon can restart itself** — this is the intended way to push a new binary without shelling into the box:

```yaml
admin_actions:
  update-pm:
    label: "Update ProcessMaster"
    command: ["/bin/sh", "-lc", "cd /opt/processmaster && ./fetch-latest.sh && systemctl restart processmaster"]
```

Trigger with `pmctl admin-run update-pm` or the web UI "Admin actions" modal. `admin-ps` shows running action PIDs; `admin-kill` cgroup-kills them all. No actions are defined by default.

## Troubleshooting quick hits

- `no processmaster socket specified` → set `PMCTL_SOCK` or pass `--sock`.
- `failed to connect to pm daemon socket ... Permission denied` → your user can't access the socket; fix `unix_socket.owner/group/mode` or use sudo.
- `pmctl is not co-built with this daemon` → deploy matching pair; check `pmctl version` vs `pmctl server-version` output in the error.
- Daemon won't start: must be root; must be cgroup v2; a live socket at the path means another daemon is running.
- Service marked FAILED and not restarting → restart tolerance exceeded (`restart_policy.tolerance`); `pmctl start <app>` to retry manually.
- Provisioning failed → app not loaded; fix the error, then `pmctl update` (delete `.pm_provisioned` first to force re-apply).
