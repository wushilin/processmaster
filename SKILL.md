---
name: processmaster
description: Deploy and operate apps under processmaster (a cgroup-v2 process supervisor + cron runner for Linux) using its CLI client pmctl. Use when deploying a new service or cron job into processmaster, writing service YAML, starting/stopping/inspecting services, tailing logs, reloading service definitions, managing the unix socket, or deploying new processmaster/pmctl binaries.
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

Two config layers (strict parsing — unknown fields are rejected):
- **Master config** (`config.yaml`, passed via `processmaster -c`): cgroup limits, unix socket, `global.config_directory` / `global.auto_service_directory`, web console, `admin_actions`.
- **Service definitions**: one YAML per app, in `global.config_directory` (explicit) or per-app directories under `global.auto_service_directory` (implicit).

## Deploying an app into processmaster

There are two ways to define an app. Both end with `pmctl update` to load it — the daemon does not watch files.

### Way 1: auto-service (fastest — just a directory with run.sh)

Every direct child directory of `global.auto_service_directory` becomes a service named after the directory:

```bash
mkdir /opt/pm/services/myapp
cp myapp-launcher.sh /opt/pm/services/myapp/run.sh   # must be executable
chmod +x /opt/pm/services/myapp/run.sh
pmctl update            # daemon discovers it, generates service.yml with defaults
pmctl start myapp
```

Defaults: working_directory = that dir, start_command = `./run.sh`, run as root (or `global.default_service_user/group`), stop = SIGTERM, logs under `./logs/`. The generated `service.yml` in the app dir is yours to edit (edit → `pmctl update` → `pmctl restart myapp`). Notes:
- Rename a directory to `<name>.disabled` to have it ignored entirely.
- Same app name in both `config_directory` and `auto_service_directory` is a hard error.
- After a processmaster upgrade, drop an empty `.regen_pm_config` file in the app dir + `pmctl update` to regenerate a fresh `service.yml` (the old one is kept as `service.yml.bak`).

### Way 2: explicit service YAML in config_directory

Create `<config_directory>/myapp.yaml` (app name derives from the filename unless `application:` is set). Minimal:

```yaml
process:
  working_directory: /opt/myapp    # runs /opt/myapp/run.sh as root, SIGTERM to stop
```

Realistic long-running service:

```yaml
application: myapp
process:
  working_directory: /opt/myapp
  start_command: ["./bin/myapp", "--config", "app.conf"]   # argv list, NOT a shell string
  stop_signal: SIGTERM              # OR stop_command: ["./stop.sh"] — exactly one, not both
  stop_grace_period_ms: 5000        # then escalates to cgroup.kill
  user: appuser                     # optional; daemon (root) setuids the child
  group: appgroup
  environment:
    - name: DB_PASSWORD
      value: "@file:///etc/myapp/db_password"   # also @base64://..., @hex://..., or literal
logs:
  stdout: ./logs/stdout.log         # relative paths resolve under working_directory
  stderr: ./logs/stderr.log
  rotation_size: 10m                # default; rotation_backups: 10, gzip on
  hints: [./logs/app.log]           # app-written files, made visible in pmctl logs / web UI
resources:                          # optional cgroup limits for this app
  max_cpu: 500m                     # "500m" or "1.5" (cores)
  max_memory: 256MiB
  max_swap: 0                       # 0 = no swap for this app
restart_policy:
  policy: always                    # "always" | "never"
  restart_backoff_ms: 1000
  tolerance: { max_restarts: 3, duration: 1m }   # exceed → app marked FAILED, no more auto-restarts
```

Then deploy it:

```bash
pmctl update           # load/reload definitions (also runs pending provisioning)
pmctl start myapp
pmctl status myapp
pmctl logs myapp -n 50
```

Your app may fork/daemonize freely — processmaster tracks everything via the app's cgroup, so stop is still deterministic.

### Cron jobs

Set `process.schedule` to make the app a cron job instead of a daemon (`restart_policy` must then be absent — they're mutually exclusive):

```yaml
process:
  working_directory: /opt/nightly-report
  start_command: ["./run.sh"]
  schedule: "15 2 * * *"        # 5-field cron, 1-minute resolution; supports , - / and JAN/MON names
  max_time_per_run: "30m"       # overtime → normal stop, then cgroup.kill; "never" to disable
  # not_before: "2026-01-01"    # optional activation window (local time)
  # not_after: "2026-12-31"
```

Runs never overlap: if the previous run is still going at the next tick, that tick is skipped (no queueing).

### Provisioning (one-time setup at load)

`provisioning:` entries run once per working_directory during definition load, guarded by the marker file `${working_directory}/.pm_provisioned`. The marker is written only if ALL entries succeed; on failure the app is not loaded — fix and `pmctl update` to retry. Relative paths resolve under working_directory.

```yaml
provisioning:
  - path: .
    ownership: { owner: appuser, group: appgroup, recursive: true }
    mode: "0770"
  - path: ./bin/myserver
    mode: "0755"
    add_net_bind_capability: true   # setcap cap_net_bind_service=+ep → bind :80/:443 without root
```

To re-apply (e.g. after changing provisioning): delete `.pm_provisioned`, then `pmctl update`.

### Updating a deployed app's binary/files

1. `pmctl stop myapp` (deterministic — nothing survives)
2. Replace the app's files in its working_directory
3. `pmctl start myapp` — or `pmctl restart myapp` if you replaced files while running (most binaries tolerate this on Linux)
4. If you changed the service YAML too: `pmctl update` first, then restart.

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

## Building and deploying the processmaster/pmctl binaries themselves

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
