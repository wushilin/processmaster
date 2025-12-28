# what is processmaster

`processmaster` is a small supervisor-style process manager built around **cgroup v2**, using Rust.
It runs on ubuntu 22, ubuntu 24, redhat 8 and any cgroup v2 supported platform.

Why it is better than supervisor? 

1. It uses about 2% of supervisor's memory
<img width="903" height="243" alt="image" src="https://github.com/user-attachments/assets/a8dba0f4-cac2-4e1e-9f1a-36b600862401" />

2. It is blazing fast. Rust runs as close speed of native app

3. It supports more features. Including but not limited to:

- It uses cgroup, you can set each service CPU, RAM, SWAP usage
- It allows you spawn your process in any way. You can spawn 20 background process, and main process exists, it can still track what processes under it
- The stop is deterministic. When you stop a service on the web UI, it is **DEFINITELY** not running!
- Supports cronjob  as well!
- Supports one time setup required as root. like allowing your CADDY to bind on port 443
- Modern, well maintained

# How you would interact with processmaster
- **`processmaster`**: the daemon (supervisor + web console + JSON-RPC server over a unix socket)
- **`pmctl`**: the CLI client (talks JSON-RPC over the unix socket)
- **`web consle: 9001`**: if you have enabled, you can use the web console

# Screenshot
## CLI Access
<img width="1547" height="472" alt="image" src="https://github.com/user-attachments/assets/22ef9c8d-773f-4175-9ec6-40c01603bd9a" />
## Web Access
<img width="1728" height="630" alt="image" src="https://github.com/user-attachments/assets/7ebc5c8e-a72a-429e-937b-735fdd80667a" />
## Online log viewing/tailing
<img width="1123" height="788" alt="image" src="https://github.com/user-attachments/assets/e6216d51-0d9e-4818-b9cd-2a2ef243f954" />
## Cron support
<img width="1728" height="314" alt="image" src="https://github.com/user-attachments/assets/62a39449-548d-485b-a7d8-6502ce230e3b" />



## Quick start (local)

Build:

```bash
cargo build
```

Start the daemon:

```bash
./target/debug/processmaster -c ./examples/config.yaml
```

In another shell, point `pmctl` at the daemon socket:

```bash
export PMCTL_SOCK=/tmp/processmaster-example.sock
./target/debug/pmctl status
```

## Versioning / co-built requirement

`processmaster` prints build metadata on boot (and the web UI shows it in the navbar).

`pmctl` has:

```bash
pmctl version         # local build info
pmctl server-version  # asks the daemon
```

Important: the daemon **rejects** `pmctl` clients that are **not co-built** (different build host/time).
If you see “pmctl is not co-built with this daemon”, rebuild and deploy `processmaster` + `pmctl` from the same build.

## Config layout

- **Master config** (daemon): `processmaster -c config.yaml` (default `config.yaml`)
- **Service definitions**: YAML files under `global.config_directory` (e.g. `config.d/*.yaml`)
- **Optional auto-services**: `global.auto_service_directory` (each direct child dir is treated as a service)

See `examples/` for working samples:

- `examples/config.yaml`: minimal master config
- `examples/config.full.yaml`: full master config with inline documentation
- `examples/config.d/sleeper.yaml`: minimal service definition
- `examples/service.full.yaml`: full service definition with inline documentation

## Master config (`config.yaml`)

Master config is grouped and strict (`deny_unknown_fields`).
At minimum you must set `global.config_directory` and/or `global.auto_service_directory`.

Important: **processmaster daemon must run as root** (required for cgroup management, socket ownership, provisioning capabilities, and admin actions).

Example:

```yaml
cgroup:
  root: /sys/fs/cgroup        # cgroup v2 root
  name: processmaster         # master cgroup name -> /sys/fs/cgroup/processmaster
  memory_max: MAX             # writes memory.max (use MAX for unlimited)
  memory_swap_max: MAX        # writes memory.swap.max
  cpu_max: MAX                # writes cpu.max (use MAX for unlimited)

unix_socket:
  path: /tmp/processmaster.sock   # pmctl/web UI connect to this socket
  owner: root                     # chown socket file (requires root)
  group: root                     # chgrp socket file (requires root)
  mode: 0660                      # octal; accepts 660, "660", or "0660"

global:
  config_directory: ./config.d    # directory of explicit service YAML files (*.yml/*.yaml)
  # auto_service_directory: ./auto_services  # optional implicit services (one per subdirectory)

web_console:
  enabled: true                   # serve web UI at http(s)://bind:port/
  bind: 0.0.0.0                   # listen address
  port: 9001                      # listen port
  auth:
    basic:
      users:
        # htpasswd bcrypt entries in the form "user:hash".
        # If you omit the whole web_console.auth section, it defaults to admin/admin (bootstrapping only).
        - "admin:$2a$10$jqNWtAzhWEVlPnvJwyI6g.Nwb8YPU5ypCED9lBEhahUSs13ac1MPe"

# Operator-triggered commands (run as root; cwd="."; fire-and-forget).
admin_actions:
  update-pm:
    label: "Update ProcessMaster"  # optional display label; defaults to the id ("update-pm")
    command: ["/bin/sh", "-lc", "systemctl restart processmaster"]  # argv list
```

### Cgroup behavior

The daemon:

- Creates a master cgroup at `${cgroup.root}/${cgroup.name}` and applies the master limits (`cpu.max`, `memory.max`, `memory.swap.max`)
- Creates one cgroup per app at `${cgroup.root}/${cgroup.name}/${app}`
- Stops/force-kills by signaling/`cgroup.kill`

### Unix socket permissions

If `unix_socket.owner` / `unix_socket.group` are set, the daemon needs to run as root to apply them.
`unix_socket.mode` is always applied.

## Running processmaster under systemd (recommended)

Example unit file: `/etc/systemd/system/processmaster.service`

```ini
[Unit]
Description=ProcessMaster daemon
After=network.target

[Service]
Type=simple
User=root
Group=root

# IMPORTANT: allow the daemon to manage cgroups (create sub-cgroups, write controllers).
Delegate=yes

# Adjust paths as needed.
WorkingDirectory=/opt/processmaster
ExecStart=/opt/processmaster/processmaster -c /etc/processmaster/config.yaml

Restart=always
RestartSec=2

# Let processmaster handle its own children (it uses its own cgroup tree).
KillMode=process

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now processmaster
sudo systemctl status processmaster
```

## Auto-services (implicit services)

If you set `global.auto_service_directory`, processmaster treats **each direct child directory** as a service.

- **App name**: the directory name (trimmed). Any directory ending with `.disabled` is ignored.
- **Config file**: inside each app directory it prefers:
  - `service.yml` (preferred), otherwise
  - `service.yaml`, otherwise
  - no config file → processmaster uses built-in defaults (working_directory = that dir, start_command = `./run.sh`, logs under `./logs/`, etc).
- **Collision rule**: if an app name exists in `config_directory` and `auto_service_directory`, that is a **hard error**.

### Regeneration flow (`.regen_pm_config`)

Auto-services support a one-shot regeneration mechanism for upgrading an existing app directory to the latest default template.

If an auto-service directory contains a file named `.regen_pm_config`:

- processmaster renames any existing `service.yml` / `service.yaml` into `service.yml.bak` (or `service.yml.bak.N`)
- then writes a freshly generated `service.yml` using canonical defaults
- then removes `.regen_pm_config` **only if** generation + write succeeded

This is intentionally explicit: you opt-in by creating the marker, and you can diff/inspect the `.bak` files.

## Service definition YAML (`config.d/<app>.yaml`)

Service definitions are grouped and strict (`deny_unknown_fields`).
`application:` is optional; if omitted it is derived from the filename (and `<app>/service.yml` derives from the parent dir name).

Example (long-running service):

```yaml
application: sleeper            # optional; if omitted, derived from the filename

process:
  working_directory: /tmp/processmaster/examples/sleeper   # required (unless auto-service and omitted there)
  start_command: ["/bin/sleep", "1000000"]                 # required; argv list

  # Stop behavior: choose exactly one of process.stop_signal or process.stop_command.
  # - If stop_command is set, processmaster runs it first (no automatic signal).
  # - Otherwise it signals the cgroup PIDs with stop_signal (default SIGTERM).
  stop_signal: SIGTERM                                     # optional (default SIGTERM if stop_command is not set)
  # stop_command: ["./stop.sh"]                            # optional; argv list

  # How long to wait (ms) after stop_command/stop_signal before forcing `cgroup.kill`.
  # Default: 5000.
  stop_grace_period_ms: 5000

  # Environment variables passed to the service.
  # Values can be literal strings or indirections like @file://..., @base64://..., @hex://...
  environment:
    - name: FOO                                            # must not contain '='
      value: bar

logs:
  # Where processmaster writes captured stdout/stderr.
  # Absolute paths are allowed; relative paths are resolved under process.working_directory.
  stdout: ./logs/stdout.log
  stderr: ./logs/stderr.log

  # Log rotation:
  # - rotation_mode=size: rotate when file exceeds rotation_size (default mode)
  # - rotation_mode=time: rotate on schedule boundary (daily/hourly/...)
  rotation_mode: size           # default: size
  rotation_size: 10m            # size-mode only; default: 10m
  rotation_backups: 10          # size-mode only; default: 10
  compression_enabled: true     # best-effort gzip for rotated logs; default: true

  # If you use process.stop_command, you can optionally capture that command's stdout/stderr too.
  stop_command_stdout: ./logs/stop_command_stdout.log      # default: ./logs/stop_command_stdout.log
  stop_command_stderr: ./logs/stop_command_stderr.log      # default: ./logs/stop_command_stderr.log

  # Extra log files that the application writes by itself (for viewing/tailing only).
  # These are *not* written by processmaster; they just show up in pmctl/web log UI.
  hints:
    - ./logs/app.log

resources:
  # Optional cgroup limits for this service.
  max_cpu: 100m                 # e.g. "100m" or "1.5"
  max_memory: 64MiB             # e.g. "64MiB", "1GiB"
  max_swap: 0                   # "0" disables swap for this cgroup

restart_policy:
  # Restart strategy for non-scheduled services. (Must not be present when process.schedule is set.)
  policy: always                # "always" | "never"
  restart_backoff_ms: 1000      # delay before restarting; default 1000
  tolerance:
    max_restarts: 3             # default 3
    duration: 1m                # restart budget window; supports ms/s/m/h

global:
  enabled: true                 # if false: daemon won’t auto-start (but you can still pmctl start --force)
```

### Cron / scheduling

If `process.schedule` is set, the app becomes a cron job:

- Standard **5-field cron** (`min hour day-of-month month day-of-week`, seconds assumed `0`)
- Also accepts 6-field cron if you want explicit seconds
- Scheduled apps **must not** define `restart_policy` (mutually exclusive)

Optional scheduling bounds:

- `process.not_before`: `"YYYY-MM-DD"` or `"YYYY-MM-DD HH:MM:SS"` (local time)
- `process.not_after`: `"YYYY-MM-DD"` or `"YYYY-MM-DD HH:MM:SS"` (local time, end-of-day inclusive for date-only)
- `process.max_time_per_run`: `"30s"` / `"10m"` / `"never"` (if exceeded, daemon attempts an overtime stop)

### Running a service as a user

In the service YAML, set:

- `process.user`
- `process.group`

Note: actually applying the uid/gid requires the daemon to have the necessary privileges (typically run the daemon as root).

### Environment indirections

Environment values support indirections for secrets/config blobs:

- `@file://...`
- `@base64://...`
- `@hex://...`

## Provisioning (one-time workdir setup)

If you define `provisioning:`, it is applied **during definition load** (startup or “reload defs”).
Provisioning is guarded by a marker file: `${working_directory}/.pm_provisioned`.

- If the marker exists, provisioning is skipped.
- The marker is written **only after all provisioning entries succeed**.
- If provisioning fails, the app is **not loaded**; fix the error and reload definitions to retry.
- Relative `provisioning[].path` is resolved **under `process.working_directory`**.

### Re-provision (reapply) flow

To re-apply provisioning for a service:

- delete `${working_directory}/.pm_provisioned`
- then reload definitions (web UI: “Reload Service Definition”, or `pmctl update`)

On the next definition load, provisioning runs again and a new marker is written only on full success.

Example:

```yaml
provisioning:
  - path: .
    ownership:
      owner: someuser
      group: somegroup
      recursive: true
    mode: "0770"

  - path: ./bin/myserver
    mode: "0755"
    add_net_bind_capability: true   # runs: setcap cap_net_bind_service=+ep ./bin/myserver
```

Root requirements:

- `ownership` (chown/chgrp) and `add_net_bind_capability` require the daemon to run as root (or equivalent capabilities).

## Admin actions

Admin actions are configured in the master config under `admin_actions`.

- Launched as **fire-and-forget** processes (RPC returns immediately)
- Placed into the cgroup `${cgroup.name}/admin_actions`
- Stdio is appended to `./logs/admin_action_stdout.log` and `./logs/admin_action_stderr.log` (relative to daemon cwd)
- Daemon must run as root to run admin actions

CLI:

```bash
pmctl admin-list
pmctl admin-ps
pmctl admin-run <id>
pmctl admin-kill
```

Web UI:

- “Admin actions” button opens a modal listing configured actions + running PIDs, with “Kill all” and “Run”.

## Observability

Useful commands:

```bash
pmctl status [<app>] [--format text|json]
pmctl events [-n 200] [<app>] [--format text|json]
pmctl logs <app> -n 50
pmctl logs -f [filename]
```

`pmctl status --format json` includes provisioning visibility fields:

- `working_directory`
- `provisioning_defined`
- `provisioning_marker`
- `provisioning_marker_exists`

## Graceful daemon shutdown

On `SIGTERM`/`SIGINT`, the daemon performs a **best-effort shutdown**:

- Attempts to stop all services via the normal supervisor stop path.
- Then does a final sweep to **force-kill** any remaining processes in app cgroups (`cgroup.kill`), and waits briefly for cgroups to become empty.
- Finally closes the unix socket and exits.
