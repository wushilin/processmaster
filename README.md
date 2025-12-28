# processmaster

`processmaster` is a small supervisor-style process manager built around **cgroup v2**.

- **`processmaster`**: the daemon (supervisor + web console + JSON-RPC server over a unix socket)
- **`pmctl`**: the CLI client (talks JSON-RPC over the unix socket)

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

See `examples/` for working samples.

## Master config (`config.yaml`)

Master config is grouped and strict (`deny_unknown_fields`).
At minimum you must set `global.config_directory` and/or `global.auto_service_directory`.

Example:

```yaml
cgroup:
  root: /sys/fs/cgroup
  name: processmaster
  memory_max: MAX
  memory_swap_max: MAX
  cpu_max: MAX

unix_socket:
  path: /tmp/processmaster.sock
  owner: root      # requires daemon to run as root to chown
  group: root      # requires daemon to run as root to chgrp
  mode: 0660       # accepts 660, "660", or "0660"

global:
  config_directory: ./config.d
  # auto_service_directory: ./auto_services

  # If the daemon starts as root, it can drop privileges:
  # user: someuser
  # group: somegroup

web_console:
  enabled: true
  bind: 0.0.0.0
  port: 9001
  auth:
    basic:
      users:
        # htpasswd bcrypt entries. Default is admin/admin if you omit this section.
        - "admin:$2a$10$jqNWtAzhWEVlPnvJwyI6g.Nwb8YPU5ypCED9lBEhahUSs13ac1MPe"

# Operator-triggered commands (run as root; cwd="."; fire-and-forget).
admin_actions:
  update-pm:
    label: "Update ProcessMaster"
    command: ["/bin/sh", "-lc", "systemctl restart processmaster"]
```

### Cgroup behavior

The daemon:

- Creates a master cgroup at `${cgroup.root}/${cgroup.name}` and applies the master limits (`cpu.max`, `memory.max`, `memory.swap.max`)
- Creates one cgroup per app at `${cgroup.root}/${cgroup.name}/${app}`
- Stops/force-kills by signaling/`cgroup.kill`

### Unix socket permissions

If `unix_socket.owner` / `unix_socket.group` are set, the daemon needs to run as root to apply them.
`unix_socket.mode` is always applied.

## Service definition YAML (`config.d/<app>.yaml`)

Service definitions are grouped and strict (`deny_unknown_fields`).
`application:` is optional; if omitted it is derived from the filename (and `<app>/service.yml` derives from the parent dir name).

Example (long-running service):

```yaml
application: sleeper

process:
  working_directory: /tmp/processmaster/examples/sleeper
  start_command: ["/bin/sleep", "1000000"]
  # Choose exactly one:
  # stop_signal: SIGTERM         # default SIGTERM when stop_command is not set
  # stop_command: ["./stop.sh"]
  stop_grace_period_ms: 5000
  environment:
    - name: FOO
      value: bar

logs:
  stdout: ./logs/stdout.log
  stderr: ./logs/stderr.log
  rotation_mode: size           # default: size
  rotation_size: 10m            # default: 10m
  rotation_backups: 10          # default: 10
  compression_enabled: true     # default: true
  stop_command_stdout: ./logs/stop_command_stdout.log
  stop_command_stderr: ./logs/stop_command_stderr.log
  hints:
    - ./logs/app.log

resources:
  max_cpu: 100m
  max_memory: 64MiB
  max_swap: 0

restart_policy:
  policy: always                # "always" | "never"
  restart_backoff_ms: 1000      # default 1000
  tolerance:
    max_restarts: 3             # default 3
    duration: 1m                # supports ms/s/m/h

global:
  enabled: true
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

## Rule-driven flags (system/user flags)

Flags are applied via a rules engine defined in:

- `src/pm/flag_rules.default.json`

Key behavior:

- Setting a flag can **also set** other flags (`also_sets`) and **clear** other flags (`clears`)
- `clears: ["*"]` clears all existing flags **except** those newly introduced in the current apply-chain

Operators can set/clear user flags via:

```bash
pmctl flag <app> <flag1,flag2> [--ttl 1h]
pmctl unflag <app> <flag1,flag2>
```

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

On `SIGTERM`/`SIGINT`, the daemon leaves services running and exits; on next startup it can reconcile via cgroup state.