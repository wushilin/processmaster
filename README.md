# processmaster

`processmaster` is a small supervisor-style process manager.

- **`processmaster`**: daemon
- **`pmctl`**: CLI client

## Quick start (local)

- **Start the daemon** (defaults to `config.yaml`):

```bash
processmaster -c examples/config.yaml
```

On daemon startup, `processmaster` will **auto-start all enabled services** from `config_directory`.

- **In another shell**, manage services:

```bash
pmctl -c examples/config.yaml update
pmctl -c examples/config.yaml status
pmctl -c examples/config.yaml start all
pmctl -c examples/config.yaml status
pmctl -c examples/config.yaml stop all
```

## Config layout

- **Master config**: `pm -c config.yaml` (default `config.yaml`)
- **Service definitions**: YAML files in `config_directory` (e.g. `config.d/*.yaml`)

See `examples/` for working samples.

## Master cgroup limits

`processmaster` applies its own cgroup v2 limits on startup:

- `cgroup_cpu_max` → writes `${cgroup_root}/${cgroup_name}/cpu.max` and moves its PID into `cgroup.procs`
- `cgroup_memory_max` → writes `memory.max`
- `cgroup_memory_swap_max` → writes `memory.swap.max`

Then `processmaster` places app cgroups under that master cgroup.

## Unix socket permissions

In `config.yaml` you can set:

- `sock_owner`: username (requires root to apply)
- `sock_group`: group name (requires root to apply)
- `sock_mode`: octal mode like `660` / `0660`

`processmaster` applies these right after binding the socket.

## Cgroup integration (self-contained)

`processmaster` is self-contained and interacts with **cgroup v2** directly:

- Creates `${cgroup_root}/${cgroup_name}/${app}` per app
- Lists PIDs via `cgroup.procs`
- Stops via signals to all PIDs, and force-kill via `cgroup.kill`
- Detects “app exited” by waiting for the cgroup to become empty (pidfd-based wait loop; no polling every second)

## Stop behavior

If `stop_command` is set for a service, `pm` runs it first. Otherwise `pm` sends `stop_signal`
to all PIDs in the app cgroup. After that, `pm` waits up to `stop_grace_ms` (default 30000ms),
checking `cgroup.procs`; if PIDs remain after the grace window, `pm` uses `cgroup.kill`.

## Logging + rotation

App config is grouped. Logging config lives under `logs:`:

- `logs.stdout` (default `./stdout.log`)
- `logs.stderr` (default `./stderr.log`)
- `logs.rotation_mode`: `time` (default) or `size`
- Time-based rotation:
  - `logs.rotation_frequency`: `minutely` | `hourly` | `daily` | `weekly` | `monthly` | `none` (default `daily`)
  - `logs.rotation_max_age_ms`: delete rotated logs older than this based on file mtime (default 30 days)
- Size-based rotation:
  - `logs.rotation_size`: e.g. `1K` / `10M` / `2G` / `1T`
  - `logs.rotation_backups`: number of rotated files to keep (default 10)
  - Filenames: `stdout.log`, then `stdout.log.1`, `stdout.log.2`, ... (oldest beyond backups is deleted)

`processmaster` redirects the service stdout/stderr into these files.
Every 1 minute it:

- Rotates logs on the hourly/daily boundary using **copy+truncate** (so long-running processes keep writing to the same path)
- Deletes rotated logs based on **last modified time**

## Viewing logs

Apps may also specify:

- `logs.hints`: list of additional log files (absolute or relative to `process.working_directory`)
- `logs.stop_command_stdout`: redirect `process.stop_command` stdout (absolute or relative to `process.working_directory`)
- `logs.stop_command_stderr`: redirect `process.stop_command` stderr (absolute or relative to `process.working_directory`)

Use:

- `pmctl logs <app> -n 50`
- `pmctl logs -f` (follow all known log files)
- `pmctl logs <app> -f` (follow logs for one app only)
- `pmctl logs -f stdout.log` (follow only files named `stdout.log`)
- `pmctl logs <app> -f stdout.log` (follow only `<app>`'s files named `stdout.log`)
- `pmctl logs -f syslog` (follow only files named `syslog`, typically via `alt_log_file_hint`)

This prints the last N lines from `log_stdout`, `log_stderr`, and any existing files from `alt_log_file_hint`.

## Scheduling (cron)

If an app sets `process.schedule`, `processmaster` will start it when the cron expression matches **and it is not already running**.

- Supports **standard 5-field cron**: `min hour day-of-month month day-of-week` (seconds assumed `0`)
- Also accepts 6-field (seconds + 5 fields) if you want explicit seconds

Example:

- `schedule: "0 * * * *"` (top of every hour)

## Restart strategy

Apps can optionally specify:

```yaml
restart_policy:
  policy: always              # never | always
  restart_backoff_ms: 1000    # default 1000
  tolerance:
    max_restarts: 3           # default 3
    duration: 1m              # default 1m (supports ms/s/m/h)
```

Notes:
- processmaster waits for the app cgroup to become empty (real time; no PID polling loop).
- This does not provide the app’s real exit code; it only indicates “all PIDs are gone”.
- If an app exceeds the tolerance window, it will stop auto-restarting until you manually `pmctl start` it again (manual start resets the tolerance/suppression).

## Graceful shutdown behavior

On `SIGTERM`/`SIGINT`, `processmaster` will:

- Leave services running (no stop/kill); it exits and on next startup can reconcile via cgroup PIDs.


