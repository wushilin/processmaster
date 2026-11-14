# what is processmaster
Definitive, Determinstic, Modern, Linux only daemon and cronjob master written in Rust. It has to run as root.

`processmaster` is a small supervisor-style process manager built around **cgroup v2**, using Rust.
It runs on ubuntu 22, ubuntu 24, redhat 8 and any cgroup v2 supported platform.

# Why it is better than supervisor? 

1. It uses about 2% of supervisor's memory. the screenshot shows it uses less than 1M memory.
<img width="903" height="243" alt="image" src="https://github.com/user-attachments/assets/a8dba0f4-cac2-4e1e-9f1a-36b600862401" />

2. It is blazing fast. Rust runs as close speed of native app

3. It supports more features. Including but not limited to:

- It uses cgroup, you can set each service CPU, RAM, SWAP usage
- It allows you spawn your process in any way. You can spawn 20 background process, and main process exists, it can still track what processes under it
- The stop is deterministic. When you stop a service on the web UI, it is **DEFINITELY** not running!
- Supports cronjob  as well!
- Supports one time setup required as root. like allowing your CADDY to bind on port 443
- Auto restart failed daemons. Subject to a tolerance (Max of X failure in Y minutes, if exceeded, service marked as failed and won't restart again but you can set X to a huge number to keep restarting, if you like)
- Supports background task. Foreground background, forking, do whatever you want! thanks to cgroup API, we know how to stop it, we know what is running under your service!
- Runs container images too (podman), with the same cgroup limits, deterministic stop, logging, restart and cron as any other service
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

## Process resource utilization view
<img width="783" height="539" alt="image" src="https://github.com/user-attachments/assets/4202e751-9842-4591-b64a-1566d0a586e7" />

<img width="786" height="279" alt="image" src="https://github.com/user-attachments/assets/8b81227e-a2ef-4057-9644-e0b49b33cdd0" />


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
  root: /sys/fs/cgroup        # cgroup v2 root, the value is default. you can ommit it.
  name: processmaster         # master cgroup name -> /sys/fs/cgroup/processmaster. optional
  memory_max: MAX             # writes memory.max (use MAX for unlimited). the limit applies not only to process master, but also to all services combined
  memory_swap_max: MAX        # writes memory.swap.max. the limit applies not only to process master, but also to all services combined
  cpu_max: MAX                # writes cpu.max (use MAX for unlimited) the limit applies not only to process master, but also to all services combined
  subtree_control_allow: true # default true. if enabled, it will auto enable all controllers listed in cgroup.controllers into cgroup.subtree_control for children cgroups.

unix_socket:
  path: /run/processmaster.sock   # pmctl/web UI connect to this socket
  owner: root                     # chown socket file (requires root)
  group: root                     # chgrp socket file (requires root)
  mode: 0660                      # octal; accepts 660, "660", or "0660"

global:
  config_directory: ./config.d    # directory of explicit service YAML files (*.yml/*.yaml). all service yamls in this folder will be loaded.
  # auto_service_directory: ./auto_services  # optional implicit services. all folders in this directory will be auto recognized as a service using defaults, but customizable later.
  default_service_user: root # auto generated service will run as this user
  default_service_group: root # auto generated service will run as this group

web_console:
  enabled: true                   # serve web UI at http(s)://bind:port/. Default is not enabled
  bind: 0.0.0.0                   # listen address
  port: 9001                      # listen port
  auth:
    basic:
      users:
        # htpasswd bcrypt entries in the form "user:hash".
        # If you omit the whole web_console.auth section, it defaults to admin/admin (bootstrapping only). Please change it
        - "admin:$2a$10$jqNWtAzhWEVlPnvJwyI6g.Nwb8YPU5ypCED9lBEhahUSs13ac1MPe"

# Generating/Verifying bcrypt htpasswd entries (`pmctl password`)
`pmctl` includes local helpers for generating and verifying the `user:<bcrypt>` strings used by `web_console.auth.basic.users`.

Generate:

```bash
pmctl password generate --user hello --password xyz
# -> prints: hello:$2b$...
```

Verify (exit 0 on success, 1 on failure):

```bash
SECURE="$(pmctl password generate --user hello --password xyz)"
echo xyz | pmctl password verify --secure "$SECURE" --user hello --password
# -> prints: OK
```

Tip: if you pass `--password` with no value, pmctl reads the password from stdin (one line).

Use the same bcrypt cost for every user (10 or more; 12 is a good default). Unknown usernames are
timed against a dummy hash at the most common configured cost, so mixed costs let an attacker tell
which usernames exist; the daemon logs a startup warning for mixed or low (< 10) costs. Costs above
16 are refused (the console does not start), since each login would take minutes or more.

Login hardening: after 10 failed logins from one source address (IPv6: per /64) with no 5-minute
pause, that source gets `429` + `Retry-After` for 30s, and no password check is run for it.
Requests during a lockout are refused without extending it, so an open console tab does not keep its
own address locked. A failure after a lockout ends locks again for twice as long, up to 15 minutes.
Successful logins do not clear the record (a logged-in admin behind the same NAT or proxy would
otherwise keep resetting an attacker's count); it is forgotten after 5 minutes without failures. Concurrent
bcrypt checks are capped at 2x the CPU count; beyond that the console answers `503` + `Retry-After: 1`.
The source is the TCP peer, so behind a reverse proxy all clients share the proxy's record.

# Operator-triggered commands (run as root; cwd="."; fire-and-forget). You can use this mechanism update processmaster binary even!
# if you did not define any, then there is extra "admin action" admin can trigger remotely on the web UI. By default no action possible.
admin_actions:
  update-pm:
    label: "Update ProcessMaster"  # optional display label; defaults to the id ("update-pm")
    command: ["/bin/sh", "-lc", "systemctl restart processmaster"]  # argv list
```

### Cgroup behavior

The daemon:

- Creates a master cgroup at `${cgroup.root}/${cgroup.name}` and applies the master limits (`cpu.max`, `memory.max`, `memory.swap.max`)
- Creates one cgroup per app at `${cgroup.root}/${cgroup.name}/${app}`, and apply per-service limit, if they were defined.
- Stops will force-kills by signaling/`cgroup.kill` if the default stop mechanism did not work (e.g. stop_command, signal).

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

# Adjust paths as needed.
WorkingDirectory=/opt/processmaster
ExecStart=/opt/processmaster/processmaster -c /etc/processmaster/config.yaml

Restart=always
RestartSec=2

# processmaster manages its own cgroup tree, so systemd must signal the daemon itself
# rather than trying to kill a cgroup the daemon has already left (see below).
KillMode=process

# Give the daemon time to stop every supervised service before systemd escalates.
TimeoutStopSec=90

[Install]
WantedBy=multi-user.target
```

### Important: the main PID must be the daemon

At startup processmaster moves itself into `${cgroup.root}/${cgroup.name}`, leaving the
systemd unit's own cgroup. One consequence catches people out:

**If `ExecStart` points at a wrapper script that runs processmaster as a child, then
`systemctl stop` will not stop processmaster.** systemd kills what is in the unit's
cgroup (or, with `KillMode=process`, only the main PID) — and by then the daemon is in
neither. The unit goes `inactive`, the daemon keeps running with the old binary, and the
next `systemctl start` fails because the orphan still holds the control socket.

So either point `ExecStart` straight at the binary, as above, or `exec` from the wrapper:

```sh
#!/bin/sh
exec processmaster -c config.yaml   # NOT: processmaster -c config.yaml
```

When upgrading, verify the daemon actually exited before replacing the binary:

```bash
sudo systemctl stop processmaster
# Confirm nothing survived; if it did, signal it directly so it can shut its
# services down cleanly, and wait for it to go.
pgrep -x processmaster && sudo pkill -TERM -x processmaster
while pgrep -x processmaster >/dev/null; do sleep 1; done

sudo install -o root -g root -m 0755 processmaster pmctl /usr/local/sbin/
sudo systemctl start processmaster
pmctl server-version   # proves the daemon is the newly deployed build
```

A direct `SIGTERM` to the daemon is safe: it stops all supervised services, force-kills
anything left in their cgroups, and releases the socket before exiting.

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now processmaster
sudo systemctl status processmaster
```

## Auto-services (implicit services)

If you set `global.auto_service_directory`, processmaster treats **each direct child directory** as a service.

Again, it is super duper simple. all you really need to do is:

```bash
mkdir /path_to_process_master/auto_services/test2
cp /other/path/run.sh /path_to_process_master/auto_services/test2/run.sh
chmod +x /path_to_process_master/auto_services/test2/run.sh
```

then run `pmctl update` (or restart the daemon). The service defaults to run as root, use SIGTERM to stop, and start using run.sh.

Isn't that simple? Of course, you will want to customize it; see below.

The daemon generates a `service.yml` with these defaults. If your app conforms to them, it works out of the box. If it doesn't, it will fail to start; edit the generated `service.yml`, and you've still saved writing it by hand.

Folders are scanned only at daemon start and on `pmctl update`. Nothing watches the directory, so creating a folder does nothing until then.

- **App name**: the directory name (trimmed). Any directory ending with `.disabled` is ignored.
- **Config file**: inside each app directory it prefers:
  - `service.yml` (preferred), otherwise
  - `service.yaml`, otherwise
  - no config file, but a `run.sh` → processmaster uses built-in defaults (working_directory = that dir, start_command = `./run.sh`, logs under `./logs/`, etc.) and writes them to a generated `service.yml`;
  - neither a config file nor a `run.sh` → the folder is **skipped** (warning `auto_service_skipped ... reason=no_service_yml_or_run_sh`), and nothing is generated. Add a `run.sh` or write a `service.yml`, then run `pmctl update`. This lets you prepare a folder (e.g. a hand-written container `service.yml`) without a default being generated behind your back.
- **Generation never overwrites**: a `service.yml` you wrote is loaded as is, with `process:` or `container:`. Only an explicit `.regen_pm_config` marker replaces it, after backing it up as `service.yml.bak`. In a folder without `run.sh`, the marker is ignored (warning `auto_service_regen_marker_ignored ... reason=no_run_sh`), so it never replaces a container definition with the `run.sh` default.
- **Container services** are never generated (there is nothing to derive an image from). Prefer defining them in `config_directory`; a hand-written `service.yml` with `container:` in an auto folder also works. See [Container services](#container-services-podman).
- **Collision rule**: if an app name exists in `config_directory` and `auto_service_directory`, that is a **hard error**.
- **`%app_dir%`**: inside an auto-service `service.yml`, `%app_dir%` expands to that service's directory (`<auto_service_directory>/<app>`), so paths need not be hard-coded. It is expanded first, in `working_directory`, `start_command`, `stop_command`, `environment` values (including `@file://%app_dir%/...`), `logs.*` paths and `provisioning[].path`. The generated `service.yml` uses `working_directory: '%app_dir%'`.
  - `working_directory` may be omitted (defaults to `%app_dir%`) or relative (resolved under `%app_dir%`); it must not contain `..`.
  - YAML cannot start an unquoted value with `%`, so quote it: `start_command: ["%app_dir%/bin/run"]`, `working_directory: "%app_dir%/data"`.
  - `%app_dir%` is **not** available in `config_directory` definitions: there `working_directory` must be absolute (or omitted, for `<auto_service_directory>/<application>`), and using the token is a load error.

### Regeneration flow (`.regen_pm_config`)
Sometimes, after version upgrade, your older version became incompatible. you are too lazy to generate the new config, you can use
this method to generate a stub for you to edit.

Auto-services support a one-shot regeneration mechanism for upgrading an existing app directory to the latest default template.

If an auto-service directory contains a file named `.regen_pm_config`:

- processmaster renames any existing `service.yml` / `service.yaml` into `service.yml.bak` (or `service.yml.bak.N`)
- then writes a freshly generated `service.yml` using canonical defaults
- then removes `.regen_pm_config` **only if** generation + write succeeded

This is intentionally explicit: you opt-in by creating the marker, and you can diff/inspect the `.bak` files.

## Service definition YAML (`config.d/<app>.yaml`)

All services parameter has reasonable defaults.
A super minimum service could be:

test.yaml
```
process:
  working_directory: /tmp/test
```
-> it will run /tmp/test/run.sh as root, in working directory /tmp/test. That's it. Stop signal is SIGTERM.

Isn't that simple? Of course you can customize it more. See below!

Service definitions are grouped and strict (`deny_unknown_fields`).
`application:` is optional; if omitted it is derived from the filename (and `<app>/service.yml` derives from the parent dir name).

Example (long-running service):

```yaml
application: sleeper            # optional; if omitted, derived from the filename

process:
  working_directory: /tmp/processmaster/examples/sleeper   # absolute; if omitted: <auto_service_directory>/<application>
  start_command: ["/bin/sleep", "1000000"]                 # required; argv list

  # Stop behavior: choose exactly one of process.stop_signal or process.stop_command.
  # - If stop_command is set, processmaster runs it first (no automatic signal).
  # - Otherwise it signals the cgroup PIDs with stop_signal (default SIGTERM).
  stop_signal: SIGTERM                                     # optional (default SIGTERM if stop_command is not set)
  # stop_command: ["./stop.sh"]                            # optional; argv list

  # How long to wait (ms) after stop_command/stop_signal before forcing `cgroup.kill`.
  # Default: 5000.
  stop_grace_period_ms: 5000

  # Environment variables passed to the service (names must not contain '=').
  # Values can be literal strings or indirections like @file://..., @base64://..., @hex://...
  # Map form; integers and booleans are taken as text, decimals must be quoted ("1.10").
  environment:
    FOO: bar
    PORT: 8080
  # The list form is also accepted:
  # environment:
  #   - name: FOO
  #     value: bar

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
  max_pids: 512                 # cap on processes+threads (pids.max); omit for unlimited.
                                # Threads count too: size it from the cgroup's pids.peak.

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

- **Supported format**: standard **5-field cron** (`min hour day-of-month month day-of-week`)
- **Minimum resolution**: **1 minute** (scheduler only evaluates schedules on minute boundaries)
- **Not supported**: a seconds field (6-field cron) or a year field (7-field cron)
- **Supported operators (per field)**: `*` (all), `,` (list), `-` (range), `/` (step, e.g. `*/15`)
- **Supported names**: month and weekday names (e.g. `JAN`, `January`, `MON`, `Monday`; case-insensitive)
- Scheduled apps **must not** define `restart_policy` (mutually exclusive)

#### Non-overlapping behavior (no concurrent runs)

Cron jobs are **non-overlapping** by design:

- When the cron expression matches, processmaster starts the job **only if it is not already running**.
- If the previous run is still running, the new scheduled tick is skipped (no queueing).

This prevents “pile-ups” for slow/blocked jobs.

#### Overtime auto-kill (`process.max_time_per_run`)

You can set a maximum runtime per scheduled run:

- `process.max_time_per_run: "30s"` / `"10m"`: if the job runs longer than this, the daemon triggers an overtime stop:
  - first tries the normal stop mechanism (`stop_command` or `stop_signal`)
  - then escalates to a force kill (`cgroup.kill`) if it doesn’t exit within the grace window
- `process.max_time_per_run: "never"` (or unset): no overtime enforcement

Optional scheduling bounds:

- `process.not_before`: `"YYYY-MM-DD"` or `"YYYY-MM-DD HH:MM:SS"` (local time)
- `process.not_after`: `"YYYY-MM-DD"` or `"YYYY-MM-DD HH:MM:SS"` (local time, end-of-day inclusive for date-only)
- `process.max_time_per_run`: `"30s"` / `"10m"` / `"never"` (maximum runtime per run; see overtime section above)

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

## Container services (podman)

A service can run an OCI image (anything from Docker Hub or another registry) instead
of a host command. Each service file has either `process:` (a host command) or
`container:` (an image), never both. Container services get the same supervision as
host commands. The container runs in the service's own cgroup, so its limits, stop,
logging, restart policy and cron all behave the same.

```yaml
# conf.d/web.yaml
application: web
container:
  image: docker.io/library/nginx:1.27-alpine
  ports: ["127.0.0.1:8080:80"]
  volumes: ["./html:/usr/share/nginx/html:ro,Z"]
  env: { TZ: Asia/Singapore }
  working_directory: /srv/web       # host side: ./html and the logs resolve here
  stop_grace_period_ms: 10000
resources:
  max_memory: 256MiB
restart_policy:
  policy: always
```

The full commented example is `examples/service.container.yaml`.

**Requirements:** rootful podman (tested with 5.8) and cgroup v2. **Docker is not
supported:** `docker run` only asks dockerd to start the container, and dockerd puts
it in its own cgroup (`system.slice/docker-<id>.scope`), outside processmaster's
control. None of the guarantees below could hold.

### Where to define them

Put container services in `config_directory` (e.g. `conf.d/web.yaml`). Auto services
never generate a container definition, because there is nothing to derive the image,
ports or mounts from. If you prefer the folder layout, you can write a `service.yml`
with `container:` into an auto-service folder by hand. It is loaded and reloaded by
`pmctl update` like any other definition, with `working_directory` defaulting to that
folder. See [Auto-services](#auto-services-implicit-services).

### Guarantees

**Cgroup: everything stays inside the service's cgroup.** processmaster runs
`podman run --cgroups=split` attached, as the service's process, in the service's own
cgroup (`<cgroup.root>/<cgroup.name>/pm-<app>/run`). Podman's CLI and its conmon monitor
go in `run/runtime`, the container in `run/libpod-payload-<id>`. So:
- `resources.*` limits (memory, cpu, pids, io) apply to the container together with
  podman's own processes;
- the process view and `pmctl perf-metrics` show the container's processes;
- liveness is the cgroup's `populated` state, exactly as for a host command.

The one podman process outside the service's cgroup is shared network infrastructure.
With a named `network:`, podman's DNS helper `aardvark-dns` serves every container on
that network from its own systemd scope, and exits when the last one leaves. It is not
part of any service and does not delay a stop.

`memory.oom.group` is set (where the memory controller is enabled), so an OOM kill takes
down the whole service, never podman's monitor alone, which would leave a container
running without its output pipes.
Helper commands (`podman pull`, `stop`, `rm`) run in a separate cgroup
(`<cgroup.name>/container_ctl/`), so a pull never makes the service look running.

**Stop: stopped means definitely stopped.**
1. `podman stop` sends `container.stop_signal` (default SIGTERM) to the container's
   init only. Podman sends SIGKILL itself after `stop_grace_period_ms`. Right after a
   start, `podman run` may still be creating the container; processmaster keeps
   retrying within the grace period, so even a very young container gets its graceful
   stop.
2. If anything is still in the cgroup after that, processmaster kills the whole
   cgroup (`cgroup.kill`), the same final step as for host commands.
3. `podman rm` always runs last. It removes the container record and what podman set
   up around it: mounts, network namespace, port-forwarding firewall rules, and
   anonymous volumes. Every start also begins with `podman rm`, so a crash or an OOM
   kill never leaves a stale container that blocks the next start.

When `pmctl stop` returns, no process of the service exists, and its podman record has
been removed. A failed removal is logged and retried at the next start. `pmctl stop` on
a container that already died on its own also clears what it left behind. The same
holds when a service changes between `process:` and `container:` (the running instance
is stopped the way it was started), and when its definition is deleted. If processmaster
itself is killed or crashes, the records left behind are cleared at its next start.

**Logging: the container's stdout and stderr go to the service's log files.** The
container runs attached with podman's own logging off (`--log-driver=none`). Its output
goes through processmaster's log pumps into `logs.stdout` / `logs.stderr`, with the usual
rotation and compression, and appears in `pmctl logs`, `pmctl logs -f` and the web UI.
`podman logs` and journald get nothing. Image pull and load progress is written to the
stderr log.

**Restart and cron work unchanged.** `restart_policy` (backoff, tolerance, FAILED) applies
to container exits and failed starts. With `container.schedule`, the container is a cron
job: runs never overlap, `max_time_per_run` stops it through the same stop path, and the
container's exit code is recorded (`last_exit_code`). For long-running services, the
exit code is not available, the same as for host commands.

### Images

- `pull: missing` (the default) pulls only when the image is not in the store;
  `always` pulls before every start; `never` requires the image to be there already.
- A pull or load runs **before** the start, as status **PULLING**. The supervisor stays
  responsive: a stop or restart cancels the fetch, and nothing starts afterwards. A pull
  that fails is handled like a start that fails (backoff, then FAILED, per
  `restart_policy`). Pull time does not count towards a cron job's `max_time_per_run`.
  Changing the service's `container:` definition during PULLING cancels that fetch too.
- `image_archive: ./images/web.tar` loads a `podman save` archive instead of pulling
  (`image` is then the tag inside the archive). It is loaded on the first start after
  each daemon start, and again whenever the file changes. Because root runs whatever is inside, the archive
  (after following symlinks) and every directory above it must be root-owned and not
  group/other-writable.
- An interrupted pull or load can't damage an image: layers are digest-checked, and an
  image is only tagged once complete. A pull or load killed midway can leave orphan
  layer data that no image refers to. processmaster runs
  `podman system check --quick --repair` right after a killed fetch and hourly. Layer
  data with no layer record is removed at once. Complete layers that no image refers to
  are removed once they are older than 24h (podman's `--max`). That age limit protects
  the layers of a pull still in progress, such as a `pmctl podman pull` you run by hand.
- **Unused images are cleaned up** at boot, after every `pmctl update`, and hourly. Images
  in processmaster's store that no loaded service definition uses are removed. This
  covers images of deleted services, and old versions left behind when a tag is
  re-pulled.
  - Kept: any image a loaded definition uses, whether that service is running,
    stopped, FAILED or disabled (`enabled: false`).
  - The cleanup never runs during a pull or load, and it reads the definitions only
    once no fetch is in progress. Removal is never forced, so an image a container
    uses is never deleted.
  - Not kept: an image pulled or loaded by hand (`pmctl podman pull`) before any
    definition names it is removed within the hour. Write the definition first, then
    let it pull. Renaming an auto-service folder to `<name>.disabled` removes its
    definition, so its image is cleaned up as well; use `pmctl disable` to keep it.
  - Turn the cleanup off with `containers.prune_unused_images: false`.

### processmaster's own container store

Images and containers always live in processmaster's own podman store, never in podman's
shared one (`/var/lib/containers`, which is refused). The defaults are
`/var/lib/processmaster/<instance>/containers` (images, containers) and
`/run/processmaster/<instance>/containers` (runtime state). `<instance>` is
`cgroup.name`, with characters other than letters, digits, `_`, `.` and `-` replaced
(plus a short hash when anything was replaced). To move them, set:

```yaml
# master config
containers:
  storage_root: /data/processmaster/containers
  run_root: /run/processmaster/containers
  prune_unused_images: true
```

Both must be root-controlled. Podman's runtime state (normally `/run/libpod`, shared by
every rootful podman on the host) is also kept separately, in `<run_root>/libpod`, so
nothing done to the host's default podman store (even `podman system reset`) affects
processmaster's containers. Don't share one store between two processmaster
instances: each would clean up the other's images.

A plain `podman ps` does not show these containers. Use `pmctl podman <args>`, which
runs podman against processmaster's store: `pmctl podman ps -a`, `pmctl podman images`,
`pmctl podman pull <image>`, `pmctl podman load -i x.tar`, `pmctl podman system df`.

### `container:` keys

| key | meaning |
|---|---|
| `image` | Required. Image reference, e.g. `docker.io/library/redis:7.4`. |
| `pull` | `missing` (default), `always`, `never`. |
| `image_archive` | Load this `podman save` archive instead of pulling (root-controlled path). |
| `command` | Replaces the image's CMD. |
| `env` | Environment inside the container: a map or a `[{name, value}]` list, with `@file://`, `@base64://`, `@hex://`. |
| `volumes` | `host:container[:options]`. Always host folders or files: absolute, or relative to `working_directory`. |
| `ports` | `[ip:][host_port:]container_port[/tcp\|udp\|sctp]`, ranges allowed (`8000-8010:8000-8010`). |
| `network` | `bridge` (default), `host`, `none`, or a named podman network. |
| `user` | User inside the container (`name` or `uid[:gid]`). Podman itself always runs as root. |
| `extra_args` | Other `podman run` options, placed before the image (see the refusals below). |
| `working_directory` | Host directory that relative volumes, `image_archive` and logs resolve under. Inside the container, the image's `WORKDIR` applies. |
| `stop_signal`, `stop_grace_period_ms` | As for host commands; sent by `podman stop`. |
| `schedule`, `not_before`, `not_after`, `max_time_per_run` | Cron, as for host commands. |

`logs:`, `resources:`, `restart_policy:`, `global:` and `provisioning:` are the same
as for host commands.

### Details and limits

- **Mounts are always explicit host folders.** Podman named volumes are not supported, so
  no data is hidden inside the container store, where it could be lost without anyone
  noticing. `-v`/`--volume`/`--mount`/`--volumes-from` in `extra_args` are refused.
  Anything a container writes outside its mounts, including the anonymous volumes
  podman creates for an image's `VOLUME` paths, is removed with the container when it
  stops. A missing mount source is reported as a start error.
- **Port forwarding** is podman's (`-p`). Rootful podman sets it up with firewall rules,
  which `podman rm` removes again on every stop.
- **Minimum limits:** podman needs about 20 MB and about 20 tasks inside the service
  cgroup to start a container. If you set `max_memory` or `max_pids`, they must be at
  least 64MiB / 64.
- **Environment values** travel through podman's environment, not its command line, so
  `ps` and the web UI don't show them. Podman does keep them in its container config,
  inside the root-only store. A short list of names podman itself reads (`PATH`,
  `HOME`, `TMPDIR`, `GOMAXPROCS`, `GOMEMLIMIT`, `XDG_*`, `CONTAINERS_*`, `LISTEN_*`, …)
  are passed on the command line instead, so don't put secrets in those.
- **SELinux:** bind mounts usually need `:z` (shared) or `:Z` (private). If the image
  runs as a non-root user, add `U` (`./data:/data:Z,U`) so podman chowns the source to
  that user; otherwise the app gets "permission denied". `z`, `Z` and `U` are refused
  for system paths (`/etc`, `/usr`, `/var/lib`, `/run`, …).
- **Startup window:** RUNNING means podman is in the service's cgroup; the container
  itself may still be being created for a moment (a stop at that point still stops it
  gracefully). Health checks are not supported: podman runs them from systemd timers,
  outside the service cgroup. An image's own `HEALTHCHECK` is disabled.
- **Refused in `extra_args`:**
  - options processmaster sets itself: `-d`, `--rm`, `--name`, `--replace`,
    `--restart`, `--cgroups`, `--cgroup-parent`, `-t`/`-i`/`-a`, `--sig-proxy`,
    `--log-driver`, `--stop-signal`, `--stop-timeout`, `--pull`;
  - podman's global options, which would move the container to a store or runtime
    processmaster does not manage: `--root`, `--runroot`, `--storage-*`,
    `--cgroup-manager`, `--runtime`, `--remote`, `--syslog`, …;
  - `--health-*`, `--rootfs`, pods, `--label-file`, and `processmaster.*` labels;
  - stray arguments, which would become the image.

  A container definition is as powerful as a `start_command` running as root (it can
  mount any host path, or use `--privileged`). Treat it with the same care.

## Provisioning (workdir setup, re-applied on change)

If you define `provisioning:`, it is checked **during definition load** (startup or “reload defs”) **and before every service start**.
Provisioning state is recorded in a marker file: `${working_directory}/.pm_provisioned`.

- The marker records each entry's spec plus a stat fingerprint (device, inode, size, mtime, ctime) of every regular-file target, taken after provisioning finished.
- If the marker matches, provisioning is skipped.
- Provisioning runs again when the marker is missing, when the `provisioning:` spec changed, or when a file target no longer matches its fingerprint — e.g. a redeployed binary, which loses its `setcap` capability when replaced.
- Markers written by older releases (empty, or `provisioned_at_ms=...`) are accepted: they trigger one more provisioning pass and are replaced by the new format.
- Directory targets are not fingerprinted (their timestamps change whenever files are created in them).
- All provisioning actions are idempotent, so a spurious re-run (e.g. after `touch`) is harmless.
- `mode` may not set setuid/setgid bits (`04000`/`02000`): provisioning re-applies automatically to whatever file sits at the target, so those bits would be stamped onto a binary the service user swapped in.
- The marker is written **only after all provisioning entries succeed**.
- If provisioning fails at load, the app is **not loaded**; if it fails at start, the start is refused. Fix the error and reload definitions / start again to retry.
- Relative `provisioning[].path` is resolved **under `process.working_directory`**.

### Re-provision (reapply) flow

Normally nothing is needed: replacing a provisioned file or editing `provisioning:` triggers a re-run on the next load or start.
To force a re-run anyway, delete `${working_directory}/.pm_provisioned` and reload definitions (web UI: “Reload Service Definition”, or `pmctl update`) or start the service.

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
- Each action runs in its own cgroup `${cgroup.name}/admin_actions/<id>`; a second run of the same id is **refused while the previous one is still running** (different ids may run concurrently)
- Action ids must be 1-64 chars of `[A-Za-z0-9_-]`; `run` is reserved
- **Only root-controlled code may run.** `command[0]` must be an absolute path, and it plus every later argument that names an existing file (e.g. the script passed to `/bin/sh`) must be owned by root and not group/other-writable — as must every parent directory, both as written and after resolving symlinks. Otherwise the daemon **refuses to start**, and the check is repeated before every run. Files referenced only inside an inline `sh -c "..."` string cannot be checked; keep those root-owned yourself.
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

## Testing

- `cargo test`: unit and config tests; no root needed.
- `tests/supervisor_scenarios.rs`: end-to-end supervision against a real daemon. Each test writes its own config in code, starts a private `processmaster` (own socket, own cgroup `pmtest-<pid>-<n>`) and cleans up afterwards. Scenarios: quick-failing service (restarted until the tolerance, then FAILED), `never` policy, daemonizing service (forks to the background and exits; tracked via its cgroup), background worker dying later, SIGTERM-immune service (force-killed after the grace period), graceful TERM handler, 20-child fan-out, output capture on both streams, and recovery of a FAILED service by manual start. They need root and cgroup v2, so they are `#[ignore]`d by default:

  ```bash
  cargo test --test supervisor_scenarios --no-run
  sudo "$(ls -t target/debug/deps/supervisor_scenarios-* | grep -v '\.d$' | head -1)" --ignored
  ```

  CI runs them on every push and PR.

## Security rules (root daemon)

processmaster runs as root and works inside directories that service users can write (working directories, `logs/`, auto-service directories). It enforces these rules; configurations that break them are refused, not silently weakened:

- **Service definitions must be root-controlled.** Every definition file (`config_directory/*.yaml`, auto-service `service.yml`) must be a regular file owned by root, with a single hard link, not writable by others, and group-writable only if its group is root. Otherwise it is not loaded, and the previously loaded definition (if any) is kept.
- **Auto-services only load from root-controlled directories.** "Root-controlled" means the directory and every directory above it are owned by root and not writable by anyone else. An auto-service directory is also the service's working directory. If the service user can write it (for example, provisioning chowned it), nothing inside it can be trusted: the user could rename a root-owned file, even a log holding its own output, into `service.yml` or `.regen_pm_config`. Such directories are **skipped** with an `auto_service_dir_not_root_controlled` warning.

  To run a service from a directory its user owns, define it in `config_directory` with `process.working_directory` pointing at that directory. A `config_directory` definition with the same name takes precedence over the skipped auto-service directory, with no conflict error.
- **No symlinks below the root-controlled part of a path.** Log files and directories, log viewing (`pmctl logs`, the web console), provisioning targets, `@file://` environment values and admin-action logs are opened one component at a time without following symlinks. This applies anywhere below the deepest root-owned, non-group/other-writable directory. Symlinks that root placed in root-controlled directories (e.g. `/var/run -> /run`) keep working. A service that swaps `logs/` for a symlink gets a log pump error, not a root write elsewhere.
- **Provisioning** refuses paths containing `..`, targets with multiple hard links, and setuid/setgid modes. Recursive chowns walk by descriptor and skip symlinks and hard-linked files. The capability is set on the opened file (no `setcap` binary is needed any more).
- **Rotated logs** are gzip-compressed in-process (no `gzip` binary needed).
- **Admin actions** whose program or script arguments a non-root user could modify are logged as a `WARNING` at startup and refused at run time. They no longer stop the daemon from starting. `command[0]` may not be `env`, and `/dev/...` arguments (e.g. `/dev/null`) are allowed.
- **Limits:** `max_cpu` must be 10m–1024 cores (below 10m the kernel rejects the quota), checked when definitions load. Durations (`stop_grace_period_ms`, `restart_backoff_ms`, duration strings) are capped at 30 days, flag TTLs at 3650 days. User flags may only contain `[a-z0-9_.:-]`. The control socket closes connections that send no request within 10 s, and accepts at most 256 at once.
- **Shutdown:** once the daemon is shutting down, requests that would start processes (start/restart/enable/update/admin actions) are refused on both the socket and the web console.

## Observability

Useful commands:

```bash
pmctl status [<app>] [--format text|json]
pmctl events [-n 200] [<app>] [--format text|json]
pmctl logs <app> -n 50
pmctl logs -f [filename]
```

When stdout is a terminal, `pmctl logs` and `pmctl events` print control characters and escape
sequences from service output as visible text (`\x1b`, `\u{9b}`), keeping only newlines, tabs and
SGR colours, so a service cannot drive the operator's terminal (clipboard writes, title changes,
cursor movement). Unicode bidi controls (e.g. `\u{202e}`) and SGR conceal (`ESC[8m`) are escaped
too, so text cannot be hidden or visually reordered; the CR of a CRLF line ending is dropped. Piped or redirected output is passed through byte-for-byte.

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

# Nesting
You can process master in another parent processmaster, child processmaster can further run other processmaster etc. You just need to allow the subtree control.

in master config, there is cgroup.subtree_control_allow, defaults to true. Once enabled, subtree in cgroup can also do exactly the same as parent cgroup.

If you do not like it, you can set it to false (default is true).

In nested processmaster, you need to configure proper parent cgroup node.

For example:
```yml
cgroup:
  root: /sys/fs/cgroup/processmaster/pm-mini_processmaster
  name: pm1
  memory_max: MAX
  memory_swap_max: MAX
  cpu_max: MAX
```

In this case, you can give root cgroup CPU of 4 cores, and 12G of ram, but partition it into 4 different sub processmaster, give it to different users to launch their processes.
The resource constraints are all honored in an ancester - descendent way.

That means we will use the parent's CGROUP node as root. And treat it as our root for new cgroups.
Things should generally work.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
