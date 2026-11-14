# Design record: native container (Podman) services

This is the design plan the feature was built from, kept as a record of the reasoning
(why Podman and not Docker, the cgroup layout, the stop sequence, the experiments and
the review findings). **The user documentation is the README section "Container
services (podman)"**; where this plan and the README differ, the README describes what
was built. The differences are listed here.

## How the implementation differs from the plan below

- **Schema**: a container service has no `process:` section; a file has either
  `process:` or `container:`. The lifecycle keys (`working_directory`, `stop_signal`,
  `stop_grace_period_ms`, `schedule`, `not_before`, `not_after`, `max_time_per_run`) live
  under `container:`.
- **Mounts**: host folders only. Podman named volumes are not supported, and
  `-v`/`--volume`/`--mount`/`--volumes-from` are refused in `extra_args`. `rm` uses
  `--volumes` (anonymous volumes for an image's `VOLUME` paths go with the container).
  `z`/`Z`/`U` are refused on system paths (`/var/lib/<app>` is allowed).
- **Store**: always processmaster's own, isolated store: `--root`, `--runroot` **and**
  `--tmpdir <run_root>/libpod`. Without `--tmpdir`, podman keeps runtime state in the
  host-wide `/run/libpod`, where `podman system reset` on the host's default store would
  disrupt processmaster's containers. Podman records the tmpdir in the store's database
  on first use. The store paths are configured under `containers:` in the master config;
  podman's shared store is refused. `pmctl podman <args>` runs podman against the store.
- **Image cleanup**: images that no loaded definition uses are removed at boot, on
  `pmctl update` and hourly (`containers.prune_unused_images`, default true). This runs
  under a store lock that excludes pulls and loads. `podman system check --quick
  --repair` runs after a killed fetch and hourly.
- **Helpers** (`podman pull/load/stop/rm/...`) run in
  `<master>/container_ctl/pm-<app>/<kind>-<seq>`, one cgroup per invocation, outside
  the service cgroup (not `<app>/ctl`).
- **Stop**: `podman stop` is retried within the grace period (right after a start, the
  container may still be being created), then `cgroup.kill`, then `podman rm`. A running
  instance is stopped with the definition it was started with.
- **Auto services**: never generate a container definition. A folder with neither
  `service.yml` nor `run.sh` is skipped (and a `.regen_pm_config` marker is ignored
  there). A hand-written container `service.yml` in an auto folder works.
- **Fetch lifecycle**: a fetch is cancelled by stop, restart, any change to the
  `container:` definition, disabling the service, and supervisor exit.
- `image_archive` must be root-controlled along its whole (symlink-resolved) path.
- **Examples**: `examples/service.container.yaml` and `examples/containers/*.yaml`, each run
  end to end by `tests/container_scenarios.rs` (with nginx, Redis, Kafka, rust-s3-server
  and a cron backup).

## 0. Decisions (agreed 2026-11-14)

1. Podman only. 2. Rootful launch; `container.user` = user inside the container
(`--userns=auto` allowed via `extra_args`). 3. Map-form `environment` shipped separately
(done: `ee14da7`); `env_file` later.
4. processmaster pulls on start (`pull: missing` default, cancellable Pulling phase).
5. Pull time does not count toward cron `max_time_per_run`. 6. No exit codes for
non-cron container services in v1. 7. `memory.oom.group=1` for container services.
8. Boot sweep of own-instance leftover containers.
9. Secrets: document podman's plaintext storage; `--secret` later. 10. Container
definitions are root-equivalent (documented); no volume ownership restriction.
11. Reject `max_memory` < 64MiB / `max_pids` < 64. 12. Keep `extra_args` with deny-list.
13. Name `pm-<instance>-<app>`. 14. Top-level `container:` key.

## 1. Goal

Let a service definition run an OCI image instead of a host binary, with **the same
guarantees as a native service**: per-service cgroup limits, process view, stdout/stderr
through processmaster's log pumps, restart policy / cron, and a deterministic stop
("stopped means definitely not running").

Non-goals for v1: Docker, compose / pods, health checks, rootless podman, adopting
containers across a daemon restart.

## 2. Why Podman only (v1)

- `podman run` is an ordinary child process (podman → conmon → container). With
  `--cgroups=split` all of it lands **inside our service cgroup**.
- `docker run` is only an API client; the container belongs to dockerd's containerd-shim
  in `system.slice/docker-<id>.scope` (systemd driver, the cgroup v2 default). `cgroup.kill`
  on our cgroup would kill only the client. Only a host-wide switch to the `cgroupfs`
  driver + `--cgroup-parent` would fix that. Deferred.
- Podman runs the same OCI images (Docker Hub, etc.).

## 3. Evidence (rootful podman 5.8.2, cgroup v2, SELinux enforcing host)

Scripts: `cgtest.sh` … `cgtest6.sh` in the session scratchpad.

Verified in the **real** layout (launcher attached to `<svc>/run`, as `cgroup::build_command` does):

| Topic | Result |
|---|---|
| Placement | `run/runtime` = podman CLI + conmon, `run/libpod-payload-<id>` = container. Nothing escapes the service cgroup. |
| `cgroup.kill` | Cgroup empties, but podman leaks state: stale "Up", 2 mounts, 1 netns, 4 nft rules; restart without cleanup → exit 125 (name in use). `podman rm -f` cleans all of it in ~0.16s. |
| `podman stop -t N` | Signals only the container init; graceful; honours `--stop-signal`; escalates to SIGKILL itself. |
| Signal-every-pid (today's stop) | OK for TERM/QUIT. SIGHUP kills conmon → container left stale; INT/USR1 delivered twice (direct + sig-proxy). **Unsafe as a container stop path.** |
| **Restart** | **Blocker:** podman enables controllers in `run/cgroup.subtree_control` and leaves `run/runtime`; the next attach to `run` fails EBUSY. Resetting `run` (rmdir children, disable controllers) fixes it — verified. |
| Limits | Podman's own overhead counts: startup peak ~21 MB, ~19 tasks. `max_memory` 8–16M → start OOM; 32M → podman OOM-killed after the container finished; `max_pids` 16 → netavark panic. |
| Concurrency | 16 containers with ports start in 0.93s, 32 in 2.3s; no lock errors. |
| Secrets | `-e NAME` hides values from `ps`, but they appear in `podman inspect` and in plaintext `config.json` under `/var/lib/containers/storage/...`. |

## 4. Cgroup layout for container services

```
<master>/<app>/          resources applied here (as today)
  run/                   launcher leaf; podman creates under it:
    runtime/             podman CLI + conmon
    libpod-payload-<id>/ the container
  ctl/                   helper leaf: podman stop / rm / pull / image exists
```

- **Before every container start**: reset `run/` — rmdir empty children, write `-<ctrl>`
  for each enabled controller in `run/cgroup.subtree_control`. Then attach as usual.
- **Helpers** (`podman stop/rm/pull`) run in `ctl/`, never in `run/` (EBUSY while the
  container runs; verified that attaching to a sibling leaf works). They are accounted
  to the service (limits apply) and visible in the process view.
- Note: podman also rewrites `subtree_control` on the master and app cgroups (enables
  cpuset/hugetlb/misc), overriding `cgroup_subtree_control_allow=false`. Harmless; document.
- Consider `memory.oom.group=1` on `<app>`: otherwise an OOM kill of only `runtime`
  leaves the payload running with no conmon/log pipes while the cgroup stays populated.

## 5. Config schema (v1, trimmed)

```yaml
application: redis
container:
  image: docker.io/library/redis:7.4     # required
  pull: missing                          # always | missing | never (default missing)
  command: [redis-server, --appendonly, "yes"]   # optional, replaces CMD
  env:                                   # map; @file:// @base64:// @hex:// supported
    TZ: Asia/Singapore
  volumes:                               # host:container[:ro|rw]; host relative to working_directory
    - ./data:/data
  ports: ["127.0.0.1:6379:6379"]
  network: bridge                        # bridge | host | none | <named network>
  user: "999:999"                        # user inside the container
  extra_args: [--init, --read-only]      # escape hatch, deny-listed (below)
process:                                 # optional when container: is present
  stop_signal: SIGTERM
  stop_grace_period_ms: 10000
resources: { max_memory: 512MiB, max_cpu: 1000m }
restart_policy: { policy: always }
```

Cut from v1 (use `extra_args`): `runtime`, `entrypoint`, `workdir`, `read_only`, `init`.
Separate PR (also for native services): map-form `environment`, `env_file`.

Validation:
- `image` required; `process.start_command` / `stop_command` forbidden; `process:` optional.
- `process.user/group` must be unset or `root` (auto-generated service.yml writes the
  default user — tolerate `root`, error otherwise with a pointer to `container.user`).
- **Floors**: `max_memory` ≥ 64MiB and `max_pids` ≥ 64 when set (podman overhead).
- **`extra_args` deny-list**: `-d/--detach`, `--rm`, `--name`, `--replace`, `--cgroups`,
  `--cgroup-parent`, `--cgroup-manager`, `--restart`, `--pod`, `-t/--tty`, `-i`,
  `--sig-proxy`, `--cidfile`, `--log-driver`, `--stop-signal`, `--stop-timeout`, `--label`
  (for `processmaster.*`).
- Volumes: relative host paths resolved under `working_directory`, must exist, no `..`;
  refuse `:z`/`:Z` on system paths. **Document that a container definition is
  root-equivalent** (podman resolves host paths as root, following symlinks), the same as
  any service config.
- Ports/volumes syntax checked at load time.

## 6. Runtime behaviour

Instance-scoped identity (nested / multiple processmasters share root podman storage):
- name `pm-<instance>-<app>`, where `<instance>` = cgroup name (default `processmaster`)
- labels `processmaster.instance=<instance>`, `processmaster.app=<app>`

**Start**
1. `podman rm -f --ignore <name>` (in `ctl/`).
2. **Pulling phase** (new `Phase::Pulling`, visible in UI/pmctl): if needed, `podman pull`
   in `ctl/`, output to the service stderr log, cancellable by stop, timeout 10 min.
   Not counted against restart tolerance. The waiter is attached only after step 4.
   The supervisor loop must not block on it (run as a task; stop cancels it).
3. Reset `run/` (§4).
4. Launcher in `run/`: `podman run --rm --name <name> --cgroups=split --log-driver=none
   --label ... --stop-signal <sig> [-e NAME ...] [-v ...] [-p ...] [--network ..]
   [--user ..] [extra_args] image [command]` — attached, no `-d/-t/-i/--restart`.
   Env values decoded by processmaster and placed in the podman process environment;
   argv carries only `-e NAME`.

**Stop** (container branch of `exec_stop`; never `launcher_kill_signal`):
1. `podman stop -t <grace_s> <name>` in `ctl/` (it escalates to SIGKILL itself).
2. If still populated after grace + margin, or podman failed: existing `cgroup.kill`.
3. Always: `podman rm -f --ignore <name>`.

**Boot sweep**: `podman ps -a --filter label=processmaster.instance=<instance>` →
`rm -f` containers whose app is not running.

**Exit codes**: non-cron services are disowned and the cgroup waiter reports no code, so
for v1 the 125/126/127 mapping applies only to cron services. (Option for later: keep the
child for container services to get real codes.)

**Secrets**: values are hidden from `ps`/argv only; they are stored by podman in
`podman inspect` / `config.json` (root-only). Document it. Later: `--secret ...,type=env`.

## 6a. Image storage and local images

- Podman manages storage: rootful default `graphRoot=/var/lib/containers/storage`,
  `runRoot=/run/containers/storage`, overlay driver (verified on this host; no
  `/etc/containers/storage.conf`, so built-in defaults apply). Relocate host-wide via
  `/etc/containers/storage.conf` (`graphroot`), or add read-only shared stores via
  `additionalimagestores`. processmaster does **not** pass `--root`: a per-service store
  would duplicate images, hide containers from plain `podman ps`, and split lock domains.
- Air-gapped / local images: `image: oci-archive:./redis.tar` (or `docker-archive:`) runs
  directly (verified), **but every run imports a fresh untagged `<none>` image** that
  accumulates. So archives get their own source field instead:
  ```yaml
  container:
    image: localhost/redis:7.4        # the tag the archive carries
    image_archive: ./images/redis.tar # podman load -i in the pulling phase when the
                                      # tag is missing or the archive's mtime/size changed
  ```
  `image_archive` implies `pull: never` for the registry.
- Image cleanup: not automatic in v1 (operator runs `podman image prune`). Possibly later
  an admin action.

## 7. Code changes

- `src/pm/app.rs`: `ContainerSection` + `ContainerSpec`, optional `process:`, lowering to
  generated argv, validation (floors, deny-list, volumes), `%app_dir%`.
- `src/pm/cgroup.rs`: `reset_leaf(run)`; launch into a named leaf (`ctl`).
- `src/pm/daemon/process.rs`: env-by-name; container stop branch; pull/rm helpers.
- `src/pm/daemon/supervisor.rs`: `Pulling` phase (non-blocking, cancellable); container
  start/stop routing; no `launcher_kill_signal` for containers.
- Boot sweep in `src/pm/daemon/mod.rs`.
- RPC/pmctl/UI: image, container name, phase; `pmctl show <app> --resolved`.
- Docs: `examples/service.container.yaml`, README, SKILL.md (root-equivalence, secrets,
  SELinux `:z`, memory/pids floors, subtree_control note).

## 8. Tests

Unit: schema parse/validation (deny-list, floors, volumes, user rule).
Root scenarios (skip if podman absent):
- **start → stop → start → stop** (EBUSY regression)
- graceful stop exit, `cgroup.kill` + cleanup leaves no mounts/netns/nft rules
- pull phase cancellable by stop; manual start during pull
- crash orphan sweep only touches own instance
- tight `max_memory` rejected at load; 64MiB works
- published port works after restart

## 9. Remaining unknowns

- IPAM lease leaks after `cgroup.kill` (not checked).
- netns leak after OOM mid-setup that `rm -f` doesn't clean (seen once) — may need
  `podman network` cleanup or document.
- SELinux denial behaviour with unlabelled volumes (not tested).
- Running under processmaster's exact minimal service environment (works under `env -i`;
  likely fine).
