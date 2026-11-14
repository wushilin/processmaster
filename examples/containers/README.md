# Container service examples (podman)

Ready-to-adapt `container:` service definitions. Copy one into your `config_directory`
(e.g. `conf.d/`), adjust the paths, create the folders it mounts, and run `pmctl update`.

Every example here is run end to end by `tests/container_scenarios.rs`
(`example_*` tests), so what you copy is known to work. The tests only substitute the
working directory, host ports, and host paths outside the working directory.

| file | shows |
|---|---|
| `nginx.yaml` | a web server: port forwarding, a read-only mounted site, a memory limit |
| `redis.yaml` | a database: persistent data folder, a non-root container user (`:U`), a secret from a file |
| `kafka.yaml` | a slow-to-stop JVM: a long grace period, memory/CPU limits, environment configuration |
| `s3-server-archive.yaml` | an offline image: `image_archive` instead of pulling, `pull` not used |
| `nightly-backup.yaml` | a container cron job: `schedule`, `max_time_per_run`, an exit code that is recorded, and an SELinux-shared (`z`) read-only mount |

The full annotated reference is `../service.container.yaml`, and the behaviour (cgroup,
stop, logging, image store and cleanup) is described in the README section
"Container services (podman)".

Notes that apply to all of them:

- Requirements: rootful podman and cgroup v2. Docker is not supported.
- Mounts are host folders only and must exist before the start. On SELinux hosts, add
  `:Z` (private) or `:z` (shared). If the image runs as a non-root user, add `U` so the
  folder is chowned to it.
- Images live in processmaster's own store. Inspect it with `pmctl podman images` and
  `pmctl podman ps -a`.
