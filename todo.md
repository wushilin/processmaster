# TODO

Pending items from the 2026-10-17 code review (its fixes landed in the commit that
added this file).

## Decisions needed

- [ ] **Default for `resources.max_pids`.** Added as opt-in (unset = unlimited) so no
      existing service changes. Decide whether services should get a default cap.
- [ ] **Repo hygiene.** Personal/test files are tracked: `.sync` (OSS upload targets),
      `conf.d/` (test scripts, `failure1.YmL`), root `config.yaml` and `run.sh`. Move to
      `examples/`, gitignore, or keep.
- [ ] **`issues.md`.** A dated audit that reads as current. Mark items done, or move it
      to `docs/`.

## Task management

- [ ] **Event-driven cgroup waiter.** Each running service holds a blocking OS thread in
      `cgroup::wait_all_cancellable`, which rescans the whole cgroup tree after every pid
      exit (CPU grows with a service's fork churn), and a cancelled waiter lingers up to
      5s (`CANCEL_POLL_MS`). Waiting on `cgroup.events` (`populated 0`) via poll/epoll
      would need one thread for all services. See A8 in `issues.md`.
- [ ] **Lock-poisoning policy.** `DaemonState` is locked with `map_err(..)?` in some
      places (any panic under the lock then fails those RPCs forever) and
      `unwrap_or_else(|p| p.into_inner())` in others. Pick one; recovering is the better
      fit for a supervisor.
- [ ] **Stop latency.** The grace loop in `stop_common` (`daemon/process.rs`) polls once
      a second, so every stop takes at least ~1s. Poll faster (e.g. 50–100ms) or wait on
      the cgroup.
- [ ] **Cron process-waiter spawn failure.** If `spawn_process_waiter` fails (thread
      creation), `Supervisor::attach_process_waiter` still marks the waiter running, so
      that run's exit is never observed. Fall back to the cgroup waiter.

## Follow-ups from the refactor

- [ ] `web_console/mod.rs` is still ~2.7k lines, mostly the `jsonrpc` handler (~400
      lines) and tests. Split the console-only RPC methods out.
- [ ] `start_enabled_services_async` (boot) spawns every service at once; it could
      reuse `fan_out` like the other bulk operations.
- [ ] The log pump's mid-stream write-error path shares code with the tested
      open-failure path but has no direct test (hard to simulate ENOSPC without root).
