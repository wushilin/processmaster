# TODO

Pending items from the 2026-10-17 code review.

## Decided

- `resources.max_pids` stays opt-in: `pids.max` counts threads, so a global default
  could break thread-heavy services, and a cap on the master cgroup would also starve
  the daemon, which lives inside it. Set it per service, sized from `pids.peak`.
- Repo hygiene: `.sync` is untracked (kept locally, gitignored). Root `config.yaml`
  (tested default), `run.sh` (documented launcher) and `conf.d/` (demo services) stay.
- `issues.md` removed; it remains in git history.

## Done

- [x] `cargo clippy --all-targets` is clean.

- [x] Console `systemd_list` timeout raised from 3s to 10s (a slow first listing failed).
- [x] Event-driven cgroup waiter: async watch on `cgroup.events` (`populated`), no
      thread per service; the pidfd thread waiter remains as a fallback.
- [x] Lock poisoning: every lock recovers (`unwrap_or_else(|p| p.into_inner())`),
      including the schedulers (used to stop firing) and the console's login throttle
      (used to stop throttling).
- [x] Stop latency: grace loop polls every 50ms (stop/restart ~90ms instead of ≥1s).
- [x] Cron process-waiter spawn failure falls back to the cgroup waiter.
- [x] Console-only RPC methods moved to `web_console/console_rpc.rs`.
- [x] Boot autostart bounded through `fan_out` (32 at a time).
- [x] Tests: `fan_out` panic, `max_pids` reset, and a root scenario that fills a
      tmpfs log directory (the service must survive; fails against the old pump).
- [x] Log pump logs only failure/recovery transitions, under the configured path.
