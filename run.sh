#!/bin/sh
#
# Example launcher for running processmaster from a systemd unit.
#
# Two things matter here, and both are easy to get wrong:
#
#   1. `exec`. Without it this shell stays alive as the parent, so systemd's main PID
#      is the shell rather than the daemon, and signals never reach processmaster.
#
#   2. Do NOT background with `&`. Under Type=simple systemd expects ExecStart to *be*
#      the service; backgrounding makes the unit look like it exited immediately.
#
# This matters more than usual here: processmaster moves itself into its own cgroup at
# startup, so it leaves the unit's cgroup behind and cgroup-based killing cannot reach
# it. If the main PID is a wrapper shell, `systemctl stop` kills only the wrapper and
# leaves the daemon running — see the systemd section in README.md.
#
# Prefer pointing ExecStart straight at the binary and skipping this wrapper entirely.

set -eu

exec processmaster -c config.yaml
