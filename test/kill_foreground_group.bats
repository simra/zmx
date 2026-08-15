#!/usr/bin/env bats
# Regression test for `zmx kill` leaving the session's guest process running.
#
# The session's shell runs with job control on, so the command typed into it
# lives in its own process group. handleKill()'s SIGHUP/SIGKILL escalation
# targeted only the shell's group (-self.pid); a guest that handles SIGHUP —
# which every TUI agent does — outlived its session as an orphan. handleKill
# now also signals the PTY's foreground process group.

load test_helper

@test "kill terminates a foreground process that ignores SIGHUP" {
  "$ZMX" run kill-fg -d /bin/zsh -c 'trap "" HUP; exec -a zmx-kill-fg-guest sleep 300'
  wait_for_session kill-fg

  # Wait for the guest to actually be running before killing the session.
  local guest_pid="" i=0
  while (( i < 50 )); do
    guest_pid=$(pgrep -f zmx-kill-fg-guest | head -1) && [[ -n "$guest_pid" ]] && break
    sleep 0.1
    (( i++ )) || true
  done
  [ -n "$guest_pid" ]

  "$ZMX" kill kill-fg

  # The guest must be gone shortly after the kill returns; poll briefly since
  # the daemon's SIGKILL lands 500ms after the SIGHUP.
  i=0
  while kill -0 "$guest_pid" 2>/dev/null; do
    if (( i >= 30 )); then
      ps -o pid,pgid,ppid,command -p "$guest_pid" >&2 || true
      kill -9 "$guest_pid" 2>/dev/null || true
      false
    fi
    sleep 0.1
    (( i++ )) || true
  done
}
