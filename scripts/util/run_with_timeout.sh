#!/usr/bin/env bash
set -euo pipefail

# Usage: run_with_timeout.sh <seconds> <cmd> [args...]
# Kills the whole process group of <cmd> if it exceeds the timeout.

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <seconds> <cmd> [args...]" >&2
  exit 2
fi

TIMEOUT_SECONDS="$1"
shift

CMD=("$@")

terminate_tree() {
  local pid="$1"
  if ps -p "$pid" >/dev/null 2>&1; then
    # Try to kill process group if possible; fall back to single process
    if command -v pkill >/dev/null 2>&1; then
      pkill -TERM -g "$pid" 2>/dev/null || true
    fi
    kill -TERM "$pid" 2>/dev/null || true
  fi
}

# Start command
"${CMD[@]}" &
CMD_PID=$!

# Watchdog
(
  sleep "$TIMEOUT_SECONDS"
  if ps -p "$CMD_PID" >/dev/null 2>&1; then
    echo "⏱️  Timeout (${TIMEOUT_SECONDS}s) exceeded; terminating test run (pid $CMD_PID)" >&2
    terminate_tree "$CMD_PID"
  fi
) &
WATCHDOG_PID=$!

trap 'terminate_tree "$CMD_PID"; kill "$WATCHDOG_PID" 2>/dev/null || true' EXIT INT TERM

wait "$CMD_PID" || exit $?
kill "$WATCHDOG_PID" 2>/dev/null || true
exit 0
