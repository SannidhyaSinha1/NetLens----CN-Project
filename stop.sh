#!/usr/bin/env bash
# Stop the NetLens dashboard.
#
#   ./stop.sh              stop whatever ./start.sh started
#   ./stop.sh --port 8600  stop an instance started on another port
#
# Falls back to the process listening on the port if the pid file is missing,
# but only kills it when it is actually Streamlit running this app.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PORT=8501
while [ $# -gt 0 ]; do
  case "$1" in
    -p|--port) PORT="${2:?--port needs a number}"; shift 2 ;;
    -h|--help) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1  (try --help)" >&2; exit 2 ;;
  esac
done

PIDFILE=".netlens-${PORT}.pid"
STOPPED=0

# Send TERM, wait for the process to go, then KILL if it refuses.
terminate() {
  local pid="$1" label="$2" sudo_prefix=""
  # A --live instance runs as root, so stopping it needs sudo too.
  if [ "$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')" = "root" ] \
     && [ "$(id -u)" != "0" ]; then
    sudo_prefix="sudo"
  fi

  $sudo_prefix kill "$pid" 2>/dev/null || return 1
  for _ in $(seq 1 20); do
    kill -0 "$pid" 2>/dev/null || { echo "stopped $label (pid $pid)"; return 0; }
    sleep 0.25
  done
  $sudo_prefix kill -9 "$pid" 2>/dev/null
  echo "force-stopped $label (pid $pid)"
  return 0
}

# ---------------------------------------------------------------- by pid file
if [ -f "$PIDFILE" ]; then
  PID=$(cat "$PIDFILE" 2>/dev/null || true)
  if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
    terminate "$PID" "NetLens" && STOPPED=1
  else
    echo "pid file pointed at $PID, which is not running — clearing it."
  fi
  rm -f "$PIDFILE"
fi

# ------------------------------------------------- by port, if anything is left
if command -v lsof >/dev/null 2>&1; then
  for PID in $(lsof -ti "tcp:${PORT}" -sTCP:LISTEN 2>/dev/null || true); do
    CMD=$(ps -o command= -p "$PID" 2>/dev/null || true)
    # Only touch it if it is Streamlit serving this project. Anything else on
    # this port belongs to someone else and is not ours to kill.
    if printf '%s' "$CMD" | grep -q 'streamlit' \
       && printf '%s' "$CMD" | grep -q 'app.py'; then
      terminate "$PID" "Streamlit on port ${PORT}" && STOPPED=1
    else
      echo "leaving pid $PID on port ${PORT} alone — not NetLens:" >&2
      echo "  $(printf '%s' "$CMD" | cut -c1-70)" >&2
    fi
  done
fi

if [ "$STOPPED" -eq 0 ]; then
  echo "NetLens was not running on port ${PORT}."
fi
