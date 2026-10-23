#!/usr/bin/env bash
# Start the NetLens dashboard.
#
#   ./start.sh              start on port 8501
#   ./start.sh --open       start and open it in Chrome
#   ./start.sh --port 8600  start on a different port
#   ./start.sh --live       run under sudo so live capture can use raw sockets
#
# Runs in the background, logging to logs/netlens-<port>.log. Stop it with ./stop.sh

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PORT=8501
OPEN=0
LIVE=0

while [ $# -gt 0 ]; do
  case "$1" in
    -o|--open)  OPEN=1; shift ;;
    -p|--port)  PORT="${2:?--port needs a number}"; shift 2 ;;
    --live)     LIVE=1; shift ;;
    -h|--help)  sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1  (try --help)" >&2; exit 2 ;;
  esac
done

VENV=".venv/bin/streamlit"
# Scoped to the port so two instances on different ports cannot confuse
# each other's pid file or interleave their logs.
PIDFILE=".netlens-${PORT}.pid"
LOG="logs/netlens-${PORT}.log"
URL="http://localhost:${PORT}"

# ---------------------------------------------------------------- preflight
if [ ! -x "$VENV" ]; then
  cat >&2 <<MSG
No virtualenv found at $VENV

Create it first:
  python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt
MSG
  exit 1
fi

# Already running? Say so and stop — do not start a second copy.
if [ -f "$PIDFILE" ]; then
  OLD=$(cat "$PIDFILE" 2>/dev/null || true)
  if [ -n "$OLD" ] && kill -0 "$OLD" 2>/dev/null; then
    echo "NetLens is already running (pid $OLD) at $URL"
    echo "Use ./stop.sh first, or ./stop.sh && ./start.sh to restart."
    exit 0
  fi
  rm -f "$PIDFILE"          # stale file from a crash or a reboot
fi

# Port taken by something we did not start?
if command -v lsof >/dev/null 2>&1; then
  BUSY=$(lsof -ti "tcp:${PORT}" -sTCP:LISTEN 2>/dev/null | head -1 || true)
  if [ -n "$BUSY" ]; then
    WHAT=$(ps -o command= -p "$BUSY" 2>/dev/null | cut -c1-70)
    if printf '%s' "$WHAT" | grep -q 'streamlit'; then
      echo "A Streamlit process (pid $BUSY) already holds port ${PORT}."
      echo "That is probably NetLens started another way — ./stop.sh will clear it."
    else
      echo "Port ${PORT} is in use by pid $BUSY:" >&2
      echo "  $WHAT" >&2
      echo "Start on another port:  ./start.sh --port 8600" >&2
    fi
    exit 1
  fi
fi

if [ ! -f "models/netlens_model.joblib" ]; then
  echo "note: no trained model found, so tier 3 (the attack classifier) will be"
  echo "      disabled. Rules and the Isolation Forest still work. To enable it:"
  echo "        .venv/bin/python train_model.py"
  echo
fi

# ---------------------------------------------------------------- launch
mkdir -p logs
: > "$LOG"

ARGS=(run app.py
      --server.port "$PORT"
      --server.headless true
      --browser.gatherUsageStats false)

if [ "$LIVE" -eq 1 ]; then
  echo "Starting under sudo so live capture can open raw sockets."
  echo "Choose 'Live interface' in the sidebar once it opens."
  sudo "$VENV" "${ARGS[@]}" >> "$LOG" 2>&1 &
else
  "$VENV" "${ARGS[@]}" >> "$LOG" 2>&1 &
fi
echo $! > "$PIDFILE"
PID=$(cat "$PIDFILE")

# ---------------------------------------------------------------- wait for it
printf "starting NetLens"
for _ in $(seq 1 40); do
  if ! kill -0 "$PID" 2>/dev/null; then
    echo
    echo "NetLens exited during startup. Last lines of $LOG:" >&2
    tail -15 "$LOG" >&2
    rm -f "$PIDFILE"
    exit 1
  fi
  if command -v curl >/dev/null 2>&1 \
     && curl -fsS -o /dev/null --max-time 1 "$URL" 2>/dev/null; then
    break
  fi
  printf "."
  sleep 0.5
done
echo

if command -v curl >/dev/null 2>&1 \
   && ! curl -fsS -o /dev/null --max-time 2 "$URL" 2>/dev/null; then
  echo "Process is up (pid $PID) but $URL is not answering yet."
  echo "Check $LOG if it does not come up shortly."
else
  echo "NetLens is running at $URL  (pid $PID)"
fi
echo "  logs:  tail -f $LOG"
if [ "$PORT" = "8501" ]; then
  echo "  stop:  ./stop.sh"
else
  echo "  stop:  ./stop.sh --port $PORT"
fi

if [ "$OPEN" -eq 1 ]; then
  if open -a "Google Chrome" "$URL" 2>/dev/null; then :; else open "$URL"; fi
fi
