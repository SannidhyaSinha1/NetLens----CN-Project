#!/usr/bin/env bash
# Double-click this file in Finder to run NetLens.
#
# It sets everything up the first time (virtualenv, dependencies, trained
# model), starts the dashboard, and opens it in your browser. Leave this
# window open while you use it — closing it, or pressing Ctrl+C, stops NetLens.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

PORT=8501
URL="http://localhost:${PORT}"
LOG="logs/netlens-${PORT}.log"
CLEANED=0
TAILPID=""

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
dim()  { printf '\033[2m%s\033[0m\n' "$1"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
work() { printf '  \033[33m•\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; }

cleanup() {
  [ "$CLEANED" -eq 1 ] && return
  CLEANED=1
  [ -n "$TAILPID" ] && kill "$TAILPID" 2>/dev/null
  echo
  bold "Stopping NetLens…"
  ./stop.sh >/dev/null 2>&1
  ok "stopped — you can close this window"
  sleep 1
}
# HUP matters as much as INT here: closing the Terminal window sends SIGHUP,
# and without it NetLens would be left running with no window to stop it from.
trap cleanup EXIT INT TERM HUP

# Must exist before anything tries to write a log into it — on a fresh
# checkout there is no logs/ yet, and the training step below redirects there.
mkdir -p logs

[ -n "${TERM:-}" ] && [ "${TERM}" != "dumb" ] && clear 2>/dev/null
bold "NetLens — Network Packet Analyzer"
dim  "Computer Networks project · Sannidhya Sinha & Avishi Sharma"
echo

# ---------------------------------------------------------- 1. interpreter
if [ ! -x ".venv/bin/streamlit" ]; then
  bold "First run — setting up. This takes a few minutes, once."
  echo

  PY=""
  for cand in "$HOME/.local/bin/python3.12" python3.12 python3.11 python3.13; do
    if command -v "$cand" >/dev/null 2>&1 || [ -x "$cand" ]; then
      PY="$cand"; break
    fi
  done
  if [ -z "$PY" ]; then
    if command -v python3 >/dev/null 2>&1; then
      PY="python3"
      work "using $(python3 --version 2>&1) — 3.11-3.13 is preferred"
    else
      bad "No Python 3 found."
      echo
      echo "  Install it from https://www.python.org/downloads/ and run this again."
      echo
      read -r -p "Press Return to close… " _
      exit 1
    fi
  fi

  work "creating the virtualenv with $("$PY" --version 2>&1)"
  if ! "$PY" -m venv .venv; then
    bad "could not create the virtualenv"
    read -r -p "Press Return to close… " _
    exit 1
  fi
  ok "virtualenv created"

  work "installing dependencies (scapy, streamlit, scikit-learn, plotly…)"
  if ! .venv/bin/pip install --quiet --upgrade pip \
     || ! .venv/bin/pip install --quiet -r requirements.txt; then
    bad "dependency install failed — see the output above"
    read -r -p "Press Return to close… " _
    exit 1
  fi
  ok "dependencies installed"
  echo
else
  ok "environment ready"
fi

# ---------------------------------------------------------- 2. the model
if [ ! -f "models/netlens_model.joblib" ]; then
  work "training the attack classifier on labelled traffic (about a minute)"
  dim  "     this is the supervised tier — it needs malicious examples to"
  dim  "     name an attack rather than just call it unusual"
  if .venv/bin/python train_model.py > logs/train.log 2>&1; then
    ACC=$(grep -m1 "accuracy  " logs/train.log | awk '{print $2}')
    ok "classifier trained${ACC:+ — test accuracy $ACC}"
  else
    bad "training failed, see logs/train.log"
    work "continuing without it: rules and the Isolation Forest still work"
  fi
else
  ok "attack classifier loaded"
fi

# ---------------------------------------------------------- 3. run it
echo
work "starting the dashboard…"
if ! ./start.sh --port "$PORT" >/dev/null 2>&1; then
  bad "could not start — port ${PORT} may be in use"
  echo
  ./start.sh --port "$PORT"
  read -r -p "Press Return to close… " _
  exit 1
fi
ok "running at $URL"

open -a "Google Chrome" "$URL" 2>/dev/null || open "$URL" 2>/dev/null || true

echo
bold "NetLens is open in your browser."
echo "  In the sidebar: choose a traffic source and press Start."
dim  "  'Simulated' needs no privileges and is the right pick for a demo."
echo
bold "Keep this window open. Press Ctrl+C (or close it) to stop NetLens."
echo
dim  "─── live log ───────────────────────────────────────────────────────"

# The log tail runs as a child and we block in `wait`, not in `tail` itself.
# `wait` is a shell builtin, so a signal runs the trap straight away; blocking
# directly in tail would make bash defer the handler until tail exited, which
# it never does — and NetLens would survive Ctrl+C.
tail -f "$LOG" 2>/dev/null &
TAILPID=$!
wait "$TAILPID" 2>/dev/null
