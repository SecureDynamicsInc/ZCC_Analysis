#!/usr/bin/env bash

set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
child=""
stopping=0

stop_child() {
  stopping=1
  if [[ -n "$child" ]] && kill -0 "$child" 2>/dev/null; then
    kill -TERM "$child" 2>/dev/null || true
    wait "$child" 2>/dev/null || true
  fi
}

trap stop_child TERM INT EXIT

while [[ "$stopping" -eq 0 ]]; do
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting ZCC Log Explorer"
  # Analyzer stdout/stderr may contain extracted member names when a parser
  # fails. Do not persist that stream. The supervisor log records only neutral
  # lifecycle status and exit codes.
  "$ROOT/start.sh" >/dev/null 2>&1 &
  child=$!
  wait "$child"
  status=$?
  child=""
  if [[ "$stopping" -eq 0 ]]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Server exited with status $status; restarting in 3 seconds"
    sleep 3
  fi
done
