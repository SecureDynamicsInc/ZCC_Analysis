#!/usr/bin/env bash
# Copyright 2026 SecureDynamics, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
RUN_DIR="$ROOT/.run"
PID_FILE="$RUN_DIR/server.pid"
LOG_FILE="$RUN_DIR/server.log"
LABEL="com.securedynamics.zcc-log-explorer"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
INSTALL_ROOT="$HOME/Library/Application Support/SecureDynamics/ZCCLogExplorer"

active_port() {
  local candidate=""
  if service_status && [[ -f "$INSTALL_ROOT/.run/active_port" ]]; then
    candidate="$(<"$INSTALL_ROOT/.run/active_port")"
  elif [[ -f "$RUN_DIR/active_port" ]]; then
    candidate="$(<"$RUN_DIR/active_port")"
  fi
  if [[ "$candidate" =~ ^[0-9]+$ ]]; then
    echo "$candidate"
  else
    echo "${ZCC_PORT:-8501}"
  fi
}

http_url() {
  echo "http://127.0.0.1:$(active_port)"
}

running() {
  [[ -f "$PID_FILE" ]] || return 1
  local pid
  pid="$(<"$PID_FILE")"
  [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null
}

start_server() {
  mkdir -p "$RUN_DIR"
  if service_status; then
    echo "ZCC Log Explorer is already managed by macOS."
    echo "Open $(http_url)"
    return
  fi
  if running; then
    echo "ZCC Log Explorer is already running (PID $(<"$PID_FILE"))."
    echo "Open $(http_url)"
    return
  fi
  rm -f "$PID_FILE"
  nohup env ZCC_HEADLESS=true ZCC_PORT="${ZCC_PORT:-8501}" \
    "$ROOT/scripts/supervise.sh" >>"$LOG_FILE" 2>&1 &
  echo $! >"$PID_FILE"
  sleep 1
  if running; then
    echo "ZCC Log Explorer started and will restart automatically if it exits."
    echo "Open $(http_url)"
    echo "Logs: $LOG_FILE"
  else
    echo "The server did not stay running. Review $LOG_FILE"
    exit 1
  fi
}

stop_server() {
  if service_status; then
    echo "ZCC Log Explorer is managed by macOS. Use './server.sh uninstall' to stop and remove the always-on service."
    return
  fi
  if ! running; then
    rm -f "$PID_FILE"
    echo "ZCC Log Explorer is not running."
    return
  fi
  local pid
  pid="$(<"$PID_FILE")"
  kill -TERM "$pid"
  for _ in {1..20}; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.25
  done
  rm -f "$PID_FILE"
  echo "ZCC Log Explorer stopped."
}

restart_server() {
  if service_status; then
    launchctl kickstart -k "gui/$(id -u)/$LABEL"
    echo "Managed ZCC Log Explorer restarted."
  else
    stop_server
    start_server
  fi
}

install_service() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "Always-on installation is currently available on macOS. Use './server.sh start' on Linux."
    exit 2
  fi
  if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
    echo "Run ./start.sh once before installing the always-on service."
    exit 1
  fi
  mkdir -p "$RUN_DIR" "$HOME/Library/LaunchAgents" "$INSTALL_ROOT"
  rsync -a --delete \
    --exclude='.git/' --exclude='.run/' --exclude='.agents/' --exclude='.claude/' \
    --exclude='* 2.py' \
    "$ROOT/" "$INSTALL_ROOT/"
  printf '%s\n' "$ROOT" > "$INSTALL_ROOT/.source_repo_path"
  local main_sha=""
  main_sha="$(git -C "$ROOT" rev-parse --verify refs/remotes/origin/main 2>/dev/null || true)"
  if [[ -z "$main_sha" ]]; then
    main_sha="$(git -C "$ROOT" rev-parse --verify HEAD 2>/dev/null || true)"
  fi
  if [[ -n "$main_sha" ]]; then
    printf '%s\n' "$main_sha" > "$INSTALL_ROOT/.build_main_commit"
  fi
  local draft="$RUN_DIR/$LABEL.plist"
  plutil -create xml1 "$draft"
  plutil -insert Label -string "$LABEL" "$draft"
  plutil -insert ProgramArguments -array "$draft"
  plutil -insert ProgramArguments.0 -string "/bin/bash" "$draft"
  plutil -insert ProgramArguments.1 -string "$INSTALL_ROOT/start.sh" "$draft"
  plutil -insert WorkingDirectory -string "$INSTALL_ROOT" "$draft"
  plutil -insert EnvironmentVariables -dictionary "$draft"
  plutil -insert EnvironmentVariables.ZCC_HEADLESS -string "true" "$draft"
  plutil -insert EnvironmentVariables.ZCC_PORT -string "${ZCC_PORT:-8501}" "$draft"
  plutil -insert RunAtLoad -bool true "$draft"
  plutil -insert KeepAlive -bool true "$draft"
  # Do not retain analyzer stdout/stderr. Parser failures can contain archive
  # member names, which are customer-derived even when raw lines are absent.
  plutil -insert StandardOutPath -string "/dev/null" "$draft"
  plutil -insert StandardErrorPath -string "/dev/null" "$draft"
  cp "$draft" "$PLIST"
  launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
  # launchd can need a brief moment to finish unloading the prior process
  # before the same label is bootstrapped again during an update.
  sleep 1
  local bootstrapped=0
  for _attempt in 1 2 3; do
    if launchctl bootstrap "gui/$(id -u)" "$PLIST"; then
      bootstrapped=1
      break
    fi
    sleep 2
  done
  if [[ "$bootstrapped" -ne 1 ]]; then
    echo "macOS could not load the user service after three attempts. Run './server.sh install' again."
    exit 1
  fi
  launchctl enable "gui/$(id -u)/$LABEL"
  launchctl kickstart -k "gui/$(id -u)/$LABEL"
  echo "Always-on ZCC Log Explorer installed for this Mac user."
  echo "It starts at login and restarts automatically at http://127.0.0.1:${ZCC_PORT:-8501}"
  echo "Analyzer output is not retained. Use './server.sh status' for health."
}

uninstall_service() {
  launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
  rm -f "$PLIST"
  echo "Always-on ZCC Log Explorer removed."
}

service_status() {
  launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1
}

open_http() {
  local url
  url="$(http_url)"
  echo "Opening $url"
  echo "Important: this local app uses HTTP, not HTTPS."
  if [[ "$(uname -s)" == "Darwin" ]]; then
    open "$url"
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url"
  else
    echo "No desktop browser opener was found. Copy the HTTP address above exactly."
  fi
}

case "${1:-status}" in
  start) start_server ;;
  stop) stop_server ;;
  restart) restart_server ;;
  install) install_service ;;
  uninstall) uninstall_service ;;
  status)
    if service_status; then
      echo "ZCC Log Explorer is managed by macOS and will restart automatically."
      echo "Open $(http_url)"
    elif running; then
      echo "ZCC Log Explorer is running (PID $(<"$PID_FILE"))."
      echo "Open $(http_url)"
    else
      echo "ZCC Log Explorer is not running."
      exit 1
    fi
    ;;
  logs)
    mkdir -p "$RUN_DIR"
    if [[ -f "$LOG_FILE" ]]; then
      echo "Supervisor lifecycle only; analyzer output is intentionally not retained."
      tail -n 80 "$LOG_FILE"
    else
      touch "$LOG_FILE"
      echo "No supervisor lifecycle events recorded yet."
    fi
    ;;
  open) open_http ;;
  *)
    echo "Usage: ./server.sh {start|stop|restart|status|logs|open|install|uninstall}"
    exit 2
    ;;
esac
