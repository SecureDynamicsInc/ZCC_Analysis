#!/usr/bin/env bash
# Copyright 2026 SecureDynamics, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ROOT="${ZCC_SOURCE_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

usage() {
  cat <<'EOF'
Usage: ./scripts/update_install.sh

Replaces a clean official ZCC Log Explorer checkout with a validated fresh
clone of origin/main, reinstalls the local service, and retains the prior clean
checkout at a named recovery path.
EOF
}

for argument in "$@"; do
  case "$argument" in
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

if [[ ! -d "$ROOT/.git" ]]; then
  echo "Update stopped: $ROOT is not a Git checkout." >&2
  exit 2
fi

python_for() {
  if [[ -x "$1/.venv/bin/python" ]]; then
    printf '%s\n' "$1/.venv/bin/python"
  else
    command -v python3
  fi
}

validate_checkout() {
  local checkout="$1"
  local python_bin="$2"
  (
    cd "$checkout"
    "$python_bin" scripts/check_public_tree.py
    "$python_bin" scripts/check_privacy_architecture.py
    "$python_bin" -m pytest -q -p no:cacheprovider
  )
}

ensure_clean_checkout() {
  local checkout="$1"
  local status ignored_path
  status="$(git -C "$checkout" status --porcelain --untracked-files=all)"
  if [[ -n "$status" ]]; then
    echo "Update stopped: the checkout has tracked or untracked local changes:" >&2
    printf '%s\n' "$status" >&2
    echo "Review them manually. The updater will not preserve or overwrite local work." >&2
    exit 2
  fi

  while IFS= read -r -d '' ignored_path; do
    case "$ignored_path" in
      .DS_Store|*/.DS_Store|.venv/*|.pytest_cache/*|.ruff_cache/*|\
      __pycache__/*|*/__pycache__/*|\
      .run/active_port|.run/server.pid|.run/server.log) ;;
      *)
        echo "Update stopped: review unexplained ignored path: $ignored_path" >&2
        exit 2
        ;;
    esac
  done < <(git -C "$checkout" ls-files --others --ignored --exclude-standard -z)
}

ensure_clean_checkout "$ROOT"

PYTHON_BIN="$(python_for "$ROOT")"
(
  cd "$ROOT"
  "$PYTHON_BIN" scripts/check_public_tree.py
  "$PYTHON_BIN" scripts/check_privacy_architecture.py
)

git -C "$ROOT" fetch origin main
LOCAL_HEAD="$(git -C "$ROOT" rev-parse HEAD)"
REMOTE_HEAD="$(git -C "$ROOT" rev-parse origin/main)"

if [[ "$LOCAL_HEAD" == "$REMOTE_HEAD" ]]; then
  validate_checkout "$ROOT" "$PYTHON_BIN"
  "$ROOT/server.sh" install
  exit 0
fi

if [[ -z "${ZCC_UPDATE_CONFIRMED:-}" ]]; then
  echo
  echo "WARNING: this updater does not merge."
  echo "It will replace this official checkout with a fresh origin/main clone:"
  echo "  $ROOT"
  echo "If you customized this checkout, cancel now and preserve that work in a"
  echo "separate fork or checkout path before updating. The prior clean checkout"
  echo "will be retained at a recovery path, but recovery is not a substitute for"
  echo "intentionally preserving custom work."
  echo
  if ! read -r -p "Type REPLACE to continue: " confirmation; then
    echo "Update cancelled because confirmation was not received."
    exit 5
  fi
  if [[ "$confirmation" != "REPLACE" ]]; then
    echo "Update cancelled. No checkout was replaced."
    exit 5
  fi
fi

# Continue from a temporary copy because replacement moves the checkout that
# originally contained this script. The helper contains no diagnostic data.
if [[ -z "${ZCC_UPDATE_HELPER:-}" ]]; then
  HELPER="$(mktemp "${TMPDIR:-/tmp}/zcc-update-helper.XXXXXX")"
  cp "$0" "$HELPER"
  chmod 700 "$HELPER"
  exec env ZCC_SOURCE_ROOT="$ROOT" ZCC_UPDATE_HELPER=1 ZCC_UPDATE_CONFIRMED=1 \
    ZCC_UPDATE_HELPER_PATH="$HELPER" bash "$HELPER" "$@"
fi
trap 'rm -f "${ZCC_UPDATE_HELPER_PATH:-}"' EXIT

ORIGIN_URL="$(git -C "$ROOT" remote get-url origin)"
PARENT="$(dirname "$ROOT")"
NAME="$(basename "$ROOT")"
FRESH="$(mktemp -d "$PARENT/.${NAME}.fresh.XXXXXX")"
BACKUP="$PARENT/.${NAME}.obsolete.${LOCAL_HEAD:0:8}.$(date +%Y%m%d%H%M%S).$$"

git clone --branch main --single-branch "$ORIGIN_URL" "$FRESH"
git -C "$FRESH" rev-parse HEAD | grep -qx "$REMOTE_HEAD"

# Scan the fresh tracked source before installing anything it declares. Then
# build and validate an independent environment before changing the active
# checkout. The prior environment remains recoverable with the backup.
(
  cd "$FRESH"
  python3 scripts/check_public_tree.py
  python3 scripts/check_privacy_architecture.py
)
python3 -m venv "$FRESH/.venv"
FRESH_PYTHON="$FRESH/.venv/bin/python"
"$FRESH_PYTHON" -m pip install -r "$FRESH/requirements-dev.txt"
validate_checkout "$FRESH" "$FRESH_PYTHON"

# Dependency installation and tests can take time. Recheck the active checkout
# immediately before replacement so work created during validation is not lost.
ensure_clean_checkout "$ROOT"
mv "$ROOT" "$BACKUP"
if ! mv "$FRESH" "$ROOT"; then
  mv "$BACKUP" "$ROOT"
  echo "Replacement failed before installation; the prior checkout was restored." >&2
  exit 1
fi

if ! "$ROOT/server.sh" install; then
  echo "Installation failed; restoring the prior checkout." >&2
  FAILED="$PARENT/.${NAME}.failed-new.$(date +%Y%m%d%H%M%S)"
  mv "$ROOT" "$FAILED"
  mv "$BACKUP" "$ROOT"
  "$ROOT/server.sh" install || true
  echo "The validated new checkout remains at $FAILED for maintainer review." >&2
  exit 1
fi

echo "Replaced the clean official checkout with validated GitHub main $REMOTE_HEAD."
echo "The prior clean checkout is retained for recovery at: $BACKUP"
