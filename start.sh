#!/usr/bin/env bash
# Copyright 2026 SecureDynamics, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")"

# Cloned contributors get the privacy and protected-main hooks before the app
# ever handles a diagnostic. Source archives without Git metadata simply skip.
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  ./scripts/install_dev_guardrails.sh >/dev/null
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"
if [[ ! -x .venv/bin/python ]]; then
  "$PYTHON_BIN" -m venv .venv
fi

if ! .venv/bin/python -c "import streamlit, maxminddb" >/dev/null 2>&1; then
  .venv/bin/python -m pip install -r requirements.txt
fi

exec .venv/bin/python run_local.py
