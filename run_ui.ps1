# Copyright 2026 SecureDynamics, Inc.
# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# Enable repository-local privacy and protected-main hooks for Git clones.
git rev-parse --is-inside-work-tree 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) {
    git config core.hooksPath .githooks
}

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    py -3 -m venv .venv
}

$Python = ".venv\Scripts\python.exe"
& $Python -c "import streamlit" 2>$null
if ($LASTEXITCODE -ne 0) {
    & $Python -m pip install -r requirements.txt
}

& $Python run_local.py
