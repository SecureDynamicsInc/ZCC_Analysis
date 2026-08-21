# Copyright 2026 SecureDynamics, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Launch the desktop analyzer on the loopback interface only."""

from __future__ import annotations

import socket
import os
import sys
from pathlib import Path


HOST = "127.0.0.1"
DEFAULT_PORT = 8501


def _available_port(start: int = DEFAULT_PORT, attempts: int = 20) -> int:
    for port in range(start, start + attempts):
        with socket.socket() as sock:
            try:
                sock.bind((HOST, port))
            except OSError:
                continue
            return port
    raise SystemExit(f"No free local port found between {start} and {start + attempts - 1}.")


def main() -> None:
    if sys.version_info < (3, 10):
        raise SystemExit("ZCC Log Explorer requires Python 3.10 or newer.")
    try:
        from streamlit.web import cli as stcli
    except ImportError as exc:
        raise SystemExit(
            "Streamlit is not installed. Run: python -m pip install -r requirements.txt"
        ) from exc

    app = Path(__file__).with_name("zcc_diag_ui.py")
    requested_port = os.environ.get("ZCC_PORT", "").strip()
    if requested_port:
        try:
            preferred_port = int(requested_port)
        except ValueError as exc:
            raise SystemExit("ZCC_PORT must be a number between 1 and 65535.") from exc
        if not 1 <= preferred_port <= 65535:
            raise SystemExit("ZCC_PORT must be a number between 1 and 65535.")
    else:
        preferred_port = DEFAULT_PORT
    port = _available_port(preferred_port)
    run_dir = app.parent / ".run"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "active_port").write_text(f"{port}\n", encoding="utf-8")
    headless = os.environ.get("ZCC_HEADLESS", "false").lower() in {"1", "true", "yes"}
    print(
        f"\nZCC Log Explorer is starting locally.\n"
        f"Copy this address exactly: http://{HOST}:{port}\n"
        "Important: use HTTP, not HTTPS. This loopback-only app does not serve TLS.\n"
    )
    sys.argv = [
        "streamlit", "run", str(app),
        f"--server.address={HOST}",
        f"--server.port={port}",
        f"--server.headless={'true' if headless else 'false'}",
        "--browser.gatherUsageStats=false",
    ]
    raise SystemExit(stcli.main())


if __name__ == "__main__":
    main()
