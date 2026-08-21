# Copyright 2026 SecureDynamics, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Process-local, single-run custody for uploaded diagnostic data.

This module is the only place the web UI may create a diagnostic workspace.
There is exactly one active run per process.  A new browser session, a new
upload, an explicit reset, or process exit destroys the previous workspace.
Nothing here rehydrates a run after refresh and nothing writes under the
repository or the user's home directory.
"""

from __future__ import annotations

import atexit
import shutil
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


Cleanup = Callable[[], None]
WORKSPACE_PREFIX = "zcc-diag-ephemeral-"


@dataclass
class TransientRun:
    """One diagnostic run and every customer-derived object it owns."""

    session_token: str
    upload_digest: str
    root: Path
    memo: dict[str, Any] = field(default_factory=dict)
    _cleanups: list[Cleanup] = field(default_factory=list, repr=False)
    _owned_handle_ids: set[int] = field(default_factory=set, repr=False)
    closed: bool = False

    @property
    def upload_path(self) -> Path:
        """Neutral path for the current input; customer filenames stay in RAM."""
        return self.root / "input.zip"

    def add_cleanup(self, cleanup: Cleanup) -> None:
        if self.closed:
            raise RuntimeError("Cannot register data on a closed diagnostic run.")
        self._cleanups.append(cleanup)

    def own_upload_handles(self, handles: list[Any]) -> None:
        """Close framework upload buffers when this run is invalidated."""
        for handle in handles:
            if id(handle) in self._owned_handle_ids:
                continue
            close = getattr(handle, "close", None)
            if callable(close):
                self._owned_handle_ids.add(id(handle))
                self.add_cleanup(close)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.memo.clear()
        for cleanup in reversed(self._cleanups):
            try:
                cleanup()
            except Exception:  # cleanup is fail-closed and best effort
                pass
        self._cleanups.clear()
        self._owned_handle_ids.clear()
        shutil.rmtree(self.root, ignore_errors=True)


class SingleRunManager:
    """Own the only diagnostic run allowed in this Python process."""

    def __init__(self, *, temp_parent: Path | None = None) -> None:
        self._lock = threading.RLock()
        self._active_session: str | None = None
        self._run: TransientRun | None = None
        self._temp_parent = temp_parent
        self._purge_orphaned_workspaces()

    def _purge_orphaned_workspaces(self) -> None:
        """Remove crash residue before accepting another diagnostic run.

        ``atexit`` cannot run after SIGKILL, an OOM kill, or power loss. A new
        analyzer process is therefore the recovery boundary: it removes every
        prior manager-owned workspace before creating its own. This is
        intentionally privacy-first. Starting a second analyzer process may
        invalidate the first process's run rather than allow two customer
        workspaces to coexist.
        """
        parent = Path(self._temp_parent or tempfile.gettempdir())
        try:
            candidates = list(parent.glob(f"{WORKSPACE_PREFIX}*"))
        except OSError:
            return
        for candidate in candidates:
            try:
                if candidate.is_symlink() or not candidate.is_dir():
                    continue
                shutil.rmtree(candidate, ignore_errors=True)
            except OSError:
                pass

    def activate_session(self, session_token: str) -> None:
        """A new browser session invalidates all data from the prior session."""
        with self._lock:
            if self._active_session != session_token:
                self._purge_locked()
                self._active_session = session_token

    def begin(self, session_token: str, upload_digest: str) -> TransientRun:
        """Return this run or atomically replace and purge the prior upload."""
        with self._lock:
            self.activate_session(session_token)
            if self._run and self._run.upload_digest == upload_digest:
                return self._run
            self._purge_locked()
            root = Path(tempfile.mkdtemp(
                prefix=WORKSPACE_PREFIX,
                dir=str(self._temp_parent) if self._temp_parent else None,
            ))
            root.chmod(0o700)
            self._run = TransientRun(session_token, upload_digest, root)
            return self._run

    def purge(self, session_token: str | None = None) -> None:
        """Destroy the active run; optionally refuse a stale session's request."""
        with self._lock:
            if session_token is None or session_token == self._active_session:
                self._purge_locked()

    def _purge_locked(self) -> None:
        if self._run is not None:
            self._run.close()
            self._run = None

    @property
    def active_run(self) -> TransientRun | None:
        with self._lock:
            return self._run


RUN_MANAGER = SingleRunManager()
atexit.register(RUN_MANAGER.purge)


def clear_customer_session_state(
    session_state: Any, *, preserve_current_upload: bool = True,
) -> None:
    """Remove all non-presentation Streamlit state before a replacement run.

    Theme and experience preferences are not derived from customer data.  Every
    other key is treated as sensitive by default so newly added UI features do
    not need to remember to opt in to cleanup.
    """

    keep = {
        "_privacy_session_token",
        "_upload_widget_generation",
        "experience_level",
        "service_scope",
        "light_mode",
    }
    for key in list(session_state.keys()):
        is_upload = str(key).startswith("diagnostic_upload_")
        if key not in keep and not (preserve_current_upload and is_upload):
            try:
                del session_state[key]
            except Exception:
                pass
