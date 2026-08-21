from pathlib import Path

from zcc_diag.transient_runtime import (
    SingleRunManager,
    clear_customer_session_state,
)


def test_new_upload_destroys_previous_workspace(tmp_path: Path):
    manager = SingleRunManager(temp_parent=tmp_path)
    first = manager.begin("session-a", "upload-a")
    first.upload_path.write_bytes(b"customer evidence")

    second = manager.begin("session-a", "upload-b")

    assert first.closed
    assert not first.root.exists()
    assert second.root.exists()
    assert second.upload_digest == "upload-b"
    manager.purge()


def test_new_browser_session_destroys_previous_run(tmp_path: Path):
    manager = SingleRunManager(temp_parent=tmp_path)
    first = manager.begin("session-a", "upload-a")
    marker = first.root / "derived.sqlite"
    marker.write_bytes(b"derived data")

    manager.activate_session("session-b")

    assert first.closed
    assert not marker.exists()
    assert manager.active_run is None


def test_same_upload_reuses_only_current_session_workspace(tmp_path: Path):
    manager = SingleRunManager(temp_parent=tmp_path)
    first = manager.begin("session-a", "upload-a")
    again = manager.begin("session-a", "upload-a")
    assert again is first
    manager.purge()


def test_cleanup_callbacks_run_before_workspace_is_removed(tmp_path: Path):
    manager = SingleRunManager(temp_parent=tmp_path)
    run = manager.begin("session-a", "upload-a")
    observed = []
    run.add_cleanup(lambda: observed.append(run.root.exists()))
    manager.purge("session-a")
    assert observed == [True]
    assert not run.root.exists()


def test_invalidating_run_closes_framework_upload_buffers(tmp_path: Path):
    manager = SingleRunManager(temp_parent=tmp_path)
    run = manager.begin("session-a", "upload-a")

    class UploadBuffer:
        closed = False

        def close(self):
            self.closed = True

    upload = UploadBuffer()
    run.own_upload_handles([upload])
    manager.activate_session("session-b")
    assert upload.closed


def test_customer_session_state_is_deny_by_default():
    state = {
        "_privacy_session_token": "safe",
        "_upload_widget_generation": 2,
        "diagnostic_upload_2": object(),
        "light_mode": True,
        "pcap_stream_result": "customer-derived",
        "new_feature_nobody_remembered": "customer-derived",
    }
    clear_customer_session_state(state)
    assert set(state) == {
        "_privacy_session_token", "_upload_widget_generation",
        "diagnostic_upload_2", "light_mode",
    }


def test_explicit_reset_removes_upload_widget_buffer():
    state = {
        "_privacy_session_token": "safe",
        "_upload_widget_generation": 3,
        "diagnostic_upload_2": object(),
    }
    clear_customer_session_state(state, preserve_current_upload=False)
    assert set(state) == {"_privacy_session_token", "_upload_widget_generation"}


def test_startup_sweep_removes_only_prior_manager_workspaces(tmp_path: Path):
    orphan = tmp_path / "zcc-diag-ephemeral-crash-residue"
    orphan.mkdir()
    (orphan / "input.zip").write_bytes(b"synthetic crash residue")
    unrelated = tmp_path / "unrelated-temporary-directory"
    unrelated.mkdir()
    (unrelated / "keep.txt").write_text("not analyzer-owned")

    manager = SingleRunManager(temp_parent=tmp_path)

    assert not orphan.exists()
    assert unrelated.exists()
    assert (unrelated / "keep.txt").read_text() == "not analyzer-owned"
    manager.purge()


def test_startup_sweep_does_not_follow_matching_symlink(tmp_path: Path):
    target = tmp_path / "outside-workspace"
    target.mkdir()
    marker = target / "keep.txt"
    marker.write_text("do not follow")
    link = tmp_path / "zcc-diag-ephemeral-link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        return

    manager = SingleRunManager(temp_parent=tmp_path)

    assert marker.read_text() == "do not follow"
    assert link.is_symlink()
    manager.purge()
