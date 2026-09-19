import importlib.util
import json
from pathlib import Path

import httpx
import pytest

spec = importlib.util.spec_from_file_location("backend_test_runner", Path("tools/backend_test_runner.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def test_runner_requires_explicit_capture_or_file_mode():
    with pytest.raises(SystemExit):
        runner.arguments([])
    with pytest.raises(SystemExit):
        runner.arguments(["--interface", "Wi-Fi", "--duration", "nan"])
    with pytest.raises(SystemExit):
        runner.arguments(["--interface", "Wi-Fi", "--packet-limit", "0"])


def test_runner_request_reports_api_errors_without_credentials():
    with httpx.Client(base_url="http://test",
        transport=httpx.MockTransport(lambda request: httpx.Response(401, json={"detail": "Invalid key"}))) as client:
        with pytest.raises(RuntimeError, match="HTTP 401: Invalid key"):
            runner.request(client, "GET", "/api/v1/interfaces")


def test_runner_saves_engine_and_ai_artifacts(tmp_path, capsys):
    report = {"summary": {"security_score": None, "score_reasons": ["no_assessable_sessions"]},
              "traffic": {"packets_processed": 0, "security_packets": 0}, "sessions": [], "findings": []}
    ai = {"assessment": {"security_score": None}}
    job = {"id": "test-job", "state": "completed"}
    def transport(request):
        if request.url.path.endswith("/report"):
            return httpx.Response(200, json=report)
        if request.url.path.endswith("/ai-input"):
            return httpx.Response(200, json=ai)
        return httpx.Response(200, json={"status": "unavailable"})
    with httpx.Client(base_url="http://test", transport=httpx.MockTransport(transport)) as client:
        runner.save_results(client, job, tmp_path, explain=True)
    assert json.loads((tmp_path / "report.json").read_text()) == report
    assert json.loads((tmp_path / "ai-input.json").read_text()) == ai
    assert (tmp_path / "ai-explanation.json").exists()
    assert "No IPsec evidence captured" in capsys.readouterr().out

def test_cleanup_retries_transient_windows_lock(tmp_path, monkeypatch):
    folder = tmp_path / "vpn-backend-manual-retry"
    folder.mkdir()
    (folder / "backend.lock").write_text("0")
    remove = runner.shutil.rmtree
    calls = []
    def locked_twice(path):
        calls.append(path)
        if len(calls) < 3:
            raise PermissionError(32, "File is in use")
        remove(path)
    monkeypatch.setattr(runner.shutil, "rmtree", locked_twice)
    monkeypatch.setattr(runner.time, "sleep", lambda _: None)
    assert runner.cleanup_workspace(folder, tmp_path)
    assert len(calls) == 3 and not folder.exists()


def test_cleanup_leaves_permanently_locked_directory_without_traceback(tmp_path, monkeypatch, capsys):
    folder = tmp_path / "vpn-backend-manual-locked"
    folder.mkdir()
    def locked(path):
        raise PermissionError(32, "File is in use")
    monkeypatch.setattr(runner.shutil, "rmtree", locked)
    monkeypatch.setattr(runner.time, "sleep", lambda _: None)
    assert not runner.cleanup_workspace(folder, tmp_path)
    assert folder.exists()
    assert "Saved reports are unaffected" in capsys.readouterr().err


def test_cleanup_refuses_unowned_directory(tmp_path):
    folder = tmp_path / "other-project"
    folder.mkdir()
    assert not runner.cleanup_workspace(folder, tmp_path)
    assert folder.exists()


def test_local_backend_lifespan_releases_windows_lock_before_cleanup(tmp_path, monkeypatch):
    # Real API lifespan/storage and real lock, with no network socket or capture.
    import asyncio
    import threading
    from api.storage import JobStore

    folder = tmp_path / "vpn-backend-manual-lifespan"
    folder.mkdir()
    backend = runner.LocalBackend("test-key-" * 5, folder, 0, tmp_path / "backend.log")
    ready = threading.Event()
    async def serve_without_network():
        app = backend.server.config.app
        async with app.router.lifespan_context(app):
            ready.set()
            while not backend.server.should_exit:
                await asyncio.sleep(0.01)
    monkeypatch.setattr(backend.server, "run", lambda: asyncio.run(serve_without_network()))
    backend.start()
    try:
        assert ready.wait(5)
        assert (folder / "backend.lock").exists()
        assert backend.close()
        assert backend.error is None
        # A second owner can acquire the same lock after graceful shutdown.
        owner = JobStore(folder)
        owner.close()
        assert runner.cleanup_workspace(folder, tmp_path)
        assert not folder.exists()
    finally:
        backend.close()


def test_local_backend_failed_shutdown_does_not_authorize_temp_deletion(tmp_path, monkeypatch):
    from api.service import JobService
    from config.settings import APISettings

    folder = tmp_path / "vpn-backend-manual-pending"
    backend = runner.LocalBackend("test-key-" * 5, folder, 0, tmp_path / "backend.log")
    service = JobService(APISettings(api_key="test-key-" * 5, data_dir=folder))
    backend.server.config.app.state.service = service
    # Mimic a dead server thread whose lifespan could not release its data lock.
    monkeypatch.setattr(backend.server, "run", lambda: None)
    backend.start()
    backend.thread.join(timeout=5)
    try:
        assert not backend.close()
        assert folder.exists()
    finally:
        service.shutdown()
        assert runner.cleanup_workspace(folder, tmp_path)
