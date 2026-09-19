
"""Temporary manual backend runner. Starts a private localhost API unless --base-url is supplied."""
import argparse
import copy
import json
import math
import os
from pathlib import Path
import secrets
import socket
import shutil
import threading
import sys
import tempfile
import time
from datetime import datetime

import httpx

ROOT = Path(__file__).resolve().parents[1]
TERMINAL = {"completed", "stopped", "failed", "interrupted"}


class LocalBackend:
    """Own the server directly, without a Windows venv launcher subprocess."""

    def __init__(self, token, directory, port, log_path):
        import uvicorn
        from uvicorn.config import LOGGING_CONFIG
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from api.routes import create_app
        from config.settings import APISettings
        logging_config = copy.deepcopy(LOGGING_CONFIG)
        for name in ("default", "access"):
            logging_config["handlers"][name] = {
                "class": "logging.FileHandler", "formatter": name,
                "filename": str(log_path), "encoding": "utf-8",
            }
        app = create_app(APISettings(api_key=token, data_dir=directory))
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port,
            log_config=logging_config, timeout_graceful_shutdown=5))
        self.error = None
        self.thread = threading.Thread(target=self._run, name="manual-backend", daemon=True)

    def _run(self):
        try:
            self.server.run()
        except BaseException as error:
            self.error = error

    def start(self):
        self.thread.start()

    def is_alive(self):
        return self.thread.is_alive()

    def close(self):
        # Uvicorn runs ASGI lifespan shutdown, including JobService.shutdown / lock release.
        self.server.should_exit = True
        if self.thread.ident is not None:
            self.thread.join(timeout=30)
        service = getattr(self.server.config.app.state, "service", None)
        lock_released = service is None or service.store._lock_file.closed
        return not self.thread.is_alive() and lock_released


def cleanup_workspace(directory, parent, attempts=5):
    """Delete only our generated temp directory; a lingering lock must not mask results."""
    directory, parent = Path(directory), Path(parent).resolve()
    if (directory.is_symlink() or directory.resolve().parent != parent
            or not directory.name.startswith("vpn-backend-manual-")):
        print(f"Temporary workspace left untouched: {directory}", file=sys.stderr)
        return False
    for attempt in range(attempts):
        try:
            shutil.rmtree(directory)
            return True
        except FileNotFoundError:
            return True
        except OSError:
            if attempt + 1 < attempts:
                time.sleep(0.2)
    print(f"Temporary workspace is still locked; left at {directory}. "
          "Saved reports are unaffected.", file=sys.stderr)
    return False


def duration(value):
    result = float(value)
    if not math.isfinite(result) or not 0 < result <= 3600:
        raise argparse.ArgumentTypeError("duration must be greater than zero and at most 3600 seconds")
    return result


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--list-interfaces", action="store_true")
    mode.add_argument("--interface", help="Exact capture interface name, for example Wi-Fi")
    mode.add_argument("--pcap", type=Path, help="Upload a saved PCAP/PCAPNG through the HTTP API")
    parser.add_argument("--duration", type=duration, default=60)
    parser.add_argument("--packet-limit", type=int)
    parser.add_argument("--explain", action="store_true", help="Explicitly request optional Gemini explanation after completion")
    parser.add_argument("--base-url", help="Use an already-running backend; reads VPN_ANALYZER_API_KEY")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "data/reports/manual")
    args = parser.parse_args(argv)
    if args.packet_limit is not None and not 0 < args.packet_limit <= 1_000_000:
        parser.error("--packet-limit must be between 1 and 1000000")
    if args.pcap and not args.pcap.is_file():
        parser.error("PCAP file does not exist")
    return args


def request(client, method, path, **kwargs):
    response = client.request(method, path, **kwargs)
    if response.is_error:
        try:
            detail = response.json().get("detail", response.reason_phrase)
        except ValueError:
            detail = response.reason_phrase
        raise RuntimeError(f"{method} {path}: HTTP {response.status_code}: {detail}")
    return response.json()


def print_status(job):
    summary = job.get("summary") or {}
    score = summary.get("security_score")
    print(f"[{job['state']}] score={score if score is not None else 'UNKNOWN'} "
          f"risk={summary.get('risk_level', 'UNKNOWN')} "
          f"coverage={summary.get('assessment_coverage', 0)}% revision={job['revision']}", flush=True)


def save_results(client, job, destination, explain=False):
    job_id = job["id"]
    report = request(client, "GET", f"/api/v1/jobs/{job_id}/report")
    ai_input = request(client, "GET", f"/api/v1/jobs/{job_id}/ai-input")
    for filename, payload in (("job.json", job), ("report.json", report), ("ai-input.json", ai_input)):
        (destination / filename).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if explain:
        explanation = request(client, "POST", f"/api/v1/jobs/{job_id}/explain", timeout=30)
        (destination / "ai-explanation.json").write_text(json.dumps(explanation, indent=2), encoding="utf-8")
        print(f"AI explanation: {explanation['status']}")
    summary, traffic = report["summary"], report["traffic"]
    print(f"Packets: {traffic['packets_processed']} | SAs: {len(report['sessions'])} | "
          f"Queue drops: {traffic.get('queue_drops', 0)}")
    if summary["security_score"] is None:
        print("Score unavailable: " + ", ".join(summary["score_reasons"]))
        for session in report["sessions"][:5]:
            print("  SA: " + ", ".join(session.get("score_reasons", [])))
    if traffic["security_packets"] == 0:
        print("No IPsec evidence captured. Confirm the interface and use an IPsec VPN; start capture before reconnecting it.")
    print("Findings (first 12 failures/suspicions):")
    notable = [f for f in report["findings"] if f["status"] in ("FAIL", "SUSPECTED")]
    for finding in notable[:12]:
        print(f"  {finding['status']} | {finding['scope']} | {finding['rule_id']} | {finding['message']}")
    if not notable:
        print("  None observed. Check coverage and UNKNOWN controls before interpreting this.")
    if job.get("error"):
        print("Job error: " + job["error"])
    print(f"Saved report and AI input: {destination}")


def main(argv=None):
    args = arguments(argv)
    destination = args.output_dir.resolve() / (datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3))
    destination.mkdir(parents=True)
    backend = client = None
    temporary = None
    temporary_parent = Path(tempfile.gettempdir()).resolve()
    job_id = None
    finished = False
    try:
        if args.base_url:
            base_url = args.base_url.rstrip("/")
            token = os.environ.get("VPN_ANALYZER_API_KEY", "")
            if not token:
                raise RuntimeError("Set VPN_ANALYZER_API_KEY to use an existing backend.")
        else:
            token = secrets.token_urlsafe(32)
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            base_url = f"http://127.0.0.1:{port}"
            temporary = Path(tempfile.mkdtemp(prefix="vpn-backend-manual-", dir=temporary_parent))
            backend = LocalBackend(token, temporary, port, destination / "backend.log")
            backend.start()
        client = httpx.Client(base_url=base_url, headers={"X-API-Key": token}, timeout=10,
                              trust_env=False)
        deadline = time.monotonic()+20
        while True:
            if backend and not backend.is_alive():
                raise RuntimeError(f"Backend exited. See {destination / 'backend.log'}")
            try:
                response = client.get("/api/v1/policy")
                if response.status_code == 401:
                    raise RuntimeError("Backend rejected the API key.")
                response.raise_for_status()
                break
            except (httpx.ConnectError, httpx.TimeoutException):
                if time.monotonic() >= deadline:
                    raise RuntimeError("Backend did not become ready within 20 seconds.") from None
                time.sleep(0.2)
        print(f"Backend: {base_url}")
        if args.list_interfaces:
            for interface in request(client, "GET", "/api/v1/interfaces")["items"]:
                print(f"{interface['index']}: {interface['name']}")
            return 0
        if args.pcap:
            if args.pcap.stat().st_size > 50*1024*1024:
                raise RuntimeError("PCAP exceeds the 50 MiB API limit.")
            with args.pcap.open("rb") as capture:
                job = request(client, "POST", "/api/v1/analyses/pcap", content=capture,
                              headers={"Content-Type": "application/octet-stream"}, timeout=65)
        else:
            job = request(client, "POST", "/api/v1/captures", json={
                "interface": args.interface, "duration_seconds": args.duration,
                "packet_limit": args.packet_limit, "update_interval_seconds": 1})
        job_id = job["id"]
        print(f"Job: {job_id}. Ctrl+C requests stop and saves the partial report.")
        previous = None
        deadline = time.monotonic()+(args.duration+30 if args.interface else 330)
        with (destination / "updates.jsonl").open("w", encoding="utf-8") as updates:
            try:
                while True:
                    job = request(client, "GET", f"/api/v1/jobs/{job_id}")
                    if job["revision"] != previous:
                        print_status(job)
                        updates.write(json.dumps(job)+"\n")
                        updates.flush()
                        previous = job["revision"]
                    if job["state"] in TERMINAL:
                        finished = True
                        break
                    if time.monotonic() > deadline:
                        raise RuntimeError("Analysis did not finish within the expected time.")
                    time.sleep(0.5)
            except KeyboardInterrupt:
                print("\nRequesting capture stop...")
                request(client, "POST", f"/api/v1/jobs/{job_id}/stop")
                deadline = time.monotonic()+15
                while time.monotonic() < deadline:
                    job = request(client, "GET", f"/api/v1/jobs/{job_id}")
                    if job["state"] in TERMINAL:
                        finished = True
                        break
                    time.sleep(0.25)
                if not finished:
                    raise RuntimeError("Stop is still pending; inspect job status on the backend.")
        save_results(client, job, destination, args.explain)
        return 1 if job["state"] in ("failed", "interrupted") else 0
    except (RuntimeError, httpx.HTTPError, OSError) as error:
        print(f"Runner failed: {error}", file=sys.stderr)
        return 1
    finally:
        if client and job_id and not finished:
            try:
                request(client, "POST", f"/api/v1/jobs/{job_id}/stop")
                deadline = time.monotonic()+10
                while time.monotonic() < deadline:
                    if request(client, "GET", f"/api/v1/jobs/{job_id}")["state"] in TERMINAL:
                        break
                    time.sleep(0.25)
            except Exception:
                pass
        if client:
            client.close()
        backend_stopped = backend.close() if backend else True
        if temporary:
            if backend_stopped:
                cleanup_workspace(temporary, temporary_parent)
            else:
                print(f"Backend shutdown is still pending; temporary workspace retained at {temporary}. "
                      "Saved reports are unaffected.", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
