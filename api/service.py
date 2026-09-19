"""Bounded capture jobs. Capture/engine state is owned by one worker per job."""
import asyncio
import logging
import threading
import time
import uuid
from datetime import datetime, timezone

from ai.ai_explainer import GeminiExplainer
from core.engine import SecurityEngine
from reports.quality import apply_report_quality
from sources.live_source import LiveSource
from sources.pcap_source import PCAPSource
from api.storage import JobStore

LOGGER = logging.getLogger(__name__)
TERMINAL = {"completed", "stopped", "failed", "interrupted"}


def utcnow():
    return datetime.now(timezone.utc).isoformat()


class JobConflict(Exception):
    pass


class JobCapacity(Exception):
    pass


class JobService:
    def __init__(self, settings, live_factory=LiveSource, pcap_factory=PCAPSource,
                 explainer_factory=GeminiExplainer):
        self.settings = settings
        self.store = JobStore(settings.data_dir)
        self.live_factory, self.pcap_factory = live_factory, pcap_factory
        self.explainer_factory = explainer_factory
        self._lock = threading.RLock()
        self._workers = {}
        self._explaining = set()
        self._closing = False
        self.upload_dir = self.store.directory / "uploads"
        self.upload_dir.mkdir(exist_ok=True)
        # A process restart cannot silently resume an old live capture.
        for job_id in self.store.list_ids(limit=self.store.count()):
            row = self.store.get(job_id)
            if row["state"] not in TERMINAL:
                report = row["report"] or SecurityEngine().snapshot(row["source_type"])
                report["metadata"].update(incomplete=True, interruption_reason="backend_restarted")
                report["traffic"]["capture_status"] = "interrupted"
                apply_report_quality(report)
                self.store.update(job_id, state="interrupted", report=report,
                    error="Backend restarted before analysis finished.", updated_at=utcnow(), finished_at=utcnow())
        # Only server-generated UUID upload names in this dedicated directory.
        for path in self.upload_dir.glob("*.pcap"):
            try:
                uuid.UUID(path.stem)
            except ValueError:
                continue
            if path.is_file() and not path.is_symlink():
                path.unlink()

    def _admit(self, source_type):
        if self._closing:
            raise JobConflict("Backend is shutting down.")
        if self.store.count() >= self.settings.max_jobs:
            raise JobCapacity("Saved-job limit reached. Delete a finished job before creating another.")
        if len(self._workers) >= self.settings.max_active_jobs:
            raise JobCapacity("Concurrent analysis limit reached.")
        if source_type == "live" and any(c["source_type"] == "live" for c in self._workers.values()):
            raise JobConflict("A live capture is already active. Stop it first.")

    def create_live(self, parameters):
        return self._create("live", parameters)

    def create_pcap(self, path, size):
        return self._create("pcap", {"input_bytes": size, "update_interval_seconds": 2}, path)

    def _create(self, source_type, parameters, input_path=None):
        with self._lock:
            self._admit(source_type)
            job_id, now = str(uuid.uuid4()), utcnow()
            self.store.insert({"id": job_id, "state": "queued", "source_type": source_type,
                               "created_at": now, "updated_at": now, "parameters": parameters})
            context = {"source_type": source_type, "stop": threading.Event(), "source": None}
            worker = threading.Thread(target=self._run, args=(job_id, context, parameters, input_path),
                                      name=f"analysis-{job_id[:8]}", daemon=True)
            context["thread"] = worker
            self._workers[job_id] = context
            try:
                worker.start()
            except Exception:
                self._workers.pop(job_id)
                self.store.update(job_id, state="failed", error="Could not start analysis worker.",
                                  updated_at=utcnow(), finished_at=utcnow())
                raise
            return self.status(job_id)

    def _publish(self, job_id, report, source, state=None, error=None):
        with self._lock:
            row = self.store.get(job_id)
            report["traffic"].update(
                queue_drops=getattr(source, "queue_drops", 0),
                capture_status=getattr(source, "status", state or row["state"]))
            report["metadata"].update(job_id=job_id, report_revision=row["revision"]+1)
            if error:
                report["metadata"].update(incomplete=True, error=error)
            apply_report_quality(report)
            fields = {"report": report, "updated_at": utcnow()}
            if state:
                fields["state"] = state
            if state in TERMINAL:
                fields.update(finished_at=utcnow(), error=error)
            self.store.update(job_id, **fields)

    def _run(self, job_id, context, parameters, input_path):
        # PyShark FileCapture expects a loop in its owning thread.
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        engine, source, error = SecurityEngine(), None, None
        state = "completed"
        try:
            source = (self.live_factory(interface=parameters["interface"],
                        timeout=parameters["duration_seconds"], packet_count=parameters["packet_limit"])
                      if context["source_type"] == "live" else self.pcap_factory(str(input_path)))
            with self._lock:
                context["source"] = source
                if context["stop"].is_set() and hasattr(source, "request_stop"):
                    source.request_stop()
                self.store.update(job_id, state="stopping" if context["stop"].is_set() else "running",
                                  updated_at=utcnow())
            last_update, started = 0, time.monotonic()
            for packet in source.read():
                if context["source_type"] == "pcap" and context["stop"].is_set():
                    break
                if context["source_type"] == "pcap" and time.monotonic()-started > 300:
                    raise TimeoutError("Offline processing duration exceeded")
                if packet is not None:
                    engine.ingest(packet)
                now = time.monotonic()
                if now-last_update >= parameters["update_interval_seconds"]:
                    self._publish(job_id, engine.snapshot(context["source_type"]), source)
                    last_update = now
            if context["stop"].is_set():
                state = "stopped"
        except Exception:
            LOGGER.exception("Analysis job %s failed", job_id)
            state, error = "failed", "Capture or analysis failed. Check server logs, TShark/Npcap and interface permissions."
        finally:
            try:
                if source:
                    source.close()
            except Exception:
                LOGGER.exception("Source cleanup failed for job %s", job_id)
                state, error = "failed", "Capture cleanup failed. Check server logs."
            try:
                report = engine.snapshot(context["source_type"])
                if state == "stopped":
                    report["metadata"]["stopped_by_user"] = True
                    if context["source_type"] == "pcap":
                        report["metadata"]["incomplete"] = True
                self._publish(job_id, report, source, state, error)
            except Exception:
                LOGGER.exception("Could not persist final report for %s", job_id)
                try:
                    self.store.update(job_id, state="failed", error="Could not persist the final report.",
                                      updated_at=utcnow(), finished_at=utcnow())
                except Exception:
                    LOGGER.exception("Job storage unavailable")
            finally:
                try:
                    if input_path:
                        input_path.unlink(missing_ok=True)
                except OSError:
                    LOGGER.exception("Could not remove temporary upload for %s", job_id)
                finally:
                    loop.close()
                    with self._lock:
                        self._workers.pop(job_id, None)

    def snapshot(self, job_id):
        row = self.store.get(job_id)
        if row["report"] and row["state"] in {"failed", "interrupted"}:
            row["report"]["metadata"]["incomplete"] = True
            apply_report_quality(row["report"])
        return row

    def status(self, job_id):
        row = self.snapshot(job_id)
        base = f"/api/v1/jobs/{job_id}"
        return {key: row[key] for key in (
            "id", "source_type", "state", "revision", "created_at", "updated_at", "finished_at",
            "parameters", "error")} | {
                "summary": row["report"]["summary"] if row["report"] else None,
                "links": {"self": base, "report": base+"/report", "events": base+"/events",
                          "ai_input": base+"/ai-input", "explain": base+"/explain", "stop": base+"/stop"}}

    def list(self, limit, offset):
        with self._lock:
            return {"items": [self.status(i) for i in self.store.list_ids(limit, offset)],
                    "total": self.store.count(), "limit": limit, "offset": offset}

    def report(self, job_id):
        row = self.snapshot(job_id)
        if row["report"] is None:
            raise JobConflict("The first report is not available yet.")
        report = row["report"]
        if row["explanation"] is not None:
            report["ai_explanation"] = row["explanation"]
        return report

    def stop(self, job_id):
        with self._lock:
            row = self.store.get(job_id)
            if row["state"] not in TERMINAL:
                context = self._workers.get(job_id)
                if context:
                    context["stop"].set()
                    if context["source"] and hasattr(context["source"], "request_stop"):
                        context["source"].request_stop()
                self.store.update(job_id, state="stopping", updated_at=utcnow())
            return self.status(job_id)

    def delete(self, job_id):
        with self._lock:
            row = self.store.get(job_id)
            if row["state"] not in TERMINAL or job_id in self._workers or job_id in self._explaining:
                raise JobConflict("Wait until capture and explanation have finished before deleting.")
            self.store.delete(job_id)

    def explain(self, job_id):
        with self._lock:
            row = self.store.get(job_id)
            if row["state"] not in TERMINAL:
                raise JobConflict("Stop or finish capture before requesting an explanation.")
            if job_id in self._explaining:
                raise JobConflict("An explanation request is already running.")
            if row["explanation"] and row["explanation"].get("status") == "available":
                return row["explanation"]
            report = self.report(job_id)
            self._explaining.add(job_id)
        try:
            result = self.explainer_factory().analyze(report)
            with self._lock:
                self.store.update(job_id, explanation=result, updated_at=utcnow())
            return result
        finally:
            with self._lock:
                self._explaining.discard(job_id)

    def shutdown(self):
        with self._lock:
            self._closing = True
            for job_id in list(self._workers):
                self.stop(job_id)
            threads = [c["thread"] for c in self._workers.values()]
        for thread in threads:
            thread.join(timeout=10)
        if any(t.is_alive() for t in threads):
            raise RuntimeError("An analysis worker did not stop; data-directory ownership is retained.")
        self.store.close()
