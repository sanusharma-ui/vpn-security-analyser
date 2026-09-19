"""HTTP interface. All analysis operations require the shared API key."""
import asyncio
import anyio
import hmac
import json
import uuid
from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import APIKeyHeader
from starlette.concurrency import run_in_threadpool

from ai.input_builder import build_ai_input
from api.schemas import AIInputResponse, CaptureRequest, JobList, JobStatus, ReportResponse
from api.service import JobCapacity, JobConflict, JobService, TERMINAL
from config.security_baseline import SECURITY_BASELINE
from config.settings import APISettings
from sources.live_source import LiveSource

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
              b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}


def authorize(request: Request, key: str | None = Depends(api_key_header)):
    expected = request.app.state.settings.api_key
    if key is None or not hmac.compare_digest(key.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="A valid X-API-Key header is required.")


def service(request: Request):
    return request.app.state.service


def create_app(settings=None, service_factory=JobService, interface_provider=None):
    interface_provider = interface_provider or LiveSource.list_interfaces

    @asynccontextmanager
    async def lifespan(application):
        config = settings or APISettings.from_env()
        if len(config.api_key) < 32:
            raise RuntimeError("API key must contain at least 32 characters.")
        application.state.settings = config
        application.state.service = service_factory(config)
        application.state.upload_slots = asyncio.Semaphore(2)
        try:
            yield
        finally:
            await run_in_threadpool(application.state.service.shutdown)

    application = FastAPI(
        title="IPsec VPN Security Analyzer", version="0.5.0",
        description="Passive IPsec analysis. Scores are provisional engine results. One worker per data directory.",
        lifespan=lifespan)
    # Read only non-secret CORS configuration before lifespan.
    if settings:
        origins = settings.allowed_origins
    else:
        import os
        origins = tuple(x.strip() for x in os.environ.get("VPN_ANALYZER_CORS_ORIGINS", "").split(",") if x.strip())
    if "*" in origins:
        raise ValueError("Wildcard CORS is not supported.")
    if origins:
        application.add_middleware(CORSMiddleware, allow_origins=list(origins),
            allow_methods=["GET", "POST", "DELETE"], allow_headers=["X-API-Key", "Content-Type", "Last-Event-ID"])

    @application.exception_handler(KeyError)
    async def missing_job(request, error):
        return JSONResponse(status_code=404, content={"detail": "Job not found."})

    @application.exception_handler(JobConflict)
    async def job_conflict(request, error):
        return JSONResponse(status_code=409, content={"detail": str(error)})

    @application.exception_handler(JobCapacity)
    async def capacity(request, error):
        return JSONResponse(status_code=429, content={"detail": str(error)}, headers={"Retry-After": "5"})

    @application.get("/health", tags=["system"])
    def health():
        return {"status": "ok", "version": "0.5.0"}

    router = APIRouter(prefix="/api/v1", dependencies=[Depends(authorize)])

    @router.get("/interfaces", tags=["capture"])
    def interfaces():
        try:
            return {"items": interface_provider()}
        except Exception:
            raise HTTPException(503, "Interface enumeration failed. Check TShark/Npcap and permissions.") from None

    @router.get("/policy", tags=["assessment"])
    def policy():
        return {"baseline": SECURITY_BASELINE, "risk_weights": {"low": 10, "medium": 30, "high": 60, "critical": 100},
                "aggregation": "Maximum confirmed severity; offered and suspected findings excluded.",
                "security_score": "100 minus risk only with complete unambiguous selected controls for every retained SA and no known evidence loss.",
                "status": "Local policy; not certification", "supported_protocols": ["IKEv1", "IKEv2", "ESP", "AH", "NAT-T"],
                "unsupported": ["WireGuard analysis", "OpenVPN analysis", "payload decryption", "ML detection", "compliance certification"]}

    @router.post("/captures", response_model=JobStatus, status_code=202, tags=["capture"])
    def capture(body: CaptureRequest, manager=Depends(service)):
        try:
            names = {i["name"] for i in interface_provider()}
        except Exception:
            raise HTTPException(503, "Could not verify capture interface. Check capture dependencies.") from None
        if body.interface not in names:
            raise HTTPException(422, "Choose an exact interface name returned by /api/v1/interfaces.")
        return manager.create_live(body.model_dump())

    @router.post("/analyses/pcap", response_model=JobStatus, status_code=202, tags=["capture"],
        openapi_extra={"requestBody": {"required": True, "content": {
            "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}}})
    async def upload_pcap(request: Request, manager=Depends(service)):
        if request.headers.get("content-type", "").split(";")[0].strip() != "application/octet-stream":
            raise HTTPException(415, "Send the PCAP bytes as application/octet-stream.")
        limit = request.app.state.settings.max_upload_bytes
        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                length = int(declared)
            except ValueError:
                raise HTTPException(400, "Invalid Content-Length.") from None
            if length < 0:
                raise HTTPException(400, "Invalid Content-Length.")
            if length > limit:
                raise HTTPException(413, "Capture file exceeds the 50 MiB upload limit.")
        # Bound in-flight uploads as well as active analysis workers.
        slots = request.app.state.upload_slots
        if slots.locked():
            raise HTTPException(429, "Too many uploads in progress.")
        async with slots:
            path = manager.upload_dir / (str(uuid.uuid4()) + ".pcap")
            accepted, size, header = False, 0, bytearray()
            try:
                with path.open("xb") as output:
                    with anyio.fail_after(60):
                        async for chunk in request.stream():
                            size += len(chunk)
                            if size > limit:
                                raise HTTPException(413, "Capture file exceeds the 50 MiB upload limit.")
                            if len(header) < 24:
                                header.extend(chunk[:24-len(header)])
                            await run_in_threadpool(output.write, chunk)
                minimum = 28 if bytes(header[:4]) == b"\x0a\x0d\x0d\x0a" else 24
                if bytes(header[:4]) not in PCAP_MAGIC or size < minimum:
                    raise HTTPException(422, "Expected a PCAP or PCAPNG file with a complete capture header.")
                result = await run_in_threadpool(manager.create_pcap, path, size)
                accepted = True
                return result
            except TimeoutError:
                raise HTTPException(408, "Upload exceeded 60 seconds.") from None
            finally:
                if not accepted:
                    path.unlink(missing_ok=True)

    @router.get("/jobs", response_model=JobList, tags=["jobs"])
    def list_jobs(limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0),
                  manager=Depends(service)):
        return manager.list(limit, offset)

    @router.get("/jobs/{job_id}", response_model=JobStatus, tags=["jobs"])
    def get_job(job_id: uuid.UUID, manager=Depends(service)):
        return manager.status(str(job_id))

    @router.post("/jobs/{job_id}/stop", response_model=JobStatus, tags=["jobs"])
    def stop_job(job_id: uuid.UUID, manager=Depends(service)):
        return manager.stop(str(job_id))

    @router.delete("/jobs/{job_id}", status_code=204, tags=["jobs"])
    def delete_job(job_id: uuid.UUID, manager=Depends(service)):
        manager.delete(str(job_id))
        return Response(status_code=204)

    @router.get("/jobs/{job_id}/report", response_model=ReportResponse, tags=["assessment"])
    def get_report(job_id: uuid.UUID, download: bool = False, manager=Depends(service)):
        report = manager.report(str(job_id))
        if download:
            return JSONResponse(report, headers={"Content-Disposition": f'attachment; filename="{job_id}.json"'})
        return report

    @router.get("/jobs/{job_id}/ai-input", response_model=AIInputResponse, tags=["AI"])
    def ai_input(job_id: uuid.UUID, manager=Depends(service)):
        return build_ai_input(manager.report(str(job_id)))

    @router.post("/jobs/{job_id}/explain", tags=["AI"])
    def explain(job_id: uuid.UUID, manager=Depends(service)):
        return manager.explain(str(job_id))

    @router.get("/jobs/{job_id}/events", tags=["jobs"],
                response_class=StreamingResponse,
                responses={200: {"content": {"text/event-stream": {}}}})
    async def events(job_id: uuid.UUID, request: Request, manager=Depends(service)):
        identifier = str(job_id)
        await run_in_threadpool(manager.status, identifier)
        async def stream():
            previous = None
            heartbeat = 0
            # Current snapshots, not a lossless packet/event history. Reconnect sends the latest state.
            while not await request.is_disconnected():
                try:
                    row = await run_in_threadpool(manager.snapshot, identifier)
                except KeyError:
                    yield 'event: deleted\ndata: {}\n\n'
                    return
                if row["revision"] != previous:
                    previous = row["revision"]
                    event = "complete" if row["state"] in TERMINAL else "snapshot"
                    data = {"id": identifier, "state": row["state"], "revision": previous,
                            "summary": row["report"]["summary"] if row["report"] else None,
                            "error": row["error"], "report_url": f"/api/v1/jobs/{identifier}/report"}
                    yield f"id: {previous}\nevent: {event}\ndata: {json.dumps(data)}\n\n"
                    heartbeat = 0
                if row["state"] in TERMINAL:
                    return
                await asyncio.sleep(0.5)
                heartbeat += 1
                if heartbeat >= 20:
                    yield ": heartbeat\n\n"
                    heartbeat = 0
        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    application.include_router(router)
    return application


app = create_app()
