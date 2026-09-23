# Backend handoff ? IPsec VPN Security Analyzer 0.6.0

Passive IPsec/IKE capture and deterministic assessment, with an authenticated HTTP API and sanitized AI inputs. The included web dashboard supports session evidence and saved-report comparison. ML remains reserved.

## Start the backend

Requirements: Python 3.10+, Wireshark/TShark, and Npcap/interface permissions for Windows live capture. Run from repository root:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:VPN_ANALYZER_API_KEY = (& .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))")
.\.venv\Scripts\python.exe -m uvicorn api.routes:app --host 127.0.0.1 --port 8000 --workers 1
```

- Base URL: `http://127.0.0.1:8000`
- Swagger: `http://127.0.0.1:8000/docs`
- OpenAPI: `http://127.0.0.1:8000/openapi.json`
- All `/api/v1` requests require `X-API-Key: <VPN_ANALYZER_API_KEY>`. In Swagger click **Authorize**.
- Keep the key in your environment/secret storage; do not commit it.
- The interface belongs to the **backend machine**, not the browser.
- Latest reports persist in SQLite under `data/backend`, excluded from Git. Override with `VPN_ANALYZER_DATA_DIR`.
- Run one worker per data directory. A directory lock rejects a second owner.
- `/health` reports server liveness, not capture-driver readiness.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Public liveness/version |
| GET | `/api/v1/interfaces` | List capture interfaces |
| GET | `/api/v1/policy` | Local rules, weights and supported scope |
| POST | `/api/v1/captures` | Start live capture; HTTP 202 |
| POST | `/api/v1/analyses/pcap` | Upload PCAP/PCAPNG bytes; HTTP 202 |
| GET | `/api/v1/jobs?limit=20&offset=0` | List saved jobs |
| GET | `/api/v1/jobs/{id}` | State, summary, revision and links |
| POST | `/api/v1/jobs/{id}/stop` | Request stop; repeat calls are safe |
| GET | `/api/v1/jobs/{id}/report` | Latest report, also during capture |
| GET | `/api/v1/jobs/{id}/report?download=true` | JSON download |
| GET | `/api/v1/jobs/{id}/events` | SSE status/summary updates |
| GET | `/api/v1/jobs/{id}/comparison?baseline_id={baseline_id}` | Compare two finished saved reports |
| GET | `/api/v1/jobs/{id}/ai-input` | Sanitized inputs for a separate AI |
| POST | `/api/v1/jobs/{id}/explain` | Optional Gemini explanation after capture |
| DELETE | `/api/v1/jobs/{id}` | Delete a finished job; HTTP 204 |

### Live capture

```json
{
  "interface": "Wi-Fi",
  "duration_seconds": 60,
  "packet_limit": 10000,
  "update_interval_seconds": 2
}
```

Use an exact interface name returned by `/interfaces`. Duration defaults to 60 seconds, maximum 3600. Packet limit is optional, maximum 1,000,000. Update interval: 0.5?30 seconds. Capture ends on whichever limit is reached first. Filter: `udp port 500 or udp port 4500 or esp or ah`.

The create response includes `id`, `state`, `source_type`, `revision`, timestamps, `parameters`, optional `summary`, `error`, and `links`. The initial summary can be null. Follow the returned links.

### Client flow and lifecycle

1. List interfaces and select one.
2. POST a capture; retain the returned job ID.
3. Poll the job every 1?2 seconds or consume SSE.
4. Render score, coverage, assessment status and score reasons together.
5. Fetch the full report and AI input.
6. Optionally request an explanation after the job finishes.
7. Offer stop, download and delete controls.

States: `queued ? running ? completed`; manual stop uses `stopping ? stopped`. Errors use `failed`. Restart marks unfinished jobs `interrupted`; capture is not automatically resumed. Terminal states: completed/stopped/failed/interrupted. Normal duration expiry is job state `completed` with `traffic.capture_status = timeout`.

Stop is asynchronous: poll until terminal. Failed/interrupted jobs preserve available evidence and suppress their security score.

### PowerShell example

In a shell containing the same API key:

```powershell
$headers = @{ "X-API-Key" = $env:VPN_ANALYZER_API_KEY }
$base = "http://127.0.0.1:8000"
Invoke-RestMethod "$base/api/v1/interfaces" -Headers $headers

$body = @{
    interface = "Wi-Fi"
    duration_seconds = 60
    update_interval_seconds = 2
} | ConvertTo-Json

$job = Invoke-RestMethod "$base/api/v1/captures" -Method Post -Headers $headers -ContentType "application/json" -Body $body
Invoke-RestMethod "$base/api/v1/jobs/$($job.id)" -Headers $headers
Invoke-RestMethod "$base/api/v1/jobs/$($job.id)/report" -Headers $headers
Invoke-RestMethod "$base/api/v1/jobs/$($job.id)/ai-input" -Headers $headers
Invoke-RestMethod "$base/api/v1/jobs/$($job.id)/stop" -Method Post -Headers $headers
```

PCAP upload accepts **raw bytes, not multipart/form-data or a server filesystem path**:

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/analyses/pcap" -H "X-API-Key: $env:VPN_ANALYZER_API_KEY" -H "Content-Type: application/octet-stream" --data-binary "@data/pcaps/test_vpn.pcap"
```

### SSE

Events: `snapshot` while active, `complete` for every terminal state (including failure), and comment heartbeats. Inspect the JSON `state`; the event name alone does not mean success. Data contains ID, revision, state, summary, error and report URL.

Reconnect sends the latest snapshot, even with `Last-Event-ID`; event history is not replayed. Fetching a report after an event may return a later revision. `metadata.report_revision` identifies the report; job revision can advance independently on stop/explanation updates.

Native browser EventSource cannot set X-API-Key. Use a fetch-based SSE reader, polling, or your own backend proxy. Never put the key in a query string.

## Score contract: do not hide uncertainty

- Risk is the maximum confirmed severity weight: low 10, medium 30, high 60, critical 100. It is not attack probability.
- Offered weak proposals use separate per-SA `offered_policy_risk`; they do not penalize selected crypto.
- Duplicate ESP sequences remain `SUSPECTED`, not proven successful replay.
- Per-SA numeric security score requires an attributed SA, complete supported checks, unambiguous selected crypto and no truncated observations. It equals `100 - risk`.
- Missing, unknown, malformed or conflicting crypto suppresses the score. Cipher/key-length inconsistencies and AEAD with separate integrity transforms are uncertain.
- Overall security score requires **every retained SA** to qualify, without known queue loss, eviction, truncation or incomplete capture. Otherwise it is JSON `null`, with `score_reasons`.
- ESP-only traffic cannot establish the encrypted CHILD_SA cipher. A healthy IKE SA does not make a separate ESP SA assessable. Overall score can be null while an individual IKE SA has a provisional score.
- Start capture before connecting/reconnecting the IPsec VPN to observe the handshake. Missing handshake evidence is never guessed.
- Kernel/Npcap drops remain unknown. Every numeric score is `PROVISIONAL`; it does not prove complete VPN safety or successful authentication.
- NIST/CNSA compliance is `UNKNOWN`; authentication, CHILD_SA policy and receiver replay enforcement remain unassessed.

Show null as **Insufficient evidence**, never zero or 100. Coverage measures six supported crypto checks only. Findings contain status, scope, severity, rule ID, affected SA, evidence and recommendations. The local policy is available through `/policy`; it is not certification.

## AI contract

GET `/jobs/{id}/ai-input` makes no external request. Schema version 1.0 includes engine-authority instructions, scores/coverage/status/reasons, policy/report context, compliance, anonymized SA summaries, finding messages/recommendations, evidence counts, limitations and omitted counts. Limits: 200 findings, 100 SA summaries. Labels are snapshot-local.

Raw endpoints, SPIs, payloads, exact timestamps and credentials are excluded. The AI must explain supplied results while preserving uncertainty; it must not recalculate scores or invent findings.

Optional Gemini settings, before starting the backend:

```powershell
$env:GEMINI_API_KEY = "your-key"
$env:GEMINI_MODEL = "your-supported-model-id"
```

POST `/explain` after the job finishes. At most 30 prioritized sanitized findings are sent, with a 20-second provider timeout and structured response validation. Missing settings/provider failures return `status: unavailable`; engine reports remain usable. Successful results are cached; unavailable results can be explicitly retried. The non-authoritative explanation is separately attached as `ai_explanation`.

## Temporary manual CLI runner

The helper starts a private localhost API with a generated key and temporary database, exercises the HTTP endpoints, then gracefully shuts down its server in the same process. It waits for the database lock to be released before deleting its temporary workspace. If Windows still holds a file open, cleanup retries briefly and reports the retained path without overriding saved results.

```powershell
.\.venv\Scripts\python.exe tools/backend_test_runner.py --list-interfaces
.\.venv\Scripts\python.exe tools/backend_test_runner.py --interface "Wi-Fi" --duration 60
.\.venv\Scripts\python.exe tools/backend_test_runner.py --pcap data/pcaps/test_vpn.pcap
```

Optional: `--packet-limit 1000`, `--explain`, or `--output-dir PATH`. Ctrl+C requests stop and saves the available partial report.

Each run creates a new timestamped folder under `data/reports/manual` containing `job.json`, `report.json`, `ai-input.json`, `updates.jsonl` (polled status snapshots), and `backend.log`. With --explain it also saves `ai-explanation.json`.

To use an existing server, add `--base-url http://127.0.0.1:8000` and set `VPN_ANALYZER_API_KEY`. That server stays running.

## Limits and operations

- One live capture, up to two analysis workers and 100 saved jobs. Delete finished jobs to reclaim the allowance.
- Upload limit: 50 MiB, two simultaneous uploads, 60-second upload deadline. Header checks precede TShark content parsing.
- Uploaded captures are removed after processing; latest snapshots persist atomically. Restart clears abandoned server-generated uploads.
- Offline processing checks a 300-second deadline between packets. A stalled external decoder may delay cancellation; a stuck worker retains data-directory ownership until process exit.
- Engine limits: 512 retained SAs, 300-second idle expiry, 1024-packet live queue, bounded observations/sequence history. Packet counters cover the whole run; scores/findings cover retained evidence.
- API persistence/SSE provide latest snapshots, not full historical reports or raw packet archives.
- Use authorized interfaces. Only traffic reaching that capture point is visible. Other machines may require gateway/mirror/TAP placement.
- No encrypted-payload decryption, OpenVPN/WireGuard assessment, ML detection or compliance certification.
- Shared operator key; no per-user job isolation. Default bind is localhost. Remote deployment needs HTTPS and access controls.
- Optional CORS: `VPN_ANALYZER_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173`. Wildcards are rejected. Do not embed the shared key in a public web application.
- Errors: 401 key, 404 unknown job, 409 incompatible state, 413 upload size, 415 media type, 422 invalid input, 429 capacity, 503 interface/dependency unavailable.

Run regression tests: `python -m pytest -q -p no:cacheprovider`. Mock-source tests do not prove real VPN traffic visibility or Gemini connectivity.


## Passive investigation additions (0.6.0)

`GET /api/v1/jobs/{current_id}/comparison?baseline_id={baseline_id}` requires the normal API key. It reads existing saved reports; it never starts a capture or an AI request. Both jobs must be terminal and have reports. Invalid UUIDs return 422, missing jobs 404, and active/same/missing-report comparisons 409. Users explicitly choose the baseline; creation time need not equal the PCAP capture time.

The response includes `baseline` and `current` report references, `newly_observed`, `persistent` and `no_longer_observed` finding-signature groups, exact-SA identity differences, and `scores`. Signatures use rule ID, parameter, value, scope, status and severity for FAIL/SUSPECTED findings. Groups include before/after SA counts and up to three evidence samples from each report. Persistent signatures across different SAs do not establish a persistent tunnel. No-longer-observed does not mean fixed.

Score `delta` is current minus baseline, or null if `score_comparison_reasons` is nonempty. Matching engine/policy/source type, exact attributed SA population, eligible complete evidence and numeric scores are required. Deltas remain descriptive, not whole-VPN improvement claims. Legacy reports without quality/version metadata suppress deltas.

Each new `sessions[]` entry adds:

- `timeline`: capture-ingestion-ordered `events` (kind, packet_number, timestamp, details), `total_events`, `omitted_events`, `limit` and `repeat_window`. Last 128 events/header identities are retained. No successful authentication or CHILD_SA lifecycle is inferred from encrypted headers.
- `ike_proposals`: up to 16 IKEv2 IKE_SA_INIT packet samples within a 64 KiB serialized-detail budget per SA (`proposal_history_limit_bytes`), each with scope, packet/timestamp, `status` (COMPLETE/PARTIAL/UNAVAILABLE), `reasons`, `truncated`, and proposals with transform IDs/names, key lengths and byte offsets. COMPLETE describes reconstructed structure, not a secure or authenticated tunnel. Limits: 16 proposals/sample, 32 transforms/proposal, 2,048 fields/name inspected.
- `proposal_samples_omitted` and `selected_proposal_issue`: malformed, incomplete or ambiguous available selected structure suppresses scores with `selected_proposal_structure_ambiguous`, including issues observed after sample storage fills. Missing offset support retains the legacy flat-assessment path and reports unavailable proposal detail.

Timeline/proposal truncation counts describe supplemental detail history, not loss of the separately retained assessment observations. SA eviction still removes that SA's bounded history and is accounted for by `traffic.evicted_sessions`. New raw details are excluded from the allowlisted AI input.

Frontend verification: `node --test tests/test_investigation.mjs`. Python regression suite: `python -m pytest -q -p no:cacheprovider`.
