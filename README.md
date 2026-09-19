# IPsec VPN Security Analyzer

Deterministic IPsec/IKE assessment from PCAP/PCAPNG or a live interface. The engine owns every finding, policy result and score. Optional Gemini explanations paraphrase engine findings; they do not perform assessment. ML integration remains reserved for a separate implementation.

## Requirements

- Python 3.10+ and the packages in `requirements.txt` (`pyshark`, `pytest`).
- Wireshark/TShark installed; Npcap and appropriate interface permissions for Windows live capture.
- Gemini is optional. It uses the standard-library HTTPS client, with no extra SDK dependency.

```powershell
python -m pip install -r requirements.txt
python app.py data/pcaps/test_vpn.pcap --output data/reports/report.json
```

## Live analysis

```powershell
python app.py --list-interfaces
python app.py --live "INTERFACE_NAME" --timeout 60 --update-interval 2 --updates-jsonl data/reports/live.jsonl --output data/reports/final.json
```

Use an actual listed interface name, or `default`. `--count 1000` optionally limits captured packets. Ctrl+C stops capture and produces the partial report. `--timeout` includes idle time. Live status goes to stderr; stdout contains final JSON. JSONL snapshots are available while capture is running, including idle heartbeats. The final snapshot includes capture status and queue-drop counts. Capture errors produce an incomplete report and nonzero exit status.

Traffic must reach the monitored interface. Capturing the local host does not automatically observe other hosts on a switched network; a gateway sensor or mirror/TAP deployment is needed for those links. No active probing or packet injection is performed.

## Gemini explanations

Set credentials in the process environment; do not commit them:

```powershell
$env:GEMINI_API_KEY = "YOUR_API_KEY"
$env:GEMINI_MODEL = "YOUR_SUPPORTED_GEMINI_MODEL_ID"
python app.py data/pcaps/test_vpn.pcap --explain --output data/reports/explained.json
```

The explicit `--explain` flag sends up to 30 prioritized engine finding messages and recommendations to Google's Gemini `generateContent` API. Local endpoint addresses, session identifiers, packet payloads and credentials are excluded from that payload. Choose a model supporting structured JSON output. See the [official API reference](https://ai.google.dev/api/generate-content).

One request runs after capture ends, with a 20-second HTTP timeout. Response size, schema, completion status and finding IDs are checked. Missing settings, provider errors or invalid output return `ai_explanation.status = unavailable`; engine findings remain usable. Explanations are stored separately with `authoritative = false` and the original engine message. Generated wording is not independently fact-verified; refer to the engine evidence for authoritative conclusions. No AI-generated score or rule result is accepted.

## Assessment semantics

- Assessments are per observed Security Association (SA). IKE identity includes peers and both SPIs, with promotion from the initial zero responder SPI. ESP identity includes source, destination and SPI. IKE and ESP SAs are not automatically linked into a full tunnel without gateway evidence.
- Repeated transform values are inspected. IKEv2 IKE_SA_INIT request proposals are `offered`; response transforms are `selected` when the response flag is available. Otherwise values are `observed`. Offered policy weaknesses have their own `offered_policy_risk` and do not describe a selected cipher.
- Flattened transform observations do not reconstruct every proposal-to-attribute association. No complete negotiated suite or CHILD_SA crypto is inferred from the top-level crypto inventory.
- Each finding includes status, scope, rule ID, affected SA and up to three packet/timestamp evidence samples. Missing evidence uses `UNKNOWN`; AEAD's separate integrity check uses `NOT_APPLICABLE`. Duplicate ESP sequences mean `SUSPECTED` replay, not proven attack or receiver acceptance.
- Nonce length does not establish entropy. AH alone does not establish whether another layer encrypts the application data. High ESP sequence numbers do not prove ESN is disabled.
- Risk is the maximum severity weight among confirmed assessed controls (low 10, medium 30, high 60, critical 100). Added weaknesses cannot lower it. Unknown/suspected findings and offered proposals do not change this score.
- Security score is `100 - risk`, only when a cipher was assessable; otherwise it is null. Every available score remains `PROVISIONAL`: it measures supported observed controls, not breach probability or whole-VPN safety. A score of 100 does not certify security.
- Coverage is the fraction of six supported passive crypto checks assessed per SA. Overall coverage is the minimum across retained SAs. `analysis_confidence` remains a compatibility alias for coverage, not statistical confidence. Unobservable authentication, CHILD_SA policy and receiver replay enforcement are listed separately.
- Full NIST SP 800-77 / CNSA 2.0 assessments remain `UNKNOWN`. This local policy is not certification; classical ECDH does not establish post-quantum compliance.

## Resource and evidence limits

The capture queue retains at most 1,024 packets and counts application queue drops. Kernel/Npcap capture drops are unknown (`capture_drops: null`); they are not reported as zero. The engine retains at most 512 active SAs, expires idle SAs after 300 seconds of processing inactivity, and retains 256 unique observations per SA with three evidence samples each. Sequence duplicate checks cover the most recent 4,096 distinct sequence values per SA. Duplicate examples are capped at 16.

Reports explicitly count evicted SAs and flag observation truncation. A truncated observation set suppresses the security score. Packet counters cover the run; scores/findings cover retained SAs only. Persist JSONL updates if historical findings are required. This is not a full forensic archive or a disk PCAP ring buffer. SPI reuse without observable lifecycle evidence remains ambiguous.

## Integration and tests

`SecurityEngine.ingest(packet)` and `snapshot()` support incremental consumers; `analyze(..., on_update=callback, update_interval=2)` supports streaming updates. `LiveSource.read()` yields `None` heartbeats while idle. Existing `api/` files remain placeholders; this release exposes CLI/JSON/JSONL and Python interfaces, not an HTTP server or dashboard.

```powershell
python -m pytest -q -p no:cacheprovider
```

Tests cover the included PCAP through real TShark, mixed SAs, repeated offers, selected crypto, evidence, scoring, bounded state and mocked live/Gemini success and failure paths. Hardware live capture and actual Gemini connectivity require separate environment-specific verification. `ai/ml_model.py`, `analysis/feature_extractor.py` and `analysis/anomaly_detector.py` remain untouched for the ML implementation.
