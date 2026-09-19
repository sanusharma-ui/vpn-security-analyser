"""Conservative score eligibility shared by CLI and HTTP consumers."""

CRYPTO_FIELDS = ("encryption", "key_length", "prf", "dh_group", "integrity")


def qualify_session(session):
    findings = session["findings"]
    reasons = []
    if not session["session_id"].startswith("ike:") or session["session_id"].endswith("/0"):
        reasons.append("selected_sa_identity_unavailable")
    selected = [f for f in findings if f["scope"] == "selected"]
    if not any(f["parameter"] == "encryption" for f in selected):
        reasons.append("selected_cipher_not_observed")
    for field in CRYPTO_FIELDS:
        rows = [f for f in selected if f["parameter"] == field]
        if not rows or any(f["status"] == "UNKNOWN" for f in rows):
            reasons.append(f"selected_{field}_unassessed")
        if len({str(f["value"]) for f in rows if f["value"] is not None}) > 1:
            reasons.append(f"ambiguous_{field}")
    if session["confidence"]["coverage"] < 100:
        reasons.append("incomplete_supported_checks")
    if session["evidence_truncated"]:
        reasons.append("observations_truncated")
    session["score_reasons"] = list(dict.fromkeys(reasons))
    if reasons:
        session["risk"]["security_score"] = None
    session["assessment_status"] = "INSUFFICIENT_EVIDENCE" if reasons else "PROVISIONAL"


def apply_report_quality(report):
    """Mutate an owned snapshot, never infer missing controls or capture success."""
    summary, traffic, metadata = report["summary"], report["traffic"], report["metadata"]
    sessions = report["sessions"]
    reasons = []
    if not sessions:
        reasons.append("no_assessable_sessions")
    if any(s["risk"]["security_score"] is None for s in sessions):
        reasons.append("one_or_more_sessions_unassessed")
    if metadata.get("evidence_truncated"):
        reasons.append("observations_truncated")
    if traffic.get("evicted_sessions", 0):
        reasons.append("sessions_evicted")
    if traffic.get("queue_drops", 0):
        reasons.append("capture_queue_drops")
    if metadata.get("incomplete"):
        reasons.append("capture_incomplete")
    capture_reasons = [reason for reason in reasons if reason in (
        "capture_queue_drops", "capture_incomplete", "sessions_evicted", "observations_truncated")]
    if capture_reasons:
        for session in sessions:
            session["risk"]["security_score"] = None
            session["score_reasons"] = list(dict.fromkeys(session.get("score_reasons", []) + capture_reasons))
            session["assessment_status"] = "INSUFFICIENT_EVIDENCE"
    if reasons:
        summary["security_score"] = None
    else:
        summary["security_score"] = min(s["risk"]["security_score"] for s in sessions)
    summary["score_reasons"] = reasons
    summary["assessment_status"] = "INSUFFICIENT_EVIDENCE" if reasons else "PROVISIONAL"
    summary["score_scope"] = "Supported passive checks across all retained SAs; not whole-VPN security"
    summary["risk_scope"] = "Worst confirmed observed/selected weakness in retained evidence; not attack probability"
    report["quality"] = {
        "security_score_eligible": not reasons,
        "reasons": reasons,
        "capture_loss_known": traffic.get("capture_drops") is not None,
        "limitations": [
            "Kernel capture loss is unknown unless supplied by the capture source.",
            "IKE and ESP SAs are not linked without gateway evidence.",
            "Authentication, CHILD_SA policy and receiver replay enforcement are unassessed.",
            "Selected IKE_SA_INIT transforms do not prove a successfully authenticated tunnel.",
        ],
    }
    return report
