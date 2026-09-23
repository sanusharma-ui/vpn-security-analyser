"""Read-only comparisons of retained observations, never claims of remediation."""
from copy import deepcopy
import json
import math


FINGERPRINT = ("rule_id", "parameter", "value", "scope", "status", "severity")


def _index(report):
    grouped = {}
    for finding in report.get("findings", []):
        if finding.get("status") not in ("FAIL", "SUSPECTED"):
            continue
        identity = {name: finding.get(name) for name in FINGERPRINT}
        key = json.dumps(identity, sort_keys=True, ensure_ascii=True)
        entry = grouped.setdefault(key, {**identity, "sessions": set(), "evidence": [],
                                        "message": finding.get("message")})
        entry["sessions"].add(finding.get("session_id"))
        for sample in finding.get("evidence", []):
            if len(entry["evidence"]) < 3:
                entry["evidence"].append(deepcopy(sample))
    return grouped


def _numeric(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def compare_reports(baseline, current):
    before, after = _index(baseline), _index(current)
    before_keys, after_keys = set(before), set(after)

    def rows(keys):
        result = []
        for key in sorted(keys):
            left, right = before.get(key), after.get(key)
            entry = right or left
            result.append({**{name: deepcopy(entry[name]) for name in FINGERPRINT},
                "message": entry["message"],
                "baseline_session_count": len(left["sessions"]) if left else 0,
                "current_session_count": len(right["sessions"]) if right else 0,
                "baseline_evidence": deepcopy(left["evidence"]) if left else [],
                "current_evidence": deepcopy(right["evidence"]) if right else []})
        return result

    previous_sas = {s["session_id"] for s in baseline.get("sessions", [])}
    current_sas = {s["session_id"] for s in current.get("sessions", [])}
    reasons = []
    bm, cm = baseline.get("metadata", {}), current.get("metadata", {})
    if not all(bm.get(k) and bm.get(k) == cm.get(k)
               for k in ("policy_name", "policy_version", "engine_version")):
        reasons.append("policy_or_engine_version_mismatch_or_missing")
    if not previous_sas or previous_sas != current_sas or any(
            s.startswith("unattributed:") or "unknown" in s for s in previous_sas):
        reasons.append("sa_population_changed_or_unattributed")
    if bm.get("source_type") not in ("pcap", "live") or bm.get("source_type") != cm.get("source_type"):
        reasons.append("capture_source_type_changed_or_missing")
    for label, report in (("baseline", baseline), ("current", current)):
        traffic = report.get("traffic", {})
        if (not report.get("quality", {}).get("security_score_eligible")
                or report.get("metadata", {}).get("incomplete")
                or report.get("metadata", {}).get("evidence_truncated")
                or any(traffic.get(k, 0) for k in ("queue_drops", "evicted_sessions", "capture_drops"))):
            reasons.append(label + "_evidence_not_score_eligible")
    for metric in ("risk_score", "security_score"):
        if not all(_numeric(r.get("summary", {}).get(metric)) for r in (baseline, current)):
            reasons.append(metric + "_unavailable")
    differences = {}
    for metric in ("risk_score", "security_score"):
        left, right = baseline.get("summary", {}).get(metric), current.get("summary", {}).get(metric)
        differences[metric] = {"baseline": left, "current": right,
                               "delta": right - left if not reasons else None}
    return {
        "schema_version": "1.0", "mode": "passive_observation_comparison",
        "baseline": {k: bm.get(k) for k in ("job_id", "report_revision", "generated_at", "policy_version")},
        "current": {k: cm.get(k) for k in ("job_id", "report_revision", "generated_at", "policy_version")},
        "newly_observed": rows(after_keys - before_keys),
        "no_longer_observed": rows(before_keys - after_keys),
        "persistent": rows(before_keys & after_keys),
        "sessions": {"shared": sorted(previous_sas & current_sas),
                     "newly_observed": sorted(current_sas - previous_sas),
                     "no_longer_observed": sorted(previous_sas - current_sas)},
        "scores": differences, "score_comparison_reasons": reasons,
        "limitations": [
            "Compares FAIL and SUSPECTED findings by rule, value, scope, status and severity across retained SAs.",
            "Persistent means the same finding signature was observed in both reports, not the same tunnel.",
            "No longer observed does not prove remediation; capture visibility and SA populations may differ.",
            "Offered proposals and suspected replay remain separate from confirmed selected weaknesses.",
            "Score deltas require matching policy/engine/source type, exact SA population and eligible evidence; "
            "even then they are descriptive, not proof of a security improvement.",
            "Unknown kernel capture loss and unobserved authentication remain limitations in both reports.",
        ],
    }
