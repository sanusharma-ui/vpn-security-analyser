import json
import pytest
from ai.input_builder import build_ai_input
from core.engine import SecurityEngine
from reports.quality import apply_report_quality
from test_regressions import ike, esp


def test_complete_selected_ike_has_provisional_score():
    report = SecurityEngine().analyze([ike()])
    assert report["summary"]["security_score"] == 100
    assert report["summary"]["assessment_status"] == "PROVISIONAL"
    assert report["quality"]["capture_loss_known"] is False


@pytest.mark.parametrize("field,value", [
    ("tf_id_prf", None), ("tf_id_prf", "999"), ("tf_id_prf", ["5", "999"]),
    ("tf_id_encr", ["20", "3"]), ("ike2_attr_key_length", "512"),
    ("tf_id_encr", ["20", "invalid"]), ("tf_id_integ", "12"),
    ("ike2_attr_key_length", ["256", "invalid"]),
    ("ike2_attr_key_length", ["128", "256"]), ("tf_id_dh", ["19", "2"]),
])
def test_incomplete_unknown_and_ambiguous_selection_never_scores_100(field, value):
    packet = ike()
    packet.isakmp.fields[field] = value
    report = SecurityEngine().analyze([packet])
    assert report["summary"]["security_score"] is None
    assert report["sessions"][0]["score_reasons"]


def test_esp_unknown_cannot_be_hidden_by_a_healthy_ike_sa():
    report = SecurityEngine().analyze([ike(), esp()])
    assert report["summary"]["security_score"] is None
    assert report["sessions"][0]["risk"]["security_score"] == 100
    assert report["summary"]["assessment_coverage"] == 0


@pytest.mark.parametrize("quality", ["queue_drops", "incomplete", "evicted"])
def test_known_evidence_loss_suppresses_overall_score_but_keeps_findings(quality):
    report = SecurityEngine().analyze([ike()])
    if quality == "queue_drops":
        report["traffic"]["queue_drops"] = 1
    elif quality == "evicted":
        report["traffic"]["evicted_sessions"] = 1
    else:
        report["metadata"]["incomplete"] = True
    apply_report_quality(report)
    assert report["summary"]["security_score"] is None
    assert report["summary"]["score_reasons"]
    assert report["findings"]
    assert all(s["risk"]["security_score"] is None for s in report["sessions"])


def test_cipher_without_clear_selection_does_not_get_security_score():
    packet = ike()
    packet.isakmp.fields["flag_r"] = None
    report = SecurityEngine().analyze([packet])
    assert report["summary"]["security_score"] is None


def test_explicit_no_integrity_with_cbc_is_a_failure():
    packet = ike(encryption="12")
    packet.isakmp.fields["tf_id_integ"] = "0"
    report = SecurityEngine().analyze([packet])
    assert report["summary"]["risk_score"] == 60
    assert report["summary"]["security_score"] == 40
    assert any(f["parameter"] == "integrity" and f["status"] == "FAIL" for f in report["findings"])


def test_weak_offer_does_not_penalize_selected_cipher():
    report = SecurityEngine().analyze([ike(response="0", responder="0", encryption="3"), ike()])
    assert report["summary"]["security_score"] == 100
    assert report["sessions"][0]["offered_policy_risk"]["score"] == 100


def test_ai_contract_is_sanitized_bounded_and_cannot_mutate_report():
    report = SecurityEngine().analyze([ike()])
    before = json.dumps(report, sort_keys=True)
    payload = build_ai_input(report, max_findings=2, max_sessions=1)
    encoded = json.dumps(payload)
    assert all(secret not in encoded for secret in ("10.0.0.1", "10.0.0.2", "abc/def", "1234.5"))
    assert payload["omitted_findings"] > 0 and len(payload["findings"]) == 2
    assert payload["assessment"]["security_score"] == 100
    assert json.dumps(report, sort_keys=True) == before
