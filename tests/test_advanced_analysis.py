import copy
from types import SimpleNamespace

import pytest

from core.engine import SecurityEngine
from core.signal import SecuritySignal
from core.session import VPNSession
from core.timeline import SessionTimeline
from parsers.ike_parser import IKEParser
from reports.comparison import compare_reports
from sources.pcap_source import PCAPSource
from ai.input_builder import build_ai_input
from test_regressions import Layer, ike, esp


class PositionedLayer(Layer):
    def __init__(self, fields, positioned):
        super().__init__(**fields)
        self.positioned = positioned

    def get_field(self, name):
        if name in self.positioned:
            return SimpleNamespace(all_fields=[SimpleNamespace(pos=str(p), size=str(n), show=str(v))
                for p, n, v in self.positioned[name]])
        return super().get_field(name)


def structured_packet(response="0"):
    packet = ike(response=response, responder="0" if response == "0" else "def")
    # Two proposals: AES-GCM/256, and 3DES with no key attribute. Flattened
    # attribute order cannot safely be zipped to the encryption transforms.
    positions = {
        "typepayload": [(100, 40, 33), (104, 20, 2), (112, 12, 3), (124, 16, 2), (132, 8, 3)],
        "payloadlength": [(102, 2, 40), (106, 2, 20), (114, 2, 12), (126, 2, 16), (134, 2, 8)],
        "prop_number": [(108, 1, 1), (128, 1, 2)],
        "spisize": [(110, 1, 0), (130, 1, 0)],
        "prop_protoid": [(109, 1, 1), (129, 1, 1)],
        "prop_transforms": [(111, 1, 1), (131, 1, 1)],
        "tf_type": [(116, 1, 1), (136, 1, 1)],
        "tf_id_encr": [(118, 2, 20), (138, 2, 3)],
        "tf_id_prf": [], "tf_id_dh": [],
        "ike2_attr_key_length": [(122, 2, 256)],
    }
    packet.isakmp = PositionedLayer(packet.isakmp.fields, positions)
    return packet


def details(packet):
    return next(s for s in IKEParser().parse(packet, 1) if s.name == "ike_proposals").value


def test_transform_key_attributes_stay_with_their_byte_range():
    result = details(structured_packet())
    assert result["status"] == "COMPLETE"
    first, second = result["proposals"]
    assert first["number"] == 1 and second["number"] == 2
    assert first["transforms"][0]["name"] == "AES-GCM-16"
    assert first["transforms"][0]["key_length"] == 256
    assert second["transforms"][0]["name"] == "3DES"
    assert second["transforms"][0]["key_length"] is None


@pytest.mark.parametrize("field,value", [
    ("payloadlength", [(106, 2, 999)]),
    ("prop_transforms", [(111, 1, 7), (131, 1, 1)]),
    ("ike2_attr_key_length", [(122, 2, 128), (122, 2, 256)]),
    ("tf_type", [(116, 1, 99), (136, 1, 1)]),
    ("typepayload", [(100, 40, 33), (104, 99, 2)]),
    ("spisize", [(110, 1, 8), (130, 1, 0)]),
    ("prop_number", [(108, 1, 0), (128, 1, 2)]),
    ("tf_id_encr", [(118, 2, 20), (138, 2, 3), (999, 2, 12)]),
    ("ike2_attr_key_length", [(122, 2, 256), (999, 2, 128)]),
    ("typepayload", [(100, 40, 33)]),
])
def test_inconsistent_ranges_never_claim_complete_proposals(field, value):
    packet = structured_packet()
    packet.isakmp.positioned[field] = value
    assert details(packet)["status"] == "PARTIAL"


def test_missing_offsets_remain_unavailable():
    assert details(ike())["status"] == "UNAVAILABLE"


def test_multiple_selected_proposals_suppress_score_without_changing_risk():
    report = SecurityEngine().analyze([structured_packet(response="1")])
    assert report["summary"]["security_score"] is None
    assert "selected_proposal_structure_ambiguous" in report["sessions"][0]["score_reasons"]
    assert report["summary"]["risk_score"] == 100


def test_proposal_input_limits_are_explicit():
    packet = structured_packet()
    packet.isakmp.positioned["prop_number"] *= 2050
    result = details(packet)
    assert result["truncated"] and result["status"] == "PARTIAL"


def message_packet(response="0", exchange="34", message_id="0", src="a", dst="b"):
    packet = ike(src=src, dst=dst, response=response, responder="0" if response == "0" else "def")
    packet.isakmp.fields.update(messageid=message_id, exchangetype=exchange)
    return packet


def test_timeline_survives_sa_promotion_and_does_not_claim_authentication():
    packets = [message_packet(), message_packet(),
               message_packet(response="1", src="b", dst="a"),
               message_packet(exchange="35", message_id="1")]
    report = SecurityEngine().analyze(packets)
    assert len(report["sessions"]) == 1
    session = report["sessions"][0]
    events = session["timeline"]["events"]
    assert [e["packet_number"] for e in events] == [1, 2, 3, 4]
    assert [e["kind"] for e in events] == ["IKE_MESSAGE", "IKE_REPEATED_HEADER", "IKE_MESSAGE", "IKE_MESSAGE"]
    assert events[-1]["details"]["exchange"] == "IKE_AUTH"
    assert "do not prove authentication" in session["timeline"]["meaning"]
    assert session["packet_count"] == 4
    assert not any(s["scope"] == "selected" for s in session["ike_proposals"] if s["packet_number"] == 4)


def test_missing_message_id_cannot_be_called_a_repeated_header():
    report = SecurityEngine().analyze([ike(), ike()])
    assert all(e["kind"] == "IKE_MESSAGE" for e in report["sessions"][0]["timeline"]["events"])


def test_repeated_notifications_and_esp_duplicates_are_observations():
    packet = message_packet()
    packet.isakmp.fields["notify_msgtype"] = ["16388", "16389", "14"]
    report = SecurityEngine().analyze([packet, esp(), esp()])
    assert report["sessions"][0]["timeline"]["events"][0]["details"]["notifications"] == [
        "NAT_DETECTION_SOURCE_IP", "NAT_DETECTION_DESTINATION_IP", "NO_PROPOSAL_CHOSEN"]
    last = report["sessions"][1]["timeline"]["events"][-1]
    assert last["kind"] == "ESP_DUPLICATE_SEQUENCE" and last["details"]["status"] == "SUSPECTED"
    assert report["sessions"][1]["replay_detected"] is False


def test_history_is_bounded_and_snapshot_is_independent():
    engine = SecurityEngine()
    engine.ingest(message_packet())
    session = next(iter(engine.session_manager.sessions.values()))
    session.timeline = SessionTimeline(limit=3)
    for i in range(10):
        engine.ingest(message_packet(message_id=str(i)))
    before = engine.snapshot()
    timeline = before["sessions"][0]["timeline"]
    assert len(timeline["events"]) == 3 and timeline["omitted_events"] == 7
    assert len(session.timeline.seen_headers) == 3
    engine.ingest(message_packet(message_id="11"))
    assert timeline["total_events"] == 10
    before["sessions"][0]["ike_proposals"][0]["reasons"].append("external-change")
    assert "external-change" not in session.proposal_samples[0]["reasons"]


def test_late_malformed_proposal_still_suppresses_score_after_sample_cap():
    engine = SecurityEngine()
    for _ in range(18):
        engine.ingest(ike())
    engine.ingest(structured_packet(response="1"))
    session = engine.snapshot()["sessions"][0]
    assert len(session["ike_proposals"]) == 16 and session["proposal_samples_omitted"] == 3
    assert session["selected_proposal_issue"] and session["risk"]["security_score"] is None


def test_real_tshark_sample_has_associated_proposals_and_timeline():
    source = PCAPSource("data/pcaps/test_vpn.pcap")
    try:
        report = SecurityEngine().analyze(source.read(), source_type="pcap")
    finally:
        source.close()
    samples = [p for s in report["sessions"] for p in s["ike_proposals"]]
    assert samples and all(s["status"] == "COMPLETE" for s in samples)
    assert samples[0]["proposals"][0]["transforms"][0]["key_length"] == 256
    assert report["traffic"]["packets_processed"] == 6
    assert sum(len(s["timeline"]["events"]) for s in report["sessions"]) > 0


def test_new_details_do_not_enter_ai_payload():
    packet = message_packet(src="192.0.2.123", dst="198.51.100.222")
    report = SecurityEngine().analyze([packet])
    import json
    payload = json.dumps(build_ai_input(report))
    assert "192.0.2.123" not in payload and "198.51.100.222" not in payload
    assert "ike_proposals" not in payload and "timeline" not in payload


def test_comparison_separates_offered_selected_and_suspected_without_mutation():
    baseline = SecurityEngine().analyze([ike(encryption="3"), esp(), esp()], source_type="pcap")
    current = SecurityEngine().analyze([ike(response="0", responder="0", encryption="3"), ike()], source_type="pcap")
    saved = copy.deepcopy((baseline, current))
    result = compare_reports(baseline, current)
    assert any(r["scope"] == "offered" and r["rule_id"] == "ENC-004" for r in result["newly_observed"])
    assert any(r["scope"] == "selected" and r["rule_id"] == "ENC-004" for r in result["no_longer_observed"])
    assert any(r["status"] == "SUSPECTED" for r in result["no_longer_observed"])
    assert result["scores"]["security_score"]["delta"] is None
    assert saved == (baseline, current)


def test_recurring_signature_across_spi_changes_does_not_mean_same_sa():
    baseline = SecurityEngine().analyze([ike(encryption="3")], source_type="pcap")
    current = SecurityEngine().analyze([ike(spi="changed", encryption="3")], source_type="pcap")
    result = compare_reports(baseline, current)
    assert any(r["rule_id"] == "ENC-004" for r in result["persistent"])
    assert not result["sessions"]["shared"]
    assert "sa_population_changed_or_unattributed" in result["score_comparison_reasons"]


def test_comparable_scores_are_descriptive_and_missing_scores_stay_null():
    baseline = SecurityEngine().analyze([ike()], source_type="pcap")
    current = copy.deepcopy(baseline)
    assert compare_reports(baseline, current)["scores"]["security_score"]["delta"] == 0
    current["summary"]["security_score"] = None
    assert compare_reports(baseline, current)["scores"]["security_score"]["delta"] is None


@pytest.mark.parametrize("change", ["policy", "loss", "incomplete", "old"])
def test_incompatible_or_incomplete_reports_never_produce_score_delta(change):
    baseline = SecurityEngine().analyze([ike()], source_type="pcap")
    current = copy.deepcopy(baseline)
    if change == "policy":
        current["metadata"]["policy_version"] = "different"
    elif change == "loss":
        current["traffic"]["queue_drops"] = 2
    elif change == "incomplete":
        current["metadata"]["incomplete"] = True
    else:
        current.pop("quality")
        current["metadata"].pop("engine_version")
    result = compare_reports(baseline, current)
    assert result["score_comparison_reasons"]
    assert all(m["delta"] is None for m in result["scores"].values())


def test_proposal_history_byte_budget_does_not_hide_quality_issues():
    engine = SecurityEngine()
    engine.ingest(ike())
    session = next(iter(engine.session_manager.sessions.values()))
    session.proposal_history_limit_bytes = session.proposal_history_bytes
    engine.ingest(structured_packet(response="1"))
    report = engine.snapshot()
    assert len(session.proposal_samples) == 1
    assert session.proposal_samples_omitted == 1
    assert session.selected_proposal_issue
    assert report["summary"]["security_score"] is None
