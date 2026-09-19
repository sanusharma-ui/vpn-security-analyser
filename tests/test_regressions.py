import asyncio
import copy
import json
import time
from types import SimpleNamespace
import pytest
from core.engine import SecurityEngine
from core.signal import SecuritySignal
from core.session_manager import SessionManager
from analysis.rule_engine import RuleEngine
from analysis.risk_engine import RiskEngine
from parsers.ike_parser import IKEParser
from parsers.ipsec_parser import IPsecParser
from ai.ai_explainer import GeminiExplainer
from sources.live_source import LiveSource


class Layer:
    def __init__(self, **fields):
        self.fields = fields
    def get_field_value(self, name):
        value = self.fields.get(name)
        return value[0] if isinstance(value, list) else value
    def get_field(self, name):
        value = self.fields.get(name)
        values = value if isinstance(value, list) else [value]
        return SimpleNamespace(all_fields=[SimpleNamespace(show=v) for v in values if v is not None])


def ike(src="10.0.0.1", dst="10.0.0.2", spi="abc", responder="def", response="1", encryption="20"):
    return SimpleNamespace(ip=SimpleNamespace(src=src, dst=dst), sniff_timestamp="1234.5",
        isakmp=Layer(ispi=spi, rspi=responder, mjver="2", exchangetype="34", flag_i="0" if response == "1" else "1",
            flag_r=response, tf_id_encr=encryption, ike2_attr_key_length="256", tf_id_prf="5", tf_id_dh="19"))


def esp(src="a", dst="b", seq="42"):
    return SimpleNamespace(ip=SimpleNamespace(src=src, dst=dst), sniff_timestamp="1235",
                          esp=Layer(spi="0x1234", sequence=seq))


def test_separate_tunnels_keep_weak_selected_cipher_and_packet_evidence():
    report = SecurityEngine().analyze([ike(), ike(src="10.0.0.3", spi="other", encryption="3")])
    assert len(report["sessions"]) == 2
    assert report["summary"]["risk_score"] == 100
    weak = next(f for f in report["findings"] if f["rule_id"] == "ENC-004")
    assert weak["scope"] == "selected"
    assert weak["evidence"][0]["packet_number"] == 2
    assert weak["evidence"][0]["timestamp"] == "1234.5"
    assert all(s["packet_count"] == 1 for s in report["sessions"])


def test_all_repeated_offers_checked_but_not_reported_as_selected():
    report = SecurityEngine().analyze([ike(response="0", responder="0", encryption=["20", "3"]), ike()])
    assert len(report["sessions"]) == 1
    weak = [f for f in report["findings"] if f["rule_id"] == "ENC-004"]
    assert len(weak) == 1 and weak[0]["scope"] == "offered"
    assert report["summary"]["risk_score"] == 0
    assert report["sessions"][0]["packet_count"] == 2


def test_repeat_request_and_different_responder_sas_do_not_merge():
    report = SecurityEngine().analyze([ike(response="0", responder="0"), ike(),
                                      ike(response="0", responder="0"), ike(responder="different")])
    assert len(report["sessions"]) == 2
    assert sorted(s["packet_count"] for s in report["sessions"]) == [1, 3]


def test_same_esp_spi_different_endpoints_and_directions_are_isolated():
    report = SecurityEngine().analyze([esp(), esp(src="c"), esp(src="b", dst="a")])
    assert len(report["sessions"]) == 3
    assert not any(s["suspected_replay"] for s in report["sessions"])
    assert report["summary"]["security_score"] is None


def test_duplicate_is_suspected_and_not_confirmed_risk():
    report = SecurityEngine().analyze([esp(), esp()])
    finding = next(f for f in report["findings"] if f["rule_id"] == "IPSEC-004")
    assert finding["status"] == "SUSPECTED"
    assert finding["evidence"][0]["packet_number"] == 2
    assert report["summary"]["security_score"] is None


def test_empty_capture_does_not_pass_compliance_or_score_secure():
    report = SecurityEngine().analyze([])
    assert report["summary"]["risk_level"] == "UNKNOWN"
    assert report["summary"]["security_score"] is None
    assert set(report["compliance"].values()) == {"UNKNOWN"}


def test_risk_is_monotonic_and_unknown_does_not_penalize():
    risk = RiskEngine()
    high = {"severity": "high", "status": "FAIL", "parameter": "encryption"}
    low = {"severity": "low", "status": "FAIL", "parameter": "key_length"}
    assert risk.calculate([high, low])["score"] >= risk.calculate([high])["score"]
    assert risk.calculate([high, {"severity": "critical", "status": "UNKNOWN"}])["score"] == 60
    assert risk.calculate([high, {"severity": "critical", "status": "SUSPECTED"}])["score"] == 60


def test_aliases_and_chacha_aead():
    findings = RuleEngine().evaluate({"encryption": ["AES-GCM-16", "3DES-CBC"]})
    assert any(f["rule_id"] == "ENC-004" for f in findings)
    findings = RuleEngine().evaluate({"encryption": "ChaCha20-Poly1305"})
    assert next(f for f in findings if f["rule_id"] == "INT-001")["status"] == "NOT_APPLICABLE"


def test_session_limits_expiry_and_sequence_window():
    manager = SessionManager(max_sessions=2, idle_timeout=10)
    for i in range(3):
        manager.ingest([SecuritySignal("ike_version", "IKEv2", "packet", session_id=str(i), packet_number=i)], now=1)
    assert len(manager.sessions) == 2 and manager.evicted == 1
    manager.expire(12)
    assert not manager.sessions and manager.evicted == 3
    manager.ingest([SecuritySignal("esp_sequence_int", 1, "packet", session_id="esp", packet_number=1)], now=12)
    session = manager.sessions["esp"]
    session.sequence_window = 4
    for i in range(10):
        session.ingest(SecuritySignal("esp_sequence_int", i, "packet", packet_number=i+2))
    assert len(session.sequences) == 4


def test_updates_are_emitted_before_input_is_exhausted_and_snapshots_are_stable():
    engine = SecurityEngine()
    updates = []
    def packets():
        yield ike()
        assert len(updates) == 1
        yield ike(src="c", encryption="3")
    report = engine.analyze(packets(), on_update=updates.append)
    assert updates[0]["traffic"]["packets_processed"] == 1
    assert report["traffic"]["packets_processed"] == 2
    assert updates[0]["summary"]["risk_score"] == 0


class FakeCapture:
    fail = False
    closed = False
    def __init__(self, **kwargs):
        pass
    async def packets_from_tshark(self, callback, packet_count=None):
        if self.fail:
            raise RuntimeError("capture failed")
        await asyncio.sleep(60)
    async def close_async(self):
        type(self).closed = True


def test_idle_live_timeout_and_cleanup(monkeypatch):
    FakeCapture.closed = False
    monkeypatch.setattr("sources.live_source.pyshark.LiveCapture", FakeCapture)
    source = LiveSource(timeout=0.02)
    assert all(p is None for p in source.read())
    assert source.status == "timeout"
    assert FakeCapture.closed and not source._thread.is_alive()


def test_capture_failure_surfaces(monkeypatch):
    class Broken(FakeCapture):
        fail = True
    monkeypatch.setattr("sources.live_source.pyshark.LiveCapture", Broken)
    source = LiveSource()
    with pytest.raises(RuntimeError, match="Live capture failed"):
        list(source.read())
    assert source.status == "error" and not source._thread.is_alive()


def test_live_close_cancels_idle_worker(monkeypatch):
    monkeypatch.setattr("sources.live_source.pyshark.LiveCapture", FakeCapture)
    source = LiveSource()
    stream = source.read()
    source.close()
    stream.close()
    assert not source._thread.is_alive()


def gemini_response(items):
    return {"candidates": [{"finishReason": "STOP", "content": {"parts": [{"text": json.dumps({"items": items})}]}}]}


def test_gemini_cannot_modify_engine_and_does_not_receive_identifiers():
    report = SecurityEngine().analyze([ike()])
    before = copy.deepcopy(report)
    def transport(payload):
        encoded = json.dumps(payload)
        assert "10.0.0.1" not in encoded and "abc/def" not in encoded
        inputs = json.loads(payload["contents"][0]["parts"][0]["text"])
        return gemini_response([{"id": row["id"], "explanation": row["message"]} for row in inputs])
    result = GeminiExplainer("test-key", "test-model", transport=transport).analyze(report)
    assert result["status"] == "available" and result["authoritative"] is False
    assert report == before
    assert result["items"][0]["finding_id"] in {f["finding_id"] for f in report["findings"]}


@pytest.mark.parametrize("kind", ["failure", "unknown_id", "new_score", "missing", "truncated"])
def test_gemini_bad_output_falls_back_without_changing_report(kind):
    report = SecurityEngine().analyze([ike()])
    before = copy.deepcopy(report)
    def transport(payload):
        if kind == "failure":
            raise RuntimeError("private provider error with secret")
        response = gemini_response([{"id": "invented", "explanation": "text"}])
        if kind == "missing":
            return gemini_response([])
        if kind == "new_score":
            return gemini_response([{"id": "F0", "explanation": "text", "security_score": 100}])
        if kind == "truncated":
            response["candidates"][0]["finishReason"] = "MAX_TOKENS"
        return response
    result = GeminiExplainer("test-key", "test-model", transport=transport).analyze(report)
    assert result["status"] == "unavailable" and report == before
    assert "secret" not in json.dumps(result)


def test_selected_evidence_removes_conflicting_missing_field_messages():
    report = SecurityEngine().analyze([ike()])
    assert not any(f["parameter"] in ("encryption", "key_length", "integrity", "dh_group", "prf")
                   and f["status"] == "UNKNOWN" for f in report["findings"])


def test_offer_only_has_no_security_score_but_records_offer_exposure():
    report = SecurityEngine().analyze([ike(response="0", responder="0", encryption="3")])
    assert report["summary"]["security_score"] is None
    assert report["sessions"][0]["offered_policy_risk"]["score"] == 100


def test_live_queue_overload_is_counted_and_bounded(monkeypatch):
    class Burst(FakeCapture):
        async def packets_from_tshark(self, callback, packet_count=None):
            for _ in range(100):
                callback(esp())
    monkeypatch.setattr("sources.live_source.pyshark.LiveCapture", Burst)
    source = LiveSource(queue_size=2)
    stream = source.read()
    assert source._done.wait(2)
    packets = [p for p in stream if p is not None]
    assert len(packets) == 2 and source.queue_drops == 98


def test_observation_truncation_suppresses_security_score():
    engine = SecurityEngine()
    engine.ingest(ike())
    session = next(iter(engine.session_manager.sessions.values()))
    session.max_observations = len(session.observations)
    session.ingest(SecuritySignal("extra", "new", "packet", packet_number=2))
    report = engine.snapshot()
    assert report["metadata"]["evidence_truncated"] is True
    assert report["summary"]["security_score"] is None


def test_cli_output_is_json_and_missing_gemini_settings_do_not_fail(monkeypatch, capsys):
    import app
    monkeypatch.setattr("sys.argv", ["app.py", "data/pcaps/test_vpn.pcap", "--explain"])
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    assert app.main() == 0
    report = json.loads(capsys.readouterr().out)
    assert report["traffic"]["packets_processed"] == 6
    assert report["ai_explanation"]["status"] == "unavailable"


def test_cli_missing_input_returns_partial_report_and_nonzero(monkeypatch, capsys):
    import app
    monkeypatch.setattr("sys.argv", ["app.py", "data/pcaps/does-not-exist.pcap"])
    assert app.main() == 1
    report = json.loads(capsys.readouterr().out)
    assert report["metadata"]["incomplete"] is True
    assert report["summary"]["security_score"] is None


@pytest.mark.parametrize("arguments", [
    ["input.pcap", "--live", "default"], ["--live", "default", "--timeout", "0"],
    ["--live", "default", "--timeout", "nan"], ["input.pcap", "--output", "input.pcap"]])
def test_invalid_cli_options_fail_before_capture(monkeypatch, arguments):
    import app
    monkeypatch.setattr("sys.argv", ["app.py", *arguments])
    with pytest.raises(SystemExit) as error:
        app.parse_args()
    assert error.value.code == 2
