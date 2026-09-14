import pytest
from analysis.rule_engine import RuleEngine
from config.security_baseline import SECURITY_BASELINE


def test_rule_engine_aggressive_mode_detection():
    engine = RuleEngine()
    signals = {
        "ike_version": "IKEv1",
        "ike_exchange": "Aggressive Mode",
        "is_aggressive_mode": True,
        "encryption": "AES-CBC",
        "key_length": 128,
        "dh_group": 14,
        "prf": "HMAC-SHA2-256"
    }
    findings = engine.evaluate(signals)
    rule_ids = [f["rule_id"] for f in findings]

    assert "IKE-005" in rule_ids
    aggressive_finding = next(f for f in findings if f["rule_id"] == "IKE-005")
    assert aggressive_finding["severity"] == "critical"

    # Aggressive mode should fail NIST SP 800-77 Rev 1
    comp_finding = next(f for f in findings if f["rule_id"] == "COMP-001")
    assert comp_finding["severity"] == "high"
    assert "fails" in comp_finding["message"].lower()


def test_rule_engine_weak_dh_logjam():
    engine = RuleEngine()
    signals = {
        "ike_version": "IKEv2",
        "encryption": "AES-CBC",
        "key_length": 128,
        "dh_group": 2,  # 1024-bit MODP
        "prf": "HMAC-SHA2-256"
    }
    findings = engine.evaluate(signals)
    rule_ids = [f["rule_id"] for f in findings]

    assert "DH-002" in rule_ids
    assert "DH-003" in rule_ids
    logjam_finding = next(f for f in findings if f["rule_id"] == "DH-003")
    assert logjam_finding["severity"] == "critical"
    assert "logjam" in logjam_finding["message"].lower()


def test_rule_engine_replay_detection():
    engine = RuleEngine()
    signals = {
        "ipsec_protocol": "ESP",
        "replay_detected": True
    }
    findings = engine.evaluate(signals)
    rule_ids = [f["rule_id"] for f in findings]

    assert "IPSEC-004" in rule_ids
    replay_finding = next(f for f in findings if f["rule_id"] == "IPSEC-004")
    assert replay_finding["severity"] == "critical"


def test_rule_engine_ah_without_esp():
    engine = RuleEngine()
    signals = {
        "ipsec_protocol": "AH",
        "ah_without_esp": True
    }
    findings = engine.evaluate(signals)
    rule_ids = [f["rule_id"] for f in findings]

    assert "IPSEC-003" in rule_ids
    ah_finding = next(f for f in findings if f["rule_id"] == "IPSEC-003")
    assert ah_finding["severity"] == "high"


def test_rule_engine_cnsa_2_0_pass():
    engine = RuleEngine()
    signals = {
        "ike_version": "IKEv2",
        "encryption": "AES-GCM-16",
        "key_length": 256,
        "dh_group": 20,  # 384-bit ECP
        "prf": "HMAC-SHA2-384"
    }
    findings = engine.evaluate(signals)

    cnsa_finding = next(f for f in findings if f["rule_id"] == "COMP-002")
    assert cnsa_finding["severity"] == "info"
    assert "meets cnsa" in cnsa_finding["message"].lower()
