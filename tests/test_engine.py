import os
import pytest
from core.engine import SecurityEngine
from core.session_manager import SessionManager
from core.signal import SecuritySignal
from sources.pcap_source import PCAPSource
from sources.live_source import LiveSource


def test_session_manager_replay_detection():
    manager = SessionManager()

    # Packet 1 with ESP Sequence 100
    sig1 = [
        SecuritySignal(name="esp_sequence_int", value=100, source="packet", session_id="esp-12345")
    ]
    extra1 = manager.ingest(sig1)
    assert len(extra1) == 0

    # Packet 2 with ESP Sequence 101
    sig2 = [
        SecuritySignal(name="esp_sequence_int", value=101, source="packet", session_id="esp-12345")
    ]
    extra2 = manager.ingest(sig2)
    assert len(extra2) == 0

    # Packet 3 with duplicate ESP Sequence 100 (Replay)
    sig3 = [
        SecuritySignal(name="esp_sequence_int", value=100, source="packet", session_id="esp-12345")
    ]
    extra3 = manager.ingest(sig3)
    assert len(extra3) == 1
    assert extra3[0].name == "replay_detected"
    assert extra3[0].value is True

    sessions = manager.get_sessions()
    assert len(sessions) == 1
    assert sessions[0]["replay_detected"] is True
    assert 100 in sessions[0]["duplicate_sequences"]


def test_live_source_interface_listing():
    interfaces = LiveSource.list_interfaces()
    assert isinstance(interfaces, list)
    # If tshark/Npcap is installed, should discover network adapters
    if interfaces:
        assert "index" in interfaces[0]
        assert "name" in interfaces[0]


def test_end_to_end_pcap_analysis():
    pcap_path = os.path.join("data", "pcaps", "test_vpn.pcap")
    if not os.path.exists(pcap_path):
        pytest.skip("Test PCAP not found")

    source = PCAPSource(pcap_path)
    engine = SecurityEngine()

    try:
        packets = source.read()
        report = engine.analyze(packets, source_type="pcap")

        assert report["summary"]["vpn_detected"] is True
        assert report["summary"]["protocol"] == "IPsec"
        assert report["crypto"]["ike_version"] == "IKEv2"
        assert report["crypto"]["encryption"] == "AES-GCM-16"
        assert report["traffic"]["packets_processed"] == 6
        assert report["compliance"]["nist_sp_800_77_rev1"] == "PASS"
        assert isinstance(report["findings"], list)
        assert len(report["findings"]) > 0
    finally:
        source.close()
