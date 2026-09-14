import pytest
from unittest.mock import MagicMock
from parsers.ike_parser import IKEParser
from parsers.ipsec_parser import IPsecParser


def test_ike_parser_ikev2_normal():
    parser = IKEParser()
    mock_packet = MagicMock()
    mock_layer = MagicMock()

    field_data = {
        "ispi": "01:02:03:04:05:06:07:08",
        "rspi": "09:0a:0b:0c:0d:0e:0f:10",
        "mjver": "2",
        "exchangetype": "34",
        "flag_i": "True",
        "tf_id_encr": "20",
        "ike2_attr_key_length": "256",
        "tf_id_prf": "5",
        "tf_id_dh": "19",
        "nonce": "a" * 64,  # 32 bytes
    }
    mock_layer.get_field_value.side_effect = lambda name: field_data.get(name)
    mock_packet.isakmp = mock_layer

    signals = parser.parse(mock_packet, packet_number=1)
    signal_map = {s.name: s.value for s in signals}

    assert signal_map["ike_detected"] is True
    assert signal_map["ike_version"] == "IKEv2"
    assert signal_map["ike_role"] == "initiator"
    assert signal_map["ike_exchange"] == "IKE_SA_INIT"
    assert signal_map["encryption"] == "AES-GCM-16"
    assert signal_map["key_length"] == 256
    assert signal_map["prf"] == "HMAC-SHA2-256"
    assert signal_map["dh_group"] == 19
    assert signal_map["nonce_length"] == 32
    assert "short_nonce" not in signal_map
    assert "is_aggressive_mode" not in signal_map


def test_ike_parser_aggressive_mode():
    parser = IKEParser()
    mock_packet = MagicMock()
    mock_layer = MagicMock()

    field_data = {
        "ispi": "11:22:33:44:55:66:77:88",
        "rspi": "00:00:00:00:00:00:00:00",
        "mjver": "1",
        "exchangetype": "4",  # Aggressive Mode
        "trans_attr_enc": "5",  # 3DES
        "trans_attr_hash": "1",  # MD5
        "trans_attr_group_desc": "2",  # Group 2 (1024-bit)
        "nonce": "11:22",  # Only 2 bytes (short nonce)
    }
    mock_layer.get_field_value.side_effect = lambda name: field_data.get(name)
    mock_packet.isakmp = mock_layer

    signals = parser.parse(mock_packet, packet_number=2)
    signal_map = {s.name: s.value for s in signals}

    assert signal_map["ike_version"] == "IKEv1"
    assert signal_map["ike_exchange"] == "Aggressive Mode"
    assert signal_map["is_aggressive_mode"] is True
    assert signal_map["encryption"] == "3DES-CBC"
    assert signal_map["prf"] == "HMAC-MD5"
    assert signal_map["dh_group"] == 2
    assert signal_map["nonce_length"] == 2
    assert signal_map["short_nonce"] is True


def test_ipsec_parser_ah_without_esp():
    parser = IPsecParser()
    mock_packet = MagicMock(spec=["ah"])
    mock_layer = MagicMock()
    mock_layer.get_field_value.side_effect = lambda name: "123456" if name == "spi" else None
    mock_packet.ah = mock_layer

    signals = parser.parse(mock_packet, packet_number=1)
    signal_map = {s.name: s.value for s in signals}

    assert signal_map["ipsec_protocol"] == "AH"
    assert signal_map["ah_without_esp"] is True


def test_ipsec_parser_esp_sequence():
    parser = IPsecParser()
    mock_packet = MagicMock(spec=["esp"])
    mock_layer = MagicMock()

    field_data = {
        "spi": "0xdeadbeef",
        "sequence": "42"
    }
    mock_layer.get_field_value.side_effect = lambda name: field_data.get(name)
    mock_packet.esp = mock_layer

    signals = parser.parse(mock_packet, packet_number=1)
    signal_map = {s.name: s.value for s in signals}

    assert signal_map["ipsec_protocol"] == "ESP"
    assert signal_map["esp_spi"] == "0xdeadbeef"
    assert signal_map["esp_sequence_int"] == 42
    assert "sequence_rollover_risk" not in signal_map
