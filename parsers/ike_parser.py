from core.signal import SecuritySignal


class IKEParser:

    ENCRYPTION_ALGORITHMS = {
        1: "DES-IV64",
        2: "DES",
        3: "3DES",
        11: "NULL",
        12: "AES-CBC",
        13: "AES-CTR",
        18: "AES-GCM-8",
        19: "AES-GCM-12",
        20: "AES-GCM-16"
    }

    PRF_ALGORITHMS = {
        1: "HMAC-MD5",
        2: "HMAC-SHA1",
        4: "AES128-XCBC",
        5: "HMAC-SHA2-256",
        6: "HMAC-SHA2-384",
        7: "HMAC-SHA2-512",
        8: "AES128-CMAC"
    }

    INTEGRITY_ALGORITHMS = {
        0: "NONE",
        1: "HMAC-MD5-96",
        2: "HMAC-SHA1-96",
        5: "AES-XCBC-96",
        12: "HMAC-SHA2-256-128",
        13: "HMAC-SHA2-384-192",
        14: "HMAC-SHA2-512-256"
    }

    DH_GROUPS = {
        1: "768-bit MODP",
        2: "1024-bit MODP",
        5: "1536-bit MODP",
        14: "2048-bit MODP",
        15: "3072-bit MODP",
        16: "4096-bit MODP",
        17: "6144-bit MODP",
        18: "8192-bit MODP",
        19: "256-bit ECP",
        20: "384-bit ECP",
        21: "521-bit ECP"
    }

    EXCHANGE_TYPES = {
        34: "IKE_SA_INIT",
        35: "IKE_AUTH",
        36: "CREATE_CHILD_SA",
        37: "INFORMATIONAL"
    }

    def parse(self, packet, packet_number=None):

        signals = []

        if not hasattr(packet, "isakmp"):
            return signals

        layer = packet.isakmp

        session_id = self._build_session_id(layer)

        signals.append(
            self._signal(
                "ike_detected",
                True,
                packet_number,
                session_id,
                "protocol"
            )
        )

        major_version = self._get_int_field(
            layer,
            "mjver"
        )

        if major_version is not None:
            signals.append(
                self._signal(
                    "ike_version",
                    f"IKEv{major_version}",
                    packet_number,
                    session_id,
                    "protocol"
                )
            )

        exchange_type = self._get_int_field(
            layer,
            "exchangetype"
        )

        if exchange_type is not None:
            signals.append(
                self._signal(
                    "ike_exchange",
                    self.EXCHANGE_TYPES.get(
                        exchange_type,
                        f"TYPE-{exchange_type}"
                    ),
                    packet_number,
                    session_id,
                    "protocol"
                )
            )

        encryption_id = self._get_int_field(
            layer,
            "tf_id_encr"
        )

        if encryption_id is not None:

            signals.append(
                self._signal(
                    "encryption_id",
                    encryption_id,
                    packet_number,
                    session_id,
                    "crypto"
                )
            )

            signals.append(
                self._signal(
                    "encryption",
                    self.ENCRYPTION_ALGORITHMS.get(
                        encryption_id,
                        f"UNKNOWN-{encryption_id}"
                    ),
                    packet_number,
                    session_id,
                    "crypto"
                )
            )

        key_length = self._get_int_field(
            layer,
            "ike2_attr_key_length"
        )

        if key_length is not None:
            signals.append(
                self._signal(
                    "key_length",
                    key_length,
                    packet_number,
                    session_id,
                    "crypto"
                )
            )

        prf_id = self._get_int_field(
            layer,
            "tf_id_prf"
        )

        if prf_id is not None:

            signals.append(
                self._signal(
                    "prf_id",
                    prf_id,
                    packet_number,
                    session_id,
                    "crypto"
                )
            )

            signals.append(
                self._signal(
                    "prf",
                    self.PRF_ALGORITHMS.get(
                        prf_id,
                        f"UNKNOWN-{prf_id}"
                    ),
                    packet_number,
                    session_id,
                    "crypto"
                )
            )

        integrity_id = self._get_int_field(
            layer,
            "tf_id_integ"
        )

        if integrity_id is not None:

            signals.append(
                self._signal(
                    "integrity_id",
                    integrity_id,
                    packet_number,
                    session_id,
                    "crypto"
                )
            )

            signals.append(
                self._signal(
                    "integrity",
                    self.INTEGRITY_ALGORITHMS.get(
                        integrity_id,
                        f"UNKNOWN-{integrity_id}"
                    ),
                    packet_number,
                    session_id,
                    "crypto"
                )
            )

        dh_group = self._get_int_field(
            layer,
            "tf_id_dh"
        )

        if dh_group is None:
            dh_group = self._get_int_field(
                layer,
                "key_exchange_dh_group"
            )

        if dh_group is not None:

            signals.append(
                self._signal(
                    "dh_group",
                    dh_group,
                    packet_number,
                    session_id,
                    "crypto"
                )
            )

            signals.append(
                self._signal(
                    "dh_group_name",
                    self.DH_GROUPS.get(
                        dh_group,
                        f"GROUP-{dh_group}"
                    ),
                    packet_number,
                    session_id,
                    "crypto"
                )
            )

        return signals

    def _signal(
        self,
        name,
        value,
        packet_number,
        session_id,
        category
    ):

        return SecuritySignal(
            name=name,
            value=value,
            source="packet",
            packet_number=packet_number,
            session_id=session_id,
            category=category
        )

    def _build_session_id(self, layer):

        initiator = self._get_field(
            layer,
            "ispi"
        )

        responder = self._get_field(
            layer,
            "rspi"
        )

        if not initiator:
            return None

        responder = responder or "unknown"

        return f"{initiator}-{responder}"

    def _get_field(self, layer, name):

        try:
            return layer.get_field_value(name)
        except Exception:
            return None

    def _get_int_field(self, layer, name):

        value = self._get_field(layer, name)

        if value is None:
            return None

        try:
            return int(str(value), 0)
        except Exception:
            return None